//! Flattened Device Tree (FDT/DTB) walker for RISC-V early boot.
//!
//! The original monolithic `init_from_fdt()` has been split into two phases
//! to respect the heap initialisation barrier:
//!
//! | Phase        | Heap required | What it does                                  |
//! |--------------|---------------|-----------------------------------------------|
//! | `fdt_phase1` | **No**        | PMM regions, initramfs bounds, PLIC base, CPUs|
//! | `fdt_phase2` | **Yes**       | virtio-net MMIO probe (allocates ring buffers) |
//!
//! ## Boot call order (kernel_main riscv64)
//! ```text
//! trap::trap_init()      — stvec, SSIE/STIE/SEIE
//! fdt::fdt_phase1(ptr)   — PMM + PLIC base + initramfs + CPUs  (no alloc)
//! plic::init()           — set S-mode threshold = 0
//! heap::init()           — linked-list allocator over PMM
//! mm::init()             — slab cache pre-warm
//! fdt::fdt_phase2(ptr)   — virtio probe (alloc now safe)
//! initramfs::mount()
//! namespace::init()
//! ...
//! ```
//!
//! Only the subset of the FDT spec needed for QEMU `virt` is implemented:
//! big-endian u32 token stream, no dynamic allocation required in phase 1.

use crate::mm::pmm;

const FDT_MAGIC: u32 = 0xD00D_FEED;
const FDT_BEGIN_NODE: u32 = 1;
const FDT_END_NODE: u32 = 2;
const FDT_PROP: u32 = 3;
const FDT_NOP: u32 = 4;
const FDT_END: u32 = 9;

#[repr(C)]
struct FdtHeader {
    magic: u32,
    totalsize: u32,
    off_dt_struct: u32,
    off_dt_strings: u32,
    _off_mem_rsvmap: u32,
    _version: u32,
    _last_comp: u32,
    _boot_cpuid: u32,
    size_dt_strings: u32,
    size_dt_struct: u32,
}

impl FdtHeader {
    unsafe fn from_ptr(ptr: usize) -> &'static FdtHeader {
        &*(ptr as *const FdtHeader)
    }
    fn magic(&self) -> u32 {
        u32::from_be(self.magic)
    }
    fn totalsize(&self) -> u32 {
        u32::from_be(self.totalsize)
    }
    fn off_dt_struct(&self) -> u32 {
        u32::from_be(self.off_dt_struct)
    }
    fn off_dt_strings(&self) -> u32 {
        u32::from_be(self.off_dt_strings)
    }
    fn size_dt_struct(&self) -> u32 {
        u32::from_be(self.size_dt_struct)
    }
    fn size_dt_strings(&self) -> u32 {
        u32::from_be(self.size_dt_strings)
    }
}

#[inline]
fn be32(b: &[u8], off: usize) -> Option<u32> {
    let s = b.get(off..off + 4)?;
    Some(u32::from_be_bytes(s.try_into().unwrap()))
}

fn cstr(bytes: &[u8], off: usize) -> &str {
    if off >= bytes.len() {
        return "";
    }
    let end = bytes[off..]
        .iter()
        .position(|&c| c == 0)
        .unwrap_or(bytes.len() - off);
    core::str::from_utf8(&bytes[off..off + end]).unwrap_or("")
}

#[inline]
fn be64(b: &[u8], off: usize) -> Option<u64> {
    let s = b.get(off..off + 8)?;
    Some(u64::from_be_bytes(s.try_into().unwrap()))
}

extern "C" {
    static _kernel_end: u8;
}

#[derive(Default)]
struct VirtioMmioNode {
    base: usize,
    irq: u32,
    is_virtio: bool,
}

#[derive(PartialEq)]
enum SocChild {
    None,
    Plic,
    Other,
}

#[derive(PartialEq)]
enum CpusChild {
    None,
    Cpu,
}

/// Validate FDT magic, bounds-check all header offsets, and return
/// (blob slice, structs slice, strings slice).
/// Returns `None` and prints a diagnostic if the blob is invalid.
unsafe fn open_fdt(fdt_ptr: usize) -> Option<(&'static [u8], &'static [u8], &'static [u8])> {
    if fdt_ptr == 0 {
        return None;
    }
    let hdr = FdtHeader::from_ptr(fdt_ptr);
    if hdr.magic() != FDT_MAGIC {
        crate::println!("fdt: invalid magic {:#010x} at {:#x}", hdr.magic(), fdt_ptr);
        return None;
    }
    let total = hdr.totalsize() as usize;
    if total < core::mem::size_of::<FdtHeader>() {
        crate::println!("fdt: totalsize {} smaller than header", total);
        return None;
    }
    let s_off = hdr.off_dt_struct() as usize;
    let str_off = hdr.off_dt_strings() as usize;
    let s_size = hdr.size_dt_struct() as usize;
    let str_size = hdr.size_dt_strings() as usize;
    // Alignment: struct section must be 4-byte aligned
    if s_off & 3 != 0 {
        crate::println!("fdt: struct offset misaligned: {:#x}", s_off);
        return None;
    }
    // Both sections must fit within the blob
    if s_off.saturating_add(s_size) > total {
        crate::println!(
            "fdt: struct section [{:#x}..+{:#x}] exceeds totalsize {}",
            s_off,
            s_size,
            total
        );
        return None;
    }
    if str_off.saturating_add(str_size) > total {
        crate::println!(
            "fdt: strings section [{:#x}..+{:#x}] exceeds totalsize {}",
            str_off,
            str_size,
            total
        );
        return None;
    }
    // Struct section must hold at least one token
    if s_size < 4 {
        crate::println!("fdt: struct section too small: {} bytes", s_size);
        return None;
    }
    let blob = core::slice::from_raw_parts(fdt_ptr as *const u8, total);
    let structs = &blob[s_off..s_off + s_size];
    let strings = &blob[str_off..str_off + str_size];
    Some((blob, structs, strings))
}

// Phase 1 — pre-heap: PMM + PLIC base + initramfs bounds + CPU enumeration
// No heap allocations permitted here.

/// Walk the FDT and populate:
///   - PMM (`pmm::add_region`) from `/memory` nodes
///   - PLIC base (`plic::set_base`) from `/soc/plic`
///   - initramfs range (`initramfs::set_initramfs_range`) from `/chosen`
///   - SMP CPU table (`smp::register_cpu`) from `/cpus/cpu@`
///
/// **No heap allocation is performed.**  Must be called before `heap::init()`.
///
/// # Safety
/// `fdt_ptr` must be the physical address of a valid DTB as passed by OpenSBI.
pub unsafe fn fdt_phase1(fdt_ptr: usize) {
    let (blob, structs, strings) = match open_fdt(fdt_ptr) {
        Some(v) => v,
        None => return,
    };
    let total = blob.len();
    crate::println!("fdt: phase1 blob at {:#x}, {} bytes", fdt_ptr, total);

    let mut pos: usize = 0;
    let mut depth: usize = 0;

    let mut in_memory: bool = false;
    let mut in_chosen: bool = false;
    let mut in_soc: bool = false;
    let mut soc_child: SocChild = SocChild::None;
    let mut plic_base: usize = 0;
    let mut in_cpus: bool = false;
    let mut cpus_child: CpusChild = CpusChild::None;
    let mut cpu_reg: u32 = u32::MAX;
    let mut cpu_status_ok: bool = false;
    let mut cpu_count: u32 = 0;
    let mut initrd_start: u64 = 0;
    let mut initrd_end: u64 = 0;

    let kernel_end_pa = (&_kernel_end as *const u8 as usize + 0xFFF) & !0xFFF;
    let boot_hart = crate::arch::riscv64::boot::BOOT_HART_ID;

    loop {
        if pos + 4 > structs.len() {
            break;
        }
        let token = match be32(structs, pos) {
            Some(t) => t,
            None => break,
        };
        pos += 4;

        match token {
            FDT_BEGIN_NODE => {
                let name_start = pos;
                let rel = match structs[pos..].iter().position(|&c| c == 0) {
                    Some(r) => r,
                    None => break, // malformed: no null terminator
                };
                let name_end = pos + rel + 1;
                let padded = (name_end + 3) & !3;
                let node_name =
                    core::str::from_utf8(&structs[name_start..name_start + rel]).unwrap_or("");
                pos = padded;

                match depth {
                    1 => {
                        in_memory = node_name == "memory" || node_name.starts_with("memory@");
                        in_chosen = node_name == "chosen";
                        in_soc = node_name == "soc";
                        in_cpus = node_name == "cpus";
                        // virtio_mmio@ nodes are handled in phase 2 only
                    },
                    2 if in_soc => {
                        soc_child = if node_name == "plic" || node_name.starts_with("plic@") {
                            SocChild::Plic
                        } else {
                            SocChild::Other
                        };
                    },
                    2 if in_cpus => {
                        if node_name == "cpu" || node_name.starts_with("cpu@") {
                            cpus_child = CpusChild::Cpu;
                            cpu_reg = u32::MAX;
                            cpu_status_ok = true;
                        } else {
                            cpus_child = CpusChild::None;
                        }
                    },
                    _ => {},
                }
                depth += 1;
            },

            FDT_END_NODE => {
                if depth > 0 {
                    depth -= 1;
                }
                match depth {
                    1 => {
                        in_memory = false;
                        in_chosen = false;
                        in_soc = false;
                        in_cpus = false;
                    },
                    2 if in_soc => {
                        if soc_child == SocChild::Plic && plic_base != 0 {
                            crate::arch::riscv64::plic::set_base(plic_base);
                        }
                        soc_child = SocChild::None;
                    },
                    2 if in_cpus => {
                        if cpus_child == CpusChild::Cpu && cpu_reg != u32::MAX && cpu_status_ok {
                            let is_bsp = cpu_reg == boot_hart as u32;
                            crate::smp::register_cpu(cpu_reg, 0, is_bsp);
                            cpu_count += 1;
                            crate::println!(
                                "fdt: cpu hart {} logical {} {}",
                                cpu_reg,
                                cpu_count - 1,
                                if is_bsp { "(BSP)" } else { "(AP)" }
                            );
                        }
                        cpus_child = CpusChild::None;
                        cpu_reg = u32::MAX;
                        cpu_status_ok = true;
                    },
                    _ => {},
                }
            },

            FDT_PROP => {
                if pos + 8 > structs.len() {
                    break;
                }
                let prop_len = match be32(structs, pos) {
                    Some(v) => v as usize,
                    None => break,
                };
                pos += 4;
                let name_off = match be32(structs, pos) {
                    Some(v) => v as usize,
                    None => break,
                };
                pos += 4;
                // Reject out-of-bounds string offsets before calling cstr
                if name_off >= strings.len() {
                    break;
                }
                let prop_name = cstr(strings, name_off);
                let prop_data = if pos + prop_len <= structs.len() {
                    &structs[pos..pos + prop_len]
                } else {
                    &[]
                };
                pos = (pos + prop_len + 3) & !3;

                // /memory reg
                if in_memory && prop_name == "reg" {
                    let mut i = 0usize;
                    while i + 16 <= prop_data.len() {
                        let base = match be64(prop_data, i) {
                            Some(v) => v as usize,
                            None => break,
                        };
                        let size = match be64(prop_data, i + 8) {
                            Some(v) => v as usize,
                            None => break,
                        };
                        i += 16;
                        if size == 0 {
                            continue;
                        }
                        let free_start = if base < kernel_end_pa {
                            kernel_end_pa
                        } else {
                            base
                        };
                        let fdt_start = fdt_ptr & !0xFFF;
                        let fdt_end = (fdt_ptr + total + 0xFFF) & !0xFFF;
                        let region_end = base + size;
                        if free_start < fdt_start && fdt_start <= region_end {
                            pmm::add_region(free_start, fdt_start - free_start);
                            crate::println!(
                                "pmm: region {:#x}..{:#x} ({} MiB)",
                                free_start,
                                fdt_start,
                                (fdt_start - free_start) / 0x10_0000
                            );
                        }
                        if fdt_end < region_end {
                            pmm::add_region(fdt_end, region_end - fdt_end);
                            crate::println!(
                                "pmm: region {:#x}..{:#x} ({} MiB)",
                                fdt_end,
                                region_end,
                                (region_end - fdt_end) / 0x10_0000
                            );
                        }
                        if fdt_end <= free_start || fdt_start >= region_end {
                            if free_start < region_end {
                                pmm::add_region(free_start, region_end - free_start);
                                crate::println!(
                                    "pmm: region {:#x}..{:#x} ({} MiB)",
                                    free_start,
                                    region_end,
                                    (region_end - free_start) / 0x10_0000
                                );
                            }
                        }
                    }
                }

                // /chosen
                if in_chosen {
                    match prop_name {
                        "linux,initrd-start" => {
                            initrd_start = if prop_data.len() == 8 {
                                be64(prop_data, 0).unwrap_or(0)
                            } else if prop_data.len() == 4 {
                                be32(prop_data, 0).unwrap_or(0) as u64
                            } else {
                                0
                            };
                        },
                        "linux,initrd-end" => {
                            initrd_end = if prop_data.len() == 8 {
                                be64(prop_data, 0).unwrap_or(0)
                            } else if prop_data.len() == 4 {
                                be32(prop_data, 0).unwrap_or(0) as u64
                            } else {
                                0
                            };
                        },
                        _ => {},
                    }
                }

                // /soc/plic reg
                if soc_child == SocChild::Plic && prop_name == "reg" {
                    if prop_data.len() >= 16 {
                        let addr_hi = be32(prop_data, 0).unwrap_or(0) as usize;
                        let addr_lo = be32(prop_data, 4).unwrap_or(0) as usize;
                        let addr = (addr_hi << 32) | addr_lo;
                        if addr != 0 {
                            plic_base = addr;
                        }
                    } else if prop_data.len() >= 8 {
                        let addr = be64(prop_data, 0).unwrap_or(0) as usize;
                        if addr != 0 {
                            plic_base = addr;
                        }
                    } else if prop_data.len() >= 4 {
                        let addr = be32(prop_data, 0).unwrap_or(0) as usize;
                        if addr != 0 {
                            plic_base = addr;
                        }
                    }
                }

                // /cpus/cpu@ reg + status
                if cpus_child == CpusChild::Cpu {
                    match prop_name {
                        "reg" => {
                            if let Some(v) = be32(prop_data, 0) {
                                cpu_reg = v;
                            }
                        },
                        "status" => {
                            let s = core::str::from_utf8(
                                prop_data.split(|&c| c == 0).next().unwrap_or(&[]),
                            )
                            .unwrap_or("");
                            cpu_status_ok = s == "okay" || s == "ok";
                        },
                        _ => {},
                    }
                }
            },

            FDT_NOP => {},
            FDT_END | _ => {
                break;
            },
        }
    }

    if cpu_count == 0 {
        crate::smp::register_cpu(boot_hart as u32, 0, true);
        crate::println!(
            "fdt: no /cpus nodes — registering boot hart {} only",
            boot_hart
        );
    }

    if initrd_start != 0 && initrd_end > initrd_start {
        let len = (initrd_end - initrd_start) as usize;
        crate::println!(
            "initramfs: found at {:#x}, {} bytes",
            initrd_start as usize,
            len
        );
        crate::initramfs::set_initramfs_range(initrd_start as usize, len);
    } else {
        crate::println!("initramfs: WARNING: /chosen missing linux,initrd-start/end");
        crate::println!("initramfs: Pass -initrd <cpio> to QEMU.");
    }
}

// Phase 2 — post-heap: virtio-net MMIO device probe
// Heap allocations ARE permitted here.

/// Walk the FDT a second time and probe all `virtio,mmio` nodes.
/// Heap must be initialised before calling this function.
///
/// # Safety
/// Same requirements as `fdt_phase1`.
pub unsafe fn fdt_phase2(fdt_ptr: usize) {
    let (_blob, structs, strings) = match open_fdt(fdt_ptr) {
        Some(v) => v,
        None => return,
    };
    crate::println!("fdt: phase2 probing virtio-mmio devices");

    let mut pos: usize = 0;
    let mut depth: usize = 0;
    let mut in_virtio: bool = false;
    let mut vmmio: VirtioMmioNode = VirtioMmioNode {
        base: 0,
        irq: 0,
        is_virtio: false,
    };

    loop {
        if pos + 4 > structs.len() {
            break;
        }
        let token = match be32(structs, pos) {
            Some(t) => t,
            None => break,
        };
        pos += 4;

        match token {
            FDT_BEGIN_NODE => {
                let name_start = pos;
                let rel = match structs[pos..].iter().position(|&c| c == 0) {
                    Some(r) => r,
                    None => break, // malformed: no null terminator
                };
                let name_end = pos + rel + 1;
                let padded = (name_end + 3) & !3;
                let node_name =
                    core::str::from_utf8(&structs[name_start..name_start + rel]).unwrap_or("");
                pos = padded;

                if depth == 1 && node_name.starts_with("virtio_mmio@") {
                    let addr_str = &node_name["virtio_mmio@".len()..];
                    in_virtio = true;
                    vmmio = VirtioMmioNode {
                        base: usize::from_str_radix(addr_str, 16).unwrap_or(0),
                        irq: 0,
                        is_virtio: false,
                    };
                }
                depth += 1;
            },

            FDT_END_NODE => {
                if depth > 0 {
                    depth -= 1;
                }
                if depth == 1 && in_virtio {
                    if vmmio.is_virtio && vmmio.base != 0 {
                        crate::drivers::virtio_net_mmio::probe(vmmio.base, vmmio.irq);
                    }
                    in_virtio = false;
                }
            },

            FDT_PROP => {
                if pos + 8 > structs.len() {
                    break;
                }
                let prop_len = match be32(structs, pos) {
                    Some(v) => v as usize,
                    None => break,
                };
                pos += 4;
                let name_off = match be32(structs, pos) {
                    Some(v) => v as usize,
                    None => break,
                };
                pos += 4;
                // Reject out-of-bounds string offsets before calling cstr
                if name_off >= strings.len() {
                    break;
                }
                let prop_name = cstr(strings, name_off);
                let prop_data = if pos + prop_len <= structs.len() {
                    &structs[pos..pos + prop_len]
                } else {
                    &[]
                };
                pos = (pos + prop_len + 3) & !3;

                if in_virtio {
                    match prop_name {
                        "compatible" => {
                            let s = core::str::from_utf8(
                                prop_data.split(|&c| c == 0).next().unwrap_or(&[]),
                            )
                            .unwrap_or("");
                            vmmio.is_virtio = s == "virtio,mmio";
                        },
                        "reg" => {
                            if let Some(addr) = be64(prop_data, 0) {
                                if addr != 0 {
                                    vmmio.base = addr as usize;
                                }
                            }
                        },
                        "interrupts" => {
                            if let Some(irq) = be32(prop_data, 0) {
                                vmmio.irq = irq;
                            }
                        },
                        _ => {},
                    }
                }
            },

            FDT_NOP => {},
            FDT_END | _ => {
                break;
            },
        }
    }
}
