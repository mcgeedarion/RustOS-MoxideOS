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

// ── Header ──────────────────────────────────────────────────────────────────

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
    _size_dt_strings: u32,
    _size_dt_struct: u32,
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
}

// ── Big-endian integer helpers ───────────────────────────────────────────────

#[inline]
fn be32(b: &[u8], off: usize) -> u32 {
    u32::from_be_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
}
fn cstr(bytes: &[u8], off: usize) -> &str {
    let end = bytes[off..].iter().position(|&c| c == 0).unwrap_or(0);
    core::str::from_utf8(&bytes[off..off + end]).unwrap_or("")
}
#[inline]
fn be64(b: &[u8], off: usize) -> u64 {
    u64::from_be_bytes([
        b[off],
        b[off + 1],
        b[off + 2],
        b[off + 3],
        b[off + 4],
        b[off + 5],
        b[off + 6],
        b[off + 7],
    ])
}

// ── Kernel end symbol ────────────────────────────────────────────────────────

extern "C" {
    static _kernel_end: u8;
}

// ── Node-tracking state (shared by both phases) ──────────────────────────────

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

// ── Shared walker primitive ───────────────────────────────────────────────────

/// Validate FDT magic and return (blob slice, structs offset, strings offset).
/// Returns `None` and prints a diagnostic if the blob is invalid.
unsafe fn open_fdt(fdt_ptr: usize) -> Option<(&'static [u8], usize, usize)> {
    if fdt_ptr == 0 {
        return None;
    }
    let hdr = FdtHeader::from_ptr(fdt_ptr);
    if hdr.magic() != FDT_MAGIC {
        crate::println!("fdt: invalid magic {:#010x} at {:#x}", hdr.magic(), fdt_ptr);
        return None;
    }
    let total = hdr.totalsize() as usize;
    let blob = core::slice::from_raw_parts(fdt_ptr as *const u8, total);
    let s_off = hdr.off_dt_struct() as usize;
    let str_off = hdr.off_dt_strings() as usize;
    Some((blob, s_off, str_off))
}

// ─────────────────────────────────────────────────────────────────────────────
// Phase 1 — pre-heap: PMM + PLIC base + initramfs bounds + CPU enumeration
// No heap allocations permitted here.
// ─────────────────────────────────────────────────────────────────────────────

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
    let (blob, s_off, str_off) = match open_fdt(fdt_ptr) {
        Some(v) => v,
        None => return,
    };
    let total = blob.len();
    let structs = &blob[s_off..];
    let strings = &blob[str_off..];
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
        let token = be32(structs, pos);
        pos += 4;

        match token {
            FDT_BEGIN_NODE => {
                let name_start = pos;
                let name_end = structs[pos..].iter().position(|&c| c == 0).unwrap_or(0) + pos + 1;
                let padded = (name_end + 3) & !3;
                let node_name =
                    core::str::from_utf8(&structs[name_start..name_end - 1]).unwrap_or("");
                pos = padded;

                match depth {
                    1 => {
                        in_memory = node_name == "memory" || node_name.starts_with("memory@");
                        in_chosen = node_name == "chosen";
                        in_soc = node_name == "soc";
                        in_cpus = node_name == "cpus";
                        // virtio_mmio@ nodes are handled in phase 2 only
                    }
                    2 if in_soc => {
                        soc_child = if node_name == "plic" || node_name.starts_with("plic@") {
                            SocChild::Plic
                        } else {
                            SocChild::Other
                        };
                    }
                    2 if in_cpus => {
                        if node_name == "cpu" || node_name.starts_with("cpu@") {
                            cpus_child = CpusChild::Cpu;
                            cpu_reg = u32::MAX;
                            cpu_status_ok = true;
                        } else {
                            cpus_child = CpusChild::None;
                        }
                    }
                    _ => {}
                }
                depth += 1;
            }

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
                    }
                    2 if in_soc => {
                        if soc_child == SocChild::Plic && plic_base != 0 {
                            crate::arch::riscv64::plic::set_base(plic_base);
                        }
                        soc_child = SocChild::None;
                    }
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
                    }
                    _ => {}
                }
            }

            FDT_PROP => {
                if pos + 8 > structs.len() {
                    break;
                }
                let prop_len = be32(structs, pos) as usize;
                pos += 4;
                let name_off = be32(structs, pos) as usize;
                pos += 4;
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
                        let base = be64(prop_data, i) as usize;
                        let size = be64(prop_data, i + 8) as usize;
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
                                be64(prop_data, 0)
                            } else if prop_data.len() == 4 {
                                be32(prop_data, 0) as u64
                            } else {
                                0
                            };
                        }
                        "linux,initrd-end" => {
                            initrd_end = if prop_data.len() == 8 {
                                be64(prop_data, 0)
                            } else if prop_data.len() == 4 {
                                be32(prop_data, 0) as u64
                            } else {
                                0
                            };
                        }
                        _ => {}
                    }
                }

                // /soc/plic reg
                if soc_child == SocChild::Plic && prop_name == "reg" {
                    if prop_data.len() >= 16 {
                        let addr_hi = be32(prop_data, 0) as usize;
                        let addr_lo = be32(prop_data, 4) as usize;
                        let addr = (addr_hi << 32) | addr_lo;
                        if addr != 0 {
                            plic_base = addr;
                        }
                    } else if prop_data.len() >= 8 {
                        let addr = be64(prop_data, 0) as usize;
                        if addr != 0 {
                            plic_base = addr;
                        }
                    } else if prop_data.len() >= 4 {
                        let addr = be32(prop_data, 0) as usize;
                        if addr != 0 {
                            plic_base = addr;
                        }
                    }
                }

                // /cpus/cpu@ reg + status
                if cpus_child == CpusChild::Cpu {
                    match prop_name {
                        "reg" => {
                            if prop_data.len() >= 4 {
                                cpu_reg = be32(prop_data, 0);
                            }
                        }
                        "status" => {
                            let s = core::str::from_utf8(
                                prop_data.split(|&c| c == 0).next().unwrap_or(&[]),
                            )
                            .unwrap_or("");
                            cpu_status_ok = s == "okay" || s == "ok";
                        }
                        _ => {}
                    }
                }
            }

            FDT_NOP => {}
            FDT_END | _ => {
                break;
            }
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

// ─────────────────────────────────────────────────────────────────────────────
// Phase 2 — post-heap: virtio-net MMIO device probe
// Heap allocations ARE permitted here.
// ─────────────────────────────────────────────────────────────────────────────

/// Walk the FDT a second time and probe all `virtio,mmio` nodes.
/// Heap must be initialised before calling this function.
///
/// # Safety
/// Same requirements as `fdt_phase1`.
pub unsafe fn fdt_phase2(fdt_ptr: usize) {
    let (blob, s_off, str_off) = match open_fdt(fdt_ptr) {
        Some(v) => v,
        None => return,
    };
    let structs = &blob[s_off..];
    let strings = &blob[str_off..];
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
        let token = be32(structs, pos);
        pos += 4;

        match token {
            FDT_BEGIN_NODE => {
                let name_start = pos;
                let name_end = structs[pos..].iter().position(|&c| c == 0).unwrap_or(0) + pos + 1;
                let padded = (name_end + 3) & !3;
                let node_name =
                    core::str::from_utf8(&structs[name_start..name_end - 1]).unwrap_or("");
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
            }

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
            }

            FDT_PROP => {
                if pos + 8 > structs.len() {
                    break;
                }
                let prop_len = be32(structs, pos) as usize;
                pos += 4;
                let name_off = be32(structs, pos) as usize;
                pos += 4;
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
                        }
                        "reg" => {
                            if prop_data.len() >= 8 {
                                let addr = be64(prop_data, 0) as usize;
                                if addr != 0 {
                                    vmmio.base = addr;
                                }
                            }
                        }
                        "interrupts" => {
                            if prop_data.len() >= 4 {
                                vmmio.irq = be32(prop_data, 0);
                            }
                        }
                        _ => {}
                    }
                }
            }

            FDT_NOP => {}
            FDT_END | _ => {
                break;
            }
        }
    }
}
