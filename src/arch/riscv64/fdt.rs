//! Flattened Device Tree (FDT/DTB) walker for RISC-V early boot.
//!
//! Reads the FDT blob passed by OpenSBI in `a1` to:
//!   1. Register physical RAM regions with the PMM (`pmm::add_region`).
//!   2. Record the initramfs location (`initramfs::set_initramfs_range`).
//!   3. Discover VirtIO-MMIO devices → `virtio_net_mmio::probe(base, irq)`.
//!   4. Discover the PLIC → `plic::set_base(base)`.
//!
//! Only the subset of the FDT spec needed for QEMU `virt` machine is
//! implemented — big-endian u32 token stream, no dynamic allocation required.
//!
//! ## FDT binary format (abbreviated)
//! Offset 0:  magic  0xD00DFEED (big-endian u32)
//! Offset 4:  totalsize
//! Offset 8:  off_dt_struct
//! Offset 12: off_dt_strings
//! Offset 16: off_mem_rsvmap
//! Offset 20: version (expected ≥17)
//! Offset 24: last_comp_version (must be ≤17)
//! Offset 36: size_dt_struct
//!
//! Token types: BEGIN_NODE=1, END_NODE=2, PROP=3, NOP=4, END=9

use crate::mm::pmm;

const FDT_MAGIC:       u32 = 0xD00D_FEED;
const FDT_BEGIN_NODE:  u32 = 1;
const FDT_END_NODE:    u32 = 2;
const FDT_PROP:        u32 = 3;
const FDT_NOP:         u32 = 4;
const FDT_END:         u32 = 9;

// ── Header ────────────────────────────────────────────────────────────────────────

#[repr(C)]
struct FdtHeader {
    magic:             u32,
    totalsize:         u32,
    off_dt_struct:     u32,
    off_dt_strings:    u32,
    _off_mem_rsvmap:   u32,
    _version:          u32,
    _last_comp:        u32,
    _boot_cpuid:       u32,
    _size_dt_strings:  u32,
    _size_dt_struct:   u32,
}

impl FdtHeader {
    unsafe fn from_ptr(ptr: usize) -> &'static FdtHeader {
        &*(ptr as *const FdtHeader)
    }
    fn magic(&self)          -> u32 { u32::from_be(self.magic)          }
    fn totalsize(&self)      -> u32 { u32::from_be(self.totalsize)      }
    fn off_dt_struct(&self)  -> u32 { u32::from_be(self.off_dt_struct)  }
    fn off_dt_strings(&self) -> u32 { u32::from_be(self.off_dt_strings) }
}

// ── Big-endian integer helpers ──────────────────────────────────────────────────────────

#[inline]
fn be32(b: &[u8], off: usize) -> u32 {
    u32::from_be_bytes([b[off], b[off+1], b[off+2], b[off+3]])
}
fn cstr(bytes: &[u8], off: usize) -> &str {
    let end = bytes[off..].iter().position(|&c| c == 0).unwrap_or(0);
    core::str::from_utf8(&bytes[off..off + end]).unwrap_or("")
}
#[inline]
fn be64(b: &[u8], off: usize) -> u64 {
    u64::from_be_bytes([
        b[off],b[off+1],b[off+2],b[off+3],
        b[off+4],b[off+5],b[off+6],b[off+7],
    ])
}

// ── Kernel end symbol ───────────────────────────────────────────────────────────────────

extern "C" { static _kernel_end: u8; }

// ── Node tracking state ───────────────────────────────────────────────────────────────

#[derive(Default)]
struct VirtioMmioNode {
    base:      usize,
    irq:       u32,
    is_virtio: bool,
}

/// Which kind of node we are currently inside (depth==2 for /soc/* children).
#[derive(PartialEq)]
enum SocChild { None, Plic, Other }

// ── Main walker ───────────────────────────────────────────────────────────────────

/// Walk the FDT blob and initialise PMM, initramfs, PLIC, and VirtIO-MMIO devices.
///
/// # Safety
/// `fdt_ptr` must be the physical address of a valid DTB blob as passed by
/// OpenSBI.  The blob must remain readable for the duration of this call.
pub unsafe fn init_from_fdt(fdt_ptr: usize) {
    if fdt_ptr == 0 { return; }

    let hdr = FdtHeader::from_ptr(fdt_ptr);
    if hdr.magic() != FDT_MAGIC {
        crate::println!("fdt: invalid magic {:#010x} at {:#x}", hdr.magic(), fdt_ptr);
        return;
    }

    let total   = hdr.totalsize() as usize;
    let blob    = core::slice::from_raw_parts(fdt_ptr as *const u8, total);
    let structs = &blob[hdr.off_dt_struct()  as usize ..];
    let strings = &blob[hdr.off_dt_strings() as usize ..];

    crate::println!("fdt: blob at {:#x}, {} bytes", fdt_ptr, total);

    let mut pos:           usize = 0;
    let mut depth:         usize = 0;
    let mut in_memory:     bool  = false;
    let mut in_chosen:     bool  = false;
    let mut in_virtio:     bool  = false;
    let mut in_soc:        bool  = false;   // inside /soc node (depth 1)
    let mut soc_child:     SocChild = SocChild::None;  // which /soc/* we are in
    let mut vmmio:         VirtioMmioNode = VirtioMmioNode { base: 0, irq: 0, is_virtio: false };
    let mut plic_base:     usize = 0;       // /soc/plic reg base
    let mut initrd_start:  u64   = 0;
    let mut initrd_end:    u64   = 0;

    let kernel_end_pa = (&_kernel_end as *const u8 as usize + 0xFFF) & !0xFFF;

    loop {
        if pos + 4 > structs.len() { break; }
        let token = be32(structs, pos); pos += 4;

        match token {
            FDT_BEGIN_NODE => {
                let name_start = pos;
                let name_end   = structs[pos..].iter().position(|&c| c == 0)
                                     .unwrap_or(0) + pos + 1;
                let padded     = (name_end + 3) & !3;
                let node_name  = core::str::from_utf8(&structs[name_start..name_end - 1])
                                     .unwrap_or("");
                pos = padded;

                match depth {
                    1 => {
                        // Top-level nodes.
                        in_memory = node_name == "memory" || node_name.starts_with("memory@");
                        in_chosen = node_name == "chosen";
                        in_soc    = node_name == "soc";
                        in_virtio = node_name.starts_with("virtio_mmio@");
                        if in_virtio {
                            let addr_str = &node_name["virtio_mmio@".len()..];
                            vmmio = VirtioMmioNode {
                                base: usize::from_str_radix(addr_str, 16).unwrap_or(0),
                                irq: 0, is_virtio: false,
                            };
                        }
                    }
                    2 if in_soc => {
                        // /soc/* children.
                        soc_child = if node_name == "plic"
                                      || node_name.starts_with("plic@") {
                            SocChild::Plic
                        } else {
                            SocChild::Other
                        };
                    }
                    _ => {}
                }
                depth += 1;
            }

            FDT_END_NODE => {
                if depth > 0 { depth -= 1; }
                match depth {
                    1 => {
                        // Leaving a top-level node.
                        if in_virtio && vmmio.is_virtio && vmmio.base != 0 {
                            crate::drivers::virtio_net_mmio::probe(vmmio.base, vmmio.irq);
                        }
                        in_memory = false;
                        in_chosen = false;
                        in_virtio = false;
                        in_soc    = false;
                    }
                    2 if in_soc => {
                        // Leaving a /soc/* child.
                        if soc_child == SocChild::Plic && plic_base != 0 {
                            crate::drivers::plic::set_base(plic_base);
                        }
                        soc_child = SocChild::None;
                    }
                    _ => {}
                }
            }

            FDT_PROP => {
                if pos + 8 > structs.len() { break; }
                let prop_len  = be32(structs, pos) as usize; pos += 4;
                let name_off  = be32(structs, pos) as usize; pos += 4;
                let prop_name = cstr(strings, name_off);
                let prop_data = if pos + prop_len <= structs.len() {
                    &structs[pos..pos + prop_len]
                } else { &[] };
                pos = (pos + prop_len + 3) & !3;

                // ── /memory reg ────────────────────────────────────────────────────
                if in_memory && prop_name == "reg" {
                    let mut i = 0usize;
                    while i + 16 <= prop_data.len() {
                        let base = be64(prop_data, i)     as usize;
                        let size = be64(prop_data, i + 8) as usize;
                        i += 16;
                        if size == 0 { continue; }
                        let free_start = if base < kernel_end_pa { kernel_end_pa } else { base };
                        let fdt_start  = fdt_ptr & !0xFFF;
                        let fdt_end    = (fdt_ptr + total + 0xFFF) & !0xFFF;
                        let region_end = base + size;
                        if free_start < fdt_start && fdt_start <= region_end {
                            pmm::add_region(free_start, fdt_start - free_start);
                            crate::println!("pmm: region {:#x}..{:#x} ({} MiB)",
                                free_start, fdt_start, (fdt_start - free_start) / 0x10_0000);
                        }
                        if fdt_end < region_end {
                            pmm::add_region(fdt_end, region_end - fdt_end);
                            crate::println!("pmm: region {:#x}..{:#x} ({} MiB)",
                                fdt_end, region_end, (region_end - fdt_end) / 0x10_0000);
                        }
                        if fdt_end <= free_start || fdt_start >= region_end {
                            if free_start < region_end {
                                pmm::add_region(free_start, region_end - free_start);
                                crate::println!("pmm: region {:#x}..{:#x} ({} MiB)",
                                    free_start, region_end, (region_end - free_start) / 0x10_0000);
                            }
                        }
                    }
                }

                // ── /chosen ─────────────────────────────────────────────────────────
                if in_chosen {
                    match prop_name {
                        "linux,initrd-start" => {
                            initrd_start = if prop_data.len() == 8 { be64(prop_data, 0) }
                                           else if prop_data.len() == 4 { be32(prop_data, 0) as u64 }
                                           else { 0 };
                        }
                        "linux,initrd-end" => {
                            initrd_end = if prop_data.len() == 8 { be64(prop_data, 0) }
                                         else if prop_data.len() == 4 { be32(prop_data, 0) as u64 }
                                         else { 0 };
                        }
                        _ => {}
                    }
                }

                // ── virtio_mmio@ node ──────────────────────────────────────────────────
                if in_virtio {
                    match prop_name {
                        "compatible" => {
                            let s = core::str::from_utf8(
                                prop_data.split(|&c| c == 0).next().unwrap_or(&[])
                            ).unwrap_or("");
                            vmmio.is_virtio = s == "virtio,mmio";
                        }
                        "reg" => {
                            if prop_data.len() >= 8 {
                                let addr = be64(prop_data, 0) as usize;
                                if addr != 0 { vmmio.base = addr; }
                            }
                        }
                        "interrupts" => {
                            if prop_data.len() >= 4 { vmmio.irq = be32(prop_data, 0); }
                        }
                        _ => {}
                    }
                }

                // ── /soc/plic node ─────────────────────────────────────────────────────
                // QEMU virt DTB has /soc { plic@c000000 { reg = <0 0xc000000 0 0x600000>; } }
                // `reg` for the PLIC is a (addr-hi, addr-lo, size-hi, size-lo) tuple
                // with 32-bit cells (each FDT cell is a big-endian u32).
                // Two address cells + two size cells = 4 u32s = 16 bytes.
                if soc_child == SocChild::Plic && prop_name == "reg" {
                    if prop_data.len() >= 16 {
                        // #address-cells = 2 on QEMU virt /soc: high u32 then low u32.
                        let addr_hi = be32(prop_data, 0) as usize;
                        let addr_lo = be32(prop_data, 4) as usize;
                        let addr    = (addr_hi << 32) | addr_lo;
                        if addr != 0 { plic_base = addr; }
                    } else if prop_data.len() >= 8 {
                        // Some firmware emits a single-cell 64-bit address.
                        let addr = be64(prop_data, 0) as usize;
                        if addr != 0 { plic_base = addr; }
                    } else if prop_data.len() >= 4 {
                        // Fallback: 32-bit address cell.
                        let addr = be32(prop_data, 0) as usize;
                        if addr != 0 { plic_base = addr; }
                    }
                }
            }

            FDT_NOP => {}
            FDT_END | _ => { break; }
        }
    }

    if initrd_start != 0 && initrd_end > initrd_start {
        let len = (initrd_end - initrd_start) as usize;
        crate::println!("initramfs: found at {:#x}, {} bytes", initrd_start as usize, len);
        crate::initramfs::set_initramfs_range(initrd_start as usize, len);
    } else {
        crate::println!("initramfs: WARNING: /chosen missing linux,initrd-start/end");
        crate::println!("initramfs: Pass -initrd <cpio> to QEMU.");
    }
}
