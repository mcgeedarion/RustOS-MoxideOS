//! RISC-V boot-time memory discovery (FDT-based).
//!
//! Parses the FDT `memory` node and converts it into the common
//! `mm::boot_memory::Regions` description consumed by the PMM.

use crate::mm::boot_memory::{Region, RegionKind, Regions};

pub fn discover(fdt_ptr: usize) -> Regions {
    let mut regions = Regions::new();
    if fdt_ptr == 0 {
        return regions;
    }
    unsafe {
        fdt_walk_memory(fdt_ptr, &mut regions);
    }
    regions
}

const FDT_MAGIC: u32 = 0xd00d_feed;
const FDT_BEGIN_NODE: u32 = 1;
const FDT_END_NODE: u32 = 2;
const FDT_PROP: u32 = 3;
const FDT_NOP: u32 = 4;
const FDT_END: u32 = 9;

#[inline]
unsafe fn fdt_u32(p: *const u8) -> u32 {
    u32::from_be_bytes([*p, *p.add(1), *p.add(2), *p.add(3)])
}
#[inline]
unsafe fn fdt_u64(p: *const u8) -> u64 {
    let b = core::slice::from_raw_parts(p, 8);
    u64::from_be_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])
}

unsafe fn fdt_walk_memory(fdt_ptr: usize, regions: &mut Regions) {
    let base = fdt_ptr as *const u8;
    if fdt_u32(base) != FDT_MAGIC {
        return;
    }
    let total_size = fdt_u32(base.add(4)) as usize;
    let off_struct = fdt_u32(base.add(8)) as usize;
    let off_strings = fdt_u32(base.add(12)) as usize;
    if total_size > 64 * 1024 * 1024 {
        return;
    }
    let strings_base = base.add(off_strings);
    let struct_base = base.add(off_struct);
    let mut offset = 0usize;
    let mut depth = 0i32;
    let mut in_mem = false;
    loop {
        let token = fdt_u32(struct_base.add(offset));
        offset += 4;
        match token {
            FDT_BEGIN_NODE => {
                let np = struct_base.add(offset);
                let mut nl = 0usize;
                while np.add(nl).read() != 0 {
                    nl += 1;
                }
                let name = core::slice::from_raw_parts(np, nl);
                depth += 1;
                in_mem = depth == 1 && name.starts_with(b"memory");
                offset += (nl + 1 + 3) & !3;
            },
            FDT_END_NODE => {
                if depth == 1 {
                    in_mem = false;
                }
                depth -= 1;
                if depth < 0 {
                    break;
                }
            },
            FDT_PROP => {
                let plen = fdt_u32(struct_base.add(offset)) as usize;
                let pnof = fdt_u32(struct_base.add(offset + 4)) as usize;
                offset += 8;
                if in_mem {
                    let pnp = strings_base.add(pnof);
                    let mut pnl = 0usize;
                    while pnp.add(pnl).read() != 0 {
                        pnl += 1;
                    }
                    if core::slice::from_raw_parts(pnp, pnl) == b"reg" {
                        let data = struct_base.add(offset);
                        let mut i = 0usize;
                        while i + 16 <= plen {
                            let bpa = fdt_u64(data.add(i)) as usize;
                            let size = fdt_u64(data.add(i + 8)) as usize;
                            if size > 0 {
                                regions.push(Region {
                                    start: bpa as u64,
                                    length: size as u64,
                                    kind: RegionKind::Usable,
                                });
                            }
                            i += 16;
                        }
                    }
                }
                offset += (plen + 3) & !3;
            },
            FDT_NOP => {},
            FDT_END | _ => break,
        }
        if offset >= total_size {
            break;
        }
    }
}
