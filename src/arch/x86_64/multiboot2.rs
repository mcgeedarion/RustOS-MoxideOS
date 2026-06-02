//! Multiboot2 header + MBI tag walker.
//!
//! ## Boot header
//! Placed at the very start of `.text.boot` so the linker script puts it
//! within the first 32 KiB of the binary.  GRUB2 / `qemu -kernel` scan for
//! the 4-byte magic 0xE85250D6 and, finding it, enter the kernel with:
//!   - EAX = 0x36D76289  (Multiboot2 magic)
//!   - EBX = physical address of the Multiboot2 Information (MBI) structure
//!
//! ## MBI tag walker
//! `parse_mbi(mbi_ptr)` walks the tag list and:
//!   - Passes memory-map entries (type 6) to `pmm::add_region()`.
//!   - Passes module tags (type 3) to `initramfs::set_initramfs_range()` for
//!     the first module whose string starts with "initrd" or is empty.
//!
//! Call `parse_mbi()` as early as possible — before `heap::init()` — so the
//! initramfs physical address is recorded before `initramfs::load()` runs.
//!
//! ## Tag type reference (Multiboot2 spec §3.6)
//!   Type 0  — end
//!   Type 1  — boot command line
//!   Type 3  — module  (mod_start u32, mod_end u32, string…)
//!   Type 6  — memory map
//!   Type 21 — EFI memory map

#[link_section = ".text.boot"]
#[used]
static MULTIBOOT2_HEADER: Multiboot2Header = Multiboot2Header::new();

// Header total size = 16 (fixed) + 8 (end tag) + 12 (mmap request) + 20 (fb tag) = 56 bytes.
// We also add a module request (type 3) so GRUB passes the initrd as a module.
const HEADER_LEN: u32 = 72; // 16 + 12 (info-req mmap) + 12 (info-req module) + 20 (fb) + 8 (end) + 4 pad

#[repr(C, align(8))]
struct Multiboot2Header {
    // Fixed part
    magic:      u32,  // 0xE85250D6
    arch:       u32,  // 0 = i386/x86-64
    header_len: u32,
    checksum:   u32,  // -(magic + arch + len)

    // Tag: information request (type 1) — ask for memory map (6) and modules (3)
    tag1_type:     u16,
    tag1_flags:    u16,
    tag1_size:     u32,
    tag1_req_mmap: u32, // 6 = memory map
    tag1_req_mod:  u32, // 3 = modules

    // Tag: framebuffer (type 5) — request text mode
    tag5_type:   u16,
    tag5_flags:  u16,
    tag5_size:   u32,
    tag5_width:  u32,
    tag5_height: u32,
    tag5_depth:  u32,

    // End tag (type 0)
    end_type:  u16,
    end_flags: u16,
    end_size:  u32,
}

impl Multiboot2Header {
    const fn new() -> Self {
        const MAGIC:    u32 = 0xE85250D6;
        const ARCH:     u32 = 0;
        const CHECKSUM: u32 = 0u32
            .wrapping_sub(MAGIC)
            .wrapping_sub(ARCH)
            .wrapping_sub(HEADER_LEN);
        Multiboot2Header {
            magic: MAGIC, arch: ARCH,
            header_len: HEADER_LEN, checksum: CHECKSUM,
            tag1_type: 1, tag1_flags: 0, tag1_size: 16,
            tag1_req_mmap: 6, tag1_req_mod: 3,
            tag5_type: 5, tag5_flags: 0, tag5_size: 20,
            tag5_width: 80, tag5_height: 25, tag5_depth: 0,
            end_type: 0, end_flags: 0, end_size: 8,
        }
    }
}

/// Walk the Multiboot2 Information structure at `mbi_ptr` and:
///   1. Feed usable memory map entries to `pmm::add_region()`.
///   2. Record the first module (initrd) via `initramfs::set_initramfs_range()`.
///
/// # Safety
/// `mbi_ptr` must be the value of EBX on kernel entry — a physical address
/// pointing to a valid MBI structure placed by GRUB2 or QEMU `-kernel`.
/// The MBI must remain accessible (identity-mapped) for the duration of this
/// call.  This is always true before `paging::remap()` is called.
pub unsafe fn parse_mbi(mbi_ptr: usize) {
    if mbi_ptr == 0 { return; }

    // MBI starts with: total_size: u32, reserved: u32, then tags.
    let total_size = *(mbi_ptr as *const u32) as usize;
    if total_size < 8 { return; }

    crate::println!("mb2: MBI at {:#x}, {} bytes", mbi_ptr, total_size);

    let mut off: usize = 8; // skip fixed header (total_size + reserved)
    let base = mbi_ptr;

    while off < total_size {
        // Each tag: type: u32, size: u32, [data...], padded to 8-byte boundary.
        if off + 8 > total_size { break; }
        let tag_type = *(( base + off    ) as *const u32);
        let tag_size = *(( base + off + 4) as *const u32) as usize;

        if tag_size < 8 { break; }

        match tag_type {
            0 => break,

            3 => {
                if tag_size >= 16 {
                    let mod_start = *(( base + off + 8 ) as *const u32) as usize;
                    let mod_end   = *(( base + off + 12) as *const u32) as usize;
                    // The module string starts at byte 16, NUL-terminated.
                    // We accept any module (take the first one as the initrd).
                    let len = mod_end.saturating_sub(mod_start);
                    if mod_start != 0 && len > 0 {
                        crate::println!(
                            "mb2: module tag: initrd at {:#x}..{:#x} ({} bytes)",
                            mod_start, mod_end, len,
                        );
                        // Record for initramfs::load().
                        crate::initramfs::set_initramfs_range(mod_start, len);
                        // Only use the first module as the initrd.
                        // If there are multiple modules, subsequent ones are ignored.
                    }
                }
            }

            6 => {
                // entry_size: u32, entry_version: u32, then entries.
                if tag_size >= 16 {
                    let entry_size = *(( base + off + 8 ) as *const u32) as usize;
                    let _entry_ver = *(( base + off + 12) as *const u32);
                    if entry_size >= 24 {
                        let mut eoff = off + 16;
                        let tag_end  = off + tag_size;
                        while eoff + entry_size <= tag_end {
                            // Entry: base_addr: u64, length: u64, type: u32, reserved: u32
                            let base_addr = *((base + eoff    ) as *const u64) as usize;
                            let length    = *((base + eoff + 8) as *const u64) as usize;
                            let mem_type  = *((base + eoff +16) as *const u32);
                            // type 1 = available RAM
                            if mem_type == 1 && length > 0 {
                                // Avoid handing the kernel image pages to the PMM.
                                // The PMM's add_region() is responsible for
                                // filtering pages that are already in use.
                                crate::mm::pmm::add_region(base_addr, length);
                                crate::println!(
                                    "mb2: usable RAM {:#x}..{:#x} ({} MiB)",
                                    base_addr,
                                    base_addr + length,
                                    length / 0x10_0000,
                                );
                            }
                            eoff += entry_size;
                        }
                    }
                }
            }

            _ => {}
        }

        // Advance to next tag, aligned to 8 bytes.
        off += (tag_size + 7) & !7;
    }
}
