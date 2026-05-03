//! Boot memory map consumer — Phase 2.
//!
//! Reads the memory map provided by the bootloader and feeds usable
//! ranges to pmm_add_region().  Called once during kernel_main, after
//! heap_init() and before any large allocation.
//!
//! ## Supported map formats
//!   1. UEFI memory map  — stored by uefi_entry.rs in UEFI_MMAP.
//!   2. Multiboot2 mmap  — EBX pointer stored by _start in MB2_INFO_PA.
//!
//! We detect which is present via the boot_source() flag.

/// How this kernel instance was booted.
#[derive(Clone, Copy, PartialEq)]
pub enum BootSource { Uefi, Multiboot2, Unknown }

/// Set by the appropriate entry point before kernel_main runs.
pub static mut BOOT_SOURCE: BootSource = BootSource::Unknown;

// ── UEFI memory map ───────────────────────────────────────────────────────

/// Copy of the UEFI memory descriptor array, captured before ExitBootServices.
/// We store raw bytes because the descriptor size varies between firmware.
pub static mut UEFI_MMAP_BUF:  [u8; 8192] = [0u8; 8192];
pub static mut UEFI_MMAP_SIZE: usize = 0;   // total bytes valid in BUF
pub static mut UEFI_DESC_SIZE: usize = 0;   // bytes per descriptor

// EFI memory type 7 = EfiConventionalMemory (usable RAM)
const EFI_CONVENTIONAL: u32 = 7;

/// Parse the saved UEFI memory map and register usable regions with the PMM.
fn ingest_uefi() {
    let buf  = unsafe { &UEFI_MMAP_BUF[..UEFI_MMAP_SIZE] };
    let dsz  = unsafe { UEFI_DESC_SIZE };
    if dsz == 0 { return; }
    let mut off = 0usize;
    while off + dsz <= buf.len() {
        // EFI_MEMORY_DESCRIPTOR layout (little-endian):
        //   u32  type        offset 0
        //   u32  _pad        offset 4
        //   u64  phys_start  offset 8
        //   u64  virt_start  offset 16
        //   u64  num_pages   offset 24
        //   u64  attribute   offset 32
        let mem_type = u32::from_le_bytes(buf[off..off+4].try_into().unwrap());
        let phys: u64 = u64::from_le_bytes(buf[off+8..off+16].try_into().unwrap());
        let npages: u64 = u64::from_le_bytes(buf[off+24..off+32].try_into().unwrap());
        if mem_type == EFI_CONVENTIONAL {
            crate::mm::pmm::pmm_add_region(phys, npages * 4096);
        }
        off += dsz;
    }
}

// ── Multiboot2 memory map ─────────────────────────────────────────────────

/// Physical address of the Multiboot2 info structure, set by _start.
pub static mut MB2_INFO_PA: u64 = 0;

// Multiboot2 tag types
const MB2_TAG_MMAP:  u32 = 6;
const MB2_TAG_END:   u32 = 0;
// Multiboot2 mmap entry type 1 = available RAM
const MB2_MEM_AVAIL: u32 = 1;

/// Walk the Multiboot2 info structure and register usable memory.
fn ingest_multiboot2() {
    let info_va = unsafe { MB2_INFO_PA } as usize;
    if info_va == 0 { return; }

    // MB2 info header: u32 total_size, u32 reserved.  Tags follow.
    let total_size = unsafe { (info_va as *const u32).read_unaligned() } as usize;
    let mut off = 8usize; // skip the 8-byte header
    while off + 8 <= total_size {
        let tag_va   = info_va + off;
        let tag_type = unsafe { (tag_va as *const u32).read_unaligned() };
        let tag_size = unsafe { ((tag_va + 4) as *const u32).read_unaligned() } as usize;
        if tag_size < 8 { break; }

        if tag_type == MB2_TAG_END { break; }

        if tag_type == MB2_TAG_MMAP {
            // Mmap tag: u32 type, u32 size, u32 entry_size, u32 entry_version, entries…
            let entry_size = unsafe { ((tag_va + 8) as *const u32).read_unaligned() } as usize;
            let entries_off = 16usize; // 8 (tag hdr) + 4 entry_size + 4 entry_ver
            let entries_end = tag_size;
            let mut e = entries_off;
            while e + entry_size <= entries_end {
                let ev = tag_va + e;
                // MB2 mmap entry: u64 base, u64 len, u32 type, u32 reserved
                let base  = unsafe { (ev as *const u64).read_unaligned() };
                let len   = unsafe { ((ev + 8) as *const u64).read_unaligned() };
                let mtype = unsafe { ((ev + 16) as *const u32).read_unaligned() };
                if mtype == MB2_MEM_AVAIL {
                    crate::mm::pmm::pmm_add_region(base, len);
                }
                e += entry_size;
            }
        }
        // Tags are 8-byte aligned.
        off += (tag_size + 7) & !7;
    }
}

// ── Public API ────────────────────────────────────────────────────────────

/// Ingest the boot memory map into the PMM.
/// Call once in kernel_main, after heap_init().
pub fn memmap_init() {
    match unsafe { BOOT_SOURCE } {
        BootSource::Uefi        => ingest_uefi(),
        BootSource::Multiboot2  => ingest_multiboot2(),
        BootSource::Unknown     => {} // no map — use static pool only
    }
    crate::arch::x86_64::serial::serial_println!(
        "pmm: {} MiB total, {} MiB free",
        crate::mm::pmm::total_pages() * 4 / 1024,
        crate::mm::pmm::free_pages()  * 4 / 1024,
    );
}
