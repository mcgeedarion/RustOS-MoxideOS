//! Multiboot2 header — placed at the very start of the `.multiboot` section.
//!
//! When booted via GRUB2 or `qemu -kernel`, the firmware/QEMU loader
//! scans the first 32 KiB of the ELF image for the 4-byte magic 0xE85250D6.
//! Finding it, it enters the kernel in 32-bit protected mode with:
//!   - EAX = 0x36D76289  (Multiboot2 magic)
//!   - EBX = physical address of the Multiboot2 information structure
//!   - CS  = flat 32-bit code segment
//!   - Interrupts disabled
//!
//! Because we target x86-64 long mode we can't use Multiboot2 32-bit entry
//! directly with SYSRET — we need a small 32→64-bit trampoline.  However,
//! QEMU's `-kernel` path for ELF64 images automatically enters long mode
//! before jumping to the entry point, so on QEMU we go straight to
//! `_start` (defined in main.rs) which sets up RSP and calls kernel_main.
//!
//! The header below tells the loader:
//!   - We want the memory map tag (type 6).
//!   - We want framebuffer info (type 5) — text mode 80×25.
//!   - No module alignment required.

/// Section placed first in `.text.boot` so the linker script puts it
/// at offset 0 inside the binary (within the first 32 KiB).
#[link_section = ".text.boot"]
#[used]
static MULTIBOOT2_HEADER: Multiboot2Header = Multiboot2Header::new();

// Header total size = 16 (fixed) + 8 (end tag) + 20 (mmap tag) + 20 (fb tag) = 64 bytes
const HEADER_LEN: u32 = 64;

#[repr(C, align(8))]
struct Multiboot2Header {
    // Fixed part
    magic:        u32,  // 0xE85250D6
    arch:         u32,  // 0 = i386/x86-64
    header_len:   u32,
    checksum:     u32,  // -(magic + arch + len)

    // Tag: information request (type 1) — ask for memory map (6)
    tag1_type:    u16,
    tag1_flags:   u16,
    tag1_size:    u32,
    tag1_request: u32,  // tag type 6 = memory map
    tag1_pad:     u32,

    // Tag: framebuffer (type 5) — request text mode
    tag5_type:    u16,
    tag5_flags:   u16,
    tag5_size:    u32,
    tag5_width:   u32,  // 0 = don't care
    tag5_height:  u32,
    tag5_depth:   u32,  // 0 = text mode

    // End tag (type 0)
    end_type:  u16,
    end_flags: u16,
    end_size:  u32,
}

impl Multiboot2Header {
    const fn new() -> Self {
        const MAGIC: u32 = 0xE85250D6;
        const ARCH:  u32 = 0;
        const CHECKSUM: u32 = (0u32
            .wrapping_sub(MAGIC)
            .wrapping_sub(ARCH)
            .wrapping_sub(HEADER_LEN));
        Multiboot2Header {
            magic:        MAGIC,
            arch:         ARCH,
            header_len:   HEADER_LEN,
            checksum:     CHECKSUM,
            tag1_type:    1,
            tag1_flags:   0,
            tag1_size:    12,
            tag1_request: 6,   // memory map
            tag1_pad:     0,
            tag5_type:    5,
            tag5_flags:   0,
            tag5_size:    20,
            tag5_width:   80,
            tag5_height:  25,
            tag5_depth:   0,   // text mode
            end_type:     0,
            end_flags:    0,
            end_size:     8,
        }
    }
}
