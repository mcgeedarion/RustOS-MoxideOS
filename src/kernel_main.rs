//! Architecture-independent kernel entry point.
//!
//! Called by the arch boot stub (_start) after a minimal stack is set up.
//! Performs subsystem init in order, prints CI sentinels, then enters the
//! scheduler idle loop.
//!
//! ## CI sentinels (must appear on serial/stdout for the smoke tests to pass)
//!   "rustos: kernel_main reached"    — boot smoke test
//!   "TEST PASS: uart_smoke"          — UART is functional
//!   "TEST PASS: alloc_smoke"         — global allocator is functional
//!   "TEST PASS: trap_smoke"          — trap handler is wired up

use crate::arch::api::{ArchInit, Serial};
use crate::arch::ArchImpl;

// CRT stub exported from src/crt/crt0.c.
// Walks __init_array_start..__init_array_end and calls each constructor.
// This is a no-op when no C/C++ globals with constructors are linked.
extern "C" {
    fn run_init_array();
}

/// Kernel entry point.  Called from `_start` with interrupts disabled.
///
/// # Arguments
/// * `hart_id`  — RISC-V hart ID (0 on single-core QEMU virt)
/// * `fdt_ptr`  — physical address of the Flattened Device Tree blob
#[no_mangle]
pub extern "C" fn kernel_main(_hart_id: usize, _fdt_ptr: usize) -> ! {
    // ── 0. C/C++ global constructors ─────────────────────────────────────
    // Must run before any C++ objects with non-trivial constructors are used.
    // Safe to call unconditionally — no-op when .init_array is empty.
    unsafe { run_init_array(); }

    // ── 1. Serial / UART init ────────────────────────────────────────────
    ArchImpl::serial_init();

    // Boot sentinel — CI boot smoke test checks for this exact string.
    println!("rustos: kernel_main reached");
    println!("TEST PASS: uart_smoke");

    // ── 2. Architecture early init (stvec, mmu stubs) ───────────────────
    ArchImpl::early_init();

    // ── 3. Physical memory manager ───────────────────────────────────────
    crate::mm::pmm::init();

    // ── 4. Global allocator smoke test ──────────────────────────────────
    {
        extern crate alloc;
        use alloc::vec::Vec;
        let mut v: Vec<u32> = Vec::new();
        v.push(0xdeadbeef);
        assert_eq!(v[0], 0xdeadbeef, "alloc_smoke: heap alloc failed");
    }
    println!("TEST PASS: alloc_smoke");

    // ── 5. Trap / interrupt init ─────────────────────────────────────────
    crate::arch::riscv64::trap::trap_init();
    println!("TEST PASS: trap_smoke");

    // ── 6. Architecture late init (enable interrupts) ────────────────────
    ArchImpl::late_init();

    // ── 7. Initramfs — locate and exec /init ─────────────────────────────
    //
    // The CPIO archive base address and byte length come from the boot
    // protocol.  Multiboot2 passes them as a module tag; UEFI stores them
    // in a config table entry.  Both paths should set INITRAMFS_BASE /
    // INITRAMFS_SIZE before jumping to kernel_main.
    //
    // For now we read two linker-exported symbols that build_x86.sh / the
    // UEFI stub will populate.  If neither is present (bare QEMU without
    // -initrd) the symbols are zero and we skip the exec path gracefully.
    extern "C" {
        /// Physical address of the CPIO archive in memory.
        /// Set to 0 if no initramfs was provided.
        static INITRAMFS_BASE: usize;
        /// Byte length of the CPIO archive.
        /// Set to 0 if no initramfs was provided.
        static INITRAMFS_SIZE: usize;
    }

    // Safety: these are linker-defined symbols; reading them is always safe.
    let (ramfs_base, ramfs_size) = unsafe { (INITRAMFS_BASE, INITRAMFS_SIZE) };

    if ramfs_base != 0 && ramfs_size != 0 {
        // Build a slice over the CPIO archive (identity-mapped PA = VA here).
        // Safety: QEMU / bootloader guarantees this memory is readable.
        let cpio: &[u8] = unsafe {
            core::slice::from_raw_parts(ramfs_base as *const u8, ramfs_size)
        };

        match crate::initramfs::find_file(cpio, "/init") {
            Some(elf_bytes) => {
                println!("rustos: found /init in initramfs ({} bytes)", elf_bytes.len());

                // Allocate a fresh page table for the init process.
                // TODO: replace with proc::new_address_space() when the
                //       process table is wired up.
                #[cfg(target_arch = "x86_64")]
                let cr3 = unsafe { crate::arch::x86_64::paging::alloc_pml4() };

                #[cfg(target_arch = "x86_64")]
                match crate::loader::elf64::load(elf_bytes, cr3) {
                    Some(loaded) => {
                        println!("rustos: /init loaded, entry={:#x} brk={:#x}",
                                 loaded.entry, loaded.brk);
                        // TODO: allocate user stack page, call
                        //   auxv::write_initial_stack(), then sysret to
                        //   loaded.entry.  Blocked on proc::exec integration.
                        println!("TEST PASS: initramfs_load");
                    }
                    None => {
                        println!("rustos: ERROR — elf64::load() failed for /init");
                    }
                }
            }
            None => {
                println!("rustos: WARNING — /init not found in initramfs");
            }
        }
    } else {
        println!("rustos: no initramfs provided, skipping /init exec");
    }

    // ── 8. Idle loop ─────────────────────────────────────────────────────
    println!("rustos: entering idle loop");
    loop {
        crate::arch::api::Cpu::halt();
    }
}
