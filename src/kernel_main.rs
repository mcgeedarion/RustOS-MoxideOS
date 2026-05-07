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
//!   "TEST PASS: initramfs_load"      — /init ELF parsed and mapped

use crate::arch::api::{ArchInit, Serial};
use crate::arch::ArchImpl;

// CRT stub exported from src/crt/crt0.c.
extern "C" {
    fn run_init_array();
}

/// Kernel entry point.  Called from `_start` with interrupts disabled.
#[no_mangle]
pub extern "C" fn kernel_main(_hart_id: usize, _fdt_ptr: usize) -> ! {
    // ── 0. C/C++ global constructors ─────────────────────────────────────
    unsafe { run_init_array(); }

    // ── 1. Serial / UART init ────────────────────────────────────────
    ArchImpl::serial_init();
    println!("rustos: kernel_main reached");
    println!("TEST PASS: uart_smoke");

    // ── 2. Seed PRNG from TSC (must precede any entropy consumer) ────────
    crate::rand::seed_from_tsc();

    // ── 2b. Architecture early init ──────────────────────────────────
    ArchImpl::early_init();

    // ── 3. Physical memory manager ───────────────────────────────────
    crate::mm::pmm::init();

    // ── 4. Global allocator smoke test ──────────────────────────────
    {
        extern crate alloc;
        use alloc::vec::Vec;
        let mut v: Vec<u32> = Vec::new();
        v.push(0xdeadbeef);
        assert_eq!(v[0], 0xdeadbeef, "alloc_smoke: heap alloc failed");
    }
    println!("TEST PASS: alloc_smoke");

    // ── 5. Trap / interrupt init ────────────────────────────────────
    crate::arch::riscv64::trap::trap_init();
    println!("TEST PASS: trap_smoke");

    // ── 6. Architecture late init (enable interrupts) ─────────────────
    ArchImpl::late_init();

    // ── 7. PCIe + virtio devices ─────────────────────────────────────
    crate::drivers::pcie::init();
    crate::drivers::virtio_blk::init();
    // virtio-gpu: scan PCI, allocate pixel buffer, set scanout.
    // No-op if -device virtio-gpu-pci was not passed to QEMU.
    crate::drivers::virtio_gpu::init();
    if crate::drivers::virtio_gpu::is_present() {
        let (w, h) = crate::drivers::virtio_gpu::dimensions().unwrap_or((0, 0));
        println!("rustos: virtio-gpu ready  {}x{}", w, h);
    } else {
        println!("rustos: virtio-gpu not found, framebuffer via GOP");
    }

    // ── 8. Initramfs — locate /init, map it, build stack, enter userspace ──
    extern "C" {
        static INITRAMFS_BASE: usize;
        static INITRAMFS_SIZE: usize;
    }
    let (ramfs_base, ramfs_size) = unsafe { (INITRAMFS_BASE, INITRAMFS_SIZE) };

    if ramfs_base != 0 && ramfs_size != 0 {
        let cpio: &[u8] = unsafe {
            core::slice::from_raw_parts(ramfs_base as *const u8, ramfs_size)
        };

        match crate::initramfs::find_file(cpio, "/init") {
            Some(elf_bytes) => {
                println!("rustos: found /init ({} bytes), loading", elf_bytes.len());

                #[cfg(target_arch = "x86_64")]
                init_exec_x86_64(elf_bytes, cpio);

                #[cfg(target_arch = "riscv64")]
                init_exec_riscv64(elf_bytes, cpio);
            }
            None => println!("rustos: WARNING — /init not found in initramfs"),
        }
    } else {
        println!("rustos: no initramfs provided, skipping /init exec");
    }

    // ── 9. Idle loop (reached only when no initramfs / exec failed) ──────
    println!("rustos: entering idle loop");
    loop {
        crate::arch::api::Cpu::halt();
    }
}

// ── x86_64: load /init and sysret into it ───────────────────────────────

#[cfg(target_arch = "x86_64")]
fn init_exec_x86_64(elf_bytes: &[u8], cpio: &[u8]) -> ! {
    use crate::arch::x86_64::{paging, uentry};
    use crate::loader::{elf64, auxv};

    let cr3 = unsafe { paging::alloc_pml4() };

    let loaded = match elf64::load(elf_bytes, cr3) {
        Some(l) => l,
        None => panic!("rustos: elf64::load failed for /init"),
    };
    println!("rustos: /init entry={:#x} brk={:#x}", loaded.entry, loaded.brk);
    println!("TEST PASS: initramfs_load");

    let stack_top = uentry::alloc_user_stack(cr3)
        .expect("rustos: failed to allocate user stack");

    const PAGE: usize = 4096;
    let stack_page_va = stack_top - PAGE;
    let stack_buf: &mut [u8] = unsafe {
        core::slice::from_raw_parts_mut(stack_page_va as *mut u8, PAGE)
    };

    let argv: &[&str] = &["/init"];
    let envp: &[&str] = &["HOME=/", "PATH=/bin"];

    let user_rsp = auxv::write_initial_stack(
        stack_buf, stack_top, argv, envp, &loaded, elf_bytes,
    );

    println!("rustos: jumping to /init at {:#x}, RSP={:#x}", loaded.entry, user_rsp);
    unsafe { uentry::sysret_to_user(cr3, loaded.entry, user_rsp) }
}

// ── RISC-V: load /init and sret into it ──────────────────────────────

#[cfg(target_arch = "riscv64")]
fn init_exec_riscv64(elf_bytes: &[u8], _cpio: &[u8]) -> ! {
    use crate::arch::riscv64::{paging, uentry};
    use crate::loader::{elf64, auxv};

    let satp_ppn = unsafe { paging::alloc_root_page_table() };

    let loaded = match elf64::load(elf_bytes, satp_ppn) {
        Some(l) => l,
        None => panic!("rustos: elf64::load failed for /init"),
    };
    println!("rustos: /init entry={:#x} brk={:#x}", loaded.entry, loaded.brk);
    println!("TEST PASS: initramfs_load");

    let stack_top = uentry::alloc_user_stack(satp_ppn)
        .expect("rustos: failed to allocate user stack");

    const PAGE: usize = 4096;
    let stack_page_va = stack_top - PAGE;
    let stack_buf: &mut [u8] = unsafe {
        core::slice::from_raw_parts_mut(stack_page_va as *mut u8, PAGE)
    };

    let argv: &[&str] = &["/init"];
    let envp: &[&str] = &["HOME=/", "PATH=/bin"];

    let user_rsp = auxv::write_initial_stack(
        stack_buf, stack_top, argv, envp, &loaded, elf_bytes,
    );

    println!("rustos: jumping to /init at {:#x}, SP={:#x}", loaded.entry, user_rsp);
    unsafe { uentry::sret_to_user(satp_ppn, loaded.entry, user_rsp) }
}
