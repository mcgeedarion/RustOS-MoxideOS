//! Architecture-independent kernel entry points and init-process launcher.
//!
//! Two entry points exist, selected at compile time by target architecture:
//!   - `kernel_main` (x86_64)   — called from multiboot2_entry() or uefi_start()
//!   - `kernel_main_riscv64`    — called from the RISC-V SBI stub (boot.rs)
//!
//! x86_64 boot sequence:
//!   1. serial::init()    — UART output
//!   2. pmm::init()       — physical memory manager
//!   3. heap::init()      — slab allocator over PMM
//!   4. gdt::init()       — GDT + TSS
//!   5. idt::init()       — IDT / exception vectors
//!   6. apic::init()      — local + IO APIC, timer IRQ
//!   7. time::init()      — clocksource calibration (TSC/HPET), timerfd, itimers
//!   8. smp::init()       — enumerate MADT CPUs, bring up APs
//!   9. tty::init()       — PTY registry + /dev/pts
//!  10. Load /init from initramfs → userspace
//!
//! RISC-V boot sequence:
//!   1. trap_init()       — install stvec, enable SIE (must be first)
//!   2. init_from_fdt()   — parse FDT /memory + /chosen → PMM + initramfs range
//!   3. heap::init()      — slab/linked-list allocator over PMM
//!   4. time::init()      — calibrate CLINT mtime clocksource, timerfd, itimers
//!   5. smp::init()       — SBI HSM hart bringup
//!   6. tty::init()       — PTY registry + /dev/pts
//!   7. Load /init from initramfs → userspace

#![allow(unused_imports)]

use crate::initramfs;

// ── x86_64 entry ──────────────────────────────────────────────────────────────
// (The real x86_64 entry lives in src/arch/x86_64/kernel_main.rs)

#[cfg(target_arch = "x86_64")]
pub fn kernel_main_x86_64() {
    use crate::arch::x86_64::{apic, gdt, idt, paging, serial, uentry};
    use crate::loader::{elf64, auxv};
    use crate::mm::{heap, pmm};

    serial::init();
    crate::println!("rustos: x86_64 kernel starting");

    pmm::init();
    heap::init();
    gdt::init();
    idt::init();
    apic::init();
    crate::time::init();
    crate::smp::init();
    crate::tty::init();

    crate::println!("rustos: subsystems initialised");

    let initramfs = initramfs::load();
    let elf_bytes = match initramfs.file("/init") {
        Some(b) => b,
        None => {
            crate::println!("rustos: FATAL: /init not found in initramfs");
            loop { unsafe { core::arch::asm!("hlt"); } }
        }
    };

    let cr3 = unsafe { paging::alloc_pml4() };
    let loaded = match elf64::load(elf_bytes, cr3) {
        Some(l) => l,
        None => {
            crate::println!("rustos: FATAL: elf64::load failed for /init");
            loop { unsafe { core::arch::asm!("hlt"); } }
        }
    };
    crate::println!("rustos: /init entry={:#x} brk={:#x}", loaded.entry, loaded.brk);
    crate::println!("TEST PASS: initramfs_load");

    let stack_top = match uentry::alloc_user_stack(cr3) {
        Some(t) => t,
        None => {
            crate::println!("rustos: FATAL: failed to allocate user stack (OOM)");
            loop { unsafe { core::arch::asm!("hlt"); } }
        }
    };

    const PAGE: usize = 4096;
    let stack_page_va = stack_top - PAGE;
    let stack_buf: &mut [u8] = unsafe {
        core::slice::from_raw_parts_mut(stack_page_va as *mut u8, PAGE)
    };
    let sp = auxv::build_stack(
        stack_buf, stack_top, &["/init"], &[],
        loaded.entry, loaded.phdr_va, loaded.phdr_count, loaded.phdr_size,
    );
    crate::println!("rustos: jumping to /init entry={:#x} sp={:#x}", loaded.entry, sp);
    unsafe { uentry::jump_to_user(loaded.entry, sp, cr3); }
}

// ── RISC-V entry ───────────────────────────────────────────────────────────────

/// Called by `_start` in `arch/riscv64/boot.rs` with:
///   `hart_id`  = value of a0 from OpenSBI
///   `fdt_ptr`  = value of a1 from OpenSBI (physical address of FDT blob)
#[cfg(target_arch = "riscv64")]
pub fn kernel_main_riscv64(hart_id: usize, fdt_ptr: usize) {
    use crate::arch::riscv64::{paging, trap, uentry};
    use crate::loader::{elf64, auxv};
    use crate::mm::{heap, pmm};

    // 1. Trap vector MUST be first — any fault before this is unrecoverable.
    trap::trap_init();

    crate::println!("rustos: riscv64 kernel starting (hart {})", hart_id);

    // 2. Walk the FDT: registers /memory regions with PMM and records the
    //    initramfs range from /chosen linux,initrd-start/end.
    //    This replaces the old pmm::init_from_fdt() stub and must come before
    //    heap::init() so the PMM free list is populated first.
    unsafe { crate::arch::riscv64::fdt::init_from_fdt(fdt_ptr); }
    crate::println!(
        "pmm: {} MiB total, {} MiB free",
        pmm::total_pages() * 4 / 1024,
        pmm::free_pages()  * 4 / 1024,
    );

    // 3. Heap over the real PMM.
    heap::init();

    // 4. Timekeeping.
    crate::time::init();

    // 5. Bring up additional harts via SBI HSM.
    crate::smp::init();

    // 6. PTY registry + /dev/pts.
    crate::tty::init();

    crate::println!("rustos: riscv64 subsystems initialised");

    // 7. Load /init and jump to userspace.
    //    initramfs::load() will use the range set by init_from_fdt() above.
    let initramfs = initramfs::load();
    let elf_bytes = match initramfs.file("/init") {
        Some(b) => b,
        None => {
            crate::println!("rustos: FATAL: /init not found in initramfs");
            loop { unsafe { core::arch::asm!("wfi"); } }
        }
    };

    let satp_ppn = unsafe { paging::alloc_root_page_table() };
    let loaded = match elf64::load(elf_bytes, satp_ppn) {
        Some(l) => l,
        None => {
            crate::println!("rustos: FATAL: elf64::load failed for /init");
            loop { unsafe { core::arch::asm!("wfi"); } }
        }
    };
    crate::println!("rustos: /init entry={:#x} brk={:#x}", loaded.entry, loaded.brk);
    crate::println!("TEST PASS: initramfs_load");

    let stack_top = match uentry::alloc_user_stack(satp_ppn) {
        Some(t) => t,
        None => {
            crate::println!("rustos: FATAL: failed to allocate user stack (OOM)");
            loop { unsafe { core::arch::asm!("wfi"); } }
        }
    };

    const PAGE: usize = 4096;
    let stack_page_va = stack_top - PAGE;
    let stack_buf: &mut [u8] = unsafe {
        core::slice::from_raw_parts_mut(stack_page_va as *mut u8, PAGE)
    };
    let sp = auxv::build_stack(
        stack_buf, stack_top, &["/init"], &[],
        loaded.entry, loaded.phdr_va, loaded.phdr_count, loaded.phdr_size,
    );
    crate::println!("rustos: jumping to /init entry={:#x} sp={:#x}", loaded.entry, sp);
    unsafe { uentry::jump_to_user(loaded.entry, sp, satp_ppn); }
}
