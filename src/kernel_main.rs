//! Architecture-independent kernel entry points and init-process launcher.
//!
//! Two entry points exist, selected at compile time by target architecture:
//!   - `kernel_main_x86_64`   — called from multiboot2_entry() or uefi_start()
//!   - `kernel_main_riscv64`  — called from the RISC-V SBI stub (boot.rs)
//!
//! x86_64 boot sequence:
//!   1. serial::init()          — UART output
//!   2. pmm::init()             — physical memory manager
//!   3. heap::init()            — slab allocator over PMM
//!   4. initramfs::mount()      — populate VFS from CPIO
//!   5. gdt::init()             — GDT + TSS
//!   6. idt::init()             — IDT / exception vectors
//!   7. apic::init()            — local + IO APIC, timer IRQ
//!   8. time::init()            — clocksource calibration (TSC/HPET), timerfd, itimers
//!   9. smp::init()             — enumerate MADT CPUs, bring up APs
//!  10. tty::init()             — PTY registry + /dev/pts
//!  11. spawn pid 1 from /init  — scheduler takes over
//!
//! RISC-V boot sequence:
//!   1. trap_init()             — install stvec, enable SIE (must be first)
//!   2. init_from_fdt()         — parse FDT /memory + /chosen → PMM + initramfs range
//!   3. heap::init()            — slab/linked-list allocator over PMM
//!   4. initramfs::mount()      — populate VFS from CPIO
//!   5. time::init()            — calibrate CLINT mtime clocksource, timerfd, itimers
//!   6. smp::init()             — SBI HSM hart bringup
//!   7. tty::init()             — PTY registry + /dev/pts
//!   8. spawn pid 1 from /init  — scheduler takes over

#![allow(unused_imports)]

use crate::initramfs;

// ── x86_64 entry ──────────────────────────────────────────────────────────────

#[cfg(target_arch = "x86_64")]
pub fn kernel_main_x86_64() {
    use crate::arch::x86_64::{apic, gdt, idt, serial};
    use crate::mm::{heap, pmm};

    serial::init();
    crate::println!("rustos: x86_64 kernel starting");

    pmm::init();
    heap::init();

    // Mount the initramfs into the VFS before anything can call open(2).
    crate::fs::initramfs::mount_initramfs();

    gdt::init();
    idt::init();
    apic::init();
    crate::time::init();
    crate::smp::init();
    crate::tty::init();

    crate::println!("rustos: subsystems initialised — launching /init");

    // Locate /init bytes directly in the CPIO slice (no VFS open needed at
    // this point; mount_initramfs has already populated the VFS for later
    // open() calls from user-space).
    let handle   = initramfs::load();
    let elf_bytes = match handle.file("/init") {
        Some(b) => b,
        None => {
            crate::println!("rustos: FATAL: /init not found in initramfs");
            loop { unsafe { core::arch::asm!("hlt"); } }
        }
    };

    // Spawn pid 1: load the ELF, build the initial stack, enqueue in the
    // scheduler.  The scheduler's first context switch will jump to entry.
    if !crate::proc::exec::spawn_user_process_from_bytes(elf_bytes, "/init", &["/init"], &[]) {
        crate::println!("rustos: FATAL: failed to spawn /init");
        loop { unsafe { core::arch::asm!("hlt"); } }
    }
    crate::println!("rustos: pid 1 enqueued");
    crate::println!("TEST PASS: initramfs_load");

    // Hand control to the scheduler — does not return.
    crate::proc::scheduler::run();
}

// ── RISC-V entry ───────────────────────────────────────────────────────────────

/// Called by `_start` in `arch/riscv64/boot.rs` with:
///   `hart_id` = value of a0 from OpenSBI
///   `fdt_ptr` = value of a1 from OpenSBI (physical address of FDT blob)
#[cfg(target_arch = "riscv64")]
pub fn kernel_main_riscv64(hart_id: usize, fdt_ptr: usize) {
    use crate::arch::riscv64::trap;
    use crate::mm::{heap, pmm};

    // 1. Trap vector MUST be first — any fault before this is unrecoverable.
    trap::trap_init();

    crate::println!("rustos: riscv64 kernel starting (hart {})", hart_id);

    // 2. Walk the FDT: registers /memory regions with PMM and records the
    //    initramfs range from /chosen linux,initrd-start/end.
    unsafe { crate::arch::riscv64::fdt::init_from_fdt(fdt_ptr); }
    crate::println!(
        "pmm: {} MiB total, {} MiB free",
        pmm::total_pages() * 4 / 1024,
        pmm::free_pages()  * 4 / 1024,
    );

    // 3. Heap over the real PMM.
    heap::init();

    // 4. Mount the initramfs into the VFS.
    crate::fs::initramfs::mount_initramfs();

    // 5. Timekeeping.
    crate::time::init();

    // 6. Bring up additional harts via SBI HSM.
    crate::smp::init();

    // 7. PTY registry + /dev/pts.
    crate::tty::init();

    crate::println!("rustos: riscv64 subsystems initialised — launching /init");

    // 8. Spawn pid 1.
    let handle    = initramfs::load();
    let elf_bytes = match handle.file("/init") {
        Some(b) => b,
        None => {
            crate::println!("rustos: FATAL: /init not found in initramfs");
            loop { unsafe { core::arch::asm!("wfi"); } }
        }
    };

    if !crate::proc::exec::spawn_user_process_from_bytes(elf_bytes, "/init", &["/init"], &[]) {
        crate::println!("rustos: FATAL: failed to spawn /init");
        loop { unsafe { core::arch::asm!("wfi"); } }
    }
    crate::println!("rustos: pid 1 enqueued");
    crate::println!("TEST PASS: initramfs_load");

    // 9. Hand control to the scheduler — does not return.
    crate::proc::scheduler::run();
}
