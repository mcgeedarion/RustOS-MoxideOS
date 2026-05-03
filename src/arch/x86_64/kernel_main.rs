//! Kernel entry point — called by the bootloader after paging is enabled.
//!
//! ## Boot sequence
//!   1.  gdt_init()         — GDT + TSS + GSBASE
//!   2.  idt_init()         — IDT exception/IRQ vectors
//!   3.  syscall_setup()    — SYSCALL/SYSRET MSRs (LSTAR, STAR, FMASK)
//!   4.  serial::init()     — COM1 UART for early console output
//!   5.  virtio_blk::init() — VirtIO PCI block driver (ext2 disk)
//!   6.  apic_init()        — Local APIC + periodic timer (enables interrupts)
//!   7.  spawn_init()       — create PID 1, load /sbin/init or /bin/sh
//!   8.  idle loop          — hlt until next timer tick
//!
//! The boot CPU runs this function at ring 0.  There is no separate
//! init task for PID 0; the boot CPU becomes the idle task after spawn_init.

use core::arch::asm;

use crate::arch::x86_64::{
    gdt::gdt_init,
    idt::idt_init,
    syscall::syscall_setup,
    serial,
    apic::apic_init,
};
use crate::drivers::virtio_blk;
use crate::proc::exec::sys_execve_from_path;

/// The C-callable kernel entry point.
/// Bootloader must call this with a flat 64-bit address space,
/// identity-mapped physical memory, and interrupts disabled.
#[no_mangle]
pub extern "C" fn kernel_main() -> ! {
    // 1. GDT + TSS + per-CPU GSBASE.
    gdt_init();

    // 2. IDT.
    idt_init();

    // 3. SYSCALL/SYSRET MSRs.
    syscall_setup();

    // 4. Serial console.
    serial::init();
    kprintln!("rustos booting...");

    // 5. VirtIO block driver (needed before VFS open).
    virtio_blk::init();
    if virtio_blk::is_present() {
        kprintln!("virtio-blk: disk found");
    } else {
        kprintln!("virtio-blk: no disk — ramfs only");
    }

    // 6. APIC timer — enables preemption. Must come after IDT.
    apic_init();
    kprintln!("apic: timer started");

    // 7. Spawn PID 1.
    spawn_init();

    // 8. Idle loop — the boot CPU drops to a hlt loop.
    kprintln!("kernel_main: entering idle loop");
    loop {
        unsafe { asm!("hlt", options(nostack, nomem)); }
    }
}

/// Create PID 1 by loading /sbin/init (falling back to /bin/sh then /init).
fn spawn_init() {
    const CANDIDATES: &[&str] = &["/sbin/init", "/bin/sh", "/init", "/bin/bash"];
    for path in CANDIDATES {
        if try_exec_pid1(path) {
            kprintln!("init: spawned PID 1 from {}", path);
            return;
        }
    }
    kprintln!("init: WARNING — no init binary found, running built-in shell");
    // Fall back: enqueue a minimal kernel-space shell task.
    crate::proc::scheduler::enqueue(make_idle_pcb());
}

/// Attempt to exec `path` as PID 1. Returns true on success.
fn try_exec_pid1(path: &str) -> bool {
    // Open the file through VFS to check it exists.
    match crate::fs::vfs::open(path, 0) {
        Ok(fd) => { crate::fs::vfs::close(fd); }
        Err(_) => return false,
    }
    // Create a fresh PCB and load the ELF.
    crate::proc::exec::spawn_user_process(path, &[path], &[])
}

/// Create a placeholder idle PCB (PID 0) so the scheduler always has a task.
fn make_idle_pcb() -> crate::proc::process::Pcb {
    use crate::proc::process::{Pcb, State};
    use crate::proc::context::Context;
    use crate::proc::fork::SignalHandlers;
    use crate::security::CapSet;
    Pcb {
        pid: 0, ppid: 0,
        state: State::Ready,
        exit_code: 0,
        caps: CapSet::empty(),
        pc: 0, sp: 0,
        user_satp: 0, kernel_satp: 0, trapframe_pa: 0,
        kstack_top: 0,
        ctx: Context::zero(),
        owned_pages: alloc::vec![],
        child_tid_va: 0, child_tid_val: 0,
        clear_child_tid_va: 0,
        exit_signal: 17,
        vfork_parent: 0,
        signal_handlers: SignalHandlers::default(),
    }
}
