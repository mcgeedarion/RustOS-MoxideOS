//! Kernel entry point — called from _start after the CPU is in 64-bit long mode.
//!
//! ## Boot sequence
//!   1.  gdt_init()         — GDT + TSS + GSBASE (must be first)
//!   2.  idt_init()         — IDT exception/IRQ vectors
//!   3.  syscall_setup()    — SYSCALL/SYSRET MSRs (LSTAR, STAR, FMASK)
//!   4.  serial::init()     — COM1 UART for early console output
//!   5.  virtio_blk::init() — VirtIO PCI block driver (ext2 disk)
//!   6.  apic_init()        — Local APIC + periodic timer (enables interrupts)
//!   7.  spawn_init()       — create PID 1, load /sbin/init or /bin/sh
//!   8.  idle loop          — hlt until next timer tick

use core::arch::asm;

use crate::arch::x86_64::{
    gdt::gdt_init,
    idt::idt_init,
    syscall::syscall_setup,
    serial,
    apic::apic_init,
};
use crate::drivers::virtio_blk;
use crate::proc::exec::spawn_user_process;

/// Kernel entry point. Bootloader jumps here with:
///   - 64-bit long mode active
///   - identity-mapped physical memory (PA == VA)
///   - interrupts disabled (we enable them in apic_init)
#[no_mangle]
pub extern "C" fn kernel_main() -> ! {
    // 1. GDT + TSS + per-CPU GSBASE.
    gdt_init();

    // 2. IDT.
    idt_init();

    // 3. SYSCALL/SYSRET MSRs.
    syscall_setup();

    // 4. Serial console (COM1 / 0x3F8).
    serial::init();
    serial_println!("rustos: booting...");

    // 5. VirtIO block driver.
    virtio_blk::init();
    if virtio_blk::is_present() {
        serial_println!("virtio-blk: disk found");
    } else {
        serial_println!("virtio-blk: no disk — ramfs only");
    }

    // 6. APIC timer — enables preemption (calls sti).
    apic_init();
    serial_println!("apic: timer started");

    // 7. Spawn PID 1.
    const CANDIDATES: &[&str] = &["/sbin/init", "/bin/sh", "/init", "/bin/bash"];
    let mut spawned = false;
    for path in CANDIDATES {
        if spawn_user_process(path, &[path], &[]) {
            serial_println!("init: spawned PID 1 from {}", path);
            spawned = true;
            break;
        }
    }
    if !spawned {
        serial_println!("init: WARNING — no init binary found in ramfs");
    }

    // 8. Idle: schedule on every timer tick, hlt between ticks.
    serial_println!("kernel_main: idle loop");
    loop {
        unsafe { asm!("hlt", options(nostack, nomem)); }
        crate::proc::scheduler::schedule();
    }
}
