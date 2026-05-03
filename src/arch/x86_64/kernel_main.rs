//! Kernel entry point — called from _start (Multiboot2) or uefi_start (UEFI)
//! after the CPU is in 64-bit long mode with interrupts disabled.
//!
//! ## Boot sequence
//!   0.  heap_init()        — global allocator (must precede any alloc::)
//!   1.  gdt_init()         — GDT + TSS + GSBASE (must be before first #GP)
//!   2.  idt_init()         — IDT exception/IRQ vectors
//!   3.  syscall_setup()    — SYSCALL/SYSRET MSRs (LSTAR, STAR, FMASK)
//!   4.  serial::init()     — COM1 UART for early console output
//!   5.  xsave::xsave_init()— XSAVE/FXSAVE feature detection
//!   6.  acpi_init()        — RSDP → MADT: CPU list, I/O APIC addresses
//!   7.  apic_init()        — Local APIC + periodic timer (enables interrupts)
//!   8.  virtio_blk_init()  — virtio-blk block device at QEMU MMIO base
//!   9.  mount_root()       — ext2 or ramfs
//!  10.  spawn_init()       — PID 1 from /sbin/init, /bin/sh, or /init
//!  11.  idle loop          — hlt between timer ticks

use core::arch::asm;
use crate::arch::x86_64::{
    gdt::gdt_init,
    idt::idt_init,
    syscall::syscall_setup,
    serial,
    apic::apic_init,
    xsave::xsave_init,
};
use crate::block::virtio_blk;
use crate::proc::exec::spawn_user_process;

/// QEMU virt machine virtio-blk MMIO base address.
const VIRTIO_BLK_MMIO_BASE: usize = 0x1000_1000;

#[no_mangle]
pub extern "C" fn kernel_main() -> ! {
    // 0. Heap allocator — must be first; everything else may alloc.
    crate::allocator::heap_init();

    // 1. GDT + TSS + per-CPU GSBASE.
    gdt_init();

    // 2. IDT.
    idt_init();

    // 3. SYSCALL/SYSRET MSRs.
    syscall_setup();

    // 4. Serial console (COM1 / 0x3F8).
    serial::init();
    serial_println!("rustos: early boot");

    // 5. FP state save/restore (XSAVE or FXSAVE).
    xsave_init();
    serial_println!("xsave: init done");

    // 6. ACPI: CPU topology + I/O APIC addresses.
    let rsdp_pa = unsafe { crate::arch::x86_64::uefi_entry::RSDP_PHYS };
    crate::acpi::acpi_init(rsdp_pa);
    serial_println!("acpi: {} CPUs detected", crate::acpi::cpu_count());

    // 7. Local APIC + timer — enables preemption (issues STI).
    apic_init();
    serial_println!("apic: timer started, interrupts enabled");

    // 8. virtio-blk block device.
    virtio_blk::virtio_blk_init(VIRTIO_BLK_MMIO_BASE);
    serial_println!("virtio-blk: init");

    // 9. Mount root filesystem.
    let has_disk = {
        // Quick check: attempt to read sector 0; if it returns all-zeros
        // the disk isn't present but we won't crash.
        let mut buf = [0u8; 512];
        crate::block::virtio_blk::read_sector(0, &mut buf)
    };
    if has_disk {
        serial_println!("virtio-blk: disk present");
        if crate::fs::ext2::mount() {
            serial_println!("ext2: root mounted at /");
        } else {
            serial_println!("ext2: mount failed — ramfs only");
        }
    } else {
        serial_println!("virtio-blk: no disk — ramfs only");
    }

    // 10. Spawn PID 1.
    const CANDIDATES: &[&str] = &["/sbin/init", "/bin/sh", "/init", "/bin/bash"];
    let mut spawned = false;
    for path in CANDIDATES {
        if spawn_user_process(path, &[path], &[]) {
            serial_println!("init: PID 1 spawned from {}", path);
            spawned = true;
            break;
        }
    }
    if !spawned {
        serial_println!("init: WARNING — no init binary found");
        serial_println!("      drop a static /bin/sh ELF into the disk image");
    }

    // 11. Idle loop — schedule on every timer tick.
    serial_println!("kernel_main: entering idle loop");
    loop {
        unsafe { asm!("hlt", options(nostack, nomem)); }
        crate::proc::scheduler::schedule();
    }
}
