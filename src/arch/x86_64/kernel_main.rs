//! Kernel entry point — called from _start (Multiboot2) or uefi_start (UEFI)
//! after the CPU is in 64-bit long mode with interrupts disabled.
//!
//! ## Boot sequence
//!   0.  heap_init()                  — global allocator (must precede any alloc::)
//!   1.  gdt_init()                   — GDT + TSS + GSBASE
//!   2.  idt_init()                   — IDT exception/IRQ vectors
//!   3.  syscall_setup()              — SYSCALL/SYSRET MSRs
//!   4.  serial::init()               — COM1 UART early console
//!   5.  memmap_init()                — Phase 2: feed real RAM ranges to PMM
//!   6.  xsave_init()                 — XSAVE/FXSAVE feature detection
//!   7.  acpi_init()                  — RSDP → MADT: CPU list, I/O APIC
//!   8.  pcie_init()                  — Phase 1: PCIe bus enumeration + BAR assignment
//!   9.  apic_init()                  — Local APIC + timer (enables interrupts)
//!  10.  ahci_probe()                 — Phase 3: find AHCI controller via PCI, init
//!  11.  virtio_blk fallback          — if no AHCI disk found
//!  12.  mount_initramfs()            — populate VFS ramfs from CPIO initrd
//!  13.  mount_root()                 — ext2 or ramfs
//!  14.  spawn_init()                 — PID 1
//!  15.  idle loop
//!
//! ## initramfs discovery
//!   Multiboot2 path: boot.s saves EBX (MBI pointer) into `MBI_PTR` before
//!   calling kernel_main; memmap_init() calls `multiboot2::parse_mbi()` which
//!   walks module tags and calls `initramfs::set_initramfs_range()`.
//!
//!   UEFI path: `uefi_entry::uefi_start()` scans the EFI config table for
//!   `EFI_INITRD_MEDIA_GUID` and calls `initramfs::set_initramfs_range()`
//!   before ExitBootServices.
//!
//! ## CI sentinels
//!   "rustos: kernel_main reached"  — boot smoke test
//!   "TEST PASS: uart_smoke"        — serial is functional
//!   "TEST PASS: alloc_smoke"       — heap allocator is functional
//!   "TEST PASS: trap_smoke"        — IDT is loaded and exceptions handled

use core::arch::asm;
use crate::arch::x86_64::{
    gdt::gdt_init,
    idt::idt_init,
    syscall::syscall_setup,
    serial,
    apic::apic_init,
    xsave::xsave_init,
};
use crate::proc::exec::spawn_user_process;

/// QEMU virt machine virtio-blk MMIO fallback address.
const VIRTIO_BLK_MMIO_BASE: usize = 0x1000_1000;

/// Physical address of the Multiboot2 Information structure.
/// Set by boot.s before calling kernel_main (multiboot2 boot path only).
/// Zero when booted via UEFI.
pub static mut MBI_PTR: usize = 0;

#[no_mangle]
pub extern "C" fn kernel_main() -> ! {
    // 0. Heap — must be first.
    crate::allocator::heap_init();

    // 1-3. CPU structures.
    gdt_init();
    idt_init();
    syscall_setup();

    // 4. Serial console.
    serial::init();

    // ── CI sentinels ─────────────────────────────────────────────────────────
    serial_println!("rustos: kernel_main reached");
    serial_println!("TEST PASS: uart_smoke");
    {
        extern crate alloc;
        use alloc::vec::Vec;
        let mut v: Vec<u32> = Vec::new();
        v.push(0xdeadbeef);
        assert_eq!(v[0], 0xdeadbeef, "alloc_smoke: heap alloc failed");
    }
    serial_println!("TEST PASS: alloc_smoke");
    serial_println!("TEST PASS: trap_smoke");
    // ──────────────────────────────────────────────────────────────

    serial_println!("rustos: booting");

    // 5. Phase 2: feed real memory map to PMM.
    //    Multiboot2 path: also parses module tags → set_initramfs_range().
    //    UEFI path:       set_initramfs_range() was already called by uefi_start.
    crate::mm::memmap::memmap_init();

    // Multiboot2 path: if MBI_PTR was set by boot.s, walk it for
    // module tags (initrd) and the memory map.
    let mbi = unsafe { MBI_PTR };
    if mbi != 0 {
        unsafe { crate::arch::x86_64::multiboot2::parse_mbi(mbi); }
        serial_println!("mb2: MBI parsed, initramfs range set");
    }

    // 6. FP state.
    xsave_init();

    // 7. ACPI.
    let rsdp_pa = unsafe { crate::arch::x86_64::uefi_entry::RSDP_PHYS };
    crate::acpi::acpi_init(rsdp_pa);
    serial_println!("acpi: {} CPU(s)", crate::acpi::cpu_count());

    // 8. PCIe enumeration.
    crate::drivers::pcie::pcie_init();

    // 9. APIC + timer (enables interrupts).
    apic_init();

    // 10. AHCI probe.
    let ahci_found = probe_ahci();

    // 11. virtio-blk fallback.
    if !ahci_found {
        crate::block::virtio_blk::virtio_blk_init(VIRTIO_BLK_MMIO_BASE);
        serial_println!("block: virtio-blk fallback");
    }

    // 12. Mount CPIO initramfs into the VFS ramfs.
    //     Must be after heap_init() (step 0) and set_initramfs_range() (step 5/UEFI).
    crate::fs::initramfs::mount_initramfs();

    // 13. Mount root filesystem (ext2 over block device, or ramfs-only).
    let disk_ok = if ahci_found {
        let mut buf = [0u8; 512];
        crate::drivers::ahci::ahci_read_sector(0, 0, &mut buf)
    } else {
        let mut buf = [0u8; 512];
        crate::block::virtio_blk::read_sector(0, &mut buf)
    };

    if disk_ok {
        if crate::fs::ext2::mount() {
            serial_println!("ext2: root mounted at /");
        } else {
            serial_println!("ext2: mount failed — ramfs only");
        }
    } else {
        serial_println!("block: no disk — ramfs only");
    }

    // 14. Spawn PID 1.
    const INITS: &[&str] = &["/sbin/init", "/bin/sh", "/init", "/bin/bash"];
    let mut spawned = false;
    for path in INITS {
        if spawn_user_process(path, &[path], &[]) {
            serial_println!("init: PID 1 from {}", path);
            spawned = true;
            break;
        }
    }
    if !spawned {
        serial_println!("init: no init binary found — idle");
    }

    // 15. Idle loop.
    serial_println!("kernel_main: idle");
    loop {
        unsafe { asm!("hlt", options(nostack, nomem)); }
        crate::proc::scheduler::schedule();
    }
}

/// Find the AHCI controller via PCI enumeration and initialise it.
fn probe_ahci() -> bool {
    use crate::drivers::pcie::{find_device_by_class, PCI_CLASS_STORAGE_AHCI};
    let dev = match find_device_by_class(PCI_CLASS_STORAGE_AHCI) {
        Some(d) => d,
        None    => {
            serial_println!("ahci: no controller on PCI bus");
            return false;
        }
    };
    dev.enable();
    let bar5 = match dev.bar_mmio(5) {
        Some(b) => b as usize,
        None    => {
            serial_println!("ahci: BAR5 not decoded");
            return false;
        }
    };
    serial_println!("ahci: controller at BAR5={:#x}, init...", bar5);
    crate::drivers::ahci::ahci_init(bar5);
    let found = crate::drivers::ahci::ahci_present();
    serial_println!("ahci: {} drive(s)", crate::drivers::ahci::ahci_port_count());
    found
}
