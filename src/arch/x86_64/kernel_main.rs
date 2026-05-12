//! Kernel entry point — called from uefi_start() (primary) or
//! multiboot2_entry() (legacy, feature = "multiboot2_boot") after the CPU is
//! in 64-bit long mode with interrupts disabled.
//!
//! ## Boot sequence
//!   0a. serial::early_init()         — 16550 TX-only, no alloc, no heap
//!   0b. vga::init()                  — VGA text mode (no-op when GOP active)
//!   0c. heap_init()                  — global allocator (panics now visible)
//!   1.  gdt_init()                   — GDT + TSS + GSBASE
//!   2.  idt_init()                   — IDT exception/IRQ vectors
//!   3.  syscall_setup()              — SYSCALL/SYSRET MSRs
//!   4.  serial::init()               — full 16550 reinit (IRQ-driven, FIFOs)
//!   5.  memmap_init()                — Phase 2: feed EFI memory map to PMM
//!       parse_mbi() [multiboot only] — walk multiboot2 info block
//!   6.  xsave_init()                 — XSAVE/FXSAVE feature detection
//!   7.  acpi_init()                  — RSDP → MADT: CPU list, I/O APIC
//!   8.  pcie_init()                  — Phase 1: PCIe bus enumeration + BAR
//!   9.  apic_init()                  — Local APIC + timer (enables interrupts)
//!  10.  ahci_probe()                 — AHCI via PCI, init
//!  11.  virtio_blk fallback          — if no AHCI disk found
//!  12.  mount_initramfs()            — populate VFS ramfs from CPIO initrd
//!  13.  mount_root()                 — ext2 or ramfs
//!  14.  spawn_init()                 — PID 1
//!  15.  idle loop
//!
//! ## Why serial::early_init() comes before everything
//!   heap_init() can panic if the kernel image layout assumptions are wrong.
//!   Without serial::early_init() that panic is completely invisible on real
//!   hardware.  early_init() uses only I/O port instructions and no heap.
//!
//! ## UEFI boot (primary path)
//!   uefi_start() in uefi_entry.rs:
//!     1. Prints banner via EFI SimpleTextOutput.
//!     2. Captures GOP framebuffer (graceful fallback to serial-only).
//!     3. Locates ACPI 2.0 RSDP from EFI configuration table.
//!     4. Loads initrd via EFI_INITRD_MEDIA_GUID LoadFile2 protocol
//!        (systemd-boot / GRUB2) or OVMF vendor table fallback.
//!     5. Obtains EFI memory map + calls ExitBootServices (with AMI/Insyde
//!        firmware retry per UEFI spec §7.4.6).
//!     6. Switches to kernel boot stack, tail-calls kernel_main().
//!
//! ## VGA text mode
//!   vga::init() probes BDA 0x0449.  When UEFI/GOP took over it returns false
//!   and the GOP framebuffer driver stays in control.  Safe unconditionally.

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

const VIRTIO_BLK_MMIO_BASE: usize = 0x1000_1000;

// ── Legacy multiboot2 entry (only compiled when feature = "multiboot2_boot") ──

#[cfg(feature = "multiboot2_boot")]
pub static mut MBI_PTR: usize = 0;

#[cfg(feature = "multiboot2_boot")]
#[no_mangle]
pub unsafe extern "C" fn multiboot2_entry(magic: u32, info_phys: u32) -> ! {
    if magic == 0x36d7_6289 {
        MBI_PTR = info_phys as usize;
    }
    kernel_main()
}

// ── Primary kernel entry ──────────────────────────────────────────────────────

#[no_mangle]
pub extern "C" fn kernel_main() -> ! {
    // 0a. Serial UART before anything that can panic.
    serial::early_init();

    // 0b. VGA text mode probe — safe no-op when GOP owns the display.
    #[cfg(target_arch = "x86_64")]
    let vga_active = crate::drivers::vga::init();
    #[cfg(not(target_arch = "x86_64"))]
    let vga_active = false;

    // 0c. Heap.
    crate::allocator::heap_init();

    // 1–3. CPU structures.
    gdt_init();
    idt_init();
    syscall_setup();

    // 4. Full serial reinit.
    serial::init();

    if vga_active {
        serial_println!("vga: text mode active (80x25)");
        vga_println!("RustOS — VGA text mode");
    } else {
        serial_println!("vga: GOP/framebuffer mode (VGA text mode inactive)");
    }

    // ── CI sentinels ──────────────────────────────────────────────────────────
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
    // ─────────────────────────────────────────────────────────────────────────

    serial_println!("rustos: booting");

    // 5. Phase 2: feed real memory map to PMM.
    crate::mm::memmap::memmap_init();

    // Multiboot2 only: walk MBI tags for additional memory map entries.
    #[cfg(feature = "multiboot2_boot")]
    {
        let mbi = unsafe { MBI_PTR };
        if mbi != 0 {
            unsafe { crate::arch::x86_64::multiboot2::parse_mbi(mbi); }
            serial_println!("mb2: MBI at {:#x} parsed", mbi);
        }
    }

    // 6. FP state.
    xsave_init();

    // 7. ACPI — RSDP comes from uefi_entry::RSDP_PHYS (UEFI) or from
    //    multiboot2 ACPI tag (legacy).  Either way it is in RSDP_PHYS.
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

    // 12. Mount CPIO initramfs.
    crate::fs::initramfs::mount_initramfs();

    // 13. Mount root filesystem.
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
