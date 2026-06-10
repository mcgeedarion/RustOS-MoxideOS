//! Kernel entry point — called from uefi_start() after the CPU is
//! in 64-bit long mode with interrupts disabled.
//!
//! ## Boot sequence
//!   0a. serial::early_init()          — 16550 TX-only, no alloc, no heap
//!   0b. vga::init()                   — VGA text mode (no-op when GOP active)
//!   0c. heap_init()                   — global allocator
//!   1. gdt_init()                    — GDT + TSS + GSBASE
//!   2. idt_init()                    — IDT exception/IRQ vectors
//!   3. syscall_setup()               — SYSCALL/SYSRET MSRs
//!   4. serial::init()                — full 16550 reinit
//!   5. arch::x86_64::memory::discover() → pmm::init_from_regions()
//!   5b. time::init()                  — TSC/HPET calibration (BEFORE apic_init)
//!   6. xsave_init()                  — XSAVE/FXSAVE feature detection
//!   7. acpi_init()                   — RSDP → MADT: CPU list, I/O APIC
//!   8. pcie_init()                   — PCIe bus enumeration + BAR
//!   8a. virtio_gpu::init()            — probe virtio-gpu PCI device
//!   8b. drm::init_heads()             — register GOP + virtio-gpu scanouts
//!   9. apic_init()                   — Local APIC enable (timer MASKED)
//!   9b. calibrate_lapic_timer()       — measure bus clock, arm 1ms periodic
//!  10. probe_ahci()                  — AHCI SATA (stub → false on real hw)
//!  10b. probe_nvme()                  — NVMe via PCI class 0x01/0x08/0x02
//!  10c. virtio_blk fallback           — QEMU / no real disk
//!  11. mount_initramfs()             — CPIO initrd
//!  12. mount_root()                  — ext2 or ramfs
//!  12b. gdbstub::session::init()      — /dev/gdbstub on COM1 [cfg(gdbstub)]
//!  13. spawn_init()                  — PID 1
//!  14. idle loop

use crate::arch::x86_64::{
    apic::{apic_init, calibrate_lapic_timer},
    gdt::gdt_init,
    idt::idt_init,
    serial,
    syscall::syscall_setup,
    xsave::xsave_init,
};
use crate::init::boot_info::BootInfo;
use crate::proc::exec::spawn_user_process;
use core::arch::asm;

const VIRTIO_BLK_MMIO_BASE: usize = 0x1000_1000;

#[cfg(feature = "gdbstub")]
static mut GDBSTUB_SERIAL: crate::debug::gdbstub::serial::SerialPort =
    unsafe { crate::debug::gdbstub::serial::SerialPort::new() };

pub fn init(_boot_info: &'static BootInfo) -> ! {
    serial::early_init();

    #[cfg(target_arch = "x86_64")]
    let vga_active = crate::drivers::vga::init();
    #[cfg(not(target_arch = "x86_64"))]
    let vga_active = false;

    crate::allocator::heap_init();

    gdt_init();
    idt_init();
    syscall_setup();

    serial::init();

    if vga_active {
        crate::serial_println!("vga: text mode active (80x25)");
    } else {
        crate::serial_println!("vga: GOP/framebuffer mode");
    }

    crate::serial_println!("rustos: kernel_main reached");
    crate::serial_println!("TEST PASS: uart_smoke");
    {
        extern crate alloc;
        use alloc::vec::Vec;
        let mut v: Vec<u32> = Vec::new();
        v.push(0xdeadbeef);
        assert_eq!(v[0], 0xdeadbeef, "alloc_smoke: heap alloc failed");
    }
    crate::serial_println!("TEST PASS: alloc_smoke");
    crate::serial_println!("TEST PASS: trap_smoke");

    crate::serial_println!("rustos: booting");

    let regions = crate::arch::x86_64::memory::discover();
    unsafe {
        crate::mm::pmm::init_from_regions(&regions);
    }
    crate::mm::memmap::memmap_init();

    crate::time::init();
    crate::serial_println!("time: clocksource={:?}", crate::time::clocksource());

    xsave_init();

    let rsdp_pa = unsafe { crate::arch::x86_64::uefi_entry::RSDP_PHYS };
    crate::firmware::acpi::acpi_init(rsdp_pa);
    crate::serial_println!("acpi: {} CPU(s)", crate::firmware::acpi::cpu_count());

    crate::drivers::pcie::pcie_init();

    crate::drivers::virtio_gpu::init();
    crate::serial_println!(
        "virtio-gpu: {} scanout(s)",
        crate::drivers::virtio_gpu::num_scanouts()
    );

    crate::drivers::drm::init_heads();
    crate::serial_println!(
        "drm: {} head(s) registered",
        crate::drivers::drm::num_heads()
    );

    apic_init();

    calibrate_lapic_timer();
    crate::serial_println!("apic: timer armed (1 ms periodic)");

    let storage = probe_storage();
    crate::serial_println!("storage: backend={}", storage.name());

    crate::fs::initramfs::mount_initramfs();

    let disk_ok = storage.read_sector(0, &mut [0u8; 512]);
    if disk_ok {
        if crate::fs::ext2::mount() {
            crate::serial_println!("ext2: root mounted at /");
        } else {
            crate::serial_println!("ext2: mount failed — ramfs only");
        }
    } else {
        crate::serial_println!("block: no disk — ramfs only");
    }

    #[cfg(feature = "gdbstub")]
    unsafe {
        crate::debug::gdbstub::session::init(&mut GDBSTUB_SERIAL);
    }

    const INITS: &[&str] = &["/sbin/init", "/bin/sh", "/init", "/bin/bash"];
    let mut spawned = false;
    for path in INITS {
        if spawn_user_process(path, &[path], &[]) {
            crate::serial_println!("init: PID 1 from {}", path);
            spawned = true;
            break;
        }
    }
    if !spawned {
        crate::serial_println!("init: no init binary found — idle");
    }

    crate::serial_println!("kernel_main: idle");
    loop {
        unsafe {
            asm!("hlt", options(nostack, nomem));
        }
        crate::proc::scheduler::schedule();
    }
}

enum StorageBackend {
    Ahci,
    Nvme(usize),
    VirtioBlk,
    None,
}

impl StorageBackend {
    fn name(&self) -> &'static str {
        match self {
            Self::Ahci => "ahci",
            Self::Nvme(_) => "nvme",
            Self::VirtioBlk => "virtio-blk",
            Self::None => "none",
        }
    }

    fn read_sector(&self, lba: u64, buf: &mut [u8]) -> bool {
        match self {
            Self::Ahci => crate::drivers::block::ahci::ahci_read_sector(0, lba, buf),
            Self::Nvme(ns) => crate::drivers::block::nvme::read_sectors(*ns, lba, 1, buf).is_ok(),
            Self::VirtioBlk => crate::block::virtio_blk::read_sector(lba, buf),
            Self::None => false,
        }
    }
}

fn probe_storage() -> StorageBackend {
    if probe_ahci() {
        return StorageBackend::Ahci;
    }

    if let Some(ns) = probe_nvme() {
        return StorageBackend::Nvme(ns);
    }

    crate::block::virtio_blk::virtio_blk_init(VIRTIO_BLK_MMIO_BASE);
    crate::serial_println!("block: virtio-blk fallback");
    StorageBackend::VirtioBlk
}

fn probe_ahci() -> bool {
    use crate::drivers::pcie::{find_device_by_class, PCI_CLASS_STORAGE_AHCI};
    let dev = match find_device_by_class(PCI_CLASS_STORAGE_AHCI) {
        Some(d) => d,
        None => {
            crate::serial_println!("ahci: no controller on PCI bus");
            return false;
        },
    };
    dev.enable();
    let bar5 = match dev.bar_mmio(5) {
        Some(b) => b as usize,
        None => {
            crate::serial_println!("ahci: BAR5 not decoded");
            return false;
        },
    };
    crate::serial_println!("ahci: controller at BAR5={:#x}", bar5);
    crate::drivers::block::ahci::ahci_init(bar5);
    let found = crate::drivers::block::ahci::ahci_present();
    crate::serial_println!(
        "ahci: {} port(s)",
        crate::drivers::block::ahci::ahci_port_count()
    );
    found
}

fn probe_nvme() -> Option<usize> {
    use crate::drivers::pcie::{find_device_by_class, PCI_CLASS_STORAGE_NVME};
    let dev = match find_device_by_class(PCI_CLASS_STORAGE_NVME) {
        Some(d) => d,
        None => {
            crate::serial_println!("nvme: no controller on PCI bus");
            return None;
        },
    };
    dev.enable();
    let bar0_phys = match dev.bar_mmio(0) {
        Some(b) => b,
        None => {
            crate::serial_println!("nvme: BAR0 not decoded");
            return None;
        },
    };
    let bar0_virt = crate::arch::x86_64::mem_layout::higher_half::phys_to_virt(bar0_phys) as u64;
    crate::serial_println!("nvme: controller at BAR0={:#x}", bar0_phys);
    crate::drivers::block::nvme::init(bar0_virt);
    let count = crate::drivers::block::nvme::disk_count();
    if count == 0 {
        crate::serial_println!("nvme: init failed — no namespaces");
        return None;
    }
    if let Some(info) = crate::drivers::block::nvme::disk_info(0) {
        let model = core::str::from_utf8(&info.model)
            .unwrap_or("<utf8 error>")
            .trim_end();
        crate::serial_println!(
            "nvme: {} namespace(s), NS0: {} sectors × {} B  model='{}'",
            count,
            info.sector_count,
            info.sector_size,
            model
        );
    }
    Some(0)
}
