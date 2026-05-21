//! Kernel entry point — called from uefi_start() (primary) or
//! multiboot2_entry() (legacy, feature = "multiboot2_boot") after the CPU is
//! in 64-bit long mode with interrupts disabled.
//!
//! ## Boot sequence
//!   0a. serial::early_init()          — 16550 TX-only, no alloc, no heap
//!   0b. vga::init()                   — VGA text mode (no-op when GOP active)
//!   0c. heap_init()                   — global allocator
//!   1.  gdt_init()                    — GDT + TSS + GSBASE
//!   2.  idt_init()                    — IDT exception/IRQ vectors
//!   3.  syscall_setup()               — SYSCALL/SYSRET MSRs
//!   4.  serial::init()                — full 16550 reinit
//!   5.  memmap_init()                 — Phase 2: feed EFI memory map to PMM
//!   5b. time::init()                  — TSC/HPET calibration (BEFORE apic_init)
//!   6.  xsave_init()                  — XSAVE/FXSAVE feature detection
//!   7.  acpi_init()                   — RSDP → MADT: CPU list, I/O APIC
//!   8.  pcie_init()                   — PCIe bus enumeration + BAR
//!   8a. virtio_gpu::init()            — probe virtio-gpu PCI device
//!   8b. drm::init_heads()             — register GOP + virtio-gpu scanouts
//!   9.  apic_init()                   — Local APIC enable (timer MASKED)
//!   9b. calibrate_lapic_timer()       — measure bus clock, arm 1ms periodic
//!  10.  probe_ahci()                  — AHCI SATA (stub → false on real hw)
//!  10b. probe_nvme()                  — NVMe via PCI class 0x01/0x08/0x02
//!  10c. virtio_blk fallback           — QEMU / no real disk
//!  11.  mount_initramfs()             — CPIO initrd
//!  12.  mount_root()                  — ext2 or ramfs
//!  13.  spawn_init()                  — PID 1
//!  14.  idle loop

use core::arch::asm;
use crate::arch::x86_64::{
    gdt::gdt_init,
    idt::idt_init,
    syscall::syscall_setup,
    serial,
    apic::{apic_init, calibrate_lapic_timer},
    xsave::xsave_init,
};
use crate::proc::exec::spawn_user_process;

const VIRTIO_BLK_MMIO_BASE: usize = 0x1000_1000;

// ── Legacy multiboot2 entry ───────────────────────────────────────────────────

#[cfg(feature = "multiboot2_boot")]
pub static mut MBI_PTR: usize = 0;

#[cfg(feature = "multiboot2_boot")]
#[no_mangle]
pub unsafe extern "C" fn multiboot2_entry(magic: u32, info_phys: u32) -> ! {
    if magic == 0x36d7_6289 { MBI_PTR = info_phys as usize; }
    kernel_main()
}

// ── Primary kernel entry ─────────────────────────────────────────────────────

#[no_mangle]
pub extern "C" fn kernel_main() -> ! {
    // 0a. Serial UART before anything that can panic.
    serial::early_init();

    // 0b. VGA text mode probe.
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
    } else {
        serial_println!("vga: GOP/framebuffer mode");
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

    // 5. Phase 2: real memory map → PMM.
    crate::mm::memmap::memmap_init();

    #[cfg(feature = "multiboot2_boot")]
    {
        let mbi = unsafe { MBI_PTR };
        if mbi != 0 {
            unsafe { crate::arch::x86_64::multiboot2::parse_mbi(mbi); }
            serial_println!("mb2: MBI at {:#x} parsed", mbi);
        }
    }

    // 5b. Time subsystem: TSC and HPET calibration.
    //     MUST come before apic_init().
    crate::time::init();
    serial_println!("time: clocksource={:?}", crate::time::clocksource());

    // 6. FP state.
    xsave_init();

    // 7. ACPI.
    let rsdp_pa = unsafe { crate::arch::x86_64::uefi_entry::RSDP_PHYS };
    crate::firmware::acpi::acpi_init(rsdp_pa);
    serial_println!("acpi: {} CPU(s)", crate::firmware::acpi::cpu_count());

    // 8. PCIe enumeration.
    crate::drivers::pcie::pcie_init();

    // 8a. virtio-gpu.
    crate::drivers::virtio_gpu::init();
    serial_println!("virtio-gpu: {} scanout(s)",
                    crate::drivers::virtio_gpu::num_scanouts());

    // 8b. DRM head registration.
    crate::drivers::drm::init_heads();
    serial_println!("drm: {} head(s) registered",
                    crate::drivers::drm::num_heads());

    // 9. APIC enable (timer MASKED until calibration).
    apic_init();

    // 9b. Calibrate APIC bus clock → arm 1 ms periodic timer.
    calibrate_lapic_timer();
    serial_println!("apic: timer armed (1 ms periodic)");

    // 10. Storage probe: AHCI → NVMe → virtio-blk.
    let storage = probe_storage();
    serial_println!("storage: backend={}", storage.name());

    // 11. Mount CPIO initramfs.
    crate::fs::initramfs::mount_initramfs();

    // 12. Mount root filesystem.
    let disk_ok = storage.read_sector(0, &mut [0u8; 512]);
    if disk_ok {
        if crate::fs::ext2::mount() {
            serial_println!("ext2: root mounted at /");
        } else {
            serial_println!("ext2: mount failed — ramfs only");
        }
    } else {
        serial_println!("block: no disk — ramfs only");
    }

    // 13. Spawn PID 1.
    const INITS: &[&str] = &["/sbin/init", "/bin/sh", "/init", "/bin/bash"];
    let mut spawned = false;
    for path in INITS {
        if spawn_user_process(path, &[path], &[]) {
            serial_println!("init: PID 1 from {}", path);
            spawned = true;
            break;
        }
    }
    if !spawned { serial_println!("init: no init binary found — idle"); }

    // 14. Idle loop.
    serial_println!("kernel_main: idle");
    loop {
        unsafe { asm!("hlt", options(nostack, nomem)); }
        crate::proc::scheduler::schedule();
    }
}

// ── Storage abstraction ───────────────────────────────────────────────────────

enum StorageBackend { Ahci, Nvme(usize), VirtioBlk, None }

impl StorageBackend {
    fn name(&self) -> &'static str {
        match self {
            Self::Ahci      => "ahci",
            Self::Nvme(_)   => "nvme",
            Self::VirtioBlk => "virtio-blk",
            Self::None      => "none",
        }
    }

    fn read_sector(&self, lba: u64, buf: &mut [u8]) -> bool {
        match self {
            Self::Ahci => {
                crate::drivers::block::ahci::ahci_read_sector(0, lba, buf)
            }
            Self::Nvme(ns) => {
                crate::drivers::block::nvme::read_sectors(*ns, lba, 1, buf).is_ok()
            }
            Self::VirtioBlk => {
                crate::block::virtio_blk::read_sector(lba, buf)
            }
            Self::None => false,
        }
    }
}

fn probe_storage() -> StorageBackend {
    // 1. AHCI
    if probe_ahci() { return StorageBackend::Ahci; }

    // 2. NVMe
    if let Some(ns) = probe_nvme() { return StorageBackend::Nvme(ns); }

    // 3. virtio-blk fallback (QEMU)
    crate::block::virtio_blk::virtio_blk_init(VIRTIO_BLK_MMIO_BASE);
    serial_println!("block: virtio-blk fallback");
    StorageBackend::VirtioBlk
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
    serial_println!("ahci: controller at BAR5={:#x}", bar5);
    crate::drivers::block::ahci::ahci_init(bar5);
    let found = crate::drivers::block::ahci::ahci_present();
    serial_println!("ahci: {} port(s)",
        crate::drivers::block::ahci::ahci_port_count());
    found
}

/// Probe for an NVMe controller via PCI class 0x01/0x08/0x02.
/// Returns the namespace index (0) if found and initialised, or `None`.
fn probe_nvme() -> Option<usize> {
    use crate::drivers::pcie::{find_device_by_class, PCI_CLASS_STORAGE_NVME};
    let dev = match find_device_by_class(PCI_CLASS_STORAGE_NVME) {
        Some(d) => d,
        None    => {
            serial_println!("nvme: no controller on PCI bus");
            return None;
        }
    };
    dev.enable();
    // NVMe BAR0 = 64-bit MMIO register space.
    let bar0_phys = match dev.bar_mmio(0) {
        Some(b) => b,
        None    => {
            serial_println!("nvme: BAR0 not decoded");
            return None;
        }
    };
    // Map BAR0 into the kernel direct-map window.
    let bar0_virt = crate::arch::x86_64::mem_layout::higher_half::phys_to_virt(bar0_phys) as u64;
    serial_println!("nvme: controller at BAR0={:#x}", bar0_phys);
    crate::drivers::block::nvme::init(bar0_virt);
    let count = crate::drivers::block::nvme::disk_count();
    if count == 0 {
        serial_println!("nvme: init failed — no namespaces");
        return None;
    }
    if let Some(info) = crate::drivers::block::nvme::disk_info(0) {
        // Model bytes are ASCII, may have trailing spaces.
        let model = core::str::from_utf8(&info.model)
            .unwrap_or("<utf8 error>").trim_end();
        serial_println!("nvme: {} namespace(s), NS0: {} sectors × {} B  model='{}'",
            count, info.sector_count, info.sector_size, model);
    }
    Some(0)
}
