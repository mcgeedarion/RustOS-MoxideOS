//! AArch64 kernel entry point.
//!
//! Called from `uefi_entry.rs` (or the boot stub) after the CPU is at EL1
//! with MMU off or with an identity map.  Mirrors the sequencing of
//! `x86_64/kernel_main.rs`.
//!
//! ## Boot sequence
//!
//!   0.  hal::init()               — disable IRQs, serial TX available
//!   1.  cpu::enable_fp_simd()     — CPACR_EL1.FPEN = 0b11
//!   2.  interrupts::init()        — VBAR_EL1 ← &__exception_vectors
//!   3.  paging::init()            — MMU on, kernel mapped in TTBR1
//!   4.  heap_init()               — global allocator
//!   5.  pmm::init()               — physical memory manager
//!   6.  time::init()              — generic timer calibration
//!   7.  gic::init()               — GICv2/v3 enable + IRQ routing
//!   8.  pci::ecam_init()          — ECAM base from ACPI / DTB
//!   9.  virtio_blk / block init   — storage backend
//!  10.  fs::initramfs::mount()    — initrd
//!  11.  spawn_init()              — PID 1
//!  12.  smp::bring_up_secondaries()
//!  13.  idle loop

use crate::init::boot_info::BootInfo;
use crate::proc::exec::spawn_user_process;
use core::arch::asm;

pub fn init(boot_info: &'static BootInfo) -> ! {
    // 0. Serial and IRQ disable (hal::init already called in uefi_entry).
    super::hal::init();

    // 1. FP/SIMD.
    unsafe { super::cpu::enable_fp_simd(); }

    // 2. Exception vectors.
    unsafe { super::interrupts::init(); }
    crate::serial_println!("aarch64: exception vectors installed");

    // 3. MMU / paging.
    super::paging::init(boot_info);
    crate::serial_println!("aarch64: MMU enabled");

    // 4. Heap.
    crate::allocator::heap_init();
    crate::serial_println!("aarch64: heap ready");

    // 5. PMM.
    {
        let regions = super::mem_layout::memory_regions(boot_info);
        unsafe { crate::mm::pmm::init_from_regions(&regions); }
    }
    crate::mm::memmap::memmap_init();
    crate::serial_println!("aarch64: PMM ready");

    // 6. Timer.
    crate::time::init();
    crate::serial_println!("time: clocksource={:?}", crate::time::clocksource());

    // 7. GIC.
    crate::irq::aarch64::gic::init(
        crate::irq::aarch64::gic::GicConfig::qemu_virt_v3()
    );
    crate::serial_println!("aarch64: GIC ready");

    // 8. PCIe ECAM (base from ACPI MCFG or DTB — 0 if not present).
    let ecam_base = crate::firmware::acpi::mcfg_base().unwrap_or(0);
    if ecam_base != 0 {
        super::pci::ecam_init(ecam_base);
        crate::serial_println!("aarch64: ECAM base={:#x}", ecam_base);
    }

    // 9. Storage.
    let storage = probe_storage();
    crate::serial_println!("storage: backend={}", storage.name());

    // 10. Filesystems.
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

    // 11. PID 1.
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

    // 12. SMP.
    super::smp::bring_up_secondaries();

    // 13. Enable IRQs and idle.
    unsafe { super::hal::interrupts_enable(); }
    crate::serial_println!("aarch64: kernel_main: idle");
    loop {
        unsafe { asm!("wfi", options(nostack, nomem)); }
        crate::proc::scheduler::schedule();
    }
}

// ── Storage backend (mirrors x86_64/kernel_main.rs) ───────────────────────────

enum StorageBackend {
    VirtioBlk,
    None,
}

impl StorageBackend {
    fn name(&self) -> &'static str {
        match self {
            Self::VirtioBlk => "virtio-blk",
            Self::None => "none",
        }
    }

    fn read_sector(&self, lba: u64, buf: &mut [u8]) -> bool {
        match self {
            Self::VirtioBlk => crate::block::virtio_blk::read_sector(lba, buf),
            Self::None => false,
        }
    }
}

fn probe_storage() -> StorageBackend {
    // On QEMU virt aarch64 the primary block device is virtio-blk over MMIO.
    const VIRTIO_BLK_MMIO_BASE: usize = 0x0a00_3e00;
    crate::block::virtio_blk::virtio_blk_init(VIRTIO_BLK_MMIO_BASE);
    crate::serial_println!("block: virtio-blk @ {:#x}", VIRTIO_BLK_MMIO_BASE);
    StorageBackend::VirtioBlk
}
