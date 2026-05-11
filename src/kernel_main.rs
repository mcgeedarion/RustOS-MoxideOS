//! Architecture-independent kernel entry points and init-process launcher.
//!
//! Two entry points exist, selected at compile time by target architecture:
//!   - `kernel_main_x86_64`   — called from multiboot2_entry() or uefi_start()
//!   - `kernel_main_riscv64`  — called from the RISC-V SBI stub (boot.rs)
//!
//! x86_64 boot sequence:
//!   1.  serial::init()         — UART output
//!   2.  pmm::init()            — physical memory manager
//!   3.  heap::init()           — linked-list allocator over PMM
//!   3a. mm::init()             — slab cache pre-warm (8 size classes)
//!   3b. io_uring::init()       — ring table init (requires alloc)
//!   4.  initramfs::mount()     — populate VFS from CPIO
//!   5.  gdt::init()            — GDT + TSS
//!   6.  idt::init()            — IDT / exception vectors
//!   7.  apic::init()           — local + IO APIC, timer IRQ
//!   8.  time::init()           — clocksource calibration (TSC/HPET), timerfd, itimers
//!   9.  smp::init()            — enumerate MADT CPUs, bring up APs
//!   10. tty::init()            — PTY registry + /dev/pts
//!   11. drivers::nic::init()   — NIC driver (e1000e/virtio-net)
//!   12. dhcp::init()           — DORA handshake; sets ip/gw/mask in ip layer
//!   13. spawn pid 1 from /init — scheduler takes over
//!
//! RISC-V boot sequence:
//!   1.  trap_init()            — install stvec, enable SSIE/STIE/SEIE (must be first)
//!   2.  init_from_fdt()        — parse FDT: /memory → PMM, /chosen → initramfs,
//!                                            /soc/plic → plic::set_base(),
//!                                            virtio_mmio@ → virtio_net_mmio::probe()
//!   3.  heap::init()           — linked-list allocator over PMM
//!   3a. mm::init()             — slab cache pre-warm (8 size classes)
//!   3b. io_uring::init()       — ring table init (requires alloc)
//!   4.  initramfs::mount()     — populate VFS from CPIO
//!   5.  plic::init()           — set S-mode context threshold=0, PLIC ready to deliver
//!   6.  virtio_net_mmio::enable_plic_irq()
//!                              — register NIC IRQ with PLIC; enables interrupt-driven RX
//!   7.  time::init()           — calibrate CLINT mtime clocksource, timerfd, itimers
//!   8.  smp::init()            — SBI HSM hart bringup
//!   9.  tty::init()            — PTY registry + /dev/pts
//!   10. drivers::nic::init()   — NIC abstraction layer init (rx_poll fallback path)
//!   11. dhcp::init()           — DORA handshake
//!   12. spawn pid 1 from /init — scheduler takes over

use crate::initramfs;
use crate::{drivers, fs, io_uring, mm, net, proc, smp, time, tty};

// ── Shared helpers ───────────────────────────────────────────────────────────────────────

/// Halt the current CPU permanently. Used only on fatal, unrecoverable errors.
/// Marked `#[cold]` so LLVM treats call sites as unlikely branches, keeping
/// the hot boot path's code layout tight.
#[cold]
#[inline(never)]
fn halt_loop() -> ! {
    loop {
        #[cfg(target_arch = "x86_64")]
        unsafe { core::arch::asm!("hlt"); }
        #[cfg(target_arch = "riscv64")]
        unsafe { core::arch::asm!("wfi"); }
    }
}

/// Common tail executed by both arch entry points after all hardware subsystems
/// are up. Loads `/init` from the initramfs, spawns it as PID 1, then hands
/// control to the scheduler — never returns.
fn kernel_main_common() -> ! {
    let handle = initramfs::load();
    let elf_bytes = match handle.file("/init") {
        Some(b) => b,
        None => {
            crate::println!("rustos: FATAL: /init not found in initramfs");
            halt_loop();
        }
    };
    if !proc::exec::spawn_user_process_from_bytes(elf_bytes, "/init", &["/init"], &[]) {
        crate::println!("rustos: FATAL: failed to spawn /init");
        halt_loop();
    }
    crate::println!("rustos: pid 1 enqueued");
    crate::println!("TEST PASS: initramfs_load");
    proc::scheduler::run()
}

// ── x86_64 entry ────────────────────────────────────────────────────────────────────────

#[cfg(target_arch = "x86_64")]
pub fn kernel_main_x86_64() {
    use crate::arch::x86_64::{apic, gdt, idt, serial};
    use crate::mm::{heap, pmm};

    // 1. Serial console — must come first for any diagnostic output.
    serial::init();
    crate::println!("rustos: x86_64 kernel starting");

    // 2. Physical memory manager — must come before heap and slab have frames.
    pmm::init();

    // 3. Kernel heap (linked-list allocator) — enables Box / Vec / String.
    heap::init();

    // 3a. Slab allocator — pre-warms 8 fixed-size caches over PMM.
    //     Must follow heap::init() so that slab::init()'s pmm::alloc_page
    //     calls (inside Cache::grow) have the PMM ready and so that any
    //     Box allocations inside init() itself work correctly.
    mm::init();
    crate::println!("rustos: slab allocator ready");

    // 3b. io_uring ring table — requires alloc, must precede any io_uring syscall.
    io_uring::init();
    crate::println!("rustos: io_uring ready");

    // 4–12. Remaining subsystems.
    fs::initramfs::mount_initramfs();
    gdt::init();
    idt::init();
    apic::init();
    time::init();
    smp::init();
    tty::init();
    drivers::nic::init();
    net::dhcp::init();
    crate::println!(
        "rustos: network up — ip={:?} gw={:?}",
        net::ip::our_ip().to_be_bytes(),
        net::dhcp::leased_gateway().to_be_bytes(),
    );
    crate::println!("rustos: subsystems initialised — launching /init");

    kernel_main_common()
}

// ── RISC-V entry ────────────────────────────────────────────────────────────────────────

/// Called by `_start` in `arch/riscv64/boot.rs` with:
///   `hart_id` = value of a0 from OpenSBI
///   `fdt_ptr` = value of a1 from OpenSBI (physical address of FDT blob)
#[cfg(target_arch = "riscv64")]
pub fn kernel_main_riscv64(hart_id: usize, fdt_ptr: usize) {
    use crate::arch::riscv64::trap;
    use crate::mm::{heap, pmm};

    // 1. Trap vector + SSIE/STIE/SEIE must be active before anything faults.
    trap::trap_init();

    crate::println!("rustos: riscv64 kernel starting (hart {})", hart_id);
    crate::println!("kernel_main reached");

    // 2. Walk the FDT: registers PMM regions, finds initramfs, sets PLIC base,
    //    probes virtio_mmio devices (virtio_net_mmio::probe is called here).
    unsafe { crate::arch::riscv64::fdt::init_from_fdt(fdt_ptr); }
    crate::println!(
        "pmm: {} MiB total, {} MiB free",
        pmm::total_pages() * 4 / 1024,
        pmm::free_pages() * 4 / 1024,
    );

    // 3. Heap must come up before any Box/Vec/String allocations.
    heap::init();

    // 3a. Slab allocator — pre-warms 8 fixed-size caches over PMM.
    mm::init();
    crate::println!("rustos: slab allocator ready");

    // 3b. io_uring ring table — requires alloc, must precede any io_uring syscall.
    io_uring::init();
    crate::println!("rustos: io_uring ready");

    // 4. VFS from CPIO.
    fs::initramfs::mount_initramfs();

    // 5. PLIC: set threshold=0 so any enabled IRQ with priority ≥1 is delivered.
    //    Must happen after fdt::init_from_fdt (which calls plic::set_base).
    if drivers::plic::init() {
        // 6. Register the virtio-net MMIO IRQ with the PLIC.
        //    From now on, RX is interrupt-driven (scause 0x8000…9 → plic::handle_irq
        //    → virtio_net_mmio_irq → rx_poll + drain_tx).
        drivers::virtio_net_mmio::enable_plic_irq();
    } else {
        crate::println!("plic: not available — NIC will use polled RX");
    }

    // 7–12. Remaining subsystems.
    time::init();
    smp::init();
    tty::init();
    drivers::nic::init();
    net::dhcp::init();
    crate::println!(
        "rustos: network up — ip={:?} gw={:?}",
        net::ip::our_ip().to_be_bytes(),
        net::dhcp::leased_gateway().to_be_bytes(),
    );
    crate::println!("rustos: riscv64 subsystems initialised — launching /init");

    kernel_main_common()
}
