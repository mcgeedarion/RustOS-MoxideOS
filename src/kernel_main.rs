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
//!   4a. namespace::init()      — seed INIT_NS in mount + UTS namespace tables
//!   5.  gdt::init()            — GDT + TSS
//!   6.  idt::init()            — IDT / exception vectors
//!   7.  apic::init()           — local + IO APIC, timer IRQ
//!   8.  time::init()           — clocksource calibration (TSC/HPET), timerfd, itimers
//!   9.  smp::init()            — enumerate MADT CPUs, bring up APs
//!   10. tty::init()            — PTY registry + /dev/pts
//!   11. drivers::nic::init()   — NIC driver (e1000e/virtio-net)
//!   11a. init::schemes::init() — register built-in schemes (file:, net:, blk:,
//!                                proc:, dev:, pipe:, null:) into SCHEME_TABLE
//!   12. dhcp::init()           — DORA handshake; sets ip/gw/mask in ip layer
//!   13. spawn pid 1 from /init — scheduler takes over
//!
//! RISC-V boot sequence:
//!   1.  trap_init()            — install stvec, enable SSIE/STIE/SEIE (must be first)
//!   2.  init_from_fdt()        — parse FDT: /memory → PMM, /chosen → initramfs,
//!                                            /soc/plic → plic::set_base(),
//!                                            virtio_mmio@ → virtio_net_mmio::probe()
//!   3.  heap::init()           — linked-list allocator over PMM
//!   3a. mm::init()             — slab cache pre-warm
//!   4.  initramfs::mount()     — populate VFS from CPIO
//!   5.  time::init()           — RISC-V timer (mtime/mtimecmp via SBI)
//!   6.  drivers::nic::init()   — virtio-net MMIO
//!   6a. init::schemes::init()  — register built-in schemes into SCHEME_TABLE
//!   7.  dhcp::init()           — DORA handshake
//!   8.  spawn pid 1 from /init — scheduler takes over

#[cfg(target_arch = "x86_64")]
pub fn kernel_main_x86_64() -> ! {
    crate::serial::init();
    crate::pmm::init();
    crate::heap::init();
    crate::mm::init();
    crate::io_uring::init();
    crate::init::initramfs::mount();
    crate::namespace::init();
    crate::arch::x86_64::gdt::init();
    crate::arch::x86_64::idt::init();
    crate::arch::x86_64::apic::init();
    crate::time::init();
    crate::smp::init();
    crate::tty::init();
    crate::drivers::nic::init();
    // Step 11a: register all built-in kernel schemes into SCHEME_TABLE.
    // Must run after NIC init (net: scheme queries the NIC) and before
    // dhcp::init() (which opens "net:eth0" via the scheme table).
    crate::init::schemes::init();
    crate::dhcp::init();
    crate::proc::spawn_init();
    unreachable!("scheduler returned to kernel_main");
}

#[cfg(target_arch = "riscv64")]
pub fn kernel_main_riscv64() -> ! {
    crate::arch::riscv64::trap::trap_init();
    crate::arch::riscv64::fdt::init_from_fdt();
    crate::heap::init();
    crate::mm::init();
    crate::init::initramfs::mount();
    crate::time::init();
    crate::drivers::nic::init();
    // Step 6a: register all built-in kernel schemes into SCHEME_TABLE.
    crate::init::schemes::init();
    crate::dhcp::init();
    crate::proc::spawn_init();
    unreachable!("scheduler returned to kernel_main");
}
