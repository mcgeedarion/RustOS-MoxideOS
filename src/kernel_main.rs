//! Architecture-independent kernel initialisation and entry-point dispatcher.
//!
//! Exactly one function is called from each architecture's boot stub:
//!
//! | Arch      | Caller                                    |
//! |-----------|-------------------------------------------|
//! | x86_64    | `multiboot2_entry()` or `uefi_start()`    |
//! | riscv64   | RISC-V SBI stub in `arch/riscv64/boot.rs` |
//!
//! ## x86_64 boot sequence
//!
//! ```text
//!  1. serial::init()          — UART output (console before heap)
//!  2. pmm::init()             — physical memory manager
//!  3. heap::init()            — linked-list allocator over PMM
//!  4. mm::init()              — slab cache pre-warm (8 size classes)
//!  5. io_uring::init()        — ring table (requires alloc)
//!  6. initramfs::mount()      — populate VFS from CPIO archive
//!  7. namespace::init()       — seed INIT_NS mount + UTS namespace tables
//!  8. gdt::init()             — GDT + TSS
//!  9. idt::init()             — IDT / exception vectors
//! 10. apic::init()            — local + IO APIC, timer IRQ
//! 11. time::init()            — clocksource calibration (TSC/HPET), timerfd
//! 12. smp::init()             — enumerate MADT CPUs, bring up APs
//! 13. tty::init()             — PTY registry + /dev/pts
//! 14. drivers::nic::init()    — NIC driver (e1000e / virtio-net)
//! 15. init::schemes::init()   — register built-in schemes into SCHEME_TABLE
//!                               (must follow NIC; must precede DHCP)
//! 16. dhcp::init()            — DORA handshake; sets IP/GW/mask
//! 17. cgroup::init()          — seed ROOT_CGROUP; ensure cgroup subsystem ready
//! 18. proc::spawn_init()      — spawn pid 1 from /init; scheduler takes over
//! ```
//!
//! ## RISC-V boot sequence
//!
//! ```text
//!  1. trap_init()             — install stvec; enable SSIE/STIE/SEIE (must be first)
//!  2. init_from_fdt()         — parse FDT: /memory → PMM, /chosen → initramfs,
//!                               /soc/plic → plic::set_base(),
//!                               virtio_mmio@ → virtio_net_mmio::probe()
//!  3. heap::init()            — linked-list allocator over PMM
//!  4. mm::init()              — slab cache pre-warm
//!  5. initramfs::mount()      — populate VFS from CPIO archive
//!  6. time::init()            — RISC-V timer (mtime/mtimecmp via SBI)
//!  7. drivers::nic::init()    — virtio-net MMIO
//!  8. init::schemes::init()   — register built-in schemes into SCHEME_TABLE
//!  9. dhcp::init()            — DORA handshake
//! 10. cgroup::init()          — seed ROOT_CGROUP
//! 11. proc::spawn_init()      — spawn pid 1; scheduler takes over
//! ```

// ── x86_64 ───────────────────────────────────────────────────────────────────

#[cfg(target_arch = "x86_64")]
pub fn kernel_main() -> ! {
    use crate::arch::x86_64::{apic, gdt, idt};

    crate::serial::init();
    crate::pmm::init();
    crate::heap::init();
    crate::mm::init();
    crate::io_uring::init();
    crate::init::initramfs::mount();
    crate::namespace::init();
    gdt::init();
    idt::init();
    apic::init();
    crate::time::init();
    crate::smp::init();
    crate::tty::init();
    crate::drivers::nic::init();
    crate::init::schemes::init();
    crate::dhcp::init();
    crate::proc::cgroup::init();
    crate::proc::spawn_init();

    unreachable!("scheduler returned to kernel_main");
}

// ── riscv64 ──────────────────────────────────────────────────────────────────

#[cfg(target_arch = "riscv64")]
pub fn kernel_main() -> ! {
    use crate::arch::riscv64::{fdt, trap};

    trap::trap_init();
    fdt::init_from_fdt();
    crate::heap::init();
    crate::mm::init();
    crate::init::initramfs::mount();
    crate::time::init();
    crate::drivers::nic::init();
    crate::init::schemes::init();
    crate::dhcp::init();
    crate::proc::cgroup::init();
    crate::proc::spawn_init();

    unreachable!("scheduler returned to kernel_main");
}
