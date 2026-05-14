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
//!  1. serial::init()          — UART output (console before everything)
//!  2. gdt::init()             — GDT + TSS (must precede any fault/NMI)
//!  3. idt::init()             — IDT / exception vectors (must precede PMM)
//!  4. pmm::init()             — physical memory manager
//!  5. heap::init()            — linked-list allocator over PMM
//!  6. mm::init()              — slab cache pre-warm (8 size classes)
//!  7. initramfs::mount()      — populate VFS from CPIO archive
//!  8. namespace::init()       — seed INIT_NS mount + UTS namespace tables
//!  9. apic::init()            — local + IO APIC, timer IRQ
//! 10. time::init()            — clocksource calibration (TSC/HPET), timerfd
//! 11. smp::init()             — enumerate MADT CPUs, bring up APs
//! 12. pci::init()             — full bus/device/function scan → PCI_DEVICES
//!                               (after smp so per-CPU IRQ affinity is ready)
//! 13. io_uring::init()        — ring table (requires alloc + live APIC/IDT)
//! 14. tty::init()             — PTY registry + /dev/pts
//! 15. drivers::nic::init()    — NIC driver (e1000e / virtio-net)
//!                               (calls pci::find_device(); pci::init() must precede)
//! 16. init::schemes::init()   — register built-in schemes into SCHEME_TABLE
//!                               (must follow NIC; must precede DHCP)
//! 17. dhcp::init()            — DORA handshake; sets IP/GW/mask
//! 18. cgroup::init()          — seed ROOT_CGROUP; ensure cgroup subsystem ready
//! 19. proc::spawn_init()      — spawn pid 1 from /init; scheduler takes over
//! ```
//!
//! ## RISC-V boot sequence
//!
//! ```text
//!  1. trap_init()             — install stvec; enable SSIE/STIE/SEIE (must be first)
//!  2. fdt_phase1(fdt_ptr)     — PMM regions, PLIC base, initramfs bounds, CPU table
//!                               NO heap allocations; safe before heap::init()
//!  3. plic::init()            — write S-mode context threshold=0; unmask all IRQ prio≥1
//!                               (must follow fdt_phase1/set_base; precede any probe)
//!  4. heap::init()            — linked-list allocator over PMM
//!  5. mm::init()              — slab cache pre-warm
//!  6. fdt_phase2(fdt_ptr)     — virtio-net MMIO probe (alloc now safe)
//!  7. initramfs::mount()      — populate VFS from CPIO archive
//!  8. namespace::init()       — seed INIT_NS mount + UTS namespace tables
//!  9. time::init()            — RISC-V timer (mtime/mtimecmp via SBI)
//! 10. drivers::nic::init()    — virtio-net MMIO
//! 11. init::schemes::init()   — register built-in schemes into SCHEME_TABLE
//! 12. dhcp::init()            — DORA handshake
//! 13. cgroup::init()          — seed ROOT_CGROUP
//! 14. proc::spawn_init()      — spawn pid 1; scheduler takes over
//! ```

// ── x86_64 ───────────────────────────────────────────────────────────────────

#[cfg(target_arch = "x86_64")]
pub fn kernel_main() -> ! {
    use crate::arch::x86_64::{apic, gdt, idt, pci};

    crate::serial::init();
    gdt::init();
    idt::init();
    crate::pmm::init();
    crate::heap::init();
    crate::mm::init();
    crate::init::initramfs::mount();
    crate::namespace::init();
    apic::init();
    crate::time::init();
    crate::smp::init();
    pci::init();
    crate::io_uring::init();
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
pub fn kernel_main(fdt_ptr: usize) -> ! {
    use crate::arch::riscv64::{fdt, plic, trap};

    trap::trap_init();
    unsafe { fdt::fdt_phase1(fdt_ptr); }  // PMM + PLIC base + initramfs + CPUs; no alloc
    plic::init();                          // threshold=0; unmask all external IRQs
    crate::heap::init();
    crate::mm::init();
    unsafe { fdt::fdt_phase2(fdt_ptr); }  // virtio probe; alloc now safe
    crate::init::initramfs::mount();
    crate::namespace::init();
    crate::time::init();
    crate::drivers::nic::init();
    crate::init::schemes::init();
    crate::dhcp::init();
    crate::proc::cgroup::init();
    crate::proc::spawn_init();

    unreachable!("scheduler returned to kernel_main");
}
