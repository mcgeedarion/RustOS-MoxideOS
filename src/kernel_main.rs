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
//!  1. serial::init()                 — UART output (console before everything)
//!  2. debug::init()                  — GDB RSP stub (conditional on cfg(debug_stub));
//!                                       placed early so every subsequent panic is
//!                                       catchable over the serial/JTAG GDB port.
//!  3. gdt::init()                    — GDT + TSS (must precede any fault/NMI)
//!  4. idt::init()                    — IDT / exception vectors (must precede PMM)
//!  5. pmm::init()                    — physical memory manager (x86_64: no-op shim;
//!                                       real work done by pmm_add_efi_map / parse_mbi
//!                                       called from the multiboot2/UEFI entry points)
//!  6. heap::init()                   — linked-list allocator over PMM
//!  7. mm::init()                     — slab cache pre-warm (8 size classes)
//!  8. security::init()               — ASLR entropy, stack canaries, seccomp tables;
//!                                       must be up before syscall dispatch is live
//!  9. display::framebuffer::init()   — connect GOP/virtio-gpu framebuffer to kernel
//!                                       console; requires heap + mm
//! 10. display::drm::init()           — DRM/KMS object model (after framebuffer)
//! 11. display::wayland::init()       — Wayland compositor (after DRM)
//! 12. initramfs::mount()             — populate VFS from CPIO archive
//! 13. namespace::init()              — seed INIT_NS mount + UTS namespace tables
//! 14. apic::init()                   — local + IO APIC, timer IRQ
//! 15. time::init()                   — clocksource calibration (TSC/HPET), timerfd
//! 16. smp::init()                    — enumerate MADT CPUs, bring up APs
//! 17. pci::init()                    — full bus/device/function scan → PCI_DEVICES
//!                                       (after smp so per-CPU IRQ affinity is ready)
//! 18. drivers::ahci::init()          — SATA/AHCI block devices (after pci)
//! 19. drivers::nvme::init()          — NVMe block devices (after pci)
//! 20. block::virtio_blk::init()      — virtio-blk PCI variant (after pci)
//! 21. drivers::usb::init()           — xHCI host controller (after pci)
//! 22. drivers::keyboard::init()      — PS/2 keyboard (8042) or USB-HID kbd
//! 23. drivers::mouse::init()         — PS/2 mouse or USB-HID mouse
//! 24. drivers::evdev::init()         — evdev event layer (after kbd + mouse)
//! 25. input::init()                  — input event subsystem (after evdev)
//! 26. io_uring::init()               — ring table (requires alloc + live APIC/IDT)
//! 27. tty::init()                    — PTY registry + /dev/pts
//! 28. drivers::nic::init()           — NIC driver (e1000e / virtio-net)
//! 29. init::schemes::init()          — register built-in schemes into SCHEME_TABLE
//! 30. dhcp::init()                   — DORA handshake; sets IP/GW/mask
//! 31. cgroup::init()                 — seed ROOT_CGROUP
//! 32. shell::init()                  — built-in debug shell (after all subsystems)
//! 33. proc::spawn_init()             — spawn pid 1 from /init; scheduler takes over
//! ```
//!
//! ## RISC-V boot sequence
//!
//! ```text
//!  1. trap_init()                    — install stvec; enable SSIE/STIE/SEIE (must be first)
//!  2. fdt_phase1(fdt_ptr)            — PLIC base, initramfs bounds, CPU table.
//!                                       NO heap or PMM calls; safe before both.
//!  3. pmm::init(fdt_ptr)             — seed buddy allocator from FDT memory nodes
//!                                       (calls init_from_fdt internally; symmetric
//!                                       with the x86_64 pmm::init() call at step 5)
//!  4. plic::init()                   — write S-mode context threshold=0; unmask all IRQ prio≥1
//!  5. heap::init()                   — linked-list allocator over PMM
//!  6. mm::init()                     — slab cache pre-warm
//!  7. security::init()               — ASLR, stack canaries, seccomp tables
//!  8. debug::init()                  — GDB RSP stub (conditional)
//!  9. display::framebuffer::init()   — virtio-gpu framebuffer → kernel console
//! 10. display::drm::init()           — DRM/KMS object model
//! 11. display::wayland::init()       — Wayland compositor
//! 12. fdt_phase2(fdt_ptr)            — virtio-net + virtio-blk MMIO probe (alloc now safe)
//! 13. block::virtio_blk::init()      — virtio-blk MMIO variant
//! 14. drivers::keyboard::init()      — USB-HID / virtio keyboard
//! 15. drivers::mouse::init()         — USB-HID / virtio mouse
//! 16. drivers::evdev::init()         — evdev event layer
//! 17. input::init()                  — input event subsystem
//! 18. initramfs::mount()             — populate VFS from CPIO archive
//! 19. namespace::init()              — seed INIT_NS + UTS namespace tables
//! 20. time::init()                   — RISC-V timer (mtime/mtimecmp via SBI)
//! 21. drivers::nic::init()           — virtio-net MMIO
//! 22. init::schemes::init()          — register built-in schemes
//! 23. dhcp::init()                   — DORA handshake
//! 24. cgroup::init()                 — seed ROOT_CGROUP
//! 25. shell::init()                  — built-in debug shell
//! 26. proc::spawn_init()             — spawn pid 1; scheduler takes over
//! ```

// ── x86_64 ───────────────────────────────────────────────────────────────────

#[cfg(target_arch = "x86_64")]
pub fn kernel_main() -> ! {
    use crate::arch::x86_64::{apic, gdt, idt, pci};

    // ── Stage 1: console + debug ─────────────────────────────────────────────
    crate::serial::init();

    // Activate GDB stub before any subsequent panic can fire so that every
    // early fault is catchable.  Compiled out when cfg(debug_stub) is absent.
    #[cfg(feature = "debug_stub")]
    crate::debug::init();

    // ── Stage 2: CPU / interrupt infrastructure ───────────────────────────────
    gdt::init();
    idt::init();

    // ── Stage 3: memory ───────────────────────────────────────────────────────
    crate::pmm::init();
    crate::heap::init();
    crate::mm::init();

    // ── Stage 4: security framework ──────────────────────────────────────────
    // Must be up before syscall dispatch goes live (seccomp pre-check) and
    // before any process is spawned.
    crate::security::init();

    // ── Stage 5: display stack ────────────────────────────────────────────────
    // Connect the GOP/virtio-gpu framebuffer that firmware already set up,
    // then layer DRM/KMS and the Wayland compositor on top.
    crate::display::framebuffer::init();
    crate::display::drm::init();
    crate::display::wayland::init();

    // ── Stage 6: filesystem / namespace ──────────────────────────────────────
    crate::init::initramfs::mount();
    crate::namespace::init();

    // ── Stage 7: timers / SMP ────────────────────────────────────────────────
    apic::init();
    crate::time::init();
    crate::smp::init();

    // ── Stage 8: PCI bus scan ────────────────────────────────────────────────
    // Must come after SMP so per-CPU IRQ affinity tables are ready.
    pci::init();

    // ── Stage 9: block devices ───────────────────────────────────────────────
    crate::drivers::ahci::init();        // SATA/AHCI
    crate::drivers::nvme::init();        // NVMe
    crate::block::virtio_blk::init();    // virtio-blk (PCI variant)

    // ── Stage 10: USB + HID input ─────────────────────────────────────────────
    crate::drivers::usb::init();         // xHCI host controller
    crate::drivers::keyboard::init();    // PS/2 keyboard or USB-HID kbd
    crate::drivers::mouse::init();       // PS/2 mouse or USB-HID mouse
    crate::drivers::evdev::init();       // evdev event layer
    crate::input::init();                // input event subsystem

    // ── Stage 11: async I/O + TTY ────────────────────────────────────────────
    crate::io_uring::init();
    crate::tty::init();

    // ── Stage 12: networking ─────────────────────────────────────────────────
    crate::drivers::nic::init();
    crate::init::schemes::init();
    crate::dhcp::init();

    // ── Stage 13: process management + shell ─────────────────────────────────
    crate::proc::cgroup::init();
    crate::shell::init();                // built-in debug shell
    crate::proc::spawn_init();           // pid 1; does not return

    unreachable!("scheduler returned to kernel_main");
}

// ── riscv64 ──────────────────────────────────────────────────────────────────

#[cfg(target_arch = "riscv64")]
pub fn kernel_main(fdt_ptr: usize) -> ! {
    use crate::arch::riscv64::{fdt, plic, trap};

    // ── Stage 1: trap / interrupt routing ────────────────────────────────────
    trap::trap_init();                          // install stvec; enable S-mode interrupts

    // Phase 1 FDT scan: discover PLIC base, initramfs bounds, and CPU table.
    // Deliberately does NOT seed the PMM — that is pmm::init()'s job below,
    // keeping the two boot paths structurally symmetric.
    unsafe { fdt::fdt_phase1(fdt_ptr); }

    // ── Stage 2: physical memory manager ─────────────────────────────────────
    // Explicit call mirrors x86_64's pmm::init() at stage 3.  Internally
    // this calls pmm::init_from_fdt(fdt_ptr) to walk the FDT memory nodes
    // and seed the buddy allocator before any heap allocation can occur.
    crate::pmm::init(fdt_ptr);

    plic::init();                               // threshold=0; unmask all external IRQs

    // ── Stage 3: heap + slab ─────────────────────────────────────────────────
    crate::heap::init();
    crate::mm::init();

    // ── Stage 4: security + debug ─────────────────────────────────────────────
    crate::security::init();

    #[cfg(feature = "debug_stub")]
    crate::debug::init();

    // ── Stage 5: display stack ────────────────────────────────────────────────
    crate::display::framebuffer::init();
    crate::display::drm::init();
    crate::display::wayland::init();

    // ── Stage 6: virtio device probe (alloc now safe) ────────────────────────
    unsafe { fdt::fdt_phase2(fdt_ptr); }        // virtio-net + virtio-blk MMIO probe
    crate::block::virtio_blk::init();           // virtio-blk MMIO variant

    // ── Stage 7: HID input ────────────────────────────────────────────────────
    crate::drivers::keyboard::init();
    crate::drivers::mouse::init();
    crate::drivers::evdev::init();
    crate::input::init();

    // ── Stage 8: filesystem / namespace ──────────────────────────────────────
    crate::init::initramfs::mount();
    crate::namespace::init();

    // ── Stage 9: timers + networking ─────────────────────────────────────────
    crate::time::init();
    crate::drivers::nic::init();
    crate::init::schemes::init();
    crate::dhcp::init();

    // ── Stage 10: process management + shell ─────────────────────────────────
    crate::proc::cgroup::init();
    crate::shell::init();
    crate::proc::spawn_init();           // pid 1; does not return

    unreachable!("scheduler returned to kernel_main");
}

// ── Panic handler ────────────────────────────────────────────────────────────

/// Kernel panic handler.
///
/// In debug builds (`--features debug`) this calls `oops()` which prints:
///   - the panic message
///   - a frame-pointer stack backtrace with symbol names
///   - a flush of any pending trace ring-buffer events
///
/// In release builds the message is printed directly to the serial console
/// and the CPU halts.
#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    let msg = if let Some(m) = info.message().as_str() {
        m
    } else {
        "(no message)"
    };

    #[cfg(feature = "debug")]
    crate::debug::oops::oops(msg);

    #[cfg(not(feature = "debug"))]
    crate::serial_println!("KERNEL PANIC: {}", msg);

    loop {
        core::hint::spin_loop();
    }
}
