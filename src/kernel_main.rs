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
//! See `arch::x86_64::kernel_main` for the full x86_64 boot pipeline.
//! When `feature = "kmtest"` is active, `kmtest::init()` is called there
//! immediately before `proc::spawn_init()` (same placement as RISC-V below).
//!
//! ## RISC-V boot sequence
//!
//! ```text
//!  1. trap_init()                    — install stvec; enable SSIE/STIE/SEIE (must be first)
//!  2. fdt_phase1(fdt_ptr)            — PLIC base, initramfs bounds, CPU table (no PMM)
//!  3. arch::riscv64::memory::discover(fdt_ptr) → pmm::init_from_regions()
//!  4. plic::init()                   — threshold=0; unmask IRQs
//!  5. heap::init()                   — linked-list allocator over PMM
//!  6. mm::init()                     — slab cache pre-warm
//!  7. security::init()               — ASLR, stack canaries, seccomp tables
//!  8. debug::init()                  — GDB RSP stub (gated on `debug_stub`; implied by `debug`)
//!  9. display::framebuffer::init()   — virtio-gpu framebuffer → kernel console
//! 10. display::drm::init()           — DRM/KMS object model
//! 11. display::wayland::init()       — Wayland compositor
//! 12. fdt_phase2(fdt_ptr)            — virtio-net + virtio-blk MMIO probe (alloc safe)
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
//! 26. kmtest::init()                 — register test suites [cfg(feature = "kmtest")]
//! 27. proc::spawn_init()             — spawn pid 1; scheduler takes over
//! ```

// ── x86_64 ────────────────────────────────────────────────────────────────────────

#[cfg(target_arch = "x86_64")]
pub fn kernel_main() -> ! {
    crate::arch::x86_64::kernel_main::kernel_main()
}

// ── riscv64 ─────────────────────────────────────────────────────────────────────

#[cfg(target_arch = "riscv64")]
pub fn kernel_main_riscv64(fdt_ptr: usize) -> ! {
    use crate::arch::riscv64::{fdt, plic, trap};

    trap::trap_init();
    unsafe { fdt::fdt_phase1(fdt_ptr); }

    let regions = crate::arch::riscv64::memory::discover(fdt_ptr);
    unsafe { crate::mm::pmm::init_from_regions(&regions); }

    plic::init();

    crate::heap::init();
    crate::mm::init();

    crate::security::init();

    // Gated on `debug_stub`; the umbrella `debug` feature implies it via
    // Cargo feature dependencies (see Cargo.toml [features]).
    #[cfg(feature = "debug_stub")]
    crate::debug::init();

    crate::display::framebuffer::init();
    crate::display::drm::init();
    crate::display::wayland::init();

    unsafe { fdt::fdt_phase2(fdt_ptr); }
    crate::block::virtio_blk::init();

    crate::drivers::keyboard::init();
    crate::drivers::mouse::init();
    crate::drivers::evdev::init();
    crate::input::init();

    crate::init::initramfs::mount();
    crate::namespace::init();

    crate::time::init();
    crate::drivers::nic::init();
    crate::init::schemes::init();
    crate::dhcp::init();

    crate::proc::cgroup::init();
    crate::shell::init();

    // Register all kernel test suites before handing off to the scheduler.
    // Tests are triggered later by the userspace kmtest runner via
    // SYS_KMTEST_LIST / SYS_KMTEST_RUN.
    #[cfg(feature = "kmtest")]
    crate::kmtest::init();

    crate::proc::spawn_init();

    unreachable!("scheduler returned to kernel_main_riscv64");
}

// ── Panic handler ─────────────────────────────────────────────────────────────

#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    let msg = info.message().as_str().unwrap_or("(no message)");

    // Always emit a canonical header with source location so the crash site
    // is visible even in release builds without a full oops backtrace.
    if let Some(loc) = info.location() {
        crate::serial_println!(
            "KERNEL PANIC at {}:{}:{}: {}",
            loc.file(),
            loc.line(),
            loc.column(),
            msg,
        );
    } else {
        crate::serial_println!("KERNEL PANIC: {}", msg);
    }

    // In debug builds additionally trigger the full oops handler:
    // register dump, frame-pointer backtrace, and trace drain.
    // `debug` implies `debug_stub` and `trace` via Cargo feature deps.
    #[cfg(feature = "debug")]
    crate::debug::oops::oops(msg);

    loop { core::hint::spin_loop(); }
}
