pub mod boot;
pub mod csr;
pub mod fdt;
pub mod hal;
pub mod mem_layout;
pub mod memory;
pub mod paging;
pub mod smp;
pub mod syscall;
pub mod trampoline;
pub mod trap;
pub mod uefi_entry;
pub mod uentry;

// Canonical home for the RISC-V PLIC driver is `crate::irq::riscv64::plic`.
// Re-export it here so call sites that use the `arch::riscv64::plic` path
// (FDT walker, kernel init, etc.) keep working without a flag day.
pub use crate::irq::riscv64::plic;

/// RISC-V early/kernel boot hook used by the common entry point.
pub fn init(boot_info: &'static crate::init::boot_info::BootInfo) -> ! {
    use crate::arch::riscv64::{fdt, trap};
    use crate::irq::riscv64::plic;

    let fdt_ptr = boot_info.fdt.start;
    trap::trap_init();
    if fdt_ptr != 0 {
        unsafe {
            fdt::fdt_phase1(fdt_ptr);
        }
    }

    let regions = crate::arch::riscv64::memory::discover(fdt_ptr);
    unsafe {
        crate::mm::pmm::init_from_regions(&regions);
    }

    plic::init();
    crate::heap::init();
    crate::mm::init();
    crate::security::init();

    // Mirror the x86_64 pattern (kernel_main.rs:141): gate on `gdbstub`,
    // not the stale `debugstub` name, and call the real session init.
    // `pub mod debug` in lib.rs is compiled only when `gdbstub` is active,
    // so `crate::debug::init()` (which does not exist) would fail to compile.
    #[cfg(feature = "gdbstub")]
    {
        static mut GDBSTUB_SERIAL: crate::debug::gdbstub::serial::SerialPort =
            unsafe { crate::debug::gdbstub::serial::SerialPort::new() };
        unsafe {
            crate::debug::gdbstub::session::init(&mut GDBSTUB_SERIAL);
        }
    }

    crate::display::framebuffer::init();
    crate::display::drm::init();
    crate::display::wayland::init();

    if fdt_ptr != 0 {
        unsafe {
            fdt::fdt_phase2(fdt_ptr);
        }
    }
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

    #[cfg(feature = "kmtest")]
    crate::kmtest::init();

    crate::proc::spawn_init();

    unreachable!("scheduler returned to kernel_main");
}
