pub mod boot;
pub mod csr;
pub mod fdt;
pub mod hal;
pub mod mem_layout;
pub mod memory;
pub mod paging;
pub mod smp;
pub mod syscall;
pub mod trap;
pub mod trampoline;
pub mod uefi_entry;
pub mod uentry;

/// RISC-V early/kernel boot hook used by the common entry point.
pub fn init(boot_info: &'static crate::init::boot_info::BootInfo) -> ! {
    use crate::arch::riscv64::{fdt, plic, trap};

    let fdt_ptr = boot_info.fdt.start;
    trap::trap_init();
    if fdt_ptr != 0 {
        unsafe { fdt::fdt_phase1(fdt_ptr); }
    }

    let regions = crate::arch::riscv64::memory::discover(fdt_ptr);
    unsafe { crate::mm::pmm::init_from_regions(&regions); }

    plic::init();
    crate::heap::init();
    crate::mm::init();
    crate::security::init();

    #[cfg(feature = "debug_stub")]
    crate::debug::init();

    crate::display::framebuffer::init();
    crate::display::drm::init();
    crate::display::wayland::init();

    if fdt_ptr != 0 {
        unsafe { fdt::fdt_phase2(fdt_ptr); }
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
