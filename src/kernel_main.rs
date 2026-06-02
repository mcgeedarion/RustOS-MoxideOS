//! Architecture-independent kernel entry-point dispatcher.
//!
//! Every boot path builds a [`BootInfo`] and enters this single exported symbol.

use crate::init::boot_info::BootInfo;

#[no_mangle]
pub extern "C" fn kernel_main(boot_info: &'static BootInfo) -> ! {
    crate::kernel::architecture::log_kernel_architecture();
    debug_assert!(crate::kernel::architecture::is_hybrid_kernel());
    crate::arch::init(boot_info)
}

#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    crate::serial_println!("KERNEL PANIC: {}", info);
    loop {
        #[cfg(target_arch = "x86_64")]
        unsafe {
            core::arch::asm!("hlt", options(nostack, nomem));
        }
        #[cfg(target_arch = "riscv64")]
        unsafe {
            core::arch::asm!("wfi", options(nostack, nomem));
        }
        #[cfg(target_arch = "aarch64")]
        crate::arch::aarch64::hal::wait_for_interrupt();
    }
}
