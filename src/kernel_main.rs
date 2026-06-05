//! Architecture-independent kernel entry-point dispatcher.
//!
//! Every boot path builds a [`BootInfo`] and enters this single exported symbol.
//! Boot priority (x86_64 = PRIMARY, aarch64 = SECONDARY, riscv64 = TERTIARY)
//! is logged here before handing off to the arch-specific initialisation layer,
//! so every boot log is self-documenting regardless of which image ran.

use crate::init::boot_info::BootInfo;

#[no_mangle]
pub extern "C" fn kernel_main(boot_info: &'static BootInfo) -> ! {
    // Emit the boot priority banner before any arch-specific code runs so
    // that the very first kernel log line identifies the active target.
    crate::serial_println!(
        "RustOS: boot target [{}] — entering common kernel_main",
        BootInfo::priority().as_str(),
    );

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
