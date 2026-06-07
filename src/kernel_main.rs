//! Architecture-independent kernel entry-point dispatcher.

use crate::init::boot_info::BootInfo;

#[no_mangle]
pub extern "C" fn kernel_main(boot_info: &'static BootInfo) -> ! {
    crate::serial_println!(
        "RustOS: boot target [{}] — entering common kernel_main",
        BootInfo::priority().as_str(),
    );

    crate::kernel::architecture::log_kernel_architecture();
    debug_assert!(crate::kernel::architecture::is_hybrid_kernel());
    crate::arch::init(boot_info)
}
