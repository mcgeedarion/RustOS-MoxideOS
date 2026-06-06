//! AArch64 SMP secondary-CPU bring-up via PSCI.
//!
//! `bring_up_secondaries()` iterates the CPU topology discovered from the
//! device tree / ACPI MADT, allocates a kernel stack for each secondary,
//! and calls `PSCI CPU_ON` to start it.
//!
//! Each secondary executes `secondary_entry` (in `secondary_entry.S`) which
//! sets up SP_EL1 then jumps to `secondary_rust_main`.
//!
//! ## PSCI interface
//!
//! We use the SMCCC / HVC conduit already wrapped by
//! `crate::firmware::psci`.  The function ID for CPU_ON (64-bit) is
//! 0xC400_0003.

#![allow(dead_code)]

use core::sync::atomic::{AtomicU64, Ordering};

/// Stack top for the next secondary being started.  Written by the BSP before
/// calling PSCI CPU_ON; read by `secondary_entry.S` before branching to Rust.
pub static SECONDARY_STACK_TOP: AtomicU64 = AtomicU64::new(0);

/// Bring up all secondary CPUs listed in the platform topology.
pub fn bring_up_secondaries() {
    let secondaries = crate::firmware::topology::secondary_mpidrs();
    if secondaries.is_empty() {
        return;
    }

    extern "C" {
        fn secondary_entry();
    }

    for mpidr in secondaries {
        let stack_top = match crate::mm::pmm::alloc_pages(4) {
            Some(pa) => pa + 4 * 4096,
            None => {
                crate::serial_println!("smp: out of memory for secondary stack mpidr={:#x}", mpidr);
                continue;
            },
        };

        SECONDARY_STACK_TOP.store(stack_top as u64, Ordering::Release);

        unsafe {
            if let Err(e) = crate::firmware::psci::cpu_on(mpidr, secondary_entry as usize as u64, 0)
            {
                crate::serial_println!(
                    "smp: psci cpu_on failed for mpidr={:#x} err={:?}",
                    mpidr,
                    e
                );
            }
        }

        // Spin briefly so SECONDARY_STACK_TOP is consumed before we
        // overwrite it for the next CPU.
        let timeout = 1_000_000u64;
        let start = super::cpu::read_virtual_count();
        while SECONDARY_STACK_TOP.load(Ordering::Acquire) != 0 {
            if super::cpu::read_virtual_count().wrapping_sub(start) > timeout {
                crate::serial_println!("smp: timeout waiting for secondary mpidr={:#x}", mpidr);
                break;
            }
            core::hint::spin_loop();
        }
    }
}

/// Rust entry point for secondary CPUs.  Called from `secondary_entry.S`
/// after SP_EL1 is set up.
#[no_mangle]
extern "C" fn secondary_rust_main() -> ! {
    // Signal that our stack has been consumed and the BSP may proceed.
    SECONDARY_STACK_TOP.store(0, Ordering::Release);

    unsafe {
        super::cpu::enable_fp_simd();
        super::interrupts::init();
    }

    crate::irq::aarch64::gic::init_percpu();
    crate::proc::scheduler::secondary_online();
    crate::proc::scheduler::run()
}
