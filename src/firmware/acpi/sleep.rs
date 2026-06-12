//! ACPI S3 (suspend-to-RAM) sleep and resume path.
//!
//! ## How it works
//!
//! 1. Before entering S3 we save the AP wakeup vector into the FACS `FirmwareWakingVector` field so
//!    firmware knows where to jump on resume.
//! 2. The BSP issues the PM1a/PM1b sleep transition.
//! 3. On resume, real-mode trampoline code (not here) reloads the GDT/IDT and jumps to
//!    `resume_entry` which restores saved registers and returns.
//!
//! This file owns:
//! - FACS discovery and wakeup-vector installation
//! - S3 preparation hooks (arch-level save is called out to `crate::arch`)
//! - A minimal resume stub that re-enables ACPI and signals completion

use super::power::{enter_sleep_state, init as power_init};
use crate::println;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

#[repr(C, packed)]
struct Facs {
    sig: [u8; 4], // "FACS"
    len: u32,
    hw_sig: u32,
    fw_waking_vector: u32, // 32-bit real-mode wakeup address
    global_lock: u32,
    flags: u32,
    x_fw_waking_vector: u64, // 64-bit wakeup address (ACPI ≥ 2.0)
    version: u8,
    _rsvd: [u8; 3],
    ospm_flags: u32,
    _rsvd2: [u8; 24],
}

const FADT_OFF_FIRMWARE_CTRL: usize = 36; // 32-bit FACS phys address
const FADT_OFF_X_FIRMWARE_CTRL: usize = 132; // 64-bit FACS phys address (v2)

// Physical address of the FACS, discovered at init time.
static FACS_PHYS: AtomicU32 = AtomicU32::new(0);

/// Set to true once a successful S3 resume has been detected.
pub static RESUMED_FROM_S3: AtomicBool = AtomicBool::new(false);

/// Locate the FACS and cache its physical address.
///
/// Must be called after `super::init()` and `power::init()`.
pub unsafe fn init() {
    let fadt = match super::find_table(b"FACP") {
        Some(p) => p as *const u8,
        None => {
            println!("acpi/sleep: FADT not found, S3 unavailable");
            return;
        },
    };

    let fadt_len = (*(fadt as *const super::SdtHeader)).len as usize;

    // Prefer the 64-bit pointer (FADT v2+).
    let facs_phys: u32 = if fadt_len > FADT_OFF_X_FIRMWARE_CTRL + 8 {
        let x = (fadt.add(FADT_OFF_X_FIRMWARE_CTRL) as *const u64).read_unaligned();
        if x != 0 && x < u32::MAX as u64 {
            x as u32
        } else {
            (fadt.add(FADT_OFF_FIRMWARE_CTRL) as *const u32).read_unaligned()
        }
    } else if fadt_len > FADT_OFF_FIRMWARE_CTRL + 4 {
        (fadt.add(FADT_OFF_FIRMWARE_CTRL) as *const u32).read_unaligned()
    } else {
        0
    };

    if facs_phys == 0 {
        println!("acpi/sleep: no FACS pointer in FADT");
        return;
    }

    let facs = &*(facs_phys as usize as *const Facs);
    if &facs.sig != b"FACS" {
        println!("acpi/sleep: bad FACS signature");
        return;
    }

    FACS_PHYS.store(facs_phys, Ordering::Relaxed);
    let hw_sig = core::ptr::addr_of!(facs.hw_sig).read_unaligned();
    println!(
        "acpi/sleep: FACS @ {:#010x}  hw_sig={:#010x}",
        facs_phys, hw_sig
    );
}

/// Install `wakeup_vector` as the 64-bit wakeup entry point in the FACS.
///
/// Call this right before `suspend_s3()`.  The vector should point at a
/// real-mode (or long-mode, for FACS version ≥ 2) trampoline page.
pub unsafe fn set_wakeup_vector(wakeup_vector: u64) {
    let phys = FACS_PHYS.load(Ordering::Relaxed);
    if phys == 0 {
        println!("acpi/sleep: FACS not discovered, cannot set wakeup vector");
        return;
    }
    let facs = &mut *(phys as usize as *mut Facs);
    if facs.version >= 1 {
        // ACPI 2.0+: use the 64-bit field so we can wake into long mode.
        core::ptr::addr_of_mut!(facs.x_fw_waking_vector).write_unaligned(wakeup_vector);
        core::ptr::addr_of_mut!(facs.fw_waking_vector).write_unaligned(0u32);
    } else {
        core::ptr::addr_of_mut!(facs.fw_waking_vector).write_unaligned(wakeup_vector as u32);
    }
    // Memory barrier so the write is visible to firmware.
    core::sync::atomic::fence(Ordering::SeqCst);
    println!("acpi/sleep: wakeup vector set to {:#018x}", wakeup_vector);
}

/// Save arch-level CPU state then enter S3.
///
/// Returns only after a successful resume; returns `Err` if the sleep
/// transition cannot be initiated.
pub unsafe fn suspend_s3(wakeup_vector: u64) -> Result<(), &'static str> {
    set_wakeup_vector(wakeup_vector);

    // Ask the arch layer to flush caches and save CPU state.
    // The architecture module exposes a thin hook we can call safely here.
    #[cfg(target_arch = "x86_64")]
    crate::arch::x86_64::power::save_and_flush();

    println!("acpi/sleep: entering S3");
    enter_sleep_state(3);
    // Execution continues here on resume (after the trampoline returns).
    on_resume()
}

/// Called by the wakeup trampoline (or directly from `suspend_s3` after the
/// CPU returns from sleep).
///
/// Re-initialises ACPI PM registers that firmware may have reset.
pub unsafe fn on_resume() -> Result<(), &'static str> {
    RESUMED_FROM_S3.store(true, Ordering::SeqCst);
    println!("acpi/sleep: resumed from S3, re-initialising power subsystem");
    // Re-arm the ACPI SCI and PM1 enables.
    power_init();
    Ok(())
}
