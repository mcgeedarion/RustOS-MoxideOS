//! ARM PSCI (Power State Coordination Interface) via SMC/HVC conduit.
//!
//! Used by the AArch64 SMP bringup path to start secondary CPUs.
//!
//! ## Conduit selection
//!
//! PSCI can be invoked via either `smc #0` (Secure Monitor Call) or
//! `hvc #0` (Hypervisor Call).  QEMU virt exposes PSCI over HVC; real
//! hardware may differ.  We default to HVC and expose `smc_call` /
//! `hvc_call` directly so callers can choose.
//!
//! ## Function IDs (PSCI 1.0, 64-bit)
//!
//!   CPU_ON          0xC400_0003
//!   CPU_OFF         0x8400_0002  (no-return, called on secondary)
//!   CPU_SUSPEND     0xC400_0001
//!   SYSTEM_OFF      0x8400_0008
//!   SYSTEM_RESET    0x8400_0009

#![allow(dead_code)]

use core::arch::asm;

// ── PSCI function IDs (SMCCC 64-bit) ──────────────────────────────────────────────
pub const CPU_ON:      u64 = 0xC400_0003;
pub const CPU_OFF:     u64 = 0x8400_0002;
pub const CPU_SUSPEND: u64 = 0xC400_0001;
pub const SYSTEM_OFF:  u64 = 0x8400_0008;
pub const SYSTEM_RESET:u64 = 0x8400_0009;
pub const PSCI_VERSION:u64 = 0x8400_0000;

// ── PSCI return codes ────────────────────────────────────────────────────────────────
pub const SUCCESS:          i64 = 0;
pub const NOT_SUPPORTED:    i64 = -1;
pub const INVALID_PARAMS:   i64 = -2;
pub const DENIED:           i64 = -3;
pub const ALREADY_ON:       i64 = -4;
pub const ON_PENDING:        i64 = -5;
pub const INTERNAL_FAILURE: i64 = -6;
pub const NOT_PRESENT:      i64 = -7;
pub const DISABLED:         i64 = -8;
pub const INVALID_ADDRESS:  i64 = -9;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PsciError {
    NotSupported,
    InvalidParams,
    Denied,
    AlreadyOn,
    OnPending,
    InternalFailure,
    NotPresent,
    Disabled,
    InvalidAddress,
    Unknown(i64),
}

impl PsciError {
    fn from_code(code: i64) -> Self {
        match code {
            NOT_SUPPORTED    => Self::NotSupported,
            INVALID_PARAMS   => Self::InvalidParams,
            DENIED           => Self::Denied,
            ALREADY_ON       => Self::AlreadyOn,
            ON_PENDING       => Self::OnPending,
            INTERNAL_FAILURE => Self::InternalFailure,
            NOT_PRESENT      => Self::NotPresent,
            DISABLED         => Self::Disabled,
            INVALID_ADDRESS  => Self::InvalidAddress,
            other            => Self::Unknown(other),
        }
    }
}

// ── Raw SMCCC call via HVC ────────────────────────────────────────────────────────

/// Invoke SMCCC via `hvc #0`.  x0 = function_id, x1/x2/x3 = args.
/// Returns (x0, x1, x2, x3).
#[inline]
pub unsafe fn hvc_call(fid: u64, a1: u64, a2: u64, a3: u64) -> (i64, u64, u64, u64) {
    let r0: i64;
    let r1: u64;
    let r2: u64;
    let r3: u64;
    asm!(
        "hvc #0",
        inout("x0") fid as i64 => r0,
        inout("x1") a1 => r1,
        inout("x2") a2 => r2,
        inout("x3") a3 => r3,
        options(nomem, nostack)
    );
    (r0, r1, r2, r3)
}

/// Invoke SMCCC via `smc #0`.
#[inline]
pub unsafe fn smc_call(fid: u64, a1: u64, a2: u64, a3: u64) -> (i64, u64, u64, u64) {
    let r0: i64;
    let r1: u64;
    let r2: u64;
    let r3: u64;
    asm!(
        "smc #0",
        inout("x0") fid as i64 => r0,
        inout("x1") a1 => r1,
        inout("x2") a2 => r2,
        inout("x3") a3 => r3,
        options(nomem, nostack)
    );
    (r0, r1, r2, r3)
}

// ── Public PSCI API ────────────────────────────────────────────────────────────────────

/// Power on a secondary CPU.
///
/// `mpidr`  — MPIDR of the target CPU (affinity value from topology)
/// `entry`  — physical address of the secondary entry point
/// `context`— value placed in x0 when the secondary starts (may be 0)
///
/// Returns `Ok(())` on success or `Err(PsciError)` on failure.
pub unsafe fn cpu_on(mpidr: u64, entry: u64, context: u64) -> Result<(), PsciError> {
    let (ret, _, _, _) = hvc_call(CPU_ON, mpidr, entry, context);
    if ret == SUCCESS { Ok(()) } else { Err(PsciError::from_code(ret)) }
}

/// Power off the calling CPU (no-return).
///
/// # Safety
/// The calling CPU must have migrated all state and must not hold any locks.
pub unsafe fn cpu_off() -> ! {
    hvc_call(CPU_OFF, 0, 0, 0);
    loop { core::arch::asm!("wfi", options(nostack, nomem)); }
}

/// System shutdown.
pub unsafe fn system_off() -> ! {
    hvc_call(SYSTEM_OFF, 0, 0, 0);
    loop { core::arch::asm!("wfi", options(nostack, nomem)); }
}

/// System reset / reboot.
pub unsafe fn system_reset() -> ! {
    hvc_call(SYSTEM_RESET, 0, 0, 0);
    loop { core::arch::asm!("wfi", options(nostack, nomem)); }
}

/// Return the PSCI version as (major, minor), or None if not supported.
pub unsafe fn version() -> Option<(u16, u16)> {
    let (ret, _, _, _) = hvc_call(PSCI_VERSION, 0, 0, 0);
    if ret < 0 { return None; }
    let v = ret as u32;
    Some(((v >> 16) as u16, (v & 0xffff) as u16))
}
