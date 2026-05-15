//! RISC-V HAL implementation.
//!
//! Provides the hardware-abstraction layer for the `riscv64gc` target, covering:
//!
//! * **SBI ecall wrappers** — Timer, Console, IPI, HSM, SRST, RFENCE (new-style +
//!   legacy fallback).
//! * **CSR read/write helpers** — `sstatus`, `sie`, `sip`, `sepc`, `scause`,
//!   `stval`, `sscratch`, `satp`, `stvec`, `time`, `cycle`, `instret`.
//! * **Interrupt control** — enable/disable/`without_interrupts`.
//! * **TLB management** — local `sfence.vma` variants; remote via SBI RFENCE.
//! * **Paging** — Sv39/Sv48/BARE `satp` helpers.
//! * **FPU** — `sstatus.FS` management.
//! * **SMP** — hart start/stop via SBI HSM; IPI dispatch.
//! * **Timer** — `time` CSR read; `set_timer` / `clear_timer` via SBI.
//! * **GDB stub** — single-step flag consumed by the trap handler.
//! * **Early console** — SBI legacy putchar/getchar (used before the UART
//!   driver is up, and by the GDB RSP transport).
//! * **Platform init** — `early_init` (boot hart) / `secondary_init` (APs).
//! * **Shutdown / reboot** — SBI SRST with legacy fallback.

#![allow(dead_code)]

use core::arch::asm;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

// ═══════════════════════════════════════════════════════════════════════════════
// SBI raw ecall
// ═══════════════════════════════════════════════════════════════════════════════

/// Return value from every SBI ecall: an error code and a return value.
///
/// The SBI calling convention places these in `a0` and `a1` after the `ecall`.
#[derive(Clone, Copy, Debug)]
pub struct SbiRet {
    pub error: isize,
    pub value: usize,
}

impl SbiRet {
    /// `true` when `error == SBI_SUCCESS (0)`.
    #[inline]
    pub fn is_ok(self) -> bool {
        self.error == SBI_SUCCESS
    }

    /// Panics with the error code on failure; otherwise returns the value.
    #[inline]
    pub fn unwrap(self) -> usize {
        assert!(self.is_ok(), "SBI call failed: error={}", self.error);
        self.value
    }
}

/// Perform a raw SBI ecall.
///
/// # Safety
/// The caller must supply a valid EID/FID pair and arguments for the SBI
/// implementation running on this hart.
#[inline(always)]
pub unsafe fn sbi_call(
    eid: usize,
    fid: usize,
    a0: usize,
    a1: usize,
    a2: usize,
    a3: usize,
    a4: usize,
    a5: usize,
) -> SbiRet {
    let error: isize;
    let value: usize;
    unsafe {
        asm!(
            "ecall",
            inlateout("a0") a0 => error,
            inlateout("a1") a1 => value,
            in("a2") a2,
            in("a3") a3,
            in("a4") a4,
            in("a5") a5,
            in("a6") fid,
            in("a7") eid,
            options(nostack),
        );
    }
    SbiRet { error, value }
}

// ─── SBI error codes ──────────────────────────────────────────────────────────

pub const SBI_SUCCESS: isize = 0;
pub const SBI_ERR_FAILED: isize = -1;
pub const SBI_ERR_NOT_SUPPORTED: isize = -2;
pub const SBI_ERR_INVALID_PARAM: isize = -3;
pub const SBI_ERR_DENIED: isize = -4;
pub const SBI_ERR_INVALID_ADDRESS: isize = -5;
pub const SBI_ERR_ALREADY_AVAILABLE: isize = -6;
pub const SBI_ERR_ALREADY_STARTED: isize = -7;
pub const SBI_ERR_ALREADY_STOPPED: isize = -8;

// ─── SBI Extension IDs (EIDs) ────────────────────────────────────────────────

// Legacy (<= SBI v0.1) — a6 is ignored; a7 is EID == FID.
pub const SBI_EID_LEGACY_SET_TIMER: usize = 0x00;
pub const SBI_EID_LEGACY_PUTCHAR: usize = 0x01;
pub const SBI_EID_LEGACY_GETCHAR: usize = 0x02;
pub const SBI_EID_LEGACY_SHUTDOWN: usize = 0x08;

// Base Extension (SBI v0.2+).
pub const SBI_EID_BASE: usize = 0x10;
pub const SBI_FID_BASE_GET_SPEC_VERSION: usize = 0;
pub const SBI_FID_BASE_GET_IMPL_ID: usize = 1;
pub const SBI_FID_BASE_GET_IMPL_VERSION: usize = 2;
pub const SBI_FID_BASE_PROBE_EXTENSION: usize = 3;
pub const SBI_FID_BASE_GET_MVENDORID: usize = 4;
pub const SBI_FID_BASE_GET_MARCHID: usize = 5;
pub const SBI_FID_BASE_GET_MIMPID: usize = 6;

// Timer Extension — EID "TIME" (0x54494D45).
pub const SBI_EID_TIMER: usize = 0x54494D45;
pub const SBI_FID_TIMER_SET_TIMER: usize = 0;

// IPI Extension — EID "sPI" (0x735049).
pub const SBI_EID_IPI: usize = 0x735049;
pub const SBI_FID_IPI_SEND_IPI: usize = 0;

// RFENCE Extension — EID "RFNC" (0x52464E43).
pub const SBI_EID_RFENCE: usize = 0x52464E43;
pub const SBI_FID_RFENCE_REMOTE_FENCE_I: usize = 0;
pub const SBI_FID_RFENCE_REMOTE_SFENCE_VMA: usize = 1;
pub const SBI_FID_RFENCE_REMOTE_SFENCE_VMA_ASID: usize = 2;

// HSM Extension — EID "HSM" (0x48534D).
pub const SBI_EID_HSM: usize = 0x48534D;
pub const SBI_FID_HSM_HART_START: usize = 0;
pub const SBI_FID_HSM_HART_STOP: usize = 1;
pub const SBI_FID_HSM_HART_GET_STATUS: usize = 2;
pub const SBI_FID_HSM_HART_SUSPEND: usize = 3;

// Hart states returned by HSM_HART_GET_STATUS.
pub const SBI_HSM_STATE_STARTED: usize = 0;
pub const SBI_HSM_STATE_STOPPED: usize = 1;
pub const SBI_HSM_STATE_START_PENDING: usize = 2;
pub const SBI_HSM_STATE_STOP_PENDING: usize = 3;
pub const SBI_HSM_STATE_SUSPENDED: usize = 4;
pub const SBI_HSM_STATE_SUSPEND_PENDING: usize = 5;
pub const SBI_HSM_STATE_RESUME_PENDING: usize = 6;

// HSM suspend types.
pub const SBI_HSM_SUSPEND_RETENTIVE: usize = 0;

// System Reset Extension — EID "SRST" (0x53525354).
pub const SBI_EID_SRST: usize = 0x53525354;
pub const SBI_FID_SRST_SYSTEM_RESET: usize = 0;
pub const SBI_SRST_TYPE_SHUTDOWN: usize = 0;
pub const SBI_SRST_TYPE_COLD_REBOOT: usize = 1;
pub const SBI_SRST_TYPE_WARM_REBOOT: usize = 2;
pub const SBI_SRST_REASON_NONE: usize = 0;
pub const SBI_SRST_REASON_SYSTEM_FAILURE: usize = 1;

// ═══════════════════════════════════════════════════════════════════════════════
// SBI convenience wrappers
// ═══════════════════════════════════════════════════════════════════════════════

pub mod sbi {
    use super::*;

    // ── Base ─────────────────────────────────────────────────────────────────

    /// Probe for a SBI extension by EID.  Returns `true` if supported.
    #[inline]
    pub fn probe_extension(eid: usize) -> bool {
        let r = unsafe {
            sbi_call(
                SBI_EID_BASE,
                SBI_FID_BASE_PROBE_EXTENSION,
                eid,
                0,
                0,
                0,
                0,
                0,
            )
        };
        r.is_ok() && r.value != 0
    }

    /// Return the SBI specification version as `(major, minor)`.
    #[inline]
    pub fn spec_version() -> (u32, u32) {
        let r = unsafe {
            sbi_call(
                SBI_EID_BASE,
                SBI_FID_BASE_GET_SPEC_VERSION,
                0,
                0,
                0,
                0,
                0,
                0,
            )
        };
        let v = r.value as u32;
        ((v >> 24) & 0x7f, v & 0x00ff_ffff)
    }

    /// Return the SBI implementation ID.
    #[inline]
    pub fn impl_id() -> usize {
        unsafe { sbi_call(SBI_EID_BASE, SBI_FID_BASE_GET_IMPL_ID, 0, 0, 0, 0, 0, 0).value }
    }

    /// Return the RISC-V `marchid` CSR value (M-mode; relayed via SBI).
    #[inline]
    pub fn marchid() -> usize {
        unsafe { sbi_call(SBI_EID_BASE, SBI_FID_BASE_GET_MARCHID, 0, 0, 0, 0, 0, 0).value }
    }

    // ── Console (legacy) ─────────────────────────────────────────────────────

    /// Transmit a byte over the SBI debug console (legacy EID 0x01).
    ///
    /// Blocks until the implementation has accepted the byte.
    #[inline]
    pub fn console_putchar(c: u8) {
        unsafe {
            sbi_call(SBI_EID_LEGACY_PUTCHAR, 0, c as usize, 0, 0, 0, 0, 0);
        }
    }

    /// Receive a byte from the SBI debug console (legacy EID 0x02).
    ///
    /// Returns `None` if no character is ready.
    #[inline]
    pub fn console_getchar() -> Option<u8> {
        let r = unsafe { sbi_call(SBI_EID_LEGACY_GETCHAR, 0, 0, 0, 0, 0, 0, 0) };
        // The legacy spec returns the character in a0 (our `error` field), or
        // -1 if nothing is available.
        if r.error < 0 {
            None
        } else {
            Some(r.error as u8)
        }
    }

    /// Write a string to the SBI debug console, one byte at a time.
    #[inline]
    pub fn console_write(s: &str) {
        for b in s.bytes() {
            console_putchar(b);
        }
    }

    // ── Timer ────────────────────────────────────────────────────────────────

    /// Program the next supervisor timer interrupt.
    ///
    /// `stime_value` is an absolute value of the `time` CSR.  When the counter
    /// reaches this value `sip.STIP` is asserted.
    ///
    /// Tries the new-style Timer extension (EID 0x54494D45) first, then falls
    /// back to legacy EID 0x00.
    #[inline]
    pub fn set_timer(stime_value: u64) {
        let r = unsafe {
            sbi_call(
                SBI_EID_TIMER,
                SBI_FID_TIMER_SET_TIMER,
                stime_value as usize,
                0,
                0,
                0,
                0,
                0,
            )
        };
        if !r.is_ok() {
            // Legacy fallback — single a0 argument on rv64.
            unsafe {
                sbi_call(
                    SBI_EID_LEGACY_SET_TIMER,
                    0,
                    stime_value as usize,
                    0,
                    0,
                    0,
                    0,
                    0,
                );
            }
        }
    }

    // ── IPI ──────────────────────────────────────────────────────────────────

    /// Send a supervisor software IPI to the harts described by the mask.
    ///
    /// `hart_mask`      — bitmask (bit *i* = hart `hart_mask_base + i`).
    /// `hart_mask_base` — lowest hart ID in the mask; `usize::MAX` means all.
    #[inline]
    pub fn send_ipi(hart_mask: usize, hart_mask_base: usize) -> SbiRet {
        unsafe {
            sbi_call(
                SBI_EID_IPI,
                SBI_FID_IPI_SEND_IPI,
                hart_mask,
                hart_mask_base,
                0,
                0,
                0,
                0,
            )
        }
    }

    // ── RFENCE ───────────────────────────────────────────────────────────────

    /// Issue a remote `SFENCE.VMA` covering `[vaddr, vaddr+size)` on harts in
    /// `hart_mask`.
    ///
    /// Pass `vaddr = 0, size = usize::MAX` to flush all mappings.
    #[inline]
    pub fn remote_sfence_vma(
        hart_mask: usize,
        hart_mask_base: usize,
        vaddr: usize,
        size: usize,
    ) -> SbiRet {
        unsafe {
            sbi_call(
                SBI_EID_RFENCE,
                SBI_FID_RFENCE_REMOTE_SFENCE_VMA,
                hart_mask,
                hart_mask_base,
                vaddr,
                size,
                0,
                0,
            )
        }
    }

    /// Issue a remote `SFENCE.VMA` for a specific ASID.
    #[inline]
    pub fn remote_sfence_vma_asid(
        hart_mask: usize,
        hart_mask_base: usize,
        vaddr: usize,
        size: usize,
        asid: usize,
    ) -> SbiRet {
        unsafe {
            sbi_call(
                SBI_EID_RFENCE,
                SBI_FID_RFENCE_REMOTE_SFENCE_VMA_ASID,
                hart_mask,
                hart_mask_base,
                vaddr,
                size,
                asid,
                0,
            )
        }
    }

    /// Issue a remote `FENCE.I` (instruction-cache flush) on harts in the mask.
    #[inline]
    pub fn remote_fence_i(hart_mask: usize, hart_mask_base: usize) -> SbiRet {
        unsafe {
            sbi_call(
                SBI_EID_RFENCE,
                SBI_FID_RFENCE_REMOTE_FENCE_I,
                hart_mask,
                hart_mask_base,
                0,
                0,
                0,
                0,
            )
        }
    }

    // ── HSM ──────────────────────────────────────────────────────────────────

    /// Start a stopped hart at `start_addr` (supervisor-mode physical address).
    ///
    /// The hart receives `hartid` in `a0` and `opaque` in `a1` at entry,
    /// matching the OpenSBI / UEFI calling convention.
    #[inline]
    pub fn hart_start(hartid: usize, start_addr: usize, opaque: usize) -> SbiRet {
        unsafe {
            sbi_call(
                SBI_EID_HSM,
                SBI_FID_HSM_HART_START,
                hartid,
                start_addr,
                opaque,
                0,
                0,
                0,
            )
        }
    }

    /// Stop the calling hart (does not return on success).
    #[inline]
    pub fn hart_stop() -> SbiRet {
        unsafe { sbi_call(SBI_EID_HSM, SBI_FID_HSM_HART_STOP, 0, 0, 0, 0, 0, 0) }
    }

    /// Query the state of `hartid`.  The returned `value` is one of the
    /// `SBI_HSM_STATE_*` constants.
    #[inline]
    pub fn hart_get_status(hartid: usize) -> SbiRet {
        unsafe {
            sbi_call(
                SBI_EID_HSM,
                SBI_FID_HSM_HART_GET_STATUS,
                hartid,
                0,
                0,
                0,
                0,
                0,
            )
        }
    }

    /// Suspend the calling hart.
    ///
    /// `suspend_type` — `SBI_HSM_SUSPEND_RETENTIVE` or a platform-specific
    /// value.  `resume_addr` and `opaque` are ignored for retentive suspend.
    #[inline]
    pub fn hart_suspend(suspend_type: usize, resume_addr: usize, opaque: usize) -> SbiRet {
        unsafe {
            sbi_call(
                SBI_EID_HSM,
                SBI_FID_HSM_HART_SUSPEND,
                suspend_type,
                resume_addr,
                opaque,
                0,
                0,
                0,
            )
        }
    }

    // ── System Reset ─────────────────────────────────────────────────────────

    /// Perform a platform reset (shutdown or reboot) via SBI SRST.
    ///
    /// Does not return on success.
    #[inline]
    pub fn system_reset(reset_type: usize, reset_reason: usize) -> SbiRet {
        unsafe {
            sbi_call(
                SBI_EID_SRST,
                SBI_FID_SRST_SYSTEM_RESET,
                reset_type,
                reset_reason,
                0,
                0,
                0,
                0,
            )
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// CSR read / write helpers
// ═══════════════════════════════════════════════════════════════════════════════

/// Read a CSR by literal name.
macro_rules! csr_read {
    ($csr:literal) => {{
        let val: usize;
        unsafe {
            core::arch::asm!(
                concat!("csrr {0}, ", $csr),
                out(reg) val,
                options(nomem, nostack),
            );
        }
        val
    }};
}

/// Write a CSR by literal name.
macro_rules! csr_write {
    ($csr:literal, $val:expr) => {{
        let v: usize = $val;
        unsafe {
            core::arch::asm!(
                concat!("csrw ", $csr, ", {0}"),
                in(reg) v,
                options(nomem, nostack),
            );
        }
    }};
}

/// Set bits in a CSR (CSRS).
macro_rules! csr_set {
    ($csr:literal, $bits:expr) => {{
        let b: usize = $bits;
        unsafe {
            core::arch::asm!(
                concat!("csrs ", $csr, ", {0}"),
                in(reg) b,
                options(nomem, nostack),
            );
        }
    }};
}

/// Clear bits in a CSR (CSRC).
macro_rules! csr_clear {
    ($csr:literal, $bits:expr) => {{
        let b: usize = $bits;
        unsafe {
            core::arch::asm!(
                concat!("csrc ", $csr, ", {0}"),
                in(reg) b,
                options(nomem, nostack),
            );
        }
    }};
}

// ═══════════════════════════════════════════════════════════════════════════════
// CSR bit-field constants
// ═══════════════════════════════════════════════════════════════════════════════

// ─── sstatus ─────────────────────────────────────────────────────────────────

/// Supervisor Interrupt Enable.
pub const SSTATUS_SIE: usize = 1 << 1;
/// Supervisor Previous Interrupt Enable.
pub const SSTATUS_SPIE: usize = 1 << 5;
/// User Big-Endian memory accesses.
pub const SSTATUS_UBE: usize = 1 << 6;
/// Supervisor Previous Privilege (0 = User, 1 = Supervisor).
pub const SSTATUS_SPP: usize = 1 << 8;
/// Vector extension state field (bits 10:9).
pub const SSTATUS_VS: usize = 3 << 9;
/// Floating-point state field (bits 14:13).
pub const SSTATUS_FS: usize = 3 << 13;
/// User-mode extension state (bits 16:15).
pub const SSTATUS_XS: usize = 3 << 15;
/// Supervisor User Memory access (allows S-mode to load/store to user pages).
pub const SSTATUS_SUM: usize = 1 << 18;
/// Make eXecutable Readable (executable-only pages become readable).
pub const SSTATUS_MXR: usize = 1 << 19;
/// User-mode XLEN (bits 33:32, rv64 only).
pub const SSTATUS_UXL: usize = 3 << 32;
/// State Dirty summary (read-only; OR of FS/VS/XS dirty bits).
pub const SSTATUS_SD: usize = 1usize << 63;

// sstatus.FS field values.
pub const FS_OFF: usize = 0 << 13;
pub const FS_INITIAL: usize = 1 << 13;
pub const FS_CLEAN: usize = 2 << 13;
pub const FS_DIRTY: usize = 3 << 13;

// ─── sie / sip ───────────────────────────────────────────────────────────────

/// Supervisor Software Interrupt Enable / Pending.
pub const SI_SSI: usize = 1 << 1;
/// Supervisor Timer Interrupt Enable / Pending.
pub const SI_STI: usize = 1 << 5;
/// Supervisor External Interrupt Enable / Pending.
pub const SI_SEI: usize = 1 << 9;

// ─── satp ────────────────────────────────────────────────────────────────────

pub const SATP_MODE_BARE: usize = 0usize << 60;
pub const SATP_MODE_SV39: usize = 8usize << 60;
pub const SATP_MODE_SV48: usize = 9usize << 60;
pub const SATP_MODE_SV57: usize = 10usize << 60;
pub const SATP_ASID_SHIFT: usize = 44;
pub const SATP_ASID_MASK: usize = 0xffff << 44;
pub const SATP_PPN_MASK: usize = (1 << 44) - 1;

// ─── scause ──────────────────────────────────────────────────────────────────

/// Set in `scause` when the cause is an interrupt (not an exception).
pub const SCAUSE_INTERRUPT_BIT: usize = 1 << 63;

// Interrupt causes (SCAUSE_INTERRUPT_BIT set).
pub const CAUSE_SSI: usize = SCAUSE_INTERRUPT_BIT | 1; // S-mode software interrupt
pub const CAUSE_STI: usize = SCAUSE_INTERRUPT_BIT | 5; // S-mode timer interrupt
pub const CAUSE_SEI: usize = SCAUSE_INTERRUPT_BIT | 9; // S-mode external interrupt

// Exception causes (SCAUSE_INTERRUPT_BIT clear).
pub const CAUSE_INSTR_MISALIGN: usize = 0;
pub const CAUSE_INSTR_ACCESS: usize = 1;
pub const CAUSE_ILLEGAL_INSTR: usize = 2;
pub const CAUSE_BREAKPOINT: usize = 3;
pub const CAUSE_LOAD_MISALIGN: usize = 4;
pub const CAUSE_LOAD_ACCESS: usize = 5;
pub const CAUSE_STORE_MISALIGN: usize = 6;
pub const CAUSE_STORE_ACCESS: usize = 7;
pub const CAUSE_ECALL_U: usize = 8;
pub const CAUSE_ECALL_S: usize = 9;
pub const CAUSE_INSTR_PAGE_FAULT: usize = 12;
pub const CAUSE_LOAD_PAGE_FAULT: usize = 13;
pub const CAUSE_STORE_PAGE_FAULT: usize = 15;

// ─── stvec ───────────────────────────────────────────────────────────────────

/// Direct mode — all traps jump to BASE.
pub const STVEC_MODE_DIRECT: usize = 0;
/// Vectored mode — exceptions → BASE; interrupts → BASE + 4*cause.
pub const STVEC_MODE_VECTORED: usize = 1;

// ═══════════════════════════════════════════════════════════════════════════════
// CSR accessors
// ═══════════════════════════════════════════════════════════════════════════════

/// Read `sstatus`.
#[inline]
pub fn read_sstatus() -> usize {
    csr_read!("sstatus")
}

/// Write `sstatus`.
///
/// # Safety
/// Incorrect values can corrupt privilege state or FPU mode.
#[inline]
pub unsafe fn write_sstatus(val: usize) {
    csr_write!("sstatus", val);
}

/// Read `sie` (supervisor interrupt enable).
#[inline]
pub fn read_sie() -> usize {
    csr_read!("sie")
}

/// Read `sip` (supervisor interrupt pending).
#[inline]
pub fn read_sip() -> usize {
    csr_read!("sip")
}

/// Clear a pending supervisor software interrupt by writing `sip.SSIP = 0`.
///
/// # Safety
/// Only valid from supervisor mode; misuse can suppress legitimate IPIs.
#[inline]
pub unsafe fn clear_ssip() {
    csr_clear!("sip", SI_SSI);
}

/// Read `sepc` (supervisor exception program counter).
#[inline]
pub fn read_sepc() -> usize {
    csr_read!("sepc")
}

/// Write `sepc`.
///
/// # Safety
/// An incorrect value redirects `sret` to an arbitrary address.
#[inline]
pub unsafe fn write_sepc(val: usize) {
    csr_write!("sepc", val);
}

/// Read `scause`.
#[inline]
pub fn read_scause() -> usize {
    csr_read!("scause")
}

/// Read `stval` (supervisor trap value — faulting address or instruction).
#[inline]
pub fn read_stval() -> usize {
    csr_read!("stval")
}

/// Read `sscratch`.
#[inline]
pub fn read_sscratch() -> usize {
    csr_read!("sscratch")
}

/// Write `sscratch`.
///
/// # Safety
/// This register holds the per-CPU block pointer after `early_init`; writing
/// it carelessly breaks all per-CPU state.
#[inline]
pub unsafe fn write_sscratch(val: usize) {
    csr_write!("sscratch", val);
}

/// Read `satp` (address-translation mode + root page-table PPN).
#[inline]
pub fn read_satp() -> usize {
    csr_read!("satp")
}

/// Write `satp` and immediately issue `sfence.vma` to make the change visible.
///
/// # Safety
/// `val` must point to a valid, fully-constructed page table.  An invalid
/// value causes an immediate instruction-fetch page fault.
#[inline]
pub unsafe fn write_satp(val: usize) {
    csr_write!("satp", val);
    sfence_vma_all();
}

/// Read `stvec` (supervisor trap-vector base address + mode).
#[inline]
pub fn read_stvec() -> usize {
    csr_read!("stvec")
}

/// Read the `time` CSR (machine-time counter, read-only from S-mode).
///
/// On QEMU virt this is a window into the CLINT `mtime` register and ticks at
/// the reference clock frequency (typically 10 MHz).
#[inline]
pub fn read_time() -> u64 {
    csr_read!("time") as u64
}

/// Read the `cycle` CSR (processor cycle counter).
#[inline]
pub fn read_cycle() -> u64 {
    csr_read!("cycle") as u64
}

/// Read the `instret` CSR (instructions-retired counter).
#[inline]
pub fn read_instret() -> u64 {
    csr_read!("instret") as u64
}

// ═══════════════════════════════════════════════════════════════════════════════
// Interrupt control
// ═══════════════════════════════════════════════════════════════════════════════

/// Enable supervisor-mode interrupts (`sstatus.SIE = 1`).
///
/// # Safety
/// The caller must ensure it is safe for interrupts to be delivered at this
/// point (trap handler installed, per-CPU state valid).
#[inline]
pub unsafe fn enable_interrupts() {
    csr_set!("sstatus", SSTATUS_SIE);
}

/// Disable supervisor-mode interrupts (`sstatus.SIE = 0`).
///
/// Returns the previous `sstatus` value so the caller can restore it exactly.
///
/// # Safety
/// Must be called from supervisor mode.
#[inline]
pub unsafe fn disable_interrupts() -> usize {
    let old = read_sstatus();
    csr_clear!("sstatus", SSTATUS_SIE);
    old
}

/// Returns `true` if supervisor-mode interrupts are currently enabled.
#[inline]
pub fn interrupts_enabled() -> bool {
    read_sstatus() & SSTATUS_SIE != 0
}

/// Execute `f` with supervisor interrupts disabled, then restore the prior
/// interrupt state.
///
/// Equivalent to Linux's `local_irq_save` / `local_irq_restore` pattern.
#[inline]
pub fn without_interrupts<F, R>(f: F) -> R
where
    F: FnOnce() -> R,
{
    // SAFETY: We restore sstatus to its pre-call value before returning.
    let saved = unsafe { disable_interrupts() };
    let result = f();
    unsafe { write_sstatus(saved) };
    result
}

/// Enable specific interrupt sources in `sie`.
///
/// `mask` should be a combination of `SI_SSI`, `SI_STI`, `SI_SEI`.
///
/// # Safety
/// The corresponding interrupt handler must be installed before enabling.
#[inline]
pub unsafe fn enable_interrupt_sources(mask: usize) {
    csr_set!("sie", mask);
}

/// Disable specific interrupt sources in `sie`.
///
/// # Safety
/// Disabling the timer interrupt while a timer is outstanding may delay
/// scheduler ticks.
#[inline]
pub unsafe fn disable_interrupt_sources(mask: usize) {
    csr_clear!("sie", mask);
}

/// Enable all standard supervisor interrupt sources (SSI + STI + SEI).
///
/// # Safety
/// All three interrupt handlers must be installed and ready before this call.
#[inline]
pub unsafe fn enable_all_interrupt_sources() {
    enable_interrupt_sources(SI_SSI | SI_STI | SI_SEI);
}

// ═══════════════════════════════════════════════════════════════════════════════
// Trap vector
// ═══════════════════════════════════════════════════════════════════════════════

/// Install a supervisor trap handler.
///
/// In `DIRECT` mode `handler` must be 4-byte aligned.  In `VECTORED` mode it
/// must be 256-byte aligned (the low bits encode cause-specific offsets).
///
/// # Safety
/// An incorrect address or misaligned value causes unrecoverable trap failures.
#[inline]
pub unsafe fn set_stvec(handler: usize, mode: usize) {
    debug_assert!(
        mode <= 1,
        "set_stvec: invalid mode {mode}; only DIRECT(0) and VECTORED(1) are defined"
    );
    csr_write!("stvec", (handler & !0x3) | (mode & 0x3));
}

// ═══════════════════════════════════════════════════════════════════════════════
// TLB management
// ═══════════════════════════════════════════════════════════════════════════════

/// Flush all TLB entries on this hart (`sfence.vma` with rs1=rs2=zero).
#[inline]
pub fn sfence_vma_all() {
    unsafe { asm!("sfence.vma zero, zero", options(nostack, nomem)) }
}

/// Flush the TLB entry for `vaddr` on this hart (all ASIDs).
#[inline]
pub fn sfence_vma_addr(vaddr: usize) {
    unsafe { asm!("sfence.vma {0}, zero", in(reg) vaddr, options(nostack, nomem)) }
}

/// Flush the TLB entry for `vaddr` in the given `asid` on this hart.
#[inline]
pub fn sfence_vma_addr_asid(vaddr: usize, asid: usize) {
    unsafe {
        asm!(
            "sfence.vma {0}, {1}",
            in(reg) vaddr, in(reg) asid,
            options(nostack, nomem),
        )
    }
}

/// Flush all TLB entries belonging to `asid` on this hart.
#[inline]
pub fn sfence_vma_asid(asid: usize) {
    unsafe { asm!("sfence.vma zero, {0}", in(reg) asid, options(nostack, nomem)) }
}

/// Instruction-cache fence on this hart.
#[inline]
pub fn fence_i() {
    unsafe { asm!("fence.i", options(nostack, nomem)) }
}

/// Full memory barrier (FENCE rw, rw).
#[inline]
pub fn memory_fence() {
    unsafe { asm!("fence rw, rw", options(nostack)) }
}

/// Flush the local TLB completely and then send a remote `sfence.vma` to all
/// other harts in `hart_mask` for the range `[vaddr, vaddr+size)`.
///
/// Used by the MM subsystem after page-table modifications that affect shared
/// address spaces (e.g. kernel mappings, COW promotion).
#[inline]
pub fn tlb_flush_range_all_harts(
    hart_mask: usize,
    hart_mask_base: usize,
    vaddr: usize,
    size: usize,
) {
    sfence_vma_all();
    sbi::remote_sfence_vma(hart_mask, hart_mask_base, vaddr, size);
}

/// Flush the local TLB for a specific ASID range and broadcast to remote harts.
#[inline]
pub fn tlb_flush_asid_all_harts(
    hart_mask: usize,
    hart_mask_base: usize,
    vaddr: usize,
    size: usize,
    asid: usize,
) {
    sfence_vma_asid(asid);
    sbi::remote_sfence_vma_asid(hart_mask, hart_mask_base, vaddr, size, asid);
}

// ═══════════════════════════════════════════════════════════════════════════════
// Paging (satp) helpers
// ═══════════════════════════════════════════════════════════════════════════════

/// Build an `satp` value for Sv39 (39-bit virtual addressing).
///
/// `ppn`  — physical page number of the L2 root page table.  
/// `asid` — 16-bit address-space identifier (0 = global / no ASID tagging).
#[inline]
pub fn satp_sv39(ppn: usize, asid: u16) -> usize {
    SATP_MODE_SV39 | ((asid as usize) << SATP_ASID_SHIFT) | (ppn & SATP_PPN_MASK)
}

/// Build an `satp` value for Sv48 (48-bit virtual addressing).
#[inline]
pub fn satp_sv48(ppn: usize, asid: u16) -> usize {
    SATP_MODE_SV48 | ((asid as usize) << SATP_ASID_SHIFT) | (ppn & SATP_PPN_MASK)
}

/// Build an `satp` value for Sv57 (57-bit virtual addressing).
#[inline]
pub fn satp_sv57(ppn: usize, asid: u16) -> usize {
    SATP_MODE_SV57 | ((asid as usize) << SATP_ASID_SHIFT) | (ppn & SATP_PPN_MASK)
}

/// Extract the PPN from an `satp` value.
#[inline]
pub fn satp_ppn(satp: usize) -> usize {
    satp & SATP_PPN_MASK
}

/// Extract the ASID from an `satp` value.
#[inline]
pub fn satp_asid(satp: usize) -> u16 {
    ((satp >> SATP_ASID_SHIFT) & 0xffff) as u16
}

/// Activate Sv39 paging on this hart.
///
/// # Safety
/// `root_ppn` must reference a valid, fully-populated Sv39 page table.
#[inline]
pub unsafe fn activate_sv39(root_ppn: usize, asid: u16) {
    write_satp(satp_sv39(root_ppn, asid));
}

/// Activate Sv48 paging on this hart.
///
/// # Safety
/// `root_ppn` must reference a valid Sv48 page table.
#[inline]
pub unsafe fn activate_sv48(root_ppn: usize, asid: u16) {
    write_satp(satp_sv48(root_ppn, asid));
}

/// Disable virtual memory (BARE mode — physical addressing).
///
/// # Safety
/// All code paths must be identity-mapped for this call to be safe; the
/// next instruction fetch uses the physical address of `pc`.
#[inline]
pub unsafe fn activate_bare() {
    write_satp(SATP_MODE_BARE);
}

// ═══════════════════════════════════════════════════════════════════════════════
// Floating-point unit
// ═══════════════════════════════════════════════════════════════════════════════

/// Enable the FPU by setting `sstatus.FS = Initial`.
///
/// Must be called before executing any floating-point instruction in
/// supervisor mode (or before entering user mode for the first time).
///
/// # Safety
/// Changing FS affects context-switch behaviour; only call during early init
/// or from the context-switch path.
#[inline]
pub unsafe fn enable_fpu() {
    let s = read_sstatus();
    write_sstatus((s & !SSTATUS_FS) | FS_INITIAL);
}

/// Mark the FPU state as clean (e.g. after saving to a `TrapFrame`).
///
/// # Safety
/// Must only be called immediately after the FP register file has been saved.
#[inline]
pub unsafe fn fpu_mark_clean() {
    let s = read_sstatus();
    write_sstatus((s & !SSTATUS_FS) | FS_CLEAN);
}

/// Returns `true` if the FPU has been written since the last clean marking.
///
/// Used by the scheduler to decide whether to save FP registers on
/// context-switch.
#[inline]
pub fn fpu_is_dirty() -> bool {
    read_sstatus() & SSTATUS_FS == FS_DIRTY
}

// ═══════════════════════════════════════════════════════════════════════════════
// Wait-for-interrupt
// ═══════════════════════════════════════════════════════════════════════════════

/// Execute the `wfi` instruction.
///
/// Suspends the hart until an interrupt is pending.  Used by idle threads and
/// the HSM suspend path to avoid busy-looping.
#[inline]
pub fn wait_for_interrupt() {
    unsafe { asm!("wfi", options(nostack, nomem)) }
}

// ═══════════════════════════════════════════════════════════════════════════════
// GDB stub — single-step support
// ═══════════════════════════════════════════════════════════════════════════════

/// Per-hart single-step flag, read by the trap handler after every instruction
/// trap when `gdbstub` is active.
///
/// Standard RISC-V does not expose `dcsr.step` from S-mode, so the GDB stub
/// emulates single-step by:
///   1. Setting this flag and installing a temporary `EBREAK` at the next PC.
///   2. On the resulting breakpoint trap the handler checks this flag, restores
///      the patched instruction, and reports a SIGTRAP to the stub.
///
/// On cores that implement the Ssdext extension this flag can instead gate a
/// CSR write to `dcsr.step` — see the gdbstub module for the dispatch.
static SINGLE_STEP: AtomicBool = AtomicBool::new(false);

/// Enable or disable single-step mode for the current hart.
///
/// Call from the GDB RSP stub's `s` / `vCont;s` handler.
#[inline]
pub fn set_single_step(enable: bool) {
    SINGLE_STEP.store(enable, Ordering::Release);
}

/// Returns `true` if single-step mode is currently active.
///
/// Polled by `src/gdbstub/riscv.rs` in the breakpoint trap handler.
#[inline]
pub fn single_step_enabled() -> bool {
    SINGLE_STEP.load(Ordering::Acquire)
}

// ═══════════════════════════════════════════════════════════════════════════════
// Hart ID
// ═══════════════════════════════════════════════════════════════════════════════

/// Boot-hart ID cached during `early_init`.
///
/// For secondary harts, the per-CPU block (pointed to by `sscratch`) stores
/// each hart's own ID.  This global is only read by code that runs before the
/// per-CPU block is initialised (early console, trap vector setup).
static BOOT_HART_ID: AtomicUsize = AtomicUsize::new(0);

/// Cache the current hart's ID.
///
/// For the boot hart this is called from `early_init`.  For secondary harts,
/// `secondary_init` calls it before the hart joins the scheduler.
///
/// The ID is the value passed by the SBI/UEFI firmware in register `a0` at
/// the supervisor entry point.
///
/// # Safety
/// Must be called exactly once per hart, before any call to
/// `current_hart_id`.
#[inline]
pub unsafe fn init_hart_id(hartid: usize) {
    // Write into sscratch as a temporary until the per-CPU block is set up.
    // The per-CPU initialisation code in `smp/percpu.rs` will overwrite
    // sscratch with the block pointer and store hartid in the block itself.
    BOOT_HART_ID.store(hartid, Ordering::Relaxed);
    write_sscratch(hartid);
}

/// Return the current hart's ID.
///
/// After the per-CPU block is set up this should be superseded by reading the
/// `hartid` field of the block directly, avoiding the atomic load.  Until then,
/// this function reads from `sscratch` (set by `init_hart_id`).
#[inline]
pub fn current_hart_id() -> usize {
    // sscratch holds the raw hartid until percpu replaces it with a pointer
    // whose first field is also the hartid, so reading sscratch is always safe.
    read_sscratch()
}

// ═══════════════════════════════════════════════════════════════════════════════
// SMP
// ═══════════════════════════════════════════════════════════════════════════════

/// Bring up a secondary hart.
///
/// `hartid`     — target hart identifier.  
/// `start_addr` — physical address of the AP entry stub (supervisor mode).  
/// `opaque`     — value placed in `a1` on the new hart at entry; conventionally
///                a pointer to the AP's stack top or per-CPU descriptor.
///
/// Returns `Ok(())` if SBI accepted the request, or `Err(SbiRet)` with the
/// raw error otherwise.
#[inline]
pub fn start_hart(hartid: usize, start_addr: usize, opaque: usize) -> Result<(), SbiRet> {
    let r = sbi::hart_start(hartid, start_addr, opaque);
    if r.is_ok() {
        Ok(())
    } else {
        Err(r)
    }
}

/// Stop the calling hart permanently (does not return on success).
///
/// If SBI HSM is unavailable, falls back to spinning in `wfi`.
pub fn stop_hart() -> ! {
    sbi::hart_stop();
    loop {
        wait_for_interrupt();
    }
}

/// Query the running state of `hartid`.  Returns one of `SBI_HSM_STATE_*`.
#[inline]
pub fn hart_state(hartid: usize) -> usize {
    sbi::hart_get_status(hartid).value
}

/// Send a software IPI to `hartid`.
#[inline]
pub fn send_ipi_to(hartid: usize) {
    sbi::send_ipi(1, hartid);
}

/// Send a software IPI to the set of harts described by `(mask, base)`.
///
/// Bit *i* of `mask` selects hart `base + i`.  Use `mask = usize::MAX` and
/// `base = 0` to broadcast to all harts.
#[inline]
pub fn send_ipi_mask(mask: usize, base: usize) {
    sbi::send_ipi(mask, base);
}

// ═══════════════════════════════════════════════════════════════════════════════
// Timer
// ═══════════════════════════════════════════════════════════════════════════════

/// Return the current hardware time counter value (ticks at the platform
/// reference clock; 10 MHz on QEMU virt, typically).
///
/// The kernel scheduler and `clock_gettime(CLOCK_MONOTONIC)` use this as the
/// raw time source before converting to nanoseconds.
#[inline]
pub fn timer_now() -> u64 {
    read_time()
}

/// Schedule the next supervisor timer interrupt.
///
/// `deadline` is an **absolute** `time` CSR value.  When the counter reaches
/// `deadline`, `sip.STIP` is asserted and a timer trap fires (if `sie.STIE`
/// is set and `sstatus.SIE` is set).
#[inline]
pub fn set_timer(deadline: u64) {
    sbi::set_timer(deadline);
}

/// Disarm the supervisor timer by programming a deadline in the distant future.
///
/// RISC-V has no direct "cancel timer" instruction from S-mode; re-arming to
/// `u64::MAX` effectively prevents the interrupt from firing.
#[inline]
pub fn clear_timer() {
    sbi::set_timer(u64::MAX);
}

/// Return the platform timer frequency in Hz, if known.
///
/// QEMU virt exports `timebase-frequency` in the device tree (10_000_000 Hz).
/// Without a DT parser this returns a conservative default; callers should
/// override this with the value read from the FDT.
#[inline]
pub fn timer_frequency_hz() -> u64 {
    10_000_000 // 10 MHz — QEMU virt default; override via FDT at runtime
}

/// Convert a `time` CSR delta to nanoseconds.
#[inline]
pub fn ticks_to_ns(ticks: u64) -> u64 {
    ticks.saturating_mul(1_000_000_000) / timer_frequency_hz()
}

/// Convert nanoseconds to `time` CSR ticks.
#[inline]
pub fn ns_to_ticks(ns: u64) -> u64 {
    ns.saturating_mul(timer_frequency_hz()) / 1_000_000_000
}

// ═══════════════════════════════════════════════════════════════════════════════
// Early console (SBI legacy putchar / getchar)
// ═══════════════════════════════════════════════════════════════════════════════

/// Transmit a byte on the SBI debug console.
///
/// Available before the NS16550/UART driver is initialised.  Also used as the
/// GDB RSP transport byte writer on the RISC-V path.
#[inline]
pub fn putchar(c: u8) {
    sbi::console_putchar(c);
}

/// Transmit a string on the SBI debug console.
#[inline]
pub fn puts(s: &str) {
    sbi::console_write(s);
}

/// Receive a byte from the SBI debug console, or `None` if nothing is ready.
///
/// Used by the GDB RSP transport reader.
#[inline]
pub fn getchar() -> Option<u8> {
    sbi::console_getchar()
}

// ═══════════════════════════════════════════════════════════════════════════════
// Shutdown / reboot
// ═══════════════════════════════════════════════════════════════════════════════

/// Power off the platform.
///
/// Tries SBI SRST (EID 0x53525354) first, then the legacy shutdown EID (0x08).
/// Spins in `wfi` if neither returns — this function never returns.
pub fn shutdown() -> ! {
    sbi::system_reset(SBI_SRST_TYPE_SHUTDOWN, SBI_SRST_REASON_NONE);
    // Legacy fallback.
    unsafe {
        sbi_call(SBI_EID_LEGACY_SHUTDOWN, 0, 0, 0, 0, 0, 0, 0);
    }
    loop {
        wait_for_interrupt();
    }
}

/// Perform a cold reboot.  Falls back to warm reboot, then spins.
pub fn reboot() -> ! {
    sbi::system_reset(SBI_SRST_TYPE_COLD_REBOOT, SBI_SRST_REASON_NONE);
    sbi::system_reset(SBI_SRST_TYPE_WARM_REBOOT, SBI_SRST_REASON_NONE);
    loop {
        wait_for_interrupt();
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Platform initialisation
// ═══════════════════════════════════════════════════════════════════════════════

/// Perform early HAL initialisation on the boot hart.
///
/// Must be called **once**, from the boot hart's entry point, **before** any
/// other HAL function and while interrupts are globally disabled.
///
/// Steps
/// ------
/// 1. Store `boot_hartid` in `sscratch` and the `BOOT_HART_ID` global.
/// 2. Install a temporary null trap vector (DIRECT, address 0) so any early
///    fault produces a visible hang rather than a silent loop.  The real trap
///    handler is installed by `trap::init()`.
/// 3. Enable the FPU (`sstatus.FS = Initial`).
/// 4. Enable all supervisor interrupt sources (`sie = SSI|STI|SEI`).
/// 5. Print the SBI spec version to the console in debug builds.
///
/// # Safety
/// Must be called from supervisor mode with `sstatus.SIE = 0`.
pub unsafe fn early_init(boot_hartid: usize) {
    // 1. Hart ID.
    init_hart_id(boot_hartid);

    // 2. Temporary trap vector (DIRECT, zeroed — causes a clean hang on fault).
    //    Overwritten by trap::init() before interrupts are enabled.
    csr_write!("stvec", 0usize);

    // 3. FPU.
    enable_fpu();

    // 4. Interrupt sources (but not global enable — keep sstatus.SIE = 0 for
    //    now; trap::init() calls enable_interrupts() after installing stvec).
    enable_all_interrupt_sources();

    // 5. SBI version banner (debug only).
    #[cfg(debug_assertions)]
    {
        let (major, minor) = sbi::spec_version();
        puts("[ riscv64/hal] SBI spec v");
        put_dec(major as u64);
        puts(".");
        put_dec(minor as u64);
        puts(", impl_id=0x");
        put_hex(sbi::impl_id() as u64);
        puts(", marchid=0x");
        put_hex(sbi::marchid() as u64);
        puts("\n");
    }
}

/// Initialise HAL state on a secondary (AP) hart.
///
/// Called from the AP entry stub (`src/arch/riscv64/smp_trampoline.rs`) after
/// the hart has set up its own stack but before it attempts to use any
/// kernel services.
///
/// # Safety
/// Must be called from supervisor mode with `sstatus.SIE = 0`.
pub unsafe fn secondary_init(hartid: usize) {
    init_hart_id(hartid);
    csr_write!("stvec", 0usize); // replaced by trap::init()
    enable_fpu();
    enable_all_interrupt_sources();
}

// ─── Debug-only console helpers ──────────────────────────────────────────────

/// Print an unsigned decimal number via the SBI console (debug builds only).
#[cfg(debug_assertions)]
fn put_dec(mut n: u64) {
    if n == 0 {
        sbi::console_putchar(b'0');
        return;
    }
    let mut buf = [0u8; 20];
    let mut i = buf.len();
    while n > 0 {
        i -= 1;
        buf[i] = b'0' + (n % 10) as u8;
        n /= 10;
    }
    for &b in &buf[i..] {
        sbi::console_putchar(b);
    }
}

/// Print an unsigned hexadecimal number via the SBI console (debug builds only).
#[cfg(debug_assertions)]
fn put_hex(n: u64) {
    const HEX: &[u8] = b"0123456789abcdef";
    let mut leading = true;
    for shift in (0..64usize).rev().step_by(4) {
        let nibble = ((n >> shift) & 0xf) as usize;
        if leading && nibble == 0 && shift != 0 {
            continue;
        }
        leading = false;
        sbi::console_putchar(HEX[nibble]);
    }
    if leading {
        sbi::console_putchar(b'0');
    }
}
