//! `vCont` packet handler for the GDB Remote Serial Protocol.
//!
//! This module extends `rsp.rs` with support for the four `vCont` actions:
//!
//! | Action | Packet      | Meaning                                  |
//! |--------|-------------|------------------------------------------|
//! | `c`    | `vCont;c`   | Continue execution.                      |
//! | `s`    | `vCont;s`   | Single-step one instruction.             |
//! | `t`    | `vCont;t`   | Stop (send `T05` stop reply immediately).|
//! | `r`    | `vCont;r<s>,<e>` | Range-step: step until PC ∉ [s, e). |
//!
//! # Capability advertisement
//!
//! When GDB sends `vCont?`, reply with the actions we support:
//! ```text
//! vCont;c;s;t;r
//! ```
//!
//! # Integration
//!
//! Call [`handle_vcont`] from the main RSP packet dispatch loop when the
//! packet body starts with `"vCont"`:
//!
//! ```rust
//! if pkt.starts_with("vCont") {
//!     rsp_vcont::handle_vcont(pkt, frame, &mut state);
//!     continue;
//! }
//! ```

use crate::debug::gdbstub::arch::{parse_vcont, VContAction};

/// Debugger execution state managed by the vCont handler.
pub struct RspState {
    /// True while the target is halted and waiting for a GDB command.
    pub halted: bool,
    /// Range-step bounds when a `vCont;r` is in progress; `None` otherwise.
    pub range_step: Option<(u64, u64)>,
}

impl RspState {
    pub const fn new() -> Self {
        Self { halted: true, range_step: None }
    }
}

/// Handle a `vCont` or `vCont?` packet.
///
/// * `pkt`   — the full packet body starting with `"vCont"`.
/// * `frame` — mutable reference to the current trap frame.
/// * `state` — mutable debugger state.
///
/// Returns the response string that should be sent back to GDB.
pub fn handle_vcont(
    pkt: &str,
    frame: &mut crate::arch::TrapFrame,
    state: &mut RspState,
) -> alloc::string::String {
    // Capability query.
    if pkt == "vCont?" {
        return alloc::string::String::from("vCont;c;s;t;r");
    }

    match parse_vcont(pkt) {
        None => {
            // Unrecognised vCont action — send empty reply so GDB falls back.
            alloc::string::String::new()
        }

        Some(VContAction::Continue) => {
            state.halted = false;
            state.range_step = None;
            // GDB expects no reply until the target stops again.
            // The caller should resume execution and send a stop reply later.
            alloc::string::String::new()
        }

        Some(VContAction::Step) => {
            state.halted = false;
            state.range_step = None;
            // Enable hardware single-step on the target architecture.
            arch_enable_single_step(frame);
            alloc::string::String::new()
        }

        Some(VContAction::Stop) => {
            state.halted = true;
            state.range_step = None;
            // Send an immediate stop reply: T05 (SIGTRAP).
            alloc::string::String::from("T05")
        }

        Some(VContAction::RangeStep { start, end }) => {
            state.halted = false;
            state.range_step = Some((start, end));
            arch_enable_single_step(frame);
            alloc::string::String::new()
        }
    }
}

/// Check whether a range-step should stop at `pc`.
///
/// Call this from the single-step debug-trap handler before deciding whether
/// to re-arm single-step or send a stop reply to GDB.
#[inline]
pub fn range_step_done(state: &RspState, pc: u64) -> bool {
    match state.range_step {
        Some((start, end)) => pc < start || pc >= end,
        None => true,
    }
}

/// Enable hardware single-step on the current architecture.
#[inline]
fn arch_enable_single_step(_frame: &mut crate::arch::TrapFrame) {
    #[cfg(target_arch = "x86_64")]
    {
        // Set TF (Trap Flag) in RFLAGS.
        _frame.rflags |= 1 << 8;
    }
    #[cfg(target_arch = "riscv64")]
    {
        // Set SSTEP in sstatus (bit 1 of dcsr when using debug mode).
        // For software single-step on RISC-V nommu targets, we patch the
        // next instruction with an EBREAK and store the original; a more
        // complete implementation belongs in the full debug stub.
        // This is a placeholder that signals intent without breaking compile.
        let _ = _frame;
    }
    #[cfg(target_arch = "aarch64")]
    {
        // Set SS (Software Step) in SPSR_EL1.
        _frame.spsr |= 1 << 21;
    }
}

extern crate alloc;
