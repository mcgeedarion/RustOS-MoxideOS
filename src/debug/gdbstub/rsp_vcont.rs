//! `vCont` packet handler for the GDB Remote Serial Protocol.

extern crate alloc;

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
        Self {
            halted: true,
            range_step: None,
        }
    }
}

/// Handle a `vCont` or `vCont?` packet.
pub fn handle_vcont(
    pkt: &str,
    frame: &mut crate::arch::TrapFrame,
    state: &mut RspState,
) -> alloc::string::String {
    if pkt == "vCont?" {
        return alloc::string::String::from("vCont;c;s;t;r");
    }

    match parse_vcont(pkt) {
        None => alloc::string::String::new(),

        Some(VContAction::Continue) => {
            state.halted = false;
            state.range_step = None;
            alloc::string::String::new()
        },

        Some(VContAction::Step) => {
            if arch_enable_single_step(frame) {
                state.halted = false;
                state.range_step = None;
                alloc::string::String::new()
            } else {
                state.halted = true;
                state.range_step = None;
                alloc::string::String::from("E45")
            }
        },

        Some(VContAction::Stop) => {
            state.halted = true;
            state.range_step = None;
            alloc::string::String::from("T05")
        },

        Some(VContAction::RangeStep { start, end }) => {
            if arch_enable_single_step(frame) {
                state.halted = false;
                state.range_step = Some((start, end));
                alloc::string::String::new()
            } else {
                state.halted = true;
                state.range_step = None;
                alloc::string::String::from("E45")
            }
        },
    }
}

/// Check whether a range-step should stop at `pc`.
#[inline]
pub fn range_step_done(state: &RspState, pc: u64) -> bool {
    match state.range_step {
        Some((start, end)) => pc < start || pc >= end,
        None => true,
    }
}

/// Enable architecture single-step.
///
/// x86_64 and AArch64 have a trap-frame bit this code can set directly.
/// RISC-V software single-step requires instruction decode plus temporary
/// EBREAK patch/restore support, so this returns `false` until that lower layer
/// exists instead of pretending the step was armed.
#[inline]
fn arch_enable_single_step(frame: &mut crate::arch::TrapFrame) -> bool {
    #[cfg(target_arch = "x86_64")]
    {
        frame.rflags |= 1 << 8;
        true
    }

    #[cfg(target_arch = "aarch64")]
    {
        frame.spsr |= 1 << 21;
        true
    }

    #[cfg(target_arch = "riscv64")]
    {
        let _ = frame;
        false
    }

    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64", target_arch = "riscv64")))]
    {
        let _ = frame;
        false
    }
}