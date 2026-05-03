//! SignalHandlers + SigAction — per-process signal dispatch table.
//! Referenced by Pcb.signal_handlers and sys_sigaction.

extern crate alloc;
use alloc::vec::Vec;

/// One entry in the per-process signal handler table.
#[derive(Clone, Default)]
pub struct SigAction {
    /// Handler VA: 0 = SIG_DFL, 1 = SIG_IGN, else user function pointer.
    pub handler: usize,
    /// sa_mask: signals blocked while handler runs.
    pub mask:    u64,
    /// sa_flags (SA_RESTART, SA_SIGINFO, etc.).
    pub flags:   u32,
}

/// Per-process signal handler table (signals 1..=64).
#[derive(Clone)]
pub struct SignalHandlers {
    pub table: Vec<SigAction>,
}

impl Default for SignalHandlers {
    fn default() -> Self {
        Self { table: (0..=64).map(|_| SigAction::default()).collect() }
    }
}
