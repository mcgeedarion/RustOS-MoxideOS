//! SignalHandlers — per-process signal dispatch table.
//!
//! This is the single definition used by Pcb, signal.rs, and exec.rs.
//! The flat array layout (indices 0..=64, signal N at index N) avoids
//! heap allocation on the hot check_and_deliver path.

/// Per-process signal handler table.
///
/// `handlers[N]`:
///   0           = SIG_DFL (default action)
///   1           = SIG_IGN (explicitly ignored)
///   other       = user handler VA
///
/// `flags[N]`    = sa_flags for signal N (SA_RESTORER, SA_NODEFER, …)
/// `restorer`    = SA_RESTORER VA (shared across all signals, per Linux ABI)
#[derive(Clone)]
pub struct SignalHandlers {
    pub handlers: [usize; 65],
    pub flags: [u32; 65],
    pub restorer: usize,
}

impl Default for SignalHandlers {
    fn default() -> Self {
        Self {
            handlers: [0usize; 65],
            flags: [0u32; 65],
            restorer: 0,
        }
    }
}

impl SignalHandlers {
    /// Return a fresh table that preserves SIG_IGN dispositions from `self`
    /// and resets everything else to SIG_DFL.  Used by execve.
    ///
    /// POSIX / Linux rule:
    ///   - SIG_IGN (handler == 1) survives exec.
    ///   - SIG_DFL (handler == 0) survives exec.
    ///   - User handler VAs are reset to SIG_DFL (the VA is invalid in the new
    ///     address space).
    ///   - sa_flags and sa_restorer are cleared for reset signals.
    pub fn exec_reset(&self) -> Self {
        let mut new = Self::default();
        for i in 0..=64usize {
            if self.handlers[i] == 1 {
                // SIG_IGN survives.
                new.handlers[i] = 1;
                new.flags[i] = 0; // flags don't survive (restorer VA gone)
            }
            // SIG_DFL (0) is already default; user VAs become SIG_DFL.
        }
        // restorer VA is from the old address space — always clear.
        new.restorer = 0;
        new
    }
}
