//! Shared context type threaded through the subsystem routers.
//!
//! `SyscallContext` is passed by reference to each dispatch sub-function
//! so that the callee can read all six argument registers and the saved
//! RIP without an 8-argument signature (which trips `clippy::too_many_arguments`).

/// Saved state from the kernel entry stub, forwarded to every syscall handler.
#[derive(Copy, Clone, Debug)]
pub struct SyscallContext {
    /// Syscall number from rax.
    pub nr: usize,
    /// Arguments from rdi/rsi/rdx/r10/r8/r9.
    pub args: [usize; 6],
    /// Saved rip at the syscall instruction site.
    pub rip: u64,
}

impl SyscallContext {
    #[inline(always)]
    pub fn new(nr: usize, args: [usize; 6], rip: u64) -> Self {
        Self { nr, args, rip }
    }
    // Convenience accessors to avoid positional errors at call sites.
    #[inline(always)] pub fn a0(&self) -> usize { self.args[0] }
    #[inline(always)] pub fn a1(&self) -> usize { self.args[1] }
    #[inline(always)] pub fn a2(&self) -> usize { self.args[2] }
    #[inline(always)] pub fn a3(&self) -> usize { self.args[3] }
    #[inline(always)] pub fn a4(&self) -> usize { self.args[4] }
    #[inline(always)] pub fn a5(&self) -> usize { self.args[5] }
}
