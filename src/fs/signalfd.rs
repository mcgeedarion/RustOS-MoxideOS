//! signalfd support — fd registry and close helpers.
//!
//! The signal delivery path currently uses traditional signal syscalls.  This
//! module provides the fd identity/close hooks needed by fcntl/fstat and keeps
//! the descriptor namespace consistent until full signalfd read semantics are
//! wired into the syscall dispatcher.

use crate::core::fast_hash::KernelFastMap;
use spin::Mutex;

/// Fast map is safe here: keys are kernel-assigned fd numbers and iteration
/// order is never exposed as an ABI.
static SIGNALFDS: Mutex<KernelFastMap<usize, ()>> = Mutex::new(KernelFastMap::new());

/// Register an already-allocated backing fd as a signalfd.
pub fn signalfd_register(fd: usize) {
    SIGNALFDS.lock().insert(fd, ());
}

/// Returns true when `fd` is a registered signalfd backing fd.
pub fn is_signalfd(fd: usize) -> bool {
    SIGNALFDS.lock().contains_key(&fd)
}

/// Close and unregister a signalfd backing fd.
pub fn sys_close_sfd(fd: usize) {
    SIGNALFDS.lock().remove(&fd);
}

/// Minimal read entry point for future dispatcher wiring.
pub fn signalfd_read(_fd: usize, _buf: &mut [u8]) -> isize {
    -38 // ENOSYS
}

/// Poll readiness bitmask.  Full queued-signal readiness is not wired yet.
pub fn signalfd_poll(_fd: usize) -> u32 {
    0
}
