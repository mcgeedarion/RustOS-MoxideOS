// P0/P1/P2 syscall gap implementations.
//
// Included from mod.rs via `include!("p0_gaps.rs")` so the functions
// share the same namespace as the rest of the syscall dispatcher.
//
// RULE: do NOT define any function here whose _impl name already exists
// in stubs.rs — include!() merges both files into the same scope and
// rustc will error on the duplicate.  Only add functions here that have
// no counterpart in stubs.rs.

// ── NR 93  lchown ──────────────────────────────────────────────────────────
// lchown(2) changes ownership of the symlink itself, not its target.
// No-op stub: ownership is not enforced in the single-user root kernel.
#[allow(dead_code)]
fn sys_lchown_impl(_path: usize, _uid: u32, _gid: u32) -> isize { 0 }
