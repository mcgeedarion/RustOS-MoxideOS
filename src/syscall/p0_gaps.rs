// P0/P1/P2 syscall gap implementations.
//
// Included from mod.rs via `include!("p0_gaps.rs")` so the functions
// share the same namespace as the rest of the syscall dispatcher.
//
// DEDUPLICATION RULE: if a function with the same _impl name already
// exists in stubs.rs, it MUST NOT be redefined here — include!() merges
// both files into the same scope and rustc will error on the duplicate.
// Only add functions here that have no counterpart in stubs.rs.

// ── P2 permission / attribute stubs (unique to this file) ──────────────────

/// lchown(2) — change ownership of a symlink itself (not its target).
/// No-op stub: ownership is not enforced in the single-user root kernel.
#[allow(dead_code, unused_variables)]
fn sys_lchown_impl(_path: usize, _uid: u32, _gid: u32) -> isize { 0 }
