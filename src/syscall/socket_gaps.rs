//! Missing socket/listen/sockopt dispatch glue — extension marker.
//!
//! Included from mod.rs via `include!("socket_gaps.rs")`.
//! All dispatch arms and implementations are inlined directly in mod.rs
//! (see sys_shutdown_impl, sys_socketpair_impl, and the dispatch match block).
//!
//! ## Wired dispatch arms added to mod.rs
//!   SYS_LISTEN     (50) => sys_listen_impl(a0, a1 as i32)
//!   SYS_ACCEPT4   (288) => sys_accept4(a0, a1, a2, a3 as i32)
//!   SYS_SETSOCKOPT (54) => crate::net::sockopt::sys_setsockopt(...)
//!   SYS_GETSOCKOPT (55) => crate::net::sockopt::sys_getsockopt(...)
//!   SYS_SHUTDOWN   (48) => sys_shutdown_impl(a0, a1 as i32)
//!   SYS_SOCKETPAIR (53) => sys_socketpair_impl(a0, a1, a2, a3)
//!
//! ## Security fix
//!   read_cstr_safe: replaced raw *ptr loop with strncpy_from_user
//!   which validates the entire range against USER_END before any read.
//!
//! To add further socket syscalls: append fn + dispatch arm here and
//! add the arm to the match block in mod.rs.
