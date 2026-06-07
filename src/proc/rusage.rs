//! `getrusage(2)` — NR 98.
//!
//! Fills a 144-byte `struct rusage` (x86-64 ABI) from the live per-process
//! `utime_ns` / `stime_ns` fields in the `Pcb`.
//!
//! Field layout (all i64):
//!   [  0.. 8]  ru_utime.tv_sec
//!   [  8..16]  ru_utime.tv_usec
//!   [ 16..24]  ru_stime.tv_sec
//!   [ 24..32]  ru_stime.tv_usec
//!   [ 32..40]  ru_maxrss          (kilobytes)
//!   [ 40..144] reserved / unused  (zeroed)

use crate::proc::scheduler;
use crate::uaccess::copy_to_user;

pub const RUSAGE_SELF: i32 = 0;
pub const RUSAGE_CHILDREN: i32 = -1;
pub const RUSAGE_THREAD: i32 = 1;

/// Implements `getrusage(2)`.
pub fn sys_getrusage(who: i32, usage_va: usize) -> isize {
    if usage_va == 0 {
        return -14; // EFAULT
    }

    let pid = scheduler::current_pid_usize();

    let (utime_ns, stime_ns) = match who {
        RUSAGE_SELF | RUSAGE_THREAD => {
            scheduler::with_proc(pid, |p| (p.utime_ns, p.stime_ns)).unwrap_or((0, 0))
        },
        RUSAGE_CHILDREN => {
            // Reaped-children accounting is wired once wait.rs
            // exposes per-child cpu time; return zeros for now.
            (0u64, 0u64)
        },
        _ => return -22, // EINVAL
    };

    let mut buf = [0u8; 144];

    let utime_sec = (utime_ns / 1_000_000_000) as i64;
    let utime_usec = ((utime_ns % 1_000_000_000) / 1_000) as i64;
    buf[0..8].copy_from_slice(&utime_sec.to_le_bytes());
    buf[8..16].copy_from_slice(&utime_usec.to_le_bytes());

    let stime_sec = (stime_ns / 1_000_000_000) as i64;
    let stime_usec = ((stime_ns % 1_000_000_000) / 1_000) as i64;
    buf[16..24].copy_from_slice(&stime_sec.to_le_bytes());
    buf[24..32].copy_from_slice(&stime_usec.to_le_bytes());

    // ru_maxrss: approximate from the sum of VMA byte spans, in KB.
    let rss_kb = scheduler::with_proc(pid, |p| {
        let pages: usize = p
            .vmas
            .iter()
            .map(|v| v.end.saturating_sub(v.start) / 4096)
            .sum();
        (pages * 4) as i64
    })
    .unwrap_or(0);
    buf[32..40].copy_from_slice(&rss_kb.to_le_bytes());

    // Fields 40..144 (ru_ixrss through ru_nivcsw) remain zero.

    if copy_to_user(usage_va, buf.as_ptr(), buf.len()).is_err() {
        return -14; // EFAULT
    }
    0
}
