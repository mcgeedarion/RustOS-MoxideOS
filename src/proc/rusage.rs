//! NR 98  getrusage — resource usage statistics.
//!
//! Reads per-process CPU time from `Pcb::utime_ns` / `Pcb::stime_ns`,
//! which are charged by `scheduler::tick()` every TICK_NS (1 ms).
//!
//! Struct layout (x86-64 Linux ABI):
//!   struct rusage {
//!     struct timeval ru_utime;   // user   CPU time  — bytes  0-15
//!     struct timeval ru_stime;   // system CPU time  — bytes 16-31
//!     long   ru_maxrss;          // bytes 32-39
//!     /* 12 × long padding */    // bytes 40-135
//!   };
//! Total: 136 bytes on x86-64.
//!
//! RUSAGE_SELF    (0)  — current process.
//! RUSAGE_CHILDREN(-1) — sum of waited-for children (zeroed; we don't track).
//! RUSAGE_THREAD  (1)  — same as SELF for now.

use crate::uaccess::copy_to_user;

const RUSAGE_SIZE: usize = 136;

pub fn sys_getrusage(who: i32, usage_va: usize) -> isize {
    if usage_va == 0 { return -14; }
    // Validate who.
    match who { 0 | 1 | -1 => {} _ => return -22 }

    let pid = crate::proc::scheduler::current_pid() as usize;

    // Read utime_ns and stime_ns from the PCB.
    let (utime_ns, stime_ns) = if who == -1 {
        // RUSAGE_CHILDREN — we don't accumulate child times yet; return zero.
        (0u64, 0u64)
    } else {
        crate::proc::scheduler::with_proc(pid, |p| {
            (p.utime_ns, p.stime_ns)
        }).unwrap_or((0, 0))
    };

    // Convert ns → {sec, usec} timeval.
    fn ns_to_timeval(ns: u64) -> (i64, i64) {
        ((ns / 1_000_000_000) as i64, ((ns % 1_000_000_000) / 1_000) as i64)
    }

    let (u_sec, u_usec) = ns_to_timeval(utime_ns);
    let (s_sec, s_usec) = ns_to_timeval(stime_ns);

    let mut buf = [0u8; RUSAGE_SIZE];
    // ru_utime
    buf[0..8].copy_from_slice(&u_sec.to_le_bytes());
    buf[8..16].copy_from_slice(&u_usec.to_le_bytes());
    // ru_stime
    buf[16..24].copy_from_slice(&s_sec.to_le_bytes());
    buf[24..32].copy_from_slice(&s_usec.to_le_bytes());
    // ru_maxrss — rough estimate: count VMAs * 4 KiB
    let rss_kb = crate::proc::scheduler::with_proc(pid, |p| p.vmas.len())
        .unwrap_or(0) as i64 * 4;
    buf[32..40].copy_from_slice(&rss_kb.to_le_bytes());
    // remaining fields zeroed

    if copy_to_user(usage_va, &buf).is_err() { return -14; }
    0
}
