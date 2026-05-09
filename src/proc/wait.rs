//! waitpid / wait4 and process-exit / process-stop notification.
//!
//! ## wstatus bit layout (matches Linux / POSIX):
//!
//!   Normal exit:   `(exit_code & 0xFF) << 8`          — WIFEXITED true
//!   Signal kill:   `(signum & 0x7F) | (core << 7)`    — WIFSIGNALED true
//!   Stopped:       `(stopsig << 8) | 0x7F`             — WIFSTOPPED true
//!   Continued:     `0xFFFF`                             — WIFCONTINUED true
//!
//! `Pcb::exit_code` stores these pre-encoded bits, NOT a raw exit value.
//! `do_exit` must call `encode_exit(code)` and signal paths must call
//! `encode_signal(signum, coredump)` before storing into `exit_code`.

use crate::proc::process::State;
use crate::proc::scheduler;
use crate::uaccess::copy_to_user;

// ── wstatus encoding (store into Pcb::exit_code) ─────────────────────────────

/// Encode a normal exit into wait-status bits.  Call from do_exit.
#[inline]
pub fn encode_exit(code: i32) -> i32 {
    (code & 0xFF) << 8
}

/// Encode a signal-kill into wait-status bits.  Call from signal delivery.
#[inline]
pub fn encode_signal(signum: u32, coredump: bool) -> i32 {
    ((signum & 0x7F) | if coredump { 0x80 } else { 0 }) as i32
}

/// Encode a stop (SIGSTOP / ptrace) into wait-status bits.
#[inline]
pub fn encode_stop(stopsig: u32) -> i32 {
    ((stopsig & 0xFF) << 8) as i32 | 0x7F
}

/// Continued (SIGCONT resumed) wstatus sentinel.
pub const WSTATUS_CONTINUED: i32 = 0xFFFF;

// ── option flags ─────────────────────────────────────────────────────────────

pub const WNOHANG:     u32 = 1;
pub const WUNTRACED:   u32 = 2;
pub const WCONTINUED:  u32 = 8;
/// Linux-specific: don't reap, just peek.  We implement it as a no-reap flag.
pub const WNOWAIT:     u32 = 0x01000000;

// ── rusage layout (Linux x86-64 / riscv64 ABI) ───────────────────────────────
//
// struct rusage {                // offset  size
//   struct timeval ru_utime;    //   0      16  (tv_sec u64 + tv_usec u64)
//   struct timeval ru_stime;    //  16      16
//   /* 14 × long padding */     //  32     112
// };                            // total: 144 bytes
//
// We approximate: charge all CPU time to utime, stime = 0.
// This satisfies `time(1)` and shells that look at ru_utime.

const RUSAGE_SIZE: usize = 144;

fn write_rusage(va: usize, cpu_ns: u64) {
    if va == 0 { return; }
    let mut buf = [0u8; RUSAGE_SIZE];
    let tv_sec  = cpu_ns / 1_000_000_000;
    let tv_usec = (cpu_ns % 1_000_000_000) / 1_000;
    buf[0..8].copy_from_slice(&tv_sec.to_ne_bytes());
    buf[8..16].copy_from_slice(&tv_usec.to_ne_bytes());
    // stime = 0, rest = 0 (already zeroed)
    let _ = copy_to_user(va, &buf);
}

// ── notify_exit ───────────────────────────────────────────────────────────────
//
// Called by do_exit() after the process is zombified.

pub fn notify_exit(exited_pid: usize) {
    let (ppid, exit_signal) = scheduler::with_proc(exited_pid, |p| (p.ppid, p.exit_signal))
        .unwrap_or((0, 17));
    if ppid == 0 { return; }
    scheduler::wake_pid(ppid);
    if exit_signal != 0 {
        crate::proc::signal::send_signal(ppid, exit_signal);
    }
}

// ── notify_stop ──────────────────────────────────────────────────────────────
//
// Called by signal.rs when a process transitions to State::Stopped (SIGSTOP,
// SIGTSTP, ptrace-stop).  Wakes the parent's waitpid loop and optionally sends
// SIGCHLD (unless SA_NOCLDSTOP is set on the parent's SIGCHLD handler).

pub fn notify_stop(stopped_pid: usize, stopsig: u32) {
    // Record stop signal in exit_code so parent can read it via wstatus.
    scheduler::with_proc_mut(stopped_pid, |p| {
        p.exit_code = encode_stop(stopsig);
    });

    let ppid = scheduler::with_proc(stopped_pid, |p| p.ppid).unwrap_or(0);
    if ppid == 0 { return; }

    scheduler::wake_pid(ppid);

    // Send SIGCHLD unless parent has SA_NOCLDSTOP on SIGCHLD (signum 17).
    const SIGCHLD: u32 = 17;
    const SA_NOCLDSTOP: u64 = 1;
    let nocldstop = scheduler::with_proc(ppid, |p| {
        p.signal_handlers
            .get(SIGCHLD as usize)
            .map(|h| h.flags & SA_NOCLDSTOP != 0)
            .unwrap_or(false)
    }).unwrap_or(false);

    if !nocldstop {
        crate::proc::signal::send_signal(ppid, SIGCHLD);
    }
}

// ── notify_continue ──────────────────────────────────────────────────────────
//
// Called by signal.rs when SIGCONT is delivered and the process resumes.
// Marks the process as Continued so WCONTINUED waiters can harvest it.

pub fn notify_continue(cont_pid: usize) {
    scheduler::with_proc_mut(cont_pid, |p| {
        p.exit_code = WSTATUS_CONTINUED;
        p.state = State::Continued;
    });
    let ppid = scheduler::with_proc(cont_pid, |p| p.ppid).unwrap_or(0);
    if ppid != 0 { scheduler::wake_pid(ppid); }
}

// ── pid / pgid match predicate ────────────────────────────────────────────────

#[inline]
fn matches_pid(p_pid: usize, p_pgid: usize, wait_pid: isize) -> bool {
    match wait_pid {
        -1       => true,                      // any child
        0        => true,                      // same process group (approx — pgid=caller not threaded here)
        n if n > 0 => p_pid == n as usize,     // specific pid
        n        => p_pgid == (-n) as usize,   // any child in pgid
    }
}

// ── one-shot scan result ─────────────────────────────────────────────────────

enum WaitScan {
    /// Found a harvestable event; `nowait` controls whether the entry is removed.
    Harvested { child_pid: usize, wstatus: i32, cpu_ns: u64 },
    /// At least one matching living child; caller should block.
    HasLiving,
    /// No matching child at all.
    NoChild,
}

// ── sys_waitpid [NR 61 on x86-64, NR 7 on riscv] ────────────────────────────

pub fn sys_waitpid(pid: isize, wstatus_va: usize, options: u32) -> isize {
    sys_wait4_impl(pid, wstatus_va, options, 0)
}

// ── sys_wait4 [NR 61 on x86-64] ──────────────────────────────────────────────

pub fn sys_wait4(pid: isize, wstatus_va: usize, options: u32, rusage_va: usize) -> isize {
    sys_wait4_impl(pid, wstatus_va, options, rusage_va)
}

// ── core implementation ───────────────────────────────────────────────────────

fn sys_wait4_impl(pid: isize, wstatus_va: usize, options: u32, rusage_va: usize) -> isize {
    let caller   = scheduler::current_pid();
    let wnohang  = options & WNOHANG    != 0;
    let wuntraced= options & WUNTRACED  != 0;
    let wcont    = options & WCONTINUED != 0;
    let nowait   = options & WNOWAIT    != 0;

    loop {
        let scan = scheduler::with_procs(|procs| {
            // ── 1. Look for a zombie ───────────────────────────────────────
            if let Some(idx) = procs.iter().position(|p| {
                p.ppid == caller
                    && p.state == State::Zombie
                    && matches_pid(p.pid, p.pgid, pid)
            }) {
                let cpu_ns  = procs[idx].cpu_time_ns;
                let wstatus = procs[idx].exit_code;
                let child_pid = procs[idx].pid;
                if !nowait { procs.swap_remove(idx); }
                return WaitScan::Harvested { child_pid, wstatus, cpu_ns };
            }

            // ── 2. WUNTRACED: look for a stopped child ─────────────────────
            if wuntraced {
                if let Some(idx) = procs.iter().position(|p| {
                    p.ppid == caller
                        && p.state == State::Stopped
                        && matches_pid(p.pid, p.pgid, pid)
                }) {
                    let cpu_ns    = procs[idx].cpu_time_ns;
                    let wstatus   = procs[idx].exit_code; // set by notify_stop
                    let child_pid = procs[idx].pid;
                    // Stopped children are NOT removed from the process table.
                    // Their stop is reported once; transition to Reported state
                    // prevents re-reporting until the next stop event.
                    procs[idx].state = State::StopReported;
                    return WaitScan::Harvested { child_pid, wstatus, cpu_ns };
                }
            }

            // ── 3. WCONTINUED: look for a continued child ──────────────────
            if wcont {
                if let Some(idx) = procs.iter().position(|p| {
                    p.ppid == caller
                        && p.state == State::Continued
                        && matches_pid(p.pid, p.pgid, pid)
                }) {
                    let cpu_ns    = procs[idx].cpu_time_ns;
                    let wstatus   = WSTATUS_CONTINUED;
                    let child_pid = procs[idx].pid;
                    // Transition back to Running/Ready after reporting.
                    procs[idx].state = State::Ready;
                    procs[idx].exit_code = 0;
                    return WaitScan::Harvested { child_pid, wstatus, cpu_ns };
                }
            }

            // ── 4. Any living matching child? ──────────────────────────────
            let any_child = procs.iter().any(|p| {
                p.ppid == caller && matches_pid(p.pid, p.pgid, pid)
            });

            if any_child { WaitScan::HasLiving } else { WaitScan::NoChild }
        });

        match scan {
            WaitScan::Harvested { child_pid, wstatus, cpu_ns } => {
                if wstatus_va != 0 {
                    let _ = copy_to_user(wstatus_va, &wstatus.to_ne_bytes());
                }
                write_rusage(rusage_va, cpu_ns);
                return child_pid as isize;
            }

            WaitScan::NoChild => return -10, // ECHILD

            WaitScan::HasLiving => {
                if wnohang { return 0; }

                // Block until a child changes state.  wake_pid() is the sole
                // owner of the Ready transition — we must NOT reset state here
                // on wakeup, because a signal delivery may have set it to
                // something else (e.g. Ready via signal_wake) while we slept.
                scheduler::block_current();
                scheduler::schedule();
                // schedule() returns only after wake_pid() made us runnable.

                // If a signal is pending, return EINTR so libc can restart.
                let sig_pending = scheduler::with_proc(caller, |p| {
                    !p.pending_signals.is_empty()
                }).unwrap_or(false);
                if sig_pending { return -4; } // EINTR
            }
        }
    }
}

// ── wstatus decode helpers ────────────────────────────────────────────────────
//
// These mirror the macros in <sys/wait.h> and operate on the encoded wstatus
// integer returned to userspace (or stored in Pcb::exit_code).

/// True if child exited normally (exit() / _exit()).
#[inline] pub fn wifexited(ws: i32)     -> bool { (ws & 0x7F) == 0 }
/// Extract exit code from a normal-exit wstatus.
#[inline] pub fn wexitstatus(ws: i32)   -> i32  { (ws >> 8) & 0xFF }
/// True if child was killed by a signal.
#[inline] pub fn wifsignaled(ws: i32)   -> bool {
    let low7 = ws & 0x7F;
    low7 != 0 && low7 != 0x7F
}
/// Extract terminating signal number.
#[inline] pub fn wtermsig(ws: i32)      -> i32  { ws & 0x7F }
/// True if core was dumped.
#[inline] pub fn wcoredump(ws: i32)     -> bool { ws & 0x80 != 0 }
/// True if child was stopped by a signal.
#[inline] pub fn wifstopped(ws: i32)    -> bool { (ws & 0xFF) == 0x7F }
/// Extract stop signal.
#[inline] pub fn wstopsig(ws: i32)      -> i32  { (ws >> 8) & 0xFF }
/// True if child was resumed by SIGCONT.
#[inline] pub fn wifcontinued(ws: i32)  -> bool { ws == WSTATUS_CONTINUED }
