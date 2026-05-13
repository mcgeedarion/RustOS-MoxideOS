//! Kernel-internal backing store for /proc/<pid>/mem, /proc/<pid>/regs,
//! and /proc/<pid>/ctl — the three fds that let the GDB stub inspect and
//! control a stopped process without going through ptrace(2).
//!
//! ## fd numbering
//! Synthetic fds are allocated from the range 512..768 so they don't collide
//! with the existing procfs range (256..512) or vfs fds.
//!
//! ## Security
//! Every open checks `may_debug(opener_pid, target_pid)` which mirrors the
//! ptrace permission check: caller must be a direct parent or hold
//! CAP_SYS_PTRACE.

extern crate alloc;
use alloc::collections::BTreeMap;
use spin::Mutex;

use crate::arch::api::{Paging, PageFlags};
use crate::arch::Arch;
use crate::proc::scheduler;
use crate::proc::ptrace::{UREG_COUNT, build_user_regs_pub, apply_user_regs_pub};

// ── fd range ────────────────────────────────────────────────────────────────

pub const PROC_DEBUG_FD_BASE: usize = 512;
pub const PROC_DEBUG_FD_END:  usize = 768;

// ── ProcDebugKind ─────────────────────────────────────────────────────────

#[derive(Clone, Copy, Debug)]
pub enum ProcDebugKind {
    Mem  { pid: usize },
    Regs { pid: usize },
    Ctl  { pid: usize },
}

#[derive(Clone)]
struct DebugFd {
    kind: ProcDebugKind,
}

static PROC_DEBUG_FDS: Mutex<BTreeMap<usize, DebugFd>> =
    Mutex::new(BTreeMap::new());

// ── helpers ───────────────────────────────────────────────────────────────

pub fn is_proc_debug_fd(fdno: usize) -> bool {
    fdno >= PROC_DEBUG_FD_BASE && fdno < PROC_DEBUG_FD_END
        && PROC_DEBUG_FDS.lock().contains_key(&fdno)
}

fn alloc_fd() -> Option<usize> {
    let guard = PROC_DEBUG_FDS.lock();
    for c in PROC_DEBUG_FD_BASE..PROC_DEBUG_FD_END {
        if !guard.contains_key(&c) { return Some(c); }
    }
    None
}

fn may_debug(opener: usize, target: usize) -> bool {
    scheduler::with_proc(target, |p| p.ppid == opener).unwrap_or(false)
        || scheduler::with_proc(opener, |p| {
            p.caps.has_cap(crate::security::CAP_SYS_PTRACE)
        }).unwrap_or(false)
}

// ── open ─────────────────────────────────────────────────────────────────

/// Called from `procfs_open` for paths it recognises as debug paths.
/// Returns a new synthetic fd ≥ PROC_DEBUG_FD_BASE, or a negative errno.
pub fn proc_debug_open(opener: usize, path: &str) -> isize {
    // path must be /proc/<pid>/mem | /proc/<pid>/regs | /proc/<pid>/ctl
    let (pid, kind_str) = match parse_debug_path(path) {
        Some(x) => x,
        None    => return -2, // ENOENT
    };
    if !may_debug(opener, pid) { return -1; } // EPERM
    let kind = match kind_str {
        "mem"  => ProcDebugKind::Mem  { pid },
        "regs" => ProcDebugKind::Regs { pid },
        "ctl"  => ProcDebugKind::Ctl  { pid },
        _      => return -2,
    };
    let fdno = match alloc_fd() {
        Some(f) => f,
        None    => return -24, // EMFILE
    };
    PROC_DEBUG_FDS.lock().insert(fdno, DebugFd { kind });
    fdno as isize
}

pub fn proc_debug_close(fdno: usize) {
    PROC_DEBUG_FDS.lock().remove(&fdno);
}

// ── read ──────────────────────────────────────────────────────────────────

/// pread64-style: `offset` is the virtual address for Mem fds;
/// ignored (treated as 0) for Regs and Ctl fds.
pub fn proc_debug_read(fdno: usize, buf: &mut [u8], offset: usize) -> isize {
    let kind = match PROC_DEBUG_FDS.lock().get(&fdno).map(|f| f.kind) {
        Some(k) => k,
        None    => return -9, // EBADF
    };
    match kind {
        ProcDebugKind::Mem { pid } => read_mem(pid, buf, offset),
        ProcDebugKind::Regs { pid } => read_regs(pid, buf),
        ProcDebugKind::Ctl { pid } => read_ctl(pid, buf),
    }
}

fn read_mem(pid: usize, buf: &mut [u8], vaddr: usize) -> isize {
    let cr3 = match scheduler::with_proc(pid, |p| p.user_satp) {
        Some(c) if c != 0 => c,
        _ => return -3, // ESRCH
    };
    let mut written = 0usize;
    let mut va = vaddr;
    for chunk in buf.iter_mut() {
        match <Arch as Paging>::virt_to_phys(cr3, va) {
            Some(pa) => { *chunk = unsafe { *(pa as *const u8) }; }
            None     => break,
        }
        va += 1;
        written += 1;
    }
    written as isize
}

fn read_regs(pid: usize, buf: &mut [u8]) -> isize {
    let needed = UREG_COUNT * 8;
    if buf.len() < needed { return -22; } // EINVAL
    let regs = match scheduler::with_proc(pid, |p| {
        if p.kstack_top == 0 { return None; }
        Some(build_user_regs_pub(p.kstack_top, p.ctx.fs_base))
    }) {
        Some(Some(r)) => r,
        _ => return -3,
    };
    let bytes = unsafe {
        core::slice::from_raw_parts(regs.as_ptr() as *const u8, needed)
    };
    buf[..needed].copy_from_slice(bytes);
    needed as isize
}

fn read_ctl(pid: usize, buf: &mut [u8]) -> isize {
    use crate::proc::ptrace::PtraceState;
    let state = match scheduler::with_proc(pid, |p| p.ptrace_state) {
        Some(s) => s,
        None    => return -3,
    };
    let msg: &[u8] = match state {
        PtraceState::Stopped { sig, .. } => {
            // Return "T<signum hex2>" like RSP stop reply
            let s = alloc::format!("T{:02x}", sig);
            let bytes = s.as_bytes();
            let n = bytes.len().min(buf.len());
            buf[..n].copy_from_slice(&bytes[..n]);
            return n as isize;
        }
        PtraceState::Tracee { .. } => b"running",
        PtraceState::None          => b"none",
    };
    let n = msg.len().min(buf.len());
    buf[..n].copy_from_slice(&msg[..n]);
    n as isize
}

// ── write ─────────────────────────────────────────────────────────────────

/// pwrite64-style: `offset` is the target virtual address for Mem fds.
pub fn proc_debug_write(fdno: usize, data: &[u8], offset: usize) -> isize {
    let kind = match PROC_DEBUG_FDS.lock().get(&fdno).map(|f| f.kind) {
        Some(k) => k,
        None    => return -9,
    };
    match kind {
        ProcDebugKind::Mem { pid } => write_mem(pid, data, offset),
        ProcDebugKind::Regs { pid } => write_regs(pid, data),
        ProcDebugKind::Ctl { pid } => write_ctl(pid, data),
    }
}

fn write_mem(pid: usize, data: &[u8], vaddr: usize) -> isize {
    let cr3 = match scheduler::with_proc(pid, |p| p.user_satp) {
        Some(c) if c != 0 => c,
        _ => return -3,
    };
    let mut written = 0usize;
    let mut va = vaddr;
    for &byte in data {
        match <Arch as Paging>::virt_to_phys(cr3, va) {
            Some(pa) => { unsafe { *(pa as *mut u8) = byte; } }
            None     => break,
        }
        va += 1;
        written += 1;
    }
    written as isize
}

fn write_regs(pid: usize, data: &[u8]) -> isize {
    let needed = UREG_COUNT * 8;
    if data.len() < needed { return -22; }
    let mut regs = [0u64; UREG_COUNT];
    for i in 0..UREG_COUNT {
        regs[i] = u64::from_le_bytes(data[i*8..(i+1)*8].try_into().unwrap());
    }
    let ok = scheduler::with_proc_mut(pid, |p, _| {
        if p.kstack_top == 0 { return false; }
        apply_user_regs_pub(p.kstack_top, &regs);
        true
    }).unwrap_or(false);
    if ok { needed as isize } else { -3 }
}

// RFLAGS trap flag (bit 8)
const RFLAGS_TF: usize = 1 << 8;
// kstack frame slot index for RFLAGS (same layout as ptrace.rs F_R11)
const FRAME_SZ: usize = 17 * 8;
const F_R11: usize = 14; // RFLAGS lives in saved R11 slot on SYSRET path

fn write_ctl(pid: usize, data: &[u8]) -> isize {
    let cmd = core::str::from_utf8(data).unwrap_or("").trim();
    use crate::proc::ptrace::PtraceState;
    use crate::proc::signal::send_signal;
    match cmd {
        "stop" => {
            send_signal(pid, 19); // SIGSTOP
            data.len() as isize
        }
        "cont" => {
            let caller = scheduler::current_pid();
            scheduler::with_proc_mut(pid, |p, _| {
                if let PtraceState::Stopped { tracer, options, .. } = p.ptrace_state {
                    if tracer == caller {
                        p.ptrace_state = PtraceState::Tracee {
                            tracer, options, in_syscall_stop: false,
                        };
                    }
                }
            });
            scheduler::wake_pid(pid);
            data.len() as isize
        }
        "step" => {
            let caller = scheduler::current_pid();
            scheduler::with_proc_mut(pid, |p, _| {
                if let PtraceState::Stopped { tracer, options, .. } = p.ptrace_state {
                    if tracer == caller {
                        p.ptrace_state = PtraceState::Tracee {
                            tracer, options, in_syscall_stop: false,
                        };
                        // Set x86-64 trap flag in saved RFLAGS
                        #[cfg(target_arch = "x86_64")]
                        if p.kstack_top != 0 {
                            let frame_base = p.kstack_top - FRAME_SZ;
                            let f = unsafe {
                                core::slice::from_raw_parts_mut(
                                    frame_base as *mut usize, 17)
                            };
                            f[F_R11] |= RFLAGS_TF;
                        }
                        // RISC-V: handled by ebreak injection in rsp_riscv.rs
                    }
                }
            });
            scheduler::wake_pid(pid);
            data.len() as isize
        }
        _ => -22, // EINVAL
    }
}

// ── path parser ───────────────────────────────────────────────────────────

/// Parse "/proc/<pid>/mem|regs|ctl" → Some((pid, "mem"|"regs"|"ctl"))
fn parse_debug_path(path: &str) -> Option<(usize, &str)> {
    let after = path.strip_prefix("/proc/")?;
    let slash = after.find('/')?;
    let pid: usize = after[..slash].parse().ok()?;
    let leaf = &after[slash+1..];
    match leaf {
        "mem" | "regs" | "ctl" => Some((pid, leaf)),
        _ => None,
    }
}
