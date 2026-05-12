//! seccomp — syscall filtering via cBPF programs.
//!
//! ## Syscall implemented
//!   seccomp(operation, flags, args_va)  [NR 317]
//!
//! ## Supported operations
//!   SECCOMP_SET_MODE_STRICT  (0) — allow only read/write/exit/sigreturn
//!   SECCOMP_SET_MODE_FILTER  (1) — install a cBPF program
//!   SECCOMP_GET_ACTION_AVAIL (2) — probe whether an action code is supported
//!   SECCOMP_GET_NOTIF_FD     (3) — stub; returns -ENOSYS for now
//!
//! ## cBPF evaluation
//!   The filter receives a `seccomp_data` struct:
//!     struct seccomp_data {
//!         i32  nr;          // syscall number
//!         u32  arch;        // AUDIT_ARCH_X86_64 = 0xC000_003E
//!         u64  instruction_pointer;
//!         u64  args[6];
//!     };
//!   The program must return one of the SECCOMP_RET_* action codes.
//!
//! ## Action codes (return value from BPF program)
//!   SECCOMP_RET_KILL_PROCESS  0x8000_0000 — kill the whole process
//!   SECCOMP_RET_KILL_THREAD   0x0000_0000 — kill current thread
//!   SECCOMP_RET_TRAP          0x0003_0000 — send SIGSYS
//!   SECCOMP_RET_ERRNO         0x0005_0000 — return -errno (low 16 bits)
//!   SECCOMP_RET_USER_NOTIF    0x7FC0_0000 — (stub) no listener → ENOSYS
//!   SECCOMP_RET_TRACE         0x7FF0_0000 — (stub) no tracer → EPERM
//!   SECCOMP_RET_LOG           0x7FFC_0000 — log and allow
//!   SECCOMP_RET_ALLOW         0x7FFF_0000 — allow the syscall
//!
//! ## Filter inheritance
//!   Filters are stored on the Pcb and inherited across fork/clone.
//!   Threads sharing CLONE_VM share a logical filter chain; each fork
//!   child gets a copy (see `inherit_seccomp`).
//!
//! ## Integration
//!   Call `seccomp_check(nr, args)` at the top of syscall dispatch.
//!   It returns `SeccompVerdict::Allow` or a specific denial action.

extern crate alloc;
use alloc::vec::Vec;

// ─── Operation codes ────────────────────────────────────────────────────────

pub const SECCOMP_SET_MODE_STRICT:  u32 = 0;
pub const SECCOMP_SET_MODE_FILTER:  u32 = 1;
pub const SECCOMP_GET_ACTION_AVAIL: u32 = 2;
pub const SECCOMP_GET_NOTIF_FD:     u32 = 3;

// ─── Flags for SET_MODE_FILTER ──────────────────────────────────────────────

pub const SECCOMP_FILTER_FLAG_TSYNC:           u32 = 1;
pub const SECCOMP_FILTER_FLAG_LOG:             u32 = 2;
pub const SECCOMP_FILTER_FLAG_SPEC_ALLOW:      u32 = 4;
pub const SECCOMP_FILTER_FLAG_NEW_LISTENER:    u32 = 8;
pub const SECCOMP_FILTER_FLAG_TSYNC_ESRCH:     u32 = 16;

// ─── Return action codes ────────────────────────────────────────────────────

pub const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;
pub const SECCOMP_RET_KILL_THREAD:  u32 = 0x0000_0000;
pub const SECCOMP_RET_TRAP:         u32 = 0x0003_0000;
pub const SECCOMP_RET_ERRNO:        u32 = 0x0005_0000;
pub const SECCOMP_RET_USER_NOTIF:   u32 = 0x7FC0_0000;
pub const SECCOMP_RET_TRACE:        u32 = 0x7FF0_0000;
pub const SECCOMP_RET_LOG:          u32 = 0x7FFC_0000;
pub const SECCOMP_RET_ALLOW:        u32 = 0x7FFF_0000;
pub const SECCOMP_RET_ACTION_FULL:  u32 = 0xFFFF_0000;
pub const SECCOMP_RET_DATA:         u32 = 0x0000_FFFF;

// Architecture constant written into seccomp_data.arch
pub const AUDIT_ARCH_X86_64: u32 = 0xC000_003E;

// ─── Errno literals (no_std; avoid libc dep) ────────────────────────────────
const EPERM:  i32 = 1;
const ENOSYS: i32 = 38;

// ─── seccomp_data (fed to BPF program as packet bytes) ──────────────────────

#[repr(C)]
pub struct SeccompData {
    pub nr:                   i32,
    pub arch:                 u32,
    pub instruction_pointer:  u64,
    pub args:                 [u64; 6],
}

impl SeccompData {
    pub fn as_bytes(&self) -> &[u8] {
        // SAFETY: SeccompData is #[repr(C)], fully initialised, no padding.
        unsafe {
            core::slice::from_raw_parts(
                self as *const Self as *const u8,
                core::mem::size_of::<Self>(),
            )
        }
    }
}

// ─── cBPF instruction (sock_filter) ─────────────────────────────────────────

#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct SockFilter {
    pub code: u16,  // BPF_LD, BPF_ALU, BPF_JMP, BPF_RET …
    pub jt:   u8,
    pub jf:   u8,
    pub k:    u32,
}

// BPF instruction class bits
const BPF_LD:   u16 = 0x00;
const BPF_LDX:  u16 = 0x01;
const BPF_ST:   u16 = 0x02;
const BPF_STX:  u16 = 0x03;
const BPF_ALU:  u16 = 0x04;
const BPF_JMP:  u16 = 0x05;
const BPF_RET:  u16 = 0x06;
const BPF_MISC: u16 = 0x07;

// BPF size bits
const BPF_W:  u16 = 0x00; // 32-bit word
const BPF_H:  u16 = 0x08; // 16-bit half-word
const BPF_B:  u16 = 0x10; // 8-bit byte

// BPF addressing mode bits
const BPF_IMM: u16 = 0x00;
const BPF_ABS: u16 = 0x20;
const BPF_IND: u16 = 0x40;
const BPF_MEM: u16 = 0x60;
const BPF_K:   u16 = 0x00;
const BPF_X:   u16 = 0x08;
const BPF_A:   u16 = 0x10;

// BPF ALU ops
const BPF_ADD:  u16 = 0x00;
const BPF_SUB:  u16 = 0x10;
const BPF_MUL:  u16 = 0x20;
const BPF_DIV:  u16 = 0x30;
const BPF_OR:   u16 = 0x40;
const BPF_AND:  u16 = 0x50;
const BPF_LSH:  u16 = 0x60;
const BPF_RSH:  u16 = 0x70;
const BPF_NEG:  u16 = 0x80;
const BPF_MOD:  u16 = 0x90;
const BPF_XOR:  u16 = 0xa0;

// BPF JMP ops
const BPF_JA:   u16 = 0x00;
const BPF_JEQ:  u16 = 0x10;
const BPF_JGT:  u16 = 0x20;
const BPF_JGE:  u16 = 0x30;
const BPF_JSET: u16 = 0x40;

// BPF RET sources
const BPF_RETK: u16 = BPF_RET | BPF_K;  // return K
const BPF_RETA: u16 = BPF_RET | BPF_A;  // return A

// BPF_MISC: TAX / TXA
const BPF_TAX: u16 = BPF_MISC | 0x00;
const BPF_TXA: u16 = BPF_MISC | 0x80;

/// Maximum BPF program length (matching Linux's BPF_MAXINSNS)
const BPF_MAXINSNS: usize = 4096;
/// V10 fix: cap evaluation steps to prevent infinite-loop DoS.
const BPF_MAX_STEPS: usize = 65_536;
/// Working memory for BPF programs (M[0..16])
const BPF_MEMWORDS: usize = 16;

// ─── Verdict returned to dispatch ───────────────────────────────────────────

#[derive(Debug, PartialEq, Eq)]
pub enum SeccompVerdict {
    Allow,
    /// Return -errno to userspace (errno = low 16 bits of RET_ERRNO data).
    Errno(i32),
    /// Send SIGSYS and kill the thread.
    Trap,
    /// Kill the process immediately.
    Kill,
}

// ─── Stored filter (a compiled + validated BPF program) ──────────────────────

#[derive(Clone)]
pub struct SeccompFilter {
    pub insns: Vec<SockFilter>,
    pub log:   bool, // SECCOMP_FILTER_FLAG_LOG
}

/// Filters chained on a process.  Evaluated last-to-first (most-recent wins).
/// This matches Linux's behaviour: the most recently installed filter is
/// consulted first, and the most restrictive action wins across the chain.
#[derive(Clone, Default)]
pub struct FilterChain {
    pub filters: Vec<SeccompFilter>,
    pub strict:  bool,  // SECCOMP_SET_MODE_STRICT active
}

// ─── cBPF evaluator ─────────────────────────────────────────────────────────

/// Evaluate a single cBPF program against `data` bytes.
/// Returns the u32 action code produced by BPF_RET.
/// On any malformed access or step-limit exceeded, returns SECCOMP_RET_KILL_PROCESS.
fn bpf_run(insns: &[SockFilter], data: &[u8]) -> u32 {
    let mut a: u32 = 0;
    let mut x: u32 = 0;
    let mut m = [0u32; BPF_MEMWORDS];
    let mut pc: usize = 0;
    // V10 fix: step counter prevents infinite-loop BPF programs from
    // hanging the kernel evaluation path.
    let mut steps: usize = 0;

    if insns.len() > BPF_MAXINSNS { return SECCOMP_RET_KILL_PROCESS; }

    loop {
        if pc >= insns.len() { return SECCOMP_RET_KILL_PROCESS; }
        steps += 1;
        if steps > BPF_MAX_STEPS { return SECCOMP_RET_KILL_PROCESS; }
        let ins = insns[pc];
        let code = ins.code;
        let k    = ins.k;

        match code {
            // ── Load word from packet (seccomp_data) at offset k ──────────
            c if c == BPF_LD | BPF_W | BPF_ABS => {
                a = load_u32(data, k as usize).unwrap_or(return SECCOMP_RET_KILL_PROCESS);
            }
            c if c == BPF_LD | BPF_H | BPF_ABS => {
                a = load_u16(data, k as usize).unwrap_or(return SECCOMP_RET_KILL_PROCESS) as u32;
            }
            c if c == BPF_LD | BPF_B | BPF_ABS => {
                a = load_u8(data, k as usize).unwrap_or(return SECCOMP_RET_KILL_PROCESS) as u32;
            }
            c if c == BPF_LD | BPF_W | BPF_IND => {
                let off = x.wrapping_add(k) as usize;
                a = load_u32(data, off).unwrap_or(return SECCOMP_RET_KILL_PROCESS);
            }
            // ── Load immediate ─────────────────────────────────────────────
            c if c == BPF_LD | BPF_IMM => {
                a = k;
            }
            c if c == BPF_LDX | BPF_W | BPF_IMM => {
                x = k;
            }
            // ── Load from memory ──────────────────────────────────────────
            c if c == BPF_LD | BPF_MEM => {
                a = *m.get(k as usize).unwrap_or(return SECCOMP_RET_KILL_PROCESS);
            }
            c if c == BPF_LDX | BPF_MEM => {
                x = *m.get(k as usize).unwrap_or(return SECCOMP_RET_KILL_PROCESS);
            }
            // ── Store to memory ───────────────────────────────────────────
            c if c == BPF_ST => {
                let slot = m.get_mut(k as usize).unwrap_or(return SECCOMP_RET_KILL_PROCESS);
                *slot = a;
            }
            c if c == BPF_STX => {
                let slot = m.get_mut(k as usize).unwrap_or(return SECCOMP_RET_KILL_PROCESS);
                *slot = x;
            }
            // ── ALU ───────────────────────────────────────────────────────
            c if c == BPF_ALU | BPF_ADD | BPF_K => { a = a.wrapping_add(k); }
            c if c == BPF_ALU | BPF_ADD | BPF_X => { a = a.wrapping_add(x); }
            c if c == BPF_ALU | BPF_SUB | BPF_K => { a = a.wrapping_sub(k); }
            c if c == BPF_ALU | BPF_SUB | BPF_X => { a = a.wrapping_sub(x); }
            c if c == BPF_ALU | BPF_MUL | BPF_K => { a = a.wrapping_mul(k); }
            c if c == BPF_ALU | BPF_MUL | BPF_X => { a = a.wrapping_mul(x); }
            c if c == BPF_ALU | BPF_DIV | BPF_K => {
                if k == 0 { return SECCOMP_RET_KILL_PROCESS; }
                a /= k;
            }
            c if c == BPF_ALU | BPF_DIV | BPF_X => {
                if x == 0 { return SECCOMP_RET_KILL_PROCESS; }
                a /= x;
            }
            c if c == BPF_ALU | BPF_MOD | BPF_K => {
                if k == 0 { return SECCOMP_RET_KILL_PROCESS; }
                a %= k;
            }
            c if c == BPF_ALU | BPF_MOD | BPF_X => {
                if x == 0 { return SECCOMP_RET_KILL_PROCESS; }
                a %= x;
            }
            c if c == BPF_ALU | BPF_OR  | BPF_K => { a |= k; }
            c if c == BPF_ALU | BPF_OR  | BPF_X => { a |= x; }
            c if c == BPF_ALU | BPF_AND | BPF_K => { a &= k; }
            c if c == BPF_ALU | BPF_AND | BPF_X => { a &= x; }
            c if c == BPF_ALU | BPF_LSH | BPF_K => { a = a.wrapping_shl(k & 31); }
            c if c == BPF_ALU | BPF_LSH | BPF_X => { a = a.wrapping_shl(x & 31); }
            c if c == BPF_ALU | BPF_RSH | BPF_K => { a = a.wrapping_shr(k & 31); }
            c if c == BPF_ALU | BPF_RSH | BPF_X => { a = a.wrapping_shr(x & 31); }
            c if c == BPF_ALU | BPF_XOR | BPF_K => { a ^= k; }
            c if c == BPF_ALU | BPF_XOR | BPF_X => { a ^= x; }
            c if c == BPF_ALU | BPF_NEG => { a = (!a).wrapping_add(1); }
            // ── MISC: register copy ───────────────────────────────────────
            c if c == BPF_TAX => { x = a; }
            c if c == BPF_TXA => { a = x; }
            // ── JMP ───────────────────────────────────────────────────────
            c if c == BPF_JMP | BPF_JA => {
                pc = pc.wrapping_add(k as usize).wrapping_add(1);
                continue;
            }
            c if c == BPF_JMP | BPF_JEQ | BPF_K => {
                pc += if a == k { ins.jt as usize } else { ins.jf as usize };
            }
            c if c == BPF_JMP | BPF_JEQ | BPF_X => {
                pc += if a == x { ins.jt as usize } else { ins.jf as usize };
            }
            c if c == BPF_JMP | BPF_JGT | BPF_K => {
                pc += if a > k  { ins.jt as usize } else { ins.jf as usize };
            }
            c if c == BPF_JMP | BPF_JGT | BPF_X => {
                pc += if a > x  { ins.jt as usize } else { ins.jf as usize };
            }
            c if c == BPF_JMP | BPF_JGE | BPF_K => {
                pc += if a >= k { ins.jt as usize } else { ins.jf as usize };
            }
            c if c == BPF_JMP | BPF_JGE | BPF_X => {
                pc += if a >= x { ins.jt as usize } else { ins.jf as usize };
            }
            c if c == BPF_JMP | BPF_JSET | BPF_K => {
                pc += if a & k != 0 { ins.jt as usize } else { ins.jf as usize };
            }
            c if c == BPF_JMP | BPF_JSET | BPF_X => {
                pc += if a & x != 0 { ins.jt as usize } else { ins.jf as usize };
            }
            // ── RET ───────────────────────────────────────────────────────
            c if c == BPF_RETK => { return k; }
            c if c == BPF_RETA => { return a; }
            // ── Unknown instruction → kill ────────────────────────────────
            _ => { return SECCOMP_RET_KILL_PROCESS; }
        }
        pc += 1;
    }
}

// ─── Packet load helpers ─────────────────────────────────────────────────────

#[inline]
fn load_u32(data: &[u8], off: usize) -> Option<u32> {
    let s = data.get(off..off + 4)?;
    Some(u32::from_ne_bytes([s[0], s[1], s[2], s[3]]))
}
#[inline]
fn load_u16(data: &[u8], off: usize) -> Option<u16> {
    let s = data.get(off..off + 2)?;
    Some(u16::from_ne_bytes([s[0], s[1]]))
}
#[inline]
fn load_u8(data: &[u8], off: usize) -> Option<u8> {
    data.get(off).copied()
}

// ─── Public: check a syscall through the current process's filter chain ───────

/// Called at the top of the syscall dispatch path.
/// `args` is `[a, b, c, d, e, f]` from the register file.
/// Returns Allow, or a denial verdict that dispatch must honour.
pub fn seccomp_check(nr: usize, args: &[usize; 6]) -> SeccompVerdict {
    let pid = crate::proc::scheduler::current_pid();
    if pid == 0 { return SeccompVerdict::Allow; }

    // Read the filter chain out of the PCB.
    let chain = match crate::proc::scheduler::with_proc(pid, |p| p.seccomp.clone()) {
        Some(c) => c,
        None    => return SeccompVerdict::Allow,
    };

    // SECCOMP_SET_MODE_STRICT: only allow read(0)/write(1)/exit(60)/exit_group(231)/rt_sigreturn(15).
    if chain.strict {
        return match nr {
            0 | 1 | 15 | 60 | 231 => SeccompVerdict::Allow,
            _ => SeccompVerdict::Kill,
        };
    }

    if chain.filters.is_empty() { return SeccompVerdict::Allow; }

    let data = SeccompData {
        nr:                  nr as i32,
        arch:                AUDIT_ARCH_X86_64,
        instruction_pointer: 0, // TODO: plumb saved RIP from SyscallFrame
        args:                [
            args[0] as u64, args[1] as u64, args[2] as u64,
            args[3] as u64, args[4] as u64, args[5] as u64,
        ],
    };
    let bytes = data.as_bytes();

    // Linux semantics: evaluate filters from most-recently-installed to oldest.
    // The most restrictive action wins across the whole chain.
    let mut worst: u32 = SECCOMP_RET_ALLOW;
    for filter in chain.filters.iter().rev() {
        let ret = bpf_run(&filter.insns, bytes);
        let action = ret & SECCOMP_RET_ACTION_FULL;
        // Lower action value = more restrictive (KILL=0 < TRAP < ERRNO < ALLOW).
        if action < (worst & SECCOMP_RET_ACTION_FULL) {
            worst = ret;
        }
    }

    action_to_verdict(worst)
}

fn action_to_verdict(ret: u32) -> SeccompVerdict {
    let action = ret & SECCOMP_RET_ACTION_FULL;
    match action {
        a if a == SECCOMP_RET_KILL_PROCESS => SeccompVerdict::Kill,
        a if a == SECCOMP_RET_KILL_THREAD  => SeccompVerdict::Kill,
        a if a == SECCOMP_RET_TRAP         => SeccompVerdict::Trap,
        a if a == SECCOMP_RET_ERRNO        => {
            let errno = (ret & SECCOMP_RET_DATA) as i32;
            SeccompVerdict::Errno(if errno == 0 { 1 } else { errno })
        }
        // V11 fix: TRACE — no ptrace tracer attached → deny with EPERM.
        // Linux default: if no tracer is present the syscall is denied.
        // When ptrace support is added, check for an attached tracer here
        // and return Allow only if one exists.
        a if a == SECCOMP_RET_TRACE => SeccompVerdict::Errno(EPERM),
        // V11 fix: USER_NOTIF — no listener installed → deny with ENOSYS
        // rather than killing the process outright, giving callers a
        // recoverable error instead of a hard crash.
        a if a == SECCOMP_RET_USER_NOTIF => SeccompVerdict::Errno(ENOSYS),
        // LOG / ALLOW
        _ => SeccompVerdict::Allow,
    }
}

// ─── sys_seccomp ─────────────────────────────────────────────────────────────

/// seccomp(operation, flags, args_va)  [NR 317]
///
/// `args_va` points to a `sock_fprog` (for FILTER mode):
///   struct sock_fprog {
///       u16          len;    // number of SockFilter instructions
///       u16          _pad[3];
///       *SockFilter  filter; // pointer to the instruction array
///   };
///   Actual layout: { u16 len; *const SockFilter filter } — 16 bytes total on
///   64-bit because the pointer is at offset 8 (4-byte hole after len).
pub fn sys_seccomp(operation: u32, flags: u32, args_va: usize) -> isize {
    // Only a process with CAP_SYS_ADMIN may install filters unless it called
    // prctl(PR_SET_NO_NEW_PRIVS, 1).  We check the simpler form: any process
    // may install a filter if it already has one (filter stacking), or if it
    // holds CAP_SYS_ADMIN.  For now we also allow unprivileged processes to
    // call SECCOMP_SET_MODE_STRICT / FILTER (matches the no_new_privs path).
    let pid = crate::proc::scheduler::current_pid();
    if pid == 0 { return -1; } // kernel threads

    match operation {
        SECCOMP_SET_MODE_STRICT => {
            if flags != 0 { return -22; } // EINVAL
            crate::proc::scheduler::with_proc_mut(pid, |p| {
                p.seccomp.strict  = true;
                p.seccomp.filters.clear();
            });
            0
        }

        SECCOMP_SET_MODE_FILTER => {
            if args_va == 0 { return -14; } // EFAULT
            // Read sock_fprog: u16 len at offset 0, u64 filter_ptr at offset 8.
            let mut fprog = [0u8; 16];
            if crate::uaccess::copy_from_user(&mut fprog, args_va).is_err() {
                return -14;
            }
            let len        = u16::from_le_bytes([fprog[0], fprog[1]]) as usize;
            let filter_ptr = usize::from_le_bytes(fprog[8..16].try_into().unwrap());

            if len == 0 || len > BPF_MAXINSNS { return -22; } // EINVAL
            if filter_ptr == 0 { return -14; } // EFAULT

            // Read the BPF instruction array.
            let insn_sz = core::mem::size_of::<SockFilter>(); // 8 bytes
            let mut raw = alloc::vec![0u8; len * insn_sz];
            if crate::uaccess::copy_from_user(&mut raw, filter_ptr).is_err() {
                return -14;
            }
            let mut insns = Vec::with_capacity(len);
            for i in 0..len {
                let b = &raw[i * insn_sz..(i + 1) * insn_sz];
                insns.push(SockFilter {
                    code: u16::from_le_bytes([b[0], b[1]]),
                    jt:   b[2],
                    jf:   b[3],
                    k:    u32::from_le_bytes([b[4], b[5], b[6], b[7]]),
                });
            }

            let log = flags & SECCOMP_FILTER_FLAG_LOG != 0;
            let filter = SeccompFilter { insns, log };

            let tsync = flags & SECCOMP_FILTER_FLAG_TSYNC != 0;

            crate::proc::scheduler::with_proc_mut(pid, |p| {
                p.seccomp.filters.push(filter.clone());
            });

            // TSYNC: push the same filter to every thread in the thread group.
            if tsync {
                let tgid = crate::proc::thread::tgid_of(pid);
                for tid in crate::proc::thread::threads_of(tgid) {
                    if tid != pid {
                        crate::proc::scheduler::with_proc_mut(tid, |p| {
                            p.seccomp.filters.push(filter.clone());
                        });
                    }
                }
            }
            0
        }

        SECCOMP_GET_ACTION_AVAIL => {
            // args_va is a pointer to a u32 action code to probe.
            let mut buf = [0u8; 4];
            if crate::uaccess::copy_from_user(&mut buf, args_va).is_err() {
                return -14;
            }
            let action = u32::from_le_bytes(buf) & SECCOMP_RET_ACTION_FULL;
            let avail = matches!(
                action,
                SECCOMP_RET_KILL_PROCESS | SECCOMP_RET_KILL_THREAD |
                SECCOMP_RET_TRAP | SECCOMP_RET_ERRNO |
                SECCOMP_RET_LOG | SECCOMP_RET_ALLOW
            );
            if avail { 0 } else { -22 }
        }

        SECCOMP_GET_NOTIF_FD => -38, // ENOSYS — notif fd not yet implemented

        _ => -22, // EINVAL
    }
}

// ─── Inheritance helper ───────────────────────────────────────────────────────

/// Returns a clone of the current process's seccomp filter chain for
/// inheritance into a fork/clone child.  Must be called while holding
/// no PCB locks.
pub fn inherit_seccomp(parent_pid: usize) -> FilterChain {
    crate::proc::scheduler::with_proc(parent_pid, |p| p.seccomp.clone())
        .unwrap_or_default()
}
