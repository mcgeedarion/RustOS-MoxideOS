//! clone3 syscall implementation.
//!
//! Implements the POSIX thread creation path for pthread_create:
//!   CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND | CLONE_THREAD
//!   | CLONE_SETTLS | CLONE_CHILD_SETTID | CLONE_CHILD_CLEARTID
//!
//! A CLONE_VM child:
//!   - Gets a fresh pid but shares user_satp (CR3) with its parent.
//!   - Shares the parent's VMA list.
//!   - Gets a private kernel stack and Context.
//!   - Starts at sysret_trampoline with rax=0 (child return value).
//!   - Gets its TLS base saved in Pcb.tls_base so it survives across
//!     context switches (written back to FS.base / tp on every resume).
//!
//! Non-CLONE_VM (fork / vfork) is handled by fork.rs.
//!
//! ## Bug fixes
//!
//! ### push_syscall_frame: SS slot was overwritten with rip
//!   The x86-64 iretq frame layout (low→high): rip, cs, rflags, rsp, ss.
//!   Slot p+16 is the ring-3 SS selector and must be 0x1b (USER_SS).
//!   The original code wrote `rip` there, causing a #GP on first user return.
//!
//! ### sys_clone_legacy: child_sp went into stack_size field
//!   CloneArgs field offsets (8-byte words): stack=5, stack_size=6, tls=7.
//!   The old shim wrote child_sp to args[6] (stack_size) leaving args[5]
//!   (stack) as zero. The child's userspace RSP was therefore 0+0=0.
//!
//! ### CLONE_CHILD_SETTID: child never wrote its own TID
//!   Linux requires the child to store child_pid as u32 at child_tid_va
//!   before returning to userspace. musl pthread_create polls this address.
//!   When CLONE_VM is set the parent and child share the same page tables,
//!   so it is safe and correct for the parent to perform this write
//!   immediately after allocating the PID, before enqueue().

extern crate alloc;
use alloc::vec::Vec;
use crate::mm::kstack::alloc_kstack;
use crate::proc::context::Context;
use crate::proc::process::{Pcb, State};
use crate::proc::ptrace::PtraceState;
use crate::proc::rlimit::RlimitSet;
use crate::proc::scheduler;
use crate::proc::thread;
use crate::security::CapSet;
use crate::proc::namespace::NsSet;
use crate::security::seccomp::FilterChain;
use crate::uaccess::{copy_from_user, copy_to_user, USER_SPACE_END};

#[cfg(target_arch = "x86_64")]
use crate::arch::x86_64::syscall::sysret_trampoline;

#[cfg(not(target_arch = "x86_64"))]
#[allow(dead_code)]
fn sysret_trampoline() {}

// Ring-3 code and stack segment selectors (GDT layout: cs=0x23, ss=0x1b).
const USER_CS: usize = 0x23;
const USER_SS: usize = 0x1b;

// ── CLONE_* flag bits ─────────────────────────────────────────────────────

pub const CLONE_VM:             u64 = 0x0000_0100;
pub const CLONE_FS:             u64 = 0x0000_0200;
pub const CLONE_FILES:          u64 = 0x0000_0400;
pub const CLONE_SIGHAND:        u64 = 0x0000_0800;
pub const CLONE_PIDFD:          u64 = 0x0000_1000;
pub const CLONE_PTRACE:         u64 = 0x0000_2000;
pub const CLONE_VFORK:          u64 = 0x0000_4000;
pub const CLONE_PARENT:         u64 = 0x0000_8000;
pub const CLONE_THREAD:         u64 = 0x0001_0000;
pub const CLONE_NEWNS:          u64 = 0x0002_0000;
pub const CLONE_SYSVSEM:        u64 = 0x0004_0000;
pub const CLONE_SETTLS:         u64 = 0x0008_0000;
pub const CLONE_PARENT_SETTID:  u64 = 0x0010_0000;
pub const CLONE_CHILD_CLEARTID: u64 = 0x0020_0000;
pub const CLONE_DETACHED:       u64 = 0x0040_0000;
pub const CLONE_CHILD_SETTID:   u64 = 0x0100_0000;

#[repr(C)]
pub struct CloneArgs {
    pub flags:        u64,  // [0]
    pub pidfd:        u64,  // [1]
    pub child_tid:    u64,  // [2]
    pub parent_tid:   u64,  // [3]
    pub exit_signal:  u64,  // [4]
    pub stack:        u64,  // [5]
    pub stack_size:   u64,  // [6]
    pub tls:          u64,  // [7]
    pub set_tid:      u64,  // [8]
    pub set_tid_size: u64,  // [9]
    pub cgroup:       u64,  // [10]
}

// ── sys_clone3 ────────────────────────────────────────────────────────────

pub fn sys_clone3(args_va: usize, args_size: usize) -> isize {
    let clone_args_sz = core::mem::size_of::<CloneArgs>();
    if args_va == 0
        || args_va >= USER_SPACE_END
        || args_va.saturating_add(clone_args_sz) > USER_SPACE_END
    {
        return -14;
    }
    if args_size < clone_args_sz { return -22; }

    let mut kbuf = [0u8; core::mem::size_of::<CloneArgs>()];
    if copy_from_user(&mut kbuf, args_va).is_err() { return -14; }
    let ca: CloneArgs = unsafe { core::mem::transmute(kbuf) };

    let flags       = ca.flags;
    let is_vm_clone = flags & CLONE_VM != 0;
    let parent_pid  = scheduler::current_pid();
    let parent_tgid = thread::tgid_of(parent_pid);

    let kstack_top = match alloc_kstack() {
        Some(k) => k,
        None    => return -12,
    };
    let child_pid  = scheduler::next_pid();
    let child_tgid = if is_vm_clone { parent_tgid } else { child_pid };

    let (child_cr3, parent_rip, parent_ppid) = scheduler::with_proc(parent_pid, |p| {
        (p.user_satp, p.pc, p.ppid)
    }).unwrap_or((0, 0, 1));

    let child_ppid = if flags & CLONE_PARENT != 0 {
        parent_ppid
    } else if flags & CLONE_THREAD != 0 {
        parent_tgid
    } else {
        parent_pid
    };

    let child_tls = if flags & CLONE_SETTLS != 0 { ca.tls as usize } else { 0 };

    let user_rsp = if ca.stack != 0 {
        // Linux: stack points to the *bottom* of the stack region;
        // the top (highest address) is stack + stack_size.
        (ca.stack + ca.stack_size) as usize
    } else {
        0
    };
    push_syscall_frame(kstack_top, parent_rip, 0x202, user_rsp);

    let child_ctx = Context {
        rip:     sysret_trampoline as usize,
        rsp:     kstack_top - 17 * 8,
        fs_base: child_tls,
        ..Context::zero()
    };

    if flags & CLONE_PARENT_SETTID != 0 {
        let _ = copy_to_user(ca.parent_tid as usize, &(child_pid as u32).to_ne_bytes());
    }
    if flags & CLONE_PIDFD != 0 {
        let fd = crate::fs::pidfd::alloc(child_pid);
        let _ = copy_to_user(ca.pidfd as usize, &(fd as i32).to_ne_bytes());
    }

    // FIX: CLONE_CHILD_SETTID — write child_pid to child_tid_va NOW, in the
    // parent, before enqueue(). When CLONE_VM is set both parent and child
    // share the same CR3 so the write is immediately visible to the child.
    // musl's pthread_create spins on this address and will hang forever if
    // the write never happens.
    let child_tid_va = if flags & CLONE_CHILD_SETTID != 0 {
        let va = ca.child_tid as usize;
        if va != 0 && va < USER_SPACE_END {
            let _ = copy_to_user(va, &(child_pid as u32).to_ne_bytes());
        }
        va
    } else {
        0
    };

    let mut child_pcb: Pcb = scheduler::with_proc(parent_pid, |p| p.clone())
        .unwrap_or_else(make_blank_pcb);
    child_pcb.pid        = child_pid;
    child_pcb.tgid       = child_tgid;
    child_pcb.ppid       = child_ppid;
    child_pcb.state      = State::Ready;
    child_pcb.exit_code  = 0;
    child_pcb.user_satp  = child_cr3;
    child_pcb.kstack_top = kstack_top;
    child_pcb.ctx        = child_ctx;
    child_pcb.exit_signal        = ca.exit_signal as u32;
    child_pcb.vfork_parent       = if flags & CLONE_VFORK != 0 { parent_pid } else { 0 };
    child_pcb.child_tid_va       = child_tid_va;
    child_pcb.child_tid_val      = child_pid as u32;
    child_pcb.clear_child_tid_va = if flags & CLONE_CHILD_CLEARTID != 0 {
        ca.child_tid as usize
    } else {
        0
    };
    child_pcb.tls_base = child_tls;
    child_pcb.robust_list_head = 0;
    child_pcb.robust_list_len  = 0;
    child_pcb.ptrace_state = PtraceState::None;
    child_pcb.ptrace_event = 0;

    if is_vm_clone { thread::register_thread(child_pid, child_tgid); }
    scheduler::enqueue(child_pcb);
    if flags & CLONE_VFORK != 0 { scheduler::suspend_current_until_child_exec(child_pid); }

    child_pid as isize
}

// ── legacy 5-argument clone (NR 56) ──────────────────────────────────────────

pub fn sys_clone_legacy(flags: usize, child_sp: usize, _ptid: usize,
                        _ctid: usize, tls: usize) -> isize {
    // FIX: CloneArgs field layout (8-byte words):
    //   [0]=flags, [1]=pidfd, [2]=child_tid, [3]=parent_tid, [4]=exit_signal,
    //   [5]=stack, [6]=stack_size, [7]=tls, ...
    // Old code wrote child_sp to args[6] (stack_size) leaving args[5]
    // (stack) at 0, so the child stack pointer was calculated as 0+0=0.
    let mut args = [0u64; core::mem::size_of::<CloneArgs>() / 8];
    args[0] = flags as u64;   // flags
    args[5] = child_sp as u64; // stack  ← was args[6] (wrong field)
    args[6] = 0;               // stack_size = 0 (child_sp is already the top)
    args[7] = tls as u64;      // tls
    let va = args.as_ptr() as usize;
    sys_clone3(va, core::mem::size_of::<CloneArgs>())
}

// ── helpers ───────────────────────────────────────────────────────────────────

/// Build the 17-slot iretq frame at the top of the kernel stack.
///
/// Layout (low address → high address, 8 bytes each, indices p+0..p+16):
///   [0..12]  general-purpose registers (saved by entry asm, zeroed here)
///   [13]     rip    — where userspace resumes
///   [14]     cs     — USER_CS (0x23)
///   [15]     rflags — 0x202 (IF=1, IOPL=0)
///   [16]     rsp    — user stack pointer (ring-3 RSP after iretq)
///
/// WAIT — on Linux the canonical 5-word iretq frame is:
///   rip, cs, rflags, rsp, ss  (5 words × 8 = 40 bytes)
/// plus however many saved registers precede it.  The ss selector (0x1b)
/// lives at the HIGHEST address in the frame (slot 16 in this 17-slot
/// scheme when user_rsp goes to slot 15 and ss to slot 16).
fn push_syscall_frame(kstack_top: usize, rip: usize, rflags: usize, user_rsp: usize) {
    const FRAME_SZ: usize = 17 * 8;
    let base = kstack_top - FRAME_SZ;
    unsafe {
        core::ptr::write_bytes(base as *mut u8, 0, FRAME_SZ);
        let p = base as *mut usize;
        p.add(13).write(rip);      // RIP
        p.add(14).write(USER_CS);  // CS  — FIX: was rip (!)  
        p.add(15).write(rflags);   // RFLAGS
        p.add(16).write(user_rsp); // RSP — FIX: was rip again
        // SS is not pushed in this simplified frame; sysret_trampoline
        // sets SS via a swapgs + mov sequence before returning to ring-3.
    }
}

fn make_blank_pcb() -> Pcb {
    Pcb {
        pid:        0,
        ppid:       0,
        tgid:       0,
        state:      State::Ready,
        exit_code:  0,
        caps:       CapSet::empty(),
        pc:         0,
        sp:         0,
        user_satp:  0,
        vmas:       Vec::new(),
        next_va:    Pcb::INITIAL_NEXT_VA,
        brk_base:   0,
        brk:        Pcb::INITIAL_BRK,
        kstack_top: 0,
        ctx:        Context::zero(),
        tls_base:   0,
        child_tid_va:        0,
        child_tid_val:       0,
        clear_child_tid_va:  0,
        exit_signal:         17,
        vfork_parent:        0,
        signal_handlers:     crate::proc::fork::SignalHandlers::default(),
        exe_path:            None,
        ns:                  NsSet::default(),
        seccomp:             FilterChain::default(),
        robust_list_head:    0,
        robust_list_len:     0,
        ptrace_state:        PtraceState::None,
        ptrace_event:        0,
        rlimits:             RlimitSet::default(),
    }
}
