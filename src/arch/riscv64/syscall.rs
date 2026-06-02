//! RISC-V supervisor-mode syscall notes.
//!
//! The actual trap entry stub lives in `trap.rs` as `riscv_trap_entry`.
//! Syscalls arrive through the ecall (environment call) exception (scause = 8)
//! and are dispatched by `handle_exception` in `trap.rs`.
//!
//! RISC-V Linux syscall ABI:
//!   a7 = NR,  a0–a5 = args,  a0 = return value.
//!   sepc is advanced by 4 (ecall instruction size) before returning.

/// Raw RISC-V Linux ABI syscall numbers (`a7` register).
///
/// These are the numbers that user-space musl / glibc places in `a7` before
/// executing `ecall`.  They must agree with the kernel headers used to build
/// the C runtime; we track the `linux-headers` / `musl` values verbatim.
#[allow(non_upper_case_globals, dead_code)]
pub mod nr {
    pub const io_setup:             usize = 0;
    pub const io_destroy:           usize = 1;
    pub const io_submit:            usize = 2;
    pub const io_cancel:            usize = 3;
    pub const io_getevents:         usize = 4;
    pub const setxattr:             usize = 5;
    pub const lsetxattr:            usize = 6;
    pub const fsetxattr:            usize = 7;
    pub const getxattr:             usize = 8;
    pub const lgetxattr:            usize = 9;
    pub const fgetxattr:            usize = 10;
    pub const listxattr:            usize = 11;
    pub const llistxattr:           usize = 12;
    pub const flistxattr:           usize = 13;
    pub const removexattr:          usize = 14;
    pub const lremovexattr:         usize = 15;
    pub const fremovexattr:         usize = 16;
    pub const getcwd:               usize = 17;
    pub const lookup_dcookie:       usize = 18;
    pub const eventfd2:             usize = 19;
    pub const epoll_create1:        usize = 20;
    pub const epoll_ctl:            usize = 21;
    pub const epoll_pwait:          usize = 22;
    pub const dup:                  usize = 23;
    pub const dup3:                 usize = 24;
    pub const fcntl:                usize = 25;
    pub const inotify_init1:        usize = 26;
    pub const inotify_add_watch:    usize = 27;
    pub const inotify_rm_watch:     usize = 28;
    pub const ioctl:                usize = 29;
    pub const ioprio_set:           usize = 30;
    pub const ioprio_get:           usize = 31;
    pub const flock:                usize = 32;
    pub const mknodat:              usize = 33;
    pub const mkdirat:              usize = 34;
    pub const unlinkat:             usize = 35;
    pub const symlinkat:            usize = 36;
    pub const linkat:               usize = 37;
    pub const renameat:             usize = 38;
    pub const umount2:              usize = 39;
    pub const mount:                usize = 40;
    pub const pivot_root:           usize = 41;
    pub const nfsservctl:           usize = 42;
    pub const statfs:               usize = 43;
    pub const fstatfs:              usize = 44;
    pub const truncate:             usize = 45;
    pub const ftruncate:            usize = 46;
    pub const fallocate:            usize = 47;
    pub const faccessat:            usize = 48;
    pub const chdir:                usize = 49;
    pub const fchdir:               usize = 50;
    pub const chroot:               usize = 51;
    pub const fchmod:               usize = 52;
    pub const fchmodat:             usize = 53;
    pub const fchownat:             usize = 54;
    pub const fchown:               usize = 55;
    pub const openat:               usize = 56;
    pub const close:                usize = 57;
    pub const vhangup:              usize = 58;
    pub const pipe2:                usize = 59;
    pub const quotactl:             usize = 60;
    pub const getdents64:           usize = 61;
    pub const lseek:                usize = 62;
    pub const read:                 usize = 63;
    pub const write:                usize = 64;
    pub const readv:                usize = 65;
    pub const writev:               usize = 66;
    pub const pread64:              usize = 67;
    pub const pwrite64:             usize = 68;
    pub const preadv:               usize = 69;
    pub const pwritev:              usize = 70;
    pub const sendfile:             usize = 71;
    pub const pselect6:             usize = 72;
    pub const ppoll:                usize = 73;
    pub const signalfd4:            usize = 74;
    pub const vmsplice:             usize = 75;
    pub const splice:               usize = 76;
    pub const tee:                  usize = 77;
    pub const readlinkat:           usize = 78;
    pub const newfstatat:           usize = 79;
    pub const fstat:                usize = 80;
    pub const sync:                 usize = 81;
    pub const fsync:                usize = 82;
    pub const fdatasync:            usize = 83;
    pub const sync_file_range:      usize = 84;
    pub const timerfd_create:       usize = 85;
    pub const timerfd_settime:      usize = 86;
    pub const timerfd_gettime:      usize = 87;
    pub const utimensat:            usize = 88;
    pub const acct:                 usize = 89;
    pub const capget:               usize = 90;
    pub const capset:               usize = 91;
    pub const personality:          usize = 92;
    pub const exit:                 usize = 93;
    pub const exit_group:           usize = 94;
    pub const waitid:               usize = 95;
    pub const set_tid_address:      usize = 96;
    pub const unshare:              usize = 97;
    pub const futex:                usize = 98;
    pub const set_robust_list:      usize = 99;
    pub const get_robust_list:      usize = 100;
    pub const nanosleep:            usize = 101;
    pub const getitimer:            usize = 102;
    pub const setitimer:            usize = 103;
    pub const kexec_load:           usize = 104;
    pub const init_module:          usize = 105;
    pub const delete_module:        usize = 106;
    pub const timer_create:         usize = 107;
    pub const timer_gettime:        usize = 108;
    pub const timer_getoverrun:     usize = 109;
    pub const timer_settime:        usize = 110;
    pub const timer_delete:         usize = 111;
    pub const clock_settime:        usize = 112;
    pub const clock_gettime:        usize = 113;
    pub const clock_getres:         usize = 114;
    pub const clock_nanosleep:      usize = 115;
    pub const syslog:               usize = 116;
    pub const ptrace:               usize = 117;
    pub const sched_setparam:       usize = 118;
    pub const sched_setscheduler:   usize = 119;
    pub const sched_getscheduler:   usize = 120;
    pub const sched_getparam:       usize = 121;
    pub const sched_setaffinity:    usize = 122;
    pub const sched_getaffinity:    usize = 123;
    pub const sched_yield:          usize = 124;
    pub const sched_get_priority_max: usize = 125;
    pub const sched_get_priority_min: usize = 126;
    pub const sched_rr_get_interval:  usize = 127;
    pub const restart_syscall:      usize = 128;
    pub const kill:                 usize = 129;
    pub const tkill:                usize = 130;
    pub const tgkill:               usize = 131;
    pub const sigaltstack:          usize = 132;
    pub const rt_sigsuspend:        usize = 133;
    pub const rt_sigaction:         usize = 134;
    pub const rt_sigprocmask:       usize = 135;
    pub const rt_sigpending:        usize = 136;
    pub const rt_sigtimedwait:      usize = 137;
    pub const rt_sigqueueinfo:      usize = 138;
    pub const rt_sigreturn:         usize = 139;
    pub const setpriority:          usize = 140;
    pub const getpriority:          usize = 141;
    pub const reboot:               usize = 142;
    pub const setregid:             usize = 143;
    pub const setgid:               usize = 144;
    pub const setreuid:             usize = 145;
    pub const setuid:               usize = 146;
    pub const setresuid:            usize = 147;
    pub const getresuid:            usize = 148;
    pub const setresgid:            usize = 149;
    pub const getresgid:            usize = 150;
    pub const setfsuid:             usize = 151;
    pub const setfsgid:             usize = 152;
    pub const times:                usize = 153;
    pub const setpgid:              usize = 154;
    pub const getpgid:              usize = 155;
    pub const getsid:               usize = 156;
    pub const setsid:               usize = 157;
    pub const getgroups:            usize = 158;
    pub const setgroups:            usize = 159;
    pub const uname:                usize = 160;
    pub const sethostname:          usize = 161;
    pub const setdomainname:        usize = 162;
    pub const getrlimit:            usize = 163;
    pub const setrlimit:            usize = 164;
    pub const getrusage:            usize = 165;
    pub const umask:                usize = 166;
    pub const prctl:                usize = 167;
    pub const getcpu:               usize = 168;
    pub const gettimeofday:         usize = 169;
    pub const settimeofday:         usize = 170;
    pub const adjtimex:             usize = 171;
    pub const getpid:               usize = 172;
    pub const getppid:              usize = 173;
    pub const getuid:               usize = 174;
    pub const geteuid:              usize = 175;
    pub const getgid:               usize = 176;
    pub const getegid:              usize = 177;
    pub const gettid:               usize = 178;
    pub const sysinfo:              usize = 179;
    pub const mq_open:              usize = 180;
    pub const mq_unlink:            usize = 181;
    pub const mq_timedsend:         usize = 182;
    pub const mq_timedreceive:      usize = 183;
    pub const mq_notify:            usize = 184;
    pub const mq_getsetattr:        usize = 185;
    pub const msgget:               usize = 186;
    pub const msgctl:               usize = 187;
    pub const msgrcv:               usize = 188;
    pub const msgsnd:               usize = 189;
    pub const semget:               usize = 190;
    pub const semctl:               usize = 191;
    pub const semtimedop:           usize = 192;
    pub const semop:                usize = 193;
    pub const shmget:               usize = 194;
    pub const shmctl:               usize = 195;
    pub const shmat:                usize = 196;
    pub const shmdt:                usize = 197;
    pub const socket:               usize = 198;
    pub const socketpair:           usize = 199;
    pub const bind:                 usize = 200;
    pub const listen:               usize = 201;
    pub const accept:               usize = 202;
    pub const connect:              usize = 203;
    pub const getsockname:          usize = 204;
    pub const getpeername:          usize = 205;
    pub const sendto:               usize = 206;
    pub const recvfrom:             usize = 207;
    pub const setsockopt:           usize = 208;
    pub const getsockopt:           usize = 209;
    pub const shutdown:             usize = 210;
    pub const sendmsg:              usize = 211;
    pub const recvmsg:              usize = 212;
    pub const readahead:            usize = 213;
    pub const brk:                  usize = 214;
    pub const munmap:               usize = 215;
    pub const mremap:               usize = 216;
    pub const add_key:              usize = 217;
    pub const request_key:          usize = 218;
    pub const keyctl:               usize = 219;
    pub const clone:                usize = 220;
    pub const execve:               usize = 221;
    pub const mmap:                 usize = 222;
    pub const fadvise64:            usize = 223;
    pub const swapon:               usize = 224;
    pub const swapoff:              usize = 225;
    pub const mprotect:             usize = 226;
    pub const msync:                usize = 227;
    pub const mlock:                usize = 228;
    pub const munlock:              usize = 229;
    pub const mlockall:             usize = 230;
    pub const munlockall:           usize = 231;
    pub const mincore:              usize = 232;
    pub const madvise:              usize = 233;
    pub const remap_file_pages:     usize = 234;
    pub const mbind:                usize = 235;
    pub const get_mempolicy:        usize = 236;
    pub const set_mempolicy:        usize = 237;
    pub const migrate_pages:        usize = 238;
    pub const move_pages:           usize = 239;
    pub const rt_tgsigqueueinfo:    usize = 240;
    pub const perf_event_open:      usize = 241;
    pub const accept4:              usize = 242;
    pub const recvmmsg:             usize = 243;
    pub const arch_specific_syscall:usize = 244;
    pub const wait4:                usize = 260;
    pub const prlimit64:            usize = 261;
    pub const fanotify_init:        usize = 262;
    pub const fanotify_mark:        usize = 263;
    pub const name_to_handle_at:    usize = 264;
    pub const open_by_handle_at:    usize = 265;
    pub const clock_adjtime:        usize = 266;
    pub const syncfs:               usize = 267;
    pub const setns:                usize = 268;
    pub const sendmmsg:             usize = 269;
    pub const process_vm_readv:     usize = 270;
    pub const process_vm_writev:    usize = 271;
    pub const kcmp:                 usize = 272;
    pub const finit_module:         usize = 273;
    pub const sched_setattr:        usize = 274;
    pub const sched_getattr:        usize = 275;
    pub const renameat2:            usize = 276;
    pub const seccomp:              usize = 277;
    pub const getrandom:            usize = 278;
    pub const memfd_create:         usize = 279;
    pub const bpf:                  usize = 280;
    pub const execveat:             usize = 281;
    pub const userfaultfd:          usize = 282;
    pub const membarrier:           usize = 283;
    pub const mlock2:               usize = 284;
    pub const copy_file_range:      usize = 285;
    pub const preadv2:              usize = 286;
    pub const pwritev2:             usize = 287;
    pub const pkey_mprotect:        usize = 288;
    pub const pkey_alloc:           usize = 289;
    pub const pkey_free:            usize = 290;
    pub const statx:                usize = 291;
    pub const io_pgetevents:        usize = 292;
    pub const rseq:                 usize = 293;
    pub const kexec_file_load:      usize = 294;
    // io_uring (5.1+)
    pub const io_uring_setup:       usize = 425;
    pub const io_uring_enter:       usize = 426;
    pub const io_uring_register:    usize = 427;
    // openat2 / close_range (5.6+)
    pub const openat2:              usize = 437;
    pub const close_range:          usize = 436;
    pub const faccessat2:           usize = 439;
    pub const process_madvise:      usize = 440;
    pub const epoll_pwait2:         usize = 441;
    pub const mount_setattr:        usize = 442;
    pub const landlock_create_ruleset: usize = 444;
    pub const landlock_add_rule:    usize = 445;
    pub const landlock_restrict_self: usize = 446;
    pub const memfd_secret:         usize = 447;
    pub const process_mrelease:     usize = 448;
}

/// The six argument registers passed by the RISC-V Linux ABI (a0 … a5).
///
/// `trap.rs` extracts these from the `TrapFrame` and passes them directly to
/// `crate::syscall::dispatch`; this struct exists so arch-independent code can
/// accept a single opaque type without knowing register names.
#[derive(Copy, Clone, Debug)]
pub struct SyscallArgs {
    pub a0: usize,
    pub a1: usize,
    pub a2: usize,
    pub a3: usize,
    pub a4: usize,
    pub a5: usize,
}

impl SyscallArgs {
    /// Build from the live `TrapFrame` fields that carry syscall arguments.
    #[inline(always)]
    pub fn from_frame(frame: &crate::arch::riscv64::trap::TrapFrame) -> Self {
        Self {
            a0: frame.a0,
            a1: frame.a1,
            a2: frame.a2,
            a3: frame.a3,
            a4: frame.a4,
            a5: frame.a5,
        }
    }

    /// Destructure into the raw tuple expected by `crate::syscall::dispatch`.
    #[inline(always)]
    pub fn into_tuple(self) -> (usize, usize, usize, usize, usize, usize) {
        (self.a0, self.a1, self.a2, self.a3, self.a4, self.a5)
    }
}

// These are *not* used for user→kernel system calls (those arrive as exceptions
// via riscv_trap_entry).  They are used for:
//   • SBI (Supervisor Binary Interface) calls to M-mode firmware
//   • Self-test / debugging shims that need to drop an ecall from S-mode
// The RISC-V SBI calling convention mirrors the Linux syscall ABI:
//   a7 = SBI extension id,  a6 = SBI function id,  a0–a5 = args.
//   a0 = SBI error code (0 = success),  a1 = SBI return value.

/// Raw result returned by every SBI call.
#[derive(Copy, Clone, Debug)]
pub struct SbiRet {
    /// SBI error code — 0 means success; negative values are SBI_ERR_* codes.
    pub error: isize,
    /// Payload returned by the SBI function (meaning depends on extension/fn).
    pub value: usize,
}

impl SbiRet {
    #[inline]
    pub fn is_ok(self) -> bool { self.error == 0 }
}

/// Issue an SBI call with up to six arguments.
///
/// # Safety
/// Caller must ensure `ext`, `fid`, and arguments are valid per the SBI spec.
/// This transitions execution to M-mode firmware; any side-effects are
/// firmware-defined.
#[inline(always)]
pub unsafe fn sbi_call(
    ext: usize,
    fid: usize,
    a0:  usize,
    a1:  usize,
    a2:  usize,
    a3:  usize,
    a4:  usize,
    a5:  usize,
) -> SbiRet {
    let error: isize;
    let value: usize;
    core::arch::asm!(
        "ecall",
        inlateout("a0") a0  => error,
        inlateout("a1") a1  => value,
        in("a2") a2,
        in("a3") a3,
        in("a4") a4,
        in("a5") a5,
        in("a6") fid,
        in("a7") ext,
        options(nostack),
    );
    SbiRet { error, value }
}

/// Convenience wrapper: SBI call with two arguments (most common case).
#[inline(always)]
pub unsafe fn sbi_call2(ext: usize, fid: usize, a0: usize, a1: usize) -> SbiRet {
    sbi_call(ext, fid, a0, a1, 0, 0, 0, 0)
}

/// Convenience wrapper: SBI call with one argument.
#[inline(always)]
pub unsafe fn sbi_call1(ext: usize, fid: usize, a0: usize) -> SbiRet {
    sbi_call(ext, fid, a0, 0, 0, 0, 0, 0)
}

/// Convenience wrapper: SBI call with no arguments (probe / query calls).
#[inline(always)]
pub unsafe fn sbi_call0(ext: usize, fid: usize) -> SbiRet {
    sbi_call(ext, fid, 0, 0, 0, 0, 0, 0)
}

/// SBI extension IDs (Chapter 4 of the SBI spec, v2.0).
pub mod sbi_eid {
    pub const BASE:      usize = 0x10;   // SBI Base Extension
    pub const TIME:      usize = 0x54494D45; // "TIME"
    pub const IPI:       usize = 0x735049;   // "sPI"
    pub const RFNC:      usize = 0x52464E43; // "RFNC" — remote fence
    pub const HSM:       usize = 0x48534D;   // "HSM"  — hart state mgmt
    pub const SRST:      usize = 0x53525354; // "SRST" — system reset
    pub const PMU:       usize = 0x504D55;   // "PMU"
    pub const DBCN:      usize = 0x4442434E; // "DBCN" — debug console
    pub const SUSP:      usize = 0x53555350; // "SUSP" — system suspend
    pub const CPPC:      usize = 0x43505043; // "CPPC"
    pub const NACL:      usize = 0x4E41434C; // "NACL"
    pub const STA:       usize = 0x535441;   // "STA"  — steal-time acct
}

/// SBI function IDs for the Time extension (EID = `sbi_eid::TIME`).
pub mod sbi_fid_time {
    pub const SET_TIMER: usize = 0;
}

/// SBI function IDs for the IPI extension (EID = `sbi_eid::IPI`).
pub mod sbi_fid_ipi {
    pub const SEND_IPI: usize = 0;
}

/// SBI function IDs for the Remote Fence extension (EID = `sbi_eid::RFNC`).
pub mod sbi_fid_rfnc {
    pub const REMOTE_FENCE_I:       usize = 0;
    pub const REMOTE_SFENCE_VMA:    usize = 1;
    pub const REMOTE_SFENCE_VMA_ASID: usize = 2;
}

/// SBI function IDs for the Hart State Management extension (EID = `sbi_eid::HSM`).
pub mod sbi_fid_hsm {
    pub const HART_START:       usize = 0;
    pub const HART_STOP:        usize = 1;
    pub const HART_GET_STATUS:  usize = 2;
    pub const HART_SUSPEND:     usize = 3;
}

/// SBI function IDs for the System Reset extension (EID = `sbi_eid::SRST`).
pub mod sbi_fid_srst {
    pub const SYSTEM_RESET: usize = 0;
    // reset_type values
    pub const SHUTDOWN:     u32 = 0x0000_0000;
    pub const COLD_REBOOT:  u32 = 0x0000_0001;
    pub const WARM_REBOOT:  u32 = 0x0000_0002;
    // reason values
    pub const NO_REASON:    u32 = 0x0000_0000;
    pub const SYSFAIL:      u32 = 0x0000_0001;
}

/// SBI function IDs for the Debug Console extension (EID = `sbi_eid::DBCN`).
pub mod sbi_fid_dbcn {
    pub const CONSOLE_WRITE:      usize = 0;
    pub const CONSOLE_READ:       usize = 1;
    pub const CONSOLE_WRITE_BYTE: usize = 2;
}

/// Program the RISC-V timer via SBI TIME extension.
///
/// `stime_value` is an absolute value in the `time` CSR domain (typically
/// nanoseconds from firmware perspective, though the unit is platform-defined).
#[inline]
pub fn sbi_set_timer(stime_value: u64) -> SbiRet {
    unsafe { sbi_call1(sbi_eid::TIME, sbi_fid_time::SET_TIMER, stime_value as usize) }
}

/// Send an inter-processor interrupt to the harts specified by `hart_mask`.
///
/// `hart_mask_base` is the lowest hart ID represented by bit 0 of `hart_mask`.
#[inline]
pub fn sbi_send_ipi(hart_mask: usize, hart_mask_base: usize) -> SbiRet {
    unsafe { sbi_call2(sbi_eid::IPI, sbi_fid_ipi::SEND_IPI, hart_mask, hart_mask_base) }
}

/// Issue a remote `fence.i` to the harts in `hart_mask`.
#[inline]
pub fn sbi_remote_fence_i(hart_mask: usize, hart_mask_base: usize) -> SbiRet {
    unsafe {
        sbi_call2(sbi_eid::RFNC, sbi_fid_rfnc::REMOTE_FENCE_I, hart_mask, hart_mask_base)
    }
}

/// Issue a remote `sfence.vma` for address range `[start, start+size)`.
#[inline]
pub fn sbi_remote_sfence_vma(
    hart_mask:      usize,
    hart_mask_base: usize,
    start:          usize,
    size:           usize,
) -> SbiRet {
    unsafe {
        sbi_call(
            sbi_eid::RFNC, sbi_fid_rfnc::REMOTE_SFENCE_VMA,
            hart_mask, hart_mask_base, start, size, 0, 0,
        )
    }
}

/// Start a secondary hart via SBI HSM.
///
/// The hart begins execution at `start_addr` in M-mode with `opaque` in `a1`.
#[inline]
pub fn sbi_hart_start(hart_id: usize, start_addr: usize, opaque: usize) -> SbiRet {
    unsafe {
        sbi_call(
            sbi_eid::HSM, sbi_fid_hsm::HART_START,
            hart_id, start_addr, opaque, 0, 0, 0,
        )
    }
}

/// Halt the calling hart (does not return on success).
#[inline]
pub fn sbi_hart_stop() -> SbiRet {
    unsafe { sbi_call0(sbi_eid::HSM, sbi_fid_hsm::HART_STOP) }
}

/// Trigger a system-wide reset (shutdown / reboot).
///
/// `reset_type` and `reset_reason` use the `sbi_fid_srst::*` constants.
#[inline]
pub fn sbi_system_reset(reset_type: u32, reset_reason: u32) -> SbiRet {
    unsafe {
        sbi_call2(
            sbi_eid::SRST, sbi_fid_srst::SYSTEM_RESET,
            reset_type as usize, reset_reason as usize,
        )
    }
}

/// Write a single byte to the SBI debug console (DBCN extension).
///
/// Falls back gracefully if the firmware does not support DBCN.
#[inline]
pub fn sbi_console_write_byte(byte: u8) -> SbiRet {
    unsafe { sbi_call1(sbi_eid::DBCN, sbi_fid_dbcn::CONSOLE_WRITE_BYTE, byte as usize) }
}

/// Convert a POSIX `errno` value into the negative `usize` return that the
/// RISC-V Linux ABI places in `a0`.
///
/// The kernel returns `-errno` cast to `usize` (i.e. a large unsigned value).
/// User-space libc checks `(isize)a0 < 0` and negates to recover `errno`.
#[inline(always)]
pub const fn errno_to_ret(errno: i32) -> usize {
    (-(errno as isize)) as usize
}

/// Check whether a raw `a0` return value represents an error.
#[inline(always)]
pub const fn is_error_ret(ret: usize) -> bool {
    (ret as isize) < 0 && (ret as isize) >= -4096
}
