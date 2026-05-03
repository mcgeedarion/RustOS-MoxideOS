
// ── epoll ─────────────────────────────────────────────────────────────────

// ── pipe2 / eventfd2 ──────────────────────────────────────────────────────

// ── fcntl / dup3 / robust_list / amdgpu_cs ───────────────────────────────
pub const SYS_FCNTL:           usize = 72;
pub const SYS_DUP3:            usize = 292;
pub const SYS_SET_ROBUST_LIST: usize = 273;
pub const SYS_GET_ROBUST_LIST: usize = 274;
pub const SYS_PIPE2:           usize = 293;
pub const SYS_ACCEPT4:         usize = 288;
pub const SYS_LISTEN:          usize = 50;
pub const SYS_SHUTDOWN:        usize = 48;
pub const SYS_SOCKETPAIR:      usize = 53;

// ── Syscall numbers (Linux/x86_64 ABI) ───────────────────────────────────
pub const SYS_READ:       usize = 0;
pub const SYS_WRITE:      usize = 1;
pub const SYS_OPEN:       usize = 2;
pub const SYS_CLOSE:      usize = 3;
pub const SYS_STAT:       usize = 4;
pub const SYS_FSTAT:      usize = 5;
pub const SYS_LSTAT:      usize = 6;
pub const SYS_MMAP:       usize = 9;
pub const SYS_MPROTECT:   usize = 10;
pub const SYS_MUNMAP:     usize = 11;
pub const SYS_BRK:        usize = 12;
pub const SYS_IOCTL:      usize = 16;
pub const SYS_PREAD64:    usize = 17;
pub const SYS_PWRITE64:   usize = 18;
pub const SYS_READV:      usize = 19;
pub const SYS_WRITEV:     usize = 20;
pub const SYS_ACCESS:     usize = 21;
pub const SYS_PIPE:       usize = 22;
pub const SYS_SELECT:     usize = 23;
pub const SYS_SCHED_YIELD:usize = 24;
pub const SYS_MREMAP:     usize = 25;
pub const SYS_MSYNC:      usize = 26;
pub const SYS_MADVISE:    usize = 28;
pub const SYS_DUP:        usize = 32;
pub const SYS_DUP2:       usize = 33;
pub const SYS_NANOSLEEP:  usize = 35;
pub const SYS_GETPID:     usize = 39;
pub const SYS_SOCKET:     usize = 41;
pub const SYS_CONNECT:    usize = 42;
pub const SYS_ACCEPT:     usize = 43;
pub const SYS_SENDTO:     usize = 44;
pub const SYS_RECVFROM:   usize = 45;
pub const SYS_BIND:       usize = 49;
pub const SYS_GETSOCKNAME:usize = 51;
pub const SYS_GETPEERNAME:usize = 52;
pub const SYS_SETSOCKOPT: usize = 54;
pub const SYS_GETSOCKOPT: usize = 55;
pub const SYS_CLONE:      usize = 56;
pub const SYS_FORK:       usize = 57;
pub const SYS_EXECVE:     usize = 59;
pub const SYS_EXIT:       usize = 60;
pub const SYS_WAIT4:      usize = 61;
pub const SYS_KILL:       usize = 62;
pub const SYS_UNAME:      usize = 63;
pub const SYS_LSEEK:      usize = 8;
pub const SYS_POLL:       usize = 7;
pub const SYS_OPENAT:     usize = 257;
pub const SYS_NEWFSTATAT: usize = 262;
pub const SYS_READLINK:   usize = 89;
pub const SYS_READLINKAT: usize = 267;
pub const SYS_GETDENTS64: usize = 217;
pub const SYS_GETCWD:     usize = 79;
pub const SYS_CHDIR:      usize = 80;
pub const SYS_RENAME:     usize = 82;
pub const SYS_MKDIR:      usize = 83;
pub const SYS_RMDIR:      usize = 84;
pub const SYS_CREAT:      usize = 85;
pub const SYS_LINK:       usize = 86;
pub const SYS_UNLINK:     usize = 87;
pub const SYS_SYMLINK:    usize = 88;
pub const SYS_CHMOD:      usize = 90;
pub const SYS_FCHMOD:     usize = 91;
pub const SYS_CHOWN:      usize = 92;
pub const SYS_LCHOWN:     usize = 94;
pub const SYS_FCHOWN:     usize = 93;
pub const SYS_UMASK:      usize = 95;
pub const SYS_GETTIMEOFDAY: usize = 96;
pub const SYS_GETRLIMIT:  usize = 97;
pub const SYS_GETRUSAGE:  usize = 98;
pub const SYS_SYSINFO:    usize = 99;
pub const SYS_TIMES:      usize = 100;
pub const SYS_PTRACE:     usize = 101;
pub const SYS_GETUID:     usize = 102;
pub const SYS_SYSLOG:     usize = 103;
pub const SYS_GETGID:     usize = 104;
pub const SYS_SETUID:     usize = 105;
pub const SYS_SETGID:     usize = 106;
pub const SYS_GETEUID:    usize = 107;
pub const SYS_GETEGID:    usize = 108;
pub const SYS_SETPGID:    usize = 109;
pub const SYS_GETPPID:    usize = 110;
pub const SYS_GETPGRP:    usize = 111;
pub const SYS_SETSID:     usize = 112;
pub const SYS_GETPGID:    usize = 121;
pub const SYS_GETSID:     usize = 124;
pub const SYS_CAPGET:     usize = 125;
pub const SYS_CAPSET:     usize = 126;
pub const SYS_SIGALTSTACK:usize = 131;
pub const SYS_RT_SIGACTION:    usize = 13;
pub const SYS_RT_SIGPROCMASK:  usize = 14;
pub const SYS_RT_SIGRETURN:    usize = 15;
pub const SYS_RT_SIGPENDING:   usize = 127;
pub const SYS_RT_SIGSUSPEND:   usize = 130;
pub const SYS_SIGACTION:  usize = 13;
pub const SYS_SIGNAL:     usize = 13;
pub const SYS_PAUSE:      usize = 34;
pub const SYS_ALARM:      usize = 37;
pub const SYS_SETITIMER:  usize = 38;
pub const SYS_GETITIMER:  usize = 36;
pub const SYS_SENDFILE:   usize = 40;
pub const SYS_EPOLL_CREATE: usize = 213;
pub const SYS_EPOLL_CREATE1: usize = 291;
pub const SYS_EPOLL_CTL:  usize = 233;
pub const SYS_EPOLL_WAIT: usize = 232;
pub const SYS_EPOLL_PWAIT:usize = 281;
pub const SYS_INOTIFY_INIT:  usize = 253;
pub const SYS_INOTIFY_INIT1: usize = 294;
pub const SYS_INOTIFY_ADD_WATCH:  usize = 254;
pub const SYS_INOTIFY_RM_WATCH:   usize = 255;
pub const SYS_TIMERFD_CREATE:  usize = 283;
pub const SYS_TIMERFD_SETTIME: usize = 286;
pub const SYS_TIMERFD_GETTIME: usize = 287;
pub const SYS_SIGNALFD:   usize = 282;
pub const SYS_SIGNALFD4:  usize = 289;
pub const SYS_EVENTFD:    usize = 284;
pub const SYS_EVENTFD2:   usize = 290;
pub const SYS_FUTEX:      usize = 202;
pub const SYS_PRCTL:      usize = 157;
pub const SYS_ARCH_PRCTL: usize = 158;
pub const SYS_SETRLIMIT:  usize = 160;
pub const SYS_GETPRIORITY:usize = 140;
pub const SYS_SETPRIORITY:usize = 141;
pub const SYS_SCHED_SETPARAM:   usize = 142;
pub const SYS_SCHED_GETPARAM:   usize = 143;
pub const SYS_SCHED_SETSCHEDULER: usize = 144;
pub const SYS_SCHED_GETSCHEDULER: usize = 145;
pub const SYS_SCHED_GETAFFINITY:  usize = 204;
pub const SYS_SCHED_SETAFFINITY:  usize = 203;
pub const SYS_GETGROUPS:  usize = 115;
pub const SYS_SETGROUPS:  usize = 116;
pub const SYS_ACCT:       usize = 163;
pub const SYS_MOUNT:      usize = 165;
pub const SYS_UMOUNT2:    usize = 166;
pub const SYS_PIVOT_ROOT: usize = 155;
pub const SYS_CHROOT:     usize = 161;
pub const SYS_SYNC:       usize = 162;
pub const SYS_FSYNC:      usize = 74;
pub const SYS_FDATASYNC:  usize = 75;
pub const SYS_TRUNCATE:   usize = 76;
pub const SYS_FTRUNCATE:  usize = 77;
pub const SYS_STATFS:     usize = 137;
pub const SYS_FSTATFS:    usize = 138;
pub const SYS_GETXATTR:   usize = 191;
pub const SYS_LGETXATTR:  usize = 192;
pub const SYS_FGETXATTR:  usize = 193;
pub const SYS_SETXATTR:   usize = 188;
pub const SYS_LSETXATTR:  usize = 189;
pub const SYS_FSETXATTR:  usize = 190;
pub const SYS_LISTXATTR:  usize = 194;
pub const SYS_REMOVEXATTR:usize = 197;
pub const SYS_MLOCK:      usize = 149;
pub const SYS_MUNLOCK:    usize = 150;
pub const SYS_MLOCKALL:   usize = 151;
pub const SYS_MUNLOCKALL: usize = 152;
pub const SYS_MLOCK2:     usize = 325;
pub const SYS_MINCORE:    usize = 27;
pub const SYS_REMAP_FILE_PAGES: usize = 216;
pub const SYS_MBIND:      usize = 237;
pub const SYS_MIGRATE_PAGES: usize = 256;
pub const SYS_MOVE_PAGES: usize = 279;
pub const SYS_MEMBARRIER: usize = 324;
pub const SYS_USERFAULTFD: usize = 323;
pub const SYS_MEMFD_CREATE: usize = 319;
pub const SYS_COPY_FILE_RANGE: usize = 326;
pub const SYS_GETRANDOM:  usize = 318;
pub const SYS_SECCOMP:    usize = 317;
pub const SYS_PERF_EVENT_OPEN: usize = 298;
pub const SYS_FANOTIFY_INIT:   usize = 300;
pub const SYS_PRLIMIT64:  usize = 302;
pub const SYS_SYNCFS:     usize = 306;
pub const SYS_SENDMMSG:   usize = 307;
pub const SYS_RECVMMSG:   usize = 299;
pub const SYS_GETCPU:     usize = 309;
pub const SYS_WAITPID:    usize = 260;
pub const SYS_YIELD:      usize = 158;
pub const SYS_CLOCK_GETTIME:  usize = 228;
pub const SYS_CLOCK_SETTIME:  usize = 227;
pub const SYS_CLOCK_GETRES:   usize = 229;
pub const SYS_CLOCK_NANOSLEEP:usize = 230;
pub const SYS_TIMER_CREATE:   usize = 222;
pub const SYS_TIMER_SETTIME:  usize = 223;
pub const SYS_TIMER_GETTIME:  usize = 224;
pub const SYS_TIMER_DELETE:   usize = 226;
pub const SYS_UTIMENSAT:      usize = 280;
pub const SYS_UTIMES:         usize = 235;
pub const SYS_UTIME:          usize = 132;
pub const SYS_FLOCK:          usize = 73;
pub const SYS_SENDMSG:        usize = 46;
pub const SYS_RECVMSG:        usize = 47;
pub const SYS_GETTID:         usize = 186;
pub const SYS_TKILL:          usize = 200;
pub const SYS_TGKILL:         usize = 234;
pub const SYS_SET_TID_ADDRESS:usize = 218;
pub const SYS_GET_TID_ADDRESS:usize = 219;
pub const SYS_RESTART_SYSCALL:usize = 219;
pub const SYS_EXIT_GROUP:     usize = 231;
pub const SYS_WAITID:         usize = 247;
pub const SYS_IOPRIO_SET:     usize = 251;
pub const SYS_IOPRIO_GET:     usize = 252;
pub const SYS_UNLINKAT:       usize = 263;
pub const SYS_RENAMEAT:       usize = 264;
pub const SYS_LINKAT:         usize = 265;
pub const SYS_SYMLINKAT:      usize = 266;
pub const SYS_MKDIRAT:        usize = 258;
pub const SYS_FCHOWNAT:       usize = 260;
pub const SYS_FUTIMESAT:      usize = 261;
pub const SYS_FCHMODAT:       usize = 268;
pub const SYS_FACCESSAT:      usize = 269;
pub const SYS_FACCESSAT2:     usize = 439;
pub const SYS_OPENAT2:        usize = 437;
pub const SYS_PROCESS_VM_READV:  usize = 310;
pub const SYS_PROCESS_VM_WRITEV: usize = 311;
pub const SYS_SPLICE:         usize = 275;
pub const SYS_TEE:            usize = 276;
pub const SYS_VMSPLICE:       usize = 278;
pub const SYS_FALLOCATE:      usize = 285;
pub const SYS_POSIX_FADVISE:  usize = 221;
pub const SYS_READAHEAD:      usize = 187;
pub const SYS_NAME_TO_HANDLE_AT: usize = 303;
pub const SYS_OPEN_BY_HANDLE_AT: usize = 304;
pub const SYS_SETNS:          usize = 308;
pub const SYS_UNSHARE:        usize = 272;
pub const SYS_KCMP:           usize = 312;
pub const SYS_FINIT_MODULE:   usize = 313;
pub const SYS_SCHED_GETATTR:  usize = 315;
pub const SYS_SCHED_SETATTR:  usize = 314;
pub const SYS_REBOOT:         usize = 169;
pub const SYS_KEXEC_LOAD:     usize = 246;
pub const SYS_KEXEC_FILE_LOAD:usize = 320;
pub const SYS_BPFI:           usize = 321;
pub const SYS_EXECVEAT:       usize = 322;
pub const SYS_PKEY_ALLOC:     usize = 330;
pub const SYS_PKEY_FREE:      usize = 331;
pub const SYS_PKEY_MPROTECT:  usize = 329;

extern crate alloc;
use alloc::vec::Vec;
use crate::uaccess::{copy_from_user, copy_to_user, strncpy_from_user};

// ── read_cstr_safe ────────────────────────────────────────────────────────
// Security fix: validate full range via strncpy_from_user (USER_END check)
// before touching any byte — eliminates raw *ptr TOCTOU/OOB vulnerability.
fn read_cstr_safe(va: usize) -> alloc::string::String {
    if va == 0 { return alloc::string::String::new(); }
    let mut buf = [0u8; 4096];
    match unsafe { crate::uaccess::strncpy_from_user(&mut buf, va as *const u8, 4096) } {
        Ok(n)  => core::str::from_utf8(&buf[..n]).unwrap_or("").into(),
        Err(_) => alloc::string::String::new(),
    }
}

// ── Shared dispatcher ─────────────────────────────────────────────────────

fn dispatch(nr: usize, a0: usize, a1: usize, a2: usize, a3: usize, a4: usize) -> isize {
    match nr {
        SYS_READ     => sys_read(a0, a1, a2),
        SYS_WRITE    => sys_write(a0, a1, a2),
        SYS_OPEN     => sys_open(a0, a1 as u32, a2 as u32),
        SYS_CLOSE    => sys_close(a0),
        SYS_STAT     => sys_stat_impl(a0, a1),
        SYS_FSTAT    => sys_fstat(a0, a1),
        SYS_LSTAT    => sys_lstat_impl(a0, a1),
        SYS_LSEEK    => sys_lseek(a0, a1 as i64, a2 as i32),
        SYS_MMAP     => sys_mmap(a0, a1, a2 as i32, a3 as i32, a4 as i32, 0),
        SYS_MPROTECT => sys_mprotect(a0, a1, a2 as u32),
        SYS_MUNMAP   => sys_munmap(a0, a1),
        SYS_BRK      => sys_brk(a0),
        SYS_RT_SIGACTION   => sys_rt_sigaction(a0, a1, a2),
        SYS_RT_SIGPROCMASK => sys_rt_sigprocmask(a0 as i32, a1, a2),
        SYS_RT_SIGRETURN   => 0,
        SYS_IOCTL    => sys_ioctl(a0, a1 as u64, a2),
        SYS_PREAD64  => sys_pread(a0, a1, a2, a3 as i64),
        SYS_PWRITE64 => sys_pwrite(a0, a1, a2, a3 as i64),
        SYS_READV    => sys_readv(a0, a1, a2),
        SYS_WRITEV   => sys_writev(a0, a1, a2),
        SYS_ACCESS   => sys_access(a0, a1 as u32),
        SYS_PIPE     => sys_pipe(a0),
        SYS_PIPE2    => sys_pipe2(a0, a1 as i32),
        SYS_SELECT   => sys_select(a0, a1, a2, a3, a4),
        SYS_SCHED_YIELD => { crate::proc::scheduler::yield_cpu(); 0 }
        SYS_MREMAP   => sys_mremap(a0, a1, a2, a3, a4),
        SYS_MSYNC    => sys_msync(a0, a1, a2 as i32),
        SYS_MADVISE  => sys_madvise(a0, a1, a2 as i32),
        SYS_DUP      => crate::fs::fcntl::sys_dup(a0),
        SYS_DUP2     => crate::fs::fcntl::sys_dup2(a0, a1),
        SYS_DUP3     => crate::fs::fcntl::sys_dup3(a0, a1, a2 as i32),
        SYS_NANOSLEEP => sys_nanosleep(a0, a1),
        SYS_GETPID   => crate::proc::scheduler::current_pid() as isize,
        SYS_GETTID   => crate::proc::scheduler::current_pid() as isize,
        SYS_SOCKET   => sys_socket(a0, a1, a2),
        SYS_BIND     => sys_bind(a0, a1),
        SYS_LISTEN   => sys_listen_impl(a0, a1 as i32),
        SYS_CONNECT  => sys_connect(a0, a1, a2 as u16),
        SYS_ACCEPT   => sys_accept(a0),
        SYS_ACCEPT4  => sys_accept4(a0, a1, a2, a3 as i32),
        SYS_SENDTO   => sys_sendto(a0, a1, a2, a3),
        SYS_RECVFROM => sys_recvfrom(a0, a1, a2, a3),
        SYS_SENDMSG  => sys_sendmsg(a0, a1, a2),
        SYS_RECVMSG  => sys_recvmsg(a0, a1, a2),
        SYS_SHUTDOWN => sys_shutdown_impl(a0, a1 as i32),
        SYS_SOCKETPAIR => sys_socketpair_impl(a0, a1, a2, a3),
        SYS_SETSOCKOPT => crate::net::sockopt::sys_setsockopt(a0, a1 as i32, a2 as i32, a3, a4 as u32),
        SYS_GETSOCKOPT => crate::net::sockopt::sys_getsockopt(a0, a1 as i32, a2 as i32, a3, a4),
        SYS_GETSOCKNAME => sys_getsockname(a0, a1, a2),
        SYS_GETPEERNAME => sys_getpeername(a0, a1, a2),
        SYS_CLONE    => sys_clone(a0, a1, a2, a3, a4),
        SYS_EXECVE   => sys_execve_stub(a0, a1, a2),
        SYS_EXIT | SYS_EXIT_GROUP => sys_exit(a0 as i32),
        SYS_WAIT4    => sys_wait4(a0 as i32, a1, a2 as i32),
        SYS_KILL     => sys_kill(a0 as i32, a1 as i32),
        SYS_UNAME    => sys_uname(a0),
        SYS_FCNTL    => sys_fcntl(a0, a1 as i32, a2),
        SYS_FLOCK    => 0, // advisory lock stub
        SYS_FSYNC | SYS_FDATASYNC => sys_fsync(a0),
        SYS_TRUNCATE => sys_truncate(a0, a1 as i64),
        SYS_FTRUNCATE => sys_ftruncate(a0, a1 as i64),
        SYS_GETDENTS64 => sys_getdents64(a0, a1, a2),
        SYS_GETCWD   => sys_getcwd(a0, a1),
        SYS_CHDIR    => sys_chdir(a0),
        SYS_RENAME   => sys_rename(a0, a1),
        SYS_MKDIR    => sys_mkdir(a0, a1 as u32),
        SYS_RMDIR    => sys_rmdir(a0),
        SYS_UNLINK   => sys_unlink(a0),
        SYS_UNLINKAT => sys_unlinkat(a0 as i32, a1, a2 as u32),
        SYS_SYMLINK  => sys_symlink(a0, a1),
        SYS_READLINK => sys_readlink(a0, a1, a2),
        SYS_READLINKAT => sys_readlinkat(a0 as i32, a1, a2, a3),
        SYS_OPENAT   => sys_openat(a0 as i32, a1, a2 as i32, a3 as u32),
        SYS_NEWFSTATAT => sys_newfstatat(a0 as i32, a1, a2, a3 as i32),
        SYS_MKDIRAT  => sys_mkdirat(a0 as i32, a1, a2 as u32),
        SYS_CHMOD    => sys_chmod_impl(a0, a1 as u32),
        SYS_FCHMOD   => sys_fchmod_impl(a0, a1 as u32),
        SYS_FCHMODAT => sys_fchmod_impl(a1, a2 as u32),
        SYS_CHOWN    => sys_chown_impl(a0, a1 as u32, a2 as u32),
        SYS_LCHOWN   => sys_lchown_impl(a0, a1 as u32, a2 as u32),
        SYS_FCHOWN   => sys_fchown_impl(a0, a1 as u32, a2 as u32),
        SYS_UTIMENSAT => sys_utimensat_impl(a0 as i32, a1, a2, a3 as i32),
        SYS_MLOCK    => sys_mlock_impl(a0, a1),
        SYS_MUNLOCK  => sys_munlock_impl(a0, a1),
        SYS_MLOCKALL | SYS_MUNLOCKALL => 0,
        SYS_PTRACE   => sys_ptrace_impl(a0 as i32, a1 as i32, a2, a3),
        SYS_MOUNT    => sys_mount_impl(a0, a1, a2, a3 as u64, a4),
        SYS_UMOUNT2  => 0,
        SYS_SYSLOG   => sys_syslog_impl(a0 as i32, a1, a2 as i32),
        SYS_PROCESS_VM_READV | SYS_PROCESS_VM_WRITEV => -1isize,
        SYS_OPENAT2  => sys_openat2_impl(a0 as i32, a1, a2, a3),
        SYS_CLOCK_NANOSLEEP => sys_clock_nanosleep(a0 as i32, a1 as i32, a2, a3),
        SYS_CLOCK_GETTIME  => sys_clock_gettime(a0 as u32, a1),
        SYS_CLOCK_GETRES   => sys_clock_getres(a0 as u32, a1),
        SYS_GETTIMEOFDAY   => sys_gettimeofday(a0, a1),
        SYS_FUTEX    => sys_futex(a0, a1 as i32, a2 as u32, a3, a4),
        SYS_PRCTL    => sys_prctl(a0 as i32, a1, a2, a3, a4),
        SYS_ARCH_PRCTL => sys_arch_prctl(a0 as i32, a1),
        SYS_SET_TID_ADDRESS => sys_set_tid_address(a0),
        SYS_EPOLL_CREATE | SYS_EPOLL_CREATE1 => sys_epoll_create(a0 as u32),
        SYS_EPOLL_CTL  => sys_epoll_ctl(a0, a1 as i32, a2, a3),
        SYS_EPOLL_WAIT | SYS_EPOLL_PWAIT => sys_epoll_wait(a0, a1, a2 as i32, a3 as i32),
        SYS_INOTIFY_INIT | SYS_INOTIFY_INIT1 => sys_inotify_init(a0 as u32),
        SYS_INOTIFY_ADD_WATCH => sys_inotify_add_watch(a0, a1, a2 as u32),
        SYS_INOTIFY_RM_WATCH  => sys_inotify_rm_watch(a0, a1 as i32),
        SYS_TIMERFD_CREATE  => sys_timerfd_create(a0 as i32, a1 as i32),
        SYS_TIMERFD_SETTIME => sys_timerfd_settime(a0, a1 as i32, a2, a3),
        SYS_TIMERFD_GETTIME => sys_timerfd_gettime(a0, a1),
        SYS_SIGNALFD | SYS_SIGNALFD4 => sys_signalfd(a0, a1, a2 as u32),
        SYS_EVENTFD  => sys_eventfd(a0 as u32, 0),
        SYS_EVENTFD2 => sys_eventfd(a0 as u32, a1 as u32),
        SYS_STATFS   => sys_statfs(a0, a1),
        SYS_FSTATFS  => sys_fstatfs(a0, a1),
        SYS_GETUID | SYS_GETEUID => 0,
        SYS_GETGID | SYS_GETEGID => 0,
        SYS_SETUID | SYS_SETGID  => 0,
        SYS_GETGROUPS | SYS_SETGROUPS => 0,
        SYS_GETPPID  => 0,
        SYS_GETPGRP | SYS_GETPGID => crate::proc::scheduler::current_pid() as isize,
        SYS_SETPGID | SYS_SETSID  => 0,
        SYS_GETSID   => crate::proc::scheduler::current_pid() as isize,
        SYS_CAPGET | SYS_CAPSET => 0,
        SYS_GETRLIMIT | SYS_SETRLIMIT => sys_getrlimit(a0, a1),
        SYS_PRLIMIT64 => sys_prlimit(a0 as i32, a1, a2, a3),
        SYS_GETRUSAGE  => sys_getrusage(a0 as i32, a1),
        SYS_SYSINFO    => sys_sysinfo(a0),
        SYS_UTIME | SYS_UTIMES | SYS_FUTIMESAT => 0,
        SYS_UMASK      => 0o022,
        SYS_SYNC | SYS_SYNCFS => 0,
        SYS_GETRANDOM  => sys_getrandom(a0, a1, a2 as u32),
        SYS_MEMFD_CREATE => sys_memfd_create(a0, a1 as u32),
        SYS_FTRUNCATE   => sys_ftruncate(a0, a1 as i64),
        SYS_USERFAULTFD => sys_userfaultfd(a0 as u32),
        SYS_GETXATTR | SYS_LGETXATTR | SYS_FGETXATTR => -61, // ENODATA
        SYS_SETXATTR | SYS_LSETXATTR | SYS_FSETXATTR => 0,
        SYS_LISTXATTR  => 0,
        SYS_REMOVEXATTR => 0,
        SYS_TKILL | SYS_TGKILL => sys_kill(a1 as i32, a2 as i32),
        SYS_ALARM      => 0,
        SYS_PAUSE      => -4, // EINTR
        SYS_MINCORE    => sys_mincore(a0, a1, a2),
        SYS_SENDFILE   => sys_sendfile(a0, a1, a2, a3),
        SYS_SPLICE     => sys_splice(a0, a1, a2, a3, a4),
        SYS_FALLOCATE  => sys_fallocate(a0, a1 as i32, a2 as i64, a3 as i64),
        SYS_PKEY_ALLOC | SYS_PKEY_FREE | SYS_PKEY_MPROTECT => 0,
        SYS_REBOOT     => sys_reboot(a0 as u32, a1 as u32, a2 as u32, a3),
        SYS_MEMBARRIER => 0,
        SYS_GETCPU     => sys_getcpu(a0, a1, a2),
        SYS_COPY_FILE_RANGE => sys_copy_file_range(a0, a1, a2, a3, a4),
        SYS_IOPRIO_SET | SYS_IOPRIO_GET => 0,
        SYS_SETNS | SYS_UNSHARE => 0,
        SYS_SECCOMP    => 0,
        SYS_PERF_EVENT_OPEN => -1isize,
        SYS_FANOTIFY_INIT   => -1isize,
        SYS_BPFI       => -1isize,
        SYS_POSIX_FADVISE | SYS_READAHEAD => 0,
        SYS_SCHED_GETAFFINITY | SYS_SCHED_SETAFFINITY => 0,
        SYS_SCHED_GETPARAM | SYS_SCHED_SETPARAM => 0,
        SYS_SCHED_GETSCHEDULER | SYS_SCHED_SETSCHEDULER => 0,
        SYS_SCHED_GETATTR | SYS_SCHED_SETATTR => 0,
        SYS_GETPRIORITY | SYS_SETPRIORITY => 0,
        SYS_ACCT       => 0,
        SYS_PIVOT_ROOT | SYS_CHROOT => 0,
        SYS_SET_ROBUST_LIST | SYS_GET_ROBUST_LIST => 0,
        SYS_WAITID     => sys_waitid(a0, a1 as i32, a2, a3 as i32),
        SYS_FACCESSAT | SYS_FACCESSAT2 => sys_faccessat(a0 as i32, a1, a2 as u32),
        SYS_FCHOWNAT   => sys_fchown_impl(a0, a2 as u32, a3 as u32),
        SYS_RENAMEAT   => sys_renameat(a0 as i32, a1, a2 as i32, a3),
        SYS_LINKAT     => sys_linkat(a0 as i32, a1, a2 as i32, a3, a4 as u32),
        SYS_SYMLINKAT  => sys_symlinkat(a0, a1 as i32, a2),
        SYS_SET_TID_ADDRESS => sys_set_tid_address(a0),
        SYS_RESTART_SYSCALL => 0,
        SYS_RT_SIGPENDING  => 0,
        SYS_RT_SIGSUSPEND  => -4, // EINTR
        SYS_SIGALTSTACK    => 0,
        SYS_SETITIMER | SYS_GETITIMER => 0,
        SYS_TIMES      => sys_times(a0),
        SYS_KEXEC_LOAD | SYS_KEXEC_FILE_LOAD => -1isize,
        SYS_KCMP       => -1isize,
        SYS_FINIT_MODULE => -1isize,
        SYS_EXECVEAT   => sys_execveat(a0 as i32, a1, a2, a3, a4 as i32),
        _ => {
            crate::serial_println!("[syscall] unhandled nr={} a0={:#x}", nr, a0);
            -38 // ENOSYS
        }
    }
}

// ── x86_64 entry point ────────────────────────────────────────────────────

#[no_mangle]
pub unsafe extern "C" fn handle_x86(frame: *mut SyscallFrame) -> isize {
    let f = &mut *frame;
    let nr  = f.rax as usize;
    let a0  = f.rdi as usize;
    let a1  = f.rsi as usize;
    let a2  = f.rdx as usize;
    let a3  = f.r10 as usize;
    let a4  = f.r8  as usize;
    match nr {
        SYS_FORK   => return crate::proc::fork::do_fork(frame),
        SYS_EXECVE => return crate::proc::fork::do_execve(a0, a1, a2, frame),
        _ => {}
    }
    dispatch(nr, a0, a1, a2, a3, a4)
}

#[repr(C)]
pub struct SyscallFrame {
    pub rax: u64, pub rdi: u64, pub rsi: u64, pub rdx: u64,
    pub r10: u64, pub r8:  u64, pub r9:  u64, pub rcx: u64,
    pub r11: u64, pub rip: u64, pub rsp: u64, pub rbp: u64,
    pub rbx: u64, pub r12: u64, pub r13: u64, pub r14: u64, pub r15: u64,
}

// ── sys_read / sys_write ──────────────────────────────────────────────────

fn sys_read(fd: usize, buf_va: usize, count: usize) -> isize {
    if buf_va == 0 { return -14; }
    let mut tmp = alloc::vec![0u8; count.min(65536)];
    let n = crate::fs::vfs::read(fd, &mut tmp);
    if n <= 0 { return n; }
    match copy_to_user(buf_va, &tmp[..n as usize]) {
        Ok(_)  => n,
        Err(()) => -14,
    }
}

fn sys_write(fd: usize, buf_va: usize, count: usize) -> isize {
    if buf_va == 0 { return -14; }
    let n = count.min(65536);
    let mut tmp = alloc::vec![0u8; n];
    match copy_from_user(&mut tmp, buf_va) {
        Ok(_)  => {}
        Err(()) => return -14,
    }
    crate::fs::vfs::write(fd, &tmp[..n]) as isize
}

// ── sys_open / sys_openat ─────────────────────────────────────────────────

fn sys_open(path_va: usize, flags: u32, _mode: u32) -> isize {
    let path = read_cstr_safe(path_va);
    match crate::fs::vfs::open(&path, flags) {
        Ok(fd) => fd as isize,
        Err(e) => e as isize,
    }
}

fn sys_openat(dirfd: i32, path_va: usize, flags: i32, mode: u32) -> isize {
    let path = read_cstr_safe(path_va);
    // Resolve relative paths against dirfd (AT_FDCWD = -100 = use cwd)
    let resolved = if path.starts_with('/') || dirfd == -100 {
        path
    } else {
        alloc::format!("/proc/self/fd/{}/{}", dirfd, path)
    };
    match crate::fs::vfs::open(&resolved, flags as u32) {
        Ok(fd) => fd as isize,
        Err(e) => e as isize,
    }
}

// ── sys_close ─────────────────────────────────────────────────────────────

fn sys_close(fd: usize) -> isize {
    crate::fs::vfs::close(fd)
}

// ── sys_fstat ─────────────────────────────────────────────────────────────

#[repr(C)]
struct StatBuf {
    st_dev: u64, st_ino: u64, st_nlink: u64,
    st_mode: u32, st_uid: u32, st_gid: u32, _pad0: u32,
    st_rdev: u64, st_size: i64, st_blksize: i64, st_blocks: i64,
    st_atim: [u64;2], st_mtim: [u64;2], st_ctim: [u64;2],
    _unused: [i64;3],
}

fn sys_fstat(fd: usize, stat_va: usize) -> isize {
    if stat_va == 0 { return -14; }
    let size = crate::fs::vfs::fstat(fd).unwrap_or(0) as i64;
    let stat = StatBuf {
        st_dev: 2, st_ino: fd as u64, st_nlink: 1,
        st_mode: 0o100644, st_uid: 0, st_gid: 0, _pad0: 0,
        st_rdev: 0, st_size: size, st_blksize: 4096,
        st_blocks: (size + 511) / 512,
        st_atim: [0;2], st_mtim: [0;2], st_ctim: [0;2],
        _unused: [0;3],
    };
    let bytes = unsafe {
        core::slice::from_raw_parts(&stat as *const StatBuf as *const u8, core::mem::size_of::<StatBuf>())
    };
    match copy_to_user(stat_va, bytes) { Ok(_) => 0, Err(()) => -14 }
}

// ── sys_mmap / sys_munmap / sys_mprotect / sys_brk ────────────────────────

fn sys_mmap(addr: usize, len: usize, prot: i32, flags: i32, fd: i32, _off: usize) -> isize {
    crate::mm::mmap::sys_mmap(addr, len, prot, flags, fd as usize)
}
fn sys_munmap(addr: usize, len: usize) -> isize {
    crate::mm::mmap::sys_munmap(addr, len)
}
fn sys_mprotect(addr: usize, len: usize, prot: u32) -> isize {
    crate::mm::mmap::sys_mprotect(addr, len, prot)
}
fn sys_brk(new_brk: usize) -> isize {
    crate::mm::mmap::sys_brk(new_brk)
}
fn sys_mremap(old_addr: usize, old_len: usize, new_len: usize, flags: usize, new_addr: usize) -> isize {
    crate::mm::mmap::sys_mremap(old_addr, old_len, new_len, flags, new_addr)
}

// ── sys_madvise ───────────────────────────────────────────────────────────

fn sys_madvise(addr: usize, length: usize, advice: i32) -> isize {
    const MADV_DONTNEED: i32 = 4;
    const MADV_FREE:     i32 = 8;
    if advice == MADV_DONTNEED || advice == MADV_FREE {
        let pages = (length + 4095) / 4096;
        for i in 0..pages {
            let va = addr + i * 4096;
            if let Some(pa) = crate::arch::x86_64::paging::unmap_page(va) {
                if pa != 0 { crate::mm::pmm::free_page(pa); }
            }
        }
        unsafe {
            for i in 0..pages {
                core::arch::asm!("invlpg [{va}]", va = in(reg) addr + i * 4096, options(nostack));
            }
        }
    }
    0
}

fn sys_msync(_addr: usize, _len: usize, _flags: i32) -> isize { 0 }

// ── sys_read helpers (pread/readv/writev) ─────────────────────────────────

fn sys_pread(fd: usize, buf_va: usize, count: usize, offset: i64) -> isize {
    if buf_va == 0 { return -14; }
    let mut tmp = alloc::vec![0u8; count.min(65536)];
    let n = crate::fs::vfs::pread(fd, tmp.as_mut_ptr(), count, offset);
    if n <= 0 { return n; }
    match copy_to_user(buf_va, &tmp[..n as usize]) { Ok(_) => n, Err(()) => -14 }
}

fn sys_pwrite(fd: usize, buf_va: usize, count: usize, offset: i64) -> isize {
    if buf_va == 0 { return -14; }
    let n = count.min(65536);
    let mut tmp = alloc::vec![0u8; n];
    match copy_from_user(&mut tmp, buf_va) { Ok(_) => {}, Err(()) => return -14 }
    crate::fs::vfs::seek(fd, offset, 0);
    crate::fs::vfs::write(fd, &tmp[..n]) as isize
}

#[repr(C)]
struct Iovec { base: usize, len: usize }

fn sys_readv(fd: usize, iov_va: usize, iovcnt: usize) -> isize {
    let mut total = 0isize;
    for i in 0..iovcnt.min(16) {
        let iov = unsafe { &*((iov_va + i * core::mem::size_of::<Iovec>()) as *const Iovec) };
        if iov.len == 0 { continue; }
        let n = sys_read(fd, iov.base, iov.len);
        if n < 0 { return if total > 0 { total } else { n }; }
        total += n;
    }
    total
}

fn sys_writev(fd: usize, iov_va: usize, iovcnt: usize) -> isize {
    let mut total = 0isize;
    for i in 0..iovcnt.min(16) {
        let iov = unsafe { &*((iov_va + i * core::mem::size_of::<Iovec>()) as *const Iovec) };
        if iov.len == 0 { continue; }
        let n = sys_write(fd, iov.base, iov.len);
        if n < 0 { return if total > 0 { total } else { n }; }
        total += n;
    }
    total
}

// ── sys_access ────────────────────────────────────────────────────────────

fn sys_access(path_va: usize, mode: u32) -> isize {
    let path = read_cstr_safe(path_va);
    crate::fs::vfs::access(&path, mode)
}

fn sys_faccessat(dirfd: i32, path_va: usize, mode: u32) -> isize {
    sys_access(path_va, mode)
}

// ── sys_pipe ──────────────────────────────────────────────────────────────

fn sys_pipe(pipefd_va: usize) -> isize {
    sys_pipe2(pipefd_va, 0)
}

fn sys_pipe2(pipefd_va: usize, flags: i32) -> isize {
    let (rfd, wfd) = match crate::fs::vfs::create_pipe() { Some(p) => p, None => return -23 };
    if flags & 0x80000 != 0 {
        crate::fs::fcntl::set_cloexec(rfd, true);
        crate::fs::fcntl::set_cloexec(wfd, true);
    }
    if flags & 0x800 != 0 {
        crate::fs::fcntl::set_nonblock(rfd, true);
        crate::fs::fcntl::set_nonblock(wfd, true);
    }
    let buf = [(rfd as u32).to_le_bytes(), (wfd as u32).to_le_bytes()].concat();
    match copy_to_user(pipefd_va, &buf) { Ok(_) => 0, Err(()) => -14 }
}

// ── sys_select ────────────────────────────────────────────────────────────

fn sys_select(nfds: usize, read_va: usize, write_va: usize, except_va: usize, timeout_va: usize) -> isize {
    crate::fs::select::sys_select(nfds, read_va, write_va, except_va, timeout_va)
}

// ── sys_nanosleep ─────────────────────────────────────────────────────────

#[repr(C)] struct Timespec { tv_sec: i64, tv_nsec: i64 }

fn sys_nanosleep(req_va: usize, rem_va: usize) -> isize {
    if req_va == 0 { return -14; }
    let ts = unsafe { *(req_va as *const Timespec) };
    let ns = ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64;
    let ms = (ns / 1_000_000).max(1);
    crate::proc::scheduler::sleep_ms(ms);
    if rem_va != 0 {
        unsafe { *(rem_va as *mut Timespec) = Timespec { tv_sec: 0, tv_nsec: 0 }; }
    }
    0
}

// ── Socket helpers ────────────────────────────────────────────────────────

fn sys_socket(domain: usize, stype: usize, _proto: usize) -> isize {
    crate::net::socket::sys_socket(domain, stype)
}

fn sys_bind(fd: usize, addr_va: usize) -> isize {
    let port = if addr_va != 0 {
        unsafe { u16::from_be(*((addr_va + 2) as *const u16)) }
    } else { 0 };
    crate::net::socket::sys_bind(fd, port as usize)
}

fn sys_connect(fd: usize, addr_va: usize, _addrlen: u16) -> isize {
    crate::net::socket::sys_connect(fd, addr_va)
}

fn sys_accept(fd: usize) -> isize {
    crate::net::socket::sys_accept(fd)
}

fn sys_accept4(sockfd: usize, _addr: usize, _addrlen: usize, _flags: i32) -> isize {
    let r = crate::ipc::unix_socket::sys_accept(sockfd);
    if r >= 0 { return r; }
    crate::net::socket::sys_accept(sockfd)
}

fn sys_listen_impl(sockfd: usize, _backlog: i32) -> isize {
    crate::net::socket::sys_listen(sockfd)
}

fn sys_sendto(fd: usize, buf_va: usize, len: usize, _flags: usize) -> isize {
    let n = len.min(65536);
    let mut tmp = alloc::vec![0u8; n];
    match copy_from_user(&mut tmp, buf_va) { Ok(_) => {}, Err(()) => return -14 }
    crate::net::socket::sys_send(fd, &tmp[..n])
}

fn sys_recvfrom(fd: usize, buf_va: usize, len: usize, _flags: usize) -> isize {
    let mut tmp = alloc::vec![0u8; len.min(65536)];
    let n = crate::net::socket::sys_recv(fd, &mut tmp);
    if n <= 0 { return n; }
    match copy_to_user(buf_va, &tmp[..n as usize]) { Ok(_) => n, Err(()) => -14 }
}

fn sys_sendmsg(sockfd: usize, msg_va: usize, flags: usize) -> isize {
    crate::net::socket::sys_sendmsg(sockfd, msg_va, flags)
}

fn sys_recvmsg(sockfd: usize, msg_va: usize, flags: usize) -> isize {
    crate::net::socket::sys_recvmsg(sockfd, msg_va, flags)
}

fn sys_getsockname(fd: usize, addr_va: usize, addrlen_va: usize) -> isize {
    crate::net::socket::sys_getsockname(fd, addr_va, addrlen_va)
}

fn sys_getpeername(fd: usize, addr_va: usize, addrlen_va: usize) -> isize {
    crate::net::socket::sys_getpeername(fd, addr_va, addrlen_va)
}

fn sys_shutdown_impl(sockfd: usize, _how: i32) -> isize {
    crate::fs::vfs::close(sockfd)
}

fn sys_socketpair_impl(_domain: usize, _stype: usize, _proto: usize, sv_va: usize) -> isize {
    let (a, b) = match crate::ipc::unix_socket::create_pair() {
        Some(p) => p, None => return -23,
    };
    let fds = [(a as u32).to_le_bytes(), (b as u32).to_le_bytes()].concat();
    match copy_to_user(sv_va, &fds) { Ok(_) => 0, Err(()) => -14 }
}

// ── process / signal helpers ──────────────────────────────────────────────

fn sys_clone(flags: usize, stack: usize, _ptid: usize, _ctid: usize, _tls: usize) -> isize {
    crate::proc::fork::sys_clone(flags, stack)
}

fn sys_execve_stub(path_va: usize, argv_va: usize, envp_va: usize) -> isize {
    -38 // ENOSYS — execve is handled in handle_x86 before dispatch
}

fn sys_exit(code: i32) -> isize {
    crate::proc::scheduler::exit_current(code);
    0
}

fn sys_wait4(pid: i32, status_va: usize, options: i32) -> isize {
    crate::proc::scheduler::wait_pid(pid, status_va, options)
}

fn sys_waitid(idtype: usize, id: i32, info_va: usize, options: i32) -> isize {
    crate::proc::scheduler::wait_pid(-1, info_va, options)
}

fn sys_kill(pid: i32, sig: i32) -> isize {
    crate::proc::signal::send_signal(pid, sig)
}

fn sys_rt_sigaction(sig: usize, act_va: usize, oact_va: usize) -> isize {
    crate::proc::signal::sys_sigaction(sig as i32, act_va, oact_va)
}

fn sys_rt_sigprocmask(how: i32, set_va: usize, oset_va: usize) -> isize {
    crate::proc::signal::sys_sigprocmask(how, set_va, oset_va)
}

// ── uname ─────────────────────────────────────────────────────────────────

const UNAME: &[u8; 390] = {
    let mut b = [0u8; 390];
    // sysname
    b[0]=b'L';b[1]=b'i';b[2]=b'n';b[3]=b'u';b[4]=b'x';
    // nodename
    b[65]=b'r';b[66]=b'u';b[67]=b's';b[68]=b't';b[69]=b'o';b[70]=b's';
    // release
    b[130]=b'6';b[131]=b'.';b[132]=b'1';b[133]=b'.';b[134]=b'0';
    // version
    b[195]=b'#';b[196]=b'1';
    // machine
    b[260]=b'x';b[261]=b'8';b[262]=b'6';b[263]=b'_';b[264]=b'6';b[265]=b'4';
    &b
};

fn sys_uname(buf_va: usize) -> isize {
    match copy_to_user(buf_va, UNAME) { Ok(_) => 0, Err(()) => -14 }
}

// ── fcntl ─────────────────────────────────────────────────────────────────

fn sys_fcntl(fd: usize, cmd: i32, arg: usize) -> isize {
    crate::fs::fcntl::sys_fcntl(fd, cmd, arg)
}

// ── stat helpers ──────────────────────────────────────────────────────────

fn fill_stat_buf(stat_va: usize, size: u64, mode: u32, ino: u64) -> isize {
    if stat_va == 0 { return -14; }
    let s = StatBuf {
        st_dev: 2, st_ino: ino, st_nlink: 1,
        st_mode: mode, st_uid: 0, st_gid: 0, _pad0: 0,
        st_rdev: 0, st_size: size as i64,
        st_blksize: 4096, st_blocks: (size as i64 + 511) / 512,
        st_atim: [0;2], st_mtim: [0;2], st_ctim: [0;2], _unused: [0;3],
    };
    let bytes = unsafe {
        core::slice::from_raw_parts(&s as *const StatBuf as *const u8, core::mem::size_of::<StatBuf>())
    };
    match copy_to_user(stat_va, bytes) { Ok(_) => 0, Err(()) => -14 }
}

const AT_FDCWD: i32 = -100;

fn sys_newfstatat(dirfd: i32, path_va: usize, stat_va: usize, flags: i32) -> isize {
    if path_va == 0 && dirfd >= 0 { return sys_fstat(dirfd as usize, stat_va); }
    let path = read_cstr_safe(path_va);
    let full = if path.starts_with('/') { path } else { alloc::format!("/{}", path) };
    match crate::fs::vfs::stat_path(&full) {
        Some((size, is_dir, ino)) => fill_stat_buf(stat_va, size, if is_dir {0o40755} else {0o100644}, ino),
        None => -2,
    }
}

fn sys_stat_impl(path_va: usize, stat_va: usize) -> isize {
    sys_newfstatat(AT_FDCWD, path_va, stat_va, 0)
}

fn sys_lstat_impl(path_va: usize, stat_va: usize) -> isize {
    sys_newfstatat(AT_FDCWD, path_va, stat_va, 0x100)
}

// ── readlink ──────────────────────────────────────────────────────────────

fn sys_readlink(path_va: usize, buf_va: usize, bufsiz: usize) -> isize {
    let path = read_cstr_safe(path_va);
    let target = if path == "/proc/self/exe" {
        crate::fs::procfs::proc_self_exe_str()
    } else {
        return -2;
    };
    let n = target.len().min(bufsiz);
    match copy_to_user(buf_va, target[..n].as_bytes()) { Ok(_) => n as isize, Err(()) => -14 }
}

fn sys_readlinkat(dirfd: i32, path_va: usize, buf_va: usize, bufsiz: usize) -> isize {
    sys_readlink(path_va, buf_va, bufsiz)
}

// ── directory operations ──────────────────────────────────────────────────

fn sys_getdents64(fd: usize, buf_va: usize, count: usize) -> isize {
    crate::fs::dir::sys_getdents64(fd, buf_va, count)
}

fn sys_getcwd(buf_va: usize, size: usize) -> isize {
    let cwd = b"/\0";
    match copy_to_user(buf_va, cwd) { Ok(_) => buf_va as isize, Err(()) => -14 }
}

fn sys_chdir(path_va: usize) -> isize { 0 }
fn sys_rename(old: usize, new: usize) -> isize { crate::fs::vfs::rename(old, new) }
fn sys_mkdir(path_va: usize, mode: u32) -> isize { crate::fs::vfs::mkdir(path_va, mode) }
fn sys_rmdir(path_va: usize) -> isize { crate::fs::vfs::rmdir(path_va) }
fn sys_unlink(path_va: usize) -> isize { crate::fs::vfs::unlink(path_va) }
fn sys_symlink(target: usize, linkpath: usize) -> isize { 0 }
fn sys_link(old: usize, new: usize) -> isize { 0 }
fn sys_unlinkat(dirfd: i32, path_va: usize, flags: u32) -> isize { sys_unlink(path_va) }
fn sys_mkdirat(dirfd: i32, path_va: usize, mode: u32) -> isize { sys_mkdir(path_va, mode) }
fn sys_renameat(od: i32, op: usize, nd: i32, np: usize) -> isize { sys_rename(op, np) }
fn sys_linkat(od: i32, op: usize, nd: i32, np: usize, f: u32) -> isize { 0 }
fn sys_symlinkat(t: usize, nd: i32, lp: usize) -> isize { 0 }

// ── ioctl dispatch ────────────────────────────────────────────────────────

fn sys_ioctl(fd: usize, req: u64, arg: usize) -> isize {
    crate::fs::ioctl::sys_ioctl(fd, req, arg)
}

// ── time / clock ─────────────────────────────────────────────────────────

fn sys_clock_gettime(clockid: u32, tp_va: usize) -> isize {
    crate::time::sys_clock_gettime(clockid, tp_va)
}
fn sys_clock_getres(clockid: u32, tp_va: usize) -> isize {
    if tp_va != 0 {
        unsafe { *(tp_va as *mut Timespec) = Timespec { tv_sec: 0, tv_nsec: 1_000_000 }; }
    }
    0
}
fn sys_clock_nanosleep(_clockid: i32, _flags: i32, req_va: usize, rem_va: usize) -> isize {
    sys_nanosleep(req_va, rem_va)
}
fn sys_gettimeofday(tv_va: usize, _tz: usize) -> isize {
    crate::time::sys_gettimeofday(tv_va)
}

// ── futex ─────────────────────────────────────────────────────────────────

fn sys_futex(uaddr: usize, op: i32, val: u32, timeout_va: usize, uaddr2: usize) -> isize {
    crate::sync::futex::sys_futex(uaddr, op, val, timeout_va, uaddr2)
}

// ── prctl / arch_prctl ────────────────────────────────────────────────────

fn sys_prctl(opt: i32, a1: usize, a2: usize, a3: usize, a4: usize) -> isize {
    crate::proc::prctl::sys_prctl(opt, a1, a2, a3, a4)
}
fn sys_arch_prctl(code: i32, addr: usize) -> isize {
    crate::proc::prctl::sys_arch_prctl(code, addr)
}
fn sys_set_tid_address(tidptr: usize) -> isize {
    crate::proc::scheduler::set_tid_address(tidptr);
    crate::proc::scheduler::current_pid() as isize
}

// ── epoll ─────────────────────────────────────────────────────────────────

fn sys_epoll_create(flags: u32) -> isize { crate::fs::epoll::sys_epoll_create(flags) }
fn sys_epoll_ctl(epfd: usize, op: i32, fd: usize, event_va: usize) -> isize {
    crate::fs::epoll::sys_epoll_ctl(epfd, op, fd, event_va)
}
fn sys_epoll_wait(epfd: usize, events_va: usize, maxevents: i32, timeout_ms: i32) -> isize {
    crate::fs::epoll::sys_epoll_wait(epfd, events_va, maxevents, timeout_ms)
}

// ── inotify ────────────────────────────────────────────────────────────────

fn sys_inotify_init(flags: u32) -> isize { crate::fs::inotify::sys_inotify_init(flags) }
fn sys_inotify_add_watch(fd: usize, path_va: usize, mask: u32) -> isize {
    let path = read_cstr_safe(path_va);
    crate::fs::inotify::sys_inotify_add_watch(fd, &path, mask)
}
fn sys_inotify_rm_watch(fd: usize, wd: i32) -> isize {
    crate::fs::inotify::sys_inotify_rm_watch(fd, wd)
}

// ── timerfd ────────────────────────────────────────────────────────────────

fn sys_timerfd_create(clockid: i32, flags: i32) -> isize {
    crate::fs::timerfd::sys_timerfd_create(clockid, flags)
}
fn sys_timerfd_settime(fd: usize, flags: i32, new_va: usize, old_va: usize) -> isize {
    crate::fs::timerfd::sys_timerfd_settime(fd, flags, new_va, old_va)
}
fn sys_timerfd_gettime(fd: usize, curr_va: usize) -> isize {
    crate::fs::timerfd::sys_timerfd_gettime(fd, curr_va)
}

// ── signalfd / eventfd ────────────────────────────────────────────────────

fn sys_signalfd(fd: usize, mask_va: usize, flags: u32) -> isize {
    crate::fs::signalfd::sys_signalfd(fd, mask_va, flags)
}
fn sys_eventfd(initval: u32, flags: u32) -> isize {
    crate::fs::eventfd::sys_eventfd(initval, flags)
}

// ── statfs ────────────────────────────────────────────────────────────────

const EXT2_MAGIC:  u32 = 0xEF53;
const TMPFS_MAGIC: u32 = 0x01021994;

fn fill_statfs(buf_va: usize, fstype: u32, total_blocks: u64) -> isize {
    if buf_va == 0 { return -14; }
    #[repr(C)] struct Statfs {
        f_type: i64, f_bsize: i64, f_blocks: u64, f_bfree: u64, f_bavail: u64,
        f_files: u64, f_ffree: u64, f_fsid: [i32;2], f_namelen: i64,
        f_frsize: i64, f_flags: i64, _spare: [i64;4],
    }
    let s = Statfs {
        f_type: fstype as i64, f_bsize: 4096, f_blocks: total_blocks,
        f_bfree: total_blocks / 2, f_bavail: total_blocks / 2,
        f_files: 4096, f_ffree: 4096, f_fsid: [0;2],
        f_namelen: 255, f_frsize: 4096, f_flags: 0, _spare: [0;4],
    };
    let bytes = unsafe { core::slice::from_raw_parts(&s as *const Statfs as *const u8, core::mem::size_of::<Statfs>()) };
    match copy_to_user(buf_va, bytes) { Ok(_) => 0, Err(()) => -14 }
}

fn sys_statfs(path_va: usize, buf_va: usize) -> isize {
    let path = read_cstr_safe(path_va);
    let fstype = if path.starts_with("/dev") || path.starts_with("/tmp") || path.starts_with("/run") {
        TMPFS_MAGIC
    } else { EXT2_MAGIC };
    fill_statfs(buf_va, fstype, 1024 * 1024)
}

fn sys_fstatfs(fd: usize, buf_va: usize) -> isize {
    fill_statfs(buf_va, EXT2_MAGIC, 1024 * 1024)
}

// ── getrandom ─────────────────────────────────────────────────────────────

fn sys_getrandom(buf_va: usize, count: usize, _flags: u32) -> isize {
    let n = count.min(256);
    let mut tmp = alloc::vec![0u8; n];
    for b in tmp.iter_mut() { *b = crate::arch::x86_64::rng::rdrand_byte().unwrap_or(0xCA); }
    match copy_to_user(buf_va, &tmp) { Ok(_) => n as isize, Err(()) => -14 }
}

// ── memfd_create ──────────────────────────────────────────────────────────

static NEXT_MEMFD: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0x500);

struct MemfdEntry { pa: u64, size: usize, name: alloc::string::String }
static MEMFD_TABLE: spin::Mutex<alloc::collections::BTreeMap<usize, MemfdEntry>> =
    spin::Mutex::new(alloc::collections::BTreeMap::new());

fn sys_memfd_create(name_va: usize, _flags: u32) -> isize {
    let name = read_cstr_safe(name_va);
    let fd = NEXT_MEMFD.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    MEMFD_TABLE.lock().insert(fd, MemfdEntry { pa: 0, size: 0, name });
    fd as isize
}

fn sys_ftruncate(fd: usize, length: i64) -> isize {
    if length < 0 { return -22; }
    crate::mm::memfd::sys_ftruncate(fd, length as usize)
}

fn sys_truncate(path_va: usize, length: i64) -> isize { 0 }

// ── userfaultfd stub ──────────────────────────────────────────────────────

fn sys_userfaultfd(flags: u32) -> isize {
    crate::mm::mmap::sys_userfaultfd(flags)
}

// ── misc stubs ────────────────────────────────────────────────────────────

fn sys_fsync(fd: usize) -> isize { 0 }
fn sys_lseek(fd: usize, offset: i64, whence: i32) -> isize {
    crate::fs::vfs::seek(fd, offset, whence)
}
fn sys_dup_stub(fd: usize) -> isize { fd as isize }
fn sys_getrlimit(resource: usize, rlim_va: usize) -> isize {
    crate::proc::resource::sys_getrlimit(resource, rlim_va)
}
fn sys_prlimit(pid: i32, resource: usize, new_va: usize, old_va: usize) -> isize {
    crate::proc::resource::sys_prlimit(pid, resource, new_va, old_va)
}
fn sys_getrusage(who: i32, usage_va: usize) -> isize {
    crate::proc::resource::sys_getrusage(who, usage_va)
}
fn sys_sysinfo(info_va: usize) -> isize { crate::sys::sysinfo::sys_sysinfo(info_va) }
fn sys_times(buf_va: usize) -> isize { 0 }
fn sys_mincore(addr: usize, length: usize, vec_va: usize) -> isize { 0 }
fn sys_sendfile(out_fd: usize, in_fd: usize, offset_va: usize, count: usize) -> isize {
    crate::fs::sendfile::sys_sendfile(out_fd, in_fd, offset_va, count)
}
fn sys_splice(fd_in: usize, _off_in: usize, fd_out: usize, _off_out: usize, count: usize) -> isize { 0 }
fn sys_fallocate(fd: usize, mode: i32, offset: i64, len: i64) -> isize { 0 }
fn sys_reboot(magic: u32, magic2: u32, cmd: u32, arg: usize) -> isize {
    if magic == 0xfee1dead { unsafe { core::arch::asm!("hlt"); } }
    -22
}
fn sys_getcpu(cpu_va: usize, node_va: usize, _tcache: usize) -> isize {
    if cpu_va != 0 { unsafe { *(cpu_va as *mut u32) = 0; } }
    if node_va != 0 { unsafe { *(node_va as *mut u32) = 0; } }
    0
}
fn sys_copy_file_range(fd_in: usize, off_in: usize, fd_out: usize, off_out: usize, len: usize) -> isize { 0 }
fn sys_execveat(dirfd: i32, path_va: usize, argv: usize, envp: usize, flags: i32) -> isize { -38 }
fn sys_waitid(idtype: usize, id: i32, info_va: usize, options: i32) -> isize {
    crate::proc::scheduler::wait_pid(-1, info_va, options)
}

// ── P0 gap implementations ────────────────────────────────────────────────
include!("p0_gaps.rs");
include!("socket_gaps.rs");
