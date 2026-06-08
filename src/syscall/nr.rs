//! Linux x86-64 syscall number constants.

pub const SYS_READ: usize = 0;
pub const SYS_WRITE: usize = 1;
pub const SYS_OPEN: usize = 2;
pub const SYS_CLOSE: usize = 3;
pub const SYS_STAT: usize = 4;
pub const SYS_FSTAT: usize = 5;
pub const SYS_LSTAT: usize = 6;
pub const SYS_POLL: usize = 7;
pub const SYS_LSEEK: usize = 8;
pub const SYS_IOCTL: usize = 16;
pub const SYS_PREAD64: usize = 17;
pub const SYS_PWRITE64: usize = 18;
pub const SYS_READV: usize = 19;
pub const SYS_WRITEV: usize = 20;
pub const SYS_ACCESS: usize = 21;
pub const SYS_PIPE: usize = 22;
pub const SYS_SELECT: usize = 23;
pub const SYS_DUP: usize = 32;
pub const SYS_DUP2: usize = 33;
pub const SYS_SENDFILE: usize = 40;
pub const SYS_FCNTL: usize = 72;
pub const SYS_SHMGET: usize = 29;
pub const SYS_SHMAT: usize = 30;
pub const SYS_SHMCTL: usize = 31;
pub const SYS_SEMGET: usize = 64;
pub const SYS_SEMOP: usize = 65;
pub const SYS_SEMCTL: usize = 66;
pub const SYS_SHMDT: usize = 67;
pub const SYS_MSGGET: usize = 68;
pub const SYS_MSGSND: usize = 69;
pub const SYS_MSGRCV: usize = 70;
pub const SYS_MSGCTL: usize = 71;
pub const SYS_FLOCK: usize = 73;
pub const SYS_FSYNC: usize = 74;
pub const SYS_FDATASYNC: usize = 75;
pub const SYS_TRUNCATE: usize = 76;
pub const SYS_FTRUNCATE: usize = 77;
pub const SYS_GETDENTS: usize = 78;
pub const SYS_GETCWD: usize = 79;
pub const SYS_CHDIR: usize = 80;
pub const SYS_FCHDIR: usize = 81;
pub const SYS_RENAME: usize = 82;
pub const SYS_MKDIR: usize = 83;
pub const SYS_RMDIR: usize = 84;
pub const SYS_CREAT: usize = 85;
pub const SYS_LINK: usize = 86;
pub const SYS_UNLINK: usize = 87;
pub const SYS_SYMLINK: usize = 88;
pub const SYS_READLINK: usize = 89;
pub const SYS_CHMOD: usize = 90;
pub const SYS_FCHMOD: usize = 91;
pub const SYS_CHOWN: usize = 92;
pub const SYS_LCHOWN: usize = 93;
pub const SYS_FCHOWN: usize = 94;
pub const SYS_UMASK: usize = 95;

pub const SYS_MMAP: usize = 9;
pub const SYS_MPROTECT: usize = 10;
pub const SYS_MUNMAP: usize = 11;
pub const SYS_BRK: usize = 12;
pub const SYS_MINCORE: usize = 27;
pub const SYS_MREMAP: usize = 25;
pub const SYS_MADVISE: usize = 28;

pub const SYS_RT_SIGACTION: usize = 13;
pub const SYS_RT_SIGPROCMASK: usize = 14;
/// rt_sigreturn is intercepted at the arch entry point before dispatch;
/// this arm exists only as a safe ENOSYS fallback.
pub const SYS_RT_SIGRETURN: usize = 15;
pub const SYS_SCHED_YIELD: usize = 24;
pub const SYS_PAUSE: usize = 34;
pub const SYS_NANOSLEEP: usize = 35;
pub const SYS_ALARM: usize = 37;
pub const SYS_GETPID: usize = 39;
pub const SYS_CLONE: usize = 56;
pub const SYS_FORK: usize = 57;
pub const SYS_VFORK: usize = 58;
pub const SYS_EXECVE: usize = 59;
pub const SYS_EXIT: usize = 60;
pub const SYS_WAIT4: usize = 61;
pub const SYS_KILL: usize = 62;
pub const SYS_UNAME: usize = 63;
pub const SYS_GETPPID: usize = 110;
pub const SYS_GETTID: usize = 186;
pub const SYS_CLONE3: usize = 435;
pub const SYS_EXIT_GROUP: usize = 231;

pub const SYS_MQ_OPEN: usize = 240;
pub const SYS_MQ_UNLINK: usize = 241;
pub const SYS_MQ_TIMEDSEND: usize = 242;
pub const SYS_MQ_TIMEDRECEIVE: usize = 243;
pub const SYS_MQ_NOTIFY: usize = 244;
pub const SYS_MQ_GETSETATTR: usize = 245;

pub const SYS_GETUID: usize = 102;
pub const SYS_GETGID: usize = 104;
pub const SYS_GETEUID: usize = 107;
pub const SYS_GETEGID: usize = 108;
pub const SYS_SETUID: usize = 105;
pub const SYS_SETGID: usize = 106;
pub const SYS_GETRESUID: usize = 118;
pub const SYS_SETRESGID: usize = 119;
pub const SYS_GETRESGID: usize = 120;

pub const SYS_FUTEX: usize = 202;
pub const SYS_TKILL: usize = 200;
pub const SYS_TGKILL: usize = 234;
pub const SYS_SET_ROBUST_LIST: usize = 273;
pub const SYS_GET_ROBUST_LIST: usize = 274;

pub const SYS_UNSHARE: usize = 272;
pub const SYS_SETNS: usize = 308;
pub const SYS_SECCOMP: usize = 317;

// Linux's strict mode only permits read(0), write(1), exit(60),
// exit_group(231), and rt_sigreturn(15).  These constants are gathered
// here so the seccomp module can reference them by name.
pub const STRICT_ALLOWLIST: &[usize] = &[
    SYS_READ,
    SYS_WRITE,
    SYS_RT_SIGRETURN,
    SYS_EXIT,
    SYS_EXIT_GROUP,
];

// SYS_KMTEST_RUN:  runs one test by index; streams pass/fail lines to the
//                  kernel serial console and returns the failure count.
pub const SYS_KMTEST_LIST: usize = 0x8000_0000;
pub const SYS_KMTEST_RUN: usize = 0x8000_0001;

// RustOS hybrid-kernel private syscall range.
pub const SYS_DRIVER_BIND: usize = 0x7000_0000;
pub const SYS_DMA_ALLOC: usize = 0x7000_0001;
pub const SYS_IRQ_SUBSCRIBE: usize = 0x7000_0002;
pub const SYS_SCHEME_REGISTER: usize = 0x7000_0003;
pub const SYS_SCHEME_UNREGISTER: usize = 0x7000_0004;
pub const SYS_IPC_ENDPOINT_CREATE: usize = 0x7000_0005;
pub const SYS_IPC_RECV: usize = 0x7000_0006;
pub const SYS_IPC_SEND: usize = 0x7000_0007;
pub const SYS_IRQ_ACK: usize = 0x7000_0008;
