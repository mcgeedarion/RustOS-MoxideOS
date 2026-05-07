/*
 * <bits/rustos_syscall.h> — syscall number table for RustOS.
 *
 * RustOS uses the Linux x86_64 / riscv64 syscall ABI verbatim.
 * Numbers below 500 are identical to Linux.  Numbers >= 500 are
 * RustOS private extensions.
 *
 * This file is auto-generated from src/syscall/stubs.rs by:
 *   cargo xtask gen-syscall-header
 * Do not edit manually.
 */
#ifndef _BITS_RUSTOS_SYSCALL_H
#define _BITS_RUSTOS_SYSCALL_H

/* Standard Linux syscalls (subset implemented by RustOS) */
#define SYS_read              0
#define SYS_write             1
#define SYS_open              2
#define SYS_close             3
#define SYS_stat              4
#define SYS_fstat             5
#define SYS_lstat             6
#define SYS_poll              7
#define SYS_lseek             8
#define SYS_mmap              9
#define SYS_mprotect         10
#define SYS_munmap           11
#define SYS_brk              12
#define SYS_rt_sigaction     13
#define SYS_rt_sigprocmask   14
#define SYS_rt_sigreturn     15
#define SYS_ioctl            16
#define SYS_pread64          17
#define SYS_pwrite64         18
#define SYS_readv            19
#define SYS_writev           20
#define SYS_access           21
#define SYS_pipe             22
#define SYS_select           23
#define SYS_sched_yield      24
#define SYS_mremap           25
#define SYS_msync            26
#define SYS_dup              32
#define SYS_dup2             33
#define SYS_nanosleep        35
#define SYS_getitimer        36
#define SYS_alarm            37
#define SYS_setitimer        38
#define SYS_getpid           39
#define SYS_socket           41
#define SYS_connect          42
#define SYS_accept           43
#define SYS_sendto           44
#define SYS_recvfrom         45
#define SYS_shutdown         48
#define SYS_bind             49
#define SYS_listen           50
#define SYS_getsockname      51
#define SYS_getpeername      52
#define SYS_clone            56
#define SYS_fork             57
#define SYS_execve           59
#define SYS_exit             60
#define SYS_wait4            61
#define SYS_kill             62
#define SYS_uname            63
#define SYS_fcntl            72
#define SYS_flock            73
#define SYS_fsync            74
#define SYS_fdatasync        75
#define SYS_truncate         76
#define SYS_ftruncate        77
#define SYS_getdents         78
#define SYS_getcwd           79
#define SYS_chdir            80
#define SYS_fchdir           81
#define SYS_rename           82
#define SYS_mkdir            83
#define SYS_rmdir            84
#define SYS_creat            85
#define SYS_link             86
#define SYS_unlink           87
#define SYS_symlink          88
#define SYS_readlink         89
#define SYS_chmod            90
#define SYS_fchmod           91
#define SYS_chown            92
#define SYS_fchown           93
#define SYS_lchown           94
#define SYS_umask            95
#define SYS_gettimeofday     96
#define SYS_getrlimit        97
#define SYS_getrusage        98
#define SYS_sysinfo          99
#define SYS_times           100
#define SYS_getuid          102
#define SYS_getgid          104
#define SYS_setuid          105
#define SYS_setgid          106
#define SYS_geteuid         107
#define SYS_getegid         108
#define SYS_getppid         110
#define SYS_getpgrp         111
#define SYS_setsid          112
#define SYS_setgroups       116
#define SYS_sigaltstack     131
#define SYS_utime           132
#define SYS_mknod           133
#define SYS_personality     135
#define SYS_statfs          137
#define SYS_fstatfs         138
#define SYS_getpriority     140
#define SYS_setpriority     141
#define SYS_sched_setparam  142
#define SYS_sched_getparam  143
#define SYS_sched_setscheduler 144
#define SYS_sched_getscheduler 145
#define SYS_sched_get_priority_max 146
#define SYS_sched_get_priority_min 147
#define SYS_mlock           149
#define SYS_munlock         150
#define SYS_mlockall        151
#define SYS_munlockall      152
#define SYS_pivot_root      155
#define SYS_prctl           157
#define SYS_arch_prctl      158
#define SYS_setrlimit       160
#define SYS_chroot          161
#define SYS_sync            162
#define SYS_getsid          124
#define SYS_fdatasync        75
#define SYS_clock_gettime   228
#define SYS_clock_settime   227
#define SYS_clock_getres    229
#define SYS_clock_nanosleep 230
#define SYS_exit_group      231
#define SYS_epoll_wait      232
#define SYS_epoll_ctl       233
#define SYS_tgkill          234
#define SYS_utimes          235
#define SYS_futex           202
#define SYS_set_tid_address 218
#define SYS_timer_create    222
#define SYS_timer_settime   223
#define SYS_timer_gettime   224
#define SYS_timer_delete    226
#define SYS_openat          257
#define SYS_mkdirat         258
#define SYS_mknodat         259
#define SYS_fchownat        260
#define SYS_futimesat       261
#define SYS_newfstatat      262
#define SYS_unlinkat        263
#define SYS_renameat        264
#define SYS_linkat          265
#define SYS_symlinkat       266
#define SYS_readlinkat      267
#define SYS_fchmodat        268
#define SYS_faccessat       269
#define SYS_pselect6        270
#define SYS_ppoll           271
#define SYS_set_robust_list 273
#define SYS_get_robust_list 274
#define SYS_splice          275
#define SYS_tee             276
#define SYS_sync_file_range 277
#define SYS_vmsplice        278
#define SYS_epoll_pwait     281
#define SYS_signalfd        282
#define SYS_timerfd_create  283
#define SYS_eventfd         284
#define SYS_fallocate       285
#define SYS_timerfd_settime 286
#define SYS_timerfd_gettime 287
#define SYS_accept4         288
#define SYS_signalfd4       289
#define SYS_eventfd2        290
#define SYS_epoll_create1   291
#define SYS_dup3            292
#define SYS_pipe2           293
#define SYS_inotify_init1   294
#define SYS_preadv          295
#define SYS_pwritev         296
#define SYS_recvmmsg        299
#define SYS_prlimit64       302
#define SYS_sendmmsg        307
#define SYS_getcpu          309
#define SYS_process_vm_readv  310
#define SYS_process_vm_writev 311
#define SYS_getrandom       318
#define SYS_memfd_create    319
#define SYS_copy_file_range 326
#define SYS_preadv2         327
#define SYS_pwritev2        328

/* RustOS private syscall extensions (>= 500) */
#define SYS_RUSTOS_VERSION       500  /* -> (major<<16)|minor */
#define SYS_RUSTOS_DEBUG_PRINT   501  /* (const char *msg) -> 0 */
#define SYS_RUSTOS_PERF_COUNTER  502  /* (u32 id, u64 *out) -> 0 */

#endif /* _BITS_RUSTOS_SYSCALL_H */
