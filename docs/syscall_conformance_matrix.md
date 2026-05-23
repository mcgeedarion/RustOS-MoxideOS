# RustOS Syscall Conformance Matrix (Seed)

This file is the source-of-truth seed for syscall conformance tracking.
Each row records expected baseline behavior and test status.

| Syscall Family | Representative Syscalls | Expected Baseline | Negative Cases | Status | Notes |
|---|---|---|---|---|---|
| FS path ops | `openat`, `renameat2`, `unlinkat`, `mkdirat` | POSIX-like path resolution + errno behavior | `EINVAL`, `EFAULT`, `ENOSYS` where unsupported flags are used | ⚠️ In progress | Start with table-driven tests in `tests/` |
| Process | `fork`, `clone`, `execve`, `wait4` | Parent/child semantics + wait status correctness | `EINVAL`, `ESRCH`, `EFAULT` | ⚠️ In progress | Validate PID namespace interactions |
| Memory | `mmap`, `munmap`, `mprotect`, `brk` | Mapping permissions and fault semantics | `EINVAL`, `ENOMEM`, `EFAULT` | ⚠️ In progress | Cross-check COW behavior |
| Signal | `rt_sigaction`, `rt_sigprocmask`, `kill` | Handler install/delivery/mask semantics | `EINVAL`, `ESRCH`, `EFAULT` | ⚠️ In progress | Include restart semantics |
| Socket | `socket`, `bind`, `connect`, `accept4` | Basic AF_UNIX/AF_INET lifecycle | `EINVAL`, `EAFNOSUPPORT`, `ENOSYS` | ⚠️ In progress | Tie to existing socket tests |

## Rollout

1. Add one table-driven test module per family.
2. Keep expected errno behavior centralized in this file.
3. Update status from ⚠️ to ✅ only after tests run in CI.
