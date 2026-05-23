# RustOS Subsystem Ownership

This document defines primary and backup reviewers for major subsystems.

| Subsystem | Primary | Backup | Notes |
|---|---|---|---|
| `arch` | @arch-owner | @kernel-owner | x86_64 + riscv64 bring-up and ABI parity |
| `mm` | @mm-owner | @kernel-owner | allocator, mmap, COW, fault handling |
| `proc` | @proc-owner | @mm-owner | fork/exec/signal/scheduling interactions |
| `fs` | @fs-owner | @proc-owner | VFS + filesystem implementations |
| `net` | @net-owner | @drivers-owner | protocol stack + socket layer |
| `drivers` | @drivers-owner | @arch-owner | block/net/gpu/input/platform |
| `security` | @security-owner | @kernel-owner | namespaces, policy, hardening |
| `xtask` + tooling | @build-owner | @kernel-owner | CI/build/image workflows |

## Ownership rules

- PRs touching multiple subsystems should request all relevant owners.
- Large refactors must include a rollout plan and compatibility shims.
- If no owner is available, escalate to backup.
