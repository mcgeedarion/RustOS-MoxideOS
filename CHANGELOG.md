# Changelog

All notable changes to rustos are documented here.

---

## [Unreleased]

### Added

- **`scheduler::block_current()`** helper — sets process state to `Blocked` and
  resets `rt_cpu_time_us` to 0 for SCHED_FIFO/SCHED_RR tasks in a single
  `with_proc_mut` call. Enforces Linux's `RLIMIT_RTTIME` semantics: the budget
  measures *continuous* RT CPU time, not a periodic quota.

### Changed

- **`proc/wait.rs`** — atomic find-and-reap: zombie lookup and `swap_remove`
  now happen inside a single `with_procs` closure, eliminating the double-reap
  race window. The `has_child` scan is folded into the same closure, reducing
  per-spin-iteration lock acquisitions from 2 to 1 and scans from 2×O(n) to
  1×O(n). Introduced `WaitScan` enum (`Reaped`, `HasLiving`, `NoChild`) to
  drive the loop cleanly.

- **`proc/nanosleep.rs`** — `rem_va` parameter was previously masked (`_rem_va`)
  and never written. Now writes a zeroed `struct timespec` back to userspace
  when `rem_va != 0`, satisfying the POSIX ABI for a completed sleep. The write
  location is marked for the future timer-interrupt path (actual remaining time
  on EINTR).

- **`proc/sched_helpers.rs`** — `nice_to_weight_pub` is now a one-line delegate
  to `scheduler::nice_to_weight` instead of a copy-pasted body, eliminating the
  risk of the two implementations diverging.

- **`proc/scheduler.rs`** — `nice_to_weight` promoted from private `fn` to
  `pub(crate) fn` to support the delegation from `sched_helpers`.

- **`proc/futex.rs`** — `futex_wait_bitset` now calls `scheduler::block_current()`
  instead of a manual two-closure `with_procs` + state assignment, removing the
  `State` import from the blocking path.

- **`arch/x86_64/interrupts.rs`** — `timer_irq_handler` charges the tick and
  snapshots all limit-relevant fields (`cpu_time_ns`, `rt_cpu_time_us`, `policy`)
  in a single `with_proc_mut` closure, then delivers signals (`SIGXCPU`,
  `SIGKILL`) after releasing the lock to prevent lock-signal inversion.

### Fixed

- **B2** — Double-reap race: a sibling thread sharing the same tgid could
  previously steal a zombie between the find and the `remove_pid` call in
  `sys_waitpid`. Fixed by atomic find+remove in one lock window.

- **M1** — `sys_nanosleep` never wrote the `rem` (remaining time) output
  parameter. Fixed: zeroed `timespec` is now written on successful return.

- **M2** — Three separate `with_proc_mut` calls per timer tick (verified
  already collapsed to one in `interrupts.rs`).

- **M3** — Duplicate `nice_to_weight` logic between `scheduler.rs` and
  `sched_helpers.rs`. Fixed by promoting the scheduler function to
  `pub(crate)` and delegating from `sched_helpers`.

- **M4** — Two O(n) process-list scans per `waitpid` spin iteration. Fixed
  by merging both scans into a single closure.

---

## [0.2.0]

### Added

- RISC-V rv64gc support: SBI boot and UEFI EDK2 RiscVVirt boot paths
- `cargo xtask` build system for RISC-V cross-compilation
- virtio-net driver stub
- virtio-gpu driver (`/dev/fb0`)
- NVMe driver stub
- Wayland compositor subsystem (`--features wayland`, WIP)
- Namespaces: PID namespace, network namespace
- `RLIMIT_CPU` enforcement (SIGXCPU/SIGKILL per tick)
- `RLIMIT_RTTIME` enforcement (continuous RT budget)
- SCHED_DEADLINE with `dl_admission_test`
- musl libc port documentation (`docs/musl_port.md`, `docs/musl_pipeline.md`)
- ptrace stub
- GDB integration (`.gdbinit`, `--gdb` flag in QEMU launchers)

### Changed

- Scheduler refactored: CFS weight table, per-CPU run queues, multi-policy
  dispatch (NORMAL / FIFO / RR / DEADLINE)
- Page table subsystem: COW, demand paging, ASLR
- exec path: dynamic linker support (`src/proc/dynlink.rs`)

---

## [0.1.0]

- Initial x86_64 kernel: UEFI boot, IDT, APIC timer, basic process model
- PMM/VMM, slab allocator
- ext2 + FAT32 VFS
- virtio-blk driver
- ~30 Linux syscalls
- initramfs (cpio) loader
