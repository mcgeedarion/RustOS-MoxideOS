# Changelog

All notable changes to rustos are documented here.

---

## [Unreleased]

### Added

- **Integration test suite** (`tests/`) — nine C programs covering the race
  conditions and correctness properties validated in the preceding bug-fix pass:
  - `futex_thundering_herd.c` — `futex_wake_bitset` O(N²) reverse-index removal
  - `futex_cmp_requeue.c` — `futex_requeue_inner` / `pthread_cond_broadcast` path
  - `futex_robust_death.c` — `robust_list_on_exit`, `FUTEX_OWNER_DIED`-only write
  - `sched_rr_fairness.c` — RR extra free-tick preemption bug
  - `sched_cfs_fairness.c` — CFS `min_vruntime` lag-capping in `RunQueue::enqueue`
  - `sched_deadline_cbs.c` — DEADLINE CBS `try_lock` miss delaying replenishment
    (gracefully skips if NR 314 `sched_setattr` is not yet wired)
  - `pipe_stress.c` — `PipeInner` ring buffer byte integrity under yield-spin
  - `vfs_concurrent_creat.c` — `alloc_fd` TOCTOU: two threads claiming same fd slot
  - `poll_close_race.c` — `poll()` vs concurrent write-end close (`POLLHUP`)
  - `run_tests.sh` — build + run harness; exits 0 only when all non-skipped pass

- **Feature flags** — all WIP / incomplete subsystems gated behind opt-in Cargo
  features; the default build is now a clean, fully functional base kernel:
  - `gdbstub` — GDB RSP placeholder
  - `input_events` — `/dev/input` evdev routing stubs
  - `sysv_ipc` — SysV msg/sem/shm + POSIX mq (logic complete; capability stub)
  - `namespaces` — PID/Mount/Net/UTS/User namespaces (setns/nsfs missing)
  - `cgroups` — cpu/memory/pids controllers (cgroupfs mount missing)
  - `wayland` — in-kernel Wayland compositor scaffold (pre-existing, retained)

- **Pinned nightly toolchain** — `rust-toolchain.toml` now pins
  `nightly-2025-05-15` (previously `channel = "nightly"` with no date). Added
  `rustfmt` and `clippy` to the components list. Documented all four nightly
  features that prevent stabilising to a stable channel, with tracking issue
  links. Added upgrade procedure (update three files atomically, build all
  targets, CHANGELOG entry).

- **`Dockerfile`** — Ubuntu 24.04 reproducible dev/CI image bundling `clang`,
  `lld`, `nasm`, `riscv64-unknown-elf-{as,ar}`, `qemu-system-{riscv64,x86_64}`,
  `ovmf`, and the pinned nightly. Includes a toolchain-verification step that
  fails at image-build time on a pin mismatch.

- **`flake.nix`** — Nix flake using `rust-overlay` to pull the pinned nightly
  from the binary cache. Provides `devShells.default` (all tools + welcome
  banner with build commands) and `packages.default` (`nix build` →
  `result/boot/rustos.efi`, reproducible via `Cargo.lock`).

- **`.dockerignore`** — excludes `target/`, `.git/`, and build artifacts from
  the Docker build context.

- **`README.md`** — comprehensive rewrite:
  - Three-option quickstart (Docker / Nix / native)
  - Complete feature-flag table with status column
  - Integration test instructions
  - Toolchain upgrade procedure (three-file rule)
  - Updated repository layout reflecting new files
  - Updated roadmap

- **`build.yml` CI** — all three jobs (RISC-V UEFI, RISC-V SBI, x86_64) now:
  - Pin `dtolnay/rust-toolchain@master` to `nightly-2025-05-15` via `$NIGHTLY`
    env var (previously `@nightly` = unpinned, non-reproducible)
  - Verify the active toolchain matches the pin before building
  - Include the nightly pin in all cache keys (pin bump auto-busts the cache)

### Changed

- **`Cargo.toml` `[features]`** — added six new feature flags with full status
  comments; `default` remains `["uefi_boot"]` only.

- **`src/lib.rs`** — `gdbstub`, `input`, `ipc`, `ns` (re-export), `cgroups`
  (re-export), and `wayland` modules are now `#[cfg(feature = "...")]`-gated.
  Each gate carries an inline doc comment describing what is and is not
  implemented, so enabling the feature gives the developer full context.

- **`rust-toolchain.toml`** — `channel` changed from `"nightly"` to
  `"nightly-2025-05-15"`; added `rustfmt` and `clippy` components.

### Fixed

- **`scheduler::block_current()`** helper — sets process state to `Blocked` and
  resets `rt_cpu_time_us` to 0 for SCHED_FIFO/SCHED_RR tasks in a single
  `with_proc_mut` call. Enforces Linux’s `RLIMIT_RTTIME` semantics: the budget
  measures *continuous* RT CPU time, not a periodic quota.

- **B2** — Double-reap race: a sibling thread sharing the same tgid could
  previously steal a zombie between the find and the `remove_pid` call in
  `sys_waitpid`. Fixed by atomic find+remove in one lock window.

- **M1** — `sys_nanosleep` never wrote the `rem` (remaining time) output
  parameter. Fixed: zeroed `timespec` is now written on successful return.

- **M2** — Three separate `with_proc_mut` calls per timer tick collapsed to one
  in `interrupts.rs`.

- **M3** — Duplicate `nice_to_weight` logic between `scheduler.rs` and
  `sched_helpers.rs`. Fixed by promoting to `pub(crate)` and delegating.

- **M4** — Two O(n) process-list scans per `waitpid` spin iteration merged into
  a single closure via `WaitScan` enum.

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
