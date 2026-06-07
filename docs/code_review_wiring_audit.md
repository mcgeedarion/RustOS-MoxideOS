# RustOS code review and wiring audit

Date: 2026-06-07

This audit starts an exhaustive review of the current tree with an emphasis on
bugs that prevent a kernel build and on source files that exist but are not yet
wired into the module, feature, or boot graph.  It intentionally records the
exact commands used so follow-up work can reproduce the same first-order
failures before drilling into runtime behavior.

## Commands run

| Command | Result | Notes |
|---|---:|---|
| `find .. -name AGENTS.md -print` | pass | No repository-local agent instructions were present. |
| `cargo metadata --no-deps --format-version 1` | pass | Workspace metadata resolves; root kernel is the default workspace member. |
| `cargo check --workspace` | fail | The repository default target is a custom JSON target, so plain Cargo requires `-Zjson-target-spec`. |
| `cargo check -p xtask --target x86_64-unknown-linux-gnu` | pass with warning | `xtask` builds, but it emits one `unused_unsafe` warning. |
| `cargo check -p scheme-api --target x86_64-unknown-linux-gnu` | pass | Host-checkable helper crate builds. |
| `cargo check -p kmtest --target x86_64-unknown-linux-gnu` | pass with warnings | Builds, but `KmTestEntry` uses `&str` in linker-section FFI boundaries. |
| `cargo check -Z build-std=core,alloc -Zjson-target-spec --target targets/riscv64-uefi-loader.json` | fail | After the build-script compiler fix, CRT compilation reaches Rust checking; remaining failures are Rust module/API wiring errors and a missing optional RISC-V assembler. |
| `cargo check -Z build-std=core,alloc -Zjson-target-spec --target targets/x86_64-kernel.json` | fail | Kernel checking still fails on the remaining module/API wiring backlog after the initial compatibility pass. |
| `cargo xtask build --arch x86_64 --boot uefi` | fail | The canonical build path reaches the same early x86_64 compile errors. |

## Executive summary

The tree is not in a buildable state for the kernel.  Host-only helper crates
mostly compile, but every kernel build path checked during this pass fails
before linking:

1. The RISC-V UEFI target now gets past freestanding CRT compilation by selecting a cross-capable Clang fallback when no explicit target C compiler is configured; remaining failures are Rust module/API wiring issues.
2. The x86_64 kernel target has widespread stale imports, missing re-exports,
   feature-gate mismatches, and architecture-specific modules compiled on the
   wrong target.
3. Several source files are present in the tree but are not declared in their
   parent `mod.rs`; meanwhile other call sites expect those modules to exist.
4. Documentation overstates architecture readiness and has drifted from the
   actual build defaults and linker-script layout.

The first engineering objective should be to restore one green kernel check for
one architecture, preferably x86_64 because it gets past the build script and
exposes the largest set of Rust wiring errors.

## Highest-priority bugs and wiring gaps

### P0: Restore the x86_64 module graph

The x86_64 check still fails after the initial compatibility pass. The first errors are all wiring
failures, which means many later type errors may be secondary fallout.  Fix
module visibility and path compatibility before attempting deeper logic fixes.

Concrete examples from the check log:

- `crate::arch::console::early_putchar` is referenced, but `arch` only exposes
  per-architecture modules plus `Arch`/`hal`; there is no `arch::console` module.
- `crate::gdbstub::...` is referenced from x86_64 exception handlers, but the
  crate root only declares `debug` behind the `gdbstub` feature and does not
  expose a root `gdbstub` alias.
- `crate::debug::gdbstub::...` is referenced with default features enabled, but
  `src/debug/mod.rs` only exposes its inner implementation when the `debug`
  feature is enabled.  The package default enables `gdbstub`, not `debug`, so
  `debug::gdbstub` is configured out in default builds.
- `crate::drivers::virtio_gpu`, `crate::drivers::drm`, `crate::drivers::gop`,
  and `crate::drivers::vga` are referenced as direct children of `drivers`, but
  the files are declared under `drivers::gpu`.
- `crate::proc::itimer`, `crate::proc::exit`, `crate::proc::nanosleep`, and
  `crate::proc::futex` are referenced, but those files are not declared in
  `src/proc/mod.rs`.
- `crate::io_uring::epoll`, `crate::mm::memfd`, and multiple scheme types such
  as `BlkScheme`, `VfsScheme`, `TtyScheme`, `DevFs`, `ProcFs`, `SysFs`, `RamFs`,
  and network schemes are referenced but are not available at the referenced
  paths.

Suggested first fix sequence:

1. Add temporary compatibility re-exports only for modules whose canonical
   implementation already exists, for example GPU children under
   `crate::drivers::*` and GDB stub aliases under the paths already used by
   x86_64 code.
2. Declare existing but omitted process modules in `src/proc/mod.rs` only after
   checking that their own dependencies compile for the target.
3. Replace references to nonexistent compatibility layers (`mm::memfd`,
   `io_uring::epoll`, scheme wrapper structs) with the actual current APIs or
   add minimal adapter modules that intentionally return `ENOSYS` until real
   implementations are connected.
4. Re-run x86_64 check and only then triage remaining semantic/type errors.

### P0: Fix debug feature gating

`Cargo.toml` says `gdbstub` is enabled by default, but `src/debug/mod.rs` wraps
all debug implementation exports in `#[cfg(feature = "debug")]`.  As a result,
code guarded only by `#[cfg(feature = "gdbstub")]` tries to use symbols that are
not compiled.

Preferred wiring:

- Compile and export `debug::gdbstub` under `feature = "gdbstub"`.
- Compile `debug::trace`, `debug::ftrace`, and `debug::oops` under their own
  intended features or under the aggregate `debug` feature.
- If root-level `crate::gdbstub` is still desired, add an explicit compatibility
  re-export guarded by `feature = "gdbstub"`; otherwise update x86_64 handlers
  to use `crate::debug::gdbstub` consistently.

### P0: Gate architecture-specific firmware and assembly

The x86_64 check tries to compile AArch64 PSCI inline assembly and fails with
invalid `x0`/`x1`/`x2`/`x3` registers.  This indicates that firmware modules are
being exposed unconditionally even when their internals are architecture-specific.

Suggested wiring:

- Gate `firmware::psci` and AArch64-only topology paths with
  `#[cfg(target_arch = "aarch64")]`, or provide no-op/`ENOSYS` shims for other
  architectures.
- Audit RISC-V-only CLINT/PLIC and AArch64 interrupt modules the same way before
  attempting multi-architecture checks.

### P0: Update nightly syntax/features used by the kernel

The current pinned nightly rejects several constructs before type checking can
complete:

- `#[naked]` now needs `#[unsafe(naked)]` at the reported sites.
- `#[thread_local]` in `kernel::uaccess` requires `#![feature(thread_local)]` or
  an alternate implementation.
- `percpu::init(cpu_id)` is unsafe but is called without an unsafe block in SMP
  initialization.

These are mechanical build blockers and should be fixed early because they are
independent of larger design questions.

### P0: Fix the cross C compiler path in `build.rs` — applied

The build script now configures Clang with an explicit target triple for RISC-V/AArch64 CRT objects when no explicit `CC`/`TARGET_CC` override is provided. This lets the RISC-V UEFI check proceed beyond C runtime compilation and expose the next Rust wiring errors.

Suggested wiring:

- Prefer environment-provided `CC_<target>`/`TARGET_CC`/`CC` when present.
- Otherwise use `clang --target=riscv64-unknown-elf` for `target_arch =
  "riscv64"` and `clang --target=aarch64-none-elf` for `target_arch =
  "aarch64"` when Clang is available.
- Emit a clear error or warning explaining the required cross C compiler instead
  of forwarding incompatible flags to host `cc`.

### P1: Declare or intentionally retire existing but orphaned source files

A module sweep found source files that are present but not declared by their
parent module.  Some are probably genuine implementations that call sites expect;
others may be abandoned prototypes.  Each should be either declared and fixed or
moved out of the buildable source tree.

| Parent module | Files present but not declared |
|---|---|
| `src/proc` | `cow_fault.rs`, `creds.rs`, `dynlink.rs`, `exit.rs`, `futex.rs`, `itimer.rs`, `nanosleep.rs`, `net_ns.rs`, `pid_ns.rs`, `restart.rs`, `sched_helpers.rs`, `task_group.rs`, `user_ns.rs` |
| `src/io_uring` | `scheduler_integration.rs`, `token.rs` |

The `src/proc` omissions are especially important because the syscall and timer
paths currently reference several of them.

### P1: Add missing or stale Cargo features

The check reports unexpected cfgs and gated modules that do not line up with
`Cargo.toml`:

- `#[cfg(feature = "cgroups")]` is used, but no `cgroups` feature is declared.
- `drivers::gpu::amdgpu_gem` is gated behind `feature = "amdgpu"`, but the
  feature is not declared in `Cargo.toml` and `gpu.rs` still references it
  unconditionally for the AMD backend.
- The `debug`, `debug_stub`, and `gdbstub` features overlap in naming but do not
  currently produce the module graph that call sites expect.

Fixing feature declarations is necessary both for Cargo's check-cfg validation
and for predictable CI coverage.

### P1: Resolve missing dependencies or replace them with local HAL APIs

`src/arch/x86_64/pci.rs` uses the external `x86` crate (`x86::io::outl/inl`),
but `Cargo.toml` does not declare such a dependency.  Either add a no-std-safe
x86 I/O dependency that works on the custom target or replace these calls with
existing local port-I/O helpers.

### P1: Repair syscall dispatcher symbol wiring

The x86_64 check reports a large number of missing syscall backing functions and
constant-pattern issues.  One visible warning is an unconditional recursion in
`syscall::proc_name_clear`, which currently calls itself through the same module
path.  The dispatcher should be split into:

- generated syscall number constants,
- one authoritative table/router,
- adapters that call real subsystem functions,
- explicit `-ENOSYS` placeholders for not-yet-supported Linux ABI calls.

This will make missing implementations intentional instead of accidental module
resolution failures.

### P2: Make documentation match build reality

The README currently describes all three architectures as production-ready and
claims complete kernel feature support.  Current checks contradict that.  The
README also points to linker names such as `linker_x86_64.ld`, while the tree
contains `linker/x86_64.ld`, `linker/riscv64.ld`, and `linker/aarch64.ld`.

Suggested documentation fixes:

- Downgrade architecture status labels until at least one check/build command is
  green per architecture.
- Replace stale linker-script names with the actual `linker/` paths.
- Clarify that plain `cargo build`/`cargo check` needs the nightly `-Z` flags
  or should be run through `cargo xtask`.
- Align the stated default build architecture with `xtask` constants.

## Recommended review phases

1. **Build graph stabilization**: fix feature gates, re-exports, missing module
   declarations, architecture cfgs, and current-nightly syntax until
   `cargo check -Z build-std=core,alloc -Zjson-target-spec --target
   targets/x86_64-kernel.json` reaches semantic errors only.
2. **Subsystem adapter pass**: for every missing symbol that represents an
   unimplemented syscall or scheme, add a deliberate adapter returning a stable
   errno and a tracking comment, then remove accidental dead paths.
3. **Cross-target pass**: after x86_64 checks, fix `build.rs` cross-compiler
   selection and run RISC-V and AArch64 checks to expose target-specific issues.
4. **Runtime smoke pass**: only after build checks pass, run `cargo xtask smoke`
   and QEMU boot scripts for each target.
5. **Documentation truth pass**: update status tables and quick-start commands
   based on the new green commands rather than intended architecture goals.

## Immediate next patch candidates

These are intentionally small enough to review independently:

1. Export `debug::gdbstub` under `feature = "gdbstub"` and normalize x86_64 GDB
   stub call paths.
2. Re-export GPU child modules from `drivers` or update x86_64 boot code to use
   `drivers::gpu::{virtio_gpu, drm, gop, vga}`.
3. Add `pub mod itimer`, `exit`, `nanosleep`, and `futex` to `src/proc/mod.rs`
   if their contents compile; otherwise add minimal intentional shims.
4. Gate `firmware::psci` to AArch64.
5. Update naked-function attributes and `thread_local` feature usage for the
   pinned nightly.
6. Continue from the post-CRT RISC-V Rust module/API errors now that `build.rs` selects a cross-capable compiler fallback.
