# RustOS Documentation

This directory collects the architecture, boot, and subsystem notes for the
current RustOS tree.  The docs are written to match the repository layout as it
exists today: one Cargo workspace, three supported 64-bit architecture ports,
a shared `BootInfo` handoff into `kernel_main`, and a hybrid-kernel service
model.

## Documents

| Document | Purpose |
|---|---|
| [`boot-architecture.md`](boot-architecture.md) | Design contract for boot paths, `BootInfo`, and the common kernel entry. |
| [`booting.md`](booting.md) | Practical build, image, QEMU, firmware, real-hardware, and debugging reference. |
| [`arch_capability_matrix.md`](arch_capability_matrix.md) | Current x86_64, RISC-V, and AArch64 capability/status tracker. |
| [`hybrid-kernel-architecture.md`](hybrid-kernel-architecture.md) | Kernel/userspace boundary rules for schemes, IPC, and userspace drivers. |

## Source-of-truth files

The docs intentionally point back to in-tree implementation files rather than
repeating every low-level detail:

- `src/init/boot_info.rs` defines the boot handoff structure.
- `src/kernel_main.rs` exports the shared `kernel_main(&BootInfo)` entry.
- `src/arch/mod.rs` selects the active architecture and exposes the common HAL
  alias used by non-architecture code.
- `xtask/src/main.rs` is the preferred build/image/initramfs automation entry
  point.
- `scripts/ci/qemu-run.sh` is the unified QEMU launcher for x86_64, RISC-V, and
  AArch64.
- `src/kernel/architecture.rs`, `src/syscall/driver.rs`,
  `src/syscall/scheme.rs`, `src/fs/scheme_table.rs`, and
  `src/fs/ipc_proxy_scheme.rs` define the hybrid service-plane hooks.

## Maintenance rules

- Update `arch_capability_matrix.md` whenever an architecture gains or loses a
  boot mode, syscall ABI feature, interrupt path, SMP milestone, or test tier.
- Update `booting.md` when `xtask` or `scripts/ci/qemu-run.sh` changes build
  flags, target JSON names, firmware paths, image names, or smoke/test markers.
- Update `boot-architecture.md` when the `BootInfo` ABI or common entry sequence
  changes.
- Update `hybrid-kernel-architecture.md` when driver handles, IPC endpoints,
  scheme registration, or userspace driver conventions change.
