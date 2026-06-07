# RustOS Architecture Capability Matrix

Tracks feature parity between the supported 64-bit RustOS ports: `x86_64`,
`riscv64`, and `aarch64`/ARM64.  The table records the current repository
state and should be updated with each architecture-facing change.

## Status legend

| Mark | Meaning |
|---|---|
| ✅ | Implemented in tree and expected to be part of the normal support set. |
| ⚠️ | Implemented partially, platform-dependent, or still needs broader validation. |
| ❌ | Not currently supported. |

## Capability table

| Subsystem | x86_64 | riscv64 | aarch64 / ARM64 | Test / validation path | Primary files | Risk / notes |
|---|---|---|---|---|---|---|
| Boot handoff | ✅ UEFI plus direct-kernel / Multiboot2-style path converge into shared `kernel_main` | ✅ SBI/FDT and UEFI entry paths converge into shared `kernel_main` | ✅ UEFI loader and bare-metal kernel target converge into shared `kernel_main` | `cargo xtask build --arch <arch> --boot <mode>`; `ARCH=<arch> ./scripts/ci/qemu-run.sh` | `src/main.rs`, `src/kernel_main.rs`, `src/init/boot_info.rs`, `src/arch/*/uefi_entry.rs` | Keep boot-specific code thin; all paths must construct `BootInfo`. |
| Firmware discovery | ✅ UEFI memory map, GOP framebuffer, RSDP; OVMF in QEMU | ✅ FDT/SBI path and EDK2 UEFI path | ✅ UEFI/EDK2 path with ACPI/GIC data; DT helpers for bare-metal paths | QEMU UEFI/SBI boots and firmware table parsing | `src/firmware/*`, `src/arch/riscv64/fdt.rs`, `src/arch/aarch64/*` | Real hardware varies; firmware paths should stay explicit in docs and scripts. |
| Trap / IRQ | ✅ IDT, APIC, syscall entry, exception debug flow | ✅ trap setup with PLIC/CLINT-style platform integration | ✅ exception vectors, SVC handler, GIC support modules | kmtest/QEMU smoke plus architecture smoke tests | `src/arch/x86_64/{idt,apic,syscall}.rs`, `src/arch/riscv64/{trap,csr}.rs`, `src/arch/aarch64/{interrupts,syscall}.rs`, `src/irq/*` | IRQ-controller behavior is still the highest-risk board-specific area. |
| Paging / VM | ✅ architecture paging helpers and common VM subsystem | ✅ architecture paging helpers and common VM subsystem | ✅ architecture paging helpers and common VM subsystem | memory tests, mmap/COW smoke workloads | `src/arch/*/paging.rs`, `src/mm/*`, `tests/shared/mmap_cow_fork.c` | Keep page-fault and COW semantics aligned across ABIs. |
| Syscall ABI | ✅ Linux-style x86_64 syscall ABI with inline `rt_sigreturn` handling | ✅ RISC-V syscall/trap path with `rt_sigreturn` handling | ✅ AArch64 SVC #0 path with `rt_sigreturn` handling | userspace smoke tests, kmtest mode, syscall workloads | `src/syscall/*`, `src/arch/x86_64/syscall.rs`, `src/arch/riscv64/trap.rs`, `src/arch/aarch64/syscall.rs` | Architecture entry code must preserve enough frame state for signals. |
| Signal delivery | ✅ thread/group delivery, masks, default actions, signal frames | ✅ RISC-V syscall exit delivery path | ✅ AArch64 signal frame and `sys_rt_sigreturn_aarch64` | `tests/shared/signal_restart.c`; syscall exit tests | `src/proc/signal.rs`, `src/syscall/signal_nr.rs` | Keep user-frame layout compatible with the libc shim/musl expectations. |
| SMP | ✅ AP startup/per-CPU infrastructure represented in tree | ✅ hart startup modules represented in tree | ✅ PSCI/topology-based bring-up represented in tree | boot logs, scheduler tests, architecture smoke | `src/smp/*`, `src/arch/x86_64/ap_boot.s`, `src/arch/riscv64/smp.rs`, `src/arch/aarch64/smp.rs`, `src/firmware/{psci,topology}.rs` | Multi-core stability depends on firmware topology quality and per-board IRQ routing. |
| Timers | ✅ HPET/TSC path and timerfd integration | ✅ CLINT/time path and common timers | ✅ architectural timer helpers and common timers | sleep/timerfd workloads and QEMU smoke | `src/time/*` | Timer IRQ wiring should be validated on each machine type. |
| Device model | ✅ PCI, virtio, block, GPU/input/net classes | ✅ virtio-MMIO-oriented QEMU path | ✅ virtio-MMIO-oriented QEMU path | QEMU with optional disk/net/GPU; userspace smoke | `src/device/*`, `src/drivers/*`, `src/block/*` | x86_64 uses PCI devices in QEMU; ARM/RISC-V virt machines use MMIO devices. |
| Userspace / initramfs | ✅ initramfs, libc shim, init/shell/smoke programs | ✅ architecture-aware userspace build paths | ✅ architecture-aware userspace build paths | `cargo xtask mkinitramfs --arch <arch>`; `--test` mode | `userspace/*`, `tools/build_userspace.sh`, `xtask/src/main.rs` | Cross-musl toolchains are required for non-host architectures. |
| Test harness | ✅ kmtest feature and QEMU `--test` mode | ✅ kmtest/user workload paths represented | ✅ kmtest/user workload paths represented | `ARCH=<arch> ./scripts/ci/qemu-run.sh --test`; `cargo xtask smoke` | `crates/kmtest*`, `src/kmtest/*`, `userspace/kmtest`, `tests/*` | Harness success depends on QEMU, firmware, cpio, and cross-toolchain availability. |

## Update policy

- Update this table when adding or changing architecture features.
- Link rows to concrete tests once a new validation path exists.
- Mark platform-dependent or not-yet-broadly-validated behavior explicitly with
  ⚠️ instead of implying universal hardware support.
