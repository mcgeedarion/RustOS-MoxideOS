# RustOS Architecture Capability Matrix

Tracks feature parity between the supported 64-bit RustOS ports: `aarch64`/ARM64,
`riscv64`, and `x86_64`.  The table records the current repository
state and should be updated with each architecture-facing change.

## Status legend

| Mark | Meaning |
|---|---|
| ✅ | Implemented and passing in CI |
| 🚧 | In progress / partial |
| ❌ | Not yet implemented |
| N/A | Not applicable for this architecture |

## Capability matrix

| Subsystem | aarch64 / ARM64 | riscv64 | x86_64 | Test / validation path | Primary files | Risk / notes |
|---|---|---|---|---|---|---|
| Firmware discovery | ✅ UEFI/EDK2 path with ACPI/GIC data; DT helpers for bare-metal paths | ✅ FDT/SBI path and EDK2 UEFI path | ✅ UEFI memory map, GOP framebuffer, RSDP; OVMF in QEMU | QEMU UEFI/SBI boots and firmware table parsing | `src/firmware/*`, `src/arch/riscv64/fdt.rs`, `src/arch/aarch64/*` | Real hardware varies; firmware paths should stay explicit in docs and scripts. |
| Trap / IRQ | ✅ exception vectors, SVC handler, GIC support modules | ✅ trap setup with PLIC/CLINT-style platform integration | ✅ IDT, APIC, syscall entry, exception debug flow | kmtest/QEMU smoke plus architecture smoke tests | `src/arch/x86_64/{idt,apic,syscall}.rs`, `src/arch/riscv64/{trap,csr}.rs`, `src/arch/aarch64/{interrupts,syscall}.rs`, `src/irq/*` | IRQ-controller behavior is still the highest-risk board-specific area. |
| Memory management | ✅ 4-level page tables (ARMv8 with optional 5-level), ASID support | ✅ SV39/SV48 paging, ASID (SATP) | ✅ 4/5-level page tables, PCID support | boot and kmtest alloc | `src/mm/*`, `src/arch/*/mm/` | TLB flush semantics differ per arch. |
| Syscall ABI | ✅ AArch64 SVC #0 path with `rt_sigreturn` handling | ✅ RISC-V syscall/trap path with `rt_sigreturn` handling | ✅ Linux-style x86_64 syscall ABI with inline `rt_sigreturn` handling | userspace smoke tests, kmtest mode, syscall workloads | `src/syscall/*`, `src/arch/x86_64/syscall.rs`, `src/arch/riscv64/trap.rs`, `src/arch/aarch64/syscall.rs` | Architecture entry code must preserve enough frame state for signals. |
| Signal delivery | ✅ AArch64 signal frame and `sys_rt_sigreturn_aarch64` | ✅ RISC-V syscall exit delivery path | ✅ thread/group delivery, masks, default actions, signal frames | `tests/shared/signal_restart.c`; syscall exit tests | `src/proc/signal.rs`, `src/syscall/signal_nr.rs` | Keep user-frame layout compatible with the libc shim/musl expectations. |
| SMP | ✅ PSCI/topology-based bring-up represented in tree | ✅ hart startup modules represented in tree | ✅ AP startup/per-CPU infrastructure represented in tree | boot logs, scheduler tests, architecture smoke | `src/smp/*`, `src/arch/x86_64/ap_boot.s`, `src/arch/riscv64/smp.rs`, `src/arch/aarch64/smp.rs`, `src/firmware/{psci,topology}.rs` | Multi-core stability depends on firmware topology quality and per-board IRQ routing. |
| GDB stub | ✅ AArch64 register layout | ✅ RISC-V register layout | ✅ x86_64 register layout | GDB connect smoke | `src/debug/gdbstub/` | |
| Device model | ✅ virtio-MMIO-oriented QEMU path | ✅ virtio-MMIO-oriented QEMU path | ✅ PCI, virtio, block, GPU/input/net classes | QEMU with optional disk/net/GPU; userspace smoke | `src/device/*`, `src/drivers/*`, `src/block/*` | x86_64 uses PCI devices in QEMU; ARM/RISC-V virt machines use MMIO devices. |
