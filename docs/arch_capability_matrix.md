# RustOS Architecture Capability Matrix

Tracks feature parity between `x86_64`, `riscv64`, and `aarch64` (ARM64).

| Subsystem | x86_64 | riscv64 | aarch64 / ARM64 | Test Coverage | Owner | Risk / Notes |
|---|---|---|---|---|---|---|
| Boot path | ✅ UEFI + kernel entry | ✅ UEFI + SBI/kernel entry | ⚠️ UEFI entry + early halt loop | smoke (`xtask smoke`) | arch | ARM64 baseline requires UEFI firmware |
| Trap / IRQ | ✅ IDT/APIC path | ✅ trap/PCLIC/CLINT path | ⚠️ GICv2/GICv3 bring-up primitives | architecture smoke/manual | arch + irq | ARM64 accepts GICv2 or GICv3, matching ReactOS baseline |
| Paging / VM | ✅ x86_64 paging | ✅ riscv64 paging | ⚠️ 4 KiB / 48-bit stage-1 helpers | memory tests + boot | mm | Complete page-fault integration needed |
| Syscall ABI | ✅ arch syscall entry | ✅ arch syscall entry | ❌ not implemented | userspace tests + syscall matrix | syscall | Add SVC ABI + userspace trampoline |
| SMP | ✅ AP startup | ✅ hart startup | ❌ PSCI bring-up pending | boot + scheduler tests | smp | UEFI/ACPI CPU discovery needed |
| Timers | ✅ HPET/TSC path | ✅ CLINT/time path | ⚠️ CNTVCT read helper only | timerfd + sleep tests | time | Wire generic timer IRQ through GIC |

## Update policy

- Update this table when adding/changing arch features.
- Link each row to concrete tests once available.
- Mark unknown/incomplete status explicitly (⚠️).
