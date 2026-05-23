# RustOS Architecture Capability Matrix

Tracks feature parity between `x86_64` and `riscv64`.

| Subsystem | x86_64 | riscv64 | Test Coverage | Owner | Risk / Notes |
|---|---|---|---|---|---|
| Boot path | ✅ UEFI + kernel entry | ✅ UEFI + SBI/kernel entry | smoke (`xtask smoke`) | arch | Keep boot artifacts aligned |
| Trap / IRQ | ✅ IDT/APIC path | ✅ trap/PCLIC/CLINT path | architecture smoke/manual | arch + irq | Validate interrupt storm behavior |
| Paging / VM | ✅ x86_64 paging | ✅ riscv64 paging | memory tests + boot | mm | Keep page-fault behavior parity |
| Syscall ABI | ✅ arch syscall entry | ✅ arch syscall entry | userspace tests + syscall matrix | syscall | Track arg width/errno mismatches |
| SMP | ✅ AP startup | ✅ hart startup | boot + scheduler tests | smp | Verify hotplug + IPI parity |
| Timers | ✅ HPET/TSC path | ✅ CLINT/time path | timerfd + sleep tests | time | Latency consistency across arch |

## Update policy

- Update this table when adding/changing arch features.
- Link each row to concrete tests once available.
- Mark unknown/incomplete status explicitly (⚠️).
