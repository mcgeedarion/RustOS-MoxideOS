# tests/arch/aarch64/

Architecture-specific tests for the AArch64 kernel port.

## Scope

Tests in this directory exercise code paths that exist only on AArch64 or
behave differently enough to warrant arch-specific validation:

| Subsystem | What to test |
|---|---|
| Boot | DTB / UEFI handoff, EL2→EL1 transition, exception vector table |
| Interrupts | GICv2/GICv3 distributor + CPU interface init, SGI/PPI/SPI routing |
| Memory | 4-level (48-bit VA) paging, ASID management, MAIR attributes |
| Syscall | `SVC #0` entry path, `TPIDR_EL0` TLS setup |
| Platform | ARM generic timer (`CNTPCT_EL0`), PSCI CPU-on / CPU-off |
| SMP | PSCI `CPU_ON` AP bringup, per-CPU `MPIDR` affinity, `ap_entry_aarch64` |

## Running

```bash
# Future: arch-specific runner
ARCH=aarch64 ./tests/arch/aarch64/run_arch_tests.sh
```

## Status

Arch-specific test stubs are pending.  Coverage is currently provided by:
- `tests/shared/` — syscall-level stress tests cross-compiled for AArch64
- In-kernel `#[cfg(target_arch = "aarch64")]` unit tests via `--features kmtest`
- `qemu-smoke.yml` — virt/cortex-a72 boot + NIC probe on every push
