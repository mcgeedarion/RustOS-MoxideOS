# tests/arch/riscv64/

Architecture-specific tests for the RISC-V 64-bit kernel port.

## Scope

Tests in this directory exercise code paths that exist only on RISC-V or
behave differently enough to warrant arch-specific validation:

| Subsystem | What to test |
|---|---|
| Boot | OpenSBI handoff, `_start` → `kernel_main` path, S-mode entry |
| Interrupts | PLIC init, AP context programming, `stvec` trap vector setup |
| Memory | Sv39/Sv48 page-table walk, ASID management, `satp` CSR switch |
| Syscall | `ecall` entry path, `sscratch` / `tp` per-CPU pointer setup |
| Platform | SBI timer extension (`sbi_set_timer`), `rdtime` CSR |
| SMP | SBI HSM `hart_start`, AP `ap_entry_riscv`, per-hart PLIC context |

## Running

```bash
# Future: arch-specific runner
ARCH=riscv64 ./tests/arch/riscv64/run_arch_tests.sh
```

## Status

Arch-specific test stubs are pending.  Coverage is currently provided by:
- `tests/shared/` — syscall-level stress tests cross-compiled for RISC-V
- In-kernel `#[cfg(target_arch = "riscv64")]` unit tests via `--features kmtest`
- `qemu-smoke.yml` — OpenSBI virt `-smp 2` boot + PLIC/SMP probes on every push
