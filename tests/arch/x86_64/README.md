# tests/arch/x86_64/

Architecture-specific tests for the x86_64 kernel port.

## Scope

Tests in this directory exercise code paths that exist only on x86_64 or
behave differently enough to warrant arch-specific validation:

| Subsystem | What to test |
|---|---|
| Boot | Multiboot2 header presence, UEFI handoff, GDT/IDT setup |
| Interrupts | APIC init, legacy PIC masking, `abi_x86_interrupt` handlers |
| Memory | 4-level paging, PAT, large-page mappings, NX bit |
| Syscall | `SYSCALL`/`SYSRET` entry path, `FS.base` TLS setup |
| Platform | HPET / TSC deadline timer, RDTSC, CPUID feature checks |
| SMP | APIC IPI delivery, AP trampoline (`ap_entry_x86`), per-CPU init |

## Running

```bash
# Future: arch-specific runner
ARCH=x86_64 ./tests/arch/x86_64/run_arch_tests.sh
```

## Status

Arch-specific test stubs are pending.  Coverage is currently provided by:
- `tests/shared/` — syscall-level stress tests compiled for x86_64
- In-kernel `#[cfg(target_arch = "x86_64")]` unit tests via `--features kmtest`
- `qemu-smoke.yml` — OVMF UEFI boot + NIC probe on every push
