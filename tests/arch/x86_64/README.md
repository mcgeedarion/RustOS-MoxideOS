# x86_64 kernel test notes

| Subsystem | What to test |
|---|---|
| Boot | UEFI handoff, GDT/IDT setup |
| Interrupts | APIC init, legacy PIC masking, `abi_x86_interrupt` handlers |
| Memory | 4-level paging, PAT, large-page mappings, NX bit |
| Syscall | `SYSCALL`/`SYSRET` entry path, `FS.base` TLS setup |
