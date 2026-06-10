# Build and run contract

RustOS supports a small explicit matrix of architecture and boot combinations.  Use these names consistently in `xtask`, CI, and QEMU scripts.

| Architecture | Boot modes |
| --- | --- |
| `x86_64` | `uefi`, `multiboot` |
| `riscv64` | `uefi`, `sbi` |
| `aarch64` | `uefi`, `baremetal` |

Aliases:

- `qemu` is accepted as a backwards-compatible alias for `x86_64 --boot multiboot` in `scripts/ci/qemu-run.sh` only.
- Do not use `sbi` for x86_64 or AArch64.

## Canonical ESP path

UEFI artifacts are staged under:

```text
target/esp/<arch>/EFI/BOOT/BOOT*.EFI
```

Examples:

```text
target/esp/x86_64/EFI/BOOT/BOOTX64.EFI
target/esp/riscv64/EFI/BOOT/BOOTRISCV64.EFI
target/esp/aarch64/EFI/BOOT/BOOTAA64.EFI
```

## Common commands

```bash
cargo xtask build --arch x86_64 --boot uefi
cargo xtask build --arch x86_64 --boot multiboot
cargo xtask build --arch riscv64 --boot sbi
cargo xtask build --arch riscv64 --boot uefi
cargo xtask build --arch aarch64 --boot uefi
cargo xtask build --arch aarch64 --boot baremetal
```

QEMU smoke/kmtest currently use direct `-kernel` style boots only:

```bash
ARCH=x86_64 ./scripts/ci/qemu-run.sh --boot multiboot --smoke
ARCH=x86_64 ./scripts/ci/qemu-run.sh --boot multiboot --test
ARCH=riscv64 ./scripts/ci/qemu-run.sh --boot sbi --smoke
ARCH=riscv64 ./scripts/ci/qemu-run.sh --boot sbi --test
```

AArch64 initramfs, smoke, and kmtest paths are intentionally disabled until `userspace/Makefile` grows `ARCH=aarch64` support.
