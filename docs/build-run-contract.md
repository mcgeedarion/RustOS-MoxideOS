# Build and run contract

RustOS supports a small explicit matrix of architecture and boot combinations.  Use these names consistently in `xtask`, CI, and QEMU scripts.

| Architecture | Boot modes |
| --- | --- |
| `aarch64` | `uefi`, `baremetal` |
| `riscv64` | `uefi`, `sbi` |
| `x86_64` | `uefi` |

Notes:

- Do not use `sbi` for aarch64 or x86_64.

## Canonical ESP path

UEFI artifacts are staged under:

```text
target/esp/<arch>/EFI/BOOT/BOOT*.EFI
```

Examples:

```text
target/esp/aarch64/EFI/BOOT/BOOTAA64.EFI
target/esp/riscv64/EFI/BOOT/BOOTRISCV64.EFI
target/esp/x86_64/EFI/BOOT/BOOTX64.EFI
```

## Common commands

```bash
cargo xtask build --arch aarch64 --boot uefi
cargo xtask build --arch aarch64 --boot baremetal
cargo xtask build --arch riscv64 --boot sbi
cargo xtask build --arch riscv64 --boot uefi
cargo xtask build --arch x86_64 --boot uefi
```

QEMU smoke/kmtest use OVMF UEFI image boots:

```bash
ARCH=riscv64 ./scripts/ci/run_qemu.sh --boot sbi --smoke
ARCH=riscv64 ./scripts/ci/run_qemu.sh --boot sbi --test
ARCH=x86_64 ./scripts/ci/run_qemu.sh --boot uefi --smoke
ARCH=x86_64 ./scripts/ci/run_qemu.sh --boot uefi --test
```

AArch64 initramfs, smoke, and kmtest paths are intentionally disabled until `userspace/Makefile` grows `ARCH=aarch64` support.
