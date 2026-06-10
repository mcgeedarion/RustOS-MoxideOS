# tests/

Unified multi-architecture test tree for RustOS.

## Layout

```
tests/
  shared/                  # Architecture-independent tests
    run_tests.sh           # Arch-aware build + run driver (ARCH=<arch>)
    run_smoke.sh           # Minimal smoke binary build + sanity check
    test_helpers.h         # Shared C macros (PASS / FAIL / SKIP / ASSERT)
    *.c                    # Syscall-level stress tests (compile + run on any arch)
  arch/
    x86_64/
      README.md            # x86_64-specific test inventory
    aarch64/
      README.md            # AArch64-specific test inventory
    riscv64/
      README.md            # RISC-V-specific test inventory
```

## Running shared tests

Shared tests are pure C programs compiled with a musl cross-toolchain and
executed against the running kernel via an initramfs.  They are
architecture-neutral at the source level but compiled separately for each
target.

```bash
# Host build + smoke run (x86_64 native musl)
ARCH=x86_64  ./tests/shared/run_tests.sh

# Cross-compile for AArch64
ARCH=aarch64 ./tests/shared/run_tests.sh

# Cross-compile for RISC-V
ARCH=riscv64 ./tests/shared/run_tests.sh
```

Build artefacts land under `build_tests/<arch>/` so outputs from different
architectures never collide.

## Architecture-specific tests

Tests that exercise arch-specific code paths (MMU layout, interrupt
controller, trap frame format, platform timer, SBI/UEFI specifics) live
under `tests/arch/<arch>/`.  See the per-arch `README.md` for the test
inventory and how to run them.

## CI integration

Shared tests are compiled and executed as part of the `kmtest` CI job for
every supported architecture via `.github/workflows/kmtest.yml` →
`.github/workflows/kernel-test.yml`.  Architecture-specific tests are
validated by the same matrix job using the per-arch test directories.

## Adding a new architecture

1. Add a `tests/arch/<newarch>/` directory with a `README.md`.
2. Add a matrix row in `.github/workflows/kmtest.yml`.
3. Ensure `tests/shared/run_tests.sh` knows the cross-compiler for `<newarch>`
   (add a case to the `CC` selection block).
