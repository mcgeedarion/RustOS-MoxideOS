# RustOS status matrix

This file is the short, test-oriented status page for RustOS.  It is meant to
answer three questions for each vertical slice:

1. what is expected to work today,
2. which command proves it, and
3. what is still missing or risky.

Status legend:

- ✅ **Known-good**: routinely buildable/testable with the listed command.
- 🟡 **Partial**: code exists and may boot or compile, but gaps remain.
- 🔴 **Planned/WIP**: design or scaffolding exists, but it is not a reliable
  vertical slice yet.

| Slice | Status | Verification command | Known gaps / notes |
| --- | --- | --- | --- |
| x86_64 UEFI boot to serial | 🟡 Partial | `./run_qemu.sh --smoke --timeout 20` | Requires pinned nightly, QEMU, and OVMF.  The smoke marker is currently `TEST PASS: uart_smoke`, so this proves early kernel serial boot, not full userspace. |
| x86_64 multiboot2 fallback | 🟡 Partial | `./run_qemu.sh --multiboot --smoke --timeout 20` | Useful for `-kernel` testing; does not exercise the UEFI PE image path. |
| RISC-V virt boot | 🟡 Partial | `./run_qemu_riscv.sh` | Needs a matching QEMU/rust target setup; smoke automation is still x86_64-only. |
| `scheme-api` shared crate | ✅ Known-good | `cargo test --manifest-path crates/scheme-api/Cargo.toml` | Keep this crate small and ABI-conscious because it is shared by kernel-adjacent code and userspace drivers. |
| Initramfs + `/init` | 🟡 Partial | `./tools/build_userspace.sh && ./tools/build_initramfs.sh && ./run_qemu.sh --smoke --smoke-marker '[init] TEST PASS: userspace_init' --timeout 30` | Depends on musl userspace and enough syscalls for PID 1 to run. |
| musl hello/init userspace | 🟡 Partial | `make -C userspace` | Requires the local musl/sysroot setup documented in `docs/musl_pipeline.md`. |
| fork/exec/wait | 🟡 Partial | `./tests/run_tests.sh` | Host/kernel coverage should be promoted into CI once the toolchain is reproducible. |
| futex/pthread basics | 🟡 Partial | `./tests/run_tests.sh` | Needs continued stress testing under QEMU and with musl userspace. |
| VFS + scheme dispatch | 🟡 Partial | `cargo check --target x86_64-unknown-none -Z build-std=core,alloc,compiler_builtins -Z build-std-features=compiler-builtins-mem` | Many filesystems/schemes exist; status should be split by mount type as tests mature. |
| Userspace virtio-net driver | 🔴 Planned/WIP | `cargo check --manifest-path userspace/drivers/virtio_net/Cargo.toml` | Driver architecture is promising, but end-to-end kernel binding, DMA, IRQ, and scheme registration need proof. |
| Networking stack | 🟡 Partial | `./run_qemu.sh --smoke --timeout 20` plus targeted network tests | Smoke boot currently disables networking by default; add packet/socket tests before calling this stable. |
| Security hooks / LSM / credentials | 🟡 Partial | Review `docs/security_audit.md` and run syscall/security tests as they are added | High-risk authorization gaps remain documented; prioritize closing them before widening the syscall surface. |
| Display / DRM / Wayland | 🔴 Planned/WIP | `cargo check --features wayland --target x86_64-unknown-none -Z build-std=core,alloc,compiler_builtins -Z build-std-features=compiler-builtins-mem` | Keep behind feature flags until DRM, input, shared memory, and compositor supervision are proven. |

## Near-term gates

The next useful CI gates are:

1. `cargo fmt --check`
2. `cargo test --manifest-path crates/scheme-api/Cargo.toml`
3. `cargo check --manifest-path userspace/drivers/virtio_net/Cargo.toml`
4. `cargo check --target x86_64-unknown-none -Z build-std=core,alloc,compiler_builtins -Z build-std-features=compiler-builtins-mem`
5. `./run_qemu.sh --smoke --timeout 20`

The smoke test is intentionally marker-based.  As the userspace path stabilizes,
move the default marker from the early kernel UART check to the PID 1 marker:
`[init] TEST PASS: userspace_init`.
