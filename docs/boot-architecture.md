# RustOS Boot Architecture Guideline

## Philosophy

RustOS supports multiple firmware and direct-kernel boot paths, but all of them
must converge into one small handoff contract and one common kernel entry point.
Boot code should discover platform facts, build `init::boot_info::BootInfo`, and
then jump to `kernel_main(&BootInfo)`.

UEFI is the primary long-term firmware path for removable-media and QEMU image
flows.  Direct-kernel paths remain useful for firmware-independent testing,
OpenSBI/FDT development, board bring-up, and low-level debugging.

---

## Architectural principle

Boot methods are responsible only for platform bring-up and transferring control
to the kernel.  All operating-system initialization must occur through the shared
kernel path.

```text
UEFI entry
    \
     \
      -> BootInfo -> kernel_main() -> arch::init() -> shared subsystems
     /
    /
SBI / FDT / direct-kernel entry
```

Boot-specific code must be minimized and isolated.  It should not duplicate the
scheduler, VFS, memory manager, security setup, userspace launch, or driver
policy.

---

## Supported architecture boot paths

| Architecture | UEFI path | Direct / firmware-specific path | Default helper behavior |
|---|---|---|---|
| `aarch64` | `src/arch/aarch64/uefi_entry.rs`; removable path `EFI/BOOT/BOOTAA64.EFI` | Bare-metal kernel target for board loaders/U-Boot-style flows | QEMU launcher currently supports `--boot uefi`; `xtask` can also build the bare-metal kernel target. |
| `riscv64` | `src/arch/riscv64/uefi_entry.rs`; removable path `EFI/BOOT/BOOTRISCV64.EFI` | SBI/OpenSBI + FDT path through the RISC-V kernel target | QEMU accepts `--boot uefi` or `--boot sbi`. |
| `x86_64` | `src/arch/x86_64/uefi_entry.rs`; removable path `EFI/BOOT/BOOTX64.EFI` | — (multiboot2 path removed; OVMF UEFI is the sole boot method) | `cargo xtask build` defaults to `x86_64` + `uefi`; QEMU accepts `--boot uefi` only. |

---

## Boot layer responsibilities

### UEFI entries

UEFI entry code is responsible for:

- Capturing firmware tables such as the RSDP where available.
- Capturing UEFI memory-map metadata before `ExitBootServices()`.
- Discovering a GOP framebuffer when firmware provides one.
- Passing optional command line, initramfs, and FDT ranges when available.
- Switching to an architecture-appropriate boot stack when required.
- Calling `ExitBootServices()` and then jumping to `kernel_main`.

UEFI entry code must not:

- Start the scheduler.
- Mount filesystems.
- Launch userspace.
- Run platform-independent driver policy.
- Duplicate common kernel initialization.

### Direct-kernel / SBI / board entries

Direct entry code is responsible for:

- Establishing the minimum CPU state and stack required by the architecture.
- Discovering or receiving memory/FDT information from firmware.
- Initializing enough serial output for early diagnostics.
- Filling `BootInfo` fields that are meaningful for that platform.
- Jumping to `kernel_main`.

Direct entry code must not duplicate common subsystem initialization.

---

## Unified boot information structure

The canonical handoff ABI is `BootInfo` in `src/init/boot_info.rs`:

```rust
#[repr(C)]
pub struct BootInfo {
    pub rsdp_phys: u64,
    pub efi_memory_map: EfiMemoryMapInfo,
    pub framebuffer: FramebufferInfo,
    pub initramfs: BootRange,
    pub cmdline: BootRange,
    pub fdt: BootRange,
    pub boot_hart_id: usize,
}
```

Supporting structures:

- `BootRange { start, len }` describes physical ranges for blobs such as an
  initramfs, command line, or FDT.
- `EfiMemoryMapInfo { ptr, size, desc_size }` preserves the EFI memory map after
  `ExitBootServices()`.
- `FramebufferInfo` describes an optional firmware framebuffer.
- `BootInfo::priority()` labels the active architecture in the boot banner:
  `PRIMARY` for x86_64, `SECONDARY` for AArch64, and `TERTIARY` for RISC-V.

The kernel must not care whether these facts came from OVMF, EDK2, OpenSBI,
U-Boot, or a direct test harness.

---

## Common kernel entry

Every boot path must enter:

```rust
#[no_mangle]
pub extern "C" fn kernel_main(boot_info: &'static BootInfo) -> !
```

The common entry performs the architecture-independent dispatch contract:

```text
kernel_main(&BootInfo)
    -> print boot-priority banner
    -> log the hybrid-kernel architecture contract
    -> arch::init(&BootInfo)
    -> architecture-specific early init
    -> shared subsystem initialization
    -> initramfs / schemes / shell / userspace or idle loop
```

`src/arch/mod.rs` owns the compile-time architecture selection and exposes
`crate::arch::Arch` as the HAL alias for common code.

---

## Architecture separation

Architecture-specific code must remain under:

```text
src/arch/
├── aarch64/
├── riscv64/
└── x86_64/
```

Architecture-specific responsibilities include:

- CPU feature setup and context switching.
- Interrupt/trap/syscall entry.
- MMU and page-table operations.
- Boot stacks, early serial, and low-level assembly.
- Architecture timer and SMP hooks.

Common code should use `crate::arch::Arch` and types/traits from
`crate::arch::api` instead of importing `arch::aarch64`, `arch::riscv64`, or
`arch::x86_64` directly.

---

## Driver and userspace initialization

Drivers must not depend on the boot method.  A driver can depend on hardware
facts exposed by the device, bus, firmware table, or kernel abstractions, but it
should not branch on "booted via UEFI" versus "booted via SBI".

```rust
// Avoid boot-policy checks inside drivers.
if booted_via_uefi {
    init_nvme();
}

// Prefer a device/bus-driven initialization path.
driver_manager.initialize();
```

Likewise, userspace launch policy belongs in the common init/service path, not in
UEFI or board entry code.

---

## Long-term maintenance rule

When adding a new subsystem:

1. Implement it once in the common kernel when possible.
2. Keep only unavoidable CPU/firmware setup in the architecture entry.
3. Extend `BootInfo` only when all boot paths can tolerate the new field.
4. Update `docs/booting.md` and `docs/arch_capability_matrix.md` if a build,
   image, firmware, or validation flow changes.

If code must exist in both UEFI and direct paths, it probably belongs in the
common kernel or in an architecture HAL abstraction.
