# RustOS Boot Architecture Guideline

## Philosophy

RustOS shall support both UEFI and bare-metal boot paths, but UEFI shall be considered
the primary and long-term supported boot mechanism.

The bare-metal path exists to support:

- Development and debugging
- Specialized hardware platforms
- Firmware-independent testing
- Embedded and research environments

The operating system shall maintain a single kernel initialization path regardless of
how the system boots.

---

## Architectural Principle

Boot methods are responsible only for platform bring-up and transferring control to
the kernel. All operating system initialization must occur through a shared kernel
initialization sequence.

```
UEFI Entry
    \
     \
      --> Common Kernel Init --> Scheduler --> Drivers --> Userspace
     /
    /
Bare Metal Entry
```

Boot-specific code should be minimized and isolated.

---

## Supported Architectures

### x86_64

| Priority   | Boot Method              |
|------------|--------------------------|
| Primary    | UEFI                     |
| Secondary  | Bare-metal bootloader    |

### ARM64 (AArch64)

| Priority   | Boot Method              |
|------------|--------------------------|
| Primary    | UEFI                     |
| Secondary  | Direct firmware/board entry |

### RISC-V

| Priority   | Boot Method              |
|------------|--------------------------|
| Primary    | UEFI where available; SBI-compliant firmware |
| Secondary  | Bare-metal board entry   |

---

## Boot Layer Responsibilities

### UEFI Entry

**Responsible for:**

- Obtain memory map
- Initialize framebuffer/GOP
- Load kernel image
- Collect boot information
- `ExitBootServices()`
- Transfer control to kernel

**Must NOT:**

- Initialize schedulers
- Start drivers
- Create processes
- Perform platform-independent kernel work

### Bare-Metal Entry

**Responsible for:**

- Establish stack
- Configure minimum CPU state
- Discover memory
- Initialize serial console
- Build boot information structure
- Transfer control to kernel

**Must NOT:**

- Duplicate kernel initialization
- Perform driver initialization
- Start scheduler

---

## Unified Boot Information Structure

All boot methods must produce the same structure:

```rust
pub struct BootInfo {
    pub memory_map: MemoryMap,
    pub framebuffer: Option<Framebuffer>,
    pub command_line: Option<String>,
    pub architecture: Architecture,
    pub boot_method: BootMethod,
}
```

This structure is the contract between the boot layer and the kernel. The kernel must
not care whether the system was started by UEFI or a bare-metal loader.

---

## Common Kernel Initialization

Every boot path must enter:

```rust
kernel_main(boot_info: &'static BootInfo)
```

Kernel initialization sequence:

```
kernel_main()
    ↓
cpu_init()
    ↓
memory_manager_init()
    ↓
interrupts_init()
    ↓
timer_init()
    ↓
scheduler_init()
    ↓
driver_manager_init()
    ↓
userspace_init()
```

No architecture should bypass this sequence.

---

## Architecture Separation

Architecture-specific code must remain confined to:

```
kernel/
├── arch/
│   ├── x86_64/
│   ├── aarch64/
│   └── riscv64/
```

Architecture-specific responsibilities:

- Context switching
- Interrupt handling
- MMU / page tables
- CPU feature detection
- Timer implementation
- Low-level synchronization

Everything else should be architecture-independent.

---

## Driver Initialization

Drivers must never depend on the boot method.

```rust
// Bad
if booted_via_uefi {
    init_nvme();
}

// Good
driver_manager.initialize();
```

Drivers should operate solely on kernel-provided abstractions.

---

## Long-Term Maintenance Rule

When adding a new subsystem:

1. Implement it once.
2. Place it in the common kernel.
3. Do not duplicate functionality for UEFI and bare-metal paths.

If code must exist in both paths, it likely belongs in the common kernel instead.

---

## Future Expansion

The architecture must accommodate future boot methods without changes to the shared
kernel:

| Boot Method      | Converges into  |
|------------------|-----------------|
| UEFI             | `kernel_main()` |
| BIOS             | `kernel_main()` |
| Coreboot         | `kernel_main()` |
| SBI              | `kernel_main()` |
| Custom Loader    | `kernel_main()` |
| Hypervisor Loader| `kernel_main()` |

No new boot method may require changes to the scheduler, drivers, memory management,
or userspace initialization.

---

## Project Policy

1. UEFI is the primary supported boot path.
2. Bare-metal support is retained as a minimal secondary path.
3. All boot methods must converge into a single kernel initialization sequence.
4. Kernel subsystems must remain boot-method agnostic.
5. Architecture-specific code must be isolated from platform-independent code.
6. No subsystem may require separate UEFI and bare-metal implementations unless
   technically unavoidable.
7. Long-term development effort should focus on improving the shared kernel rather
   than expanding boot-specific logic.

This approach scales across x86_64, ARM64, and RISC-V while avoiding the maintenance
burden of two separate OS initialization paths.
