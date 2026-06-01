# RustOS Hybrid Kernel Architecture

RustOS is a **hybrid kernel**.  The kernel keeps latency-sensitive and
security-critical mechanisms in privileged code, while allowing driver-like
services to run as isolated userspace servers through kernel-mediated IPC and
scheme routing.

This model intentionally combines two operating-system styles:

- **Monolithic fast paths** for components that need direct access to CPU state,
  address spaces, interrupts, and scheduler data.
- **Microkernel-style service isolation** for drivers and resource servers that
  benefit from process boundaries, restartability, and capability checks.

The machine-readable contract for this split lives in
`src/kernel/architecture.rs`.

---

## Privileged Kernel Core

The following subsystems remain in kernel space:

| Area | Reason |
|---|---|
| Architecture HAL, traps, and context switching | Requires privileged CPU state. |
| Physical/virtual memory management | Owns address spaces, page tables, and fault handling. |
| Scheduler and process model | Needs direct run-queue and task-state access. |
| Interrupt-controller routing | Masks, acknowledges, and routes hardware interrupts safely. |
| VFS and core filesystems | Provides the common file-descriptor and path-resolution model. |
| Network stack fast path | Keeps packet processing efficient for common sockets. |
| Security enforcement | Applies capabilities, namespaces, seccomp, and cgroup policy. |

These pieces form the stable, trusted computing base of RustOS.

---

## Userspace Service Plane

Drivers and resource providers may run outside the kernel when they can tolerate
an IPC boundary.  A userspace service typically follows this lifecycle:

1. A privileged process with driver capability calls `sys_driver_bind` to claim a
   PCI device and receive a `DriverHandle`.
2. It maps MMIO/DMA resources through driver syscalls instead of touching raw
   kernel state.
3. It subscribes to interrupts with `sys_irq_subscribe`; the kernel masks the IRQ
   and posts `IrqNotification` messages to the service endpoint.
4. It registers a named scheme with `sys_scheme_register`, such as `net:` or
   `blk:`.
5. Normal processes use `open`, `read`, `write`, `ioctl`, and `close`; the VFS
   routes those operations to either an in-kernel scheme or an `IpcProxyScheme`
   backed by the userspace service.

This gives RustOS a single resource namespace while preserving process isolation
for services that do not need to live permanently in the kernel.

---

## Boundary Rules

New subsystems should follow these rules:

1. Keep mandatory CPU, memory, scheduler, and security mechanisms in the kernel.
2. Prefer a userspace service when the component is device-specific,
   restartable, or security-sensitive and can be represented as a scheme.
3. Expose resources through the scheme table rather than adding ad-hoc syscall
   paths.
4. Gate privileged userspace services through capabilities and typed handles.
5. Route interrupts and DMA through kernel APIs so the kernel remains the owner
   of isolation and revocation.

---

## Existing Implementation Hooks

| Hook | Role |
|---|---|
| `src/kernel/architecture.rs` | Declares `KernelArchitecture::Hybrid` and the canonical hybrid contract. |
| `src/syscall/driver.rs` | Provides capability-checked driver binding, DMA allocation, and IRQ subscription. |
| `src/syscall/scheme.rs` | Lets privileged userspace services publish named schemes. |
| `src/fs/scheme_table.rs` | Provides the shared scheme registry for in-kernel and userspace-backed providers. |
| `src/fs/ipc_proxy_scheme.rs` | Proxies VFS-style scheme operations to userspace services over IPC. |
| `crates/scheme-api/src/lib.rs` | Defines the shared request/response protocol between kernel and userspace services. |
| `userspace/drivers/virtio_net/main.rs` | Demonstrates a userspace virtio-net service that binds a device and publishes `net:`. |

Together these pieces ensure RustOS is not purely monolithic: the privileged core
remains compact and fast, while drivers and resource servers can be moved across
the kernel/userspace boundary without changing the application-facing file API.
