# RustOS Hybrid Kernel Architecture

RustOS is a **hybrid kernel**.  It keeps latency-sensitive and
security-critical mechanisms in privileged code while allowing driver-like
services and resource providers to run as isolated userspace servers through
kernel-mediated IPC, schemes, and capability-checked handles.

This model intentionally combines two operating-system styles:

- **Monolithic fast paths** for components that need direct access to CPU state,
  address spaces, interrupts, scheduler data, or VFS internals.
- **Microkernel-style service isolation** for drivers and resource servers that
  benefit from process boundaries, restartability, and capability checks.

The machine-readable contract for this split lives in
`src/kernel/architecture.rs`, where `KERNEL_ARCHITECTURE` is set to
`KernelArchitecture::Hybrid` and logged from the common `kernel_main` path.

---

## Privileged kernel core

The following subsystems remain in kernel space:

| Area | Reason |
|---|---|
| Architecture HAL, traps, syscalls, and context switching | Requires privileged CPU state and exact register-frame ownership. |
| Physical/virtual memory management | Owns address spaces, page tables, COW, mmap, faults, kernel stacks, and swap/KASAN hooks. |
| Scheduler and process model | Needs direct run-queue, signal, wait/reaping, namespace, cgroup, and task-state access. |
| Interrupt-controller routing | Masks, acknowledges, and routes hardware interrupts safely. |
| VFS, file descriptors, and core filesystems | Provides the common path-resolution and file API used by both native and proxied schemes. |
| Network stack fast path | Keeps common socket and packet-processing paths efficient. |
| Security enforcement | Applies capabilities, DAC checks, namespaces, seccomp, ASLR/canary, cgroup policy, and LSM-style hooks. |
| Kernel debugging/test hooks | Provides panic/oops/trace/GDB/kmtest facilities that must work before userspace is healthy. |

These pieces form the stable, trusted computing base of RustOS.

---

## Userspace service plane

Drivers and resource providers may run outside the kernel when they can tolerate
an IPC boundary and can be represented through a named scheme.  A userspace
service typically follows this lifecycle:

1. A privileged process calls `sys_driver_bind` to claim a device and receive a
   typed `DriverHandle`.
2. It maps device resources through driver syscalls instead of touching raw
   kernel state directly.
3. It allocates DMA buffers with `sys_dma_alloc`, receiving both a userspace VA
   and physical address for device programming.
4. It subscribes to interrupts with `sys_irq_subscribe`; the kernel posts
   `IrqNotification` messages to the service endpoint and requires explicit IRQ
   acknowledgement through `sys_irq_ack`.
5. It registers a named scheme with `sys_scheme_register`, such as `net` or
   `blk`, binding the scheme name to an owned IPC endpoint.
6. Normal processes use file operations such as `open`, `read`, `write`,
   `ioctl`, and `close`; the VFS routes those operations to either an in-kernel
   scheme handler or an `IpcProxyScheme` backed by the userspace service.

This gives RustOS one application-facing resource namespace while preserving
process isolation for services that do not need to live permanently in the
kernel.

---

## Boundary rules

New subsystems should follow these rules:

1. Keep mandatory CPU, memory, scheduler, interrupt ownership, VFS core, and
   security mechanisms in the kernel.
2. Prefer a userspace service when a component is device-specific, restartable,
   or security-sensitive and can be represented as a scheme.
3. Expose resources through the scheme table instead of adding ad-hoc syscall
   paths for each service.
4. Gate privileged userspace services through capabilities, process ownership,
   endpoint ownership, and typed handles.
5. Route interrupts, MMIO, and DMA through kernel APIs so the kernel remains the
   owner of isolation and revocation.
6. Keep the userspace protocol stable by updating `crates/scheme-api` and the
   libc shim headers together when syscall or message layouts change.

---

## Existing implementation hooks

| Hook | Role |
|---|---|
| `src/kernel/architecture.rs` | Declares `KernelArchitecture::Hybrid`, the canonical hybrid contract, and the boot-time architecture log. |
| `src/syscall/driver.rs` | Provides driver binding, handle validation, DMA allocation, IRQ subscription, and IRQ acknowledgement dispatch. |
| `src/syscall/scheme.rs` | Lets privileged userspace services publish named schemes backed by owned IPC endpoints. |
| `src/syscall/routers.rs` | Routes RustOS-private driver/scheme syscall numbers into the service-plane modules. |
| `src/fs/scheme_table.rs` | Provides the shared registry for native in-kernel and userspace-backed scheme providers. |
| `src/fs/ipc_proxy_scheme.rs` | Proxies VFS-style scheme operations to a userspace service over IPC. |
| `src/ipc/mod.rs` | Provides endpoint queues used by both VFS proxy traffic and IRQ notifications. |
| `crates/scheme-api/src/lib.rs` | Defines shared request/response, handle, endpoint, and notification types for kernel and userspace services. |
| `userspace/musl/sysroot/include/sys/rustos.h` | Exposes libc-shim wrappers for RustOS-private driver, IPC, and scheme syscalls. |
| `userspace/drivers/virtio_net/main.rs` | Demonstrates a userspace virtio-net service that binds a device, sets up DMA/IRQ plumbing, and publishes a `net` scheme. |
| `src/init/service_manager.rs` | Tracks service descriptors, capabilities, restartability, and process-exit restart state. |

Together these pieces ensure RustOS is not purely monolithic: the privileged core
remains fast and predictable, while selected drivers and resource servers can be
moved across the kernel/userspace boundary without changing the application file
API.

---

## Implementation details

The current service plane has concrete kernel plumbing for these behaviors:

- RustOS-private syscall numbers route driver binding, DMA allocation, IRQ
  subscription/acknowledgement, IPC endpoint operations, and scheme registration
  through the syscall routers.
- `sys_driver_bind` records per-process device leases and returns
  `DriverHandle` values that must match the owning PID for later DMA and IRQ
  operations.
- `sys_dma_alloc` allocates bounded, page-mapped DMA buffers, zeroes them before
  userspace visibility, and returns the information a userspace driver needs to
  program the device.
- IPC endpoints maintain separate kernel-to-server and server-to-kernel queues so
  VFS `IpcProxyScheme` calls and IRQ notifications can share one endpoint
  without confusing requests with replies.
- Scheme registration validates names, verifies endpoint ownership, rejects
  cross-process takeovers, and unregisters schemes automatically during process
  exit.
- The init service manager records selected userspace services, applies service
  capability sets, and marks restartable services pending when their process
  exits.

Driver placement remains a policy decision: a driver can stay in the kernel when
latency, early-boot availability, or trusted-core constraints dominate, and can
move to userspace when isolation and restartability are more important.

---

## Userspace virtio-net example

`userspace/drivers/virtio_net/main.rs` is the reference userspace-driver shape:

1. Bind a virtio-net device and convert the returned integer into
   `DriverHandle`.
2. Use DMA-aware buffers for virtqueue state and packet movement.
3. Subscribe to the device IRQ through the service endpoint.
4. Serve scheme requests from normal processes.
5. Publish the `net` scheme with `sys_scheme_register`.

This example is intentionally useful as a template for other restartable
drivers: keep unsafe hardware access local to the service, use typed kernel
handles for authority, and expose the driver through the same VFS/scheme surface
as in-kernel providers.
