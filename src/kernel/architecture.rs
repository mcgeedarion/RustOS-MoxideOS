//! Kernel architecture contract.
//!
//! RustOS uses a **hybrid kernel** architecture: latency-sensitive core
//! services remain in kernel space, while driver-like services can also run as
//! isolated userspace servers behind the same scheme and IPC abstractions used
//! by in-kernel providers.  Keeping this contract in code makes the intended
//! architecture explicit instead of relying only on README prose.

/// The high-level architecture selected for this kernel build.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KernelArchitecture {
    /// Hybrid kernel: monolithic fast paths plus microkernel-style userspace
    /// service isolation where the scheme/IPC boundary is appropriate.
    Hybrid,
}

/// Machine-readable description of the RustOS hybrid-kernel contract.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HybridKernelContract {
    /// Human-readable name shown in logs and diagnostics.
    pub name: &'static str,
    /// Privileged services intentionally kept in kernel space for direct,
    /// low-latency access to CPU, memory, interrupts, and scheduling state.
    pub in_kernel_services: &'static [&'static str],
    /// Services that may be provided by isolated userspace servers through
    /// kernel-mediated IPC, capabilities, and scheme routing.
    pub user_server_services: &'static [&'static str],
    /// The transport used to cross from kernel-space clients into userspace
    /// service providers.
    pub ipc_transport: &'static str,
    /// The resource namespace used to make in-kernel and userspace-backed
    /// services visible through one uniform open/read/write/ioctl interface.
    pub resource_routing: &'static str,
}

/// RustOS is intentionally built as a hybrid kernel.
pub const KERNEL_ARCHITECTURE: KernelArchitecture = KernelArchitecture::Hybrid;

// Fail compilation if the declared architecture ever stops satisfying the
// hybrid-kernel contract.
const _: () = assert!(is_hybrid_kernel());

/// The concrete hybrid-kernel split enforced by RustOS subsystems.
pub const HYBRID_KERNEL_CONTRACT: HybridKernelContract = HybridKernelContract {
    name: "RustOS hybrid kernel",
    in_kernel_services: &[
        "architecture HAL and traps",
        "memory management",
        "scheduler and process model",
        "interrupt controller routing",
        "VFS and core filesystems",
        "network stack fast path",
        "security policy enforcement",
    ],
    user_server_services: &[
        "PCI/virtio device drivers",
        "scheme-backed block and network endpoints",
        "display/compositor services",
        "optional filesystem or protocol servers",
    ],
    ipc_transport: "kernel IPC endpoints with capability-checked driver handles",
    resource_routing: "scheme table with IpcProxyScheme userspace forwarding",
};

/// Return `true` only for builds that declare the hybrid-kernel contract.
pub const fn is_hybrid_kernel() -> bool {
    matches!(KERNEL_ARCHITECTURE, KernelArchitecture::Hybrid)
}

/// Emit a concise boot-time diagnostic so QEMU logs identify the architecture.
pub fn log_kernel_architecture() {
    log::info!(
        "kernel architecture: {} (core services in-kernel, drivers/services via schemes + IPC)",
        HYBRID_KERNEL_CONTRACT.name
    );
}
