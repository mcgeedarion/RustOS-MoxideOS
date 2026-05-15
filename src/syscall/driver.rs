//! Driver syscalls — three new kernel entry points that let a userspace
//! driver process claim hardware, allocate DMA memory, and subscribe to
//! hardware interrupts without any driver code running in ring 0.
//!
//! # Syscall numbers (provisional — add to your master SyscallNumber enum)
//!
//! | Number | Name                |
//! |--------|---------------------|
//! | 400    | `sys_driver_bind`   |
//! | 401    | `sys_dma_alloc`     |
//! | 402    | `sys_irq_subscribe` |
//!
//! # Safety
//!
//! These functions are called from the syscall dispatch table with
//! arguments already validated to be in userspace-accessible memory.
//! Pointer arguments that cross the kernel/user boundary are validated
//! via `validate_user_ptr` before any dereference.

use crate::{
    kernel::capabilities::Capability,
    mm::{dma_alloc_coherent, PhysAddr, VirtAddr},
    proc::current_process,
};
use scheme_api::{DriverHandle, IpcEndpoint};

/// Errors that these syscalls can return (mapped to errno at the boundary).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i64)]
pub enum DriverSysError {
    /// Caller does not hold `CAP_DRIVER`.
    PermissionDenied = -1,
    /// The requested PCI BDF does not exist or is already owned.
    NxDevice = -2,
    /// DMA allocation failed (out of physically contiguous memory).
    NoMem = -3,
    /// `irq` is out of range or already subscribed by another process.
    InvalidIrq = -4,
    /// Argument pointer is not a valid userspace address.
    BadAddress = -14,
}

// ---------------------------------------------------------------------------
// sys_driver_bind
// ---------------------------------------------------------------------------

/// Claim ownership of a PCI device identified by its BDF (Bus/Device/Function)
/// encoded as `(bus << 16) | (dev << 8) | func`.
///
/// On success the kernel:
/// 1. Verifies the calling process holds `CAP_DRIVER`.
/// 2. Marks the device as owned by this process in the PCI device table.
/// 3. Maps the device's MMIO BARs read/write into the calling process's
///    address space.
/// 4. Returns a `DriverHandle` that authorises subsequent DMA and IRQ
///    syscalls for this device.
///
/// # Arguments
/// - `bdf`       — PCI Bus/Device/Function (24-bit encoded).
/// - `cap_flags` — requested capabilities bitmask (currently reserved; pass 0).
pub fn sys_driver_bind(bdf: u32, cap_flags: u32) -> Result<DriverHandle, DriverSysError> {
    let proc = current_process();

    // Capability check: caller must hold CAP_DRIVER.
    if !proc.capabilities().has(Capability::Driver) {
        return Err(DriverSysError::PermissionDenied);
    }

    // Locate the device in the PCI device tree.
    let pci_dev = crate::drivers::pcie::find_device_by_bdf(bdf).ok_or(DriverSysError::NxDevice)?;

    // Atomically claim ownership; fails if another process already owns it.
    pci_dev
        .try_claim(proc.pid())
        .map_err(|_| DriverSysError::NxDevice)?;

    // Map each BAR into the caller's address space.
    for bar in pci_dev.bars() {
        if let Some(mmio) = bar.as_mmio() {
            proc.vm_map_mmio(mmio.phys_base, mmio.size)
                .map_err(|_| DriverSysError::NoMem)?;
        }
    }

    // Mint and return a driver handle bound to (pid, bdf).
    let handle = DriverHandle(((proc.pid() as u64) << 32) | (bdf as u64));
    log::debug!(
        "[driver] pid {} bound to BDF {:06x} handle={:?}\n",
        proc.pid(),
        bdf,
        handle
    );
    Ok(handle)
}

// ---------------------------------------------------------------------------
// sys_dma_alloc
// ---------------------------------------------------------------------------

/// Allocate a physically contiguous DMA buffer and map it into the calling
/// process's address space.
///
/// Returns a `(virt, phys)` pair.  The virtual address is valid in the
/// calling process's address space.  The physical address can be
/// programmed directly into device DMA descriptor rings.
///
/// # Arguments
/// - `handle` — `DriverHandle` from a prior `sys_driver_bind` call.
/// - `size`   — number of bytes to allocate (rounded up to page size).
/// - `align`  — physical alignment in bytes (must be a power of two,
///              minimum 4096).
///
/// # Safety note for callers
/// The returned physical address aliases the returned virtual mapping.
/// Do **not** also map it via `mmap`; use only the returned virt pointer.
pub fn sys_dma_alloc(
    handle: DriverHandle,
    size: usize,
    align: usize,
) -> Result<(VirtAddr, PhysAddr), DriverSysError> {
    let proc = current_process();

    // Validate that this handle belongs to the calling process.
    let owner_pid = (handle.0 >> 32) as u32;
    if owner_pid != proc.pid() {
        return Err(DriverSysError::PermissionDenied);
    }

    if !align.is_power_of_two() || align < 4096 {
        return Err(DriverSysError::BadAddress);
    }

    // Allocate physically contiguous pages.
    let (phys, virt_kernel) = dma_alloc_coherent(size, align).ok_or(DriverSysError::NoMem)?;

    // Map the pages into the user process's address space.
    let virt_user = proc
        .vm_map_phys(phys, size, /* rw */ true)
        .map_err(|_| DriverSysError::NoMem)?;

    // Zero the buffer before handing it to userspace.
    unsafe {
        core::ptr::write_bytes(virt_kernel.as_mut_ptr::<u8>(), 0, size);
    }

    log::debug!(
        "[driver] DMA alloc pid {} size=0x{:x} phys={:?} virt={:?}\n",
        proc.pid(),
        size,
        phys,
        virt_user
    );
    Ok((virt_user, phys))
}

// ---------------------------------------------------------------------------
// sys_irq_subscribe
// ---------------------------------------------------------------------------

/// Route hardware interrupts for `irq` as `IrqNotification` messages to
/// `endpoint` instead of running a kernel ISR.
///
/// When the IRQ fires the kernel will:
/// 1. Mask the IRQ at the interrupt controller (APIC / PLIC).
/// 2. Post an `IrqNotification { irq, timestamp_ns }` message to `endpoint`.
/// 3. The driver process receives the message, handles the interrupt, then
///    calls `sys_irq_ack(handle, irq)` to unmask it.
///
/// # Arguments
/// - `handle`   — `DriverHandle` authorising access to this IRQ.
/// - `irq`      — IRQ line to subscribe (MSI vector or legacy IRQ number).
/// - `endpoint` — `IpcEndpoint` that will receive `IrqNotification` messages.
pub fn sys_irq_subscribe(
    handle: DriverHandle,
    irq: u32,
    endpoint: IpcEndpoint,
) -> Result<(), DriverSysError> {
    let proc = current_process();

    let owner_pid = (handle.0 >> 32) as u32;
    if owner_pid != proc.pid() {
        return Err(DriverSysError::PermissionDenied);
    }

    // Register the IRQ → endpoint mapping in the interrupt routing table.
    crate::kernel::irq::subscribe_userspace(irq, endpoint)
        .map_err(|_| DriverSysError::InvalidIrq)?;

    log::info!(
        "[driver] pid {} subscribed IRQ {} → endpoint {:?}\n",
        proc.pid(),
        irq,
        endpoint
    );
    Ok(())
}
