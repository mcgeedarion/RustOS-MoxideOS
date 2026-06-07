//! Userspace-driver syscalls for the RustOS hybrid-kernel boundary.
//!
//! These calls let a privileged service process claim a PCI function, map its
//! BARs, allocate DMA memory, and receive IRQs as IPC notifications without
//! putting the device-specific driver in ring 0.

extern crate alloc;

use alloc::{collections::BTreeMap, vec::Vec};
use core::sync::atomic::{AtomicU64, Ordering};

use scheme_api::{DriverHandle, IpcEndpoint, IrqNotification};
use spin::Mutex;

use crate::arch::{
    api::{PageFlags, Paging},
    Arch,
};
use crate::device::pci::{self, PciDevice};
use crate::mm::{
    mmap::{self, Vma, VmaKind},
    phys, pmm,
};
use crate::security::{cap, CapSet};

const DRIVER_MMIO_BAR_SIZE: usize = mmap::PAGE;
const DRIVER_DMA_MAX_BYTES: usize = 16 * 1024 * 1024;
const DRIVER_HANDLE_MAGIC: u64 = 0xD1A0_0000_0000_0000;

/// Errors returned by userspace-driver syscalls.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i64)]
pub enum DriverSysError {
    PermissionDenied = -1,
    NxDevice = -2,
    NoMem = -3,
    InvalidIrq = -4,
    BadAddress = -14,
    InvalidHandle = -22,
}

impl DriverSysError {
    #[inline]
    fn as_isize(self) -> isize {
        self as i64 as isize
    }
}

#[derive(Clone, Debug)]
struct DriverLease {
    owner_pid: usize,
    bdf: u32,
    device: PciDevice,
    mapped_bars: Vec<(u8, usize, usize, usize)>, // bar, user va, phys, size
    dma_regions: Vec<(usize, usize, usize)>,     // user va, phys, size
    irq_endpoints: Vec<(u32, IpcEndpoint)>,
}

static NEXT_HANDLE: AtomicU64 = AtomicU64::new(1);
static DRIVER_LEASES: Mutex<BTreeMap<u64, DriverLease>> = Mutex::new(BTreeMap::new());
static DEVICE_OWNERS: Mutex<BTreeMap<u32, usize>> = Mutex::new(BTreeMap::new());
static IRQ_OWNERS: Mutex<BTreeMap<u32, (usize, u64, IpcEndpoint)>> = Mutex::new(BTreeMap::new());

#[inline]
fn current_pid() -> usize {
    crate::proc::scheduler::current_pid() as usize
}

fn current_caps() -> CapSet {
    crate::proc::scheduler::with_proc(current_pid(), |p| p.caps).unwrap_or_else(CapSet::empty)
}

fn has_driver_capability() -> bool {
    let caps = current_caps();
    caps.has(cap::DRIVER) || caps.has(cap::SYS_ADMIN)
}

fn mint_handle() -> u64 {
    DRIVER_HANDLE_MAGIC | NEXT_HANDLE.fetch_add(1, Ordering::Relaxed)
}

fn handle_id(handle: DriverHandle) -> Result<u64, DriverSysError> {
    if handle.0 & 0xFFFF_0000_0000_0000 != DRIVER_HANDLE_MAGIC {
        return Err(DriverSysError::InvalidHandle);
    }
    Ok(handle.0)
}

fn with_lease_mut<T>(
    handle: DriverHandle,
    f: impl FnOnce(&mut DriverLease) -> Result<T, DriverSysError>,
) -> Result<T, DriverSysError> {
    let hid = handle_id(handle)?;
    let pid = current_pid();
    let mut leases = DRIVER_LEASES.lock();
    let lease = leases.get_mut(&hid).ok_or(DriverSysError::InvalidHandle)?;
    if lease.owner_pid != pid {
        return Err(DriverSysError::PermissionDenied);
    }
    f(lease)
}

fn map_phys_to_user(
    pid: usize,
    phys_base: usize,
    size: usize,
    writable: bool,
) -> Result<usize, DriverSysError> {
    let size = mmap::page_align_up(size.max(mmap::PAGE));
    let (va, user_cr3) = mmap::with_mm_write(pid, |p| {
        let va = mmap::page_align_up(p.next_va);
        p.next_va = mmap::page_align_up(va + size + mmap::PAGE);
        (va, p.user_satp)
    })
    .ok_or(DriverSysError::NoMem)?;

    if va == 0 || user_cr3 == 0 {
        return Err(DriverSysError::NoMem);
    }

    let mut flags = PageFlags::PRESENT | PageFlags::USER | PageFlags::NX;
    if writable {
        flags = flags | PageFlags::WRITE;
    }
    for (i, page_va) in (va..va + size).step_by(mmap::PAGE).enumerate() {
        <Arch as Paging>::map_page(user_cr3, page_va, phys_base + i * mmap::PAGE, flags);
    }

    mmap::insert_vma(
        pid,
        Vma {
            start: va,
            end: va + size,
            prot: mmap::PROT_READ | if writable { mmap::PROT_WRITE } else { 0 },
            flags: mmap::MAP_SHARED,
            kind: VmaKind::PhysMap(phys_base as u64),
            file_offset: phys_base as u64,
            locked: true,
        },
    );
    Ok(va)
}

fn zero_phys_range(phys_base: usize, size: usize) {
    unsafe {
        core::ptr::write_bytes(phys::phys_to_virt(phys_base) as *mut u8, 0, size);
    }
}

/// Claim a PCI function and map its non-zero BARs into the caller.
pub fn sys_driver_bind(bdf: u32, _cap_flags: u32) -> Result<DriverHandle, DriverSysError> {
    if !has_driver_capability() {
        return Err(DriverSysError::PermissionDenied);
    }

    let pid = current_pid();
    let device = pci::find_by_bdf(bdf).ok_or(DriverSysError::NxDevice)?;

    {
        let mut owners = DEVICE_OWNERS.lock();
        if owners.get(&bdf).copied().is_some_and(|owner| owner != pid) {
            return Err(DriverSysError::NxDevice);
        }
        owners.insert(bdf, pid);
    }

    let mut mapped_bars = Vec::new();
    for (idx, &bar_phys) in device.bars.iter().enumerate() {
        if bar_phys == 0 {
            continue;
        }
        let user_va = map_phys_to_user(pid, bar_phys as usize, DRIVER_MMIO_BAR_SIZE, true)?;
        mapped_bars.push((idx as u8, user_va, bar_phys as usize, DRIVER_MMIO_BAR_SIZE));
    }

    let handle = mint_handle();
    DRIVER_LEASES.lock().insert(
        handle,
        DriverLease {
            owner_pid: pid,
            bdf,
            device,
            mapped_bars,
            dma_regions: Vec::new(),
            irq_endpoints: Vec::new(),
        },
    );

    Ok(DriverHandle(handle))
}

/// Allocate physically contiguous DMA memory, map it into the caller, and
/// return `(user_va, phys)`.
pub fn sys_dma_alloc(
    handle: DriverHandle,
    size: usize,
    align: usize,
) -> Result<(usize, usize), DriverSysError> {
    if size == 0 || size > DRIVER_DMA_MAX_BYTES || align == 0 || !align.is_power_of_two() {
        return Err(DriverSysError::BadAddress);
    }
    let effective_align = align.max(mmap::PAGE);

    with_lease_mut(handle, |lease| {
        let pages = mmap::page_align_up(size) / mmap::PAGE;
        let phys_base = if effective_align <= mmap::PAGE {
            pmm::alloc_pages_contig(pages).ok_or(DriverSysError::NoMem)?
        } else {
            pmm::alloc_pages_aligned(pages, effective_align)
                .map(|ptr| ptr.as_ptr() as usize)
                .ok_or(DriverSysError::NoMem)?
        };
        zero_phys_range(phys_base, pages * mmap::PAGE);
        let user_va = map_phys_to_user(lease.owner_pid, phys_base, pages * mmap::PAGE, true)?;
        lease
            .dma_regions
            .push((user_va, phys_base, pages * mmap::PAGE));
        Ok((user_va, phys_base))
    })
}

/// Subscribe the driver's IPC endpoint to an IRQ.
pub fn sys_irq_subscribe(
    handle: DriverHandle,
    irq: u32,
    endpoint: IpcEndpoint,
) -> Result<(), DriverSysError> {
    if irq == 0 || !crate::ipc::endpoint_owned_by_current(endpoint) {
        return Err(DriverSysError::InvalidIrq);
    }

    let hid = handle_id(handle)?;
    with_lease_mut(handle, |lease| {
        let mut owners = IRQ_OWNERS.lock();
        if owners
            .get(&irq)
            .is_some_and(|(owner, _, _)| *owner != lease.owner_pid)
        {
            return Err(DriverSysError::InvalidIrq);
        }
        owners.insert(irq, (lease.owner_pid, hid, endpoint));
        lease.irq_endpoints.push((irq, endpoint));
        Ok(())
    })
}

/// Acknowledge an IRQ after a userspace driver has handled it.
pub fn sys_irq_ack(handle: DriverHandle, irq: u32) -> Result<(), DriverSysError> {
    let hid = handle_id(handle)?;
    let pid = current_pid();
    match IRQ_OWNERS.lock().get(&irq).copied() {
        Some((owner, owner_handle, _)) if owner == pid && owner_handle == hid => Ok(()),
        _ => Err(DriverSysError::InvalidIrq),
    }
}

/// Called by arch IRQ paths when a userspace-owned IRQ fires.
pub fn notify_userspace_irq(irq: u32, timestamp_ns: u64) -> bool {
    let endpoint = match IRQ_OWNERS.lock().get(&irq).copied() {
        Some((_, _, endpoint)) => endpoint,
        None => return false,
    };
    let notification = IrqNotification {
        tag: 0xFF,
        irq,
        timestamp_ns,
    };
    let bytes = unsafe {
        core::slice::from_raw_parts(
            &notification as *const IrqNotification as *const u8,
            core::mem::size_of::<IrqNotification>(),
        )
    };
    crate::ipc::endpoint_notify_server(endpoint, bytes).is_ok()
}

/// Cleanup all driver resources owned by an exiting process.
pub fn cleanup_pid(pid: usize) {
    let handles: Vec<u64> = DRIVER_LEASES
        .lock()
        .iter()
        .filter_map(|(handle, lease)| (lease.owner_pid == pid).then_some(*handle))
        .collect();

    for handle in handles {
        if let Some(lease) = DRIVER_LEASES.lock().remove(&handle) {
            DEVICE_OWNERS.lock().remove(&lease.bdf);
            let mut irq_owners = IRQ_OWNERS.lock();
            for (irq, _) in lease.irq_endpoints {
                irq_owners.remove(&irq);
            }
        }
    }
}

/// Syscall wrapper: return the opaque handle as an integer.
pub fn dispatch_driver_bind(bdf: u32, cap_flags: u32) -> isize {
    sys_driver_bind(bdf, cap_flags)
        .map(|h| h.0 as isize)
        .unwrap_or_else(|e| e.as_isize())
}

/// Syscall wrapper matching userspace `sys_dma_alloc(handle, size, align,
/// phys_out)`.
pub fn dispatch_dma_alloc(handle: u64, size: usize, align: usize, phys_out: usize) -> isize {
    match sys_dma_alloc(DriverHandle(handle), size, align) {
        Ok((user_va, phys_addr)) => {
            if crate::uaccess::copy_to_user(
                phys_out,
                &phys_addr.to_ne_bytes() as *const u8,
                core::mem::size_of::<usize>(),
            )
            .is_err()
            {
                -14
            } else {
                user_va as isize
            }
        },
        Err(e) => e.as_isize(),
    }
}

pub fn dispatch_irq_subscribe(handle: u64, irq: u32, endpoint: u64) -> isize {
    sys_irq_subscribe(DriverHandle(handle), irq, IpcEndpoint(endpoint))
        .map(|_| 0)
        .unwrap_or_else(|e| e.as_isize())
}

pub fn dispatch_irq_ack(handle: u64, irq: u32) -> isize {
    sys_irq_ack(DriverHandle(handle), irq)
        .map(|_| 0)
        .unwrap_or_else(|e| e.as_isize())
}
