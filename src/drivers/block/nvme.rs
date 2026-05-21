//! NVMe host controller driver.
//!
//! Current capabilities:
//!   - Admin queue + single IO queue pair
//!   - IDENTIFY controller/namespace
//!   - READ / WRITE
//!   - Polling completions
//!   - Proper CQ phase handling
//!   - Admin timeout handling
//!   - Basic PRP chaining (up to 8 KiB contiguous)
//!   - Correct IDENTIFY namespace parsing
//!   - MMIO ordering fences
//!
//! Remaining limitations:
//!   - No MSI/MSI-X interrupts
//!   - No PRP list support (>8 KiB transfers unsupported)
//!   - Assumes physically contiguous DMA buffers
//!   - Assumes identity-mapped physical memory
extern crate alloc;
use alloc::vec::Vec;
use core::ptr::{read_volatile, write_volatile};
use core::sync::atomic::{fence, Ordering};
use spin::Mutex;
// ---------------------------------------------------------------------------
// Controller register offsets
// ---------------------------------------------------------------------------
const NVME_CAP: usize = 0x00;
const NVME_CC: usize = 0x14;
const NVME_CSTS: usize = 0x1C;
const NVME_AQA: usize = 0x24;
const NVME_ASQ: usize = 0x28;
const NVME_ACQ: usize = 0x30;
// ---------------------------------------------------------------------------
// CAP fields
// ---------------------------------------------------------------------------
const CAP_DSTRD_SHIFT: u64 = 32;
const CAP_DSTRD_MASK: u64 = 0xF;
// ---------------------------------------------------------------------------
// CC fields
// ---------------------------------------------------------------------------
const CC_EN: u32       = 1 << 0;
const CC_CSS_NVM: u32 = 0 << 4;
const CC_MPS_4K: u32  = 0 << 7;
const CC_AQS_64: u32  = 6 << 16;
const CC_IOSQES: u32  = 6 << 20;
const CC_IOCQES: u32  = 4 << 24;
// ---------------------------------------------------------------------------
// CSTS fields
// ---------------------------------------------------------------------------
const CSTS_RDY: u32 = 1 << 0;
const CSTS_CFS: u32 = 1 << 1;
// ---------------------------------------------------------------------------
// Queue depths
// ---------------------------------------------------------------------------
const ADMIN_DEPTH: usize = 64;
const IO_DEPTH: usize = 64;
// ---------------------------------------------------------------------------
// Opcodes
// ---------------------------------------------------------------------------
const ADM_DELETE_IOSQ: u8 = 0x00;
const ADM_CREATE_IOSQ: u8 = 0x01;
const ADM_CREATE_IOCQ: u8 = 0x05;
const ADM_IDENTIFY: u8    = 0x06;
const ADM_SET_FEAT: u8    = 0x09;
const IO_WRITE: u8 = 0x01;
const IO_READ: u8  = 0x02;
// ---------------------------------------------------------------------------
// IDENTIFY CNS
// ---------------------------------------------------------------------------
const CNS_NAMESPACE: u32 = 0x00;
const CNS_CONTROLLER: u32 = 0x01;
// ---------------------------------------------------------------------------
// Structures
// ---------------------------------------------------------------------------
#[repr(C, packed)]
#[derive(Clone, Copy, Default)]
struct SqEntry {
    cdw0: u32,
    nsid: u32,
    cdw2: u32,
    cdw3: u32,
    mptr: u64,
    prp1: u64,
    prp2: u64,
    cdw10: u32,
    cdw11: u32,
    cdw12: u32,
    cdw13: u32,
    cdw14: u32,
    cdw15: u32,
}
#[repr(C, packed)]
#[derive(Clone, Copy, Default)]
struct CqEntry {
    dw0: u32,
    dw1: u32,
    sq_hd: u16,
    sq_id: u16,
    cid: u16,
    status: u16,
}
// ---------------------------------------------------------------------------
// Disk info
// ---------------------------------------------------------------------------
#[derive(Clone, Debug, Default)]
pub struct DiskInfo {
    pub sector_count: u64,
    pub sector_size: u32,
    pub model: [u8; 40],
}
// ---------------------------------------------------------------------------
// Controller state
// ---------------------------------------------------------------------------
struct NvmeCtrl {
    bar0: u64,
    dstrd: usize,
    asq_phys: u64,
    acq_phys: u64,
    iosq_phys: u64,
    iocq_phys: u64,
    dma_phys: u64,
    asq_tail: usize,
    acq_head: usize,
    acq_phase: u8,
    iosq_tail: usize,
    iocq_head: usize,
    iocq_phase: u8,
    next_cid: u16,
}
static CTRL: Mutex<Option<NvmeCtrl>> = Mutex::new(None);
static DISKS: Mutex<Vec<DiskInfo>> = Mutex::new(Vec::new());
// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------
pub fn init(bar0_phys: u64) {
    unsafe { _init(bar0_phys) }
}
pub fn disk_count() -> usize {
    DISKS.lock().len()
}
pub fn disk_info(idx: usize) -> Option<DiskInfo> {
    DISKS.lock().get(idx).cloned()
}
pub fn read_sectors(
    ns: usize,
    lba: u64,
    count: u32,
    buf: &mut [u8],
) -> Result<(), &'static str> {
    let info = disk_info(ns).ok_or("invalid namespace")?;
    let needed = count as usize * info.sector_size as usize;
    if buf.len() < needed {
        return Err("buffer too small");
    }
    io_rw(
        ns as u32 + 1,
        lba,
        count,
        buf.as_mut_ptr() as u64,
        false,
    )
}
pub fn write_sectors(
    ns: usize,
    lba: u64,
    count: u32,
    buf: &[u8],
) -> Result<(), &'static str> {
    let info = disk_info(ns).ok_or("invalid namespace")?;
    let needed = count as usize * info.sector_size as usize;
    if buf.len() < needed {
        return Err("buffer too small");
    }
    io_rw(
        ns as u32 + 1,
        lba,
        count,
        buf.as_ptr() as u64,
        true,
    )
}
// ---------------------------------------------------------------------------
// Init
// ---------------------------------------------------------------------------
unsafe fn _init(bar0: u64) {
    let cap = mmio_read64(bar0, NVME_CAP);
    let dstrd_bits =
        ((cap >> CAP_DSTRD_SHIFT) & CAP_DSTRD_MASK) as usize;
    let dstrd = 1usize << (2 + dstrd_bits);
    // Disable controller.
    mmio_write32(bar0, NVME_CC, 0);
    let mut spin = 0usize;
    while mmio_read32(bar0, NVME_CSTS) & CSTS_RDY != 0 {
        core::hint::spin_loop();
        spin += 1;
        if spin > 2_000_000 {
            return;
        }
    }
    // Allocate queues.
    let asq = alloc_dma(ADMIN_DEPTH * 64, 4096)
        .expect("asq alloc");
    let acq = alloc_dma(ADMIN_DEPTH * 16, 4096)
        .expect("acq alloc");
    let iosq = alloc_dma(IO_DEPTH * 64, 4096)
        .expect("iosq alloc");
    let iocq = alloc_dma(IO_DEPTH * 16, 4096)
        .expect("iocq alloc");
    let dma = alloc_dma(4096, 4096)
        .expect("dma alloc");
    mmio_write32(
        bar0,
        NVME_AQA,
        ((ADMIN_DEPTH as u32 - 1) << 16)
            | (ADMIN_DEPTH as u32 - 1),
    );
    mmio_write64(bar0, NVME_ASQ, asq);
    mmio_write64(bar0, NVME_ACQ, acq);
    let cc =
        CC_EN |
        CC_CSS_NVM |
        CC_MPS_4K |
        CC_AQS_64 |
        CC_IOSQES |
        CC_IOCQES;
    mmio_write32(bar0, NVME_CC, cc);
    spin = 0;
    loop {
        let csts = mmio_read32(bar0, NVME_CSTS);
        if csts & CSTS_CFS != 0 {
            return;
        }
        if csts & CSTS_RDY != 0 {
            break;
        }
        spin += 1;
        if spin > 4_000_000 {
            return;
        }
        core::hint::spin_loop();
    }
    *CTRL.lock() = Some(NvmeCtrl {
        bar0,
        dstrd,
        asq_phys: asq,
        acq_phys: acq,
        iosq_phys: iosq,
        iocq_phys: iocq,
        dma_phys: dma,
        asq_tail: 0,
        acq_head: 0,
        acq_phase: 1,
        iosq_tail: 0,
        iocq_head: 0,
        iocq_phase: 1,
        next_cid: 1,
    });
    // SET FEATURES - number of queues.
    let mut cmd = SqEntry::default();
    cmd.cdw0 =
        (ADM_SET_FEAT as u32)
        | (next_cid() << 16);
    cmd.cdw10 = 0x07;
    cmd.cdw11 = 0x0001_0001;
    admin_submit(cmd);
    admin_complete()?;
    // CREATE IO CQ
    let iocq_pa =
        CTRL.lock().as_ref().unwrap().iocq_phys;
    let mut cmd = SqEntry::default();
    cmd.cdw0 =
        (ADM_CREATE_IOCQ as u32)
        | (next_cid() << 16);
    cmd.prp1 = iocq_pa;
    cmd.cdw10 =
        ((IO_DEPTH as u32 - 1) << 16) | 1;
    cmd.cdw11 = 1;
    admin_submit(cmd);
    admin_complete()?;
    // CREATE IO SQ
    let iosq_pa =
        CTRL.lock().as_ref().unwrap().iosq_phys;
    let mut cmd = SqEntry::default();
    cmd.cdw0 =
        (ADM_CREATE_IOSQ as u32)
        | (next_cid() << 16);
    cmd.prp1 = iosq_pa;
    cmd.cdw10 =
        ((IO_DEPTH as u32 - 1) << 16) | 1;
    cmd.cdw11 =
        (1 << 16) | 1;
    admin_submit(cmd);
    admin_complete()?;
    // IDENTIFY NAMESPACE
    let dma_pa =
        CTRL.lock().as_ref().unwrap().dma_phys;
    core::ptr::write_bytes(
        dma_pa as *mut u8,
        0,
        4096,
    );
    let mut cmd = SqEntry::default();
    cmd.cdw0 =
        (ADM_IDENTIFY as u32)
        | (next_cid() << 16);
    cmd.nsid = 1;
    cmd.prp1 = dma_pa;
    cmd.cdw10 = CNS_NAMESPACE;
    admin_submit(cmd);
    admin_complete()?;
    let id_ns =
        core::slice::from_raw_parts(
            dma_pa as *const u8,
            4096,
        );
    let nsze =
        *(id_ns.as_ptr() as *const u64);
    let flbas =
        id_ns[26] & 0x0F;
    let lbaf_off =
        128 + flbas as usize * 4;
    let lbads =
        id_ns[lbaf_off + 2] as u32;
    let sector_size =
        1u32 << lbads;
    // IDENTIFY CONTROLLER
    core::ptr::write_bytes(
        dma_pa as *mut u8,
        0,
        4096,
    );
    let mut cmd = SqEntry::default();
    cmd.cdw0 =
        (ADM_IDENTIFY as u32)
        | (next_cid() << 16);
    cmd.prp1 = dma_pa;
    cmd.cdw10 = CNS_CONTROLLER;
    admin_submit(cmd);
    admin_complete()?;
    let id_ctrl =
        core::slice::from_raw_parts(
            dma_pa as *const u8,
            4096,
        );
    let mut model = [0u8; 40];
    for i in 0..40 {
        model[i] = id_ctrl[24 + i];
    }
    DISKS.lock().push(DiskInfo {
        sector_count: nsze,
        sector_size,
        model,
    });
}
// ---------------------------------------------------------------------------
// IO
// ---------------------------------------------------------------------------
fn io_rw(
    nsid: u32,
    lba: u64,
    count: u32,
    buf_phys: u64,
    write: bool,
) -> Result<(), &'static str> {
    if count == 0 {
        return Err("zero-length io");
    }
    if (buf_phys & 0xFFF) != 0 {
        return Err("buffer not page aligned");
    }
    let len = count as usize * 512;
    let cid = next_cid();
    let opcode =
        if write { IO_WRITE }
        else { IO_READ };
    let mut cmd = SqEntry::default();
    cmd.cdw0 =
        (opcode as u32)
        | ((cid as u32) << 16);
    cmd.nsid = nsid;
    setup_prps(
        &mut cmd,
        buf_phys,
        len,
    )?;
    cmd.cdw10 = lba as u32;
    cmd.cdw11 = (lba >> 32) as u32;
    cmd.cdw12 = count - 1;
    let mut ctrl = CTRL.lock();
    let c =
        ctrl.as_mut()
        .ok_or("nvme not initialised")?;
    let entry =
        (c.iosq_phys as usize
            + c.iosq_tail * 64)
            as *mut SqEntry;
    unsafe {
        entry.write_volatile(cmd);
    }
    fence(Ordering::Release);
    c.iosq_tail =
        (c.iosq_tail + 1)
        % IO_DEPTH;
    let db =
        0x1000 + 2 * c.dstrd;
    unsafe {
        write_volatile(
            (c.bar0 as usize + db)
                as *mut u32,
            c.iosq_tail as u32,
        );
    }
    let timeout = 10_000_000usize;
    for _ in 0..timeout {
        let cqe = unsafe {
            &*((c.iocq_phys as usize
                + c.iocq_head * 16)
                as *const CqEntry)
        };
        fence(Ordering::Acquire);
        if (cqe.status & 1) as u8
            == c.iocq_phase
        {
            let status =
                cqe.status >> 1;
            let sc =
                status & 0xFF;
            let _sct =
                (status >> 8) & 0x7;
            c.iocq_head =
                (c.iocq_head + 1)
                % IO_DEPTH;
            if c.iocq_head == 0 {
                c.iocq_phase ^= 1;
            }
            let cq_db =
                0x1000
                + (2 * 1 + 1)
                * c.dstrd;
            unsafe {
                write_volatile(
                    (c.bar0 as usize + cq_db)
                        as *mut u32,
                    c.iocq_head as u32,
                );
            }
            return if sc == 0 {
                Ok(())
            } else {
                Err("nvme io error")
            };
        }
        core::hint::spin_loop();
    }
    Err("nvme io timeout")
}
// ---------------------------------------------------------------------------
// PRPs
// ---------------------------------------------------------------------------
fn setup_prps(
    cmd: &mut SqEntry,
    phys: u64,
    len: usize,
) -> Result<(), &'static str> {
    if len <= 4096 {
        cmd.prp1 = phys;
        cmd.prp2 = 0;
        return Ok(());
    }
    if len <= 8192 {
        cmd.prp1 = phys;
        cmd.prp2 = phys + 4096;
        return Ok(());
    }
    Err("transfer too large")
}
// ---------------------------------------------------------------------------
// Admin queue
// ---------------------------------------------------------------------------
fn admin_submit(cmd: SqEntry) {
    let mut ctrl = CTRL.lock();
    let c =
        ctrl.as_mut().unwrap();
    let entry =
        (c.asq_phys as usize
            + c.asq_tail * 64)
            as *mut SqEntry;
    unsafe {
        entry.write_volatile(cmd);
    }
    fence(Ordering::Release);
    c.asq_tail =
        (c.asq_tail + 1)
        % ADMIN_DEPTH;
    unsafe {
        write_volatile(
            (c.bar0 as usize + 0x1000)
                as *mut u32,
            c.asq_tail as u32,
        );
    }
}
fn admin_complete()
    -> Result<(), &'static str>
{
    let mut ctrl = CTRL.lock();
    let c =
        ctrl.as_mut().unwrap();
    let timeout = 10_000_000usize;
    for _ in 0..timeout {
        let cqe = unsafe {
            &*((c.acq_phys as usize
                + c.acq_head * 16)
                as *const CqEntry)
        };
        fence(Ordering::Acquire);
        if (cqe.status & 1) as u8
            == c.acq_phase
        {
            let status =
                cqe.status >> 1;
            let sc =
                status & 0xFF;
            let _sct =
                (status >> 8) & 0x7;
            c.acq_head =
                (c.acq_head + 1)
                % ADMIN_DEPTH;
            if c.acq_head == 0 {
                c.acq_phase ^= 1;
            }
            let db =
                0x1000 + c.dstrd;
            unsafe {
                write_volatile(
                    (c.bar0 as usize + db)
                        as *mut u32,
                    c.acq_head as u32,
                );
            }
            return if sc == 0 {
                Ok(())
            } else {
                Err("nvme admin command failed")
            };
        }
        core::hint::spin_loop();
    }
    Err("nvme admin timeout")
}
// ---------------------------------------------------------------------------
// CID allocator
// ---------------------------------------------------------------------------
fn next_cid() -> u32 {
    let mut ctrl = CTRL.lock();
    let c =
        ctrl.as_mut().unwrap();
    let cid = c.next_cid;
    c.next_cid =
        c.next_cid.wrapping_add(1);
    cid as u32
}
// ---------------------------------------------------------------------------
// MMIO helpers
// ---------------------------------------------------------------------------
#[inline]
unsafe fn mmio_read32(
    base: u64,
    off: usize,
) -> u32 {
    read_volatile(
        (base as usize + off)
            as *const u32
    )
}
#[inline]
unsafe fn mmio_write32(
    base: u64,
    off: usize,
    val: u32,
) {
    write_volatile(
        (base as usize + off)
            as *mut u32,
        val,
    );
}
#[inline]
unsafe fn mmio_read64(
    base: u64,
    off: usize,
) -> u64 {
    let lo =
        read_volatile(
            (base as usize + off)
                as *const u32
        ) as u64;
    let hi =
        read_volatile(
            (base as usize + off + 4)
                as *const u32
        ) as u64;
    lo | (hi << 32)
}
#[inline]
unsafe fn mmio_write64(
    base: u64,
    off: usize,
    val: u64,
) {
    write_volatile(
        (base as usize + off)
            as *mut u32,
        val as u32,
    );
    write_volatile(
        (base as usize + off + 4)
            as *mut u32,
        (val >> 32) as u32,
    );
}
// ---------------------------------------------------------------------------
// DMA allocation
// ---------------------------------------------------------------------------
fn alloc_dma(
    size: usize,
    align: usize,
) -> Option<u64> {
    let pages =
        (size + 0xFFF) / 0x1000;
    let phys =
        crate::mm::pmm::alloc_pages_aligned(
            pages,
            align,
        )?
        .as_ptr() as u64;
    unsafe {
        core::ptr::write_bytes(
            phys as *mut u8,
            0,
            pages * 0x1000,
        );
    }
    Some(phys)
}