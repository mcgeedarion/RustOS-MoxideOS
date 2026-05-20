//! NVMe host controller driver.
//!
//! ## Architecture
//!   One Admin queue pair (SQ + CQ, 64 entries each) for controller init.
//!   One IO queue pair  (SQ + CQ, 64 entries each) for read/write I/O.
//!   Submission queues are doorbell-driven; completion queues are polled.
//!
//! ## Supported commands
//!   Admin: IDENTIFY (CNS 0x01 controller, 0x00 namespace), CREATE SQ/CQ,
//!          SET FEATURES (number of queues), DELETE SQ/CQ
//!   IO:    READ (opcode 0x02), WRITE (opcode 0x01)
//!
//! ## Usage
//!   ```
//!   nvme::init(bar0_phys);
//!   let info = nvme::disk_info(0).unwrap();
//!   nvme::read_sectors(0, 0, 1, &mut buf).unwrap();
//!   ```

extern crate alloc;
use alloc::vec::Vec;
use core::ptr::{read_volatile, write_volatile};
use spin::Mutex;

// ---------------------------------------------------------------------------
// Controller register offsets (BAR0 = MMIO base)
// ---------------------------------------------------------------------------

const NVME_CAP:      usize = 0x00; // Controller Capabilities (8 B)
const NVME_VS:       usize = 0x08; // Version (4 B)
const NVME_CC:       usize = 0x14; // Controller Configuration (4 B)
const NVME_CSTS:     usize = 0x1C; // Controller Status (4 B)
const NVME_AQA:      usize = 0x24; // Admin Queue Attributes (4 B)
const NVME_ASQ:      usize = 0x28; // Admin SQ Base Address (8 B)
const NVME_ACQ:      usize = 0x30; // Admin CQ Base Address (8 B)

// CAP field masks
const CAP_MQES_MASK:  u64 = 0xFFFF;
const CAP_DSTRD_SHIFT: u64 = 32;
const CAP_DSTRD_MASK:  u64 = 0xF;

// CC fields
const CC_EN:     u32 = 1 << 0;
const CC_CSS_NVM:u32 = 0 << 4;
const CC_MPS_4K: u32 = 0 << 7;   // 4 KiB page size (MPS=0)
const CC_AQS_512:u32 = 6 << 16;  // Admin CQ entry size 64 B (2^6)
const CC_IOYS_64:u32 = 6 << 20;  // IO SQ  entry size 64 B
const CC_IOCS_16:u32 = 4 << 24;  // IO CQ  entry size 16 B

// CSTS fields
const CSTS_RDY:  u32 = 1 << 0;
const CSTS_CFS:  u32 = 1 << 1;

// Queue depths
const ADMIN_DEPTH: usize = 64;
const IO_DEPTH:    usize = 64;

// NVMe Submission Queue entry size = 64 B
// NVMe Completion Queue entry size = 16 B

// ---------------------------------------------------------------------------
// NVMe command structures
// ---------------------------------------------------------------------------

#[repr(C, packed)]
#[derive(Clone, Copy, Default)]
struct SqEntry {
    cdw0:   u32,  // opcode[7:0], fuse[9:8], psdt[15:14], cid[31:16]
    nsid:   u32,
    cdw2:   u32,
    cdw3:   u32,
    mptr:   u64,
    prp1:   u64,  // Physical Region Page 1
    prp2:   u64,  // Physical Region Page 2 (or PRP List)
    cdw10:  u32,
    cdw11:  u32,
    cdw12:  u32,
    cdw13:  u32,
    cdw14:  u32,
    cdw15:  u32,
}

#[repr(C, packed)]
#[derive(Clone, Copy, Default)]
struct CqEntry {
    dw0:    u32,
    dw1:    u32,
    sq_hd:  u16,  // SQ head pointer
    sq_id:  u16,  // SQ identifier
    cid:    u16,  // Command ID
    status: u16,  // Phase tag (bit 0) + status (bits 15:1)
}

// ---------------------------------------------------------------------------
// Opcodes
// ---------------------------------------------------------------------------

const ADM_IDENTIFY:    u8 = 0x06;
const ADM_SET_FEAT:    u8 = 0x09;
const ADM_CREATE_IOCQ: u8 = 0x05;
const ADM_CREATE_IOSQ: u8 = 0x01;
const IO_WRITE:        u8 = 0x01;
const IO_READ:         u8 = 0x02;

// IDENTIFY CNS selectors
const CNS_NAMESPACE:   u32 = 0x00;
const CNS_CONTROLLER:  u32 = 0x01;

// ---------------------------------------------------------------------------
// Controller state
// ---------------------------------------------------------------------------

struct NvmeCtrl {
    bar0:       u64,
    dstrd:      usize,   // doorbell stride in bytes
    /// Admin SQ physical address
    asq_phys:   u64,
    /// Admin CQ physical address
    acq_phys:   u64,
    asq_tail:   usize,
    acq_head:   usize,
    acq_phase:  u8,
    /// IO SQ/CQ physical addresses
    iosq_phys:  u64,
    iocq_phys:  u64,
    iosq_tail:  usize,
    iocq_head:  usize,
    iocq_phase: u8,
    /// Next command ID
    next_cid:   u16,
    /// Scratch DMA buffer (4 KiB page)
    dma_phys:   u64,
}

static CTRL: Mutex<Option<NvmeCtrl>> = Mutex::new(None);

// ---------------------------------------------------------------------------
// Disk info
// ---------------------------------------------------------------------------

#[derive(Clone, Default, Debug)]
pub struct DiskInfo {
    pub sector_count: u64,
    pub sector_size:  u32,
    pub model:        [u8; 40],
}

static DISKS: Mutex<Vec<DiskInfo>> = Mutex::new(Vec::new());

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

pub fn init(bar0_phys: u64) {
    unsafe { _init(bar0_phys); }
}

pub fn read_sectors(ns: usize, lba: u64, count: u32, buf: &mut [u8]) -> Result<(), &'static str> {
    if buf.len() < count as usize * 512 { return Err("buffer too small"); }
    io_rw(ns as u32 + 1, lba, count, buf.as_mut_ptr() as u64, false)
}

pub fn write_sectors(ns: usize, lba: u64, count: u32, buf: &[u8]) -> Result<(), &'static str> {
    if buf.len() < count as usize * 512 { return Err("buffer too small"); }
    io_rw(ns as u32 + 1, lba, count, buf.as_ptr() as u64, true)
}

pub fn disk_info(ns: usize) -> Option<DiskInfo> {
    DISKS.lock().get(ns).cloned()
}

pub fn disk_count() -> usize { DISKS.lock().len() }

// ---------------------------------------------------------------------------
// Internal init
// ---------------------------------------------------------------------------

unsafe fn _init(bar0: u64) {
    let cap = mmio_read64(bar0, NVME_CAP);
    let dstrd = (((cap >> CAP_DSTRD_SHIFT) & CAP_DSTRD_MASK) as usize) * 4 + 4;

    // Disable controller.
    mmio_write32(bar0, NVME_CC, 0);
    let mut spin = 0u32;
    while mmio_read32(bar0, NVME_CSTS) & CSTS_RDY != 0 {
        core::hint::spin_loop();
        spin += 1;
        if spin > 2_000_000 { return; }
    }

    // Allocate admin queues.
    let asq = alloc_dma(ADMIN_DEPTH * 64, 4096).expect("asq alloc");
    let acq = alloc_dma(ADMIN_DEPTH * 16, 4096).expect("acq alloc");
    let dma = alloc_dma(4096, 4096).expect("dma alloc");

    // Configure admin queues.
    mmio_write32(bar0, NVME_AQA,
        ((ADMIN_DEPTH as u32 - 1) << 16) | (ADMIN_DEPTH as u32 - 1));
    mmio_write64(bar0, NVME_ASQ, asq);
    mmio_write64(bar0, NVME_ACQ, acq);

    // Enable controller.
    let cc = CC_EN | CC_CSS_NVM | CC_MPS_4K | CC_AQS_512 | CC_IOYS_64 | CC_IOCS_16;
    mmio_write32(bar0, NVME_CC, cc);

    // Wait for RDY.
    spin = 0;
    loop {
        let csts = mmio_read32(bar0, NVME_CSTS);
        if csts & CSTS_CFS != 0 { return; }
        if csts & CSTS_RDY != 0 { break; }
        core::hint::spin_loop();
        spin += 1;
        if spin > 4_000_000 { return; }
    }

    let iosq = alloc_dma(IO_DEPTH * 64, 4096).expect("iosq alloc");
    let iocq = alloc_dma(IO_DEPTH * 16, 4096).expect("iocq alloc");

    *CTRL.lock() = Some(NvmeCtrl {
        bar0, dstrd,
        asq_phys: asq, acq_phys: acq,
        asq_tail: 0, acq_head: 0, acq_phase: 1,
        iosq_phys: iosq, iocq_phys: iocq,
        iosq_tail: 0, iocq_head: 0, iocq_phase: 1,
        next_cid: 1, dma_phys: dma,
    });

    // SET FEATURES: Number of Queues = 1 IO pair.
    let mut cmd = SqEntry::default();
    cmd.cdw0  = (ADM_SET_FEAT as u32) | (next_cid() << 16);
    cmd.cdw10 = 0x07;   // Feature ID: Number of Queues
    cmd.cdw11 = 0x0001_0001; // 1 IO SQ, 1 IO CQ (0-based)
    admin_submit(cmd);
    admin_complete();

    // CREATE IO CQ.
    let iocq_pa = CTRL.lock().as_ref().unwrap().iocq_phys;
    let mut cmd = SqEntry::default();
    cmd.cdw0  = (ADM_CREATE_IOCQ as u32) | (next_cid() << 16);
    cmd.prp1  = iocq_pa;
    cmd.cdw10 = ((IO_DEPTH as u32 - 1) << 16) | 1; // QID=1
    cmd.cdw11 = 1; // IEN=0, PC=1 (physically contiguous)
    admin_submit(cmd);
    admin_complete();

    // CREATE IO SQ.
    let iosq_pa = CTRL.lock().as_ref().unwrap().iosq_phys;
    let mut cmd = SqEntry::default();
    cmd.cdw0  = (ADM_CREATE_IOSQ as u32) | (next_cid() << 16);
    cmd.prp1  = iosq_pa;
    cmd.cdw10 = ((IO_DEPTH as u32 - 1) << 16) | 1; // QID=1
    cmd.cdw11 = (1 << 16) | 1; // CQID=1, PC=1
    admin_submit(cmd);
    admin_complete();

    // IDENTIFY Namespace 1.
    let dma_pa = CTRL.lock().as_ref().unwrap().dma_phys;
    core::ptr::write_bytes(dma_pa as *mut u8, 0, 4096);
    let mut cmd = SqEntry::default();
    cmd.cdw0  = (ADM_IDENTIFY as u32) | (next_cid() << 16);
    cmd.nsid  = 1;
    cmd.prp1  = dma_pa;
    cmd.cdw10 = CNS_NAMESPACE;
    admin_submit(cmd);
    admin_complete();

    let id_ns = core::slice::from_raw_parts(dma_pa as *const u64, 512);
    let nsze  = id_ns[0]; // NSZE: namespace size in logical blocks
    let lbads = ((id_ns[13] >> 48) & 0xF) as u32; // LBADS field of active format
    let sector_size = 1u32 << lbads;

    // IDENTIFY Controller.
    core::ptr::write_bytes(dma_pa as *mut u8, 0, 4096);
    let mut cmd = SqEntry::default();
    cmd.cdw0  = (ADM_IDENTIFY as u32) | (next_cid() << 16);
    cmd.prp1  = dma_pa;
    cmd.cdw10 = CNS_CONTROLLER;
    admin_submit(cmd);
    admin_complete();

    // Model string at offset 24, 40 bytes, byte-swapped per word.
    let id_ctrl = core::slice::from_raw_parts(dma_pa as *const u8, 4096);
    let mut model = [0u8; 40];
    for i in 0..40 {
        model[i] = id_ctrl[24 + i];
    }

    DISKS.lock().push(DiskInfo { sector_count: nsze, sector_size, model });
}

// ---------------------------------------------------------------------------
// IO submit / complete
// ---------------------------------------------------------------------------

fn io_rw(nsid: u32, lba: u64, count: u32, buf_phys: u64, write: bool)
    -> Result<(), &'static str>
{
    let cid = next_cid();
    let opcode = if write { IO_WRITE } else { IO_READ };
    let mut cmd = SqEntry::default();
    cmd.cdw0  = (opcode as u32) | ((cid as u32) << 16);
    cmd.nsid  = nsid;
    cmd.prp1  = buf_phys;
    cmd.prp2  = 0;
    cmd.cdw10 = lba as u32;
    cmd.cdw11 = (lba >> 32) as u32;
    cmd.cdw12 = count - 1; // NLB is 0-based

    let mut ctrl = CTRL.lock();
    let c = ctrl.as_mut().ok_or("nvme not initialised")?;

    // Write SQ entry.
    let sq_entry = (c.iosq_phys as usize + c.iosq_tail * 64) as *mut SqEntry;
    unsafe { sq_entry.write_volatile(cmd); }
    c.iosq_tail = (c.iosq_tail + 1) % IO_DEPTH;

    // Ring IO SQ doorbell (offset = 0x1000 + 2 * qid * dstrd).
    let db_off = 0x1000 + 2 * 1 * c.dstrd;
    unsafe { write_volatile((c.bar0 as usize + db_off) as *mut u32, c.iosq_tail as u32); }

    // Poll IO CQ.
    let deadline = 10_000_000usize;
    for _ in 0..deadline {
        let cqe = unsafe {
            &*((c.iocq_phys as usize + c.iocq_head * 16) as *const CqEntry)
        };
        let phase = (cqe.status & 1) as u8;
        if phase == c.iocq_phase {
            let sc = (cqe.status >> 1) & 0xFF;
            c.iocq_head = (c.iocq_head + 1) % IO_DEPTH;
            if c.iocq_head == 0 { c.iocq_phase ^= 1; }
            // Ring IO CQ doorbell.
            let cq_db = 0x1000 + (2 * 1 + 1) * c.dstrd;
            unsafe { write_volatile((c.bar0 as usize + cq_db) as *mut u32, c.iocq_head as u32); }
            return if sc == 0 { Ok(()) } else { Err("nvme io error") };
        }
        core::hint::spin_loop();
    }
    Err("nvme io timeout")
}

// ---------------------------------------------------------------------------
// Admin queue helpers
// ---------------------------------------------------------------------------

fn admin_submit(cmd: SqEntry) {
    let mut ctrl = CTRL.lock();
    let c = ctrl.as_mut().unwrap();
    let entry = (c.asq_phys as usize + c.asq_tail * 64) as *mut SqEntry;
    unsafe { entry.write_volatile(cmd); }
    c.asq_tail = (c.asq_tail + 1) % ADMIN_DEPTH;
    // Ring Admin SQ doorbell (offset = 0x1000).
    unsafe { write_volatile((c.bar0 as usize + 0x1000) as *mut u32, c.asq_tail as u32); }
}

fn admin_complete() {
    let mut ctrl = CTRL.lock();
    let c = ctrl.as_mut().unwrap();
    loop {
        let cqe = unsafe {
            &*((c.acq_phys as usize + c.acq_head * 16) as *const CqEntry)
        };
        if (cqe.status & 1) as u8 == c.acq_phase {
            c.acq_head = (c.acq_head + 1) % ADMIN_DEPTH;
            if c.acq_head == 0 { c.acq_phase ^= 1; }
            // Ring Admin CQ doorbell (offset = 0x1000 + dstrd).
            let db = 0x1000 + c.dstrd;
            unsafe { write_volatile((c.bar0 as usize + db) as *mut u32, c.acq_head as u32); }
            return;
        }
        core::hint::spin_loop();
    }
}

fn next_cid() -> u32 {
    let mut ctrl = CTRL.lock();
    if let Some(c) = ctrl.as_mut() {
        let id = c.next_cid;
        c.next_cid = c.next_cid.wrapping_add(1);
        id as u32
    } else { 1 }
}

// ---------------------------------------------------------------------------
// MMIO helpers
// ---------------------------------------------------------------------------

#[inline]
unsafe fn mmio_read32(base: u64, off: usize) -> u32 {
    read_volatile((base as usize + off) as *const u32)
}

#[inline]
unsafe fn mmio_write32(base: u64, off: usize, val: u32) {
    write_volatile((base as usize + off) as *mut u32, val);
}

#[inline]
unsafe fn mmio_read64(base: u64, off: usize) -> u64 {
    let lo = read_volatile((base as usize + off) as *const u32) as u64;
    let hi = read_volatile((base as usize + off + 4) as *const u32) as u64;
    lo | (hi << 32)
}

#[inline]
unsafe fn mmio_write64(base: u64, off: usize, val: u64) {
    write_volatile((base as usize + off)     as *mut u32, (val & 0xFFFF_FFFF) as u32);
    write_volatile((base as usize + off + 4) as *mut u32, (val >> 32) as u32);
}

fn alloc_dma(size: usize, align: usize) -> Option<u64> {
    let pages = (size + 0xFFF) / 0x1000;
    let phys = crate::mm::pmm::alloc_pages_aligned(pages, align)?
        .as_ptr() as u64;
    unsafe { core::ptr::write_bytes(phys as *mut u8, 0, pages * 0x1000); }
    Some(phys)
}
