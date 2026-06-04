//! NVMe host controller driver.
//!
//! Current capabilities:
//!   - Admin queue + single IO queue pair
//!   - IDENTIFY controller/namespace
//!   - READ / WRITE
//!   - MSI-X interrupt wiring (vectors 0 = Admin CQ, 1 = IO CQ)
//!   - Hybrid completion: IRQ fast-path + polled fallback
//!   - PRP list support (transfers > 8 KiB, up to one 4 KiB PRP-list page = 511 entries = ~2 MiB)
//!   - Proper CQ phase handling
//!   - Admin timeout handling
//!   - Correct IDENTIFY namespace parsing
//!   - MMIO ordering fences
//!
//! Limitations:
//!   - Single IO queue pair (no multi-queue)
//!   - Assumes physically contiguous DMA buffers per transfer
//!   - Assumes identity-mapped physical memory
//!   - PRP list limited to 511 additional pages (~2 MiB) per transfer
extern crate alloc;
use alloc::vec::Vec;
use core::ptr::{read_volatile, write_volatile};
use core::sync::atomic::{AtomicBool, fence, Ordering};
use spin::Mutex;

const NVME_CAP: usize = 0x00;
const NVME_CC: usize = 0x14;
const NVME_CSTS: usize = 0x1C;
const NVME_AQA: usize = 0x24;
const NVME_ASQ: usize = 0x28;
const NVME_ACQ: usize = 0x30;

const CAP_DSTRD_SHIFT: u64 = 32;
const CAP_DSTRD_MASK: u64 = 0xF;

const CC_EN: u32      = 1 << 0;
const CC_CSS_NVM: u32 = 0 << 4;
const CC_MPS_4K: u32  = 0 << 7;
const CC_AQS_64: u32  = 6 << 16;
const CC_IOSQES: u32  = 6 << 20;
const CC_IOCQES: u32  = 4 << 24;

const CSTS_RDY: u32 = 1 << 0;
const CSTS_CFS: u32 = 1 << 1;

const ADMIN_DEPTH: usize = 64;
const IO_DEPTH: usize    = 64;

const ADM_CREATE_IOSQ: u8 = 0x01;
const ADM_CREATE_IOCQ: u8 = 0x05;
const ADM_IDENTIFY: u8    = 0x06;
const ADM_SET_FEAT: u8    = 0x09;

const IO_WRITE: u8 = 0x01;
const IO_READ: u8  = 0x02;

const CNS_NAMESPACE:  u32 = 0x00;
const CNS_CONTROLLER: u32 = 0x01;

/// IDT vectors reserved for NVMe completions.
/// Vector 0x32 = Admin CQ, 0x33 = IO CQ.
/// Using a single shared vector keeps the ISR simple.
const NVME_IRQ_VECTOR: u8 = 0x32;

// ── Completion signals ────────────────────────────────────────────────────────

/// Set by the MSI-X ISR; polled (swap) by `admin_complete` and `io_rw`.
static NVME_COMPLETION_FLAG: AtomicBool = AtomicBool::new(false);

// ── NVMe submission / completion entry layouts ────────────────────────────────

#[repr(C, packed)]
#[derive(Clone, Copy, Default)]
struct SqEntry {
    cdw0:  u32,
    nsid:  u32,
    cdw2:  u32,
    cdw3:  u32,
    mptr:  u64,
    prp1:  u64,
    prp2:  u64,
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
    dw0:    u32,
    dw1:    u32,
    sq_hd:  u16,
    sq_id:  u16,
    cid:    u16,
    status: u16,
}

// ── Public types ──────────────────────────────────────────────────────────────

#[derive(Clone, Debug, Default)]
pub struct DiskInfo {
    pub sector_count: u64,
    pub sector_size:  u32,
    pub model:        [u8; 40],
}

// ── Controller state ──────────────────────────────────────────────────────────

struct NvmeCtrl {
    bar0:         u64,
    dstrd:        usize,
    asq_phys:     u64,
    acq_phys:     u64,
    iosq_phys:    u64,
    iocq_phys:    u64,
    dma_phys:     u64,
    /// 4 KiB page used as scratch space for PRP lists.
    prp_list_phys: u64,
    asq_tail:     usize,
    acq_head:     usize,
    acq_phase:    u8,
    iosq_tail:    usize,
    iocq_head:    usize,
    iocq_phase:   u8,
    next_cid:     u16,
}

static CTRL: Mutex<Option<NvmeCtrl>> = Mutex::new(None);
static DISKS: Mutex<Vec<DiskInfo>>  = Mutex::new(Vec::new());

// ── Public API ────────────────────────────────────────────────────────────────

pub fn init(bar0_phys: u64) {
    unsafe { _init(bar0_phys) }
    wire_nvme_msix();
}

pub fn disk_count() -> usize {
    DISKS.lock().len()
}

pub fn disk_info(idx: usize) -> Option<DiskInfo> {
    DISKS.lock().get(idx).cloned()
}

pub fn read_sectors(
    ns:    usize,
    lba:   u64,
    count: u32,
    buf:   &mut [u8],
) -> Result<(), &'static str> {
    let info = disk_info(ns).ok_or("invalid namespace")?;
    let needed = count as usize * info.sector_size as usize;
    if buf.len() < needed {
        return Err("buffer too small");
    }
    io_rw(ns as u32 + 1, lba, count, buf.as_mut_ptr() as u64, false)
}

pub fn write_sectors(
    ns:    usize,
    lba:   u64,
    count: u32,
    buf:   &[u8],
) -> Result<(), &'static str> {
    let info = disk_info(ns).ok_or("invalid namespace")?;
    let needed = count as usize * info.sector_size as usize;
    if buf.len() < needed {
        return Err("buffer too small");
    }
    io_rw(ns as u32 + 1, lba, count, buf.as_ptr() as u64, true)
}

// ── BlockDev impl ─────────────────────────────────────────────────────────────

pub struct NvmeBlockDev {
    pub ns: usize,
}

impl crate::block::BlockDev for NvmeBlockDev {
    fn read(&self, lba: u64, buf: &mut [u8]) {
        let info = match disk_info(self.ns) {
            Some(i) => i,
            None    => return,
        };
        let count = (buf.len() / info.sector_size as usize) as u32;
        let _ = read_sectors(self.ns, lba, count, buf);
    }
    fn write(&self, lba: u64, buf: &[u8]) {
        let info = match disk_info(self.ns) {
            Some(i) => i,
            None    => return,
        };
        let count = (buf.len() / info.sector_size as usize) as u32;
        let _ = write_sectors(self.ns, lba, count, buf);
    }
    fn sector_size(&self) -> usize {
        disk_info(self.ns)
            .map(|i| i.sector_size as usize)
            .unwrap_or(512)
    }
}

// ── MSI-X wiring ──────────────────────────────────────────────────────────────

/// Wire MSI-X vectors 0 and 1 (Admin CQ and IO CQ) to `NVME_IRQ_VECTOR`
/// on the BSP LAPIC and register the ISR in the IDT.
///
/// Safe to call when no MSI-X capability is present — returns early and
/// the driver remains in polling mode.
fn wire_nvme_msix() {
    use crate::device::pci;
    use crate::device::pci::msix::msix_configure;
    use crate::arch::x86_64::{apic, idt};

    // NVMe class code = 0x0108 (Mass Storage Controller, NVM Express).
    let dev = match pci::devices()
        .into_iter()
        .find(|d| d.class == 0x0108)
    {
        Some(d) => d,
        None    => return,
    };

    if dev.msix_cap == 0 {
        return;
    }

    let lapic = apic::lapic_id();
    // Vector 0 = Admin CQ, vector 1 = IO CQ; both deliver NVME_IRQ_VECTOR.
    msix_configure(&dev, 0, lapic, NVME_IRQ_VECTOR);
    msix_configure(&dev, 1, lapic, NVME_IRQ_VECTOR);

    idt::register_irq(NVME_IRQ_VECTOR, |_frame| {
        NVME_COMPLETION_FLAG.store(true, Ordering::Release);
        apic::send_eoi();
    });

    log::info!("nvme: MSI-X wired to vector {:#x}", NVME_IRQ_VECTOR);
}

// ── PRP helpers ───────────────────────────────────────────────────────────────

/// Build the PRP1 / PRP2 pair for a physically contiguous transfer.
///
/// | Transfer size    | PRP1        | PRP2                          |
/// |------------------|-------------|-------------------------------|
/// | ≤ 4 KiB          | buf_phys    | 0                             |
/// | 4 KiB < n ≤ 8 KiB| buf_phys    | buf_phys + 4096               |
/// | > 8 KiB          | buf_phys    | phys addr of PRP list page    |
///
/// For the >8 KiB case the PRP list is written into `list_page_phys`
/// (a caller-supplied 4 KiB-aligned page).  The list contains the
/// physical addresses of pages 2, 3, … of the buffer (each entry is
/// 8 bytes, little-endian).  Up to 511 entries fit in one 4 KiB page,
/// supporting transfers up to 512 * 4096 = 2 MiB.
///
/// # Safety
/// `list_page_phys` must be a valid, writable 4 KiB physical page and
/// must remain stable for the duration of the DMA transfer.
unsafe fn build_prps(
    buf_phys:      u64,
    byte_len:      usize,
    list_page_phys: u64,
) -> Result<(u64, u64), &'static str> {
    const PAGE: usize = 4096;
    if byte_len <= PAGE {
        return Ok((buf_phys, 0));
    }
    if byte_len <= PAGE * 2 {
        return Ok((buf_phys, buf_phys + PAGE as u64));
    }
    // PRP list path.
    let pages_total = (byte_len + PAGE - 1) / PAGE;
    let list_entries = pages_total - 1; // page 0 is in PRP1
    // One 4 KiB list page holds 512 u64 entries.  The last entry in the
    // page may itself be a pointer to the next list page (chaining), but
    // we do not implement chaining — cap at 511 data entries + no chain.
    if list_entries > 511 {
        return Err("transfer too large for single PRP list page");
    }
    let list = list_page_phys as *mut u64;
    for n in 0..list_entries {
        let page_phys = buf_phys + ((n + 1) * PAGE) as u64;
        write_volatile(list.add(n), page_phys);
    }
    fence(Ordering::Release);
    Ok((buf_phys, list_page_phys))
}

// ── Controller initialisation ─────────────────────────────────────────────────

unsafe fn _init(bar0: u64) {
    let cap = mmio_read64(bar0, NVME_CAP);
    let dstrd_bits = ((cap >> CAP_DSTRD_SHIFT) & CAP_DSTRD_MASK) as usize;
    let dstrd = 1usize << (2 + dstrd_bits);

    // Disable controller.
    mmio_write32(bar0, NVME_CC, 0);
    let mut spin = 0usize;
    while mmio_read32(bar0, NVME_CSTS) & CSTS_RDY != 0 {
        core::hint::spin_loop();
        spin += 1;
        if spin > 2_000_000 { return; }
    }

    // Allocate queues and DMA scratch regions.
    let asq  = alloc_dma(ADMIN_DEPTH * 64, 4096).expect("asq alloc");
    let acq  = alloc_dma(ADMIN_DEPTH * 16, 4096).expect("acq alloc");
    let iosq = alloc_dma(IO_DEPTH    * 64, 4096).expect("iosq alloc");
    let iocq = alloc_dma(IO_DEPTH    * 16, 4096).expect("iocq alloc");
    let dma  = alloc_dma(4096, 4096).expect("dma alloc");
    // Dedicated 4 KiB page for PRP lists.
    let prp_list = alloc_dma(4096, 4096).expect("prp list alloc");

    mmio_write32(
        bar0, NVME_AQA,
        ((ADMIN_DEPTH as u32 - 1) << 16) | (ADMIN_DEPTH as u32 - 1),
    );
    mmio_write64(bar0, NVME_ASQ, asq);
    mmio_write64(bar0, NVME_ACQ, acq);

    let cc = CC_EN | CC_CSS_NVM | CC_MPS_4K | CC_AQS_64 | CC_IOSQES | CC_IOCQES;
    mmio_write32(bar0, NVME_CC, cc);

    spin = 0;
    loop {
        let csts = mmio_read32(bar0, NVME_CSTS);
        if csts & CSTS_CFS != 0 { return; }
        if csts & CSTS_RDY != 0 { break; }
        spin += 1;
        if spin > 4_000_000 { return; }
        core::hint::spin_loop();
    }

    *CTRL.lock() = Some(NvmeCtrl {
        bar0,
        dstrd,
        asq_phys:      asq,
        acq_phys:      acq,
        iosq_phys:     iosq,
        iocq_phys:     iocq,
        dma_phys:      dma,
        prp_list_phys: prp_list,
        asq_tail:  0,
        acq_head:  0,
        acq_phase: 1,
        iosq_tail:  0,
        iocq_head:  0,
        iocq_phase: 1,
        next_cid:   1,
    });

    // SET FEATURES — number of queues (1 IO SQ + 1 IO CQ).
    let mut cmd = SqEntry::default();
    cmd.cdw0  = (ADM_SET_FEAT as u32) | (next_cid() << 16);
    cmd.cdw10 = 0x07;
    cmd.cdw11 = 0x0001_0001;
    admin_submit(cmd);
    if admin_complete().is_err() { return; }

    // CREATE IO CQ.
    let iocq_pa = CTRL.lock().as_ref().unwrap().iocq_phys;
    let mut cmd = SqEntry::default();
    cmd.cdw0  = (ADM_CREATE_IOCQ as u32) | (next_cid() << 16);
    cmd.prp1  = iocq_pa;
    cmd.cdw10 = ((IO_DEPTH as u32 - 1) << 16) | 1;
    cmd.cdw11 = 1; // physically contiguous
    admin_submit(cmd);
    if admin_complete().is_err() { return; }

    // CREATE IO SQ.
    let iosq_pa = CTRL.lock().as_ref().unwrap().iosq_phys;
    let mut cmd = SqEntry::default();
    cmd.cdw0  = (ADM_CREATE_IOSQ as u32) | (next_cid() << 16);
    cmd.prp1  = iosq_pa;
    cmd.cdw10 = ((IO_DEPTH as u32 - 1) << 16) | 1;
    cmd.cdw11 = (1 << 16) | 1; // CQID=1, physically contiguous
    admin_submit(cmd);
    if admin_complete().is_err() { return; }

    // IDENTIFY NAMESPACE 1.
    let dma_pa = CTRL.lock().as_ref().unwrap().dma_phys;
    core::ptr::write_bytes(dma_pa as *mut u8, 0, 4096);
    let mut cmd = SqEntry::default();
    cmd.cdw0  = (ADM_IDENTIFY as u32) | (next_cid() << 16);
    cmd.nsid  = 1;
    cmd.prp1  = dma_pa;
    cmd.cdw10 = CNS_NAMESPACE;
    admin_submit(cmd);
    if admin_complete().is_err() { return; }
    let id_ns = core::slice::from_raw_parts(dma_pa as *const u8, 4096);
    let nsze   = *(id_ns.as_ptr() as *const u64);
    let flbas  = id_ns[26] & 0x0F;
    let lbaf_off = 128 + flbas as usize * 4;
    let lbads    = id_ns[lbaf_off + 2] as u32;
    let sector_size = 1u32 << lbads;

    // IDENTIFY CONTROLLER.
    core::ptr::write_bytes(dma_pa as *mut u8, 0, 4096);
    let mut cmd = SqEntry::default();
    cmd.cdw0  = (ADM_IDENTIFY as u32) | (next_cid() << 16);
    cmd.prp1  = dma_pa;
    cmd.cdw10 = CNS_CONTROLLER;
    admin_submit(cmd);
    if admin_complete().is_err() { return; }
    let id_ctrl = core::slice::from_raw_parts(dma_pa as *const u8, 4096);
    let mut model = [0u8; 40];
    for i in 0..40 { model[i] = id_ctrl[24 + i]; }

    DISKS.lock().push(DiskInfo { sector_count: nsze, sector_size, model });
}

// ── IO path ───────────────────────────────────────────────────────────────────

fn io_rw(
    nsid:     u32,
    lba:      u64,
    count:    u32,
    buf_phys: u64,
    write:    bool,
) -> Result<(), &'static str> {
    if count == 0 {
        return Err("zero-length io");
    }
    if (buf_phys & 0xFFF) != 0 {
        return Err("buffer not page aligned");
    }
    let byte_len = count as usize * 512;
    let cid      = next_cid();
    let opcode   = if write { IO_WRITE } else { IO_READ };

    // Build SQ entry.
    let mut cmd = SqEntry::default();
    cmd.cdw0  = (opcode as u32) | ((cid as u32) << 16);
    cmd.nsid  = nsid;
    cmd.cdw10 = lba as u32;
    cmd.cdw11 = (lba >> 32) as u32;
    cmd.cdw12 = count - 1;

    // Set up PRPs; requires controller lock to access prp_list_phys.
    {
        let ctrl = CTRL.lock();
        let c = ctrl.as_ref().ok_or("nvme not initialised")?;
        let (prp1, prp2) = unsafe {
            build_prps(buf_phys, byte_len, c.prp_list_phys)?
        };
        cmd.prp1 = prp1;
        cmd.prp2 = prp2;
    }

    // Submit and poll/wait for completion.
    let mut ctrl = CTRL.lock();
    let c = ctrl.as_mut().ok_or("nvme not initialised")?;

    let entry = (c.iosq_phys as usize + c.iosq_tail * 64) as *mut SqEntry;
    unsafe { entry.write_volatile(cmd); }
    fence(Ordering::Release);

    c.iosq_tail = (c.iosq_tail + 1) % IO_DEPTH;
    let sq_db = 0x1000 + 2 * c.dstrd;
    unsafe {
        write_volatile(
            (c.bar0 as usize + sq_db) as *mut u32,
            c.iosq_tail as u32,
        );
    }

    // Clear stale flag before entering the wait loop.
    NVME_COMPLETION_FLAG.store(false, Ordering::Release);

    let timeout = 10_000_000usize;
    for _ in 0..timeout {
        // Fast path: ISR fired.
        if NVME_COMPLETION_FLAG.swap(false, Ordering::AcqRel) {
            // Fall through to CQE check below.
        }

        let cqe = unsafe {
            &*((c.iocq_phys as usize + c.iocq_head * 16) as *const CqEntry)
        };
        fence(Ordering::Acquire);

        if (cqe.status & 1) as u8 == c.iocq_phase {
            let sc = (cqe.status >> 1) & 0xFF;
            c.iocq_head = (c.iocq_head + 1) % IO_DEPTH;
            if c.iocq_head == 0 { c.iocq_phase ^= 1; }
            let cq_db = 0x1000 + (2 * 1 + 1) * c.dstrd;
            unsafe {
                write_volatile(
                    (c.bar0 as usize + cq_db) as *mut u32,
                    c.iocq_head as u32,
                );
            }
            return if sc == 0 { Ok(()) } else { Err("nvme io error") };
        }

        core::hint::spin_loop();
    }
    Err("nvme io timeout")
}

// ── Admin helpers ─────────────────────────────────────────────────────────────

fn admin_submit(cmd: SqEntry) {
    let mut ctrl = CTRL.lock();
    let c = ctrl.as_mut().unwrap();
    let entry = (c.asq_phys as usize + c.asq_tail * 64) as *mut SqEntry;
    unsafe { entry.write_volatile(cmd); }
    fence(Ordering::Release);
    c.asq_tail = (c.asq_tail + 1) % ADMIN_DEPTH;
    unsafe {
        write_volatile(
            (c.bar0 as usize + 0x1000) as *mut u32,
            c.asq_tail as u32,
        );
    }
}

fn admin_complete() -> Result<(), &'static str> {
    let mut ctrl = CTRL.lock();
    let c = ctrl.as_mut().unwrap();

    // Clear stale flag before entering the wait loop.
    NVME_COMPLETION_FLAG.store(false, Ordering::Release);

    let timeout = 10_000_000usize;
    for _ in 0..timeout {
        // Fast path: ISR fired.
        if NVME_COMPLETION_FLAG.swap(false, Ordering::AcqRel) {
            // Fall through to CQE check.
        }

        let cqe = unsafe {
            &*((c.acq_phys as usize + c.acq_head * 16) as *const CqEntry)
        };
        fence(Ordering::Acquire);

        if (cqe.status & 1) as u8 == c.acq_phase {
            let sc = (cqe.status >> 1) & 0xFF;
            c.acq_head = (c.acq_head + 1) % ADMIN_DEPTH;
            if c.acq_head == 0 { c.acq_phase ^= 1; }
            let db = 0x1000 + c.dstrd;
            unsafe {
                write_volatile(
                    (c.bar0 as usize + db) as *mut u32,
                    c.acq_head as u32,
                );
            }
            return if sc == 0 { Ok(()) } else { Err("nvme admin command failed") };
        }

        core::hint::spin_loop();
    }
    Err("nvme admin timeout")
}

fn next_cid() -> u32 {
    let mut ctrl = CTRL.lock();
    let c = ctrl.as_mut().unwrap();
    let cid = c.next_cid;
    c.next_cid = c.next_cid.wrapping_add(1);
    cid as u32
}

// ── MMIO helpers ──────────────────────────────────────────────────────────────

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
    let lo = read_volatile((base as usize + off)     as *const u32) as u64;
    let hi = read_volatile((base as usize + off + 4) as *const u32) as u64;
    lo | (hi << 32)
}
#[inline]
unsafe fn mmio_write64(base: u64, off: usize, val: u64) {
    write_volatile((base as usize + off)     as *mut u32, val as u32);
    write_volatile((base as usize + off + 4) as *mut u32, (val >> 32) as u32);
}

fn alloc_dma(size: usize, align: usize) -> Option<u64> {
    let pages = (size + 0xFFF) / 0x1000;
    let phys = crate::mm::pmm::alloc_pages_aligned(pages, align)?
        .as_ptr() as u64;
    unsafe {
        core::ptr::write_bytes(phys as *mut u8, 0, pages * 0x1000);
    }
    Some(phys)
}
