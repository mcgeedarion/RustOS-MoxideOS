//! NVMe host controller driver.
//!
//! ## Architecture
//!   One Admin queue pair (SQ + CQ, 64 entries each) for controller init.
//!   One IO queue pair  (SQ + CQ, 64 entries each) for read/write I/O.
//!   Polled completion with IRQ drain fallback (MSI-X at NVME_IRQ_VECTOR).
//!
//! ## Initialization sequence (nvme_probe)
//!   1. PCIe discovery: find_device_by_class(PCI_CLASS_STORAGE_NVME)
//!   2. BAR0 MMIO map (UC), dev.enable()
//!   3. MSI-X (entry 0) → NVME_IRQ_VECTOR; fallback MSI; fallback polled
//!   4. Controller reset: CC.EN=0 → CSTS.RDY=0
//!   5. Program AQA / ASQ / ACQ
//!   6. Set CC (4K pages, NVM cmd set, SQ/CQ 64-byte entries)
//!   7. CC.EN=1 → spin CSTS.RDY=1 (timeout = CAP.TO × 500 ms)
//!   8. Admin Identify Controller (CNS=1) — log model string
//!   9. Admin Identify Namespace 1 (CNS=0) — store NSZE + LBADS
//!  10. Create IO Completion Queue (Admin cmd 0x05)
//!  11. Create IO Submission Queue (Admin cmd 0x01)
//!
//! ## Register map (BAR0 offsets)
//!   0x000  CAP    (u64)  Controller Capabilities
//!   0x008  VS     (u32)  Version
//!   0x014  INTMS  (u32)  Interrupt Mask Set
//!   0x018  INTMC  (u32)  Interrupt Mask Clear
//!   0x01C  CC     (u32)  Controller Configuration
//!   0x01C  CSTS   (u32)  Controller Status  (offset 0x01C + 4 = 0x020)
//!   0x024  AQA    (u32)  Admin Queue Attributes
//!   0x028  ASQ    (u64)  Admin Submission Queue Base Address
//!   0x030  ACQ    (u64)  Admin Completion Queue Base Address
//!   0x1000 SQ0TDB (u32)  Admin SQ tail doorbell  (stride = 4 << CAP.DSTRD)
//!   0x1004 CQ0HDB (u32)  Admin CQ head doorbell
//!   0x1008 SQ1TDB (u32)  IO SQ tail doorbell
//!   0x100C CQ1HDB (u32)  IO CQ head doorbell
//!
//! ## Wiring in kernel_main
//!   ```
//!   // After pcie_init():
//!   nvme::nvme_probe();
//!   idt.set_handler(nvme::NVME_IRQ_VECTOR, nvme_irq_stub);
//!   // naked extern fn nvme_irq_stub calls nvme::nvme_irq()
//!   ```

extern crate alloc;
use alloc::string::String;
use spin::Mutex;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

use crate::drivers::pcie::{
    find_device_by_class, pci_enable_msix, pci_enable_msi_ex,
    PCI_CLASS_STORAGE_NVME,
};
use crate::mm::pmm;

// ── IRQ vector ────────────────────────────────────────────────────────────

/// IDT vector reserved for the NVMe MSI-X interrupt.
pub const NVME_IRQ_VECTOR: u8 = 0x32;

// ── NVMe register offsets (BAR0) ──────────────────────────────────────────

const NVME_REG_CAP:    u64 = 0x000;
const NVME_REG_VS:     u64 = 0x008;
const NVME_REG_INTMS:  u64 = 0x014;
const NVME_REG_INTMC:  u64 = 0x018;
const NVME_REG_CC:     u64 = 0x01C;
const NVME_REG_CSTS:   u64 = 0x020;
const NVME_REG_AQA:    u64 = 0x024;
const NVME_REG_ASQ:    u64 = 0x028;
const NVME_REG_ACQ:    u64 = 0x030;

// Doorbell base offset and stride (4 << CAP.DSTRD, DSTRD usually 0 → stride = 4)
const NVME_DOORBELL_BASE: u64 = 0x1000;

// CC bits
const CC_EN:       u32 = 1 << 0;
const CC_CSS_NVM:  u32 = 0 << 4;  // NVM command set
const CC_MPS_4K:   u32 = 0 << 7;  // 4 KiB memory page size (2^(12+MPS))
const CC_AMS_RR:   u32 = 0 << 11; // Round-robin arbitration
const CC_SQS_64:   u32 = 6 << 16; // IO SQ entry size = 2^6 = 64 bytes
const CC_CQS_16:   u32 = 4 << 20; // IO CQ entry size = 2^4 = 16 bytes

// CSTS bits
const CSTS_RDY:   u32 = 1 << 0;
const CSTS_CFS:   u32 = 1 << 1;

// Admin command opcodes
const ADMIN_DELETE_IO_SQ:  u8 = 0x00;
const ADMIN_CREATE_IO_SQ:  u8 = 0x01;
const ADMIN_DELETE_IO_CQ:  u8 = 0x04;
const ADMIN_CREATE_IO_CQ:  u8 = 0x05;
const ADMIN_IDENTIFY:      u8 = 0x06;

// NVM command opcodes
const NVM_FLUSH:  u8 = 0x00;
const NVM_WRITE:  u8 = 0x01;
const NVM_READ:   u8 = 0x02;

// Identify CNS values
const CNS_NAMESPACE:  u8 = 0x00;
const CNS_CONTROLLER: u8 = 0x01;

// Queue depth (number of entries)
const QUEUE_DEPTH: usize = 64;

// ── Submission Queue Entry (SQE) — 64 bytes ───────────────────────────────

#[repr(C, align(64))]
#[derive(Clone, Copy, Default)]
struct Sqe {
    cdw0:    u32, // [7:0]=opcode [9:8]=fuse [15:14]=psdt [31:16]=CID
    nsid:    u32,
    cdw2:    u32,
    cdw3:    u32,
    mptr:    u64, // metadata pointer
    prp1:    u64, // first PRP entry (or SGL descriptor)
    prp2:    u64, // second PRP entry (or PRP list pointer)
    cdw10:   u32,
    cdw11:   u32,
    cdw12:   u32,
    cdw13:   u32,
    cdw14:   u32,
    cdw15:   u32,
}

// ── Completion Queue Entry (CQE) — 16 bytes ───────────────────────────────

#[repr(C, align(16))]
#[derive(Clone, Copy, Default)]
struct Cqe {
    dw0:  u32, // command-specific result
    dw1:  u32, // reserved
    dw2:  u32, // [15:0]=SQ head ptr [31:16]=SQ identifier
    dw3:  u32, // [15:0]=CID  [16]=phase  [31:17]=status field
}

impl Cqe {
    #[inline] fn phase(&self) -> bool  { self.dw3 & (1 << 16) != 0 }
    #[inline] fn status(&self) -> u16  { ((self.dw3 >> 17) & 0x7FFF) as u16 }
    #[inline] fn cid(&self)   -> u16  { (self.dw3 & 0xFFFF) as u16 }
}

// ── Queue pair ────────────────────────────────────────────────────────────

struct Queue {
    /// Physical/virtual base of the SQ (64 × 64-byte SQEs = 4 KiB)
    sq_base: u64,
    /// Physical/virtual base of the CQ (64 × 16-byte CQEs = 1 KiB, padded to 4 KiB)
    cq_base: u64,
    sq_tail: u32,
    cq_head: u32,
    cq_phase: bool, // expected phase bit for next CQE
    next_cid: u16,
    /// Doorbell MMIO pointer for SQ tail
    sq_db: *mut u32,
    /// Doorbell MMIO pointer for CQ head
    cq_db: *mut u32,
}

unsafe impl Send for Queue {}

impl Queue {
    const fn uninit() -> Self {
        Queue {
            sq_base: 0, cq_base: 0,
            sq_tail: 0, cq_head: 0,
            cq_phase: true,
            next_cid: 1,
            sq_db: core::ptr::null_mut(),
            cq_db: core::ptr::null_mut(),
        }
    }

    /// Submit a pre-filled SQE, ring the tail doorbell.
    /// Returns the CID assigned to this command.
    unsafe fn submit(&mut self, mut sqe: Sqe) -> u16 {
        let cid = self.next_cid;
        self.next_cid = self.next_cid.wrapping_add(1).max(1);
        sqe.cdw0 = (sqe.cdw0 & 0x0000_FFFF) | ((cid as u32) << 16);

        let slot = (self.sq_base as *mut Sqe).add(self.sq_tail as usize);
        core::ptr::write_volatile(slot, sqe);

        self.sq_tail = (self.sq_tail + 1) % QUEUE_DEPTH as u32;
        core::ptr::write_volatile(self.sq_db, self.sq_tail);
        cid
    }

    /// Poll the CQ until a CQE with `cid` appears or `retries` spins elapse.
    /// Returns the status field (0 = success).
    unsafe fn poll(&mut self, cid: u16, retries: usize) -> u16 {
        for _ in 0..retries {
            let slot = (self.cq_base as *mut Cqe).add(self.cq_head as usize);
            let cqe = core::ptr::read_volatile(slot);
            if cqe.phase() == self.cq_phase && cqe.cid() == cid {
                let status = cqe.status();
                self.cq_head = (self.cq_head + 1) % QUEUE_DEPTH as u32;
                if self.cq_head == 0 { self.cq_phase = !self.cq_phase; }
                // Ack CQ head to controller
                core::ptr::write_volatile(self.cq_db, self.cq_head);
                return status;
            }
            core::arch::asm!("pause", options(nomem, nostack));
        }
        0xFFFF // timeout
    }

    /// Drain all newly-completed CQEs (IRQ path — no specific CID).
    unsafe fn drain(&mut self) {
        loop {
            let slot = (self.cq_base as *mut Cqe).add(self.cq_head as usize);
            let cqe = core::ptr::read_volatile(slot);
            if cqe.phase() != self.cq_phase { break; }
            self.cq_head = (self.cq_head + 1) % QUEUE_DEPTH as u32;
            if self.cq_head == 0 { self.cq_phase = !self.cq_phase; }
        }
        core::ptr::write_volatile(self.cq_db, self.cq_head);
    }
}

// ── Controller state ──────────────────────────────────────────────────────

struct NvmeCtrl {
    bar0:       u64,   // BAR0 MMIO virtual base
    db_stride:  u64,   // doorbell register stride in bytes (4 << DSTRD)
    admin:      Queue,
    io:         Queue,
    ns_size:    u64,   // total LBA count (from Identify NS NSZE)
    lba_shift:  u32,   // log2 of LBA size (from LBAF[FLBAS].LBADS); usually 9 (512B) or 12 (4KiB)
    ready:      bool,
}

unsafe impl Send for NvmeCtrl {}

impl NvmeCtrl {
    const fn uninit() -> Self {
        NvmeCtrl {
            bar0: 0, db_stride: 4,
            admin: Queue::uninit(),
            io:    Queue::uninit(),
            ns_size: 0, lba_shift: 9,
            ready: false,
        }
    }

    // ── Register accessors ────────────────────────────────────────────

    #[inline] unsafe fn read32(&self, off: u64) -> u32 {
        core::ptr::read_volatile((self.bar0 + off) as *const u32)
    }
    #[inline] unsafe fn write32(&self, off: u64, v: u32) {
        core::ptr::write_volatile((self.bar0 + off) as *mut u32, v);
    }
    #[inline] unsafe fn read64(&self, off: u64) -> u64 {
        core::ptr::read_volatile((self.bar0 + off) as *const u64)
    }
    #[inline] unsafe fn write64(&self, off: u64, v: u64) {
        core::ptr::write_volatile((self.bar0 + off) as *mut u64, v);
    }

    // ── Doorbell helpers ──────────────────────────────────────────────

    /// Return a *mut u32 doorbell pointer given its index in the doorbell array.
    /// Doorbells start at BAR0+0x1000, spaced db_stride bytes apart.
    /// Index layout: SQ0TDB=0, CQ0HDB=1, SQ1TDB=2, CQ1HDB=3, ...
    fn db_ptr(&self, idx: usize) -> *mut u32 {
        (self.bar0 + NVME_DOORBELL_BASE + idx as u64 * self.db_stride) as *mut u32
    }

    // ── Allocate one 4 KiB physically-contiguous page from PMM ───────

    fn alloc_page() -> u64 {
        let pa = pmm::alloc_page();
        assert!(pa != 0, "nvme: PMM out of memory");
        // Zero the page so SQEs/CQEs start in a known state.
        unsafe { core::ptr::write_bytes(pa as *mut u8, 0, 4096); }
        pa
    }

    // ── Controller reset ──────────────────────────────────────────────

    /// Disable the controller and wait for CSTS.RDY to clear.
    /// Returns false on timeout.
    unsafe fn reset(&mut self) -> bool {
        let cap = self.read64(NVME_REG_CAP);
        // CAP.TO [31:24] — timeout in 500 ms units
        let to_500ms = ((cap >> 24) & 0xFF) as u64;
        let spin_limit: u64 = (to_500ms + 1) * 500_000; // rough loop count

        // Clear CC.EN
        let cc = self.read32(NVME_REG_CC);
        self.write32(NVME_REG_CC, cc & !CC_EN);

        // Wait for CSTS.RDY=0
        for _ in 0..spin_limit {
            if self.read32(NVME_REG_CSTS) & CSTS_RDY == 0 { return true; }
            core::arch::asm!("pause", options(nomem, nostack));
        }
        false
    }

    // ── Admin queue setup ─────────────────────────────────────────────

    unsafe fn setup_admin_queues(&mut self) {
        let sq_pa = Self::alloc_page();
        let cq_pa = Self::alloc_page();

        // AQA: admin CQ size [27:16] and admin SQ size [11:0], 0-based
        let aqa: u32 = (((QUEUE_DEPTH - 1) as u32) << 16) | (QUEUE_DEPTH - 1) as u32;
        self.write32(NVME_REG_AQA, aqa);
        self.write64(NVME_REG_ASQ, sq_pa);
        self.write64(NVME_REG_ACQ, cq_pa);

        self.admin.sq_base  = sq_pa;
        self.admin.cq_base  = cq_pa;
        self.admin.sq_tail  = 0;
        self.admin.cq_head  = 0;
        self.admin.cq_phase = true;
        self.admin.sq_db    = self.db_ptr(0); // SQ0TDB
        self.admin.cq_db    = self.db_ptr(1); // CQ0HDB
    }

    // ── Enable controller ─────────────────────────────────────────────

    /// Set CC fields and raise CC.EN. Spin until CSTS.RDY=1.
    unsafe fn enable(&mut self) -> bool {
        let cap = self.read64(NVME_REG_CAP);
        let to_500ms = ((cap >> 24) & 0xFF) as u64;
        let spin_limit: u64 = (to_500ms + 1) * 500_000;

        let cc = CC_EN | CC_CSS_NVM | CC_MPS_4K | CC_AMS_RR | CC_SQS_64 | CC_CQS_16;
        self.write32(NVME_REG_CC, cc);

        for _ in 0..spin_limit {
            let csts = self.read32(NVME_REG_CSTS);
            if csts & CSTS_CFS != 0 { return false; } // fatal status
            if csts & CSTS_RDY != 0 { return true;  }
            core::arch::asm!("pause", options(nomem, nostack));
        }
        false
    }

    // ── Admin command helpers ─────────────────────────────────────────

    /// Send one admin command and poll for completion. Returns status (0=OK).
    unsafe fn admin_cmd(&mut self, sqe: Sqe) -> u16 {
        let cid = self.admin.submit(sqe);
        self.admin.poll(cid, 4_000_000)
    }

    // ── Identify Controller (CNS=1) ───────────────────────────────────

    unsafe fn identify_controller(&mut self) -> String {
        let buf_pa = Self::alloc_page(); // 4 KiB Identify data structure
        let sqe = Sqe {
            cdw0:  ADMIN_IDENTIFY as u32,
            nsid:  0,
            prp1:  buf_pa,
            prp2:  0,
            cdw10: CNS_CONTROLLER as u32,
            ..Default::default()
        };
        let status = self.admin_cmd(sqe);
        let mut model = String::new();
        if status == 0 {
            // Identify Controller bytes [24..63] = Model Number (ASCII, space-padded)
            let ptr = buf_pa as *const u8;
            for i in 24..64usize {
                let b = core::ptr::read_volatile(ptr.add(i));
                if b == 0 || b == b' ' { continue; }
                model.push(b as char);
            }
        }
        // Return page to PMM
        pmm::free_page(buf_pa);
        model
    }

    // ── Identify Namespace 1 (CNS=0) ─────────────────────────────────

    unsafe fn identify_namespace(&mut self) {
        let buf_pa = Self::alloc_page();
        let sqe = Sqe {
            cdw0:  ADMIN_IDENTIFY as u32,
            nsid:  1,
            prp1:  buf_pa,
            prp2:  0,
            cdw10: CNS_NAMESPACE as u32,
            ..Default::default()
        };
        let status = self.admin_cmd(sqe);
        if status == 0 {
            let ptr = buf_pa as *const u64;
            // NSZE at offset 0 (bytes 0–7)
            self.ns_size = core::ptr::read_volatile(ptr);
            // FLBAS at byte 26: bits [3:0] = index into LBAF array
            let flbas = core::ptr::read_volatile((buf_pa + 26) as *const u8) & 0xF;
            // LBAF[i] at offset 128 + i*4; bits [23:16] = LBADS
            let lbaf_off = 128 + flbas as u64 * 4;
            let lbaf = core::ptr::read_volatile((buf_pa + lbaf_off) as *const u32);
            self.lba_shift = (lbaf >> 16) & 0xFF;
            if self.lba_shift == 0 { self.lba_shift = 9; } // default 512B
        }
        pmm::free_page(buf_pa);
    }

    // ── Create IO Completion Queue (Admin cmd 0x05) ───────────────────

    unsafe fn create_io_cq(&mut self, cq_pa: u64) -> bool {
        // CDW10: [15:0]=QID=1, [31:16]=QSIZE-1
        // CDW11: [0]=PC (physically contiguous), [1]=IEN (IRQ enable), [31:16]=IV=0
        let cdw10: u32 = 1 | (((QUEUE_DEPTH - 1) as u32) << 16);
        let cdw11: u32 = 1 | (1 << 1); // PC=1, IEN=1, IV=0
        let sqe = Sqe {
            cdw0:  ADMIN_CREATE_IO_CQ as u32,
            prp1:  cq_pa,
            cdw10, cdw11,
            ..Default::default()
        };
        self.admin_cmd(sqe) == 0
    }

    // ── Create IO Submission Queue (Admin cmd 0x01) ───────────────────

    unsafe fn create_io_sq(&mut self, sq_pa: u64) -> bool {
        // CDW10: [15:0]=QID=1, [31:16]=QSIZE-1
        // CDW11: [0]=PC, [15:1]=reserved, [31:16]=CQID=1 (associated CQ)
        let cdw10: u32 = 1 | (((QUEUE_DEPTH - 1) as u32) << 16);
        let cdw11: u32 = 1 | (1 << 16); // PC=1, CQID=1
        let sqe = Sqe {
            cdw0:  ADMIN_CREATE_IO_SQ as u32,
            prp1:  sq_pa,
            cdw10, cdw11,
            ..Default::default()
        };
        self.admin_cmd(sqe) == 0
    }

    // ── IO queue setup ────────────────────────────────────────────────

    unsafe fn setup_io_queues(&mut self) -> bool {
        let cq_pa = Self::alloc_page();
        let sq_pa = Self::alloc_page();

        if !self.create_io_cq(cq_pa) { return false; }
        if !self.create_io_sq(sq_pa) { return false; }

        self.io.sq_base  = sq_pa;
        self.io.cq_base  = cq_pa;
        self.io.sq_tail  = 0;
        self.io.cq_head  = 0;
        self.io.cq_phase = true;
        self.io.sq_db    = self.db_ptr(2); // SQ1TDB
        self.io.cq_db    = self.db_ptr(3); // CQ1HDB
        true
    }
}

// ── Global controller instance ────────────────────────────────────────────

static CTRL: Mutex<NvmeCtrl> = Mutex::new(NvmeCtrl::uninit());

// ── Public API ────────────────────────────────────────────────────────────

/// Probe, reset, identify, and set up the NVMe controller.
/// Call after pcie_init() and before any storage I/O.
pub fn nvme_probe() {
    let dev = match find_device_by_class(PCI_CLASS_STORAGE_NVME) {
        Some(d) => d,
        None => {
            crate::arch::x86_64::serial::serial_println!("nvme: no NVMe controller found");
            return;
        }
    };

    let bar0 = match dev.bar_mmio(0) {
        Some(b) => b,
        None => {
            crate::arch::x86_64::serial::serial_println!("nvme: BAR0 not MMIO");
            return;
        }
    };

    dev.enable();

    // Enable MSI-X (entry 0), fall back to MSI, then run polled.
    let irq_mode = if pci_enable_msix(&dev, 0, NVME_IRQ_VECTOR, 0) {
        "MSI-X"
    } else if pci_enable_msi_ex(&dev, 0, NVME_IRQ_VECTOR) {
        "MSI"
    } else {
        "polled"
    };

    let mut ctrl = CTRL.lock();
    ctrl.bar0      = bar0;

    // Read doorbell stride from CAP.DSTRD [35:32]
    let cap = unsafe { ctrl.read64(NVME_REG_CAP) };
    let dstrd = ((cap >> 32) & 0xF) as u64;
    ctrl.db_stride = 4u64 << dstrd;

    // Log version
    let vs = unsafe { ctrl.read32(NVME_REG_VS) };
    crate::arch::x86_64::serial::serial_println!(
        "nvme: BAR0={:#x} vs={}.{} irq={}",
        bar0,
        (vs >> 16), (vs >> 8) & 0xFF,
        irq_mode
    );

    // 1. Reset
    if !unsafe { ctrl.reset() } {
        crate::arch::x86_64::serial::serial_println!("nvme: reset timeout");
        return;
    }

    // 2. Admin queues (must be before CC.EN)
    unsafe { ctrl.setup_admin_queues(); }

    // 3. Enable
    if !unsafe { ctrl.enable() } {
        crate::arch::x86_64::serial::serial_println!("nvme: enable timeout / CFS");
        return;
    }

    // 4. Identify Controller
    let model = unsafe { ctrl.identify_controller() };
    crate::arch::x86_64::serial::serial_println!("nvme: model: {}", model);

    // 5. Identify Namespace 1
    unsafe { ctrl.identify_namespace(); }
    crate::arch::x86_64::serial::serial_println!(
        "nvme: ns1 size={} LBAs  lba_shift={}",
        ctrl.ns_size, ctrl.lba_shift
    );

    // 6. IO queues
    if !unsafe { ctrl.setup_io_queues() } {
        crate::arch::x86_64::serial::serial_println!("nvme: IO queue creation failed");
        return;
    }

    ctrl.ready = true;
    crate::arch::x86_64::serial::serial_println!("nvme: ready");
}

/// Return the total number of logical blocks on namespace 1.
/// Returns 0 if the controller has not been successfully probed.
pub fn nvme_capacity() -> u64 {
    CTRL.lock().ns_size
}

/// Return the LBA size in bytes (typically 512 or 4096).
pub fn nvme_lba_size() -> u32 {
    1u32 << CTRL.lock().lba_shift
}

/// Read `count` contiguous LBAs starting at `lba` into `buf`.
/// `buf` must be physically contiguous and at least `count * lba_size` bytes.
/// Returns true on success.
pub fn nvme_read(lba: u64, count: u16, buf: *mut u8) -> bool {
    let mut ctrl = CTRL.lock();
    if !ctrl.ready { return false; }
    let buf_pa = buf as u64;

    // CDW10: SLBA low 32 bits  CDW11: SLBA high 32 bits
    // CDW12: [15:0]=NLB-1 (0-based number of logical blocks)
    let sqe = Sqe {
        cdw0:  NVM_READ as u32,
        nsid:  1,
        prp1:  buf_pa,
        prp2:  0, // single-page transfer ≤ 4 KiB; for larger use PRP list
        cdw10: (lba & 0xFFFF_FFFF) as u32,
        cdw11: (lba >> 32) as u32,
        cdw12: (count as u32).saturating_sub(1),
        ..Default::default()
    };
    let cid = unsafe { ctrl.io.submit(sqe) };
    let status = unsafe { ctrl.io.poll(cid, 4_000_000) };
    status == 0
}

/// Write `count` contiguous LBAs starting at `lba` from `buf`.
/// `buf` must be physically contiguous and at least `count * lba_size` bytes.
/// Returns true on success.
pub fn nvme_write(lba: u64, count: u16, buf: *const u8) -> bool {
    let mut ctrl = CTRL.lock();
    if !ctrl.ready { return false; }
    let buf_pa = buf as u64;

    let sqe = Sqe {
        cdw0:  NVM_WRITE as u32,
        nsid:  1,
        prp1:  buf_pa,
        prp2:  0,
        cdw10: (lba & 0xFFFF_FFFF) as u32,
        cdw11: (lba >> 32) as u32,
        cdw12: (count as u32).saturating_sub(1),
        ..Default::default()
    };
    let cid = unsafe { ctrl.io.submit(sqe) };
    let status = unsafe { ctrl.io.poll(cid, 4_000_000) };
    status == 0
}

/// Convenience wrapper: read a single 512-byte sector.
pub fn nvme_read_sector(lba: u64, buf: &mut [u8; 512]) -> bool {
    nvme_read(lba, 1, buf.as_mut_ptr())
}

/// Convenience wrapper: write a single 512-byte sector.
pub fn nvme_write_sector(lba: u64, buf: &[u8; 512]) -> bool {
    nvme_write(lba, 1, buf.as_ptr())
}

/// IRQ handler — call from the naked IDT stub at NVME_IRQ_VECTOR.
/// Drains the IO CQ and clears the MSI-X interrupt.
pub fn nvme_irq() {
    let mut ctrl = CTRL.lock();
    if !ctrl.ready { return; }
    unsafe {
        // Clear interrupt mask (INTMC) so the device de-asserts the line
        ctrl.write32(NVME_REG_INTMC, 1);
        ctrl.io.drain();
    }
}
