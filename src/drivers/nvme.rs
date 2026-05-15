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
//! ## PRP physical addresses
//!
//! NVMe PRPs are *physical* addresses — the controller performs DMA using the
//! host physical address space.  All buffers passed to nvme_read/nvme_write
//! must be described by their physical address, not their virtual address.
//!
//! For kernel-mode callers with identity-mapped memory the two are the same,
//! but for any future higher-half or non-identity mapping the distinction
//! matters.  The public API therefore takes a `u64 buf_pa` (physical address)
//! rather than a raw pointer, forcing the caller to perform the VA→PA
//! translation (typically via `virt_to_phys()`).
//!
//! Internal DMA scratch buffers (alloc_page) come from the PMM which returns
//! physical addresses directly, so those paths are always correct.
//!
//! ## sfence vs mfence in the submit path
//!
//! The NVMe spec requires that all SQE stores are visible to the device
//! before the doorbell write.  Only *store* ordering is required.
//! `sfence` (store-only barrier, ~1 cycle) is sufficient and is what Linux
//! and other production NVMe drivers use.  `mfence` (~100 cycles) is
//! unnecessarily expensive.
//!
//! ## poll() load ordering
//!
//! `poll()` uses `read_volatile` for the CQE, which includes a compiler
//! barrier.  On x86_64 loads are strongly ordered (TSO) so no `lfence` is
//! required.  On RISC-V (weak ordering) a `fence r,r` is emitted before
//! reading each CQE to prevent speculative hoisting of the load.

extern crate alloc;
use alloc::string::String;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use spin::Mutex;

use crate::drivers::pcie::{
    find_device_by_class, pci_enable_msi_ex, pci_enable_msix, PCI_CLASS_STORAGE_NVME,
};
use crate::mm::pmm;

// ── IRQ vector ────────────────────────────────────────────────────────────

pub const NVME_IRQ_VECTOR: u8 = 0x32;

// ── NVMe register offsets (BAR0) ──────────────────────────────────────────

const NVME_REG_CAP: u64 = 0x000;
const NVME_REG_VS: u64 = 0x008;
const NVME_REG_INTMS: u64 = 0x014;
const NVME_REG_INTMC: u64 = 0x018;
const NVME_REG_CC: u64 = 0x01C;
const NVME_REG_CSTS: u64 = 0x020;
const NVME_REG_AQA: u64 = 0x024;
const NVME_REG_ASQ: u64 = 0x028;
const NVME_REG_ACQ: u64 = 0x030;

const NVME_DOORBELL_BASE: u64 = 0x1000;

const CC_EN: u32 = 1 << 0;
const CC_CSS_NVM: u32 = 0 << 4;
const CC_MPS_4K: u32 = 0 << 7;
const CC_AMS_RR: u32 = 0 << 11;
const CC_SQS_64: u32 = 6 << 16;
const CC_CQS_16: u32 = 4 << 20;

const CSTS_RDY: u32 = 1 << 0;
const CSTS_CFS: u32 = 1 << 1;

const ADMIN_CREATE_IO_SQ: u8 = 0x01;
const ADMIN_CREATE_IO_CQ: u8 = 0x05;
const ADMIN_IDENTIFY: u8 = 0x06;

const NVM_WRITE: u8 = 0x01;
const NVM_READ: u8 = 0x02;

const CNS_NAMESPACE: u8 = 0x00;
const CNS_CONTROLLER: u8 = 0x01;

const QUEUE_DEPTH: usize = 64;

// ── Submission Queue Entry (SQE) — 64 bytes ───────────────────────────────

#[repr(C, align(64))]
#[derive(Clone, Copy, Default)]
struct Sqe {
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

// ── Completion Queue Entry (CQE) — 16 bytes ───────────────────────────────

#[repr(C, align(16))]
#[derive(Clone, Copy, Default)]
struct Cqe {
    dw0: u32,
    dw1: u32,
    dw2: u32,
    dw3: u32,
}

impl Cqe {
    #[inline]
    fn phase(&self) -> bool {
        self.dw3 & (1 << 16) != 0
    }
    #[inline]
    fn status(&self) -> u16 {
        ((self.dw3 >> 17) & 0x7FFF) as u16
    }
    #[inline]
    fn cid(&self) -> u16 {
        (self.dw3 & 0xFFFF) as u16
    }
}

// ── Queue pair ────────────────────────────────────────────────────────────

struct Queue {
    sq_base: u64,
    cq_base: u64,
    sq_tail: u32,
    cq_head: u32,
    cq_phase: bool,
    next_cid: u16,
    sq_db: *mut u32,
    cq_db: *mut u32,
}

unsafe impl Send for Queue {}

impl Queue {
    const fn uninit() -> Self {
        Queue {
            sq_base: 0,
            cq_base: 0,
            sq_tail: 0,
            cq_head: 0,
            cq_phase: true,
            next_cid: 1,
            sq_db: core::ptr::null_mut(),
            cq_db: core::ptr::null_mut(),
        }
    }

    /// Submit a pre-filled SQE and ring the tail doorbell.
    ///
    /// Uses `sfence` (not `mfence`) to order the SQE stores before the
    /// doorbell write.  Only store ordering is required by the NVMe spec;
    /// `sfence` (~1 cycle) vs `mfence` (~100 cycles).
    unsafe fn submit(&mut self, mut sqe: Sqe) -> u16 {
        let cid = self.next_cid;
        self.next_cid = self.next_cid.wrapping_add(1).max(1);
        sqe.cdw0 = (sqe.cdw0 & 0x0000_FFFF) | ((cid as u32) << 16);

        let slot = (self.sq_base as *mut Sqe).add(self.sq_tail as usize);
        core::ptr::write_volatile(slot, sqe);

        // sfence: all SQE stores must be globally visible before doorbell.
        #[cfg(target_arch = "x86_64")]
        core::arch::asm!("sfence", options(nostack, preserves_flags));
        // RISC-V: store fence (fence w,w).
        #[cfg(target_arch = "riscv64")]
        core::arch::asm!("fence w,w", options(nostack));

        self.sq_tail = (self.sq_tail + 1) % QUEUE_DEPTH as u32;
        core::ptr::write_volatile(self.sq_db, self.sq_tail);
        cid
    }

    /// Poll for a specific CQE by `cid`.  Returns the NVMe status field
    /// (0 = success, 0xFFFF = timeout).
    ///
    /// ## Load ordering
    ///
    /// x86_64: TSO guarantees load ordering; no lfence needed.
    /// RISC-V: emit `fence r,r` before each CQE read to prevent the CPU
    /// from speculating the load above a prior store (e.g. the doorbell
    /// write that produced this completion).
    unsafe fn poll(&mut self, cid: u16, retries: usize) -> u16 {
        for _ in 0..retries {
            // RISC-V: acquire load ordering before reading CQE.
            #[cfg(target_arch = "riscv64")]
            core::arch::asm!("fence r,r", options(nostack));

            let slot = (self.cq_base as *mut Cqe).add(self.cq_head as usize);
            let cqe = core::ptr::read_volatile(slot);
            if cqe.phase() == self.cq_phase && cqe.cid() == cid {
                let status = cqe.status();
                self.cq_head = (self.cq_head + 1) % QUEUE_DEPTH as u32;
                if self.cq_head == 0 {
                    self.cq_phase = !self.cq_phase;
                }
                core::ptr::write_volatile(self.cq_db, self.cq_head);
                return status;
            }
            #[cfg(target_arch = "x86_64")]
            core::arch::asm!("pause", options(nomem, nostack));
            #[cfg(target_arch = "riscv64")]
            core::arch::asm!("wfi", options(nomem, nostack));
        }
        0xFFFF
    }

    unsafe fn drain(&mut self) {
        loop {
            #[cfg(target_arch = "riscv64")]
            core::arch::asm!("fence r,r", options(nostack));

            let slot = (self.cq_base as *mut Cqe).add(self.cq_head as usize);
            let cqe = core::ptr::read_volatile(slot);
            if cqe.phase() != self.cq_phase {
                break;
            }
            self.cq_head = (self.cq_head + 1) % QUEUE_DEPTH as u32;
            if self.cq_head == 0 {
                self.cq_phase = !self.cq_phase;
            }
        }
        core::ptr::write_volatile(self.cq_db, self.cq_head);
    }
}

// ── Controller state ──────────────────────────────────────────────────────

struct NvmeCtrl {
    bar0: u64,
    db_stride: u64,
    admin: Queue,
    io: Queue,
    ns_size: u64,
    lba_shift: u32,
    ready: bool,
}

unsafe impl Send for NvmeCtrl {}

impl NvmeCtrl {
    const fn uninit() -> Self {
        NvmeCtrl {
            bar0: 0,
            db_stride: 4,
            admin: Queue::uninit(),
            io: Queue::uninit(),
            ns_size: 0,
            lba_shift: 9,
            ready: false,
        }
    }

    #[inline]
    unsafe fn read32(&self, off: u64) -> u32 {
        core::ptr::read_volatile((self.bar0 + off) as *const u32)
    }
    #[inline]
    unsafe fn write32(&self, off: u64, v: u32) {
        core::ptr::write_volatile((self.bar0 + off) as *mut u32, v);
    }
    #[inline]
    unsafe fn read64(&self, off: u64) -> u64 {
        core::ptr::read_volatile((self.bar0 + off) as *const u64)
    }
    #[inline]
    unsafe fn write64(&self, off: u64, v: u64) {
        core::ptr::write_volatile((self.bar0 + off) as *mut u64, v);
    }

    fn db_ptr(&self, idx: usize) -> *mut u32 {
        (self.bar0 + NVME_DOORBELL_BASE + idx as u64 * self.db_stride) as *mut u32
    }

    /// Allocate and zero a 4 KiB page.  Returns the **physical** address.
    ///
    /// # Panics
    /// Panics if the PMM is out of memory.  All internal NVMe DMA buffers
    /// are allocated at init time, so OOM here is a fatal boot error.
    fn alloc_page() -> u64 {
        let pa = pmm::alloc_page().expect("nvme: PMM out of memory during init");
        // Zero the page through the physical alias (identity-mapped kernel).
        unsafe {
            core::ptr::write_bytes(pa as *mut u8, 0, 4096);
        }
        pa as u64
    }

    unsafe fn reset(&mut self) -> bool {
        let cap = self.read64(NVME_REG_CAP);
        let to_500ms = ((cap >> 24) & 0xFF) as u64;
        let spin_limit: u64 = (to_500ms + 1) * 500_000;

        let cc = self.read32(NVME_REG_CC);
        self.write32(NVME_REG_CC, cc & !CC_EN);

        for _ in 0..spin_limit {
            if self.read32(NVME_REG_CSTS) & CSTS_RDY == 0 {
                return true;
            }
            core::arch::asm!("pause", options(nomem, nostack));
        }
        false
    }

    unsafe fn setup_admin_queues(&mut self) {
        let sq_pa = Self::alloc_page();
        let cq_pa = Self::alloc_page();

        let aqa: u32 = (((QUEUE_DEPTH - 1) as u32) << 16) | (QUEUE_DEPTH - 1) as u32;
        self.write32(NVME_REG_AQA, aqa);
        self.write64(NVME_REG_ASQ, sq_pa);
        self.write64(NVME_REG_ACQ, cq_pa);

        self.admin.sq_base = sq_pa;
        self.admin.cq_base = cq_pa;
        self.admin.sq_tail = 0;
        self.admin.cq_head = 0;
        self.admin.cq_phase = true;
        self.admin.sq_db = self.db_ptr(0);
        self.admin.cq_db = self.db_ptr(1);
    }

    unsafe fn enable(&mut self) -> bool {
        let cap = self.read64(NVME_REG_CAP);
        let to_500ms = ((cap >> 24) & 0xFF) as u64;
        let spin_limit: u64 = (to_500ms + 1) * 500_000;

        let cc = CC_EN | CC_CSS_NVM | CC_MPS_4K | CC_AMS_RR | CC_SQS_64 | CC_CQS_16;
        self.write32(NVME_REG_CC, cc);

        for _ in 0..spin_limit {
            let csts = self.read32(NVME_REG_CSTS);
            if csts & CSTS_CFS != 0 {
                return false;
            }
            if csts & CSTS_RDY != 0 {
                return true;
            }
            core::arch::asm!("pause", options(nomem, nostack));
        }
        false
    }

    unsafe fn admin_cmd(&mut self, sqe: Sqe) -> u16 {
        let cid = self.admin.submit(sqe);
        self.admin.poll(cid, 4_000_000)
    }

    unsafe fn identify_controller(&mut self) -> String {
        let buf_pa = Self::alloc_page();
        let sqe = Sqe {
            cdw0: ADMIN_IDENTIFY as u32,
            nsid: 0,
            prp1: buf_pa, // physical address — correct for DMA
            prp2: 0,
            cdw10: CNS_CONTROLLER as u32,
            ..Default::default()
        };
        let status = self.admin_cmd(sqe);
        let mut model = String::new();
        if status == 0 {
            // Read response through the physical alias (identity-mapped).
            let ptr = buf_pa as *const u8;
            for i in 24..64usize {
                let b = core::ptr::read_volatile(ptr.add(i));
                if b == 0 || b == b' ' {
                    continue;
                }
                model.push(b as char);
            }
        }
        pmm::free_page(buf_pa as usize);
        model
    }

    unsafe fn identify_namespace(&mut self) {
        let buf_pa = Self::alloc_page();
        let sqe = Sqe {
            cdw0: ADMIN_IDENTIFY as u32,
            nsid: 1,
            prp1: buf_pa, // physical address — correct for DMA
            prp2: 0,
            cdw10: CNS_NAMESPACE as u32,
            ..Default::default()
        };
        let status = self.admin_cmd(sqe);
        if status == 0 {
            // NSZE: bytes 0-7 of Identify Namespace data (physical alias).
            let ptr = buf_pa as *const u8;
            self.ns_size = core::ptr::read_volatile(ptr as *const u64);

            // FLBAS: byte 26, lower 4 bits = active LBA format index.
            let flbas = core::ptr::read_volatile(ptr.add(26)) & 0xF;

            // LBAFn: at offset 128 + n*4.  Each entry is 4 bytes; bits[23:16]
            // hold the LBADS (log2 of sector size).
            let lbaf_off = 128usize + flbas as usize * 4;
            // Guard: lbaf_off max = 128 + 15*4 = 188; well within 4096 bytes.
            let lbaf = core::ptr::read_volatile(ptr.add(lbaf_off) as *const u32);
            self.lba_shift = (lbaf >> 16) & 0xFF;
            if self.lba_shift == 0 {
                self.lba_shift = 9;
            }
        }
        pmm::free_page(buf_pa as usize);
    }

    unsafe fn create_io_cq(&mut self, cq_pa: u64) -> bool {
        let cdw10: u32 = 1 | (((QUEUE_DEPTH - 1) as u32) << 16);
        let cdw11: u32 = 1 | (1 << 1); // PC=1, IEN=1
        let sqe = Sqe {
            cdw0: ADMIN_CREATE_IO_CQ as u32,
            prp1: cq_pa,
            cdw10,
            cdw11,
            ..Default::default()
        };
        self.admin_cmd(sqe) == 0
    }

    unsafe fn create_io_sq(&mut self, sq_pa: u64) -> bool {
        let cdw10: u32 = 1 | (((QUEUE_DEPTH - 1) as u32) << 16);
        let cdw11: u32 = 1 | (1 << 16); // CQID=1
        let sqe = Sqe {
            cdw0: ADMIN_CREATE_IO_SQ as u32,
            prp1: sq_pa,
            cdw10,
            cdw11,
            ..Default::default()
        };
        self.admin_cmd(sqe) == 0
    }

    unsafe fn setup_io_queues(&mut self) -> bool {
        let cq_pa = Self::alloc_page();
        let sq_pa = Self::alloc_page();

        if !self.create_io_cq(cq_pa) {
            return false;
        }
        if !self.create_io_sq(sq_pa) {
            return false;
        }

        self.io.sq_base = sq_pa;
        self.io.cq_base = cq_pa;
        self.io.sq_tail = 0;
        self.io.cq_head = 0;
        self.io.cq_phase = true;
        self.io.sq_db = self.db_ptr(2);
        self.io.cq_db = self.db_ptr(3);
        true
    }
}

// ── Global controller instance ────────────────────────────────────────────

static CTRL: Mutex<NvmeCtrl> = Mutex::new(NvmeCtrl::uninit());

// ── Public API ────────────────────────────────────────────────────────────

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

    let irq_mode = if pci_enable_msix(&dev, 0, NVME_IRQ_VECTOR, 0) {
        "MSI-X"
    } else if pci_enable_msi_ex(&dev, 0, NVME_IRQ_VECTOR) {
        "MSI"
    } else {
        "polled"
    };

    let mut ctrl = CTRL.lock();
    ctrl.bar0 = bar0;

    let cap = unsafe { ctrl.read64(NVME_REG_CAP) };
    let dstrd = ((cap >> 32) & 0xF) as u64;
    ctrl.db_stride = 4u64 << dstrd;

    let vs = unsafe { ctrl.read32(NVME_REG_VS) };
    crate::arch::x86_64::serial::serial_println!(
        "nvme: BAR0={:#x} vs={}.{} irq={}",
        bar0,
        (vs >> 16),
        (vs >> 8) & 0xFF,
        irq_mode
    );

    if !unsafe { ctrl.reset() } {
        crate::arch::x86_64::serial::serial_println!("nvme: reset timeout");
        return;
    }

    unsafe {
        ctrl.setup_admin_queues();
    }

    if !unsafe { ctrl.enable() } {
        crate::arch::x86_64::serial::serial_println!("nvme: enable timeout / CFS");
        return;
    }

    let model = unsafe { ctrl.identify_controller() };
    crate::arch::x86_64::serial::serial_println!("nvme: model: {}", model);

    unsafe {
        ctrl.identify_namespace();
    }
    crate::arch::x86_64::serial::serial_println!(
        "nvme: ns1 size={} LBAs  lba_shift={}",
        ctrl.ns_size,
        ctrl.lba_shift
    );

    if !unsafe { ctrl.setup_io_queues() } {
        crate::arch::x86_64::serial::serial_println!("nvme: IO queue creation failed");
        return;
    }

    ctrl.ready = true;
    crate::arch::x86_64::serial::serial_println!("nvme: ready");
}

pub fn nvme_capacity() -> u64 {
    CTRL.lock().ns_size
}

pub fn nvme_lba_size() -> u32 {
    1u32 << CTRL.lock().lba_shift
}

/// Read `count` LBAs starting at `lba` into the buffer at physical address
/// `buf_pa`.
///
/// # Safety
/// `buf_pa` must be a valid physical address for a buffer of at least
/// `count * lba_size` bytes.  For identity-mapped kernel buffers, pass
/// `buf_ptr as u64` (virtual == physical).  For heap buffers use
/// `virt_to_phys(buf_ptr)`.
pub fn nvme_read(lba: u64, count: u16, buf_pa: u64) -> bool {
    let mut ctrl = CTRL.lock();
    if !ctrl.ready {
        return false;
    }

    let sqe = Sqe {
        cdw0: NVM_READ as u32,
        nsid: 1,
        prp1: buf_pa, // physical address — required by NVMe spec
        prp2: 0,
        cdw10: (lba & 0xFFFF_FFFF) as u32,
        cdw11: (lba >> 32) as u32,
        cdw12: (count as u32).saturating_sub(1),
        ..Default::default()
    };
    let cid = unsafe { ctrl.io.submit(sqe) };
    let status = unsafe { ctrl.io.poll(cid, 4_000_000) };
    status == 0
}

/// Write `count` LBAs from the buffer at physical address `buf_pa` to `lba`.
///
/// # Safety
/// `buf_pa` must be a valid physical address.  See `nvme_read` for details.
pub fn nvme_write(lba: u64, count: u16, buf_pa: u64) -> bool {
    let mut ctrl = CTRL.lock();
    if !ctrl.ready {
        return false;
    }

    let sqe = Sqe {
        cdw0: NVM_WRITE as u32,
        nsid: 1,
        prp1: buf_pa, // physical address — required by NVMe spec
        prp2: 0,
        cdw10: (lba & 0xFFFF_FFFF) as u32,
        cdw11: (lba >> 32) as u32,
        cdw12: (count as u32).saturating_sub(1),
        ..Default::default()
    };
    let cid = unsafe { ctrl.io.submit(sqe) };
    let status = unsafe { ctrl.io.poll(cid, 4_000_000) };
    status == 0
}

/// Convenience wrapper: read one 512-byte sector into a stack buffer.
/// The buffer must be identity-mapped (stack = kernel = PA == VA).
pub fn nvme_read_sector(lba: u64, buf: &mut [u8; 512]) -> bool {
    nvme_read(
        lba,
        1,
        crate::mm::vmm::virt_to_phys(buf.as_mut_ptr() as usize) as u64,
    )
}

/// Convenience wrapper: write one 512-byte sector from a stack buffer.
pub fn nvme_write_sector(lba: u64, buf: &[u8; 512]) -> bool {
    nvme_write(
        lba,
        1,
        crate::mm::vmm::virt_to_phys(buf.as_ptr() as usize) as u64,
    )
}

pub fn nvme_irq() {
    let mut ctrl = CTRL.lock();
    if !ctrl.ready {
        return;
    }
    unsafe {
        ctrl.write32(NVME_REG_INTMC, 1);
        ctrl.io.drain();
    }
}
