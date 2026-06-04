//! AHCI SATA controller driver.
//!
//! Implements:
//!   - HBA port enumeration (PI register)
//!   - COMRESET / BIST bring-up per port
//!   - 32-slot command list + FIS receive buffer per port
//!   - H2D Register FIS construction for ATA READ/WRITE DMA EXT (48-bit LBA)
//!   - Polled command completion
//!
//! Limitations:
//!   - Polling only — no MSI/MSI-X
//!   - One PRDT entry per command (≤128 KiB contiguous DMA)
//!   - Assumes identity-mapped physical memory

extern crate alloc;
use alloc::vec::Vec;
use core::ptr::{read_volatile, write_volatile};
use core::sync::atomic::{fence, Ordering};
use spin::Mutex;

// ── HBA memory-mapped register offsets (from BAR5 base) ──────────────────────
const HBA_CAP:  usize = 0x00; // Host Capabilities
const HBA_GHC:  usize = 0x04; // Global Host Control
const HBA_IS:   usize = 0x08; // Interrupt Status
const HBA_PI:   usize = 0x0C; // Ports Implemented
const HBA_VS:   usize = 0x10; // Version

const GHC_AE:   u32 = 1 << 31; // AHCI Enable
const GHC_HR:   u32 = 1 << 0;  // HBA Reset
const GHC_IE:   u32 = 1 << 1;  // Interrupt Enable (keep clear — polling)

// ── Per-port register offsets (relative to port base = BAR5 + 0x100 + port*0x80) ─
const P_CLB:  usize = 0x00; // Command List Base (low 32)
const P_CLBU: usize = 0x04; // Command List Base (high 32)
const P_FB:   usize = 0x08; // FIS Base (low 32)
const P_FBU:  usize = 0x0C; // FIS Base (high 32)
const P_IS:   usize = 0x10; // Interrupt Status
const P_IE:   usize = 0x14; // Interrupt Enable
const P_CMD:  usize = 0x18; // Command and Status
const P_TFD:  usize = 0x20; // Task File Data
const P_SIG:  usize = 0x24; // Signature
const P_SSTS: usize = 0x28; // SATA Status (SCR0)
const P_SCTL: usize = 0x2C; // SATA Control (SCR2)
const P_SERR: usize = 0x30; // SATA Error (SCR1)
const P_SACT: usize = 0x34; // SATA Active
const P_CI:   usize = 0x38; // Command Issue

const PCMD_ST:  u32 = 1 << 0;  // Start
const PCMD_FRE: u32 = 1 << 4;  // FIS Receive Enable
const PCMD_FR:  u32 = 1 << 14; // FIS Receive Running
const PCMD_CR:  u32 = 1 << 15; // Command List Running

const SSTS_DET_PRESENT: u32 = 0x3; // device present + comm established
const SSTS_IPM_ACTIVE:  u32 = 0x1; // interface active

const SIG_SATA: u32 = 0x0000_0101; // SATA drive

// ATA commands
const ATA_READ_DMA_EXT:  u8 = 0x25;
const ATA_WRITE_DMA_EXT: u8 = 0x35;

// ── Command Header (32 bytes, one per slot in the command list) ───────────────
#[repr(C, packed)]
#[derive(Clone, Copy, Default)]
struct CmdHeader {
    dw0: u32,  // CFL[4:0], A, W, P, R, B, C, PMP[3:0], PRDTL[15:0]
    prdbc: u32,
    ctba:  u32, // command table base address (low)
    ctbau: u32, // command table base address (high)
    _res:  [u32; 4],
}

// ── Physical Region Descriptor Table entry (16 bytes) ────────────────────────
#[repr(C, packed)]
#[derive(Clone, Copy, Default)]
struct PrdtEntry {
    dba:  u32, // data base address (low)
    dbau: u32, // data base address (high)
    _res: u32,
    dbc:  u32, // byte count (bit 0 must be 0); bit 31 = interrupt on completion
}

// ── Command Table ─────────────────────────────────────────────────────────────
// CFIS (64B) + ACMD (16B) + reserved (48B) + one PRDT entry (16B) = 144 bytes
// We round up to a page (4096) per port for simplicity.
#[repr(C, packed)]
#[derive(Clone, Copy)]
struct CmdTable {
    cfis:  [u8; 64],
    acmd:  [u8; 16],
    _res:  [u8; 48],
    prdt:  [PrdtEntry; 1],
}

impl Default for CmdTable {
    fn default() -> Self {
        // SAFETY: all-zero is valid for this packed POD type.
        unsafe { core::mem::zeroed() }
    }
}

// ── Per-port state ────────────────────────────────────────────────────────────
struct AhciPort {
    base:     usize, // port MMIO base (virtual, identity-mapped)
    clb_phys: u64,   // command list physical base
    fb_phys:  u64,   // FIS receive buffer physical base
    ct_phys:  u64,   // command table physical base (slot 0 only)
    dma_phys: u64,   // scratch DMA buffer physical base
}

static PORTS: Mutex<Vec<AhciPort>> = Mutex::new(Vec::new());

// ── Public API ────────────────────────────────────────────────────────────────

/// Initialise AHCI using the HBA MMIO at `bar5_virt` (virtual = physical).
/// Enumerates all implemented and attached SATA ports.
pub fn ahci_init(bar5_virt: usize) {
    unsafe { _init(bar5_virt) }
}

/// Number of ready SATA ports found after `ahci_init`.
pub fn ahci_port_count() -> usize {
    PORTS.lock().len()
}

/// Legacy shim used by boot-detection code.
pub fn ahci_present() -> bool {
    ahci_port_count() > 0
}

/// Read `count` 512-byte sectors from `port` starting at `lba` into `buf`.
/// Returns `true` on success.
pub fn ahci_read_sector(port: usize, lba: u64, buf: &mut [u8]) -> bool {
    issue_rw(port, lba, buf.as_mut_ptr() as u64, buf.len(), false)
}

/// Write `buf` to `port` starting at `lba`.
/// Returns `true` on success.
pub fn ahci_write_sector(port: usize, lba: u64, buf: &[u8]) -> bool {
    issue_rw(port, lba, buf.as_ptr() as u64, buf.len(), true)
}

// ── BlockDev impl ─────────────────────────────────────────────────────────────

pub struct AhciBlockDev {
    pub port: usize,
}

impl crate::block::BlockDev for AhciBlockDev {
    fn read(&self, lba: u64, buf: &mut [u8]) {
        ahci_read_sector(self.port, lba, buf);
    }
    fn write(&self, lba: u64, buf: &[u8]) {
        ahci_write_sector(self.port, lba, buf);
    }
}

// ── Internals ─────────────────────────────────────────────────────────────────

unsafe fn _init(bar5: usize) {
    // Enable AHCI mode.
    let ghc = hba_r32(bar5, HBA_GHC);
    hba_w32(bar5, HBA_GHC, ghc | GHC_AE);

    // Clear global interrupt status.
    let is = hba_r32(bar5, HBA_IS);
    hba_w32(bar5, HBA_IS, is);

    let pi = hba_r32(bar5, HBA_PI);

    for port_idx in 0..32usize {
        if pi & (1 << port_idx) == 0 {
            continue;
        }
        let pbase = bar5 + 0x100 + port_idx * 0x80;

        // Check device present.
        let ssts = port_r32(pbase, P_SSTS);
        let det = ssts & 0xF;
        let ipm = (ssts >> 8) & 0xF;
        if det != SSTS_DET_PRESENT || ipm != SSTS_IPM_ACTIVE {
            continue;
        }
        // Only handle SATA drives (not SATAPI).
        let sig = port_r32(pbase, P_SIG);
        if sig != SIG_SATA {
            continue;
        }

        // Allocate per-port DMA regions.
        let clb = alloc_dma(32 * 32, 1024).expect("ahci clb");
        let fb  = alloc_dma(256, 256).expect("ahci fb");
        let ct  = alloc_dma(core::mem::size_of::<CmdTable>(), 128)
                    .expect("ahci ct");
        let dma = alloc_dma(512 * 256, 4096).expect("ahci dma"); // up to 128 KiB

        // Stop engine before reconfiguring.
        stop_engine(pbase);

        // Program CLB and FB.
        port_w32(pbase, P_CLB,  clb as u32);
        port_w32(pbase, P_CLBU, (clb >> 32) as u32);
        port_w32(pbase, P_FB,   fb as u32);
        port_w32(pbase, P_FBU,  (fb >> 32) as u32);

        // Point slot-0 command header at our command table.
        let hdr = clb as *mut CmdHeader;
        (*hdr).ctba  = ct as u32;
        (*hdr).ctbau = (ct >> 32) as u32;

        // Clear errors and start engine.
        port_w32(pbase, P_SERR, !0u32);
        port_w32(pbase, P_IS,   !0u32);
        start_engine(pbase);

        let mut ports = PORTS.lock();
        ports.push(AhciPort {
            base:     pbase,
            clb_phys: clb,
            fb_phys:  fb,
            ct_phys:  ct,
            dma_phys: dma,
        });
    }
}

fn issue_rw(port_idx: usize, lba: u64, buf_phys: u64, byte_len: usize, write: bool) -> bool {
    if byte_len == 0 || byte_len % 512 != 0 {
        return false;
    }
    let sector_count = (byte_len / 512) as u16;

    let mut ports = PORTS.lock();
    let p = match ports.get_mut(port_idx) {
        Some(p) => p,
        None => return false,
    };

    unsafe {
        // Build command table in place.
        let ct = p.ct_phys as *mut CmdTable;
        core::ptr::write_bytes(ct as *mut u8, 0, core::mem::size_of::<CmdTable>());

        // H2D Register FIS (type 0x27).
        let cfis = &mut (*ct).cfis;
        cfis[0] = 0x27; // FIS type: H2D Register
        cfis[1] = 0x80; // C-bit = 1 (command)
        cfis[2] = if write { ATA_WRITE_DMA_EXT } else { ATA_READ_DMA_EXT };
        cfis[7] = 0x40; // Device: LBA mode
        // LBA (48-bit)
        cfis[4]  =  lba        as u8;
        cfis[5]  = (lba >>  8) as u8;
        cfis[6]  = (lba >> 16) as u8;
        cfis[8]  = (lba >> 24) as u8;
        cfis[9]  = (lba >> 32) as u8;
        cfis[10] = (lba >> 40) as u8;
        // Sector count (split across two bytes per ATA-8 spec).
        cfis[12] =  sector_count       as u8;
        cfis[13] = (sector_count >> 8) as u8;

        // PRDT entry.
        let prdt = &mut (*ct).prdt[0];
        prdt.dba  = buf_phys as u32;
        prdt.dbau = (buf_phys >> 32) as u32;
        prdt.dbc  = (byte_len as u32) - 1; // byte count – 1

        // Command header slot 0.
        let hdr = p.clb_phys as *mut CmdHeader;
        let cfl: u32 = (core::mem::size_of::<[u8; 20]>() / 4) as u32; // 5 DWORDs
        let w_bit: u32 = if write { 1 << 6 } else { 0 };
        (*hdr).dw0  = cfl | w_bit | (1 << 16); // PRDTL = 1
        (*hdr).prdbc = 0;

        fence(Ordering::Release);

        // Clear port error / interrupt status.
        port_w32(p.base, P_SERR, !0u32);
        port_w32(p.base, P_IS,   !0u32);

        // Issue command in slot 0.
        port_w32(p.base, P_CI, 1);

        // Poll for completion.
        let timeout = 10_000_000usize;
        for _ in 0..timeout {
            fence(Ordering::Acquire);
            let ci  = port_r32(p.base, P_CI);
            let tfd = port_r32(p.base, P_TFD);
            let is  = port_r32(p.base, P_IS);

            // Check for fatal error bits in IS (TFES = bit 30).
            if is & (1 << 30) != 0 {
                return false;
            }
            // Slot cleared and no BSY/DRQ in TFD.
            if ci & 1 == 0 && tfd & 0x88 == 0 {
                return true;
            }
            core::hint::spin_loop();
        }
    }
    false // timeout
}

unsafe fn stop_engine(pbase: usize) {
    let mut cmd = port_r32(pbase, P_CMD);
    cmd &= !(PCMD_ST | PCMD_FRE);
    port_w32(pbase, P_CMD, cmd);
    for _ in 0..500_000usize {
        let c = port_r32(pbase, P_CMD);
        if c & (PCMD_FR | PCMD_CR) == 0 {
            break;
        }
        core::hint::spin_loop();
    }
}

unsafe fn start_engine(pbase: usize) {
    // Wait for BSY and DRQ cleared.
    for _ in 0..500_000usize {
        if port_r32(pbase, P_TFD) & 0x88 == 0 {
            break;
        }
        core::hint::spin_loop();
    }
    let mut cmd = port_r32(pbase, P_CMD);
    cmd |= PCMD_FRE;
    port_w32(pbase, P_CMD, cmd);
    cmd |= PCMD_ST;
    port_w32(pbase, P_CMD, cmd);
}

#[inline]
unsafe fn hba_r32(base: usize, off: usize) -> u32 {
    read_volatile((base + off) as *const u32)
}
#[inline]
unsafe fn hba_w32(base: usize, off: usize, val: u32) {
    write_volatile((base + off) as *mut u32, val);
}
#[inline]
unsafe fn port_r32(pbase: usize, off: usize) -> u32 {
    read_volatile((pbase + off) as *const u32)
}
#[inline]
unsafe fn port_w32(pbase: usize, off: usize, val: u32) {
    write_volatile((pbase + off) as *mut u32, val);
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
