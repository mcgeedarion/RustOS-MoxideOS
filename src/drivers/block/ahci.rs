//! AHCI SATA host controller driver.
//!
//! ## AHCI overview
//!   An AHCI controller (class 0x01, subclass 0x06) exposes:
//!     - Generic Host Control registers at BAR5 (HBA MMIO, "ABAR")
//!     - Up to 32 port registers at ABAR + 0x100 + port * 0x80
//!     - Each port has a 32-slot Command List and a single FIS receive buffer
//!
//! ## Driver scope
//!   • PCI BAR5 mapping and capability discovery
//!   • BIOS ↔ OS handoff (BOHC)
//!   • Port reset and COMRESET sequence
//!   • 32-entry command list / command table setup
//!   • ATA-8 commands: IDENTIFY, READ DMA EXT, WRITE DMA EXT
//!   • Synchronous command submission (spin on CI/TFD)
//!   • DiskInfo struct and public API (init, read_sectors, write_sectors, info)

extern crate alloc;
use alloc::vec::Vec;
use core::ptr::{read_volatile, write_volatile};

// ─────────────────────────────────────────────────────────────────────────────
// MMIO layout constants (all offsets in bytes)
// ─────────────────────────────────────────────────────────────────────────────

const HBA_CAP:      usize = 0x00; // Host capabilities
const HBA_GHC:      usize = 0x04; // Global host control
const HBA_IS:       usize = 0x08; // Interrupt status
const HBA_PI:       usize = 0x0C; // Ports implemented
const HBA_BOHC:     usize = 0x28; // BIOS/OS handoff control

const GHC_AE:       u32   = 1 << 31; // AHCI enable
const GHC_HR:       u32   = 1 <<  0; // HBA reset
const BOHC_OOS:     u32   = 1 <<  1; // OS ownership
const BOHC_BOS:     u32   = 1 <<  0; // BIOS ownership

// Per-port offsets (base = ABAR + 0x100 + port * 0x80)
const PX_CLB:   usize = 0x00; // Command list base (lo)
const PX_CLBU:  usize = 0x04; // Command list base (hi)
const PX_FB:    usize = 0x08; // FIS base (lo)
const PX_FBU:   usize = 0x0C; // FIS base (hi)
const PX_IS:    usize = 0x10; // Interrupt status
const PX_IE:    usize = 0x14; // Interrupt enable
const PX_CMD:   usize = 0x18; // Command & status
const PX_TFD:   usize = 0x20; // Task file data
const PX_SIG:   usize = 0x24; // Signature
const PX_SSTS:  usize = 0x28; // SATA status
const PX_SERR:  usize = 0x30; // SATA error
const PX_CI:    usize = 0x38; // Command issue

const CMD_ST:   u32  = 1 <<  0; // Start (DMA engine)
const CMD_FRE:  u32  = 1 <<  4; // FIS receive enable
const CMD_FR:   u32  = 1 << 14; // FIS receive running
const CMD_CR:   u32  = 1 << 15; // Command list running
const TFD_BSY:  u32  = 1 <<  7;
const TFD_DRQ:  u32  = 1 <<  3;

// ATA command codes
const ATA_CMD_IDENTIFY:        u8 = 0xEC;
const ATA_CMD_READ_DMA_EXT:    u8 = 0x25;
const ATA_CMD_WRITE_DMA_EXT:   u8 = 0x35;

// Signature for SATA disk
const SATA_SIG_ATA:  u32 = 0x00000101;

// ─────────────────────────────────────────────────────────────────────────────
// Command List Entry (Command Header) — 32 bytes, 32 slots per port
// ─────────────────────────────────────────────────────────────────────────────
#[repr(C, packed)]
struct CmdHeader {
    dw0:     u32, // CFL, A, W, P, R, B, C, PMP, PRDTL
    prdbc:   u32, // PRD byte count (written by HBA)
    ctba:    u32, // Command table base address (lo)
    ctbau:   u32, // Command table base address (hi)
    _rsv:    [u32; 4],
}

const CMDH_CFL_FIS5: u32 = 5;       // FIS length = 5 dwords
const CMDH_WRITE:    u32 = 1 << 6;  // Write direction
const CMDH_PREFETCH: u32 = 1 << 7;  // Prefetch
const CMDH_CLR_BUSY: u32 = 1 << 10; // Clear busy on R_OK

// ─────────────────────────────────────────────────────────────────────────────
// Command Table — FIS + PRDT (one PRD per transfer here)
// ─────────────────────────────────────────────────────────────────────────────
#[repr(C, packed)]
struct CmdTable {
    cfis:  [u8; 64],   // Command FIS
    acmd:  [u8; 16],   // ATAPI cmd (unused)
    _rsv:  [u8; 48],
    prd:   PrdEntry,   // Single PRD (one 512-byte sector)
}

#[repr(C, packed)]
struct PrdEntry {
    dba:   u32,  // Data base address (lo)
    dbau:  u32,  // Data base address (hi)
    _rsv:  u32,
    dw3:   u32,  // Byte count (bits 21:0), I (bit 31)
}

// ─────────────────────────────────────────────────────────────────────────────
// Register Host-to-Device (H2D) FIS structure
// ─────────────────────────────────────────────────────────────────────────────
#[repr(C, packed)]
struct FisRegH2D {
    fis_type:  u8,  // 0x27
    flags:     u8,  // bit 7 = Command
    command:   u8,
    features:  u8,
    lba0:      u8,
    lba1:      u8,
    lba2:      u8,
    device:    u8,
    lba3:      u8,
    lba4:      u8,
    lba5:      u8,
    featuresex:u8,
    count_lo:  u8,
    count_hi:  u8,
    icc:       u8,
    control:   u8,
    _aux:      [u8; 4],
}

const FIS_TYPE_REG_H2D: u8 = 0x27;

// ─────────────────────────────────────────────────────────────────────────────
// Port context — per-port driver state
// ─────────────────────────────────────────────────────────────────────────────

/// Physical base of a port's MMIO registers.
struct Port {
    base: u64, // ABAR + 0x100 + port * 0x80
    /// Physical address of the command list (2 KiB, 32 × 32 B aligned to 1 KiB)
    cl_phys:   u64,
    /// Physical address of the FIS receive buffer (256 B, aligned to 256)
    fis_phys:  u64,
    /// Physical address of the command table array (one per slot)
    ct_phys:   [u64; 32],
    /// Scratch DMA buffer physical address (one 4 KiB page per port)
    buf_phys:  u64,
}

impl Port {
    #[inline]
    unsafe fn read32(&self, off: usize) -> u32 {
        read_volatile((self.base as usize + off) as *const u32)
    }
    #[inline]
    unsafe fn write32(&self, off: usize, v: u32) {
        write_volatile((self.base as usize + off) as *mut u32, v)
    }
    #[inline]
    unsafe fn stop_cmd(&self) {
        let mut cmd = self.read32(PX_CMD);
        cmd &= !(CMD_ST | CMD_FRE);
        self.write32(PX_CMD, cmd);
        for _ in 0..500_000 {
            let cmd = self.read32(PX_CMD);
            if cmd & (CMD_FR | CMD_CR) == 0 { break; }
            core::hint::spin_loop();
        }
    }
    #[inline]
    unsafe fn start_cmd(&self) {
        while self.read32(PX_CMD) & CMD_CR != 0 { core::hint::spin_loop(); }
        let cmd = self.read32(PX_CMD) | CMD_FRE | CMD_ST;
        self.write32(PX_CMD, cmd);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Global state
// ─────────────────────────────────────────────────────────────────────────────

use spin::Mutex;

static PORTS: Mutex<Vec<Port>> = Mutex::new(Vec::new());
static ABAR:  Mutex<u64>       = Mutex::new(0);

// ─────────────────────────────────────────────────────────────────────────────
// Disk information returned by identify
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Clone, Default, Debug)]
pub struct DiskInfo {
    pub port:          usize,
    pub sector_count:  u64,
    pub sector_size:   u32,
    pub model:         [u8; 40],
}

static DISKS: Mutex<Vec<DiskInfo>> = Mutex::new(Vec::new());

// ─────────────────────────────────────────────────────────────────────────────
// Public API
// ─────────────────────────────────────────────────────────────────────────────

/// Initialise the AHCI controller at BAR5 physical address `abar_phys`.
///
/// Performs BIOS handoff, HBA reset, port init and IDENTIFY for each
/// implemented SATA disk port.  Safe to call once at boot.
pub fn init(abar_phys: u64) {
    unsafe { _init(abar_phys); }
}

/// Read `count` 512-byte sectors starting at LBA `lba` into `buf`.
/// `buf` must be at least `count * 512` bytes.
pub fn read_sectors(port: usize, lba: u64, count: u16, buf: &mut [u8]) -> Result<(), &'static str> {
    if buf.len() < count as usize * 512 { return Err("buffer too small"); }
    unsafe { dma_rw(port, lba, count, buf.as_mut_ptr() as u64, false) }
}

/// Write `count` 512-byte sectors from `buf` to LBA `lba`.
pub fn write_sectors(port: usize, lba: u64, count: u16, buf: &[u8]) -> Result<(), &'static str> {
    if buf.len() < count as usize * 512 { return Err("buffer too small"); }
    unsafe { dma_rw(port, lba, count, buf.as_ptr() as u64, true) }
}

/// Return metadata for disk on `port`, or None if absent.
pub fn disk_info(port: usize) -> Option<DiskInfo> {
    DISKS.lock().iter().find(|d| d.port == port).cloned()
}

/// Number of detected SATA disks.
pub fn disk_count() -> usize { DISKS.lock().len() }

// ─────────────────────────────────────────────────────────────────────────────
// Internal implementation
// ─────────────────────────────────────────────────────────────────────────────

unsafe fn hba_read(abar: u64, off: usize) -> u32 {
    read_volatile((abar as usize + off) as *const u32)
}
unsafe fn hba_write(abar: u64, off: usize, v: u32) {
    write_volatile((abar as usize + off) as *mut u32, v);
}

unsafe fn _init(abar_phys: u64) {
    *ABAR.lock() = abar_phys;

    // BIOS/OS handoff (AHCI 1.3 §10.6.3).
    let bohc = hba_read(abar_phys, HBA_BOHC);
    if bohc & BOHC_BOS != 0 {
        hba_write(abar_phys, HBA_BOHC, bohc | BOHC_OOS);
        let mut spin = 0u32;
        while hba_read(abar_phys, HBA_BOHC) & BOHC_BOS != 0 && spin < 2_000_000 {
            core::hint::spin_loop();
            spin += 1;
        }
    }

    // Enable AHCI mode.
    let ghc = hba_read(abar_phys, HBA_GHC);
    hba_write(abar_phys, HBA_GHC, ghc | GHC_AE);

    // Clear interrupt status.
    let is = hba_read(abar_phys, HBA_IS);
    hba_write(abar_phys, HBA_IS, is);

    // Enumerate implemented ports.
    let pi = hba_read(abar_phys, HBA_PI);
    let _cap = hba_read(abar_phys, HBA_CAP);

    let mut ports_guard = PORTS.lock();
    for i in 0..32u32 {
        if pi & (1 << i) == 0 { continue; }
        let port_base = abar_phys + 0x100 + i as u64 * 0x80;

        // Check device type.
        let sig = read_volatile((port_base as usize + PX_SIG) as *const u32);
        if sig != SATA_SIG_ATA { continue; }

        // Allocate command list + FIS receive buffers from PMM.
        let cl_phys  = alloc_dma(1024, 1024)?;  // 1 KiB, 1 KiB aligned
        let fis_phys = alloc_dma(256,  256)?;   // 256 B, 256 B aligned
        let buf_phys = alloc_dma(4096, 4096)?;  // 4 KiB scratch

        // Command tables: 32 slots × 256 B each (128 B + 1 PRD).
        let mut ct_phys = [0u64; 32];
        for s in 0..32 {
            ct_phys[s] = alloc_dma(256, 128)?;
        }

        let mut port = Port {
            base: port_base,
            cl_phys, fis_phys, ct_phys, buf_phys,
        };

        // Programme CLB/FB registers.
        port.stop_cmd();
        port.write32(PX_CLB,  (cl_phys  & 0xFFFF_FFFF) as u32);
        port.write32(PX_CLBU, (cl_phys  >> 32) as u32);
        port.write32(PX_FB,   (fis_phys & 0xFFFF_FFFF) as u32);
        port.write32(PX_FBU,  (fis_phys >> 32) as u32);

        // Clear error & interrupt status.
        let serr = port.read32(PX_SERR);
        port.write32(PX_SERR, serr);
        let is = port.read32(PX_IS);
        port.write32(PX_IS, is);
        port.write32(PX_IE, 0);

        // Point each command list slot at its command table.
        let cl = cl_phys as *mut CmdHeader;
        for s in 0..32usize {
            let hdr = &mut *cl.add(s);
            hdr.ctba  = (ct_phys[s] & 0xFFFF_FFFF) as u32;
            hdr.ctbau = (ct_phys[s] >> 32) as u32;
        }

        port.start_cmd();

        let port_idx = ports_guard.len();
        ports_guard.push(port);

        // IDENTIFY to populate DiskInfo.
        drop(ports_guard); // release lock during I/O
        let disk = identify_disk(port_idx, buf_phys);
        if let Some(mut d) = disk {
            d.port = port_idx;
            DISKS.lock().push(d);
        }
        ports_guard = PORTS.lock();
    }
}

/// Allocate physically-contiguous DMA memory from the PMM.
fn alloc_dma(size: usize, align: usize) -> Option<u64> {
    let pages = (size + 0xFFF) / 0x1000;
    let phys = crate::mm::pmm::alloc_pages_aligned(pages, align)?
        .as_ptr() as u64;
    // Zero-initialise.
    unsafe { core::ptr::write_bytes(phys as *mut u8, 0, pages * 0x1000); }
    Some(phys)
}

/// Issue ATA IDENTIFY and return disk metadata.
unsafe fn identify_disk(port_idx: usize, buf_phys: u64) -> Option<DiskInfo> {
    let ports = PORTS.lock();
    let port  = ports.get(port_idx)?;

    // Build command table at slot 0.
    let hdr = &mut *(port.cl_phys as *mut CmdHeader);
    hdr.dw0  = CMDH_CFL_FIS5 | (1 << 16); // PRDTL = 1
    hdr.prdbc = 0;

    let ct = &mut *(port.ct_phys[0] as *mut CmdTable);
    core::ptr::write_bytes(ct as *mut CmdTable as *mut u8, 0, core::mem::size_of::<CmdTable>());

    // H2D FIS for IDENTIFY.
    let fis = &mut *(ct.cfis.as_mut_ptr() as *mut FisRegH2D);
    fis.fis_type = FIS_TYPE_REG_H2D;
    fis.flags    = 0x80; // Command
    fis.command  = ATA_CMD_IDENTIFY;
    fis.device   = 0;

    // One PRD: 512 bytes.
    ct.prd = PrdEntry { dba: (buf_phys & 0xFFFF_FFFF) as u32, dbau: (buf_phys >> 32) as u32, _rsv: 0, dw3: 511 };

    // Issue slot 0.
    port.write32(PX_CI, 1);
    let ok = spin_cmd(port, 0);
    drop(ports);
    if !ok { return None; }

    let id = core::slice::from_raw_parts(buf_phys as *const u16, 256);
    let sector_count = (id[100] as u64) | ((id[101] as u64) << 16)
                     | ((id[102] as u64) << 32) | ((id[103] as u64) << 48);
    let mut model = [0u8; 40];
    for i in 0..20usize {
        let w = id[27 + i];
        model[i * 2]     = (w >> 8) as u8;
        model[i * 2 + 1] = (w & 0xFF) as u8;
    }
    Some(DiskInfo { port: 0, sector_count, sector_size: 512, model })
}

/// DMA read or write — issues one command per call (up to 64 KiB per PRD).
unsafe fn dma_rw(port_idx: usize, lba: u64, count: u16, buf_phys: u64, write: bool)
    -> Result<(), &'static str>
{
    let ports = PORTS.lock();
    let port  = ports.get(port_idx).ok_or("port not found")?;

    let hdr = &mut *(port.cl_phys as *mut CmdHeader);
    hdr.dw0  = CMDH_CFL_FIS5 | (1 << 16)
             | if write { CMDH_WRITE } else { 0 };
    hdr.prdbc = 0;

    let ct = &mut *(port.ct_phys[0] as *mut CmdTable);
    core::ptr::write_bytes(ct as *mut _ as *mut u8, 0, core::mem::size_of::<CmdTable>());

    let fis = &mut *(ct.cfis.as_mut_ptr() as *mut FisRegH2D);
    fis.fis_type  = FIS_TYPE_REG_H2D;
    fis.flags     = 0x80;
    fis.command   = if write { ATA_CMD_WRITE_DMA_EXT } else { ATA_CMD_READ_DMA_EXT };
    fis.device    = 0x40; // LBA mode
    fis.lba0      = (lba & 0xFF) as u8;
    fis.lba1      = ((lba >>  8) & 0xFF) as u8;
    fis.lba2      = ((lba >> 16) & 0xFF) as u8;
    fis.lba3      = ((lba >> 24) & 0xFF) as u8;
    fis.lba4      = ((lba >> 32) & 0xFF) as u8;
    fis.lba5      = ((lba >> 40) & 0xFF) as u8;
    fis.count_lo  = (count & 0xFF) as u8;
    fis.count_hi  = (count >> 8)   as u8;

    ct.prd = PrdEntry {
        dba:  (buf_phys & 0xFFFF_FFFF) as u32,
        dbau: (buf_phys >> 32) as u32,
        _rsv: 0,
        dw3:  (count as u32 * 512 - 1) | (1 << 31), // interrupt on completion
    };

    port.write32(PX_CI, 1);
    if spin_cmd(port, 0) { Ok(()) } else { Err("AHCI command timeout") }
}

/// Spin-wait for command slot 0 to clear in CI register.
/// Returns true on success, false on timeout or error.
unsafe fn spin_cmd(port: &Port, slot: u32) -> bool {
    let mask = 1 << slot;
    for _ in 0..10_000_000 {
        if port.read32(PX_CI) & mask == 0 { return true; }
        if port.read32(PX_TFD) & (TFD_BSY | TFD_DRQ) == 0
            && port.read32(PX_IS) & (1 << 30) != 0 { return false; } // task file error
        core::hint::spin_loop();
    }
    false // timeout
}
