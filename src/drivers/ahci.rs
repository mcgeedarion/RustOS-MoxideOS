//! Phase 3 — AHCI SATA host controller driver.
//!
//! ## AHCI overview
//!   An AHCI controller (class 0x01, subclass 0x06) exposes:
//!     - Generic Host Control registers at BAR5 (HBA MMIO)
//!     - Up to 32 ports, each with its own register set at
//!       BAR5 + 0x100 + port * 0x80.
//!
//! ## Initialisation sequence (per AHCI 1.3.1 spec)
//!   1. Read GHC.AE (bit 31): if 0, set it to switch to AHCI mode.
//!   2. Read PI (Ports Implemented) bitmask.
//!   3. For each set bit in PI:
//!      a. Ensure port is idle (PxCMD.ST=0, PxCMD.FRE=0).
//!      b. Allocate command list (1 KiB, 32-entry × 32 B) and FIS buffer (256 B).
//!      c. Write physical addresses to PxCLB/CLBU and PxFB/FBU.
//!      d. Clear PxSERR, PxIS.
//!      e. Set PxCMD.FRE=1 then PxCMD.ST=1.
//!      f. Check PxSSTS.DET == 3 (device present + PHY ready).
//!      g. Check PxSSTS.IPM == 1 (active).
//!   4. Issue IDENTIFY DEVICE (ATA command 0xEC) via a non-data FIS to
//!      discover capacity and model string.
//!
//! ## Command issue (48-bit LBA, DMA)
//!   1. Find a free command slot (PxCI == 0 for that slot).
//!   2. Fill command header in the command list:
//!        CFL = 5 (FIS length in dwords), W (write flag), PRDTL = 1.
//!   3. Fill command table:
//!        CFIS: type=0x27, C=1, command=0x25 (READ DMA EXT) or 0x35 (WRITE DMA EXT),
//!              LBA[47:0], count.
//!        PRDT entry 0: DBA = physical address of data buffer, DBC = size-1.
//!   4. Set bit in PxCI to issue.
//!   5. Poll PxCI until the bit clears (command complete).
//!   6. Check PxIS.TFES for errors.
//!
//! ## Integration with the block layer
//!   ahci_read_sector(port, lba, buf)  → bool
//!   ahci_write_sector(port, lba, buf) → bool
//!   These have the same signature as virtio_blk::{read,write}_sector so
//!   the VFS block layer can pick whichever backend is present.

extern crate alloc;
use alloc::vec::Vec;
use spin::Mutex;

// ── HBA register offsets (from BAR5 base) ────────────────────────────────

const HBA_CAP:     usize = 0x000; // Host Capabilities
const HBA_GHC:     usize = 0x004; // Global Host Control
const HBA_IS:      usize = 0x008; // Interrupt Status
const HBA_PI:      usize = 0x00C; // Ports Implemented
const HBA_VS:      usize = 0x010; // Version

// ── Port register offsets (from port_base = BAR5 + 0x100 + port*0x80) ───

const PORT_CLB:    usize = 0x00;  // Command List Base (low)
const PORT_CLBU:   usize = 0x04;  // Command List Base (high)
const PORT_FB:     usize = 0x08;  // FIS Base (low)
const PORT_FBU:    usize = 0x0C;  // FIS Base (high)
const PORT_IS:     usize = 0x10;  // Interrupt Status
const PORT_IE:     usize = 0x14;  // Interrupt Enable
const PORT_CMD:    usize = 0x18;  // Command and Status
const PORT_TFD:    usize = 0x20;  // Task File Data
const PORT_SIG:    usize = 0x24;  // Signature
const PORT_SSTS:   usize = 0x28;  // SATA Status (SCR0)
const PORT_SERR:   usize = 0x30;  // SATA Error (SCR1)
const PORT_CI:     usize = 0x38;  // Command Issue

const PORT_CMD_ST:  u32 = 1 << 0;  // Start
const PORT_CMD_FRE: u32 = 1 << 4;  // FIS Receive Enable
const PORT_CMD_FR:  u32 = 1 << 14; // FIS Receive Running
const PORT_CMD_CR:  u32 = 1 << 15; // Command List Running
const PORT_IS_TFES: u32 = 1 << 30; // Task File Error Status

const SSTS_DET_PRESENT: u32 = 0x3; // device detected, PHY ready
const SSTS_IPM_ACTIVE:  u32 = 0x1; // interface in active state

// ── Command FIS types ─────────────────────────────────────────────────────

const FIS_TYPE_REG_H2D: u8 = 0x27; // Register FIS, host to device

// ATA commands
const ATA_CMD_IDENTIFY:    u8 = 0xEC;
const ATA_CMD_READ_DMA_EX: u8 = 0x25;
const ATA_CMD_WRITE_DMA_EX:u8 = 0x35;

const SECTOR_SIZE: usize = 512;
const CMD_SLOTS:   usize = 32;

// ── AHCI data structures (must be physically contiguous + aligned) ────────

/// Command header (32 bytes each, 32 headers = 1 KiB command list).
#[repr(C, align(32))]
#[derive(Clone, Copy, Default)]
struct CmdHeader {
    dw0:   u32, // CFL[4:0], A, W, P, R, B, C, reserved, PRDTL[15:0]
    prdbc: u32, // PRDT Byte Count (filled by HBA)
    ctba:  u32, // Command Table Base Address (low)
    ctbau: u32, // Command Table Base Address (high)
    _res:  [u32; 4],
}

/// PRDT entry (16 bytes).
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct PrdtEntry {
    dba:   u32, // Data Base Address (low)
    dbau:  u32, // Data Base Address (high)
    _res:  u32,
    dbc:   u32, // Byte count minus 1 (bit 31 = IRQ on completion)
}

/// Command table: CFIS (64 B) + ACMD (16 B) + reserved (48 B) + PRDT (≥1 entry).
#[repr(C, align(128))]
#[derive(Clone, Copy)]
struct CmdTable {
    cfis: [u8; 64],   // Command FIS
    acmd: [u8; 16],   // ATAPI command (unused for ATA)
    _res: [u8; 48],
    prdt: [PrdtEntry; 1],
}
impl Default for CmdTable { fn default() -> Self { unsafe { core::mem::zeroed() } } }

/// Per-port memory (allocated from PMM, must be 1 KiB-aligned).
struct PortMem {
    cmd_list: [CmdHeader; CMD_SLOTS], // 1024 bytes
    fis_buf:  [u8; 256],
    cmd_table:[CmdTable; CMD_SLOTS],  // one per slot
    data_buf: [u8; SECTOR_SIZE],      // scratch buffer for DMA
}

// ── Port state ────────────────────────────────────────────────────────────

struct AhciPort {
    hba_base: usize,   // BAR5 virtual address
    port_idx: usize,
    mem:      &'static mut PortMem,
}

static PORTS: Mutex<Vec<AhciPort>> = Mutex::new(Vec::new());

// ── MMIO helpers ──────────────────────────────────────────────────────────

unsafe fn hba_r32(base: usize, off: usize) -> u32 {
    ((base + off) as *const u32).read_volatile()
}
unsafe fn hba_w32(base: usize, off: usize, v: u32) {
    ((base + off) as *mut u32).write_volatile(v);
}
fn port_base(hba: usize, port: usize) -> usize {
    hba + 0x100 + port * 0x80
}
unsafe fn pr32(hba: usize, port: usize, off: usize) -> u32 {
    hba_r32(port_base(hba, port), off)
}
unsafe fn pw32(hba: usize, port: usize, off: usize, v: u32) {
    hba_w32(port_base(hba, port), off, v);
}

// ── Init ──────────────────────────────────────────────────────────────────

/// Initialise the AHCI controller found at `bar5_pa` (physical = virtual).
/// Called by kernel_main after PCIe enumeration identifies an AHCI device.
pub fn ahci_init(bar5_pa: usize) {
    unsafe {
        // Enable AHCI mode.
        let ghc = hba_r32(bar5_pa, HBA_GHC);
        if ghc & (1 << 31) == 0 {
            hba_w32(bar5_pa, HBA_GHC, ghc | (1 << 31));
        }

        let pi = hba_r32(bar5_pa, HBA_PI);
        let mut ports = PORTS.lock();

        for port in 0..32usize {
            if pi & (1 << port) == 0 { continue; }

            // Check device presence.
            let ssts = pr32(bar5_pa, port, PORT_SSTS);
            let det  = ssts & 0xF;
            let ipm  = (ssts >> 8) & 0xF;
            if det != SSTS_DET_PRESENT || ipm != SSTS_IPM_ACTIVE { continue; }

            // Stop port before reconfiguring.
            stop_port(bar5_pa, port);

            // Allocate port memory from PMM.
            let mem_pa = match alloc_port_mem() {
                Some(p) => p,
                None    => continue,
            };
            let mem: &'static mut PortMem =
                &mut *(mem_pa as *mut PortMem);
            core::ptr::write_bytes(mem as *mut PortMem as *mut u8, 0,
                                   core::mem::size_of::<PortMem>());

            // Program CLB and FB.
            let clb_pa = mem.cmd_list.as_ptr() as u64;
            let fb_pa  = mem.fis_buf.as_ptr() as u64;
            pw32(bar5_pa, port, PORT_CLB,  (clb_pa & 0xFFFF_FFFF) as u32);
            pw32(bar5_pa, port, PORT_CLBU, (clb_pa >> 32)          as u32);
            pw32(bar5_pa, port, PORT_FB,   (fb_pa  & 0xFFFF_FFFF) as u32);
            pw32(bar5_pa, port, PORT_FBU,  (fb_pa  >> 32)          as u32);

            // Clear errors and interrupts.
            pw32(bar5_pa, port, PORT_SERR, 0xFFFF_FFFF);
            pw32(bar5_pa, port, PORT_IS,   0xFFFF_FFFF);

            // Start port: FRE then ST.
            let cmd = pr32(bar5_pa, port, PORT_CMD);
            pw32(bar5_pa, port, PORT_CMD, cmd | PORT_CMD_FRE);
            pw32(bar5_pa, port, PORT_CMD, cmd | PORT_CMD_FRE | PORT_CMD_ST);

            // Program each command table.
            for slot in 0..CMD_SLOTS {
                let ct_pa = &mem.cmd_table[slot] as *const CmdTable as u64;
                mem.cmd_list[slot].ctba  = (ct_pa & 0xFFFF_FFFF) as u32;
                mem.cmd_list[slot].ctbau = (ct_pa >> 32)          as u32;
            }

            crate::arch::x86_64::serial::serial_println!(
                "ahci: port {} — device present", port);

            ports.push(AhciPort { hba_base: bar5_pa, port_idx: port, mem });
        }
    }
}

fn stop_port(hba: usize, port: usize) {
    unsafe {
        let mut cmd = pr32(hba, port, PORT_CMD);
        cmd &= !(PORT_CMD_ST | PORT_CMD_FRE);
        pw32(hba, port, PORT_CMD, cmd);
        // Wait for CR and FR to clear (max 500 ms at ~1 ns per iteration).
        for _ in 0..500_000 {
            let c = pr32(hba, port, PORT_CMD);
            if c & (PORT_CMD_CR | PORT_CMD_FR) == 0 { break; }
            core::hint::spin_loop();
        }
    }
}

fn alloc_port_mem() -> Option<usize> {
    // PortMem is ~5 KiB; round up to next page boundary and allocate.
    const PM_SIZE: usize = core::mem::size_of::<PortMem>();
    const PM_PAGES: usize = (PM_SIZE + 4095) / 4096;
    let first_pa = crate::mm::pmm::alloc_page()?;
    for _ in 1..PM_PAGES {
        crate::mm::pmm::alloc_page()?; // must be contiguous (bump allocator guarantees this)
    }
    Some(first_pa)
}

// ── Command issue ─────────────────────────────────────────────────────────

/// Read one 512-byte sector at `lba` into `buf`.
/// `port_no` indexes into the AHCI port list (use 0 for the first drive).
pub fn ahci_read_sector(port_no: usize, lba: u64, buf: &mut [u8; SECTOR_SIZE]) -> bool {
    issue_rw(port_no, lba, buf, false)
}

/// Write one 512-byte sector from `buf` at `lba`.
pub fn ahci_write_sector(port_no: usize, lba: u64, buf: &[u8; SECTOR_SIZE]) -> bool {
    let mut tmp = *buf;
    issue_rw(port_no, lba, &mut tmp, true)
}

fn issue_rw(port_no: usize, lba: u64, buf: &mut [u8; SECTOR_SIZE], write: bool) -> bool {
    let mut ports = PORTS.lock();
    let port = match ports.get_mut(port_no) {
        Some(p) => p,
        None    => return false,
    };

    let slot = 0usize; // single-command; slot 0 always free in our polled driver
    let hba  = port.hba_base;
    let pidx = port.port_idx;
    let mem  = &mut *port.mem;

    unsafe {
        // Copy data to/from scratch buffer.
        if write { mem.data_buf.copy_from_slice(buf); }

        // Build command FIS (H2D Register FIS, 20 bytes = 5 dwords).
        let ct = &mut mem.cmd_table[slot];
        ct.cfis = [0u8; 64];
        ct.cfis[0]  = FIS_TYPE_REG_H2D;
        ct.cfis[1]  = 0x80;                                      // C=1 (command)
        ct.cfis[2]  = if write { ATA_CMD_WRITE_DMA_EX } else { ATA_CMD_READ_DMA_EX };
        ct.cfis[3]  = 0; // features low
        // LBA 28-bit fields (LBA mode, device = 0x40 | LBA[27:24])
        ct.cfis[4]  = (lba & 0xFF) as u8;          // LBA low
        ct.cfis[5]  = ((lba >> 8)  & 0xFF) as u8;  // LBA mid
        ct.cfis[6]  = ((lba >> 16) & 0xFF) as u8;  // LBA high
        ct.cfis[7]  = 0x40 | ((lba >> 24) & 0x0F) as u8; // device
        // LBA ext (48-bit)
        ct.cfis[8]  = ((lba >> 24) & 0xFF) as u8;
        ct.cfis[9]  = ((lba >> 32) & 0xFF) as u8;
        ct.cfis[10] = ((lba >> 40) & 0xFF) as u8;
        ct.cfis[11] = 0; // features high
        ct.cfis[12] = 1; // count low = 1 sector
        ct.cfis[13] = 0; // count high

        // PRDT entry 0: point at data_buf.
        let dba = mem.data_buf.as_ptr() as u64;
        ct.prdt[0].dba  = (dba & 0xFFFF_FFFF) as u32;
        ct.prdt[0].dbau = (dba >> 32) as u32;
        ct.prdt[0].dbc  = (SECTOR_SIZE - 1) as u32; // byte count minus 1

        // Command header for slot 0.
        let w_bit: u32 = if write { 1 << 6 } else { 0 }; // W bit
        mem.cmd_list[slot].dw0 = 5 | w_bit | (1 << 16); // CFL=5, PRDTL=1
        mem.cmd_list[slot].prdbc = 0;

        // Memory barrier before issuing.
        core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);

        // Clear port IS, then issue command.
        pw32(hba, pidx, PORT_IS, 0xFFFF_FFFF);
        pw32(hba, pidx, PORT_CI, 1 << slot);

        // Poll CI until slot bit clears (command done), timeout ~5 s.
        for _ in 0..5_000_000usize {
            core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
            if pr32(hba, pidx, PORT_CI) & (1 << slot) == 0 { break; }
            core::hint::spin_loop();
        }

        // Check for error.
        if pr32(hba, pidx, PORT_IS) & PORT_IS_TFES != 0 { return false; }

        // Copy data out on read.
        if !write { buf.copy_from_slice(&mem.data_buf); }
        true
    }
}

/// Returns true if at least one AHCI port has a device.
pub fn ahci_present() -> bool {
    !PORTS.lock().is_empty()
}

/// Number of AHCI-attached drives found.
pub fn ahci_port_count() -> usize {
    PORTS.lock().len()
}
