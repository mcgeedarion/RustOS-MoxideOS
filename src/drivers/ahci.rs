//! AHCI SATA host controller driver.
//!
//! ## AHCI overview
//!   An AHCI controller (class 0x01, subclass 0x06) exposes:
//!     - Generic Host Control registers at BAR5 (HBA MMIO, "ABAR")
//!     - Up to 32 ports, each at BAR5 + 0x100 + port * 0x80.
//!
//! ## Initialisation sequence (AHCI 1.3.1 §10.1)
//!   1. PCIe: locate device by class, call dev.enable(), request MSI-X/MSI.
//!   2. Map ABAR (BAR5) as Uncacheable (UC) in the page tables.
//!   3. Set GHC.AE (bit 31) to enter AHCI mode.
//!   4. Read PI bitmask; for each set port:
//!      a. Stop port (ST=0, FRE=0, wait for CR/FR to clear).
//!      b. Allocate command list (1 KiB) + FIS buffer (256 B) + cmd tables.
//!      c. Program PxCLB/CLBU, PxFB/FBU.
//!      d. Clear PxSERR, PxIS.
//!      e. Set PxIE to enable D2H, DMA-setup, PIO-setup, error interrupts.
//!      f. Set PxCMD.FRE=1, then PxCMD.ST=1.
//!      g. Check PxSSTS.DET==3, IPM==1.
//!   5. Issue IDENTIFY (ATA 0xEC) to confirm capacity + model.
//!
//! ## Command issue (48-bit LBA DMA, polled or IRQ)
//!   1. Find free slot: first bit clear in PxCI & PxSACT.
//!   2. Fill CmdHeader: CFL=5, W=write, PRDTL=prdt_count.
//!   3. Fill CmdTable CFIS (H2D Register FIS) + PRDT entries.
//!   4. Set PxCI bit; poll or wait for IRQ.
//!   5. Check PxIS.TFES on completion.
//!
//! ## Public API
//!   ahci_probe()                           — PCIe discovery + full init
//!   ahci_init(bar5_pa)                     — init from known BAR5 address
//!   ahci_read_sector(port, lba, buf)       — read one 512-byte sector
//!   ahci_write_sector(port, lba, buf)      — write one 512-byte sector
//!   ahci_read(port, lba, count, buf)       — read `count` sectors
//!   ahci_write(port, lba, count, buf)      — write `count` sectors
//!   ahci_identify(port)                    — ATA IDENTIFY → [u16;256]
//!   ahci_port_lba48_max(port)              — drive capacity in sectors
//!   ahci_present() / ahci_port_count()     — presence checks
//!   ahci_irq_handler()                     — call from your IRQ dispatcher

extern crate alloc;
use alloc::vec::Vec;
use spin::Mutex;

use crate::drivers::pcie::{
    PCI_CLASS_STORAGE_AHCI, find_device_by_class,
    pci_enable_msix, pci_enable_msi_ex,
};

// ── HBA register offsets (from BAR5 base) ────────────────────────────────

const HBA_CAP:  usize = 0x000; // Host Capabilities
const HBA_GHC:  usize = 0x004; // Global Host Control  (bit31=AE, bit1=IE, bit0=HR)
const HBA_IS:   usize = 0x008; // Interrupt Status (one bit per port)
const HBA_PI:   usize = 0x00C; // Ports Implemented bitmask
const HBA_VS:   usize = 0x010; // Version

// ── Port register offsets (from port_base = BAR5 + 0x100 + port*0x80) ───

const PORT_CLB:  usize = 0x00; // Command List Base (low)
const PORT_CLBU: usize = 0x04; // Command List Base (high)
const PORT_FB:   usize = 0x08; // FIS Base (low)
const PORT_FBU:  usize = 0x0C; // FIS Base (high)
const PORT_IS:   usize = 0x10; // Interrupt Status  (write 1 to clear)
const PORT_IE:   usize = 0x14; // Interrupt Enable
const PORT_CMD:  usize = 0x18; // Command and Status
const PORT_TFD:  usize = 0x20; // Task File Data (status + error)
const PORT_SIG:  usize = 0x24; // Signature
const PORT_SSTS: usize = 0x28; // SATA Status (SCR0: DET, IPM)
const PORT_SERR: usize = 0x30; // SATA Error  (SCR1)
const PORT_CI:   usize = 0x38; // Command Issue

const PORT_CMD_ST:  u32 = 1 << 0;  // Start
const PORT_CMD_FRE: u32 = 1 << 4;  // FIS Receive Enable
const PORT_CMD_FR:  u32 = 1 << 14; // FIS Receive Running (RO)
const PORT_CMD_CR:  u32 = 1 << 15; // Command List Running (RO)

// PORT_IS / PORT_IE bits
const PORT_IS_DHRS: u32 = 1 << 0;  // Device-to-Host Register FIS
const PORT_IS_PSS:  u32 = 1 << 1;  // PIO Setup FIS
const PORT_IS_DSS:  u32 = 1 << 2;  // DMA Setup FIS
const PORT_IS_TFES: u32 = 1 << 30; // Task File Error Status
const PORT_IS_HBFS: u32 = 1 << 29; // HBA Fatal Error
const PORT_IS_HBDS: u32 = 1 << 28; // HBA Data Error
const PORT_IS_IFS:  u32 = 1 << 27; // Interface Fatal Error

/// Interrupt enable mask: D2H + DMA setup + PIO setup + fatal errors.
const PORT_IE_MASK: u32 =
    PORT_IS_DHRS | PORT_IS_PSS | PORT_IS_DSS |
    PORT_IS_TFES | PORT_IS_HBFS | PORT_IS_HBDS | PORT_IS_IFS;

const SSTS_DET_PRESENT: u32 = 0x3;
const SSTS_IPM_ACTIVE:  u32 = 0x1;

// ── Command FIS / ATA constants ───────────────────────────────────────────

const FIS_TYPE_REG_H2D:  u8 = 0x27;
const ATA_CMD_IDENTIFY:  u8 = 0xEC;
const ATA_CMD_READ_DMA_EX:  u8 = 0x25;
const ATA_CMD_WRITE_DMA_EX: u8 = 0x35;

pub const SECTOR_SIZE: usize = 512;
const CMD_SLOTS: usize = 32;

// AHCI IRQ vector assigned at probe time (driver-chosen; match your IDT entry).
pub const AHCI_IRQ_VECTOR: u8 = 0x2C;

// ── AHCI data structures ──────────────────────────────────────────────────

#[repr(C, align(32))]
#[derive(Clone, Copy, Default)]
struct CmdHeader {
    dw0:   u32, // CFL[4:0] | A | W | P | R | B | C | reserved | PRDTL[15:0]
    prdbc: u32, // PRDT Byte Count (written by HBA on completion)
    ctba:  u32, // Command Table Base Address (low 32)
    ctbau: u32, // Command Table Base Address (high 32)
    _res:  [u32; 4],
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct PrdtEntry {
    dba:  u32, // Data Base Address (low)
    dbau: u32, // Data Base Address (high)
    _res: u32,
    dbc:  u32, // Byte count minus 1 (bit31 = IRQ on completion)
}

/// Command table: CFIS (64 B) + ACMD (16 B) + reserved (48 B) + PRDT.
/// One per command slot.
#[repr(C, align(128))]
#[derive(Clone, Copy)]
struct CmdTable {
    cfis: [u8; 64],
    acmd: [u8; 16],
    _res: [u8; 48],
    prdt: [PrdtEntry; 1],
}
impl Default for CmdTable {
    fn default() -> Self { unsafe { core::mem::zeroed() } }
}

/// Per-port DMA memory.  Allocated from the PMM (bump allocator guarantees
/// physical contiguity).  Must be 1 KiB-aligned for cmd_list.
///
/// Layout chosen so that:
///   - cmd_list is first → naturally 1 KiB-aligned when the struct is page-aligned.
///   - fis_buf follows   → 256-byte aligned (32*32 = 1024, 1024 % 256 == 0).
///   - data_buf at end   → used as a single scratch page for polled I/O.
struct PortMem {
    cmd_list:  [CmdHeader; CMD_SLOTS], // 1024 bytes
    fis_buf:   [u8; 256],
    cmd_table: [CmdTable; CMD_SLOTS],  // 128 * 32 = 4096 bytes
    data_buf:  [u8; SECTOR_SIZE * 128],// scratch: up to 128 sectors (64 KiB)
}

// ── Port state ────────────────────────────────────────────────────────────

struct AhciPort {
    hba_base: usize,
    port_idx: usize,
    mem:      &'static mut PortMem,
    lba_max:  u64,   // total addressable sectors (from IDENTIFY word 100-103)
}

static PORTS: Mutex<Vec<AhciPort>> = Mutex::new(Vec::new());

// ── MMIO helpers ──────────────────────────────────────────────────────────

#[inline]
unsafe fn hba_r32(base: usize, off: usize) -> u32 {
    core::ptr::read_volatile((base + off) as *const u32)
}
#[inline]
unsafe fn hba_w32(base: usize, off: usize, v: u32) {
    core::ptr::write_volatile((base + off) as *mut u32, v);
}
#[inline]
fn port_base(hba: usize, port: usize) -> usize {
    hba + 0x100 + port * 0x80
}
#[inline]
unsafe fn pr32(hba: usize, port: usize, off: usize) -> u32 {
    hba_r32(port_base(hba, port), off)
}
#[inline]
unsafe fn pw32(hba: usize, port: usize, off: usize, v: u32) {
    hba_w32(port_base(hba, port), off, v);
}

// ── PCIe discovery + full init ────────────────────────────────────────────

/// Locate the AHCI controller via PCIe, enable it, request MSI-X (falling
/// back to MSI), then call ahci_init().
///
/// Call once from kernel_main after pcie_init() and ECAM mapping.
/// Registers AHCI_IRQ_VECTOR in your IDT before calling this.
pub fn ahci_probe() -> bool {
    let dev = match find_device_by_class(PCI_CLASS_STORAGE_AHCI) {
        Some(d) => d,
        None    => {
            crate::arch::x86_64::serial::serial_println!("ahci: no AHCI controller found");
            return false;
        }
    };

    dev.enable(); // set MMIO + bus-master bits in command register

    // Prefer MSI-X (entry 0), fall back to MSI.
    if !pci_enable_msix(&dev, 0, AHCI_IRQ_VECTOR, 0) {
        if !pci_enable_msi_ex(&dev, 0, AHCI_IRQ_VECTOR) {
            crate::arch::x86_64::serial::serial_println!(
                "ahci: no MSI/MSI-X, running polled");
        } else {
            crate::arch::x86_64::serial::serial_println!("ahci: MSI enabled");
        }
    } else {
        crate::arch::x86_64::serial::serial_println!("ahci: MSI-X enabled");
    }

    let bar5_pa = match dev.bar_mmio(5) {
        Some(b) => b as usize,
        None    => {
            crate::arch::x86_64::serial::serial_println!("ahci: BAR5 missing");
            return false;
        }
    };

    // The caller is responsible for mapping bar5_pa..bar5_pa+0x1100 as UC.
    ahci_init(bar5_pa);
    true
}

// ── Controller init ───────────────────────────────────────────────────────

/// Initialise AHCI from a known BAR5 physical address.
/// BAR5 must already be mapped Uncacheable (UC) in the page tables.
pub fn ahci_init(bar5_pa: usize) {
    unsafe {
        // Enable AHCI mode (GHC.AE).
        let ghc = hba_r32(bar5_pa, HBA_GHC);
        if ghc & (1 << 31) == 0 {
            hba_w32(bar5_pa, HBA_GHC, ghc | (1 << 31));
        }
        // Enable controller-level interrupts (GHC.IE).
        let ghc = hba_r32(bar5_pa, HBA_GHC);
        hba_w32(bar5_pa, HBA_GHC, ghc | (1 << 1));

        let pi  = hba_r32(bar5_pa, HBA_PI);
        let cap = hba_r32(bar5_pa, HBA_CAP);
        let _ncq_support = cap & (1 << 30) != 0;

        let mut ports = PORTS.lock();

        for port in 0..32usize {
            if pi & (1 << port) == 0 { continue; }

            let ssts = pr32(bar5_pa, port, PORT_SSTS);
            if (ssts & 0xF) != SSTS_DET_PRESENT
            || ((ssts >> 8) & 0xF) != SSTS_IPM_ACTIVE
            {
                continue;
            }

            stop_port(bar5_pa, port);

            let mem_pa = match alloc_port_mem() {
                Some(p) => p,
                None    => { continue; }
            };
            let mem: &'static mut PortMem = &mut *(mem_pa as *mut PortMem);
            core::ptr::write_bytes(
                mem as *mut PortMem as *mut u8, 0, core::mem::size_of::<PortMem>());

            // Program CLB / FIS base registers.
            let clb_pa = mem.cmd_list.as_ptr() as u64;
            let fb_pa  = mem.fis_buf.as_ptr()  as u64;
            pw32(bar5_pa, port, PORT_CLB,  (clb_pa & 0xFFFF_FFFF) as u32);
            pw32(bar5_pa, port, PORT_CLBU, (clb_pa >> 32) as u32);
            pw32(bar5_pa, port, PORT_FB,   (fb_pa  & 0xFFFF_FFFF) as u32);
            pw32(bar5_pa, port, PORT_FBU,  (fb_pa  >> 32) as u32);

            // Pre-fill command table base addresses in every header.
            for slot in 0..CMD_SLOTS {
                let ct_pa = &mem.cmd_table[slot] as *const CmdTable as u64;
                mem.cmd_list[slot].ctba  = (ct_pa & 0xFFFF_FFFF) as u32;
                mem.cmd_list[slot].ctbau = (ct_pa >> 32) as u32;
            }

            // Clear stale error/interrupt bits.
            pw32(bar5_pa, port, PORT_SERR, 0xFFFF_FFFF);
            pw32(bar5_pa, port, PORT_IS,   0xFFFF_FFFF);

            // Enable interrupts on this port.
            pw32(bar5_pa, port, PORT_IE, PORT_IE_MASK);

            // Start port: FRE first, then ST.
            let cmd = pr32(bar5_pa, port, PORT_CMD);
            pw32(bar5_pa, port, PORT_CMD, cmd | PORT_CMD_FRE);
            pw32(bar5_pa, port, PORT_CMD, cmd | PORT_CMD_FRE | PORT_CMD_ST);

            // IDENTIFY to get drive capacity.
            let lba_max = identify_lba_max(bar5_pa, port, mem);

            crate::arch::x86_64::serial::serial_println!(
                "ahci: port {} — {:?} sectors ({} MiB)",
                port, lba_max,
                lba_max * SECTOR_SIZE as u64 / (1024 * 1024)
            );

            ports.push(AhciPort { hba_base: bar5_pa, port_idx: port, mem, lba_max });
        }
    }
}

fn stop_port(hba: usize, port: usize) {
    unsafe {
        let cmd = pr32(hba, port, PORT_CMD);
        pw32(hba, port, PORT_CMD, cmd & !(PORT_CMD_ST | PORT_CMD_FRE));
        for _ in 0..500_000 {
            if pr32(hba, port, PORT_CMD) & (PORT_CMD_CR | PORT_CMD_FR) == 0 { break; }
            core::hint::spin_loop();
        }
    }
}

fn alloc_port_mem() -> Option<usize> {
    const PM_PAGES: usize =
        (core::mem::size_of::<PortMem>() + 4095) / 4096;
    let first_pa = crate::mm::pmm::alloc_page()?;
    for _ in 1..PM_PAGES {
        crate::mm::pmm::alloc_page()?; // bump allocator → contiguous
    }
    Some(first_pa)
}

// ── IDENTIFY ──────────────────────────────────────────────────────────────

/// Issue ATA IDENTIFY DEVICE; return the raw 256-word response.
pub fn ahci_identify(port_no: usize) -> Option<[u16; 256]> {
    let mut ports = PORTS.lock();
    let port = ports.get_mut(port_no)?;
    let hba  = port.hba_base;
    let pidx = port.port_idx;
    let mem  = &mut *port.mem;
    Some(unsafe { do_identify(hba, pidx, mem) })
}

unsafe fn do_identify(hba: usize, pidx: usize, mem: &mut PortMem) -> [u16; 256] {
    let slot = 0usize;
    let ct   = &mut mem.cmd_table[slot];
    ct.cfis       = [0u8; 64];
    ct.cfis[0]    = FIS_TYPE_REG_H2D;
    ct.cfis[1]    = 0x80;             // C=1
    ct.cfis[2]    = ATA_CMD_IDENTIFY;
    ct.cfis[7]    = 0xA0;             // device: LBA mode

    // PRDT: one entry, 512 bytes into data_buf.
    let dba = mem.data_buf.as_ptr() as u64;
    ct.prdt[0].dba  = (dba & 0xFFFF_FFFF) as u32;
    ct.prdt[0].dbau = (dba >> 32) as u32;
    ct.prdt[0].dbc  = (SECTOR_SIZE - 1) as u32;

    mem.cmd_list[slot].dw0   = 5 | (1 << 16); // CFL=5, PRDTL=1, W=0
    mem.cmd_list[slot].prdbc = 0;

    core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
    pw32(hba, pidx, PORT_IS, 0xFFFF_FFFF);
    pw32(hba, pidx, PORT_CI, 1 << slot);

    for _ in 0..2_000_000usize {
        core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
        if pr32(hba, pidx, PORT_CI) & (1 << slot) == 0 { break; }
        core::hint::spin_loop();
    }

    // Reinterpret data_buf as [u16; 256].
    let mut id = [0u16; 256];
    core::ptr::copy_nonoverlapping(
        mem.data_buf.as_ptr() as *const u16,
        id.as_mut_ptr(),
        256,
    );
    id
}

/// Extract LBA48 max sectors from an IDENTIFY response (words 100-103).
fn identify_lba_max(hba: usize, pidx: usize, mem: &mut PortMem) -> u64 {
    let id = unsafe { do_identify(hba, pidx, mem) };
    let lo = id[100] as u64
        | ((id[101] as u64) << 16)
        | ((id[102] as u64) << 32)
        | ((id[103] as u64) << 48);
    lo
}

// ── Multi-sector DMA I/O ──────────────────────────────────────────────────

/// Read `count` sectors (1-based, max 128) starting at `lba` into `buf`.
/// `buf` must be at least `count as usize * SECTOR_SIZE` bytes.
pub fn ahci_read(port_no: usize, lba: u64, count: u16, buf: &mut [u8]) -> bool {
    if count == 0 || count > 128 { return false; }
    if buf.len() < count as usize * SECTOR_SIZE { return false; }
    issue_rw_multi(port_no, lba, count, buf, false)
}

/// Write `count` sectors (1-based, max 128) from `buf` starting at `lba`.
pub fn ahci_write(port_no: usize, lba: u64, count: u16, buf: &[u8]) -> bool {
    if count == 0 || count > 128 { return false; }
    if buf.len() < count as usize * SECTOR_SIZE { return false; }
    // Copy to scratch so we own a mut reference for DMA.
    let mut ports = PORTS.lock();
    let port = match ports.get_mut(port_no) {
        Some(p) => p,
        None    => return false,
    };
    let n = count as usize * SECTOR_SIZE;
    port.mem.data_buf[..n].copy_from_slice(&buf[..n]);
    drop(ports);
    issue_rw_multi(port_no, lba, count, &mut [], true)
}

/// Read exactly one 512-byte sector.
pub fn ahci_read_sector(port_no: usize, lba: u64, buf: &mut [u8; SECTOR_SIZE]) -> bool {
    let mut tmp = [0u8; SECTOR_SIZE];
    if !ahci_read(port_no, lba, 1, &mut tmp) { return false; }
    buf.copy_from_slice(&tmp);
    true
}

/// Write exactly one 512-byte sector.
pub fn ahci_write_sector(port_no: usize, lba: u64, buf: &[u8; SECTOR_SIZE]) -> bool {
    ahci_write(port_no, lba, 1, buf)
}

fn issue_rw_multi(
    port_no: usize, lba: u64, count: u16,
    buf: &mut [u8], write: bool,
) -> bool {
    let mut ports = PORTS.lock();
    let port = match ports.get_mut(port_no) {
        Some(p) => p,
        None    => return false,
    };

    let slot  = 0usize;
    let hba   = port.hba_base;
    let pidx  = port.port_idx;
    let mem   = &mut *port.mem;
    let nbytes = count as usize * SECTOR_SIZE;

    unsafe {
        // For writes, copy caller data into scratch DMA buffer.
        if write && !buf.is_empty() {
            mem.data_buf[..nbytes].copy_from_slice(&buf[..nbytes]);
        }

        // Build H2D Register FIS.
        let ct = &mut mem.cmd_table[slot];
        ct.cfis = [0u8; 64];
        ct.cfis[0]  = FIS_TYPE_REG_H2D;
        ct.cfis[1]  = 0x80; // C=1
        ct.cfis[2]  = if write { ATA_CMD_WRITE_DMA_EX } else { ATA_CMD_READ_DMA_EX };
        ct.cfis[4]  =  (lba        & 0xFF) as u8; // LBA[7:0]
        ct.cfis[5]  = ((lba >>  8) & 0xFF) as u8; // LBA[15:8]
        ct.cfis[6]  = ((lba >> 16) & 0xFF) as u8; // LBA[23:16]
        ct.cfis[7]  = 0x40;                        // LBA mode, DEV=0
        ct.cfis[8]  = ((lba >> 24) & 0xFF) as u8; // LBA[31:24]
        ct.cfis[9]  = ((lba >> 32) & 0xFF) as u8; // LBA[39:32]
        ct.cfis[10] = ((lba >> 40) & 0xFF) as u8; // LBA[47:40]
        ct.cfis[11] = 0; // features high
        ct.cfis[12] = (count & 0xFF) as u8;        // sector count low
        ct.cfis[13] = ((count >> 8) & 0xFF) as u8; // sector count high

        // One PRDT entry covering all sectors.
        let dba = mem.data_buf.as_ptr() as u64;
        ct.prdt[0].dba  = (dba & 0xFFFF_FFFF) as u32;
        ct.prdt[0].dbau = (dba >> 32) as u32;
        ct.prdt[0].dbc  = (nbytes - 1) as u32;

        // Command header.
        let w_bit: u32 = if write { 1 << 6 } else { 0 };
        mem.cmd_list[slot].dw0   = 5 | w_bit | (1 << 16); // CFL=5, PRDTL=1
        mem.cmd_list[slot].prdbc = 0;

        core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
        pw32(hba, pidx, PORT_IS, 0xFFFF_FFFF);
        pw32(hba, pidx, PORT_CI, 1 << slot);

        // Poll PxCI until slot bit clears (timeout ~5 s).
        let mut ok = false;
        for _ in 0..5_000_000usize {
            core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
            if pr32(hba, pidx, PORT_CI) & (1 << slot) == 0 {
                ok = true;
                break;
            }
            core::hint::spin_loop();
        }
        if !ok { return false; }

        // Error check.
        if pr32(hba, pidx, PORT_IS) & (PORT_IS_TFES | PORT_IS_HBFS | PORT_IS_IFS) != 0 {
            return false;
        }

        // Copy DMA result into caller buffer on reads.
        if !write { buf[..nbytes].copy_from_slice(&mem.data_buf[..nbytes]); }
        true
    }
}

// ── IRQ handler ───────────────────────────────────────────────────────────

/// Call from your IRQ dispatcher when AHCI_IRQ_VECTOR fires.
/// Clears HBA_IS and port IS bits; logs errors.
/// In a future async driver this would wake waiters; for now it just drains.
pub fn ahci_irq_handler() {
    let ports = PORTS.lock();
    if ports.is_empty() { return; }

    let hba = ports[0].hba_base;
    let is  = unsafe { hba_r32(hba, HBA_IS) };
    if is == 0 { return; }

    for port in ports.iter() {
        let bit = 1u32 << port.port_idx;
        if is & bit == 0 { continue; }

        let p_is = unsafe { pr32(hba, port.port_idx, PORT_IS) };

        if p_is & (PORT_IS_TFES | PORT_IS_HBFS | PORT_IS_IFS) != 0 {
            let tfd = unsafe { pr32(hba, port.port_idx, PORT_TFD) };
            crate::arch::x86_64::serial::serial_println!(
                "ahci: port {} error IS={:#010x} TFD={:#010x}",
                port.port_idx, p_is, tfd
            );
        }

        // Clear port IS, then controller IS.
        unsafe {
            pw32(hba, port.port_idx, PORT_IS, p_is);
            hba_w32(hba, HBA_IS, bit);
        }
    }
}

// ── Public accessors ──────────────────────────────────────────────────────

/// Total addressable sectors on port `port_no` (LBA48 max from IDENTIFY).
pub fn ahci_port_lba48_max(port_no: usize) -> Option<u64> {
    PORTS.lock().get(port_no).map(|p| p.lba_max)
}

/// Returns true if at least one AHCI port has a device.
pub fn ahci_present() -> bool {
    !PORTS.lock().is_empty()
}

/// Number of AHCI-attached drives found.
pub fn ahci_port_count() -> usize {
    PORTS.lock().len()
}
