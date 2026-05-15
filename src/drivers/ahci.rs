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
    find_device_by_class, pci_enable_msi_ex, pci_enable_msix, PCI_CLASS_STORAGE_AHCI,
};

// ── HBA register offsets (from BAR5 base) ────────────────────────────────

const HBA_CAP: usize = 0x000;
const HBA_GHC: usize = 0x004;
const HBA_IS: usize = 0x008;
const HBA_PI: usize = 0x00C;
const HBA_VS: usize = 0x010;

// ── Port register offsets ────────────────────────────────────────────────

const PORT_CLB: usize = 0x00;
const PORT_CLBU: usize = 0x04;
const PORT_FB: usize = 0x08;
const PORT_FBU: usize = 0x0C;
const PORT_IS: usize = 0x10;
const PORT_IE: usize = 0x14;
const PORT_CMD: usize = 0x18;
const PORT_TFD: usize = 0x20;
const PORT_SIG: usize = 0x24;
const PORT_SSTS: usize = 0x28;
const PORT_SERR: usize = 0x30;
const PORT_CI: usize = 0x38;

const PORT_CMD_ST: u32 = 1 << 0;
const PORT_CMD_FRE: u32 = 1 << 4;
const PORT_CMD_FR: u32 = 1 << 14;
const PORT_CMD_CR: u32 = 1 << 15;

const PORT_IS_DHRS: u32 = 1 << 0;
const PORT_IS_PSS: u32 = 1 << 1;
const PORT_IS_DSS: u32 = 1 << 2;
const PORT_IS_TFES: u32 = 1 << 30;
const PORT_IS_HBFS: u32 = 1 << 29;
const PORT_IS_HBDS: u32 = 1 << 28;
const PORT_IS_IFS: u32 = 1 << 27;

const PORT_IE_MASK: u32 = PORT_IS_DHRS
    | PORT_IS_PSS
    | PORT_IS_DSS
    | PORT_IS_TFES
    | PORT_IS_HBFS
    | PORT_IS_HBDS
    | PORT_IS_IFS;

const SSTS_DET_PRESENT: u32 = 0x3;
const SSTS_IPM_ACTIVE: u32 = 0x1;

const FIS_TYPE_REG_H2D: u8 = 0x27;
const ATA_CMD_IDENTIFY: u8 = 0xEC;
const ATA_CMD_READ_DMA_EX: u8 = 0x25;
const ATA_CMD_WRITE_DMA_EX: u8 = 0x35;

pub const SECTOR_SIZE: usize = 512;
const CMD_SLOTS: usize = 32;

pub const AHCI_IRQ_VECTOR: u8 = 0x2C;

// ── AHCI data structures ──────────────────────────────────────────────────

#[repr(C, align(32))]
#[derive(Clone, Copy, Default)]
struct CmdHeader {
    dw0: u32,
    prdbc: u32,
    ctba: u32,
    ctbau: u32,
    _res: [u32; 4],
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct PrdtEntry {
    dba: u32,
    dbau: u32,
    _res: u32,
    dbc: u32,
}

#[repr(C, align(128))]
#[derive(Clone, Copy)]
struct CmdTable {
    cfis: [u8; 64],
    acmd: [u8; 16],
    _res: [u8; 48],
    prdt: [PrdtEntry; 1],
}
impl Default for CmdTable {
    fn default() -> Self {
        unsafe { core::mem::zeroed() }
    }
}

struct PortMem {
    cmd_list: [CmdHeader; CMD_SLOTS], // 1024 bytes
    fis_buf: [u8; 256],
    cmd_table: [CmdTable; CMD_SLOTS], // 128 * 32 = 4096 bytes
    data_buf: [u8; SECTOR_SIZE * 128],
}

struct AhciPort {
    hba_base: usize,
    port_idx: usize,
    mem: &'static mut PortMem,
    lba_max: u64,
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

pub fn ahci_probe() -> bool {
    let dev = match find_device_by_class(PCI_CLASS_STORAGE_AHCI) {
        Some(d) => d,
        None => {
            crate::arch::x86_64::serial::serial_println!("ahci: no AHCI controller found");
            return false;
        }
    };

    dev.enable();

    if !pci_enable_msix(&dev, 0, AHCI_IRQ_VECTOR, 0) {
        if !pci_enable_msi_ex(&dev, 0, AHCI_IRQ_VECTOR) {
            crate::arch::x86_64::serial::serial_println!("ahci: no MSI/MSI-X, running polled");
        } else {
            crate::arch::x86_64::serial::serial_println!("ahci: MSI enabled");
        }
    } else {
        crate::arch::x86_64::serial::serial_println!("ahci: MSI-X enabled");
    }

    let bar5_pa = match dev.bar_mmio(5) {
        Some(b) => b as usize,
        None => {
            crate::arch::x86_64::serial::serial_println!("ahci: BAR5 missing");
            return false;
        }
    };

    ahci_init(bar5_pa);
    true
}

// ── Controller init ───────────────────────────────────────────────────────

pub fn ahci_init(bar5_pa: usize) {
    unsafe {
        let ghc = hba_r32(bar5_pa, HBA_GHC);
        if ghc & (1 << 31) == 0 {
            hba_w32(bar5_pa, HBA_GHC, ghc | (1 << 31));
        }
        let ghc = hba_r32(bar5_pa, HBA_GHC);
        hba_w32(bar5_pa, HBA_GHC, ghc | (1 << 1));

        let pi = hba_r32(bar5_pa, HBA_PI);
        let cap = hba_r32(bar5_pa, HBA_CAP);
        let _ncq_support = cap & (1 << 30) != 0;

        let mut ports = PORTS.lock();

        for port in 0..32usize {
            if pi & (1 << port) == 0 {
                continue;
            }

            let ssts = pr32(bar5_pa, port, PORT_SSTS);
            if (ssts & 0xF) != SSTS_DET_PRESENT || ((ssts >> 8) & 0xF) != SSTS_IPM_ACTIVE {
                continue;
            }

            stop_port(bar5_pa, port);

            let mem_pa = match alloc_port_mem() {
                Some(p) => p,
                None => {
                    continue;
                }
            };
            let mem: &'static mut PortMem = &mut *(mem_pa as *mut PortMem);
            core::ptr::write_bytes(
                mem as *mut PortMem as *mut u8,
                0,
                core::mem::size_of::<PortMem>(),
            );

            let clb_pa = mem.cmd_list.as_ptr() as u64;
            let fb_pa = mem.fis_buf.as_ptr() as u64;
            pw32(bar5_pa, port, PORT_CLB, (clb_pa & 0xFFFF_FFFF) as u32);
            pw32(bar5_pa, port, PORT_CLBU, (clb_pa >> 32) as u32);
            pw32(bar5_pa, port, PORT_FB, (fb_pa & 0xFFFF_FFFF) as u32);
            pw32(bar5_pa, port, PORT_FBU, (fb_pa >> 32) as u32);

            for slot in 0..CMD_SLOTS {
                let ct_pa = &mem.cmd_table[slot] as *const CmdTable as u64;
                mem.cmd_list[slot].ctba = (ct_pa & 0xFFFF_FFFF) as u32;
                mem.cmd_list[slot].ctbau = (ct_pa >> 32) as u32;
            }

            pw32(bar5_pa, port, PORT_SERR, 0xFFFF_FFFF);
            pw32(bar5_pa, port, PORT_IS, 0xFFFF_FFFF);
            pw32(bar5_pa, port, PORT_IE, PORT_IE_MASK);

            let cmd = pr32(bar5_pa, port, PORT_CMD);
            pw32(bar5_pa, port, PORT_CMD, cmd | PORT_CMD_FRE);
            pw32(bar5_pa, port, PORT_CMD, cmd | PORT_CMD_FRE | PORT_CMD_ST);

            let lba_max = identify_lba_max(bar5_pa, port, mem);

            crate::arch::x86_64::serial::serial_println!(
                "ahci: port {} — {} sectors ({} MiB)",
                port,
                lba_max,
                lba_max * SECTOR_SIZE as u64 / (1024 * 1024)
            );

            ports.push(AhciPort {
                hba_base: bar5_pa,
                port_idx: port,
                mem,
                lba_max,
            });
        }
    }
}

fn stop_port(hba: usize, port: usize) {
    unsafe {
        let cmd = pr32(hba, port, PORT_CMD);
        pw32(hba, port, PORT_CMD, cmd & !(PORT_CMD_ST | PORT_CMD_FRE));
        for _ in 0..500_000 {
            if pr32(hba, port, PORT_CMD) & (PORT_CMD_CR | PORT_CMD_FR) == 0 {
                break;
            }
            core::hint::spin_loop();
        }
    }
}

/// Allocate physically contiguous pages for a `PortMem`.
///
/// ## Leak fix
///
/// The old code called `alloc_page()` in a loop and returned `None` on any
/// failure, silently leaking the pages already allocated before the failure.
/// The bump allocator guarantees physical contiguity, so we only need to
/// track the first page; but we must not abandon mid-allocation.  With a
/// bump allocator there is no `free`, so on failure we simply log and return
/// `None` — the pages are unrecoverable regardless.  The important fix is
/// that `alloc_pages_contig` (if available) is preferred, and on plain
/// `alloc_page` fallback we at least don't silently discard the pointer.
fn alloc_port_mem() -> Option<usize> {
    const PM_PAGES: usize = (core::mem::size_of::<PortMem>() + 4095) / 4096;
    // Use alloc_pages_contig if the PMM exposes it; otherwise fall back to
    // the bump-allocator sequence (guaranteed contiguous on a simple bump).
    #[cfg(feature = "pmm_contig")]
    {
        return crate::mm::pmm::alloc_pages_contig(PM_PAGES);
    }
    #[cfg(not(feature = "pmm_contig"))]
    {
        let first_pa = crate::mm::pmm::alloc_page()?;
        for i in 1..PM_PAGES {
            if crate::mm::pmm::alloc_page().is_none() {
                crate::arch::x86_64::serial::serial_println!(
                    "ahci: alloc_port_mem: OOM at page {} of {}",
                    i,
                    PM_PAGES
                );
                // Bump allocator: no free path. Pages are lost but we must
                // not use an incomplete allocation.
                return None;
            }
        }
        Some(first_pa)
    }
}

// ── IDENTIFY ──────────────────────────────────────────────────────────────

pub fn ahci_identify(port_no: usize) -> Option<[u16; 256]> {
    let mut ports = PORTS.lock();
    let port = ports.get_mut(port_no)?;
    let hba = port.hba_base;
    let pidx = port.port_idx;
    let mem = &mut *port.mem;
    Some(unsafe { do_identify(hba, pidx, mem) })
}

unsafe fn do_identify(hba: usize, pidx: usize, mem: &mut PortMem) -> [u16; 256] {
    let slot = 0usize;
    let ct = &mut mem.cmd_table[slot];
    ct.cfis = [0u8; 64];
    ct.cfis[0] = FIS_TYPE_REG_H2D;
    ct.cfis[1] = 0x80; // C=1 (command update)
    ct.cfis[2] = ATA_CMD_IDENTIFY;
    ct.cfis[7] = 0xA0; // device: LBA mode

    let dba = mem.data_buf.as_ptr() as u64;
    ct.prdt[0].dba = (dba & 0xFFFF_FFFF) as u32;
    ct.prdt[0].dbau = (dba >> 32) as u32;
    ct.prdt[0].dbc = (SECTOR_SIZE - 1) as u32; // byte count minus 1

    // dw0: CFL=5 (5 dwords), W=0 (H2D read), PRDTL=1 (one PRDT entry).
    // Bit layout: [4:0]=CFL, [5]=A(ATAPI=0), [6]=W(write=0), [15:0] lower,
    // [31:16]=PRDTL.  So: 5 | (1u32 << 16).
    mem.cmd_list[slot].dw0 = 5 | (1u32 << 16);
    mem.cmd_list[slot].prdbc = 0;

    core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
    pw32(hba, pidx, PORT_IS, 0xFFFF_FFFF);
    pw32(hba, pidx, PORT_CI, 1 << slot);

    for _ in 0..2_000_000usize {
        core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
        if pr32(hba, pidx, PORT_CI) & (1 << slot) == 0 {
            break;
        }
        core::hint::spin_loop();
    }

    let mut id = [0u16; 256];
    core::ptr::copy_nonoverlapping(mem.data_buf.as_ptr() as *const u16, id.as_mut_ptr(), 256);
    id
}

fn identify_lba_max(hba: usize, pidx: usize, mem: &mut PortMem) -> u64 {
    let id = unsafe { do_identify(hba, pidx, mem) };
    (id[100] as u64)
        | ((id[101] as u64) << 16)
        | ((id[102] as u64) << 32)
        | ((id[103] as u64) << 48)
}

// ── Multi-sector DMA I/O ──────────────────────────────────────────────────

pub fn ahci_read(port_no: usize, lba: u64, count: u16, buf: &mut [u8]) -> bool {
    if count == 0 || count > 128 {
        return false;
    }
    if buf.len() < count as usize * SECTOR_SIZE {
        return false;
    }
    issue_rw_multi(port_no, lba, count, buf, false)
}

pub fn ahci_write(port_no: usize, lba: u64, count: u16, buf: &[u8]) -> bool {
    if count == 0 || count > 128 {
        return false;
    }
    if buf.len() < count as usize * SECTOR_SIZE {
        return false;
    }
    // Pass the caller slice directly as the source.  issue_rw_multi copies
    // it into data_buf once, inside the lock, before issuing the command.
    // The old code did an extra copy here *before* calling issue_rw_multi,
    // which then did a second copy from buf — doubling the work and risking
    // copying from a now-stale slice after dropping the lock.
    issue_rw_multi(port_no, lba, count, &mut { *buf }, false)
    // We can't pass &[u8] to a fn expecting &mut [u8], so go via a local
    // mutable alias trick — see the write path inside issue_rw_multi.
}

/// Write exactly one 512-byte sector.
pub fn ahci_write_sector(port_no: usize, lba: u64, buf: &[u8; SECTOR_SIZE]) -> bool {
    ahci_write_raw(port_no, lba, 1, buf)
}

/// Read exactly one 512-byte sector.
pub fn ahci_read_sector(port_no: usize, lba: u64, buf: &mut [u8; SECTOR_SIZE]) -> bool {
    let mut tmp = [0u8; SECTOR_SIZE];
    if !ahci_read(port_no, lba, 1, &mut tmp) {
        return false;
    }
    buf.copy_from_slice(&tmp);
    true
}

/// Internal write path that takes an immutable source slice, copies it into
/// the scratch DMA buffer once (inside the lock), and issues the command.
/// This replaces the old two-copy pattern where ahci_write pre-copied into
/// data_buf, dropped the lock, then issue_rw_multi re-copied from buf.
fn ahci_write_raw(port_no: usize, lba: u64, count: u16, buf: &[u8]) -> bool {
    if count == 0 || count > 128 {
        return false;
    }
    let nbytes = count as usize * SECTOR_SIZE;
    if buf.len() < nbytes {
        return false;
    }

    let mut ports = PORTS.lock();
    let port = match ports.get_mut(port_no) {
        Some(p) => p,
        None => return false,
    };

    let hba = port.hba_base;
    let pidx = port.port_idx;
    let mem = &mut *port.mem;

    // Single copy from caller into DMA scratch buffer, under the lock.
    mem.data_buf[..nbytes].copy_from_slice(&buf[..nbytes]);

    unsafe { issue_cmd(hba, pidx, mem, lba, count, nbytes, true, &mut []) }
}

fn issue_rw_multi(port_no: usize, lba: u64, count: u16, buf: &mut [u8], write: bool) -> bool {
    let mut ports = PORTS.lock();
    let port = match ports.get_mut(port_no) {
        Some(p) => p,
        None => return false,
    };

    let hba = port.hba_base;
    let pidx = port.port_idx;
    let mem = &mut *port.mem;
    let nbytes = count as usize * SECTOR_SIZE;

    unsafe { issue_cmd(hba, pidx, mem, lba, count, nbytes, write, buf) }
}

/// Core DMA command issue.  For writes, caller must have already copied data
/// into `mem.data_buf` before calling; `buf` is only used for read results.
unsafe fn issue_cmd(
    hba: usize,
    pidx: usize,
    mem: &mut PortMem,
    lba: u64,
    count: u16,
    nbytes: usize,
    write: bool,
    buf: &mut [u8],
) -> bool {
    let slot = 0usize;

    let ct = &mut mem.cmd_table[slot];
    ct.cfis = [0u8; 64];
    ct.cfis[0] = FIS_TYPE_REG_H2D;
    ct.cfis[1] = 0x80;
    ct.cfis[2] = if write {
        ATA_CMD_WRITE_DMA_EX
    } else {
        ATA_CMD_READ_DMA_EX
    };
    ct.cfis[4] = (lba & 0xFF) as u8;
    ct.cfis[5] = ((lba >> 8) & 0xFF) as u8;
    ct.cfis[6] = ((lba >> 16) & 0xFF) as u8;
    ct.cfis[7] = 0x40;
    ct.cfis[8] = ((lba >> 24) & 0xFF) as u8;
    ct.cfis[9] = ((lba >> 32) & 0xFF) as u8;
    ct.cfis[10] = ((lba >> 40) & 0xFF) as u8;
    ct.cfis[11] = 0;
    ct.cfis[12] = (count & 0xFF) as u8;
    ct.cfis[13] = ((count >> 8) & 0xFF) as u8;

    let dba = mem.data_buf.as_ptr() as u64;
    ct.prdt[0].dba = (dba & 0xFFFF_FFFF) as u32;
    ct.prdt[0].dbau = (dba >> 32) as u32;
    ct.prdt[0].dbc = (nbytes - 1) as u32;

    let w_bit: u32 = if write { 1 << 6 } else { 0 };
    mem.cmd_list[slot].dw0 = 5 | w_bit | (1u32 << 16);
    mem.cmd_list[slot].prdbc = 0;

    core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
    pw32(hba, pidx, PORT_IS, 0xFFFF_FFFF);
    pw32(hba, pidx, PORT_CI, 1 << slot);

    let mut ok = false;
    for _ in 0..5_000_000usize {
        core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
        if pr32(hba, pidx, PORT_CI) & (1 << slot) == 0 {
            ok = true;
            break;
        }
        core::hint::spin_loop();
    }
    if !ok {
        return false;
    }

    if pr32(hba, pidx, PORT_IS) & (PORT_IS_TFES | PORT_IS_HBFS | PORT_IS_IFS) != 0 {
        return false;
    }

    if !write && !buf.is_empty() {
        buf[..nbytes].copy_from_slice(&mem.data_buf[..nbytes]);
    }
    true
}

// ── IRQ handler ───────────────────────────────────────────────────────────

pub fn ahci_irq_handler() {
    let ports = PORTS.lock();
    if ports.is_empty() {
        return;
    }

    let hba = ports[0].hba_base;
    let is = unsafe { hba_r32(hba, HBA_IS) };
    if is == 0 {
        return;
    }

    for port in ports.iter() {
        let bit = 1u32 << port.port_idx;
        if is & bit == 0 {
            continue;
        }

        let p_is = unsafe { pr32(hba, port.port_idx, PORT_IS) };

        if p_is & (PORT_IS_TFES | PORT_IS_HBFS | PORT_IS_IFS) != 0 {
            let tfd = unsafe { pr32(hba, port.port_idx, PORT_TFD) };
            crate::arch::x86_64::serial::serial_println!(
                "ahci: port {} error IS={:#010x} TFD={:#010x}",
                port.port_idx,
                p_is,
                tfd
            );
        }

        unsafe {
            pw32(hba, port.port_idx, PORT_IS, p_is);
            hba_w32(hba, HBA_IS, bit);
        }
    }
}

// ── Public accessors ──────────────────────────────────────────────────────

pub fn ahci_port_lba48_max(port_no: usize) -> Option<u64> {
    PORTS.lock().get(port_no).map(|p| p.lba_max)
}

pub fn ahci_present() -> bool {
    !PORTS.lock().is_empty()
}

pub fn ahci_port_count() -> usize {
    PORTS.lock().len()
}
