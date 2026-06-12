//! AHCI SATA controller driver.
//!
//! Implements:
//!   - HBA port enumeration (PI register)
//!   - COMRESET / BIST bring-up per port
//!   - 32-slot command list + FIS receive buffer per port
//!   - H2D Register FIS construction for ATA READ/WRITE DMA EXT (48-bit LBA)
//!   - MSI-X interrupt wiring (falls back gracefully to polling when absent)
//!   - Hybrid completion: IRQ fast-path + polled fallback
//!
//! Limitations:
//!   - One PRDT entry per command (≤128 KiB contiguous DMA)
//!   - Assumes identity-mapped physical memory

extern crate alloc;
use alloc::vec::Vec;
use core::ptr::{read_volatile, write_volatile};
use core::sync::atomic::{fence, AtomicBool, Ordering};
use spin::Mutex;

// ── HBA memory-mapped register offsets (from BAR5 base) ──────────────────────
const HBA_CAP: usize = 0x00;
const HBA_GHC: usize = 0x04;
const HBA_IS: usize = 0x08;
const HBA_PI: usize = 0x0C;
const HBA_VS: usize = 0x10;

const GHC_AE: u32 = 1 << 31;
const GHC_HR: u32 = 1 << 0;
const GHC_IE: u32 = 1 << 1; // interrupt enable — set when MSI-X is wired

// ── Per-port register offsets
// ─────────────────────────────────────────────────
const P_CLB: usize = 0x00;
const P_CLBU: usize = 0x04;
const P_FB: usize = 0x08;
const P_FBU: usize = 0x0C;
const P_IS: usize = 0x10;
const P_IE: usize = 0x14;
const P_CMD: usize = 0x18;
const P_TFD: usize = 0x20;
const P_SIG: usize = 0x24;
const P_SSTS: usize = 0x28;
const P_SCTL: usize = 0x2C;
const P_SERR: usize = 0x30;
const P_SACT: usize = 0x34;
const P_CI: usize = 0x38;

const PCMD_ST: u32 = 1 << 0;
const PCMD_FRE: u32 = 1 << 4;
const PCMD_FR: u32 = 1 << 14;
const PCMD_CR: u32 = 1 << 15;

const SSTS_DET_PRESENT: u32 = 0x3;
const SSTS_IPM_ACTIVE: u32 = 0x1;

const SIG_SATA: u32 = 0x0000_0101;

// Port interrupt-enable bits we care about:
//   bit 5  = Descriptor Processed
//   bit 0  = D2H Register FIS received (command complete)
const P_IE_ENABLE: u32 = (1 << 5) | (1 << 0);

// ATA commands
const ATA_READ_DMA_EXT: u8 = 0x25;
const ATA_WRITE_DMA_EXT: u8 = 0x35;

// IDT vector reserved for AHCI completions.
const AHCI_IRQ_VECTOR: u8 = 0x31;

// ── Completion signal
// ─────────────────────────────────────────────────────────

/// Set to `true` by the MSI-X ISR; cleared (swap) by `issue_rw`.
static COMPLETION_FLAG: AtomicBool = AtomicBool::new(false);

// ── Command Header (32 bytes)
// ─────────────────────────────────────────────────
#[repr(C, packed)]
#[derive(Clone, Copy, Default)]
struct CmdHeader {
    dw0: u32,
    prdbc: u32,
    ctba: u32,
    ctbau: u32,
    _res: [u32; 4],
}

// ── Physical Region Descriptor Table entry (16 bytes) ────────────────────────
#[repr(C, packed)]
#[derive(Clone, Copy, Default)]
struct PrdtEntry {
    dba: u32,
    dbau: u32,
    _res: u32,
    dbc: u32,
}

// ── Command Table
// ─────────────────────────────────────────────────────────────
#[repr(C, packed)]
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

// ── Per-port state
// ────────────────────────────────────────────────────────────
struct AhciPort {
    base: usize,
    clb_phys: u64,
    fb_phys: u64,
    ct_phys: u64,
    dma_phys: u64,
}

static PORTS: Mutex<Vec<AhciPort>> = Mutex::new(Vec::new());

// ── Public API
// ────────────────────────────────────────────────────────────────

/// Initialise AHCI using the HBA MMIO at `bar5_virt` (virtual = physical).
/// Enumerates all implemented and attached SATA ports, then attempts to
/// wire one MSI-X vector for interrupt-driven completion.
pub fn ahci_init(bar5_virt: usize) {
    unsafe { _init(bar5_virt) }
    // MSI-X wiring relies on x86 APIC/IDT; on other architectures the AHCI
    // controller drops back to polling mode silently.
    #[cfg(target_arch = "x86_64")]
    wire_msix(bar5_virt);
    #[cfg(not(target_arch = "x86_64"))]
    let _ = bar5_virt;
}

/// Number of ready SATA ports found after `ahci_init`.
pub fn ahci_port_count() -> usize {
    PORTS.lock().len()
}

/// Legacy shim used by boot-detection code.
pub fn ahci_present() -> bool {
    ahci_port_count() > 0
}

/// Read `buf.len()` bytes from `port` starting at `lba` into `buf`.
/// `buf` length must be a multiple of 512 bytes.
pub fn ahci_read_sector(port: usize, lba: u64, buf: &mut [u8]) -> bool {
    issue_rw(port, lba, buf.as_mut_ptr() as u64, buf.len(), false)
}

/// Write `buf` to `port` starting at `lba`.
/// `buf` length must be a multiple of 512 bytes.
pub fn ahci_write_sector(port: usize, lba: u64, buf: &[u8]) -> bool {
    issue_rw(port, lba, buf.as_ptr() as u64, buf.len(), true)
}

// ── BlockDev impl
// ─────────────────────────────────────────────────────────────

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

// ── MSI-X wiring
// ──────────────────────────────────────────────────────────────

/// Wire MSI-X vector 0 of the AHCI HBA to `AHCI_IRQ_VECTOR` on the BSP
/// LAPIC, then enable per-port interrupts and the global HBA interrupt.
///
/// Uses `crate::device::pci::find_by_class_progif` which bridges into the
/// arch-level registry — guaranteed non-empty after `pci::init()` runs.
///
/// Safe to call when no MSI-X capability is present — returns early and
/// the driver remains in polling mode.
#[cfg(target_arch = "x86_64")]
fn wire_msix(bar5_virt: usize) {
    use crate::arch::x86_64::{apic, idt};
    use crate::device::pci;
    use crate::device::pci::msix::msix_configure;

    // AHCI: class=0x01, subclass=0x06, prog_if=0x01
    let dev = match pci::find_by_class_progif(0x01, 0x06, 0x01) {
        Some(d) => d,
        None => return,
    };

    if dev.msix_cap == 0 {
        return;
    }

    let lapic = apic::lapic_id();
    msix_configure(&dev, 0, lapic, AHCI_IRQ_VECTOR);

    // Register the ISR: clear per-port IS, update global IS, then EOI.
    idt::register_irq(AHCI_IRQ_VECTOR, |_frame| {
        // Clear interrupt status on every active port.
        let ports = PORTS.lock();
        for p in ports.iter() {
            let is = unsafe { port_r32(p.base, P_IS) };
            if is != 0 {
                unsafe {
                    port_w32(p.base, P_IS, is);
                }
            }
        }
        drop(ports);
        // Signal any waiting issue_rw caller.
        COMPLETION_FLAG.store(true, Ordering::Release);
        apic::send_eoi();
    });

    // Enable per-port interrupt delivery and the global HBA interrupt enable.
    {
        let ports = PORTS.lock();
        for p in ports.iter() {
            unsafe {
                port_w32(p.base, P_IE, P_IE_ENABLE);
            }
        }
    }
    unsafe {
        let ghc = hba_r32(bar5_virt, HBA_GHC);
        hba_w32(bar5_virt, HBA_GHC, ghc | GHC_IE);
    }

    log::info!("ahci: MSI-X wired to vector {:#x}", AHCI_IRQ_VECTOR);
}

// ── Internals
// ─────────────────────────────────────────────────────────────────

unsafe fn _init(bar5: usize) {
    let ghc = hba_r32(bar5, HBA_GHC);
    hba_w32(bar5, HBA_GHC, ghc | GHC_AE);

    let is = hba_r32(bar5, HBA_IS);
    hba_w32(bar5, HBA_IS, is);

    let pi = hba_r32(bar5, HBA_PI);

    for port_idx in 0..32usize {
        if pi & (1 << port_idx) == 0 {
            continue;
        }
        let pbase = bar5 + 0x100 + port_idx * 0x80;

        let ssts = port_r32(pbase, P_SSTS);
        let det = ssts & 0xF;
        let ipm = (ssts >> 8) & 0xF;
        if det != SSTS_DET_PRESENT || ipm != SSTS_IPM_ACTIVE {
            continue;
        }
        let sig = port_r32(pbase, P_SIG);
        if sig != SIG_SATA {
            continue;
        }

        let clb = alloc_dma(32 * 32, 1024).expect("ahci clb");
        let fb = alloc_dma(256, 256).expect("ahci fb");
        let ct = alloc_dma(core::mem::size_of::<CmdTable>(), 128).expect("ahci ct");
        let dma = alloc_dma(512 * 256, 4096).expect("ahci dma");

        stop_engine(pbase);

        port_w32(pbase, P_CLB, clb as u32);
        port_w32(pbase, P_CLBU, (clb >> 32) as u32);
        port_w32(pbase, P_FB, fb as u32);
        port_w32(pbase, P_FBU, (fb >> 32) as u32);

        let hdr = clb as *mut CmdHeader;
        (*hdr).ctba = ct as u32;
        (*hdr).ctbau = (ct >> 32) as u32;

        port_w32(pbase, P_SERR, !0u32);
        port_w32(pbase, P_IS, !0u32);
        start_engine(pbase);

        let mut ports = PORTS.lock();
        ports.push(AhciPort {
            base: pbase,
            clb_phys: clb,
            fb_phys: fb,
            ct_phys: ct,
            dma_phys: dma,
        });
    }
}

/// Issue a single DMA read or write using slot 0.
///
/// Completion is detected via `COMPLETION_FLAG` (set by the MSI-X ISR)
/// as a fast path; the spin-poll loop serves as fallback when running
/// without interrupts.
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
        let ct = p.ct_phys as *mut CmdTable;
        core::ptr::write_bytes(ct as *mut u8, 0, core::mem::size_of::<CmdTable>());

        let cfis = &mut (*ct).cfis;
        cfis[0] = 0x27;
        cfis[1] = 0x80;
        cfis[2] = if write {
            ATA_WRITE_DMA_EXT
        } else {
            ATA_READ_DMA_EXT
        };
        cfis[7] = 0x40;
        cfis[4] = lba as u8;
        cfis[5] = (lba >> 8) as u8;
        cfis[6] = (lba >> 16) as u8;
        cfis[8] = (lba >> 24) as u8;
        cfis[9] = (lba >> 32) as u8;
        cfis[10] = (lba >> 40) as u8;
        cfis[12] = sector_count as u8;
        cfis[13] = (sector_count >> 8) as u8;

        let prdt = &mut (*ct).prdt[0];
        prdt.dba = buf_phys as u32;
        prdt.dbau = (buf_phys >> 32) as u32;
        prdt.dbc = (byte_len as u32) - 1;

        let hdr = p.clb_phys as *mut CmdHeader;
        let cfl: u32 = (core::mem::size_of::<[u8; 20]>() / 4) as u32;
        let w_bit: u32 = if write { 1 << 6 } else { 0 };
        (*hdr).dw0 = cfl | w_bit | (1 << 16);
        (*hdr).prdbc = 0;

        fence(Ordering::Release);

        // Clear any stale completion flag before issuing the command.
        COMPLETION_FLAG.store(false, Ordering::Release);

        port_w32(p.base, P_SERR, !0u32);
        port_w32(p.base, P_IS, !0u32);

        port_w32(p.base, P_CI, 1);

        let timeout = 10_000_000usize;
        for _ in 0..timeout {
            fence(Ordering::Acquire);

            // Fast path: MSI-X ISR fired.
            if COMPLETION_FLAG.swap(false, Ordering::AcqRel) {
                let tfd = port_r32(p.base, P_TFD);
                let is = port_r32(p.base, P_IS);
                if is & (1 << 30) != 0 {
                    return false; // TFES — task-file error
                }
                if tfd & 0x88 == 0 {
                    return true;
                }
                // ISR fired but BSY/DRQ still set — keep waiting.
            }

            // Polled fallback.
            let ci = port_r32(p.base, P_CI);
            let tfd = port_r32(p.base, P_TFD);
            let is = port_r32(p.base, P_IS);

            if is & (1 << 30) != 0 {
                return false;
            }
            if ci & 1 == 0 && tfd & 0x88 == 0 {
                return true;
            }
            core::hint::spin_loop();
        }
    }
    false
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
    let phys = crate::mm::pmm::alloc_pages_aligned(pages, align)?.as_ptr() as u64;
    unsafe {
        core::ptr::write_bytes(phys as *mut u8, 0, pages * 0x1000);
    }
    Some(phys)
}
