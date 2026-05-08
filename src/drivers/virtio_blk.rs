//! VirtIO block device driver — PCI transport, legacy + modern (1.0).
//!
//! ## Spec references
//!   - VirtIO 1.2 spec §§ 2, 4.1, 5.2
//!   - VirtIO legacy (0.9.5) PCI transport
//!
//! ## Transport detection
//!   device ID 0x1001 (legacy)  → BAR0 = I/O port base
//!   device ID 0x1042 (modern)  → BAR1 = CommonCfg MMIO
//!   We probe both: find 0x1042 first, fall back to 0x1001.
//!
//! ## Virtqueue
//!   Single split virtqueue (queue 0).  Descriptors and data buffers are
//!   in identity-mapped PMM pages (PA == VA).
//!   Requests are synchronous: kick queue, spin-poll used ring.
//!
//! ## Public API
//!   virtio_blk_probe()                    — PCIe discovery + init
//!   init()                                — legacy compat entry point
//!   is_present() -> bool
//!   read_sectors(lba, buf)  -> Result<(), i32>
//!   write_sectors(lba, buf) -> Result<(), i32>
//!   virtio_blk_capacity()   -> Option<u64>  (sectors)
//!   virtio_blk_irq_handler()               — call from IRQ dispatcher

extern crate alloc;
use core::sync::atomic::{AtomicBool, Ordering};
use spin::Mutex;

use crate::drivers::pcie::{
    find_device_by_id, pci_enable_msix, pci_enable_msi_ex,
};

// IRQ vector assigned to virtio-blk MSI-X entry 0.
pub const VIRTIO_BLK_IRQ_VECTOR: u8 = 0x2D;

// VirtIO PCI IDs.
const VIRTIO_VENDOR:     u16 = 0x1AF4;
const VIRTIO_BLK_LEGACY: u16 = 0x1001; // legacy device ID
const VIRTIO_BLK_MODERN: u16 = 0x1042; // modern (1.0+) device ID

// ── VirtIO legacy I/O port register offsets (from BAR0) ─────────────────

const VTIO_DEVICE_FEATURES: u16 = 0x00;
const VTIO_GUEST_FEATURES:  u16 = 0x04;
const VTIO_QUEUE_PFN:       u16 = 0x08;
const VTIO_QUEUE_SIZE:      u16 = 0x0C;
const VTIO_QUEUE_SELECT:    u16 = 0x0E;
const VTIO_QUEUE_NOTIFY:    u16 = 0x10;
const VTIO_DEVICE_STATUS:   u16 = 0x12;
const VTIO_ISR_STATUS:      u16 = 0x13;

// VirtIO 1.0 CommonCfg MMIO offsets (BAR1, via capability list).
const VCFG_DEVICE_FEATURE_SELECT: usize = 0x00;
const VCFG_DEVICE_FEATURE:        usize = 0x04;
const VCFG_DRIVER_FEATURE_SELECT: usize = 0x08;
const VCFG_DRIVER_FEATURE:        usize = 0x0C;
const VCFG_CONFIG_MSIX_VECTOR:    usize = 0x10;
const VCFG_NUM_QUEUES:            usize = 0x12;
const VCFG_DEVICE_STATUS:         usize = 0x14;
const VCFG_CONFIG_GENERATION:     usize = 0x15;
const VCFG_QUEUE_SELECT:          usize = 0x16;
const VCFG_QUEUE_SIZE:            usize = 0x18;
const VCFG_QUEUE_MSIX_VECTOR:     usize = 0x1A;
const VCFG_QUEUE_ENABLE:          usize = 0x1C;
const VCFG_QUEUE_NOTIFY_OFF:      usize = 0x1E;
const VCFG_QUEUE_DESC_LO:         usize = 0x20;
const VCFG_QUEUE_DESC_HI:         usize = 0x24;
const VCFG_QUEUE_AVAIL_LO:        usize = 0x28;
const VCFG_QUEUE_AVAIL_HI:        usize = 0x2C;
const VCFG_QUEUE_USED_LO:         usize = 0x30;
const VCFG_QUEUE_USED_HI:         usize = 0x34;

// Device status bits.
const VTIO_S_ACK:        u8 = 1;
const VTIO_S_DRIVER:     u8 = 2;
const VTIO_S_DRIVER_OK:  u8 = 4;
const VTIO_S_FEATURES_OK:u8 = 8;
const VTIO_S_FAILED:     u8 = 128;

// ── Virtqueue layout (split queue, power-of-two size 16) ─────────────────

const QUEUE_SIZE:  usize = 16;
const DESC_SIZE:   usize = 16; // addr:u64, len:u32, flags:u16, next:u16
const AVAIL_OFF:   usize = QUEUE_SIZE * DESC_SIZE; // right after descriptors
const AVAIL_SIZE:  usize = 6 + QUEUE_SIZE * 2;
const USED_OFF_UA: usize = AVAIL_OFF + AVAIL_SIZE;
const USED_OFF:    usize = (USED_OFF_UA + 4095) & !4095;

// Descriptor flags.
const VRING_DESC_F_NEXT:  u16 = 1;
const VRING_DESC_F_WRITE: u16 = 2;

// Request type field.
const VIRTIO_BLK_T_IN:  u32 = 0;
const VIRTIO_BLK_T_OUT: u32 = 1;

// ── Transport variant ────────────────────────────────────────────────────

enum Transport {
    /// Legacy: I/O port BAR0.
    Legacy { io_base: u16 },
    /// Modern (VirtIO 1.0): MMIO BAR1 CommonCfg + notify base.
    Modern { cfg_base: usize, notify_base: usize, notify_off_mult: u32 },
}

// ── Driver state ─────────────────────────────────────────────────────────

struct BlkDev {
    transport: Transport,
    queue_va:  usize,   // PA == VA of desc table page
    last_used: u16,
    capacity:  u64,     // sectors
}

static DEV:     Mutex<Option<BlkDev>> = Mutex::new(None);
static PRESENT: AtomicBool = AtomicBool::new(false);

// ── PCIe discovery + init ────────────────────────────────────────────────

/// Locate the virtio-blk device via PCIe, enable MSI-X, and initialise.
/// Prefers the modern (1.0) device ID 0x1042; falls back to legacy 0x1001.
/// Call once from kernel_main after pcie_init().
pub fn virtio_blk_probe() -> bool {
    // Try modern first.
    let (dev, modern) = if let Some(d) = find_device_by_id(VIRTIO_VENDOR, VIRTIO_BLK_MODERN) {
        (d, true)
    } else if let Some(d) = find_device_by_id(VIRTIO_VENDOR, VIRTIO_BLK_LEGACY) {
        (d, false)
    } else {
        crate::arch::x86_64::serial::serial_println!("virtio_blk: device not found");
        return false;
    };

    dev.enable();

    // Request MSI-X (entry 0), fall back to MSI, then polled.
    if pci_enable_msix(&dev, 0, VIRTIO_BLK_IRQ_VECTOR, 0) {
        crate::arch::x86_64::serial::serial_println!("virtio_blk: MSI-X enabled");
    } else if pci_enable_msi_ex(&dev, 0, VIRTIO_BLK_IRQ_VECTOR) {
        crate::arch::x86_64::serial::serial_println!("virtio_blk: MSI enabled");
    } else {
        crate::arch::x86_64::serial::serial_println!("virtio_blk: polled mode");
    }

    if modern {
        let cfg_base = match dev.bar_mmio(1) {
            Some(b) => b as usize,
            None    => {
                crate::arch::x86_64::serial::serial_println!("virtio_blk: BAR1 missing");
                return false;
            }
        };
        // Notify BAR is BAR2; notify_off_mult from capability (assume 4 for QEMU).
        let notify_base     = dev.bar_mmio(2).unwrap_or(cfg_base + 0x1000) as usize;
        let notify_off_mult = 4u32;
        unsafe { init_modern(cfg_base, notify_base, notify_off_mult) };
    } else {
        let io_base = match dev.bar_io(0) {
            Some(b) => b as u16,
            None    => {
                crate::arch::x86_64::serial::serial_println!("virtio_blk: BAR0 I/O missing");
                return false;
            }
        };
        unsafe { init_legacy(io_base) };
    }
    true
}

/// Legacy compat entry point — scans via PCIe layer instead of raw port I/O.
pub fn init() {
    virtio_blk_probe();
}

// ── Legacy init ──────────────────────────────────────────────────────────

unsafe fn init_legacy(io_base: u16) {
    // Reset.
    vio_writeb(io_base, VTIO_DEVICE_STATUS, 0);
    vio_writeb(io_base, VTIO_DEVICE_STATUS, VTIO_S_ACK);
    vio_writeb(io_base, VTIO_DEVICE_STATUS, VTIO_S_ACK | VTIO_S_DRIVER);

    // Accept all features (legacy: no FEATURES_OK step).
    let feats = vio_readl(io_base, VTIO_DEVICE_FEATURES);
    vio_writel(io_base, VTIO_GUEST_FEATURES, feats);

    // Allocate queue pages.
    let queue_va = match alloc_queue_pages() { Some(p) => p, None => return };

    vio_writew(io_base, VTIO_QUEUE_SELECT, 0);
    let _qs = vio_readw(io_base, VTIO_QUEUE_SIZE);
    vio_writel(io_base, VTIO_QUEUE_PFN, (queue_va as u32) >> 12);

    vio_writeb(io_base, VTIO_DEVICE_STATUS,
               VTIO_S_ACK | VTIO_S_DRIVER | VTIO_S_DRIVER_OK);

    // Capacity at BAR0+0x14 for legacy.
    let cap_lo = vio_readl(io_base, 0x14);
    let cap_hi = vio_readl(io_base, 0x18);
    let capacity = ((cap_hi as u64) << 32) | cap_lo as u64;

    crate::arch::x86_64::serial::serial_println!(
        "virtio_blk: legacy init ok, {} sectors", capacity);

    *DEV.lock() = Some(BlkDev {
        transport: Transport::Legacy { io_base },
        queue_va, last_used: 0, capacity,
    });
    PRESENT.store(true, Ordering::Release);
}

// ── Modern (VirtIO 1.0) init ─────────────────────────────────────────────

unsafe fn init_modern(cfg: usize, notify_base: usize, notify_off_mult: u32) {
    // 1. Reset.
    mcfg_wb(cfg, VCFG_DEVICE_STATUS, 0u8);
    // 2. Acknowledge.
    mcfg_wb(cfg, VCFG_DEVICE_STATUS, VTIO_S_ACK);
    mcfg_wb(cfg, VCFG_DEVICE_STATUS, VTIO_S_ACK | VTIO_S_DRIVER);

    // 3. Feature negotiation: accept RING_PACKED=0, just want BLK basic.
    //    Select feature word 0, write back what device offers.
    mcfg_wl(cfg, VCFG_DEVICE_FEATURE_SELECT, 0);
    let feats0 = mcfg_rl(cfg, VCFG_DEVICE_FEATURE);
    mcfg_wl(cfg, VCFG_DRIVER_FEATURE_SELECT, 0);
    mcfg_wl(cfg, VCFG_DRIVER_FEATURE, feats0);
    // Word 1: accept VERSION_1 bit (bit 32 of full feature set = bit 0 of word 1).
    mcfg_wl(cfg, VCFG_DEVICE_FEATURE_SELECT, 1);
    let feats1 = mcfg_rl(cfg, VCFG_DEVICE_FEATURE);
    mcfg_wl(cfg, VCFG_DRIVER_FEATURE_SELECT, 1);
    mcfg_wl(cfg, VCFG_DRIVER_FEATURE, feats1 & 1); // only VERSION_1

    // 4. FEATURES_OK.
    mcfg_wb(cfg, VCFG_DEVICE_STATUS, VTIO_S_ACK | VTIO_S_DRIVER | VTIO_S_FEATURES_OK);
    let status = mcfg_rb(cfg, VCFG_DEVICE_STATUS);
    if status & VTIO_S_FEATURES_OK == 0 {
        mcfg_wb(cfg, VCFG_DEVICE_STATUS, VTIO_S_FAILED);
        crate::arch::x86_64::serial::serial_println!("virtio_blk: FEATURES_OK rejected");
        return;
    }

    // 5. Set up queue 0.
    let queue_va = match alloc_queue_pages() { Some(p) => p, None => return };

    mcfg_ww(cfg, VCFG_QUEUE_SELECT, 0);
    mcfg_ww(cfg, VCFG_QUEUE_SIZE, QUEUE_SIZE as u16);

    let desc_pa  = queue_va as u64;
    let avail_pa = (queue_va + AVAIL_OFF) as u64;
    let used_pa  = (queue_va + USED_OFF)  as u64;

    mcfg_wl(cfg, VCFG_QUEUE_DESC_LO,  (desc_pa  & 0xFFFF_FFFF) as u32);
    mcfg_wl(cfg, VCFG_QUEUE_DESC_HI,  (desc_pa  >> 32) as u32);
    mcfg_wl(cfg, VCFG_QUEUE_AVAIL_LO, (avail_pa & 0xFFFF_FFFF) as u32);
    mcfg_wl(cfg, VCFG_QUEUE_AVAIL_HI, (avail_pa >> 32) as u32);
    mcfg_wl(cfg, VCFG_QUEUE_USED_LO,  (used_pa  & 0xFFFF_FFFF) as u32);
    mcfg_wl(cfg, VCFG_QUEUE_USED_HI,  (used_pa  >> 32) as u32);
    mcfg_ww(cfg, VCFG_QUEUE_ENABLE, 1);

    // Get notify offset for queue 0 (used when kicking the queue).
    mcfg_ww(cfg, VCFG_QUEUE_SELECT, 0);
    let q_notify_off = mcfg_rw(cfg, VCFG_QUEUE_NOTIFY_OFF) as u32;
    let _notify_addr = notify_base + (q_notify_off * notify_off_mult) as usize;

    // 6. DRIVER_OK.
    mcfg_wb(cfg, VCFG_DEVICE_STATUS,
            VTIO_S_ACK | VTIO_S_DRIVER | VTIO_S_FEATURES_OK | VTIO_S_DRIVER_OK);

    // 7. Read capacity: device config starts at CommonCfg + 0x38 for blk.
    let cap_lo = mcfg_rl(cfg, 0x38);
    let cap_hi = mcfg_rl(cfg, 0x3C);
    let capacity = ((cap_hi as u64) << 32) | cap_lo as u64;

    crate::arch::x86_64::serial::serial_println!(
        "virtio_blk: modern init ok, {} sectors", capacity);

    *DEV.lock() = Some(BlkDev {
        transport: Transport::Modern { cfg_base: cfg, notify_base, notify_off_mult },
        queue_va, last_used: 0, capacity,
    });
    PRESENT.store(true, Ordering::Release);
}

fn alloc_queue_pages() -> Option<usize> {
    // Two pages: one for desc+avail, one for used ring (page-aligned).
    let p0 = crate::mm::pmm::alloc_page()?;
    let p1 = crate::mm::pmm::alloc_page()?;
    unsafe {
        core::ptr::write_bytes(p0 as *mut u8, 0, 4096);
        core::ptr::write_bytes(p1 as *mut u8, 0, 4096);
    }
    Some(p0)
}

// ── Request submission ───────────────────────────────────────────────────

#[repr(C, packed)]
struct BlkReqHdr {
    typ:    u32,
    _rsvd:  u32,
    sector: u64,
}

pub fn read_sectors(lba: u64, buf: &mut [u8]) -> Result<(), i32> {
    submit(VIRTIO_BLK_T_IN, lba, buf)
}

pub fn write_sectors(lba: u64, buf: &[u8]) -> Result<(), i32> {
    // SAFETY: device only reads this buffer; we never alias it.
    let buf_mut = unsafe {
        core::slice::from_raw_parts_mut(buf.as_ptr() as *mut u8, buf.len())
    };
    submit(VIRTIO_BLK_T_OUT, lba, buf_mut)
}

/// Total drive capacity in 512-byte sectors.
pub fn virtio_blk_capacity() -> Option<u64> {
    DEV.lock().as_ref().map(|d| d.capacity)
}

pub fn is_present() -> bool { PRESENT.load(Ordering::Acquire) }

fn submit(typ: u32, lba: u64, buf: &mut [u8]) -> Result<(), i32> {
    if buf.is_empty() || buf.len() % 512 != 0 { return Err(-22); } // EINVAL
    let mut guard = DEV.lock();
    let dev = guard.as_mut().ok_or(-6i32)?; // ENXIO

    let io_base = match &dev.transport {
        Transport::Legacy { io_base } => Some(*io_base),
        Transport::Modern { .. }      => None,
    };
    let (cfg_base, notify_base, notify_mult) = match &dev.transport {
        Transport::Modern { cfg_base, notify_base, notify_off_mult } =>
            (Some(*cfg_base), Some(*notify_base), *notify_off_mult),
        _ => (None, None, 4),
    };

    let qva = dev.queue_va;

    // Carve header + status byte from scratch space inside the queue page.
    const HDR_OFF:    usize = 0x800;
    const STATUS_OFF: usize = 0x810;
    let hdr_va    = qva + HDR_OFF;
    let status_va = qva + STATUS_OFF;

    unsafe {
        (hdr_va as *mut BlkReqHdr).write_volatile(BlkReqHdr {
            typ, _rsvd: 0, sector: lba,
        });
        (status_va as *mut u8).write_volatile(0xFF); // sentinel

        let desc = qva as *mut u8;

        // 3-descriptor chain: hdr → data → status.
        write_desc(desc, 0, hdr_va as u64,
                   core::mem::size_of::<BlkReqHdr>() as u32,
                   VRING_DESC_F_NEXT, 1);
        let data_flags = if typ == VIRTIO_BLK_T_IN {
            VRING_DESC_F_WRITE | VRING_DESC_F_NEXT
        } else {
            VRING_DESC_F_NEXT
        };
        write_desc(desc, 1, buf.as_ptr() as u64, buf.len() as u32, data_flags, 2);
        write_desc(desc, 2, status_va as u64, 1, VRING_DESC_F_WRITE, 0);

        // Post to avail ring.
        let avail = (qva + AVAIL_OFF) as *mut u16;
        avail.add(0).write_volatile(0);                              // flags=0
        let old_idx = avail.add(1).read_volatile();
        avail.add(2 + old_idx as usize % QUEUE_SIZE).write_volatile(0); // head=0
        core::sync::atomic::fence(Ordering::SeqCst);
        avail.add(1).write_volatile(old_idx.wrapping_add(1));
        core::sync::atomic::fence(Ordering::SeqCst);

        // Kick the queue.
        if let Some(b) = io_base {
            vio_writew(b, VTIO_QUEUE_NOTIFY, 0);
        } else {
            // Modern: write queue index (0) to notify address.
            let n_base  = notify_base.unwrap();
            let cfg     = cfg_base.unwrap();
            let q_noff  = mcfg_rw(cfg, VCFG_QUEUE_NOTIFY_OFF) as u32;
            let n_addr  = n_base + (q_noff * notify_mult) as usize;
            (n_addr as *mut u16).write_volatile(0);
        }

        // Poll used ring (timeout ~5 s).
        let used = (qva + USED_OFF) as *const u16;
        let target = dev.last_used.wrapping_add(1);
        let mut ok = false;
        for _ in 0..5_000_000usize {
            core::sync::atomic::fence(Ordering::Acquire);
            if used.add(1).read_volatile() == target {
                ok = true;
                break;
            }
            core::hint::spin_loop();
        }
        if !ok { return Err(-5); } // EIO — timeout
        dev.last_used = target;

        let status = (status_va as *const u8).read_volatile();
        if status != 0 { Err(-5) } else { Ok(()) }
    }
}

#[inline]
fn write_desc(base: *mut u8, idx: usize, addr: u64, len: u32, flags: u16, next: u16) {
    let p = unsafe { base.add(idx * DESC_SIZE) as *mut u64 };
    unsafe {
        p.write_volatile(addr);
        (p as *mut u32).add(2).write_volatile(len);
        (p as *mut u16).add(6).write_volatile(flags);
        (p as *mut u16).add(7).write_volatile(next);
    }
}

// ── IRQ handler ──────────────────────────────────────────────────────────

/// Call from your IRQ dispatcher when VIRTIO_BLK_IRQ_VECTOR fires.
/// Reads and clears the ISR register to acknowledge the interrupt.
pub fn virtio_blk_irq_handler() {
    let guard = DEV.lock();
    let dev = match guard.as_ref() { Some(d) => d, None => return };
    // For legacy: read ISR to ACK.  For modern: ISR cap is at cfg+0x60 (typical).
    match &dev.transport {
        Transport::Legacy { io_base } => {
            let _isr = unsafe { vio_readb(*io_base, VTIO_ISR_STATUS) };
        }
        Transport::Modern { cfg_base, .. } => {
            // ISR Status capability MMIO — offset 0x60 in QEMU virtio-pci layout.
            let isr_addr = cfg_base + 0x60;
            let _isr = unsafe { (isr_addr as *const u8).read_volatile() };
        }
    }
    // Polled driver: used-ring advancement happens in submit(); no wakeup needed yet.
}

// ── Legacy I/O port helpers ───────────────────────────────────────────────

#[inline] unsafe fn vio_readb(b: u16, o: u16) -> u8 {
    let mut v: u8;
    core::arch::asm!("in al, dx", in("dx") b+o, out("al") v, options(nostack)); v
}
#[inline] unsafe fn vio_readw(b: u16, o: u16) -> u16 {
    let mut v: u16;
    core::arch::asm!("in ax, dx", in("dx") b+o, out("ax") v, options(nostack)); v
}
#[inline] unsafe fn vio_readl(b: u16, o: u16) -> u32 {
    let mut v: u32;
    core::arch::asm!("in eax, dx", in("dx") b+o, out("eax") v, options(nostack)); v
}
#[inline] unsafe fn vio_writeb(b: u16, o: u16, v: u8) {
    core::arch::asm!("out dx, al",  in("dx") b+o, in("al")  v, options(nostack));
}
#[inline] unsafe fn vio_writew(b: u16, o: u16, v: u16) {
    core::arch::asm!("out dx, ax",  in("dx") b+o, in("ax")  v, options(nostack));
}
#[inline] unsafe fn vio_writel(b: u16, o: u16, v: u32) {
    core::arch::asm!("out dx, eax", in("dx") b+o, in("eax") v, options(nostack));
}

// ── Modern MMIO helpers (CommonCfg reads/writes) ──────────────────────────

#[inline] unsafe fn mcfg_rb(base: usize, off: usize) -> u8 {
    core::ptr::read_volatile((base + off) as *const u8)
}
#[inline] unsafe fn mcfg_rw(base: usize, off: usize) -> u16 {
    core::ptr::read_volatile((base + off) as *const u16)
}
#[inline] unsafe fn mcfg_rl(base: usize, off: usize) -> u32 {
    core::ptr::read_volatile((base + off) as *const u32)
}
#[inline] unsafe fn mcfg_wb(base: usize, off: usize, v: u8) {
    core::ptr::write_volatile((base + off) as *mut u8, v)
}
#[inline] unsafe fn mcfg_ww(base: usize, off: usize, v: u16) {
    core::ptr::write_volatile((base + off) as *mut u16, v)
}
#[inline] unsafe fn mcfg_wl(base: usize, off: usize, v: u32) {
    core::ptr::write_volatile((base + off) as *mut u32, v)
}
