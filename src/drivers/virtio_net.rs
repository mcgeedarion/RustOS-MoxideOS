//! virtio-net driver — PCI transport, legacy + modern (1.0).
//!
//! ## Spec references
//!   - VirtIO 1.2 spec §§ 2, 4.1, 5.1
//!   - VirtIO legacy (0.9.5) PCI transport
//!
//! ## Transport detection
//!   0x1000 (legacy/transitional) → BAR0 = I/O port base
//!   0x1041 (modern)              → BAR1 = CommonCfg MMIO, BAR2 = notify
//!
//! ## Virtqueues
//!   Queue 0: RX  — driver posts write-only buffers; device fills them.
//!   Queue 1: TX  — driver posts read-only frames; device drains them.
//!   Both queues use split-ring format, QUEUE_SIZE=256 descriptors.
//!
//! ## Public API
//!   virtio_net_probe()         — PCIe discovery + full init
//!   virtio_net_init()          — legacy compat alias
//!   send_frame(frame: &[u8])   — transmit one Ethernet frame
//!   rx_poll()                  — drain received frames into net stack
//!   mac_address() -> [u8;6]
//!   virtio_net_irq()           — call from IRQ dispatcher (RX vector)
//!   virtio_net_tx_irq()        — call from IRQ dispatcher (TX vector)
//!   VIRTIO_NET_RX_VECTOR / VIRTIO_NET_TX_VECTOR

use crate::drivers::pcie::{
    find_device_by_id, pci_enable_msix, pci_enable_msi_ex,
};
use crate::drivers::nic::{register_nic, NicDevice};
use crate::mm::pmm;
use core::sync::atomic::{fence, Ordering};
use spin::Mutex;

// ── IRQ vectors ───────────────────────────────────────────────────────────

/// MSI-X entry 0 — RX completions.
pub const VIRTIO_NET_RX_VECTOR: u8 = 0x2E;
/// MSI-X entry 1 — TX completions.
pub const VIRTIO_NET_TX_VECTOR: u8 = 0x2F;

// ── PCI IDs ───────────────────────────────────────────────────────────────

const VENDOR_VIRTIO: u16 = 0x1AF4;
const DEV_NET_LEGACY: u16 = 0x1000;
const DEV_NET_MODERN: u16 = 0x1041;

// ── Legacy I/O register offsets (BAR0) ────────────────────────────────────

const VIRT_DEVICE_FEATURES: u16 = 0x00;
const VIRT_DRIVER_FEATURES: u16 = 0x04;
const VIRT_QUEUE_ADDRESS:   u16 = 0x08;
const VIRT_QUEUE_SIZE:      u16 = 0x0C;
const VIRT_QUEUE_SELECT:    u16 = 0x0E;
const VIRT_QUEUE_NOTIFY:    u16 = 0x10;
const VIRT_DEVICE_STATUS:   u16 = 0x12;
const VIRT_ISR_STATUS:      u16 = 0x13;
const VIRT_NET_MAC_BASE:    u16 = 0x14;

// ── Modern CommonCfg MMIO offsets (BAR1) ────────────────────────────────

const VCFG_DEVICE_FEATURE_SELECT: usize = 0x00;
const VCFG_DEVICE_FEATURE:        usize = 0x04;
const VCFG_DRIVER_FEATURE_SELECT: usize = 0x08;
const VCFG_DRIVER_FEATURE:        usize = 0x0C;
const VCFG_DEVICE_STATUS:         usize = 0x14;
const VCFG_QUEUE_SELECT:          usize = 0x16;
const VCFG_QUEUE_SIZE:            usize = 0x18;
const VCFG_QUEUE_ENABLE:          usize = 0x1C;
const VCFG_QUEUE_NOTIFY_OFF:      usize = 0x1E;
const VCFG_QUEUE_DESC_LO:         usize = 0x20;
const VCFG_QUEUE_DESC_HI:         usize = 0x24;
const VCFG_QUEUE_AVAIL_LO:        usize = 0x28;
const VCFG_QUEUE_AVAIL_HI:        usize = 0x2C;
const VCFG_QUEUE_USED_LO:         usize = 0x30;
const VCFG_QUEUE_USED_HI:         usize = 0x34;
const VCFG_NET_MAC:               usize = 0x38;

const STATUS_ACK:         u8 = 0x01;
const STATUS_DRIVER:      u8 = 0x02;
const STATUS_DRIVER_OK:   u8 = 0x04;
const STATUS_FEATURES_OK: u8 = 0x08;
const STATUS_FAILED:      u8 = 0x80;

const FEAT_CSUM: u32 = 1 << 0;
const FEAT_MAC:  u32 = 1 << 5;

const VRING_DESC_F_NEXT:  u16 = 1;
const VRING_DESC_F_WRITE: u16 = 2;

const QUEUE_SIZE:     usize = 256;
const NET_HEADER_LEN: usize = 12;
const RX_BUF_SIZE:    usize = 4096;

// ── Transport ────────────────────────────────────────────────────────────

enum Transport {
    Legacy { io_base: u16 },
    Modern { cfg_base: usize, notify_base: usize, notify_off_mult: u32 },
}

// ── Split virtqueue ──────────────────────────────────────────────────────

#[repr(C)]
struct VirtDesc {
    addr:  u64,
    len:   u32,
    flags: u16,
    next:  u16,
}

#[repr(C)]
struct VirtAvail {
    flags:      u16,
    idx:        u16,
    ring:       [u16; QUEUE_SIZE],
    used_event: u16,
}

#[repr(C)]
struct VirtUsedElem {
    id:  u32,
    len: u32,
}

#[repr(C)]
struct VirtUsed {
    flags:       u16,
    idx:         u16,
    ring:        [VirtUsedElem; QUEUE_SIZE],
    avail_event: u16,
}

/// Per-TX-descriptor metadata so we can free the right pages.
///
/// `base_pa` is the first page of the bounce buffer; `pages` is how many
/// contiguous pages were allocated (= ceil((NET_HEADER_LEN + frame_len) / 4096)).
#[derive(Clone, Copy, Default)]
struct TxMeta {
    base_pa: usize,
    pages:   usize,
}

struct Virtqueue {
    desc:      *mut VirtDesc,
    avail:     *mut VirtAvail,
    used:      *mut VirtUsed,
    free_head: usize,
    last_used: u16,
    bufs:      [*mut u8; QUEUE_SIZE],
    /// TX metadata — only meaningful for the TX queue (rxq leaves this zeroed).
    tx_meta:   [TxMeta; QUEUE_SIZE],
}

unsafe impl Send for Virtqueue {}
unsafe impl Sync for Virtqueue {}

impl Virtqueue {
    const fn zeroed() -> Self {
        Self {
            desc:      core::ptr::null_mut(),
            avail:     core::ptr::null_mut(),
            used:      core::ptr::null_mut(),
            free_head: 0,
            last_used: 0,
            bufs:      [core::ptr::null_mut(); QUEUE_SIZE],
            tx_meta:   [TxMeta { base_pa: 0, pages: 0 }; QUEUE_SIZE],
        }
    }

    unsafe fn alloc(&mut self) -> (u64, u64, u64) {
        let desc_bytes  = core::mem::size_of::<VirtDesc>() * QUEUE_SIZE;
        let avail_bytes = 6 + QUEUE_SIZE * 2;
        let _used_bytes = 6 + QUEUE_SIZE * 8;

        let pages_da = (desc_bytes + avail_bytes + 4095) / 4096;
        let desc_pa  = alloc_pages(pages_da);
        self.desc  = desc_pa as *mut VirtDesc;
        self.avail = (desc_pa + desc_bytes) as *mut VirtAvail;

        let used_pa = alloc_pages(1);
        self.used   = used_pa as *mut VirtUsed;

        for i in 0..QUEUE_SIZE - 1 {
            (*self.desc.add(i)).next = (i + 1) as u16;
        }
        self.free_head = 0;

        (desc_pa as u64, (desc_pa + desc_bytes) as u64, used_pa as u64)
    }

    unsafe fn add_rx_buf(&mut self, buf: *mut u8, len: u32) {
        let idx = self.alloc_desc();
        let d = &mut *self.desc.add(idx);
        d.addr  = buf as u64;
        d.len   = len;
        d.flags = VRING_DESC_F_WRITE;
        d.next  = 0;
        self.bufs[idx] = buf;
        self.push_avail(idx);
    }

    /// Post a TX buffer.  `base_pa` and `pages` record the allocation so
    /// drain_used can free it back to the PMM.
    unsafe fn add_tx_buf(&mut self, buf: *const u8, len: u32, base_pa: usize, pages: usize) {
        let idx = self.alloc_desc();
        let d = &mut *self.desc.add(idx);
        d.addr  = buf as u64;
        d.len   = len;
        d.flags = 0;
        d.next  = 0;
        self.bufs[idx]    = buf as *mut u8;
        self.tx_meta[idx] = TxMeta { base_pa, pages };
        self.push_avail(idx);
    }

    unsafe fn drain_used(&mut self, mut f: impl FnMut(*mut u8, u32, TxMeta)) -> bool {
        fence(Ordering::Acquire);
        let mut drained = false;
        while self.last_used != (*self.used).idx {
            let slot = self.last_used as usize & (QUEUE_SIZE - 1);
            let elem = (*self.used).ring[slot];
            let meta = self.tx_meta[elem.id as usize];
            f(self.bufs[elem.id as usize], elem.len, meta);
            self.free_desc(elem.id as usize);
            self.last_used = self.last_used.wrapping_add(1);
            drained = true;
        }
        drained
    }

    #[inline]
    unsafe fn alloc_desc(&mut self) -> usize {
        let idx = self.free_head;
        self.free_head = (*self.desc.add(idx)).next as usize;
        idx
    }

    #[inline]
    unsafe fn free_desc(&mut self, idx: usize) {
        (*self.desc.add(idx)).next = self.free_head as u16;
        self.free_head = idx;
    }

    #[inline]
    unsafe fn push_avail(&mut self, idx: usize) {
        let avail = &mut *self.avail;
        let slot  = avail.idx as usize & (QUEUE_SIZE - 1);
        avail.ring[slot] = idx as u16;
        fence(Ordering::Release);
        avail.idx = avail.idx.wrapping_add(1);
    }
}

fn alloc_pages(n: usize) -> usize {
    let first = pmm::alloc_page().expect("virtio_net: out of memory");
    for _ in 1..n { pmm::alloc_page().expect("virtio_net: out of memory"); }
    unsafe { core::ptr::write_bytes(first as *mut u8, 0, n * 4096); }
    first
}

// ── Device state ─────────────────────────────────────────────────────────

struct VirtioNetDev {
    transport: Transport,
    mac:       [u8; 6],
    rxq:       Virtqueue,
    txq:       Virtqueue,
}

unsafe impl Send for VirtioNetDev {}
unsafe impl Sync for VirtioNetDev {}

static DEV: Mutex<Option<VirtioNetDev>> = Mutex::new(None);

// ── PCIe discovery ────────────────────────────────────────────────────────

pub fn virtio_net_probe() -> bool {
    let (dev, modern) =
        if let Some(d) = find_device_by_id(VENDOR_VIRTIO, DEV_NET_MODERN) {
            (d, true)
        } else if let Some(d) = find_device_by_id(VENDOR_VIRTIO, DEV_NET_LEGACY) {
            (d, false)
        } else {
            crate::arch::x86_64::serial::serial_println!("virtio_net: no device found");
            return false;
        };

    dev.enable();

    let msix_ok = pci_enable_msix(&dev, 0, VIRTIO_NET_RX_VECTOR, 0)
               && pci_enable_msix(&dev, 1, VIRTIO_NET_TX_VECTOR, 0);
    if msix_ok {
        crate::arch::x86_64::serial::serial_println!("virtio_net: MSI-X RX+TX");
    } else if pci_enable_msi_ex(&dev, 0, VIRTIO_NET_RX_VECTOR) {
        crate::arch::x86_64::serial::serial_println!("virtio_net: MSI (shared)");
    } else {
        crate::arch::x86_64::serial::serial_println!("virtio_net: polled");
    }

    if modern {
        let cfg_base = match dev.bar_mmio(1) {
            Some(b) => b as usize,
            None    => { crate::arch::x86_64::serial::serial_println!("virtio_net: BAR1 missing"); return false; }
        };
        let notify_base     = dev.bar_mmio(2).unwrap_or(cfg_base as u64 + 0x1000) as usize;
        let notify_off_mult = 4u32;
        unsafe { init_modern(cfg_base, notify_base, notify_off_mult) }
    } else {
        let io_base = match dev.bar_io(0) {
            Some(b) => b as u16,
            None    => { crate::arch::x86_64::serial::serial_println!("virtio_net: BAR0 I/O missing"); return false; }
        };
        unsafe { init_legacy(io_base) }
    }
    true
}

pub fn virtio_net_init() { virtio_net_probe(); }

// ── Legacy init ───────────────────────────────────────────────────────────

unsafe fn init_legacy(io: u16) {
    io_writeb(io, VIRT_DEVICE_STATUS, 0);
    io_writeb(io, VIRT_DEVICE_STATUS, STATUS_ACK | STATUS_DRIVER);

    let dev_feats = io_readl(io, VIRT_DEVICE_FEATURES);
    let drv_feats = dev_feats & (FEAT_MAC | FEAT_CSUM);
    io_writel(io, VIRT_DRIVER_FEATURES, drv_feats);

    let s = io_readb(io, VIRT_DEVICE_STATUS) | STATUS_FEATURES_OK;
    io_writeb(io, VIRT_DEVICE_STATUS, s);
    if io_readb(io, VIRT_DEVICE_STATUS) & STATUS_FEATURES_OK == 0 {
        io_writeb(io, VIRT_DEVICE_STATUS, STATUS_FAILED);
        crate::arch::x86_64::serial::serial_println!("virtio_net: legacy FEATURES_OK rejected");
        return;
    }

    let mut mac = [0u8; 6];
    for i in 0..6u16 { mac[i as usize] = io_readb(io, VIRT_NET_MAC_BASE + i); }

    let (rxq, txq) = setup_queues_legacy(io);
    io_writeb(io, VIRT_DEVICE_STATUS,
              STATUS_ACK | STATUS_DRIVER | STATUS_FEATURES_OK | STATUS_DRIVER_OK);

    log_mac("legacy", &mac);
    finalize(Transport::Legacy { io_base: io }, mac, rxq, txq);
}

unsafe fn setup_queues_legacy(io: u16) -> (Virtqueue, Virtqueue) {
    io_writew(io, VIRT_QUEUE_SELECT, 0);
    let mut rxq = Virtqueue::zeroed();
    let (desc_pa, _, _) = rxq.alloc();
    io_writel(io, VIRT_QUEUE_ADDRESS, (desc_pa >> 12) as u32);
    prefill_rx(&mut rxq);

    io_writew(io, VIRT_QUEUE_SELECT, 1);
    let mut txq = Virtqueue::zeroed();
    let (desc_pa, _, _) = txq.alloc();
    io_writel(io, VIRT_QUEUE_ADDRESS, (desc_pa >> 12) as u32);

    (rxq, txq)
}

// ── Modern init ───────────────────────────────────────────────────────────

unsafe fn init_modern(cfg: usize, notify_base: usize, notify_mult: u32) {
    mcfg_wb(cfg, VCFG_DEVICE_STATUS, 0);
    mcfg_wb(cfg, VCFG_DEVICE_STATUS, STATUS_ACK);
    mcfg_wb(cfg, VCFG_DEVICE_STATUS, STATUS_ACK | STATUS_DRIVER);

    mcfg_wl(cfg, VCFG_DEVICE_FEATURE_SELECT, 0);
    let f0 = mcfg_rl(cfg, VCFG_DEVICE_FEATURE) & (FEAT_MAC | FEAT_CSUM);
    mcfg_wl(cfg, VCFG_DRIVER_FEATURE_SELECT, 0);
    mcfg_wl(cfg, VCFG_DRIVER_FEATURE, f0);
    mcfg_wl(cfg, VCFG_DEVICE_FEATURE_SELECT, 1);
    let f1 = mcfg_rl(cfg, VCFG_DEVICE_FEATURE);
    mcfg_wl(cfg, VCFG_DRIVER_FEATURE_SELECT, 1);
    mcfg_wl(cfg, VCFG_DRIVER_FEATURE, f1 & 1);

    mcfg_wb(cfg, VCFG_DEVICE_STATUS,
            STATUS_ACK | STATUS_DRIVER | STATUS_FEATURES_OK);
    if mcfg_rb(cfg, VCFG_DEVICE_STATUS) & STATUS_FEATURES_OK == 0 {
        mcfg_wb(cfg, VCFG_DEVICE_STATUS, STATUS_FAILED);
        crate::arch::x86_64::serial::serial_println!("virtio_net: modern FEATURES_OK rejected");
        return;
    }

    let mut mac = [0u8; 6];
    for i in 0..6 { mac[i] = mcfg_rb(cfg, VCFG_NET_MAC + i); }

    let (rxq, txq) = setup_queues_modern(cfg, notify_base, notify_mult);
    mcfg_wb(cfg, VCFG_DEVICE_STATUS,
            STATUS_ACK | STATUS_DRIVER | STATUS_FEATURES_OK | STATUS_DRIVER_OK);

    log_mac("modern", &mac);
    finalize(Transport::Modern { cfg_base: cfg, notify_base, notify_off_mult: notify_mult },
             mac, rxq, txq);
}

unsafe fn setup_queues_modern(
    cfg: usize, notify_base: usize, notify_mult: u32,
) -> (Virtqueue, Virtqueue) {
    let mut queues = [Virtqueue::zeroed(), Virtqueue::zeroed()];
    for (qi, q) in queues.iter_mut().enumerate() {
        mcfg_ww(cfg, VCFG_QUEUE_SELECT, qi as u16);
        mcfg_ww(cfg, VCFG_QUEUE_SIZE, QUEUE_SIZE as u16);
        let (desc_pa, avail_pa, used_pa) = q.alloc();
        mcfg_wl(cfg, VCFG_QUEUE_DESC_LO,  (desc_pa  & 0xFFFF_FFFF) as u32);
        mcfg_wl(cfg, VCFG_QUEUE_DESC_HI,  (desc_pa  >> 32) as u32);
        mcfg_wl(cfg, VCFG_QUEUE_AVAIL_LO, (avail_pa & 0xFFFF_FFFF) as u32);
        mcfg_wl(cfg, VCFG_QUEUE_AVAIL_HI, (avail_pa >> 32) as u32);
        mcfg_wl(cfg, VCFG_QUEUE_USED_LO,  (used_pa  & 0xFFFF_FFFF) as u32);
        mcfg_wl(cfg, VCFG_QUEUE_USED_HI,  (used_pa  >> 32) as u32);
        mcfg_ww(cfg, VCFG_QUEUE_ENABLE, 1);
    }
    prefill_rx(&mut queues[0]);
    mcfg_ww(cfg, VCFG_QUEUE_SELECT, 0);
    let q_noff = mcfg_rw(cfg, VCFG_QUEUE_NOTIFY_OFF) as u32;
    let n_addr = notify_base + (q_noff * notify_mult) as usize;
    (n_addr as *mut u16).write_volatile(0);
    let [rxq, txq] = queues;
    (rxq, txq)
}

unsafe fn prefill_rx(rxq: &mut Virtqueue) {
    for _ in 0..QUEUE_SIZE / 2 {
        let buf = pmm::alloc_page().expect("virtio_net: rx buf") as *mut u8;
        core::ptr::write_bytes(buf, 0, 4096);
        rxq.add_rx_buf(buf, RX_BUF_SIZE as u32);
    }
}

fn log_mac(kind: &str, mac: &[u8; 6]) {
    crate::arch::x86_64::serial::serial_println!(
        "virtio_net: {} MAC {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        kind, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    );
}

fn finalize(transport: Transport, mac: [u8; 6], rxq: Virtqueue, txq: Virtqueue) {
    crate::net::eth::set_mac(mac);
    *DEV.lock() = Some(VirtioNetDev { transport, mac, rxq, txq });
    register_nic(NicDevice {
        send_frame: |frame| send_frame(frame),
        rx_poll:    rx_poll,
        mac,
    });
    crate::arch::x86_64::serial::serial_println!("virtio_net: device ready");
}

// ── TX ────────────────────────────────────────────────────────────────────

/// Send one Ethernet frame.
///
/// Allocates a PMM bounce buffer (header + frame), hands it to the TX
/// virtqueue, and records `(base_pa, pages)` in `tx_meta` so `drain_tx`
/// can return the pages to the PMM once the device signals completion.
pub fn send_frame(frame: &[u8]) -> bool {
    let mut guard = DEV.lock();
    let Some(dev) = guard.as_mut() else { return false; };

    let total  = NET_HEADER_LEN + frame.len();
    let pages  = (total + 4095) / 4096;
    let base_pa = alloc_pages(pages);
    let buf     = base_pa as *mut u8;
    unsafe {
        // header already zeroed by alloc_pages
        core::ptr::copy_nonoverlapping(frame.as_ptr(), buf.add(NET_HEADER_LEN), frame.len());
        dev.txq.add_tx_buf(buf, total as u32, base_pa, pages);
        notify(&dev.transport, 1);
    }
    true
}

// ── RX ────────────────────────────────────────────────────────────────────

pub fn rx_poll() {
    let mut guard = DEV.lock();
    let Some(dev) = guard.as_mut() else { return; };
    unsafe {
        let transport = &dev.transport as *const Transport;
        dev.rxq.drain_used(|buf, len, _meta| {
            if len as usize > NET_HEADER_LEN {
                let frame = core::slice::from_raw_parts(
                    buf.add(NET_HEADER_LEN),
                    len as usize - NET_HEADER_LEN,
                );
                crate::net::eth::receive_frame(frame);
            }
            core::ptr::write_bytes(buf, 0, RX_BUF_SIZE);
            dev.rxq.add_rx_buf(buf, RX_BUF_SIZE as u32);
        });
        notify(&*transport, 0);
    }
}

/// Drain the TX used ring and return bounce buffers to the PMM.
///
/// Previously a no-op because pmm::free_page() did not exist.  Now that
/// the PMM has a full Treiber-stack free list, we free every page of each
/// completed TX bounce buffer here, eliminating the TX memory leak.
pub fn drain_tx() {
    let mut guard = DEV.lock();
    let Some(dev) = guard.as_mut() else { return; };
    unsafe {
        dev.txq.drain_used(|_buf, _len, meta| {
            if meta.base_pa != 0 && meta.pages != 0 {
                pmm::free_pages_contig(meta.base_pa, meta.pages);
            }
        });
    }
}

// ── IRQ handlers ──────────────────────────────────────────────────────────

pub fn virtio_net_irq() {
    ack_isr();
    rx_poll();
}

pub fn virtio_net_tx_irq() {
    ack_isr();
    drain_tx();
}

fn ack_isr() {
    let guard = DEV.lock();
    let Some(dev) = guard.as_ref() else { return; };
    match &dev.transport {
        Transport::Legacy { io_base } => unsafe {
            let _ = io_readb(*io_base, VIRT_ISR_STATUS);
        },
        Transport::Modern { cfg_base, .. } => unsafe {
            let _ = core::ptr::read_volatile((cfg_base + 0x60) as *const u8);
        },
    }
}

// ── Queue notify ──────────────────────────────────────────────────────────

unsafe fn notify(t: &Transport, queue_idx: u16) {
    match t {
        Transport::Legacy { io_base } =>
            io_writew(*io_base, VIRT_QUEUE_NOTIFY, queue_idx),
        Transport::Modern { cfg_base, notify_base, notify_off_mult } => {
            mcfg_ww(*cfg_base, VCFG_QUEUE_SELECT, queue_idx);
            let q_noff = mcfg_rw(*cfg_base, VCFG_QUEUE_NOTIFY_OFF) as u32;
            let n_addr = notify_base + (q_noff * notify_off_mult) as usize;
            (n_addr as *mut u16).write_volatile(queue_idx);
        }
    }
}

// ── Public accessors ──────────────────────────────────────────────────────

pub fn mac_address() -> [u8; 6] {
    DEV.lock().as_ref().map(|d| d.mac).unwrap_or([0u8; 6])
}

pub fn is_present() -> bool {
    DEV.lock().is_some()
}

// ── I/O port helpers (legacy path, x86_64 only) ───────────────────────────

#[cfg(target_arch = "x86_64")]
unsafe fn io_readb(b: u16, o: u16) -> u8 {
    let v: u8;
    core::arch::asm!("in al, dx", out("al") v, in("dx") b+o, options(nomem, nostack)); v
}
#[cfg(target_arch = "x86_64")]
unsafe fn io_writeb(b: u16, o: u16, v: u8) {
    core::arch::asm!("out dx, al", in("dx") b+o, in("al") v, options(nomem, nostack));
}
#[cfg(target_arch = "x86_64")]
unsafe fn io_readw(b: u16, o: u16) -> u16 {
    let v: u16;
    core::arch::asm!("in ax, dx", out("ax") v, in("dx") b+o, options(nomem, nostack)); v
}
#[cfg(target_arch = "x86_64")]
unsafe fn io_writew(b: u16, o: u16, v: u16) {
    core::arch::asm!("out dx, ax", in("dx") b+o, in("ax") v, options(nomem, nostack));
}
#[cfg(target_arch = "x86_64")]
unsafe fn io_readl(b: u16, o: u16) -> u32 {
    let v: u32;
    core::arch::asm!("in eax, dx", out("eax") v, in("dx") b+o, options(nomem, nostack)); v
}
#[cfg(target_arch = "x86_64")]
unsafe fn io_writel(b: u16, o: u16, v: u32) {
    core::arch::asm!("out dx, eax", in("dx") b+o, in("eax") v, options(nomem, nostack));
}

#[cfg(not(target_arch = "x86_64"))]
unsafe fn io_readb(_: u16, _: u16) -> u8   { 0 }
#[cfg(not(target_arch = "x86_64"))]
unsafe fn io_writeb(_: u16, _: u16, _: u8) {}
#[cfg(not(target_arch = "x86_64"))]
unsafe fn io_readw(_: u16, _: u16) -> u16   { 0 }
#[cfg(not(target_arch = "x86_64"))]
unsafe fn io_writew(_: u16, _: u16, _: u16) {}
#[cfg(not(target_arch = "x86_64"))]
unsafe fn io_readl(_: u16, _: u16) -> u32   { 0 }
#[cfg(not(target_arch = "x86_64"))]
unsafe fn io_writel(_: u16, _: u16, _: u32) {}

// ── Modern MMIO helpers ───────────────────────────────────────────────────

#[inline] unsafe fn mcfg_rb(b: usize, o: usize) -> u8  { core::ptr::read_volatile((b+o) as *const u8)  }
#[inline] unsafe fn mcfg_rw(b: usize, o: usize) -> u16 { core::ptr::read_volatile((b+o) as *const u16) }
#[inline] unsafe fn mcfg_rl(b: usize, o: usize) -> u32 { core::ptr::read_volatile((b+o) as *const u32) }
#[inline] unsafe fn mcfg_wb(b: usize, o: usize, v: u8)  { core::ptr::write_volatile((b+o) as *mut u8,  v) }
#[inline] unsafe fn mcfg_ww(b: usize, o: usize, v: u16) { core::ptr::write_volatile((b+o) as *mut u16, v) }
#[inline] unsafe fn mcfg_wl(b: usize, o: usize, v: u32) { core::ptr::write_volatile((b+o) as *mut u32, v) }
