//! VirtIO-net driver — MMIO transport (RISC-V `virt` machine).
//!
//! ## Spec references
//!   VirtIO 1.2 §§ 2, 4.2, 5.1
//!   QEMU `virt` machine DTB: /virtio_mmio@<base> nodes, each 0x200 bytes apart.
//!
//! ## How the device is found
//!   The FDT walker in `src/arch/riscv64/fdt.rs` scans every `virtio_mmio`
//!   node.  For each one whose MagicValue / Version / DeviceID registers
//!   identify a virtio-net device it calls `probe(base, irq)`.
//!
//! ## MMIO register map (offsets from BAR base, 4-byte aligned reads)
//!   0x000  MagicValue       must be 0x74726976 ("virt")
//!   0x004  Version          1 = legacy, 2 = modern
//!   0x008  DeviceID         1 = net
//!   0x00C  VendorID
//!   0x010  DeviceFeatures
//!   0x014  DeviceFeaturesSel
//!   0x020  DriverFeatures
//!   0x024  DriverFeaturesSel
//!   0x030  QueueSel
//!   0x034  QueueNumMax
//!   0x038  QueueNum
//!   0x044  QueueReady       (modern only)
//!   0x050  QueueNotify
//!   0x060  InterruptStatus
//!   0x064  InterruptACK
//!   0x070  Status
//!   0x080  QueueDescLow/Hi, AvailLow/Hi, UsedLow/Hi  (modern)
//!   0x100  Config space     MAC at bytes 0..6
//!
//! ## Virtqueues
//!   Queue 0: RX  — driver posts write-only 4 KiB buffers.
//!   Queue 1: TX  — driver posts read-only frames.
//!   Split-ring, QUEUE_SIZE = 256.
//!
//! ## PLIC wiring
//!   After `probe()` succeeds, `kernel_main` calls `enable_plic_irq()` which
//!   registers `virtio_net_mmio_irq` as the PLIC handler for the IRQ number
//!   stored by probe.  From that point on RX is interrupt-driven instead of
//!   polled.
//!
//! ## Public API
//!   probe(base, irq)          — called from FDT walker
//!   enable_plic_irq()         — called from kernel_main after plic::init()
//!   send_frame(frame: &[u8])  — transmit one Ethernet frame
//!   rx_poll()                 — drain RX ring into net stack (polled fallback)
//!   mac_address() -> [u8;6]
//!   virtio_net_mmio_irq()     — PLIC interrupt handler

use crate::drivers::nic::{register_nic, NicDevice};
use crate::mm::pmm;
use core::sync::atomic::{fence, Ordering};
use spin::Mutex;

// ── MMIO register offsets ──────────────────────────────────────────────────────

const REG_MAGIC:             usize = 0x000;
const REG_VERSION:           usize = 0x004;
const REG_DEVICE_ID:         usize = 0x008;
const REG_VENDOR_ID:         usize = 0x00C;
const REG_DEVICE_FEATURES:   usize = 0x010;
const REG_DEVICE_FEAT_SEL:   usize = 0x014;
const REG_DRIVER_FEATURES:   usize = 0x020;
const REG_DRIVER_FEAT_SEL:   usize = 0x024;
const REG_QUEUE_SEL:         usize = 0x030;
const REG_QUEUE_NUM_MAX:     usize = 0x034;
const REG_QUEUE_NUM:         usize = 0x038;
const REG_QUEUE_READY:       usize = 0x044;
const REG_QUEUE_NOTIFY:      usize = 0x050;
const REG_INTERRUPT_STATUS:  usize = 0x060;
const REG_INTERRUPT_ACK:     usize = 0x064;
const REG_STATUS:            usize = 0x070;
const REG_QUEUE_DESC_LO:     usize = 0x080;
const REG_QUEUE_DESC_HI:     usize = 0x084;
const REG_QUEUE_AVAIL_LO:    usize = 0x090;
const REG_QUEUE_AVAIL_HI:    usize = 0x094;
const REG_QUEUE_USED_LO:     usize = 0x0A0;
const REG_QUEUE_USED_HI:     usize = 0x0A4;
const REG_CONFIG_MAC:        usize = 0x100;

const MMIO_MAGIC: u32   = 0x7472_6976;
const DEV_ID_NET: u32   = 1;

const STATUS_ACK:         u32 = 0x01;
const STATUS_DRIVER:      u32 = 0x02;
const STATUS_DRIVER_OK:   u32 = 0x04;
const STATUS_FEATURES_OK: u32 = 0x08;
const STATUS_FAILED:      u32 = 0x80;

const FEAT_MAC:       u32 = 1 << 5;
const FEAT_CSUM:      u32 = 1 << 0;
const FEAT_VERSION_1: u32 = 1 << 0;

const VRING_DESC_F_WRITE: u16 = 2;

const QUEUE_SIZE:    usize = 256;
const NET_HDR_LEN:   usize = 12;
const RX_BUF_SIZE:   usize = 4096;

// ── MMIO accessors ────────────────────────────────────────────────────────────────

#[inline] unsafe fn mmio_r32(base: usize, off: usize) -> u32 {
    core::ptr::read_volatile((base + off) as *const u32)
}
#[inline] unsafe fn mmio_w32(base: usize, off: usize, val: u32) {
    core::ptr::write_volatile((base + off) as *mut u32, val);
}
#[inline] unsafe fn mmio_rb(base: usize, off: usize) -> u8 {
    core::ptr::read_volatile((base + off) as *const u8)
}

// ── Split virtqueue ───────────────────────────────────────────────────────────────────

#[repr(C)] struct VirtDesc  { addr: u64, len: u32, flags: u16, next: u16 }
#[repr(C)] struct VirtAvail { flags: u16, idx: u16, ring: [u16; QUEUE_SIZE], used_event: u16 }
#[repr(C)] struct VirtUsedElem { id: u32, len: u32 }
#[repr(C)] struct VirtUsed  { flags: u16, idx: u16, ring: [VirtUsedElem; QUEUE_SIZE], avail_event: u16 }

#[derive(Clone, Copy, Default)]
struct TxMeta { base_pa: usize, pages: usize }

struct Virtqueue {
    desc:      *mut VirtDesc,
    avail:     *mut VirtAvail,
    used:      *mut VirtUsed,
    free_head: usize,
    last_used: u16,
    bufs:      [*mut u8;  QUEUE_SIZE],
    tx_meta:   [TxMeta;   QUEUE_SIZE],
    desc_pa:   usize,
    avail_pa:  usize,
    used_pa:   usize,
}
unsafe impl Send for Virtqueue {}
unsafe impl Sync for Virtqueue {}

fn alloc_pages(n: usize) -> usize {
    let first = pmm::alloc_page().expect("virtio_net_mmio: OOM");
    for _ in 1..n { pmm::alloc_page().expect("virtio_net_mmio: OOM"); }
    unsafe { core::ptr::write_bytes(first as *mut u8, 0, n * 4096); }
    first
}

impl Virtqueue {
    const fn zeroed() -> Self {
        Self {
            desc: core::ptr::null_mut(), avail: core::ptr::null_mut(),
            used: core::ptr::null_mut(), free_head: 0, last_used: 0,
            bufs: [core::ptr::null_mut(); QUEUE_SIZE],
            tx_meta: [TxMeta { base_pa: 0, pages: 0 }; QUEUE_SIZE],
            desc_pa: 0, avail_pa: 0, used_pa: 0,
        }
    }
    unsafe fn alloc(&mut self) {
        let desc_bytes  = core::mem::size_of::<VirtDesc>() * QUEUE_SIZE;
        let avail_bytes = 6 + QUEUE_SIZE * 2;
        let pages_da    = (desc_bytes + avail_bytes + 4095) / 4096;
        let dp = alloc_pages(pages_da);
        self.desc_pa  = dp;
        self.avail_pa = dp + desc_bytes;
        self.desc  = dp as *mut VirtDesc;
        self.avail = (dp + desc_bytes) as *mut VirtAvail;
        let up = alloc_pages(1);
        self.used_pa = up;
        self.used  = up as *mut VirtUsed;
        for i in 0..QUEUE_SIZE - 1 { (*self.desc.add(i)).next = (i + 1) as u16; }
        self.free_head = 0;
    }
    unsafe fn add_rx_buf(&mut self, buf: *mut u8, len: u32) {
        let idx = self.alloc_desc();
        let d = &mut *self.desc.add(idx);
        d.addr = buf as u64; d.len = len;
        d.flags = VRING_DESC_F_WRITE; d.next = 0;
        self.bufs[idx] = buf;
        self.push_avail(idx);
    }
    unsafe fn add_tx_buf(&mut self, buf: *const u8, len: u32, base_pa: usize, pages: usize) {
        let idx = self.alloc_desc();
        let d = &mut *self.desc.add(idx);
        d.addr = buf as u64; d.len = len; d.flags = 0; d.next = 0;
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
    #[inline] unsafe fn alloc_desc(&mut self) -> usize {
        let idx = self.free_head;
        self.free_head = (*self.desc.add(idx)).next as usize;
        idx
    }
    #[inline] unsafe fn free_desc(&mut self, idx: usize) {
        (*self.desc.add(idx)).next = self.free_head as u16;
        self.free_head = idx;
    }
    #[inline] unsafe fn push_avail(&mut self, idx: usize) {
        let avail = &mut *self.avail;
        let slot  = avail.idx as usize & (QUEUE_SIZE - 1);
        avail.ring[slot] = idx as u16;
        fence(Ordering::Release);
        avail.idx = avail.idx.wrapping_add(1);
    }
}

// ── Device state ───────────────────────────────────────────────────────────────────

struct MmioDev {
    base: usize,
    mac:  [u8; 6],
    irq:  u32,   // PLIC IRQ number, 0 = unknown
    rxq:  Virtqueue,
    txq:  Virtqueue,
}
unsafe impl Send for MmioDev {}
unsafe impl Sync for MmioDev {}

static DEV: Mutex<Option<MmioDev>> = Mutex::new(None);

// ── Probe ─────────────────────────────────────────────────────────────────────────────

pub fn probe(base: usize, irq: u32) -> bool {
    unsafe {
        let magic   = mmio_r32(base, REG_MAGIC);
        let version = mmio_r32(base, REG_VERSION);
        let dev_id  = mmio_r32(base, REG_DEVICE_ID);
        if magic != MMIO_MAGIC { return false; }
        if dev_id == 0         { return false; }
        if dev_id != DEV_ID_NET { return false; }
        if version != 1 && version != 2 {
            crate::println!("virtio_net_mmio: unknown version {} at {:#x}", version, base);
            return false;
        }
        crate::println!("virtio_net_mmio: found net device at {:#x} (v{})", base, version);
        if version == 2 { init_modern(base, irq) } else { init_legacy(base, irq) }
    }
}

// ── Modern init ────────────────────────────────────────────────────────────────────

unsafe fn init_modern(base: usize, irq: u32) -> bool {
    mmio_w32(base, REG_STATUS, 0);
    mmio_w32(base, REG_STATUS, STATUS_ACK);
    mmio_w32(base, REG_STATUS, STATUS_ACK | STATUS_DRIVER);
    mmio_w32(base, REG_DEVICE_FEAT_SEL, 0);
    let f0 = mmio_r32(base, REG_DEVICE_FEATURES) & (FEAT_MAC | FEAT_CSUM);
    mmio_w32(base, REG_DRIVER_FEAT_SEL, 0);
    mmio_w32(base, REG_DRIVER_FEATURES, f0);
    mmio_w32(base, REG_DEVICE_FEAT_SEL, 1);
    let f1 = mmio_r32(base, REG_DEVICE_FEATURES) & FEAT_VERSION_1;
    mmio_w32(base, REG_DRIVER_FEAT_SEL, 1);
    mmio_w32(base, REG_DRIVER_FEATURES, f1);
    mmio_w32(base, REG_STATUS, STATUS_ACK | STATUS_DRIVER | STATUS_FEATURES_OK);
    if mmio_r32(base, REG_STATUS) & STATUS_FEATURES_OK == 0 {
        mmio_w32(base, REG_STATUS, STATUS_FAILED);
        crate::println!("virtio_net_mmio: FEATURES_OK rejected at {:#x}", base);
        return false;
    }
    let mut mac = [0u8; 6];
    for i in 0..6 { mac[i] = mmio_rb(base, REG_CONFIG_MAC + i); }
    let mut rxq = Virtqueue::zeroed();
    let mut txq = Virtqueue::zeroed();
    setup_queue_modern(base, 0, &mut rxq);
    setup_queue_modern(base, 1, &mut txq);
    prefill_rx(&mut rxq);
    mmio_w32(base, REG_QUEUE_NOTIFY, 0);
    mmio_w32(base, REG_STATUS, STATUS_ACK | STATUS_DRIVER | STATUS_FEATURES_OK | STATUS_DRIVER_OK);
    finalize(base, mac, irq, rxq, txq);
    true
}

unsafe fn setup_queue_modern(base: usize, qi: u32, q: &mut Virtqueue) {
    mmio_w32(base, REG_QUEUE_SEL, qi);
    let qmax = mmio_r32(base, REG_QUEUE_NUM_MAX) as usize;
    let qsz  = QUEUE_SIZE.min(qmax);
    mmio_w32(base, REG_QUEUE_NUM, qsz as u32);
    q.alloc();
    mmio_w32(base, REG_QUEUE_DESC_LO,  (q.desc_pa  & 0xFFFF_FFFF) as u32);
    mmio_w32(base, REG_QUEUE_DESC_HI,  (q.desc_pa  >> 32) as u32);
    mmio_w32(base, REG_QUEUE_AVAIL_LO, (q.avail_pa & 0xFFFF_FFFF) as u32);
    mmio_w32(base, REG_QUEUE_AVAIL_HI, (q.avail_pa >> 32) as u32);
    mmio_w32(base, REG_QUEUE_USED_LO,  (q.used_pa  & 0xFFFF_FFFF) as u32);
    mmio_w32(base, REG_QUEUE_USED_HI,  (q.used_pa  >> 32) as u32);
    mmio_w32(base, REG_QUEUE_READY, 1);
}

// ── Legacy init ────────────────────────────────────────────────────────────────────

unsafe fn init_legacy(base: usize, irq: u32) -> bool {
    mmio_w32(base, 0x028, 4096);
    mmio_w32(base, REG_STATUS, 0);
    mmio_w32(base, REG_STATUS, STATUS_ACK | STATUS_DRIVER);
    let dev_feats = mmio_r32(base, REG_DEVICE_FEATURES);
    mmio_w32(base, REG_DRIVER_FEATURES, dev_feats & (FEAT_MAC | FEAT_CSUM));
    mmio_w32(base, REG_STATUS, STATUS_ACK | STATUS_DRIVER | STATUS_FEATURES_OK);
    let mut mac = [0u8; 6];
    for i in 0..6 { mac[i] = mmio_rb(base, REG_CONFIG_MAC + i); }
    let mut rxq = Virtqueue::zeroed();
    let mut txq = Virtqueue::zeroed();
    setup_queue_legacy(base, 0, &mut rxq);
    setup_queue_legacy(base, 1, &mut txq);
    prefill_rx(&mut rxq);
    mmio_w32(base, REG_QUEUE_NOTIFY, 0);
    mmio_w32(base, REG_STATUS, STATUS_ACK | STATUS_DRIVER | STATUS_FEATURES_OK | STATUS_DRIVER_OK);
    finalize(base, mac, irq, rxq, txq);
    true
}

unsafe fn setup_queue_legacy(base: usize, qi: u32, q: &mut Virtqueue) {
    mmio_w32(base, REG_QUEUE_SEL, qi);
    let qmax = mmio_r32(base, REG_QUEUE_NUM_MAX) as usize;
    let qsz  = QUEUE_SIZE.min(qmax);
    mmio_w32(base, REG_QUEUE_NUM, qsz as u32);
    q.alloc();
    mmio_w32(base, 0x040, (q.desc_pa >> 12) as u32);
}

// ── Common ────────────────────────────────────────────────────────────────────────────

unsafe fn prefill_rx(rxq: &mut Virtqueue) {
    for _ in 0..QUEUE_SIZE / 2 {
        let buf = pmm::alloc_page().expect("virtio_net_mmio: rx buf") as *mut u8;
        core::ptr::write_bytes(buf, 0, 4096);
        rxq.add_rx_buf(buf, RX_BUF_SIZE as u32);
    }
}

fn finalize(base: usize, mac: [u8; 6], irq: u32, rxq: Virtqueue, txq: Virtqueue) {
    crate::net::eth::set_mac(mac);
    *DEV.lock() = Some(MmioDev { base, mac, irq, rxq, txq });
    register_nic(NicDevice {
        send_frame: |frame| send_frame(frame),
        rx_poll:    rx_poll,
        mac,
    });
    crate::println!(
        "virtio_net_mmio: device ready, MAC {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    );
    crate::println!("nic: registered device 0 MAC {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    );
}

// ── PLIC wiring ─────────────────────────────────────────────────────────────────────

/// Register the virtio-net interrupt with the PLIC.
///
/// Call this from `kernel_main` after `plic::init()` succeeds.  From this
/// point on, incoming frames wake the kernel via a PLIC IRQ (scause = 0x8..9)
/// rather than being discovered only on the next `rx_poll()` call.
///
/// If the IRQ number stored by `probe()` is 0 (not found in FDT), this is a
/// no-op and polled mode remains active.
pub fn enable_plic_irq() {
    let irq = DEV.lock().as_ref().map(|d| d.irq).unwrap_or(0);
    if irq == 0 {
        crate::println!("virtio_net_mmio: no IRQ from FDT — staying in polled mode");
        return;
    }
    crate::drivers::plic::enable_irq(irq, virtio_net_mmio_irq);
    crate::println!("virtio_net_mmio: IRQ {} registered with PLIC — interrupt-driven RX enabled", irq);
}

// ── TX ──────────────────────────────────────────────────────────────────────────

pub fn send_frame(frame: &[u8]) -> bool {
    let mut guard = DEV.lock();
    let Some(dev) = guard.as_mut() else { return false; };
    let total   = NET_HDR_LEN + frame.len();
    let pages   = (total + 4095) / 4096;
    let base_pa = alloc_pages(pages);
    let buf     = base_pa as *mut u8;
    unsafe {
        core::ptr::copy_nonoverlapping(frame.as_ptr(), buf.add(NET_HDR_LEN), frame.len());
        dev.txq.add_tx_buf(buf, total as u32, base_pa, pages);
        mmio_w32(dev.base, REG_QUEUE_NOTIFY, 1);
    }
    true
}

// ── RX ──────────────────────────────────────────────────────────────────────────

pub fn rx_poll() {
    let mut guard = DEV.lock();
    let Some(dev) = guard.as_mut() else { return; };
    let base = dev.base;
    unsafe {
        dev.rxq.drain_used(|buf, len, _meta| {
            if len as usize > NET_HDR_LEN {
                let frame = core::slice::from_raw_parts(
                    buf.add(NET_HDR_LEN), len as usize - NET_HDR_LEN,
                );
                crate::net::eth::receive_frame(frame);
            }
            core::ptr::write_bytes(buf, 0, RX_BUF_SIZE);
            dev.rxq.add_rx_buf(buf, RX_BUF_SIZE as u32);
        });
        mmio_w32(base, REG_QUEUE_NOTIFY, 0);
    }
}

fn drain_tx() {
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

// ── IRQ handler ───────────────────────────────────────────────────────────────────

pub fn virtio_net_mmio_irq() {
    let guard = DEV.lock();
    let Some(dev) = guard.as_ref() else { return; };
    let base = dev.base;
    drop(guard);
    unsafe {
        let status = mmio_r32(base, REG_INTERRUPT_STATUS);
        mmio_w32(base, REG_INTERRUPT_ACK, status);
    }
    rx_poll();
    drain_tx();
}

// ── Accessors ─────────────────────────────────────────────────────────────────────

pub fn mac_address() -> [u8; 6] {
    DEV.lock().as_ref().map(|d| d.mac).unwrap_or([0u8; 6])
}
pub fn is_present() -> bool {
    DEV.lock().is_some()
}
