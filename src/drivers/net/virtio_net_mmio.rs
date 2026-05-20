//! Virtio-net MMIO driver (for RISC-V `virt` machine and other MMIO transports).
//!
//! Provides a single RX queue and a single TX queue using the virtio 1.0 MMIO
//! transport.  Packets include the standard 10-byte virtio-net header.

extern crate alloc;
use alloc::vec::Vec;
use core::ptr::{read_volatile, write_volatile};
use spin::Mutex;

use crate::drivers::net::nic::{MacAddr, NicStats};

const MMIO_MAGIC:       usize = 0x000;
const MMIO_VERSION:     usize = 0x004;
const MMIO_DEVICE_ID:   usize = 0x008;
const MMIO_VENDOR_ID:   usize = 0x00C;
const MMIO_DEV_FEAT:    usize = 0x010;
const MMIO_DEV_FEATSEL: usize = 0x014;
const MMIO_DRV_FEAT:    usize = 0x020;
const MMIO_DRV_FEATSEL: usize = 0x024;
const MMIO_GUEST_PAGE:  usize = 0x028; // legacy field on old QEMU, harmless otherwise
const MMIO_QUEUE_SEL:   usize = 0x030;
const MMIO_QUEUE_NUMMAX:usize = 0x034;
const MMIO_QUEUE_NUM:   usize = 0x038;
const MMIO_QUEUE_ALIGN: usize = 0x03C;
const MMIO_QUEUE_PFN:   usize = 0x040;
const MMIO_QUEUE_READY: usize = 0x044;
const MMIO_QUEUE_NOTIFY:usize = 0x050;
const MMIO_INT_STATUS:  usize = 0x060;
const MMIO_INT_ACK:     usize = 0x064;
const MMIO_STATUS:      usize = 0x070;
const MMIO_CONFIG:      usize = 0x100;

const STATUS_ACK:      u32 = 1;
const STATUS_DRIVER:   u32 = 2;
const STATUS_OK:       u32 = 4;
const STATUS_FEAT_OK:  u32 = 8;

const FEAT_MAC:        u32 = 1 << 5;

const QUEUE_RX:        u32 = 0;
const QUEUE_TX:        u32 = 1;
const QSZ:             usize = 256;
const PKT_BUF:         usize = 2048;
const NET_HDR_LEN:     usize = 10;

#[repr(C, packed)]
#[derive(Clone, Copy, Default)]
struct Desc {
    addr:  u64,
    len:   u32,
    flags: u16,
    next:  u16,
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
struct Avail {
    flags: u16,
    idx:   u16,
    ring:  [u16; QSZ],
}

#[repr(C, packed)]
#[derive(Clone, Copy, Default)]
struct UsedElem {
    id:  u32,
    len: u32,
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
struct Used {
    flags: u16,
    idx:   u16,
    ring:  [UsedElem; QSZ],
}

const DESC_F_WRITE: u16 = 2;

struct Queue {
    desc:  *mut Desc,
    avail: *mut Avail,
    used:  *mut Used,
    bufs:  Vec<u64>,
    last_used: u16,
}

struct VirtioNetMmio {
    base:   usize,
    rxq:    Queue,
    txq:    Queue,
    mac:    MacAddr,
    stats:  NicStats,
}

unsafe impl Send for VirtioNetMmio {}
unsafe impl Sync for VirtioNetMmio {}

static NIC: Mutex<Option<VirtioNetMmio>> = Mutex::new(None);

pub fn init(mmio_base: u64) { unsafe { _init(mmio_base as usize); } }
pub fn is_initialised() -> bool { NIC.lock().is_some() }
pub fn mac() -> Option<MacAddr> { NIC.lock().as_ref().map(|n| n.mac) }
pub fn stats() -> Option<NicStats> { NIC.lock().as_ref().map(|n| n.stats) }
pub fn send(frame: &[u8]) -> Result<(), &'static str> { unsafe { _send(frame) } }
pub fn recv(out: &mut [u8]) -> Option<usize> { unsafe { _recv(out) } }

unsafe fn _init(base: usize) {
    if read32(base, MMIO_MAGIC) != 0x7472_6976 { return; }
    if read32(base, MMIO_DEVICE_ID) != 1 { return; } // net device

    write32(base, MMIO_STATUS, 0);
    write32(base, MMIO_STATUS, STATUS_ACK | STATUS_DRIVER);

    // Feature negotiation (page 0 only, enough for MAC).
    write32(base, MMIO_DEV_FEATSEL, 0);
    let feats = read32(base, MMIO_DEV_FEAT);
    write32(base, MMIO_DRV_FEATSEL, 0);
    write32(base, MMIO_DRV_FEAT, feats & FEAT_MAC);
    write32(base, MMIO_STATUS, STATUS_ACK | STATUS_DRIVER | STATUS_FEAT_OK);

    let rxq = setup_queue(base, QUEUE_RX);
    let txq = setup_queue(base, QUEUE_TX);

    let mut mac = [0u8; 6];
    for i in 0..6 { mac[i] = read8(base, MMIO_CONFIG + i); }

    write32(base, MMIO_STATUS, STATUS_ACK | STATUS_DRIVER | STATUS_FEAT_OK | STATUS_OK);

    let mut nic = VirtioNetMmio {
        base,
        rxq,
        txq,
        mac: MacAddr(mac),
        stats: NicStats::default(),
    };
    refill_rx(&mut nic.rxq, base);
    *NIC.lock() = Some(nic);
}

unsafe fn _send(frame: &[u8]) -> Result<(), &'static str> {
    let mut g = NIC.lock();
    let nic = g.as_mut().ok_or("virtio-net-mmio not initialised")?;
    if frame.len() + NET_HDR_LEN > PKT_BUF { return Err("frame too large"); }

    let idx = poll_free_desc(&nic.txq)?;
    let buf = nic.txq.bufs[idx as usize] as *mut u8;
    core::ptr::write_bytes(buf, 0, NET_HDR_LEN);
    core::ptr::copy_nonoverlapping(frame.as_ptr(), buf.add(NET_HDR_LEN), frame.len());

    let d = &mut *nic.txq.desc.add(idx as usize);
    d.addr = nic.txq.bufs[idx as usize];
    d.len  = (frame.len() + NET_HDR_LEN) as u32;
    d.flags = 0;
    d.next  = 0;

    post_avail(&mut nic.txq, idx, nic.base, QUEUE_TX);
    nic.stats.tx_packets += 1;
    nic.stats.tx_bytes += frame.len() as u64;
    Ok(())
}

unsafe fn _recv(out: &mut [u8]) -> Option<usize> {
    let mut g = NIC.lock();
    let nic = g.as_mut()?;
    let used = pop_used(&mut nic.rxq)?;
    let buf = nic.rxq.bufs[used.id as usize] as *const u8;
    if used.len as usize <= NET_HDR_LEN {
        recycle_rx(&mut nic.rxq, used.id as u16, nic.base);
        return None;
    }
    let plen = used.len as usize - NET_HDR_LEN;
    let n = out.len().min(plen);
    core::ptr::copy_nonoverlapping(buf.add(NET_HDR_LEN), out.as_mut_ptr(), n);
    recycle_rx(&mut nic.rxq, used.id as u16, nic.base);
    nic.stats.rx_packets += 1;
    nic.stats.rx_bytes += plen as u64;
    Some(n)
}

unsafe fn setup_queue(base: usize, q: u32) -> Queue {
    write32(base, MMIO_QUEUE_SEL, q);
    let qmax = read32(base, MMIO_QUEUE_NUMMAX) as usize;
    assert!(qmax >= QSZ);
    write32(base, MMIO_QUEUE_NUM, QSZ as u32);
    write32(base, MMIO_QUEUE_ALIGN, 4096);

    let bytes_desc  = QSZ * core::mem::size_of::<Desc>();
    let bytes_avail = core::mem::size_of::<Avail>();
    let bytes_used  = core::mem::size_of::<Used>();
    let total = align_up(bytes_desc + bytes_avail, 4096) + align_up(bytes_used, 4096);
    let phys = alloc_dma(total, 4096).unwrap();
    core::ptr::write_bytes(phys as *mut u8, 0, total);

    write32(base, MMIO_QUEUE_PFN, (phys >> 12) as u32);
    write32(base, MMIO_QUEUE_READY, 1);

    let desc  = phys as *mut Desc;
    let avail = (phys as usize + bytes_desc) as *mut Avail;
    let used  = (phys as usize + align_up(bytes_desc + bytes_avail, 4096)) as *mut Used;

    let mut bufs = Vec::with_capacity(QSZ);
    for _ in 0..QSZ { bufs.push(alloc_dma(PKT_BUF, 2048).unwrap()); }

    Queue { desc, avail, used, bufs, last_used: 0 }
}

unsafe fn refill_rx(q: &mut Queue, base: usize) {
    for i in 0..QSZ as u16 { recycle_rx(q, i, base); }
}

unsafe fn recycle_rx(q: &mut Queue, idx: u16, base: usize) {
    let d = &mut *q.desc.add(idx as usize);
    d.addr = q.bufs[idx as usize];
    d.len  = PKT_BUF as u32;
    d.flags = DESC_F_WRITE;
    d.next  = 0;
    post_avail(q, idx, base, QUEUE_RX);
}

unsafe fn poll_free_desc(q: &Queue) -> Result<u16, &'static str> {
    for i in 0..QSZ {
        let d = &*q.desc.add(i);
        if d.len == 0 { return Ok(i as u16); }
    }
    Err("no free tx desc")
}

unsafe fn post_avail(q: &mut Queue, idx: u16, base: usize, which: u32) {
    let a = &mut *q.avail;
    let slot = (a.idx as usize) % QSZ;
    a.ring[slot] = idx;
    a.idx = a.idx.wrapping_add(1);
    write32(base, MMIO_QUEUE_NOTIFY, which);
}

unsafe fn pop_used(q: &mut Queue) -> Option<UsedElem> {
    let u = &*q.used;
    if q.last_used == u.idx { return None; }
    let elem = u.ring[(q.last_used as usize) % QSZ];
    q.last_used = q.last_used.wrapping_add(1);
    let d = &mut *q.desc.add(elem.id as usize);
    d.len = 0;
    Some(elem)
}

#[inline]
fn align_up(x: usize, a: usize) -> usize { (x + a - 1) & !(a - 1) }

fn alloc_dma(size: usize, align: usize) -> Option<u64> {
    let pages = (size + 0xFFF) / 0x1000;
    let phys = crate::mm::pmm::alloc_pages_aligned(pages, align)?.as_ptr() as u64;
    unsafe { core::ptr::write_bytes(phys as *mut u8, 0, pages * 0x1000); }
    Some(phys)
}

#[inline] unsafe fn read8(base: usize, off: usize) -> u8 { read_volatile((base + off) as *const u8) }
#[inline] unsafe fn read32(base: usize, off: usize) -> u32 { read_volatile((base + off) as *const u32) }
#[inline] unsafe fn write32(base: usize, off: usize, val: u32) { write_volatile((base + off) as *mut u32, val); }
