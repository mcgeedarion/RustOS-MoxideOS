//! Virtio-net PCI driver.
//!
//! Supports a single RX and TX virtqueue plus the legacy 10-byte virtio-net
//! header prepended to each packet buffer.  This implementation uses the
//! same split-ring helper strategy as the block driver and is suitable for
//! QEMU's `virtio-net-pci` device.

extern crate alloc;
use alloc::vec::Vec;
use core::ptr::{read_volatile, write_volatile};
use spin::Mutex;

use crate::drivers::net::nic::{MacAddr, NicStats};

const VIRTIO_PCI_VENDOR: u16 = 0x1AF4;
const VIRTIO_NET_DEV: u16 = 0x1041; // transitional virtio-net

const VIRTIO_PCI_QUEUE_SEL: u16 = 0x0E;
const VIRTIO_PCI_QUEUE_NUM: u16 = 0x0C;
const VIRTIO_PCI_QUEUE_PFN: u16 = 0x08;
const VIRTIO_PCI_STATUS: u16 = 0x12;
const VIRTIO_PCI_ISR: u16 = 0x13;
const VIRTIO_PCI_DEV_FEAT: u16 = 0x00;
const VIRTIO_PCI_DRV_FEAT: u16 = 0x04;
const VIRTIO_PCI_GUEST_PAGE: u16 = 0x28;
const VIRTIO_PCI_MAC: u16 = 0x14;

const STATUS_ACK: u8 = 1;
const STATUS_DRIVER: u8 = 2;
const STATUS_OK: u8 = 4;
const STATUS_FEAT_OK: u8 = 8;

const FEAT_MAC: u32 = 1 << 5;

const QUEUE_RX: u16 = 0;
const QUEUE_TX: u16 = 1;
const QSZ: usize = 256;
const PKT_BUF: usize = 2048;
const NET_HDR_LEN: usize = 10;

#[repr(C, packed)]
#[derive(Clone, Copy, Default)]
struct Desc {
    addr: u64,
    len: u32,
    flags: u16,
    next: u16,
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
struct Avail {
    flags: u16,
    idx: u16,
    ring: [u16; QSZ],
}

#[repr(C, packed)]
#[derive(Clone, Copy, Default)]
struct UsedElem {
    id: u32,
    len: u32,
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
struct Used {
    flags: u16,
    idx: u16,
    ring: [UsedElem; QSZ],
}

const DESC_F_NEXT: u16 = 1;
const DESC_F_WRITE: u16 = 2;

struct Queue {
    desc: *mut Desc,
    avail: *mut Avail,
    used: *mut Used,
    bufs: Vec<u64>,
    last_used: u16,
}

struct VirtioNet {
    iobase: u16,
    rxq: Queue,
    txq: Queue,
    mac: MacAddr,
    stats: NicStats,
}

unsafe impl Send for VirtioNet {}
unsafe impl Sync for VirtioNet {}

static NIC: Mutex<Option<VirtioNet>> = Mutex::new(None);

pub fn init(iobase: u16) {
    unsafe {
        _init(iobase);
    }
}

pub fn is_initialised() -> bool {
    NIC.lock().is_some()
}
pub fn mac() -> Option<MacAddr> {
    NIC.lock().as_ref().map(|n| n.mac)
}
pub fn stats() -> Option<NicStats> {
    NIC.lock().as_ref().map(|n| n.stats)
}
pub fn send(frame: &[u8]) -> Result<(), &'static str> {
    unsafe { _send(frame) }
}
pub fn recv(out: &mut [u8]) -> Option<usize> {
    unsafe { _recv(out) }
}

unsafe fn _init(iobase: u16) {
    out8(iobase + VIRTIO_PCI_STATUS, 0);
    out8(iobase + VIRTIO_PCI_STATUS, STATUS_ACK | STATUS_DRIVER);
    out32(iobase + VIRTIO_PCI_GUEST_PAGE, 4096);

    let dev_feat = in32(iobase + VIRTIO_PCI_DEV_FEAT);
    let drv_feat = dev_feat & FEAT_MAC;
    out32(iobase + VIRTIO_PCI_DRV_FEAT, drv_feat);
    out8(
        iobase + VIRTIO_PCI_STATUS,
        STATUS_ACK | STATUS_DRIVER | STATUS_FEAT_OK,
    );

    let rxq = setup_queue(iobase, QUEUE_RX);
    let txq = setup_queue(iobase, QUEUE_TX);

    let mut mac = [0u8; 6];
    for i in 0..6 {
        mac[i] = in8(iobase + VIRTIO_PCI_MAC + i as u16);
    }

    out8(
        iobase + VIRTIO_PCI_STATUS,
        STATUS_ACK | STATUS_DRIVER | STATUS_FEAT_OK | STATUS_OK,
    );

    let mut nic = VirtioNet {
        iobase,
        rxq,
        txq,
        mac: MacAddr(mac),
        stats: NicStats::default(),
    };
    refill_rx(&mut nic.rxq, iobase);
    *NIC.lock() = Some(nic);
}

unsafe fn _send(frame: &[u8]) -> Result<(), &'static str> {
    let mut g = NIC.lock();
    let nic = g.as_mut().ok_or("virtio-net not initialised")?;
    if frame.len() + NET_HDR_LEN > PKT_BUF {
        return Err("frame too large");
    }

    let idx = poll_free_desc(&nic.txq)?;
    let buf = nic.txq.bufs[idx as usize] as *mut u8;
    core::ptr::write_bytes(buf, 0, NET_HDR_LEN);
    core::ptr::copy_nonoverlapping(frame.as_ptr(), buf.add(NET_HDR_LEN), frame.len());

    let d = &mut *nic.txq.desc.add(idx as usize);
    d.addr = nic.txq.bufs[idx as usize];
    d.len = (frame.len() + NET_HDR_LEN) as u32;
    d.flags = 0;
    d.next = 0;

    post_avail(&mut nic.txq, idx, nic.iobase, QUEUE_TX);
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
        recycle_rx(&mut nic.rxq, used.id as u16, nic.iobase);
        return None;
    }
    let plen = used.len as usize - NET_HDR_LEN;
    let n = out.len().min(plen);
    core::ptr::copy_nonoverlapping(buf.add(NET_HDR_LEN), out.as_mut_ptr(), n);
    recycle_rx(&mut nic.rxq, used.id as u16, nic.iobase);
    nic.stats.rx_packets += 1;
    nic.stats.rx_bytes += plen as u64;
    Some(n)
}

unsafe fn setup_queue(iobase: u16, q: u16) -> Queue {
    out16(iobase + VIRTIO_PCI_QUEUE_SEL, q);
    let qsz = in16(iobase + VIRTIO_PCI_QUEUE_NUM) as usize;
    assert!(qsz >= QSZ);

    let bytes_desc = QSZ * core::mem::size_of::<Desc>();
    let bytes_avail = core::mem::size_of::<Avail>();
    let bytes_used = core::mem::size_of::<Used>();
    let total = align_up(bytes_desc + bytes_avail, 4096) + align_up(bytes_used, 4096);
    let phys = alloc_dma(total, 4096).unwrap();

    out32(iobase + VIRTIO_PCI_QUEUE_PFN, (phys >> 12) as u32);

    let desc = phys as *mut Desc;
    let avail = (phys as usize + bytes_desc) as *mut Avail;
    let used = (phys as usize + align_up(bytes_desc + bytes_avail, 4096)) as *mut Used;
    core::ptr::write_bytes(phys as *mut u8, 0, total);

    let mut bufs = Vec::with_capacity(QSZ);
    for _ in 0..QSZ {
        bufs.push(alloc_dma(PKT_BUF, 2048).unwrap());
    }

    Queue {
        desc,
        avail,
        used,
        bufs,
        last_used: 0,
    }
}

unsafe fn refill_rx(q: &mut Queue, iobase: u16) {
    for i in 0..QSZ as u16 {
        recycle_rx(q, i, iobase);
    }
}

unsafe fn recycle_rx(q: &mut Queue, idx: u16, iobase: u16) {
    let d = &mut *q.desc.add(idx as usize);
    d.addr = q.bufs[idx as usize];
    d.len = PKT_BUF as u32;
    d.flags = DESC_F_WRITE;
    d.next = 0;
    post_avail(q, idx, iobase, QUEUE_RX);
}

unsafe fn poll_free_desc(q: &Queue) -> Result<u16, &'static str> {
    for i in 0..QSZ {
        let d = &*q.desc.add(i);
        if d.len == 0 {
            return Ok(i as u16);
        }
    }
    Err("no free tx desc")
}

unsafe fn post_avail(q: &mut Queue, idx: u16, iobase: u16, which: u16) {
    let a = &mut *q.avail;
    let slot = (a.idx as usize) % QSZ;
    a.ring[slot] = idx;
    a.idx = a.idx.wrapping_add(1);
    notify(iobase, which);
}

unsafe fn pop_used(q: &mut Queue) -> Option<UsedElem> {
    let u = &*q.used;
    if q.last_used == u.idx {
        return None;
    }
    let elem = u.ring[(q.last_used as usize) % QSZ];
    q.last_used = q.last_used.wrapping_add(1);
    let d = &mut *q.desc.add(elem.id as usize);
    d.len = 0;
    Some(elem)
}

#[inline]
unsafe fn notify(iobase: u16, q: u16) {
    out16(iobase + 0x10, q);
}
#[inline]
fn align_up(x: usize, a: usize) -> usize {
    (x + a - 1) & !(a - 1)
}

fn alloc_dma(size: usize, align: usize) -> Option<u64> {
    let pages = (size + 0xFFF) / 0x1000;
    let phys = crate::mm::pmm::alloc_pages_aligned(pages, align)?.as_ptr() as u64;
    unsafe {
        core::ptr::write_bytes(phys as *mut u8, 0, pages * 0x1000);
    }
    Some(phys)
}

#[inline]
unsafe fn in8(port: u16) -> u8 {
    let mut v: u8;
    core::arch::asm!("in al, dx", out("al") v, in("dx") port);
    v
}
#[inline]
unsafe fn in16(port: u16) -> u16 {
    let mut v: u16;
    core::arch::asm!("in ax, dx", out("ax") v, in("dx") port);
    v
}
#[inline]
unsafe fn in32(port: u16) -> u32 {
    let mut v: u32;
    core::arch::asm!("in eax, dx", out("eax") v, in("dx") port);
    v
}
#[inline]
unsafe fn out8(port: u16, val: u8) {
    core::arch::asm!("out dx, al", in("dx") port, in("al") val);
}
#[inline]
unsafe fn out16(port: u16, val: u16) {
    core::arch::asm!("out dx, ax", in("dx") port, in("ax") val);
}
#[inline]
unsafe fn out32(port: u16, val: u32) {
    core::arch::asm!("out dx, eax", in("dx") port, in("eax") val);
}
