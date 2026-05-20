//! virtio-net PCI driver (x86_64).
//!
//! ## Device
//!   PCI vendor 0x1AF4, device 0x1000 (legacy) or 0x1041 (modern).
//!   Queues: 0 = receiveq, 1 = transmitq.
//!
//! ## Virtqueue layout (split-ring)
//!   Descriptor table + Available ring + Used ring.
//!
//! ## Feature negotiation
//!   We request VIRTIO_NET_F_MAC (bit 5) only.

use spin::Mutex;
use crate::drivers::net::nic::{NicDevice, register_nic};
use crate::drivers::platform::pcie::{cam_read32, cam_write32, enumerate};
use crate::net::eth::receive_frame;

const VIRTIO_VENDOR: u16 = 0x1AF4;
const VIRTIO_DEV_NET_LEG: u16 = 0x1000;
const VIRTIO_DEV_NET_MOD: u16 = 0x1041;

const REG_DEVICE_FEATURES: u16 = 0x00; const REG_GUEST_FEATURES: u16 = 0x04;
const REG_QUEUE_ADDR: u16 = 0x08;     const REG_QUEUE_SIZE: u16 = 0x0C;
const REG_QUEUE_SELECT: u16 = 0x0E;   const REG_QUEUE_NOTIFY: u16 = 0x10;
const REG_DEVICE_STATUS: u16 = 0x12;  const REG_ISR_STATUS: u16 = 0x13;
const REG_NET_MAC_BASE: u16 = 0x14;

const STATUS_RESET: u8 = 0x00; const STATUS_ACK: u8 = 0x01; const STATUS_DRIVER: u8 = 0x02;
const STATUS_DRIVER_OK: u8 = 0x04; const STATUS_FEATURES_OK: u8 = 0x08; const STATUS_FAILED: u8 = 0x80;

const VIRTIO_NET_F_MAC: u32 = 1 << 5;
const QUEUE_SIZE: usize = 16;
const VRING_DESC_F_NEXT: u16 = 0x1;
const VRING_DESC_F_WRITE: u16 = 0x2;
const NET_HDR_LEN: usize = 10;

#[repr(C)] struct VirtioNetHdr { flags: u8, gso_type: u8, hdr_len: u16, gso_size: u16, csum_start: u16, csum_offset: u16, num_buffers: u16 }
#[repr(C, align(16))] #[derive(Copy, Clone)] struct VirtqDesc { addr: u64, len: u32, flags: u16, next: u16 }
#[repr(C, align(2))] struct VirtqAvail { flags: u16, idx: u16, ring: [u16; QUEUE_SIZE], used_event: u16 }
#[repr(C)] #[derive(Copy, Clone)] struct VirtqUsedElem { id: u32, len: u32 }
#[repr(C, align(4))] struct VirtqUsed { flags: u16, idx: u16, ring: [VirtqUsedElem; QUEUE_SIZE], avail_event: u16 }

const RX_BUF_SIZE: usize = 1526;

#[repr(C, align(4096))]
struct RxQueue {
    desc: [VirtqDesc; QUEUE_SIZE], avail: VirtqAvail,
    _pad1: [u8; 4096 - (core::mem::size_of::<VirtqAvail>() % 4096)],
    used: VirtqUsed, bufs: [[u8; RX_BUF_SIZE]; QUEUE_SIZE],
}
#[repr(C, align(4096))]
struct TxQueue {
    desc: [VirtqDesc; QUEUE_SIZE * 2], avail: VirtqAvail,
    _pad1: [u8; 4096 - (core::mem::size_of::<VirtqAvail>() % 4096)],
    used: VirtqUsed, hdrs: [VirtioNetHdr; QUEUE_SIZE],
}

static mut RXQ: RxQueue = unsafe { core::mem::zeroed() };
static mut TXQ: TxQueue = unsafe { core::mem::zeroed() };

struct NetState { io_base: u16, rx_last_used: u16, tx_last_used: u16, tx_avail_head: u16 }
static RX_STATE: Mutex<Option<NetState>> = Mutex::new(None);
static TX_STATE: Mutex<Option<NetState>> = Mutex::new(None);

#[inline(always)] unsafe fn inb(port: u16) -> u8 { let v: u8; core::arch::asm!("in al, dx", out("al") v, in("dx") port, options(nomem, nostack)); v }
#[inline(always)] unsafe fn inw(port: u16) -> u16 { let v: u16; core::arch::asm!("in ax, dx", out("ax") v, in("dx") port, options(nomem, nostack)); v }
#[inline(always)] unsafe fn inl(port: u16) -> u32 { let v: u32; core::arch::asm!("in eax, dx", out("eax") v, in("dx") port, options(nomem, nostack)); v }
#[inline(always)] unsafe fn outb(port: u16, v: u8) { core::arch::asm!("out dx, al", in("dx") port, in("al") v, options(nomem, nostack)); }
#[inline(always)] unsafe fn outw(port: u16, v: u16) { core::arch::asm!("out dx, ax", in("dx") port, in("ax") v, options(nomem, nostack)); }
#[inline(always)] unsafe fn outl(port: u16, v: u32) { core::arch::asm!("out dx, eax", in("dx") port, in("eax") v, options(nomem, nostack)); }

unsafe fn set_queue(io: u16, queue_idx: u16, page_addr: u64) { outw(io + REG_QUEUE_SELECT, queue_idx); outl(io + REG_QUEUE_ADDR, (page_addr >> 12) as u32); }
unsafe fn notify(io: u16, queue_idx: u16) { outw(io + REG_QUEUE_NOTIFY, queue_idx); }

unsafe fn rx_queue_init(io: u16) {
    let q = &mut RXQ;
    for i in 0..QUEUE_SIZE { q.desc[i].addr = q.bufs[i].as_ptr() as u64; q.desc[i].len = RX_BUF_SIZE as u32; q.desc[i].flags = VRING_DESC_F_WRITE; q.desc[i].next = 0; q.avail.ring[i] = i as u16; }
    q.avail.idx = QUEUE_SIZE as u16;
    core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
    set_queue(io, 0, q.desc.as_ptr() as u64);
}

unsafe fn tx_queue_init(io: u16) { let q = &mut TXQ; q.avail.idx = 0; set_queue(io, 1, q.desc.as_ptr() as u64); }

pub fn probe() -> Option<[u8; 6]> {
    let dev = enumerate().into_iter().find(|d| d.vendor == VIRTIO_VENDOR && (d.device == VIRTIO_DEV_NET_LEG || d.device == VIRTIO_DEV_NET_MOD))?;
    let bar0 = dev.bars[0]; if bar0 & 1 == 0 { return None; }
    let io = (bar0 & 0xFFFC) as u16;
    dev.enable_bus_master();
    let cmd = cam_read32(dev.bus, dev.dev, dev.func, 0x04);
    cam_write32(dev.bus, dev.dev, dev.func, 0x04, cmd | 0x05);
    unsafe {
        outb(io + REG_DEVICE_STATUS, STATUS_RESET);
        outb(io + REG_DEVICE_STATUS, STATUS_ACK | STATUS_DRIVER);
        let dev_feat = inl(io + REG_DEVICE_FEATURES);
        outl(io + REG_GUEST_FEATURES, dev_feat & VIRTIO_NET_F_MAC);
        outb(io + REG_DEVICE_STATUS, STATUS_ACK | STATUS_DRIVER | STATUS_FEATURES_OK);
        if inb(io + REG_DEVICE_STATUS) & STATUS_FEATURES_OK == 0 { outb(io + REG_DEVICE_STATUS, STATUS_FAILED); return None; }
        let mac = [inb(io + REG_NET_MAC_BASE), inb(io + REG_NET_MAC_BASE + 1), inb(io + REG_NET_MAC_BASE + 2), inb(io + REG_NET_MAC_BASE + 3), inb(io + REG_NET_MAC_BASE + 4), inb(io + REG_NET_MAC_BASE + 5)];
        rx_queue_init(io); tx_queue_init(io);
        outb(io + REG_DEVICE_STATUS, STATUS_ACK | STATUS_DRIVER | STATUS_FEATURES_OK | STATUS_DRIVER_OK);
        notify(io, 0);
        *RX_STATE.lock() = Some(NetState { io_base: io, rx_last_used: 0, tx_last_used: 0, tx_avail_head: 0 });
        *TX_STATE.lock() = Some(NetState { io_base: io, rx_last_used: 0, tx_last_used: 0, tx_avail_head: 0 });
        Some(mac)
    }
}

pub fn send_frame(frame: &[u8]) -> bool {
    if frame.len() > 1514 { return false; }
    let mut guard = TX_STATE.lock(); let st = match guard.as_mut() { Some(s) => s, None => return false };
    unsafe {
        let q = &mut TXQ; let slot = st.tx_avail_head as usize % QUEUE_SIZE;
        while q.used.idx != st.tx_last_used { st.tx_last_used = st.tx_last_used.wrapping_add(1); }
        let hdr_desc = slot * 2; let data_desc = slot * 2 + 1;
        let hdr = &mut q.hdrs[slot] as *mut VirtioNetHdr; core::ptr::write_bytes(hdr, 0, 1);
        q.desc[hdr_desc].addr = hdr as u64; q.desc[hdr_desc].len = NET_HDR_LEN as u32; q.desc[hdr_desc].flags = VRING_DESC_F_NEXT; q.desc[hdr_desc].next = data_desc as u16;
        q.desc[data_desc].addr = frame.as_ptr() as u64; q.desc[data_desc].len = frame.len() as u32; q.desc[data_desc].flags = 0; q.desc[data_desc].next = 0;
        let avail_slot = q.avail.idx as usize % QUEUE_SIZE; q.avail.ring[avail_slot] = hdr_desc as u16;
        core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
        q.avail.idx = q.avail.idx.wrapping_add(1);
        core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
        notify(st.io_base, 1); st.tx_avail_head = st.tx_avail_head.wrapping_add(1);
    }
    true
}

pub fn rx_poll() {
    let mut guard = RX_STATE.lock(); let st = match guard.as_mut() { Some(s) => s, None => return };
    unsafe {
        let q = &mut RXQ; let _isr = inb(st.io_base + REG_ISR_STATUS);
        while q.used.idx != st.rx_last_used {
            let used_idx = st.rx_last_used as usize % QUEUE_SIZE;
            let desc_idx = q.used.ring[used_idx].id as usize;
            let pkt_len  = q.used.ring[used_idx].len as usize;
            st.rx_last_used = st.rx_last_used.wrapping_add(1);
            if pkt_len > NET_HDR_LEN { receive_frame(&q.bufs[desc_idx][NET_HDR_LEN..pkt_len]); }
            q.desc[desc_idx].flags = VRING_DESC_F_WRITE;
            let avail_slot = q.avail.idx as usize % QUEUE_SIZE; q.avail.ring[avail_slot] = desc_idx as u16;
            core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
            q.avail.idx = q.avail.idx.wrapping_add(1);
            core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
        }
        notify(st.io_base, 0);
    }
}

pub fn init() {
    match probe() {
        Some(mac) => { crate::net::eth::set_mac(mac); register_nic(NicDevice { send_frame: |f| send_frame(f), rx_poll: || rx_poll(), mac }); }
        None => { crate::println!("virtio_net: no device found"); }
    }
}
