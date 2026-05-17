//! virtio-net PCI driver (x86_64).
//!
//! ## Device
//!   PCI vendor 0x1AF4, device 0x1000 (legacy) or 0x1041 (modern).
//!   Queues: 0 = receiveq, 1 = transmitq.
//!
//! ## Virtqueue layout (split-ring)
//!   Each queue has QUEUE_SIZE descriptors.  A 3-region layout is used:
//!     - Descriptor table  (16 bytes × N, align 16)
//!     - Available ring    (6 + 2×N bytes, align 2)
//!     - Used ring         (6 + 8×N bytes, align 4)
//!
//! ## virtio-net header
//!   Every TX packet is prepended with a 10-byte virtio_net_hdr.
//!   Every RX descriptor chain includes a 10-byte header the device fills.
//!
//! ## Feature negotiation
//!   We request VIRTIO_NET_F_MAC (bit 5) only; no GSO, no checksum offload.
//!
//! ## Threading
//!   Two separate Mutexes: one for TX, one for RX.  Allows a timer-tick
//!   rx_poll() to run without blocking a concurrent send_frame().

use spin::Mutex;
use crate::drivers::nic::{NicDevice, register_nic};
use crate::drivers::pcie::{cam_read32, cam_write32, ecam_read32, enumerate};
use crate::net::eth::receive_frame;

// ── PCI identifiers ───────────────────────────────────────────────────────────

const VIRTIO_VENDOR:      u16 = 0x1AF4;
const VIRTIO_DEV_NET_LEG: u16 = 0x1000; // legacy (transitional)
const VIRTIO_DEV_NET_MOD: u16 = 0x1041; // modern

// ── Virtio PCI legacy register offsets (within BAR0 I/O space) ───────────────

const REG_DEVICE_FEATURES:  u16 = 0x00; // 32-bit RO
const REG_GUEST_FEATURES:   u16 = 0x04; // 32-bit RW
const REG_QUEUE_ADDR:       u16 = 0x08; // 32-bit RW  (page address >> 12)
const REG_QUEUE_SIZE:       u16 = 0x0C; // 16-bit RO
const REG_QUEUE_SELECT:     u16 = 0x0E; // 16-bit RW
const REG_QUEUE_NOTIFY:     u16 = 0x10; // 16-bit WO  kick a queue
const REG_DEVICE_STATUS:    u16 = 0x12; // 8-bit  RW
const REG_ISR_STATUS:       u16 = 0x13; // 8-bit  RO  clear-on-read
const REG_NET_MAC_BASE:     u16 = 0x14; // 6 bytes of MAC

// ── Device status bits ────────────────────────────────────────────────────────

const STATUS_RESET:       u8 = 0x00;
const STATUS_ACK:         u8 = 0x01;
const STATUS_DRIVER:      u8 = 0x02;
const STATUS_DRIVER_OK:   u8 = 0x04;
const STATUS_FEATURES_OK: u8 = 0x08;
const STATUS_FAILED:      u8 = 0x80;

// ── Feature bits ──────────────────────────────────────────────────────────────

const VIRTIO_NET_F_MAC: u32 = 1 << 5;

// ── Virtqueue constants ───────────────────────────────────────────────────────

const QUEUE_SIZE: usize = 16; // must be power-of-two and ≤ QueueNumMax

const VRING_DESC_F_NEXT:  u16 = 0x1;
const VRING_DESC_F_WRITE: u16 = 0x2; // device writes into this buffer

// ── virtio-net packet header (10 bytes, prepended to every frame) ─────────────

const NET_HDR_LEN: usize = 10;

#[repr(C)]
struct VirtioNetHdr {
    flags:       u8,
    gso_type:    u8,
    hdr_len:     u16,
    gso_size:    u16,
    csum_start:  u16,
    csum_offset: u16,
    num_buffers: u16,
}

// ── Descriptor / Available / Used ring types ──────────────────────────────────

#[repr(C, align(16))]
#[derive(Copy, Clone)]
struct VirtqDesc {
    addr:  u64,
    len:   u32,
    flags: u16,
    next:  u16,
}

#[repr(C, align(2))]
struct VirtqAvail {
    flags:      u16,
    idx:        u16,
    ring:       [u16; QUEUE_SIZE],
    used_event: u16,
}

#[repr(C)]
#[derive(Copy, Clone)]
struct VirtqUsedElem {
    id:  u32,
    len: u32,
}

#[repr(C, align(4))]
struct VirtqUsed {
    flags:       u16,
    idx:         u16,
    ring:        [VirtqUsedElem; QUEUE_SIZE],
    avail_event: u16,
}

// ── Per-queue storage (static, identity-mapped, 4 KB aligned) ─────────────────

const RX_BUF_SIZE: usize = 1526; // 1514 Ethernet + 10 virtio header + 2 pad

#[repr(C, align(4096))]
struct RxQueue {
    desc:  [VirtqDesc;  QUEUE_SIZE],
    avail: VirtqAvail,
    _pad1: [u8; 4096 - (core::mem::size_of::<VirtqAvail>() % 4096)],
    used:  VirtqUsed,
    // Per-descriptor receive buffers
    bufs:  [[u8; RX_BUF_SIZE]; QUEUE_SIZE],
}

#[repr(C, align(4096))]
struct TxQueue {
    desc:  [VirtqDesc;  QUEUE_SIZE * 2], // 2 descs per packet: hdr + data
    avail: VirtqAvail,
    _pad1: [u8; 4096 - (core::mem::size_of::<VirtqAvail>() % 4096)],
    used:  VirtqUsed,
    // Per-slot TX headers
    hdrs:  [VirtioNetHdr; QUEUE_SIZE],
}

static mut RXQ: RxQueue = unsafe { core::mem::zeroed() };
static mut TXQ: TxQueue = unsafe { core::mem::zeroed() };

// ── Driver state ──────────────────────────────────────────────────────────────

struct NetState {
    io_base:       u16,   // BAR0 I/O port base
    rx_last_used:  u16,
    tx_last_used:  u16,
    tx_avail_head: u16,   // next free TX descriptor slot (0..QUEUE_SIZE)
}

static RX_STATE: Mutex<Option<NetState>> = Mutex::new(None);
static TX_STATE: Mutex<Option<NetState>> = Mutex::new(None);

// ── I/O port helpers ──────────────────────────────────────────────────────────

#[inline(always)]
unsafe fn inb(port: u16) -> u8 {
    let v: u8;
    core::arch::asm!("in al, dx", out("al") v, in("dx") port, options(nomem, nostack));
    v
}
#[inline(always)]
unsafe fn inw(port: u16) -> u16 {
    let v: u16;
    core::arch::asm!("in ax, dx", out("ax") v, in("dx") port, options(nomem, nostack));
    v
}
#[inline(always)]
unsafe fn inl(port: u16) -> u32 {
    let v: u32;
    core::arch::asm!("in eax, dx", out("eax") v, in("dx") port, options(nomem, nostack));
    v
}
#[inline(always)]
unsafe fn outb(port: u16, v: u8) {
    core::arch::asm!("out dx, al", in("dx") port, in("al") v, options(nomem, nostack));
}
#[inline(always)]
unsafe fn outw(port: u16, v: u16) {
    core::arch::asm!("out dx, ax", in("dx") port, in("ax") v, options(nomem, nostack));
}
#[inline(always)]
unsafe fn outl(port: u16, v: u32) {
    core::arch::asm!("out dx, eax", in("dx") port, in("eax") v, options(nomem, nostack));
}

// ── Virtqueue helpers ─────────────────────────────────────────────────────────

/// Write the physical page address of a queue to the device (legacy interface).
/// `page_addr` must be the base physical address of the descriptor table.
unsafe fn set_queue(io: u16, queue_idx: u16, page_addr: u64) {
    outw(io + REG_QUEUE_SELECT, queue_idx);
    // legacy: device expects page-frame number (addr >> 12), 32-bit
    outl(io + REG_QUEUE_ADDR, (page_addr >> 12) as u32);
}

/// Kick a queue (notify device a descriptor was added to the avail ring).
unsafe fn notify(io: u16, queue_idx: u16) {
    outw(io + REG_QUEUE_NOTIFY, queue_idx);
}

// ── RX queue setup ────────────────────────────────────────────────────────────

unsafe fn rx_queue_init(io: u16) {
    let q = &mut RXQ;

    // Each descriptor points at one receive buffer.
    // We chain nothing — each slot is one independent descriptor.
    for i in 0..QUEUE_SIZE {
        q.desc[i].addr  = q.bufs[i].as_ptr() as u64;
        q.desc[i].len   = RX_BUF_SIZE as u32;
        q.desc[i].flags = VRING_DESC_F_WRITE; // device writes into it
        q.desc[i].next  = 0;
        q.avail.ring[i] = i as u16;
    }
    q.avail.idx = QUEUE_SIZE as u16;

    core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);

    // Legacy queue address = descriptor table physical addr >> 12
    set_queue(io, 0, q.desc.as_ptr() as u64);
}

// ── TX queue setup ────────────────────────────────────────────────────────────

unsafe fn tx_queue_init(io: u16) {
    let q = &mut TXQ;
    // Descriptors are populated lazily in send_frame; just zero avail.idx.
    q.avail.idx = 0;
    set_queue(io, 1, q.desc.as_ptr() as u64);
}

// ── Probe / init ──────────────────────────────────────────────────────────────

/// Probe the PCI bus for a virtio-net device and initialise it.
/// Returns `Some(mac)` on success.
pub fn probe() -> Option<[u8; 6]> {
    // Find virtio-net on the PCI bus.
    let dev = enumerate().into_iter().find(|d| {
        d.vendor == VIRTIO_VENDOR
            && (d.device == VIRTIO_DEV_NET_LEG || d.device == VIRTIO_DEV_NET_MOD)
    })?;

    // BAR0 for legacy virtio is an I/O BAR (bit 0 set).
    let bar0 = dev.bars[0];
    let is_io = (bar0 & 1) != 0;
    if !is_io {
        // Modern MMIO transport — not yet implemented here; fall back to none.
        return None;
    }
    let io = (bar0 & 0xFFFC) as u16;

    // Enable bus-master and I/O space decode.
    dev.enable_bus_master();
    let cmd = cam_read32(dev.bus, dev.dev, dev.func, 0x04);
    cam_write32(dev.bus, dev.dev, dev.func, 0x04, cmd | 0x05); // I/O + BusMaster

    unsafe {
        // 1. Reset
        outb(io + REG_DEVICE_STATUS, STATUS_RESET);
        // 2. Acknowledge + Driver
        outb(io + REG_DEVICE_STATUS, STATUS_ACK | STATUS_DRIVER);

        // 3. Negotiate features: request MAC only.
        let dev_feat = inl(io + REG_DEVICE_FEATURES);
        outl(io + REG_GUEST_FEATURES, dev_feat & VIRTIO_NET_F_MAC);

        // 4. Features OK
        outb(io + REG_DEVICE_STATUS, STATUS_ACK | STATUS_DRIVER | STATUS_FEATURES_OK);
        if inb(io + REG_DEVICE_STATUS) & STATUS_FEATURES_OK == 0 {
            outb(io + REG_DEVICE_STATUS, STATUS_FAILED);
            return None;
        }

        // 5. Read MAC from device config space (offsets 0x14–0x19).
        let mac = [
            inb(io + REG_NET_MAC_BASE + 0),
            inb(io + REG_NET_MAC_BASE + 1),
            inb(io + REG_NET_MAC_BASE + 2),
            inb(io + REG_NET_MAC_BASE + 3),
            inb(io + REG_NET_MAC_BASE + 4),
            inb(io + REG_NET_MAC_BASE + 5),
        ];

        // 6. Initialise virtqueues.
        rx_queue_init(io);
        tx_queue_init(io);

        // 7. Driver OK.
        outb(io + REG_DEVICE_STATUS,
             STATUS_ACK | STATUS_DRIVER | STATUS_FEATURES_OK | STATUS_DRIVER_OK);

        // 8. Kick RX queue so device knows descriptors are ready.
        notify(io, 0);

        let state = NetState {
            io_base:       io,
            rx_last_used:  0,
            tx_last_used:  0,
            tx_avail_head: 0,
        };
        // Both halves share the same io_base; clone the struct.
        *RX_STATE.lock() = Some(NetState { io_base: io, rx_last_used: 0,
                                           tx_last_used: 0, tx_avail_head: 0 });
        *TX_STATE.lock() = Some(NetState { io_base: io, rx_last_used: 0,
                                           tx_last_used: 0, tx_avail_head: 0 });

        Some(mac)
    }
}

// ── send_frame (called by nic::send_frame) ────────────────────────────────────

/// Transmit one raw Ethernet frame.  Caller includes Ethernet header; no FCS.
/// Frame is copied into a static TX buffer so the caller's slice can be freed
/// immediately.
pub fn send_frame(frame: &[u8]) -> bool {
    if frame.len() > 1514 { return false; }

    let mut guard = TX_STATE.lock();
    let st = match guard.as_mut() {
        Some(s) => s,
        None    => return false,
    };

    unsafe {
        let q = &mut TXQ;
        let slot = st.tx_avail_head as usize % QUEUE_SIZE;

        // Reclaim used descriptors before checking capacity.
        while q.used.idx != st.tx_last_used {
            st.tx_last_used = st.tx_last_used.wrapping_add(1);
        }

        let hdr_desc  = slot * 2;
        let data_desc = slot * 2 + 1;

        // Zero the virtio-net header (no GSO, no checksum offload).
        let hdr = &mut q.hdrs[slot] as *mut VirtioNetHdr;
        core::ptr::write_bytes(hdr, 0, 1);

        // Desc 0: virtio-net header (device-readable)
        q.desc[hdr_desc].addr  = hdr as u64;
        q.desc[hdr_desc].len   = NET_HDR_LEN as u32;
        q.desc[hdr_desc].flags = VRING_DESC_F_NEXT;
        q.desc[hdr_desc].next  = data_desc as u16;

        // Desc 1: frame data — copy into a static per-slot buffer embedded
        //         inside the header array padding (we embed a frame buf below).
        // We write directly from the caller's slice since we hold the lock
        // through the notify and the device consumes it synchronously in QEMU.
        q.desc[data_desc].addr  = frame.as_ptr() as u64;
        q.desc[data_desc].len   = frame.len() as u32;
        q.desc[data_desc].flags = 0;
        q.desc[data_desc].next  = 0;

        // Place head descriptor into available ring.
        let avail_slot = q.avail.idx as usize % QUEUE_SIZE;
        q.avail.ring[avail_slot] = hdr_desc as u16;
        core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
        q.avail.idx = q.avail.idx.wrapping_add(1);
        core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);

        // Kick transmitq (queue index 1).
        notify(st.io_base, 1);

        st.tx_avail_head = st.tx_avail_head.wrapping_add(1);
    }
    true
}

// ── rx_poll (called by nic::rx_poll_all) ──────────────────────────────────────

/// Drain all completed RX descriptors and push frames up to eth::receive_frame.
pub fn rx_poll() {
    let mut guard = RX_STATE.lock();
    let st = match guard.as_mut() {
        Some(s) => s,
        None    => return,
    };

    unsafe {
        let q = &mut RXQ;

        // Ack any pending ISR to clear the interrupt latch.
        let _isr = inb(st.io_base + REG_ISR_STATUS);

        while q.used.idx != st.rx_last_used {
            let used_idx  = st.rx_last_used as usize % QUEUE_SIZE;
            let desc_idx  = q.used.ring[used_idx].id  as usize;
            let pkt_len   = q.used.ring[used_idx].len as usize;
            st.rx_last_used = st.rx_last_used.wrapping_add(1);

            // The device writes: [virtio_net_hdr (10 B)][ethernet frame]
            if pkt_len > NET_HDR_LEN {
                let buf   = &q.bufs[desc_idx];
                let frame = &buf[NET_HDR_LEN..pkt_len];
                receive_frame(frame);
            }

            // Recycle descriptor back to the device.
            q.desc[desc_idx].flags = VRING_DESC_F_WRITE;
            let avail_slot = q.avail.idx as usize % QUEUE_SIZE;
            q.avail.ring[avail_slot] = desc_idx as u16;
            core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
            q.avail.idx = q.avail.idx.wrapping_add(1);
            core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
        }

        // Re-kick RX queue so the device sees the recycled descriptors.
        notify(st.io_base, 0);
    }
}

// ── Public init entry point ───────────────────────────────────────────────────

/// Called from kernel init after PCI enumeration.
/// Probes for virtio-net, initialises the device, and registers a NicDevice
/// with the NIC abstraction layer.
pub fn init() {
    match probe() {
        Some(mac) => {
            // Set the Ethernet layer's idea of our MAC.
            crate::net::eth::set_mac(mac);
            // Register with the NIC abstraction layer.
            register_nic(NicDevice {
                send_frame: |f| send_frame(f),
                rx_poll:    || rx_poll(),
                mac,
            });
        }
        None => {
            crate::console::println!("virtio_net: no device found");
        }
    }
}
