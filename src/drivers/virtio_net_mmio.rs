//! virtio-net MMIO driver (RISC-V QEMU `virt` machine).
//!
//! ## Transport
//!   Memory-mapped I/O at a base discovered by the FDT walker in
//!   `fdt::fdt_phase2()`, which calls `probe(base, irq)` directly.
//!   Register layout follows virtio spec §4.2 (MMIO transport v2).
//!
//! ## Virtqueues
//!   Queue 0 = receiveq,  Queue 1 = transmitq.
//!   Split-ring, QUEUE_SIZE = 16 descriptors each.
//!
//! ## Interrupts
//!   The PLIC IRQ number comes from the FDT `interrupts` property.
//!   `irq_handler()` is called from `trap::trap_handler` when the
//!   PLIC reports an external interrupt for this device's source.
//!
//! ## Integration
//!   On success, `probe()` registers a `NicDevice` with `nic::register_nic()`
//!   and calls `eth::set_mac()`.  The rest of the stack (ARP, IP, TCP, DHCP)
//!   needs no changes.

use core::sync::atomic::{fence, Ordering};
use spin::Mutex;

use crate::drivers::nic::{NicDevice, register_nic};
use crate::net::eth::receive_frame;

// ── MMIO register offsets (virtio spec §4.2.2) ────────────────────────────────

const MMIO_MAGIC:          usize = 0x000; // RO  should read 0x74726976 ("virt")
const MMIO_VERSION:        usize = 0x004; // RO  1 = legacy, 2 = modern
const MMIO_DEVICE_ID:      usize = 0x008; // RO  1 = net, 2 = blk, ...
const MMIO_VENDOR_ID:      usize = 0x00C;
const MMIO_DEVICE_FEATURES:usize = 0x010; // RO  device feature bits
const MMIO_DEVICE_FEAT_SEL:usize = 0x014; // WO  select feature word (0 or 1)
const MMIO_DRIVER_FEATURES:usize = 0x020; // WO  driver accepted features
const MMIO_DRIVER_FEAT_SEL:usize = 0x024; // WO
const MMIO_QUEUE_SEL:      usize = 0x030; // WO  select queue index
const MMIO_QUEUE_NUM_MAX:  usize = 0x034; // RO  max descriptors for selected queue
const MMIO_QUEUE_NUM:      usize = 0x038; // WO  actual descriptors to use
const MMIO_QUEUE_READY:    usize = 0x044; // RW  1 = queue live
const MMIO_QUEUE_NOTIFY:   usize = 0x050; // WO  kick queue N
const MMIO_INT_STATUS:     usize = 0x060; // RO  pending interrupt reasons
const MMIO_INT_ACK:        usize = 0x064; // WO  clear interrupt reasons
const MMIO_STATUS:         usize = 0x070; // RW  device status byte
const MMIO_QUEUE_DESC_LO:  usize = 0x080; // WO  descriptor table phys addr [31:0]
const MMIO_QUEUE_DESC_HI:  usize = 0x084; // WO  descriptor table phys addr [63:32]
const MMIO_DRIVER_DESC_LO: usize = 0x090; // WO  available ring phys addr [31:0]
const MMIO_DRIVER_DESC_HI: usize = 0x094;
const MMIO_DEVICE_DESC_LO: usize = 0x0A0; // WO  used ring phys addr [31:0]
const MMIO_DEVICE_DESC_HI: usize = 0x0A4;
// Device-specific config space begins at 0x100
const MMIO_CONFIG_MAC:     usize = 0x100; // 6 bytes: MAC address

// ── Device status bits ────────────────────────────────────────────────────────

const S_ACKNOWLEDGE:  u32 = 1;
const S_DRIVER:       u32 = 2;
const S_DRIVER_OK:    u32 = 4;
const S_FEATURES_OK:  u32 = 8;
const S_FAILED:       u32 = 128;

// ── Feature bits ──────────────────────────────────────────────────────────────

const VIRTIO_NET_F_MAC:  u32 = 1 << 5;  // word 0
// We deliberately skip CSUM, GSO, MRG_RXBUF, STATUS — keep it simple.

// ── Virtqueue geometry ────────────────────────────────────────────────────────

const QUEUE_SIZE: usize = 16;

const VRING_DESC_F_NEXT:  u16 = 0x1;
const VRING_DESC_F_WRITE: u16 = 0x2;

// ── virtio-net header (prepended to every TX frame, filled by device on RX) ──

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

// ── Split-ring virtqueue structs ──────────────────────────────────────────────

#[repr(C, align(16))]
#[derive(Clone, Copy)]
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

#[repr(C, align(4))]
struct VirtqUsed {
    flags:       u16,
    idx:         u16,
    ring:        [UsedElem; QUEUE_SIZE],
    avail_event: u16,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct UsedElem { id: u32, len: u32 }

// ── Per-queue static storage (4 KiB aligned, identity-mapped) ────────────────

const RX_BUF_SIZE: usize = 1526; // 10 virtio hdr + 1514 max Ethernet + 2 pad

#[repr(C, align(4096))]
struct RxQueueMem {
    desc:  [VirtqDesc; QUEUE_SIZE],
    avail: VirtqAvail,
    _p1:   [u8; 4096 - core::mem::size_of::<VirtqAvail>() % 4096],
    used:  VirtqUsed,
    bufs:  [[u8; RX_BUF_SIZE]; QUEUE_SIZE],
}

#[repr(C, align(4096))]
struct TxQueueMem {
    // 2 descriptors per packet: one for the virtio-net header, one for data
    desc:  [VirtqDesc; QUEUE_SIZE * 2],
    avail: VirtqAvail,
    _p1:   [u8; 4096 - core::mem::size_of::<VirtqAvail>() % 4096],
    used:  VirtqUsed,
    hdrs:  [VirtioNetHdr; QUEUE_SIZE],
}

static mut RXQ: RxQueueMem = unsafe { core::mem::zeroed() };
static mut TXQ: TxQueueMem = unsafe { core::mem::zeroed() };

// ── Driver state ──────────────────────────────────────────────────────────────

struct DevState {
    mmio_base:     usize,
    plic_irq:      u32,
    rx_last_used:  u16,
    tx_last_used:  u16,
    tx_next_slot:  u16,
}

// Separate locks for TX and RX so a timer-tick poll never blocks a send.
static RX: Mutex<Option<DevState>> = Mutex::new(None);
static TX: Mutex<Option<DevState>> = Mutex::new(None);

// ── MMIO helpers ──────────────────────────────────────────────────────────────

#[inline(always)]
unsafe fn r32(base: usize, off: usize) -> u32 {
    ((base + off) as *const u32).read_volatile()
}

#[inline(always)]
unsafe fn w32(base: usize, off: usize, val: u32) {
    ((base + off) as *mut u32).write_volatile(val);
}

#[inline(always)]
unsafe fn r8(base: usize, off: usize) -> u8 {
    ((base + off) as *const u8).read_volatile()
}

// ── Queue initialisation ──────────────────────────────────────────────────────

unsafe fn setup_rxq(base: usize) {
    let q = &mut RXQ;

    for i in 0..QUEUE_SIZE {
        q.desc[i] = VirtqDesc {
            addr:  q.bufs[i].as_ptr() as u64,
            len:   RX_BUF_SIZE as u32,
            flags: VRING_DESC_F_WRITE, // device writes received frame here
            next:  0,
        };
        q.avail.ring[i] = i as u16;
    }
    q.avail.flags = 0;
    q.avail.idx   = QUEUE_SIZE as u16; // all descriptors pre-filled

    w32(base, MMIO_QUEUE_SEL,      0);
    w32(base, MMIO_QUEUE_NUM,      QUEUE_SIZE as u32);

    let desc_pa  = q.desc.as_ptr()  as u64;
    let avail_pa = (&q.avail as *const _) as u64;
    let used_pa  = (&q.used  as *const _) as u64;

    w32(base, MMIO_QUEUE_DESC_LO,  (desc_pa  & 0xFFFF_FFFF) as u32);
    w32(base, MMIO_QUEUE_DESC_HI,  (desc_pa  >> 32)          as u32);
    w32(base, MMIO_DRIVER_DESC_LO, (avail_pa & 0xFFFF_FFFF) as u32);
    w32(base, MMIO_DRIVER_DESC_HI, (avail_pa >> 32)          as u32);
    w32(base, MMIO_DEVICE_DESC_LO, (used_pa  & 0xFFFF_FFFF) as u32);
    w32(base, MMIO_DEVICE_DESC_HI, (used_pa  >> 32)          as u32);
    w32(base, MMIO_QUEUE_READY,    1);
}

unsafe fn setup_txq(base: usize) {
    let q = &mut TXQ;
    q.avail.flags = 0;
    q.avail.idx   = 0;

    w32(base, MMIO_QUEUE_SEL,      1);
    w32(base, MMIO_QUEUE_NUM,      (QUEUE_SIZE * 2) as u32);

    let desc_pa  = q.desc.as_ptr()  as u64;
    let avail_pa = (&q.avail as *const _) as u64;
    let used_pa  = (&q.used  as *const _) as u64;

    w32(base, MMIO_QUEUE_DESC_LO,  (desc_pa  & 0xFFFF_FFFF) as u32);
    w32(base, MMIO_QUEUE_DESC_HI,  (desc_pa  >> 32)          as u32);
    w32(base, MMIO_DRIVER_DESC_LO, (avail_pa & 0xFFFF_FFFF) as u32);
    w32(base, MMIO_DRIVER_DESC_HI, (avail_pa >> 32)          as u32);
    w32(base, MMIO_DEVICE_DESC_LO, (used_pa  & 0xFFFF_FFFF) as u32);
    w32(base, MMIO_DEVICE_DESC_HI, (used_pa  >> 32)          as u32);
    w32(base, MMIO_QUEUE_READY,    1);
}

// ── probe — called from fdt::fdt_phase2 ───────────────────────────────────────

/// Probe a virtio-mmio node discovered by the FDT walker.
/// `mmio_base` is the physical (identity-mapped) address; `plic_irq` is the
/// 1-based PLIC source number from the FDT `interrupts` property.
///
/// Silently returns if the node is not a virtio-net device.
pub fn probe(mmio_base: usize, plic_irq: u32) {
    unsafe {
        // Verify magic and device type.
        if r32(mmio_base, MMIO_MAGIC) != 0x7472_6976 { return; } // "virt"
        if r32(mmio_base, MMIO_DEVICE_ID) != 1       { return; } // not net

        crate::println!("virtio_net_mmio: found net device at {:#x} irq={}", mmio_base, plic_irq);

        // ── Initialisation sequence (virtio spec §3.1.1) ──────────────────

        // 1. Reset
        w32(mmio_base, MMIO_STATUS, 0);

        // 2. ACKNOWLEDGE + DRIVER
        w32(mmio_base, MMIO_STATUS, S_ACKNOWLEDGE | S_DRIVER);

        // 3. Feature negotiation — word 0 only, request MAC
        w32(mmio_base, MMIO_DEVICE_FEAT_SEL, 0);
        let dev_feat = r32(mmio_base, MMIO_DEVICE_FEATURES);
        w32(mmio_base, MMIO_DRIVER_FEAT_SEL, 0);
        w32(mmio_base, MMIO_DRIVER_FEATURES, dev_feat & VIRTIO_NET_F_MAC);

        // Word 1: explicitly clear — no high feature bits requested
        w32(mmio_base, MMIO_DRIVER_FEAT_SEL, 1);
        w32(mmio_base, MMIO_DRIVER_FEATURES, 0);

        // 4. FEATURES_OK
        w32(mmio_base, MMIO_STATUS, S_ACKNOWLEDGE | S_DRIVER | S_FEATURES_OK);
        fence(Ordering::SeqCst);
        if r32(mmio_base, MMIO_STATUS) & S_FEATURES_OK == 0 {
            w32(mmio_base, MMIO_STATUS, S_FAILED);
            crate::println!("virtio_net_mmio: FEATURES_OK not set — aborting");
            return;
        }

        // 5. Read MAC from device config space
        let mac = [
            r8(mmio_base, MMIO_CONFIG_MAC + 0),
            r8(mmio_base, MMIO_CONFIG_MAC + 1),
            r8(mmio_base, MMIO_CONFIG_MAC + 2),
            r8(mmio_base, MMIO_CONFIG_MAC + 3),
            r8(mmio_base, MMIO_CONFIG_MAC + 4),
            r8(mmio_base, MMIO_CONFIG_MAC + 5),
        ];
        crate::println!(
            "virtio_net_mmio: MAC {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
        );

        // Verify queue limits before committing.
        w32(mmio_base, MMIO_QUEUE_SEL, 0);
        if (r32(mmio_base, MMIO_QUEUE_NUM_MAX) as usize) < QUEUE_SIZE {
            w32(mmio_base, MMIO_STATUS, S_FAILED);
            crate::println!("virtio_net_mmio: QueueNumMax too small");
            return;
        }
        w32(mmio_base, MMIO_QUEUE_SEL, 1);
        if (r32(mmio_base, MMIO_QUEUE_NUM_MAX) as usize) < QUEUE_SIZE * 2 {
            w32(mmio_base, MMIO_STATUS, S_FAILED);
            crate::println!("virtio_net_mmio: TX QueueNumMax too small");
            return;
        }

        // 6. Set up virtqueues
        setup_rxq(mmio_base);
        setup_txq(mmio_base);

        // 7. DRIVER_OK
        w32(mmio_base, MMIO_STATUS,
            S_ACKNOWLEDGE | S_DRIVER | S_FEATURES_OK | S_DRIVER_OK);
        fence(Ordering::SeqCst);

        // 8. Kick RX queue so device sees pre-filled descriptors
        w32(mmio_base, MMIO_QUEUE_NOTIFY, 0);

        // 9. Enable PLIC interrupt source
        crate::arch::riscv64::plic::set_priority(plic_irq, 1);
        crate::arch::riscv64::plic::enable_irq(plic_irq);

        // 10. Stash state in both Mutex slots
        let mk = || Some(DevState {
            mmio_base,
            plic_irq,
            rx_last_used: 0,
            tx_last_used: 0,
            tx_next_slot: 0,
        });
        *RX.lock() = mk();
        *TX.lock() = mk();

        // 11. Register with NIC layer + set Ethernet MAC
        crate::net::eth::set_mac(mac);
        register_nic(NicDevice {
            send_frame: |f| send_frame(f),
            rx_poll:    || rx_poll(),
            mac,
        });

        crate::println!("virtio_net_mmio: ready");
    }
}

// ── send_frame ────────────────────────────────────────────────────────────────

/// Transmit one raw Ethernet frame (including Ethernet header, no FCS).
/// The frame slice must remain valid through the notify; QEMU consumes it
/// synchronously so we return immediately after the kick.
pub fn send_frame(frame: &[u8]) -> bool {
    if frame.is_empty() || frame.len() > 1514 { return false; }

    let mut guard = TX.lock();
    let st = match guard.as_mut() { Some(s) => s, None => return false };

    unsafe {
        let q    = &mut TXQ;
        let slot = st.tx_next_slot as usize % QUEUE_SIZE;

        // Reclaim used TX descriptors to avoid stalling.
        while q.used.idx != st.tx_last_used {
            st.tx_last_used = st.tx_last_used.wrapping_add(1);
        }

        let hdr_desc  = slot * 2;
        let data_desc = slot * 2 + 1;

        // Zero the virtio-net header (no GSO, no checksum offload needed).
        core::ptr::write_bytes(&mut q.hdrs[slot] as *mut VirtioNetHdr, 0, 1);

        // Desc 0: 10-byte virtio-net header, device-readable
        q.desc[hdr_desc] = VirtqDesc {
            addr:  &q.hdrs[slot] as *const VirtioNetHdr as u64,
            len:   NET_HDR_LEN as u32,
            flags: VRING_DESC_F_NEXT,
            next:  data_desc as u16,
        };

        // Desc 1: Ethernet frame data, device-readable
        q.desc[data_desc] = VirtqDesc {
            addr:  frame.as_ptr() as u64,
            len:   frame.len() as u32,
            flags: 0,
            next:  0,
        };

        // Publish head descriptor to the available ring.
        let avail_slot = q.avail.idx as usize % QUEUE_SIZE;
        q.avail.ring[avail_slot] = hdr_desc as u16;
        fence(Ordering::SeqCst);
        q.avail.idx = q.avail.idx.wrapping_add(1);
        fence(Ordering::SeqCst);

        // Kick transmitq (queue index 1).
        w32(st.mmio_base, MMIO_QUEUE_NOTIFY, 1);

        st.tx_next_slot = st.tx_next_slot.wrapping_add(1);
    }
    true
}

// ── rx_poll ───────────────────────────────────────────────────────────────────

/// Drain completed RX descriptors and push frames up to `eth::receive_frame`.
/// Called from `nic::rx_poll_all()` — timer tick or IRQ handler.
pub fn rx_poll() {
    let mut guard = RX.lock();
    let st = match guard.as_mut() { Some(s) => s, None => return };

    unsafe {
        let q    = &mut RXQ;
        let base = st.mmio_base;

        // Acknowledge interrupt status.
        let isr = r32(base, MMIO_INT_STATUS);
        if isr != 0 { w32(base, MMIO_INT_ACK, isr); }

        while q.used.idx != st.rx_last_used {
            let ui       = st.rx_last_used as usize % QUEUE_SIZE;
            let desc_idx = q.used.ring[ui].id  as usize;
            let pkt_len  = q.used.ring[ui].len as usize;
            st.rx_last_used = st.rx_last_used.wrapping_add(1);

            // Strip the 10-byte virtio-net header, pass raw Ethernet frame up.
            if pkt_len > NET_HDR_LEN {
                receive_frame(&q.bufs[desc_idx][NET_HDR_LEN..pkt_len]);
            }

            // Recycle descriptor: re-arm it and return to available ring.
            q.desc[desc_idx].flags = VRING_DESC_F_WRITE;
            q.desc[desc_idx].len   = RX_BUF_SIZE as u32;
            let avail_slot = q.avail.idx as usize % QUEUE_SIZE;
            q.avail.ring[avail_slot] = desc_idx as u16;
            fence(Ordering::SeqCst);
            q.avail.idx = q.avail.idx.wrapping_add(1);
            fence(Ordering::SeqCst);
        }

        // Re-kick RX queue so device sees the recycled descriptors.
        w32(base, MMIO_QUEUE_NOTIFY, 0);
    }
}

// ── irq_handler — called from trap::trap_handler ─────────────────────────────

/// External interrupt handler for this device's PLIC source.
/// Must be called by the trap handler when the claimed PLIC IRQ matches
/// this device's `plic_irq`.  Issues `plic::complete()` when done.
pub fn irq_handler(claimed_irq: u32) {
    // Delegate to the poll path — it acks MMIO_INT_STATUS internally.
    rx_poll();

    // Signal completion back to the PLIC.
    crate::arch::riscv64::plic::complete(claimed_irq);
}

/// Return this device's PLIC IRQ number (0 if not yet probed).
/// The trap handler uses this to route claimed IRQs.
pub fn plic_irq() -> u32 {
    RX.lock().as_ref().map(|s| s.plic_irq).unwrap_or(0)
}
