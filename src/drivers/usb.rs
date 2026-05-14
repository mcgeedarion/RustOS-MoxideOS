//! xHCI USB 3.x host controller driver.
//!
//! ## Spec references
//!   - Intel xHCI Specification for USB rev 1.2 (§§ 4, 5, 6)
//!   - USB 2.0 spec §11 (hub / port logic)
//!   - USB HID spec §B (boot protocol)
//!
//! ## Architecture
//!
//! ```text
//!  PCIe BAR0 (MMIO)
//!    ├─ Capability regs  (base + 0)
//!    ├─ Operational regs (base + CAPLENGTH)
//!    ├─ Runtime regs     (base + RTSOFF)
//!    └─ Doorbell array   (base + DBOFF)
//!
//!  Memory structures (PMM, 64-byte aligned)
//!    ├─ DCBAA            Device Context Base Address Array
//!    ├─ Command Ring     producer-consumer TRB ring
//!    ├─ Event Ring       device → driver completions
//!    └─ Event Ring Seg   table (ERST)
//! ```
//!
//! ## Supported device classes
//!   - HID boot keyboard  (class 0x03, subclass 0x01, proto 0x01)
//!   - HID boot mouse     (class 0x03, subclass 0x01, proto 0x02)
//!
//! ## Public API
//!   xhci_probe()      — PCIe discovery + controller init
//!   xhci_irq()        — call from IDT at USB_XHCI_VECTOR
//!   USB_XHCI_VECTOR   — MSI-X vector constant

use core::sync::atomic::{fence, Ordering};
use crate::drivers::hid::{hid_kbd_report, hid_mouse_report};
use crate::drivers::pcie::{find_device_by_class, pci_enable_msix, pci_enable_msi_ex};
use crate::mm::pmm;
use spin::Mutex;

// ── IRQ vector ─────────────────────────────────────────────────────────────

pub const USB_XHCI_VECTOR: u8 = 0x31;

// ── PCI class codes ───────────────────────────────────────────────────────────

const USB_CLASS: u32 = 0x0C_03_30;

// ── xHCI Capability register offsets ─────────────────────────────────────────

const CAP_CAPLENGTH:   usize = 0x00;
const CAP_HCIVERSION:  usize = 0x02;
const CAP_HCSPARAMS1:  usize = 0x04;
const CAP_HCSPARAMS2:  usize = 0x08;
const CAP_HCCPARAMS1:  usize = 0x10;
const CAP_DBOFF:       usize = 0x14;
const CAP_RTSOFF:      usize = 0x18;

// ── xHCI Operational register offsets ───────────────────────────────────────

const OP_USBCMD:    usize = 0x00;
const OP_USBSTS:    usize = 0x04;
const OP_DNCTRL:    usize = 0x14;
const OP_CRCR_LO:   usize = 0x18;
const OP_CRCR_HI:   usize = 0x1C;
const OP_DCBAAP_LO: usize = 0x30;
const OP_DCBAAP_HI: usize = 0x34;
const OP_CONFIG:    usize = 0x38;
const OP_PORT_BASE: usize = 0x400;

const CMD_RUN:  u32 = 1 << 0;
const CMD_HCRST: u32 = 1 << 1;
const CMD_INTE: u32 = 1 << 2;
const CMD_HSEE: u32 = 1 << 3;
const STS_HCH:  u32 = 1 << 0;
const STS_CNR:  u32 = 1 << 11;
const PORTSC_CCS: u32 = 1 << 0;
const PORTSC_PR:  u32 = 1 << 4;
const PORTSC_PRC: u32 = 1 << 21;
const PORTSC_CSC: u32 = 1 << 17;
const PORTSC_PED: u32 = 1 << 1;

// ── Runtime register offsets ─────────────────────────────────────────────────

const RT_IMAN:      usize = 0x20;
const RT_IMOD:      usize = 0x24;
const RT_ERSTSZ:    usize = 0x28;
const RT_ERSTBA_LO: usize = 0x30;
const RT_ERSTBA_HI: usize = 0x34;
const RT_ERDP_LO:   usize = 0x38;
const RT_ERDP_HI:   usize = 0x3C;

// ── TRB types ────────────────────────────────────────────────────────────────

const TRB_NORMAL:       u32 = 1;
const TRB_SETUP_STAGE:  u32 = 2;
const TRB_DATA_STAGE:   u32 = 3;
const TRB_STATUS_STAGE: u32 = 4;
const TRB_LINK:         u32 = 6;
const TRB_NO_OP:        u32 = 8;
const TRB_ENABLE_SLOT:  u32 = 9;
const TRB_ADDRESS_DEV:  u32 = 11;
const TRB_CONFIG_EP:    u32 = 12;
const TRB_EV_TRANSFER:  u32 = 32;
const TRB_EV_CMD_COMPL: u32 = 33;
const TRB_EV_PORT_SC:   u32 = 34;
const TRB_C:   u32 = 1 << 0;
const TRB_TC:  u32 = 1 << 1;
const TRB_IOC: u32 = 1 << 5;
const TRB_IDT: u32 = 1 << 6;

// ── Ring sizes ────────────────────────────────────────────────────────────────

const CMD_RING_SIZE:   usize = 64;
const EVENT_RING_SIZE: usize = 256;
const XFER_RING_SIZE:  usize = 64;
const MAX_SLOTS:       usize = 32;
const MAX_PORTS:       usize = 16;

// ── TRB layout ───────────────────────────────────────────────────────────────

#[repr(C, align(16))]
#[derive(Clone, Copy, Default)]
struct Trb { param: u64, status: u32, ctrl: u32 }

impl Trb {
    fn trb_type(self) -> u32 { (self.ctrl >> 10) & 0x3F }
    fn cycle(self)    -> bool { self.ctrl & TRB_C != 0 }
}

#[repr(C, align(64))]
struct ErstEntry { base_lo: u32, base_hi: u32, size: u32, _rsvd: u32 }

const CTX_SIZE:  usize = 0x20;
const INPUT_CTX: usize = CTX_SIZE * 34;

// ── Ring buffer ─────────────────────────────────────────────────────────────

struct Ring { base: *mut Trb, size: usize, enq: usize, deq: usize, cycle: bool }

unsafe impl Send for Ring {}
unsafe impl Sync for Ring {}

impl Ring {
    const fn zeroed() -> Self {
        Self { base: core::ptr::null_mut(), size: 0, enq: 0, deq: 0, cycle: true }
    }

    unsafe fn alloc(&mut self, size: usize) {
        let bytes = size * core::mem::size_of::<Trb>();
        let pa = alloc_pages_zeroed((bytes + 4095) / 4096);
        self.base = pa as *mut Trb;
        self.size = size;
        self.enq  = 0;
        self.deq  = 0;
        self.cycle = true;
        let link = &mut *self.base.add(size - 1);
        link.param  = pa as u64;
        link.status = 0;
        link.ctrl   = (TRB_LINK << 10) | TRB_TC | if self.cycle { TRB_C } else { 0 };
    }

    unsafe fn push(&mut self, mut trb: Trb) {
        if self.cycle { trb.ctrl |= TRB_C; } else { trb.ctrl &= !TRB_C; }
        fence(Ordering::Release);
        *self.base.add(self.enq) = trb;
        self.enq += 1;
        if self.enq >= self.size - 1 {
            let link = &mut *self.base.add(self.size - 1);
            if self.cycle { link.ctrl |= TRB_C; } else { link.ctrl &= !TRB_C; }
            self.enq   = 0;
            self.cycle = !self.cycle;
        }
    }

    unsafe fn pop_event(&mut self) -> Option<Trb> {
        fence(Ordering::Acquire);
        let trb = *self.base.add(self.deq);
        if trb.cycle() != self.cycle { return None; }
        self.deq += 1;
        if self.deq >= self.size { self.deq = 0; self.cycle = !self.cycle; }
        Some(trb)
    }

    fn pa(&self) -> u64 { self.base as u64 }
}

// ── Per-slot state ───────────────────────────────────────────────────────────

#[derive(Clone, Copy, PartialEq, Eq)]
enum SlotState { Free, Addressing, Addressed, Configured, Polling }

#[derive(Clone, Copy, PartialEq, Eq)]
enum HidKind { None, Keyboard, Mouse }

struct Slot {
    state: SlotState, port: u8, kind: HidKind,
    xfer_ring: Ring, buf: *mut u8,
}

unsafe impl Send for Slot {}
unsafe impl Sync for Slot {}

impl Slot {
    const fn zeroed() -> Self {
        Self { state: SlotState::Free, port: 0, kind: HidKind::None,
               xfer_ring: Ring::zeroed(), buf: core::ptr::null_mut() }
    }
}

// ── Controller state ────────────────────────────────────────────────────────

struct Xhci {
    cap_base: usize, op_base: usize, rt_base: usize, db_base: usize,
    num_ports: u8,
    cmd_ring: Ring, event_ring: Ring, erst: *mut ErstEntry,
    dcbaa: *mut u64,
    pending_port: Option<u8>,
    slots: [Slot; MAX_SLOTS],
    slot_port: [u8; MAX_SLOTS + 1],
    cmd_cycle: bool,
}

unsafe impl Send for Xhci {}
unsafe impl Sync for Xhci {}

impl Xhci {
    const fn zeroed() -> Self {
        const SLOT_INIT: Slot = Slot::zeroed();
        Self {
            cap_base: 0, op_base: 0, rt_base: 0, db_base: 0,
            num_ports: 0,
            cmd_ring: Ring::zeroed(), event_ring: Ring::zeroed(),
            erst: core::ptr::null_mut(), dcbaa: core::ptr::null_mut(),
            pending_port: None,
            slots: [SLOT_INIT; MAX_SLOTS],
            slot_port: [0u8; MAX_SLOTS + 1],
            cmd_cycle: true,
        }
    }

    unsafe fn cap_read32(&self, off: usize)   -> u32 { r32(self.cap_base + off) }
    unsafe fn op_read32(&self,  off: usize)   -> u32 { r32(self.op_base  + off) }
    unsafe fn op_write32(&self, off: usize, v: u32)  { w32(self.op_base  + off, v) }
    unsafe fn rt_write32(&self, off: usize, v: u32)  { w32(self.rt_base  + off, v) }
    unsafe fn rt_read32(&self,  off: usize)   -> u32 { r32(self.rt_base  + off) }
    unsafe fn db_write32(&self, slot: usize, v: u32) { w32(self.db_base + slot * 4, v) }

    unsafe fn op_write64(&self, off: usize, v: u64) {
        w32(self.op_base + off,       v as u32);
        w32(self.op_base + off + 4, (v >> 32) as u32);
    }
    unsafe fn rt_write64(&self, off: usize, v: u64) {
        w32(self.rt_base + off,       v as u32);
        w32(self.rt_base + off + 4, (v >> 32) as u32);
    }
}

// ── MMIO helpers ────────────────────────────────────────────────────────────

#[inline] unsafe fn r32(a: usize) -> u32 { core::ptr::read_volatile(a as *const u32) }
#[inline] unsafe fn w32(a: usize, v: u32) { core::ptr::write_volatile(a as *mut u32, v) }

// ── PMM allocator shim ─────────────────────────────────────────────────────────

unsafe fn alloc_pages_zeroed(pages: usize) -> usize {
    let pa = pmm::alloc_pages(pages).expect("xhci: OOM");
    core::slice::from_raw_parts_mut(pa as *mut u8, pages * 4096).fill(0);
    pa
}

// ── Global instance ──────────────────────────────────────────────────────────

static XHCI: Mutex<Xhci> = Mutex::new(Xhci::zeroed());

// ── Probe ───────────────────────────────────────────────────────────────────

pub fn xhci_probe() {
    let dev = match find_device_by_class(USB_CLASS) {
        Some(d) => d,
        None    => { crate::println!("xhci: no xHCI controller found"); return; }
    };
    let bar0 = dev.bar64(0);
    crate::println!("xhci: BAR0 = {:#x}", bar0);
    unsafe { init_controller(bar0 as usize, &dev); }
}

unsafe fn init_controller(bar0: usize, dev: &crate::drivers::pcie::PciDevice) {
    let mut xhci = XHCI.lock();

    let caplength = (r32(bar0 + CAP_CAPLENGTH) & 0xFF) as usize;
    let hcsparams1 = r32(bar0 + CAP_HCSPARAMS1);
    let rtsoff = (r32(bar0 + CAP_RTSOFF) & !0x1F) as usize;
    let dboff  = (r32(bar0 + CAP_DBOFF)  & !0x03) as usize;

    xhci.cap_base  = bar0;
    xhci.op_base   = bar0 + caplength;
    xhci.rt_base   = bar0 + rtsoff;
    xhci.db_base   = bar0 + dboff;
    xhci.num_ports = (hcsparams1 >> 24) as u8;

    // Reset controller.
    xhci.op_write32(OP_USBCMD, CMD_HCRST);
    while xhci.op_read32(OP_USBCMD) & CMD_HCRST != 0 {}
    while xhci.op_read32(OP_USBSTS) & STS_CNR != 0 {}

    // Allocate DCBAA (256 entries × 8 bytes = 2KB).
    let dcbaa_pa = alloc_pages_zeroed(1);
    xhci.dcbaa = dcbaa_pa as *mut u64;
    xhci.op_write64(OP_DCBAAP_LO, dcbaa_pa as u64);

    // Command ring.
    xhci.cmd_ring.alloc(CMD_RING_SIZE);
    let crcr = xhci.cmd_ring.pa() | 1; // RCS=1
    w32(xhci.op_base + OP_CRCR_LO, crcr as u32);
    w32(xhci.op_base + OP_CRCR_HI, (crcr >> 32) as u32);

    // Event ring + ERST (single segment).
    xhci.event_ring.alloc(EVENT_RING_SIZE);
    let erst_pa = alloc_pages_zeroed(1);
    xhci.erst = erst_pa as *mut ErstEntry;
    let erst = &mut *xhci.erst;
    erst.base_lo = xhci.event_ring.pa() as u32;
    erst.base_hi = (xhci.event_ring.pa() >> 32) as u32;
    erst.size    = EVENT_RING_SIZE as u32;
    erst._rsvd   = 0;

    xhci.rt_write32(RT_ERSTSZ, 1);
    xhci.rt_write64(RT_ERSTBA_LO, erst_pa as u64);
    xhci.rt_write64(RT_ERDP_LO,   xhci.event_ring.pa());
    xhci.rt_write32(RT_IMAN, 3); // IE + IP

    // Configure MaxSlotsEn.
    xhci.op_write32(OP_CONFIG, MAX_SLOTS as u32);
    xhci.op_write32(OP_DNCTRL, 0xFFFF);

    // Enable MSI-X vector 0.
    pci_enable_msix(dev, 0, USB_XHCI_VECTOR);

    // Run!
    xhci.op_write32(OP_USBCMD, CMD_RUN | CMD_INTE | CMD_HSEE);
    while xhci.op_read32(OP_USBSTS) & STS_HCH != 0 {}
    crate::println!("xhci: controller running ({} ports)", xhci.num_ports);
}

// ── IRQ handler ──────────────────────────────────────────────────────────────

pub fn xhci_irq() {
    let mut xhci = XHCI.lock();
    unsafe {
        while let Some(trb) = xhci.event_ring.pop_event() {
            match trb.trb_type() {
                TRB_EV_PORT_SC  => handle_port_status_change(&mut xhci, trb),
                TRB_EV_CMD_COMPL => handle_command_completion(&mut xhci, trb),
                TRB_EV_TRANSFER => handle_transfer_event(&mut xhci, trb),
                _ => {}
            }
        }
        // Acknowledge interrupter: write ERDP with EHB=1.
        let erdp = xhci.event_ring.pa() + (xhci.event_ring.deq as u64) * 16;
        xhci.rt_write64(RT_ERDP_LO, erdp | (1 << 3));
        xhci.rt_write32(RT_IMAN, xhci.rt_read32(RT_IMAN) | 1);
    }
}

unsafe fn handle_port_status_change(xhci: &mut Xhci, trb: Trb) {
    let port = ((trb.param >> 24) & 0xFF) as u8;
    let portsc_off = OP_PORT_BASE + (port as usize - 1) * 0x10;
    let portsc = r32(xhci.op_base + portsc_off);

    // Clear all W1C bits.
    w32(xhci.op_base + portsc_off, portsc | PORTSC_CSC | PORTSC_PRC);

    if portsc & PORTSC_CCS != 0 {
        // Device connected — trigger port reset.
        w32(xhci.op_base + portsc_off, (portsc | PORTSC_PR) & !(PORTSC_PED));
        xhci.pending_port = Some(port);
    } else if portsc & PORTSC_PRC != 0 {
        // Reset complete — send Enable Slot command.
        if let Some(p) = xhci.pending_port {
            if p == port { send_enable_slot(xhci, port); }
        }
    }
}

unsafe fn send_enable_slot(xhci: &mut Xhci, port: u8) {
    // Find a free slot.
    let slot_id = match (1..MAX_SLOTS).find(|&i| xhci.slots[i].state == SlotState::Free) {
        Some(i) => i,
        None    => { crate::println!("xhci: no free slots"); return; }
    };
    xhci.slots[slot_id].state = SlotState::Addressing;
    xhci.slots[slot_id].port  = port;
    xhci.slot_port[slot_id]   = port;
    xhci.cmd_ring.push(Trb { param: 0, status: 0, ctrl: TRB_ENABLE_SLOT << 10 });
    xhci.db_write32(0, 0); // ring host controller doorbell
}

unsafe fn handle_command_completion(xhci: &mut Xhci, trb: Trb) {
    let completion_code = (trb.status >> 24) & 0xFF;
    let slot_id = ((trb.ctrl >> 24) & 0xFF) as usize;
    if completion_code != 1 {
        crate::println!("xhci: cmd completion code {} slot {}", completion_code, slot_id);
        return;
    }
    match xhci.slots.get(slot_id).map(|s| s.state) {
        Some(SlotState::Addressing) => send_address_device(xhci, slot_id),
        Some(SlotState::Addressed)  => send_configure_ep(xhci, slot_id),
        _ => {}
    }
}

unsafe fn send_address_device(xhci: &mut Xhci, slot_id: usize) {
    // Allocate Input Context and Device Context.
    let in_ctx  = alloc_pages_zeroed((INPUT_CTX + 4095) / 4096);
    let dev_ctx = alloc_pages_zeroed(1);

    // Pointer into input context: control context (entry 0), slot (1), EP0 (2).
    let ictx = in_ctx as *mut u32;
    // Add flags: A1 (slot) | A2 (EP0).
    ictx.add(1).write_volatile(0b110); // A1|A2

    // Slot context: root hub port, context entries = 1.
    let slot_ctx = (in_ctx + CTX_SIZE) as *mut u32;
    let port = xhci.slots[slot_id].port;
    slot_ctx.add(0).write_volatile((1 << 27) | ((port as u32) << 16)); // ctx_entries=1, port
    slot_ctx.add(1).write_volatile(0);

    // EP0 context: control endpoint, max packet size 8 (low-speed default).
    let ep0_ctx = (in_ctx + CTX_SIZE * 2) as *mut u32;
    ep0_ctx.add(0).write_volatile(0);
    ep0_ctx.add(1).write_volatile((4 << 3) | (3 << 1) | (8 << 16)); // ep_type=4 (ctrl), mps=8
    // TR dequeue pointer for EP0.
    xhci.slots[slot_id].xfer_ring.alloc(XFER_RING_SIZE);
    let tr_dq = xhci.slots[slot_id].xfer_ring.pa() | 1; // DCS=1
    ep0_ctx.add(2).write_volatile(tr_dq as u32);
    ep0_ctx.add(3).write_volatile((tr_dq >> 32) as u32);
    ep0_ctx.add(4).write_volatile(8); // average TRB length = 8

    // Install device context pointer in DCBAA.
    *xhci.dcbaa.add(slot_id) = dev_ctx as u64;

    xhci.slots[slot_id].state = SlotState::Addressed;
    xhci.cmd_ring.push(Trb {
        param:  in_ctx as u64,
        status: 0,
        ctrl:   (TRB_ADDRESS_DEV << 10) | ((slot_id as u32) << 24),
    });
    xhci.db_write32(0, 0);
}

unsafe fn send_configure_ep(xhci: &mut Xhci, slot_id: usize) {
    // Re-use an existing input context (simplified: allocate fresh).
    let in_ctx = alloc_pages_zeroed((INPUT_CTX + 4095) / 4096);
    let ictx   = in_ctx as *mut u32;
    ictx.add(1).write_volatile(0b110); // A1|A2

    // Slot context: route string, context entries = 1.
    let slot_ctx = (in_ctx + CTX_SIZE) as *mut u32;
    let port = xhci.slots[slot_id].port;
    slot_ctx.add(0).write_volatile((1 << 27) | ((port as u32) << 16));

    // Interrupt IN EP context (EP1 IN = index 3 in context array).
    let ep1_ctx = (in_ctx + CTX_SIZE * 3) as *mut u32;
    ep1_ctx.add(1).write_volatile((7 << 3) | (3 << 1) | (8 << 16)); // ep_type=7 (int IN)
    ep1_ctx.add(2).write_volatile(8); // avg TRB len
    ictx.add(1).write_volatile(0b1010); // A1|A3

    // Allocate interrupt IN transfer ring.
    xhci.slots[slot_id].xfer_ring.alloc(XFER_RING_SIZE);
    xhci.slots[slot_id].buf = alloc_pages_zeroed(1) as *mut u8;

    let tr_dq = xhci.slots[slot_id].xfer_ring.pa() | 1;
    ep1_ctx.add(2).write_volatile(tr_dq as u32);
    ep1_ctx.add(3).write_volatile((tr_dq >> 32) as u32);

    xhci.slots[slot_id].state = SlotState::Configured;
    xhci.cmd_ring.push(Trb {
        param:  in_ctx as u64,
        status: 0,
        ctrl:   (TRB_CONFIG_EP << 10) | ((slot_id as u32) << 24),
    });
    xhci.db_write32(0, 0);
}

unsafe fn handle_transfer_event(xhci: &mut Xhci, trb: Trb) {
    let slot_id = ((trb.ctrl >> 24) & 0xFF) as usize;
    if slot_id == 0 || slot_id >= MAX_SLOTS { return; }
    let slot = &mut xhci.slots[slot_id];
    if slot.buf.is_null() { return; }

    let len = 8usize; // HID boot report is always 8 bytes
    let report = core::slice::from_raw_parts(slot.buf, len);

    match slot.kind {
        HidKind::Keyboard => hid_kbd_report(report),
        HidKind::Mouse    => hid_mouse_report(report),
        HidKind::None     => {
            // First report: detect device type from report descriptor (simplified:
            // use EP interval / subclass stored in slot.port as placeholder).
            // For now, assume keyboard if byte 0 is modifier-like.
            slot.kind = if report[0] < 0x10 { HidKind::Keyboard } else { HidKind::Mouse };
        }
    }

    // Re-queue interrupt IN TRB.
    slot.xfer_ring.push(Trb {
        param:  slot.buf as u64,
        status: len as u32,
        ctrl:   (TRB_NORMAL << 10) | TRB_IOC,
    });
    // Ring EP1 IN doorbell.
    xhci.db_write32(slot_id, (1 << 16) | 1); // endpoint 1 IN
}
