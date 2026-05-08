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

use crate::drivers::pcie::{find_device_by_class, pci_enable_msix, pci_enable_msi_ex};
use crate::drivers::hid::{hid_kbd_report, hid_mouse_report};
use crate::mm::pmm;
use core::sync::atomic::{fence, Ordering};
use spin::Mutex;

// ── IRQ vector ───────────────────────────────────────────────────────────────

/// MSI-X entry 0 — xHCI event ring interrupt.
pub const USB_XHCI_VECTOR: u8 = 0x31;

// ── PCI class codes ──────────────────────────────────────────────────────────

/// PCI class 0x0C (Serial Bus), subclass 0x03 (USB), prog-if 0x30 (xHCI).
const USB_CLASS: u32 = 0x0C_03_30;

// ── xHCI Capability register offsets (from BAR0) ────────────────────────────

const CAP_CAPLENGTH:   usize = 0x00; // u8  — length of cap regs
const CAP_HCIVERSION:  usize = 0x02; // u16 — xHCI version
const CAP_HCSPARAMS1:  usize = 0x04; // u32 — MaxSlots[7:0], MaxIntrs[18:8], MaxPorts[31:24]
const CAP_HCSPARAMS2:  usize = 0x08; // u32
const CAP_HCCPARAMS1:  usize = 0x10; // u32
const CAP_DBOFF:       usize = 0x14; // u32 — doorbell array offset
const CAP_RTSOFF:      usize = 0x18; // u32 — runtime register set offset

// ── xHCI Operational register offsets (from base + CAPLENGTH) ───────────────

const OP_USBCMD:        usize = 0x00;
const OP_USBSTS:        usize = 0x04;
const OP_DNCTRL:        usize = 0x14;
const OP_CRCR_LO:       usize = 0x18;
const OP_CRCR_HI:       usize = 0x1C;
const OP_DCBAAP_LO:     usize = 0x30;
const OP_DCBAAP_HI:     usize = 0x34;
const OP_CONFIG:        usize = 0x38;
const OP_PORT_BASE:     usize = 0x400; // PORTSC for port N = OP_PORT_BASE + N*0x10

// USBCMD bits
const CMD_RUN:          u32 = 1 << 0;
const CMD_HCRST:        u32 = 1 << 1;
const CMD_INTE:         u32 = 1 << 2;
const CMD_HSEE:         u32 = 1 << 3;

// USBSTS bits
const STS_HCH:          u32 = 1 << 0;  // host controller halted
const STS_CNR:          u32 = 1 << 11; // controller not ready

// PORTSC bits
const PORTSC_CCS:       u32 = 1 << 0;  // current connect status
const PORTSC_PR:        u32 = 1 << 4;  // port reset
const PORTSC_PRC:       u32 = 1 << 21; // port reset change (W1C)
const PORTSC_CSC:       u32 = 1 << 17; // connect status change (W1C)
const PORTSC_PED:       u32 = 1 << 1;  // port enabled

// ── Runtime register offsets (from base + RTSOFF) ───────────────────────────

const RT_IMAN:    usize = 0x20;  // Interrupter Management
const RT_IMOD:    usize = 0x24;  // Interrupter Moderation
const RT_ERSTSZ:  usize = 0x28;  // Event Ring Segment Table Size
const RT_ERSTBA_LO: usize = 0x30;
const RT_ERSTBA_HI: usize = 0x34;
const RT_ERDP_LO: usize = 0x38;  // Event Ring Dequeue Pointer
const RT_ERDP_HI: usize = 0x3C;

// ── TRB types ────────────────────────────────────────────────────────────────

const TRB_NORMAL:        u32 = 1;
const TRB_SETUP_STAGE:   u32 = 2;
const TRB_DATA_STAGE:    u32 = 3;
const TRB_STATUS_STAGE:  u32 = 4;
const TRB_LINK:          u32 = 6;
const TRB_NO_OP:         u32 = 8;
const TRB_ENABLE_SLOT:   u32 = 9;
const TRB_ADDRESS_DEV:   u32 = 11;
const TRB_CONFIG_EP:     u32 = 12;
const TRB_EV_TRANSFER:   u32 = 32;
const TRB_EV_CMD_COMPL:  u32 = 33;
const TRB_EV_PORT_SC:    u32 = 34;

// TRB flags
const TRB_C:    u32 = 1 << 0;  // cycle bit
const TRB_TC:   u32 = 1 << 1;  // toggle cycle (Link TRB)
const TRB_IOC:  u32 = 1 << 5;  // interrupt on completion
const TRB_IDT:  u32 = 1 << 6;  // immediate data (Setup Stage)

// ── Ring sizes ───────────────────────────────────────────────────────────────

const CMD_RING_SIZE:   usize = 64;
const EVENT_RING_SIZE: usize = 256;
const XFER_RING_SIZE:  usize = 64;  // per endpoint
const MAX_SLOTS:       usize = 32;
const MAX_PORTS:       usize = 16;

// ── TRB layout ───────────────────────────────────────────────────────────────

/// A 16-byte Transfer Request Block.
#[repr(C, align(16))]
#[derive(Clone, Copy, Default)]
struct Trb {
    param:  u64,   // address or immediate data
    status: u32,   // transfer length, completion code, etc.
    ctrl:   u32,   // TRB type, flags, slot, endpoint
}

impl Trb {
    fn trb_type(self) -> u32 { (self.ctrl >> 10) & 0x3F }
    fn cycle(self)    -> bool { self.ctrl & TRB_C != 0 }
}

// ── ERST entry ───────────────────────────────────────────────────────────────

#[repr(C, align(64))]
struct ErstEntry {
    base_lo: u32,
    base_hi: u32,
    size:    u32,
    _rsvd:   u32,
}

// ── Input Context (simplified, 32-byte slot + 32-byte EP0) ───────────────────
// Full xHCI context is 2048 bytes (64-byte contexts × 32 entries).
// We use 64-byte context size (HCCPARAMS1.CSZ = 0, the QEMU default).

const CTX_SIZE:    usize = 0x20;  // 32 bytes per context entry
const INPUT_CTX:   usize = CTX_SIZE * 34;  // input control + 32 device ctx slots

// ── Ring buffer ──────────────────────────────────────────────────────────────

struct Ring {
    base:   *mut Trb,
    size:   usize,
    enq:    usize,  // next write index
    deq:    usize,  // next read index (event ring only)
    cycle:  bool,   // producer cycle state
}

unsafe impl Send for Ring {}
unsafe impl Sync for Ring {}

impl Ring {
    const fn zeroed() -> Self {
        Self { base: core::ptr::null_mut(), size: 0, enq: 0, deq: 0, cycle: true }
    }

    unsafe fn alloc(&mut self, size: usize) {
        let bytes = size * core::mem::size_of::<Trb>();
        let pages = (bytes + 4095) / 4096;
        let pa = alloc_pages_zeroed(pages);
        self.base  = pa as *mut Trb;
        self.size  = size;
        self.enq   = 0;
        self.deq   = 0;
        self.cycle = true;
        // Install Link TRB at last slot to make it circular.
        let link = &mut *self.base.add(size - 1);
        link.param  = pa as u64;
        link.status = 0;
        link.ctrl   = (TRB_LINK << 10) | TRB_TC | if self.cycle { TRB_C } else { 0 };
    }

    /// Push one TRB; advances enq, wrapping via the Link TRB.
    unsafe fn push(&mut self, mut trb: Trb) {
        if self.cycle { trb.ctrl |= TRB_C; } else { trb.ctrl &= !TRB_C; }
        fence(Ordering::Release);
        *self.base.add(self.enq) = trb;
        self.enq += 1;
        // Skip the Link TRB slot (last entry).
        if self.enq >= self.size - 1 {
            // Update Link TRB cycle bit.
            let link = &mut *self.base.add(self.size - 1);
            if self.cycle { link.ctrl |= TRB_C; } else { link.ctrl &= !TRB_C; }
            self.enq   = 0;
            self.cycle = !self.cycle;
        }
    }

    /// Pop one event TRB from the event ring (consumer side).
    /// Returns None if no event is available.
    unsafe fn pop_event(&mut self) -> Option<Trb> {
        fence(Ordering::Acquire);
        let trb = *self.base.add(self.deq);
        // Event TRBs are owned by the driver when their cycle bit matches.
        if trb.cycle() != self.cycle { return None; }
        self.deq += 1;
        if self.deq >= self.size {
            self.deq   = 0;
            self.cycle = !self.cycle;
        }
        Some(trb)
    }

    fn pa(&self) -> u64 { self.base as u64 }
}

// ── Per-slot (device) state ───────────────────────────────────────────────────

#[derive(Clone, Copy, PartialEq, Eq)]
enum SlotState {
    Free,
    Addressing,  // Enable Slot sent, waiting for slot ID
    Addressed,   // Address Device sent
    Configured,  // Configure Endpoint sent; HID enumeration done
    Polling,     // Active; interrupt IN polling running
}

/// HID device type discovered during enumeration.
#[derive(Clone, Copy, PartialEq, Eq)]
enum HidKind {
    None,
    Keyboard,
    Mouse,
}

struct Slot {
    state:      SlotState,
    port:       u8,
    kind:       HidKind,
    xfer_ring:  Ring,
    /// Bounce buffer for interrupt IN data (one page).
    buf:        *mut u8,
}

unsafe impl Send for Slot {}
unsafe impl Sync for Slot {}

impl Slot {
    const fn zeroed() -> Self {
        Self {
            state:     SlotState::Free,
            port:      0,
            kind:      HidKind::None,
            xfer_ring: Ring::zeroed(),
            buf:       core::ptr::null_mut(),
        }
    }
}

// ── Controller state ──────────────────────────────────────────────────────────

struct Xhci {
    cap_base: usize,  // BAR0
    op_base:  usize,  // cap_base + CAPLENGTH
    rt_base:  usize,  // cap_base + RTSOFF
    db_base:  usize,  // cap_base + DBOFF
    num_ports: u8,

    cmd_ring:   Ring,
    event_ring: Ring,
    erst:       *mut ErstEntry,

    dcbaa:      *mut u64,  // 256 × u64

    /// Pending port that triggered connection; processed in irq handler.
    pending_port: Option<u8>,

    slots: [Slot; MAX_SLOTS],

    /// Map: slot_id → port (for command completion routing).
    slot_port: [u8; MAX_SLOTS + 1],

    /// Cycle state for command ring completions.
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
            cmd_ring:   Ring::zeroed(),
            event_ring: Ring::zeroed(),
            erst:       core::ptr::null_mut(),
            dcbaa:      core::ptr::null_mut(),
            pending_port: None,
            slots:      [SLOT_INIT; MAX_SLOTS],
            slot_port:  [0u8; MAX_SLOTS + 1],
            cmd_cycle:  true,
        }
    }
}

static XHCI: Mutex<Option<Xhci>> = Mutex::new(None);

// ── PMM helpers ───────────────────────────────────────────────────────────────

fn alloc_pages_zeroed(n: usize) -> usize {
    let first = pmm::alloc_page().expect("xhci: OOM");
    for _ in 1..n { pmm::alloc_page().expect("xhci: OOM"); }
    unsafe { core::ptr::write_bytes(first as *mut u8, 0, n * 4096); }
    first
}

// ── MMIO helpers ──────────────────────────────────────────────────────────────

#[inline] unsafe fn mm_r8 (b: usize, o: usize) -> u8  { core::ptr::read_volatile((b+o) as *const u8)  }
#[inline] unsafe fn mm_r16(b: usize, o: usize) -> u16 { core::ptr::read_volatile((b+o) as *const u16) }
#[inline] unsafe fn mm_r32(b: usize, o: usize) -> u32 { core::ptr::read_volatile((b+o) as *const u32) }
#[inline] unsafe fn mm_w32(b: usize, o: usize, v: u32) { core::ptr::write_volatile((b+o) as *mut u32, v) }
#[inline] unsafe fn mm_r64(b: usize, o: usize) -> u64 { core::ptr::read_volatile((b+o) as *const u64) }
#[inline] unsafe fn mm_w64(b: usize, o: usize, v: u64) { core::ptr::write_volatile((b+o) as *mut u64, v) }

// ── Probe & init ──────────────────────────────────────────────────────────────

/// Locate the first xHCI controller via PCIe class scan and initialise it.
/// Call after pcie_init() from kernel_main.
pub fn xhci_probe() -> bool {
    let dev = match find_device_by_class(USB_CLASS) {
        Some(d) => d,
        None    => { log!("xhci: no controller found"); return false; }
    };

    dev.enable();
    let bar0 = match dev.bar_mmio(0) {
        Some(b) => b as usize,
        None    => { log!("xhci: BAR0 missing"); return false; }
    };

    if !pci_enable_msix(&dev, 0, USB_XHCI_VECTOR, 0) {
        pci_enable_msi_ex(&dev, 0, USB_XHCI_VECTOR);
    }

    unsafe { init(bar0) }
}

unsafe fn init(cap: usize) -> bool {
    let caplength  = mm_r8(cap,  CAP_CAPLENGTH) as usize;
    let op         = cap + caplength;
    let hciver     = mm_r16(cap, CAP_HCIVERSION);
    let hcsp1      = mm_r32(cap, CAP_HCSPARAMS1);
    let num_ports  = (hcsp1 >> 24) as u8;
    let max_slots  = (hcsp1 & 0xFF) as u8;
    let dboff      = mm_r32(cap, CAP_DBOFF) as usize;
    let rtsoff     = mm_r32(cap, CAP_RTSOFF) as usize;
    let rt         = cap + rtsoff;
    let db         = cap + dboff;

    log!("xhci: ver {:#06x}  ports={}  slots={}", hciver, num_ports, max_slots);

    // ── Reset ────────────────────────────────────────────────────────────────
    // 1. Halt: clear RUN, wait for HCH.
    mm_w32(op, OP_USBCMD, mm_r32(op, OP_USBCMD) & !CMD_RUN);
    for _ in 0..1_000_000 {
        if mm_r32(op, OP_USBSTS) & STS_HCH != 0 { break; }
        core::hint::spin_loop();
    }
    // 2. Reset.
    mm_w32(op, OP_USBCMD, CMD_HCRST);
    for _ in 0..1_000_000 {
        if mm_r32(op, OP_USBCMD) & CMD_HCRST == 0 { break; }
        core::hint::spin_loop();
    }
    for _ in 0..1_000_000 {
        if mm_r32(op, OP_USBSTS) & STS_CNR == 0 { break; }
        core::hint::spin_loop();
    }

    // ── DCBAA ────────────────────────────────────────────────────────────────
    let dcbaa_pa = alloc_pages_zeroed(1);
    let dcbaa    = dcbaa_pa as *mut u64;
    mm_w64(op, OP_DCBAAP_LO, dcbaa_pa as u64);

    // ── Command ring ─────────────────────────────────────────────────────────
    let mut cmd_ring = Ring::zeroed();
    cmd_ring.alloc(CMD_RING_SIZE);
    // CRCR: PA | RCS (cycle state = 1)
    mm_w64(op, OP_CRCR_LO, cmd_ring.pa() | 1);

    // ── Event ring ───────────────────────────────────────────────────────────
    let mut event_ring = Ring::zeroed();
    event_ring.alloc(EVENT_RING_SIZE);

    // ERST (one segment).
    let erst_pa = alloc_pages_zeroed(1);
    let erst    = erst_pa as *mut ErstEntry;
    (*erst).base_lo = (event_ring.pa() & 0xFFFF_FFFF) as u32;
    (*erst).base_hi = (event_ring.pa() >> 32) as u32;
    (*erst).size    = EVENT_RING_SIZE as u32;

    // Programme interrupter 0.
    mm_w32(rt, RT_ERSTSZ, 1);
    mm_w64(rt, RT_ERSTBA_LO, erst_pa as u64);
    mm_w64(rt, RT_ERDP_LO, event_ring.pa());
    mm_w32(rt, RT_IMOD, 0x000F_4000); // ~1ms moderation
    mm_w32(rt, RT_IMAN, mm_r32(rt, RT_IMAN) | 0x3); // IP + IE

    // ── Config: MaxSlotsEn ───────────────────────────────────────────────────
    mm_w32(op, OP_CONFIG, max_slots as u32);
    mm_w32(op, OP_DNCTRL, 0xFFFF);

    // ── Start ────────────────────────────────────────────────────────────────
    mm_w32(op, OP_USBCMD, CMD_RUN | CMD_INTE | CMD_HSEE);
    for _ in 0..1_000_000 {
        if mm_r32(op, OP_USBSTS) & STS_HCH == 0 { break; }
        core::hint::spin_loop();
    }

    let xhci = Xhci {
        cap_base: cap,
        op_base:  op,
        rt_base:  rt,
        db_base:  db,
        num_ports,
        cmd_ring,
        event_ring,
        erst,
        dcbaa,
        pending_port: None,
        slots: { const S: Slot = Slot::zeroed(); [S; MAX_SLOTS] },
        slot_port: [0u8; MAX_SLOTS + 1],
        cmd_cycle: true,
    };

    *XHCI.lock() = Some(xhci);
    log!("xhci: controller running");

    // Initial port scan — detect already-connected devices.
    port_scan_all();
    true
}

// ── Port management ───────────────────────────────────────────────────────────

fn port_scan_all() {
    let mut guard = XHCI.lock();
    let Some(xhci) = guard.as_mut() else { return; };
    let np = xhci.num_ports as usize;
    let op = xhci.op_base;
    unsafe {
        for p in 0..np.min(MAX_PORTS) {
            let portsc = mm_r32(op, OP_PORT_BASE + p * 0x10);
            if portsc & PORTSC_CCS != 0 {
                port_reset(xhci, p as u8);
            }
        }
    }
}

unsafe fn port_reset(xhci: &mut Xhci, port: u8) {
    let portsc_off = OP_PORT_BASE + port as usize * 0x10;
    let portsc = mm_r32(xhci.op_base, portsc_off);
    // Assert port reset (W1S).
    mm_w32(xhci.op_base, portsc_off,
           (portsc & !0x00FE_0000) | PORTSC_PR); // preserve non-RW1C bits, clear W1C
    log!("xhci: port {} reset", port);
}

unsafe fn port_connect(xhci: &mut Xhci, port: u8) {
    let portsc_off = OP_PORT_BASE + port as usize * 0x10;
    let portsc = mm_r32(xhci.op_base, portsc_off);
    if portsc & PORTSC_CCS == 0 {
        log!("xhci: port {} disconnect", port);
        return;
    }
    if portsc & PORTSC_PED == 0 {
        // Port not enabled — issue reset.
        port_reset(xhci, port);
        return;
    }
    // Port enabled after reset: send Enable Slot command.
    let trb = Trb {
        param:  0,
        status: 0,
        ctrl:   TRB_ENABLE_SLOT << 10,
    };
    xhci.cmd_ring.push(trb);
    // Remember which port this slot request is for (slot not assigned yet;
    // use a temporary mapping in pending_port).
    xhci.pending_port = Some(port);
    // Ring host controller doorbell (doorbell 0 = host, value 0).
    core::ptr::write_volatile(xhci.db_base as *mut u32, 0);
    log!("xhci: port {} enable-slot sent", port);
}

// ── USB control transfer helpers ──────────────────────────────────────────────

/// Send a USB SETUP + optional DATA + STATUS sequence on the default control
/// pipe (endpoint 0) of `slot_id`.
///
/// setup_data: 8 bytes of USB Setup packet (little-endian).
/// data_buf:   optional bounce buffer for IN data stage.
/// data_len:   length of data stage (0 = no data stage).
unsafe fn control_transfer(
    xhci:     &mut Xhci,
    slot_id:  usize,
    setup:    [u8; 8],
    data_buf: *mut u8,
    data_len: u32,
    is_in:    bool,
) {
    let slot = &mut xhci.slots[slot_id];

    // Setup Stage TRB — immediate data, 8 bytes.
    let setup_u64 = u64::from_le_bytes(setup);
    let trt: u32 = if data_len == 0 { 0 } else if is_in { 3 } else { 2 }; // TRT field
    let setup_trb = Trb {
        param:  setup_u64,
        status: 8,  // TRB transfer length
        ctrl:   (TRB_SETUP_STAGE << 10) | TRB_IDT | TRB_IOC | (trt << 16),
    };
    slot.xfer_ring.push(setup_trb);

    // Data Stage TRB (optional).
    if data_len > 0 {
        let dir_bit: u32 = if is_in { 1 << 16 } else { 0 };
        let data_trb = Trb {
            param:  data_buf as u64,
            status: data_len,
            ctrl:   (TRB_DATA_STAGE << 10) | TRB_IOC | dir_bit,
        };
        slot.xfer_ring.push(data_trb);
    }

    // Status Stage TRB.
    let status_dir: u32 = if data_len == 0 || !is_in { 1 << 16 } else { 0 };
    let status_trb = Trb {
        param:  0,
        status: 0,
        ctrl:   (TRB_STATUS_STAGE << 10) | TRB_IOC | status_dir,
    };
    slot.xfer_ring.push(status_trb);

    // Ring endpoint 1 (EP0) doorbell for this slot.
    let db_addr = (xhci.db_base + slot_id * 4) as *mut u32;
    core::ptr::write_volatile(db_addr, 1); // doorbell target = EP1 (ctrl)
}

// ── HID enumeration sequence ──────────────────────────────────────────────────

/// Step 1: allocate transfer ring + input context, send Address Device.
unsafe fn enumerate_slot(xhci: &mut Xhci, slot_id: usize, port: u8) {
    let slot = &mut xhci.slots[slot_id];
    slot.state = SlotState::Addressing;
    slot.port  = port;

    // Allocate transfer ring for EP0.
    slot.xfer_ring.alloc(XFER_RING_SIZE);

    // Allocate input context (2 pages to be safe).
    let ctx_pa = alloc_pages_zeroed(1);
    let ctx    = ctx_pa as *mut u32;

    // Input control context: A0 = slot context, A1 = EP0 context.
    *ctx.add(1) = 0x0000_0003; // A[1:0] set

    // Slot context: root hub port number, 1 context entry.
    let slot_ctx = ctx.add(8);  // offset 0x20 (input control = 0x00)
    *slot_ctx     = (1 << 27) | ((port as u32 + 1) << 16); // context entries=1, root_port

    // EP0 context: max packet size 8, EP type = Control (4), TR dequeue PA.
    let ep0_ctx = ctx.add(16); // offset 0x40
    *ep0_ctx.add(1) = (8 << 16) | (4 << 3); // MaxPacketSize=8, EPType=Control
    let deq_pa = slot.xfer_ring.pa() | 1; // DCS=1
    *ep0_ctx.add(2) = (deq_pa & 0xFFFF_FFFF) as u32;
    *ep0_ctx.add(3) = (deq_pa >> 32) as u32;

    // Programme DCBAA: slot_id → output device context.
    let out_ctx_pa = alloc_pages_zeroed(1);
    *xhci.dcbaa.add(slot_id) = out_ctx_pa as u64;
    fence(Ordering::Release);

    // Address Device command.
    let trb = Trb {
        param:  ctx_pa as u64,
        status: 0,
        ctrl:   (TRB_ADDRESS_DEV << 10) | ((slot_id as u32) << 24),
    };
    xhci.cmd_ring.push(trb);
    core::ptr::write_volatile(xhci.db_base as *mut u32, 0);
    xhci.slot_port[slot_id] = port;
}

/// Step 2: send GET_DESCRIPTOR(Device) to learn max packet size + class.
unsafe fn get_descriptor(xhci: &mut Xhci, slot_id: usize) {
    let slot  = &mut xhci.slots[slot_id];
    if slot.buf.is_null() {
        slot.buf = alloc_pages_zeroed(1) as *mut u8;
    }
    // GET_DESCRIPTOR: bmRequestType=0x80, bRequest=6, wValue=0x0100 (Device),
    //                 wIndex=0, wLength=18.
    let setup: [u8; 8] = [0x80, 0x06, 0x00, 0x01, 0x00, 0x00, 18, 0x00];
    slot.state = SlotState::Addressed;
    control_transfer(xhci, slot_id, setup, slot.buf, 18, true);
}

/// Step 3 (called from Transfer Event): parse device descriptor, send
/// GET_DESCRIPTOR(Config) then SET_PROTOCOL(boot).
unsafe fn process_device_descriptor(xhci: &mut Xhci, slot_id: usize) {
    let slot = &mut xhci.slots[slot_id];
    let buf  = slot.buf;
    if buf.is_null() { return; }
    // bDeviceClass @ offset 4.
    let class = *buf.add(4);
    // If class==0, check interface class via config descriptor.
    // For HID boot devices, class is often 0 at device level.
    // Just request config descriptor and parse interface.
    let setup: [u8; 8] = [0x80, 0x06, 0x00, 0x02, 0x00, 0x00, 64, 0x00]; // GET_DESCRIPTOR(Config, 64 bytes)
    let _ = class;
    control_transfer(xhci, slot_id, setup, slot.buf, 64, true);
}

/// Step 4: parse config descriptor, identify HID boot class, send SET_PROTOCOL.
unsafe fn process_config_descriptor(xhci: &mut Xhci, slot_id: usize) {
    let slot = &mut xhci.slots[slot_id];
    let buf  = slot.buf;
    if buf.is_null() { return; }

    // Walk descriptors to find interface with class=HID(3), subclass=1, proto=1/2.
    let total_len = u16::from_le_bytes([*buf.add(2), *buf.add(3)]) as usize;
    let mut off = 0usize;
    let mut hid_kind = HidKind::None;
    let mut ep_addr  = 0u8;

    while off + 2 <= total_len.min(64) {
        let len  = *buf.add(off) as usize;
        let typ  = *buf.add(off + 1);
        if len == 0 { break; }
        if typ == 0x04 && off + 9 <= 64 {
            // Interface descriptor.
            let cls  = *buf.add(off + 5);
            let sub  = *buf.add(off + 6);
            let prot = *buf.add(off + 7);
            if cls == 3 && sub == 1 {
                hid_kind = if prot == 1 { HidKind::Keyboard } else { HidKind::Mouse };
            }
        }
        if typ == 0x05 && off + 7 <= 64 {
            // Endpoint descriptor — save the interrupt IN address.
            let addr = *buf.add(off + 2);
            if addr & 0x80 != 0 { ep_addr = addr & 0x0F; } // IN endpoint
        }
        off += len;
    }

    slot.kind = hid_kind;
    if hid_kind == HidKind::None { return; }

    log!("xhci: slot {} is {:?} HID, ep_in={}", slot_id,
         if hid_kind == HidKind::Keyboard { "keyboard" } else { "mouse" },
         ep_addr);

    // SET_PROTOCOL(boot = 0) — interface 0, protocol 0.
    let setup: [u8; 8] = [0x21, 0x0B, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
    control_transfer(xhci, slot_id, setup, core::ptr::null_mut(), 0, false);
    slot.state = SlotState::Configured;

    // Schedule the first interrupt IN transfer to start polling.
    if ep_addr > 0 {
        schedule_interrupt_in(xhci, slot_id, ep_addr);
    }
}

/// Post one Normal TRB on the interrupt IN transfer ring.
unsafe fn schedule_interrupt_in(xhci: &mut Xhci, slot_id: usize, ep_addr: u8) {
    let slot = &mut xhci.slots[slot_id];
    let report_size: u32 = if slot.kind == HidKind::Keyboard { 8 } else { 4 };

    let trb = Trb {
        param:  slot.buf as u64,
        status: report_size,
        ctrl:   (TRB_NORMAL << 10) | TRB_IOC,
    };
    slot.xfer_ring.push(trb);
    slot.state = SlotState::Polling;

    // Ring endpoint doorbell: ep_addr maps to xHCI DCI = (ep_addr * 2) + 1 for IN.
    let dci = (ep_addr as u32) * 2 + 1;
    let db_addr = (xhci.db_base + slot_id * 4) as *mut u32;
    core::ptr::write_volatile(db_addr, dci);
}

// ── IRQ handler ───────────────────────────────────────────────────────────────

/// Call from IDT at USB_XHCI_VECTOR.
pub fn xhci_irq() {
    let mut guard = XHCI.lock();
    let Some(xhci) = guard.as_mut() else { return; };
    unsafe { drain_events(xhci); }
}

unsafe fn drain_events(xhci: &mut Xhci) {
    let rt = xhci.rt_base;

    while let Some(trb) = xhci.event_ring.pop_event() {
        match trb.trb_type() {
            TRB_EV_CMD_COMPL => handle_cmd_completion(xhci, &trb),
            TRB_EV_TRANSFER  => handle_transfer_event(xhci, &trb),
            TRB_EV_PORT_SC   => handle_port_sc(xhci, &trb),
            _                => {}
        }
    }

    // Update event ring dequeue pointer (clear EHB).
    let deq_pa = xhci.event_ring.pa()
        + xhci.event_ring.deq as u64 * core::mem::size_of::<Trb>() as u64;
    mm_w64(rt, RT_ERDP_LO, deq_pa | (1 << 3)); // EHB

    // Clear IP in IMAN.
    mm_w32(rt, RT_IMAN, mm_r32(rt, RT_IMAN));
}

unsafe fn handle_cmd_completion(xhci: &mut Xhci, trb: &Trb) {
    let slot_id  = ((trb.ctrl >> 24) & 0xFF) as usize;
    let trb_type_orig = (mm_r32(trb.param as usize, 0) >> 10) & 0x3F; // TRB that generated this
    let cc       = (trb.status >> 24) & 0xFF;  // completion code

    if cc != 1 {
        log!("xhci: cmd completion slot={} cc={}", slot_id, cc);
        return;
    }

    match trb_type_orig {
        TRB_ENABLE_SLOT => {
            // slot_id is the newly assigned slot.
            if let Some(port) = xhci.pending_port.take() {
                enumerate_slot(xhci, slot_id, port);
            }
        }
        TRB_ADDRESS_DEV => {
            get_descriptor(xhci, slot_id);
        }
        _ => {}
    }
}

unsafe fn handle_transfer_event(xhci: &mut Xhci, trb: &Trb) {
    let slot_id = ((trb.ctrl >> 24) & 0xFF) as usize;
    if slot_id == 0 || slot_id >= MAX_SLOTS { return; }
    let slot = &mut xhci.slots[slot_id];
    let cc   = (trb.status >> 24) & 0xFF;

    if cc != 1 && cc != 13 { // 1=success, 13=short packet
        log!("xhci: xfer event slot={} cc={}", slot_id, cc);
        return;
    }

    match slot.state {
        SlotState::Addressed => {
            // Completed GET_DESCRIPTOR(Device) → next step.
            process_device_descriptor(xhci, slot_id);
        }
        SlotState::Addressing => {
            // Completed GET_DESCRIPTOR(Config).
            process_config_descriptor(xhci, slot_id);
        }
        SlotState::Polling => {
            // Interrupt IN data ready — dispatch to HID layer.
            if !slot.buf.is_null() {
                let report_size: usize = if slot.kind == HidKind::Keyboard { 8 } else { 4 };
                let report = core::slice::from_raw_parts(slot.buf, report_size);
                match slot.kind {
                    HidKind::Keyboard => hid_kbd_report(report),
                    HidKind::Mouse    => hid_mouse_report(report),
                    HidKind::None     => {}
                }
            }
            // Re-schedule next poll.
            let ep_addr = (trb.ctrl & 0x1F) as u8; // endpoint ID from event
            schedule_interrupt_in(xhci, slot_id, ep_addr);
        }
        _ => {}
    }
}

unsafe fn handle_port_sc(xhci: &mut Xhci, trb: &Trb) {
    // Port number is 1-based in TRB param field bits [31:24].
    let port1 = ((trb.param >> 24) & 0xFF) as u8;
    let port  = port1.saturating_sub(1);
    let portsc_off = OP_PORT_BASE + port as usize * 0x10;
    let portsc = mm_r32(xhci.op_base, portsc_off);

    // Clear all W1C change bits.
    mm_w32(xhci.op_base, portsc_off,
           portsc & !0x00FE_0000 | PORTSC_CSC | PORTSC_PRC);

    log!("xhci: port SC port={} portsc={:#010x}", port, portsc);

    if portsc & PORTSC_PRC != 0 {
        // Port reset complete — port should now be enabled.
        port_connect(xhci, port);
    } else if portsc & PORTSC_CSC != 0 {
        // Connect status changed.
        port_reset(xhci, port);
    }
}

// ── log! shim ─────────────────────────────────────────────────────────────────

macro_rules! log {
    ($($t:tt)*) => {
        crate::arch::x86_64::serial::serial_println!($($t)*)
    };
}
use log;
