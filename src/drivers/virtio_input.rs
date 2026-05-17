//! virtio-input driver — keyboard and pointer devices under QEMU.
//!
//! ## Device
//!   PCI vendor 0x1AF4, device 0x1052 (virtio-input-pci).
//!   On RISC-V QEMU the same MMIO transport as virtio-net-mmio is used;
//!   both transports are implemented here via a shared `VirtioInputDev`.
//!
//! ## Virtqueues
//!   Queue 0 = eventq   — device writes input_event structs into it.
//!   Queue 1 = statusq  — driver writes LED/force-feedback; we ignore it.
//!
//! ## Wire format
//!   Each used descriptor carries one `virtio_input_event` (8 bytes):
//!     type  : u16  — EV_KEY=1, EV_REL=2, EV_ABS=3, EV_SYN=0
//!     code  : u16  — key/axis code
//!     value : i32  — 1=down, 0=up, 2=repeat / axis delta
//!
//! ## Integration
//!   Received events are forwarded to `evdev::push_event()`.
//!   The shell / TTY layer reads them via `evdev::pop_event()`.
//!
//! ## Discovery
//!   PCI: `init()` is called from kernel init after PCI enumeration.
//!   MMIO: `probe_mmio(base, irq)` is called from `fdt::fdt_phase2()`.

use core::sync::atomic::{fence, Ordering};
use spin::Mutex;

use crate::drivers::evdev::{push_event, EventType, InputEvent};

// ── virtio-input wire event (8 bytes) ─────────────────────────────────────────

#[repr(C)]
#[derive(Clone, Copy)]
struct VirtioInputEvent {
    typ:   u16,
    code:  u16,
    value: i32,
}

// ── virtio-input device sub-type selection (config select field) ──────────────

#[allow(dead_code)]
const VIRTIO_INPUT_CFG_UNSET:     u8 = 0x00;
const VIRTIO_INPUT_CFG_ID_NAME:   u8 = 0x01;
const VIRTIO_INPUT_CFG_EV_BITS:   u8 = 0x11;

// ── PCI identifiers ───────────────────────────────────────────────────────────

const VIRTIO_VENDOR:    u16 = 0x1AF4;
const VIRTIO_DEV_INPUT: u16 = 0x1052;

// ── MMIO register offsets (virtio spec §4.2.2) ────────────────────────────────

const MMIO_MAGIC:           usize = 0x000;
const MMIO_DEVICE_ID:       usize = 0x008; // 18 = input
const MMIO_DEVICE_FEAT_SEL: usize = 0x014;
const MMIO_DEVICE_FEATURES: usize = 0x010;
const MMIO_DRIVER_FEAT_SEL: usize = 0x024;
const MMIO_DRIVER_FEATURES: usize = 0x020;
const MMIO_QUEUE_SEL:       usize = 0x030;
const MMIO_QUEUE_NUM_MAX:   usize = 0x034;
const MMIO_QUEUE_NUM:       usize = 0x038;
const MMIO_QUEUE_READY:     usize = 0x044;
const MMIO_QUEUE_NOTIFY:    usize = 0x050;
const MMIO_INT_STATUS:      usize = 0x060;
const MMIO_INT_ACK:         usize = 0x064;
const MMIO_STATUS:          usize = 0x070;
const MMIO_QUEUE_DESC_LO:   usize = 0x080;
const MMIO_QUEUE_DESC_HI:   usize = 0x084;
const MMIO_DRIVER_DESC_LO:  usize = 0x090;
const MMIO_DRIVER_DESC_HI:  usize = 0x094;
const MMIO_DEVICE_DESC_LO:  usize = 0x0A0;
const MMIO_DEVICE_DESC_HI:  usize = 0x0A4;

// virtio-input config space (MMIO base + 0x100)
const MMIO_CFG_SELECT:      usize = 0x100;
const MMIO_CFG_SUBSEL:      usize = 0x101;
const MMIO_CFG_SIZE:        usize = 0x102;
// name string starts at 0x108 (u8 × 128)

// ── Device status bits ────────────────────────────────────────────────────────

const S_ACKNOWLEDGE: u32 = 1;
const S_DRIVER:      u32 = 2;
const S_DRIVER_OK:   u32 = 4;
const S_FEATURES_OK: u32 = 8;
const S_FAILED:      u32 = 128;

// ── Virtqueue geometry ────────────────────────────────────────────────────────

const QUEUE_SIZE: usize = 16;

const VRING_DESC_F_NEXT:  u16 = 0x1;
const VRING_DESC_F_WRITE: u16 = 0x2;

// ── Split-ring structs ────────────────────────────────────────────────────────

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

#[repr(C)]
#[derive(Clone, Copy)]
struct UsedElem { id: u32, len: u32 }

#[repr(C, align(4))]
struct VirtqUsed {
    flags:       u16,
    idx:         u16,
    ring:        [UsedElem; QUEUE_SIZE],
    avail_event: u16,
}

// ── Static queue storage ──────────────────────────────────────────────────────
// One set for keyboard, one for pointer — the two common virtio-input devices
// QEMU exposes. We support up to MAX_DEVS simultaneous devices.

const MAX_DEVS: usize = 4;

#[repr(C, align(4096))]
struct EventQueue {
    desc:  [VirtqDesc; QUEUE_SIZE],
    avail: VirtqAvail,
    _pad:  [u8; 4096 - core::mem::size_of::<VirtqAvail>() % 4096],
    used:  VirtqUsed,
    bufs:  [VirtioInputEvent; QUEUE_SIZE],
}

// Per-device state stored alongside its queue memory.
struct DevSlot {
    queue:    EventQueue,
    state:    Option<DevState>,
}

struct DevState {
    mmio_base:    usize,
    plic_irq:     u32,       // 0 on x86_64 PCI
    last_used:    u16,
    is_pointer:   bool,
}

// Static pool — zeroed at compile time.
static mut SLOTS: [DevSlot; MAX_DEVS] = unsafe { core::mem::zeroed() };

// Guards each slot independently.
static LOCKS: [Mutex<()>; MAX_DEVS] = [
    Mutex::new(()), Mutex::new(()), Mutex::new(()), Mutex::new(()),
];

// Next free slot index.
static NEXT_SLOT: core::sync::atomic::AtomicUsize =
    core::sync::atomic::AtomicUsize::new(0);

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

// ── Queue setup ───────────────────────────────────────────────────────────────

unsafe fn setup_eventq(slot: usize, base: usize) {
    let q = &mut SLOTS[slot].queue;

    // Pre-fill: every descriptor points at its matching event buffer.
    // Device writes 8-byte VirtioInputEvent structs into them.
    for i in 0..QUEUE_SIZE {
        q.desc[i] = VirtqDesc {
            addr:  &q.bufs[i] as *const VirtioInputEvent as u64,
            len:   core::mem::size_of::<VirtioInputEvent>() as u32,
            flags: VRING_DESC_F_WRITE,
            next:  0,
        };
        q.avail.ring[i] = i as u16;
    }
    q.avail.flags = 0;
    q.avail.idx   = QUEUE_SIZE as u16;

    // Program eventq (queue index 0)
    w32(base, MMIO_QUEUE_SEL,      0);
    w32(base, MMIO_QUEUE_NUM,      QUEUE_SIZE as u32);

    let desc_pa  = q.desc.as_ptr() as u64;
    let avail_pa = (&q.avail as *const _) as u64;
    let used_pa  = (&q.used  as *const _) as u64;

    w32(base, MMIO_QUEUE_DESC_LO,  (desc_pa  & 0xFFFF_FFFF) as u32);
    w32(base, MMIO_QUEUE_DESC_HI,  (desc_pa  >> 32)          as u32);
    w32(base, MMIO_DRIVER_DESC_LO, (avail_pa & 0xFFFF_FFFF) as u32);
    w32(base, MMIO_DRIVER_DESC_HI, (avail_pa >> 32)          as u32);
    w32(base, MMIO_DEVICE_DESC_LO, (used_pa  & 0xFFFF_FFFF) as u32);
    w32(base, MMIO_DEVICE_DESC_HI, (used_pa  >> 32)          as u32);
    w32(base, MMIO_QUEUE_READY,    1);

    // statusq (queue index 1) — we don't use it, just mark it ready
    // with size 0 so the device doesn't stall waiting for it.
    w32(base, MMIO_QUEUE_SEL,   1);
    w32(base, MMIO_QUEUE_NUM,   0);
    w32(base, MMIO_QUEUE_READY, 0); // leave inactive
}

// ── Device name query — tells us if this is a pointer device ─────────────────

unsafe fn read_device_name(base: usize) -> bool {
    // Write select=ID_NAME to config space, then read the name string.
    ((base + MMIO_CFG_SELECT) as *mut u8).write_volatile(VIRTIO_INPUT_CFG_ID_NAME);
    ((base + MMIO_CFG_SUBSEL) as *mut u8).write_volatile(0);
    fence(Ordering::SeqCst);

    let size = r8(base, MMIO_CFG_SIZE) as usize;
    if size == 0 || size > 128 { return false; }

    let mut name_buf = [0u8; 128];
    for i in 0..size {
        name_buf[i] = r8(base, 0x108 + i);
    }

    let name = core::str::from_utf8(&name_buf[..size]).unwrap_or("?");
    crate::println!("virtio_input: device name = \"{}\"", name);

    // Heuristic: QEMU names pointer devices "QEMU virtio-input-mouse-pci-XXX"
    // or "virtio-input-mouse". Keyboards say "keyboard".
    !name.to_ascii_lowercase().contains("keyboard")
}

// ── Shared probe core ─────────────────────────────────────────────────────────

unsafe fn do_probe(mmio_base: usize, plic_irq: u32) -> bool {
    // Verify magic + device ID 18 (virtio-input)
    if r32(mmio_base, MMIO_MAGIC) != 0x7472_6976 { return false; }
    if r32(mmio_base, MMIO_DEVICE_ID) != 18       { return false; }

    let slot = NEXT_SLOT.fetch_add(1, Ordering::Relaxed);
    if slot >= MAX_DEVS {
        crate::println!("virtio_input: MAX_DEVS ({}) exceeded", MAX_DEVS);
        return false;
    }

    crate::println!(
        "virtio_input: slot {} at {:#x} plic_irq={}",
        slot, mmio_base, plic_irq
    );

    // ── Init sequence ────────────────────────────────────────────────────────

    w32(mmio_base, MMIO_STATUS, 0);
    w32(mmio_base, MMIO_STATUS, S_ACKNOWLEDGE | S_DRIVER);

    // virtio-input has no interesting feature bits; accept nothing.
    w32(mmio_base, MMIO_DEVICE_FEAT_SEL, 0);
    w32(mmio_base, MMIO_DRIVER_FEAT_SEL, 0);
    w32(mmio_base, MMIO_DRIVER_FEATURES, 0);
    w32(mmio_base, MMIO_DRIVER_FEAT_SEL, 1);
    w32(mmio_base, MMIO_DRIVER_FEATURES, 0);

    w32(mmio_base, MMIO_STATUS, S_ACKNOWLEDGE | S_DRIVER | S_FEATURES_OK);
    fence(Ordering::SeqCst);
    if r32(mmio_base, MMIO_STATUS) & S_FEATURES_OK == 0 {
        w32(mmio_base, MMIO_STATUS, S_FAILED);
        return false;
    }

    // Check queue size.
    w32(mmio_base, MMIO_QUEUE_SEL, 0);
    if (r32(mmio_base, MMIO_QUEUE_NUM_MAX) as usize) < QUEUE_SIZE {
        w32(mmio_base, MMIO_STATUS, S_FAILED);
        return false;
    }

    // Read device name to identify pointer vs keyboard.
    let is_pointer = read_device_name(mmio_base);

    // Set up eventq.
    setup_eventq(slot, mmio_base);

    // DRIVER_OK
    w32(mmio_base, MMIO_STATUS,
        S_ACKNOWLEDGE | S_DRIVER | S_FEATURES_OK | S_DRIVER_OK);
    fence(Ordering::SeqCst);

    // Kick eventq — let device know descriptors are ready.
    w32(mmio_base, MMIO_QUEUE_NOTIFY, 0);

    // Store state.
    SLOTS[slot].state = Some(DevState {
        mmio_base,
        plic_irq,
        last_used: 0,
        is_pointer,
    });

    // Enable PLIC for RISC-V; no-op (irq=0) on x86_64 PCI path.
    if plic_irq != 0 {
        crate::arch::riscv64::plic::set_priority(plic_irq, 1);
        crate::arch::riscv64::plic::enable_irq(plic_irq);
    }

    crate::println!(
        "virtio_input: slot {} ready ({})",
        slot,
        if is_pointer { "pointer" } else { "keyboard" }
    );
    true
}

// ── MMIO probe — called from fdt::fdt_phase2 (RISC-V) ────────────────────────

/// Probe a `virtio,mmio` node discovered by the FDT walker.
/// `plic_irq` is the 1-based PLIC source from the FDT `interrupts` property.
pub fn probe_mmio(mmio_base: usize, plic_irq: u32) {
    unsafe { do_probe(mmio_base, plic_irq); }
}

// ── PCI probe — called from kernel init (x86_64) ──────────────────────────────

/// Scan the PCI bus for virtio-input devices and initialise each one.
/// Call after `pcie::enumerate()` is available.
pub fn init_pci() {
    use crate::drivers::pcie::{enumerate, cam_write32, cam_read32};

    for dev in enumerate() {
        if dev.vendor != VIRTIO_VENDOR || dev.device != VIRTIO_DEV_INPUT {
            continue;
        }

        // BAR0 for legacy virtio-input is an MMIO BAR (not I/O).
        let bar0 = dev.bars[0];
        let is_mem = (bar0 & 1) == 0;
        if !is_mem { continue; }

        let mmio_base = (bar0 & 0xFFFF_FFF0) as usize;
        if mmio_base == 0 { continue; }

        // Enable bus-master + MMIO decode.
        dev.enable_bus_master();
        dev.enable_mmio();

        unsafe { do_probe(mmio_base, 0 /* no PLIC on x86_64 */); }
    }
}

// ── Event draining ────────────────────────────────────────────────────────────

/// Drain completed eventq descriptors for one slot and push to evdev.
unsafe fn drain_slot(slot: usize) {
    let _guard = LOCKS[slot].lock();
    let s = match &mut SLOTS[slot].state {
        Some(s) => s,
        None    => return,
    };

    let q    = &mut SLOTS[slot].queue;
    let base = s.mmio_base;

    // Ack MMIO interrupt latch.
    let isr = r32(base, MMIO_INT_STATUS);
    if isr != 0 { w32(base, MMIO_INT_ACK, isr); }

    while q.used.idx != s.last_used {
        let ui       = s.last_used as usize % QUEUE_SIZE;
        let desc_idx = q.used.ring[ui].id as usize;
        let pkt_len  = q.used.ring[ui].len as usize;
        s.last_used  = s.last_used.wrapping_add(1);

        if pkt_len >= core::mem::size_of::<VirtioInputEvent>() {
            let ev = q.bufs[desc_idx];
            dispatch_event(ev, s.is_pointer);
        }

        // Recycle descriptor.
        q.desc[desc_idx].flags = VRING_DESC_F_WRITE;
        q.desc[desc_idx].len   = core::mem::size_of::<VirtioInputEvent>() as u32;
        let avail_slot = q.avail.idx as usize % QUEUE_SIZE;
        q.avail.ring[avail_slot] = desc_idx as u16;
        fence(Ordering::SeqCst);
        q.avail.idx = q.avail.idx.wrapping_add(1);
        fence(Ordering::SeqCst);
    }

    // Re-kick so device sees recycled descriptors.
    w32(base, MMIO_QUEUE_NOTIFY, 0);
}

// ── Event dispatch — wire event → evdev ──────────────────────────────────────

fn dispatch_event(ev: VirtioInputEvent, is_pointer: bool) {
    let etype = EventType::from_u16(ev.typ);

    match etype {
        // EV_SYN — pass through as SYN_REPORT
        EventType::Syn => {
            push_event(InputEvent { typ: EventType::Syn, code: ev.code, value: ev.value });
        }

        // EV_KEY — key press/release/repeat, or mouse button
        EventType::Key => {
            push_event(InputEvent { typ: EventType::Key, code: ev.code, value: ev.value });
            // Auto-generate SYN_REPORT after each key event.
            push_event(InputEvent { typ: EventType::Syn, code: 0, value: 0 });
        }

        // EV_REL — relative pointer motion / scroll wheel
        EventType::Rel => {
            push_event(InputEvent { typ: EventType::Rel, code: ev.code, value: ev.value });
        }

        // EV_ABS — absolute coordinates (tablet/touchscreen)
        EventType::Abs => {
            push_event(InputEvent { typ: EventType::Abs, code: ev.code, value: ev.value });
        }

        // Unknown type — drop silently.
        EventType::Unknown(_) => {}
    }

    // For pointer devices, generate a SYN_REPORT after every REL/ABS burst
    // (the device sends them before EV_SYN anyway, but be defensive).
    if is_pointer {
        if matches!(etype, EventType::Rel | EventType::Abs) {
            push_event(InputEvent { typ: EventType::Syn, code: 0, value: 0 });
        }
    }
}

// ── Poll — called from timer tick or nic::rx_poll_all equivalent ──────────────

/// Drain all registered virtio-input devices.
/// Call periodically (e.g. from the scheduler tick) or from each IRQ handler.
pub fn poll_all() {
    let count = NEXT_SLOT.load(Ordering::Relaxed);
    for slot in 0..count.min(MAX_DEVS) {
        unsafe { drain_slot(slot); }
    }
}

// ── IRQ handler — called from trap handler (RISC-V) ──────────────────────────

/// Called by the RISC-V trap handler when the PLIC claims an IRQ that
/// matches one of our registered devices.  Drains that device and
/// calls `plic::complete()`.
pub fn irq_handler(claimed_irq: u32) {
    let count = NEXT_SLOT.load(Ordering::Relaxed);
    for slot in 0..count.min(MAX_DEVS) {
        let matches = unsafe {
            SLOTS[slot].state.as_ref().map(|s| s.plic_irq == claimed_irq).unwrap_or(false)
        };
        if matches {
            unsafe { drain_slot(slot); }
            crate::arch::riscv64::plic::complete(claimed_irq);
            return;
        }
    }
    // IRQ didn't match any input slot — complete anyway to prevent lockup.
    crate::arch::riscv64::plic::complete(claimed_irq);
}

/// Return the PLIC IRQ for slot `n`, or 0 if not registered.
/// Used by the trap handler to build its dispatch table.
pub fn plic_irq(slot: usize) -> u32 {
    if slot >= MAX_DEVS { return 0; }
    unsafe { SLOTS[slot].state.as_ref().map(|s| s.plic_irq).unwrap_or(0) }
}
