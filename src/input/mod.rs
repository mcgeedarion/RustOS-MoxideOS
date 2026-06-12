//! Linux-compatible evdev input layer for RustOS.
//!
//! # Feature gate
//!
//! This module is compiled only when `--features input_events` is passed.
//! The gate is applied at `src/lib.rs` (`#[cfg(feature = "input_events")] pub
//! mod input`). When `kernel-drivers` is split into its own crate this becomes
//! a native feature of that crate, re-exported from the root as:
//!
//! ```toml
//! input_events = ["kernel-drivers/input_events"]
//! ```
//!
//! # Architecture
//!
//! ```text
//!  IRQ / virtio-input driver
//!         │
//!         ▼
//!  InputDeviceRegistry::dispatch_*()     ← single call-site per HW event
//!         │  appends InputEvent to EvdevRingBuf
//!         │  wakes WaitQueue
//!         ▼
//!  EventNode (FileOps impl)              ← one per /dev/input/eventN fd
//!    read()  → drain ring → copy_to_user
//!    poll()  → POLLIN when ring non-empty
//!    ioctl() → EVIOCGID / EVIOCGNAME / EVIOCGBIT
//! ```
//!
//! The ring buffer is a power-of-2 SPSC queue with `AtomicU32` head/tail so
//! the producer (interrupt context) never spins waiting for the consumer.  On
//! overflow the oldest event is silently dropped — identical to Linux evdev.

#![allow(dead_code)]

use alloc::{string::String, sync::Arc, vec::Vec};
use core::{
    cell::UnsafeCell,
    sync::atomic::{AtomicU32, Ordering},
};

pub const EV_SYN: u16 = 0x00;
pub const EV_KEY: u16 = 0x01;
pub const EV_REL: u16 = 0x02;
pub const EV_ABS: u16 = 0x03;
pub const EV_MSC: u16 = 0x04;
pub const EV_LED: u16 = 0x11;
pub const EV_MAX: u16 = 0x1f;

pub const SYN_REPORT: u16 = 0;
pub const SYN_DROPPED: u16 = 3;

pub const REL_X: u16 = 0x00;
pub const REL_Y: u16 = 0x01;
pub const REL_WHEEL: u16 = 0x08;

pub const BTN_LEFT: u16 = 0x110;
pub const BTN_RIGHT: u16 = 0x111;
pub const BTN_MIDDLE: u16 = 0x112;

/// KEY_MAX — highest key code; bitmask sent by EVIOCGBIT(EV_KEY) is
/// ceil((KEY_MAX+1)/8) = 96 bytes.  Standard for a full PC keyboard.
pub const KEY_MAX: u16 = 767;

/// `struct input_event` wire format.  Must stay `repr(C)` and 24 bytes so
/// userspace can `read(fd, buf, 24*N)` and get exactly N events.
#[derive(Clone, Copy, Debug, Default)]
#[repr(C)]
pub struct InputEvent {
    /// Seconds component of timestamp.  Set to 0 at the kernel layer;
    /// userspace that cares can stamp with `clock_gettime(CLOCK_MONOTONIC)`.
    pub tv_sec: i64,
    /// Microseconds component of timestamp.
    pub tv_usec: i64,
    /// Event type (EV_KEY, EV_REL, …)
    pub r#type: u16,
    /// Event code (key scancode, REL_X, …)
    pub code: u16,
    /// Event value (1 = press, 0 = release, ±delta for relative axes)
    pub value: i32,
}

const _: () = assert!(core::mem::size_of::<InputEvent>() == 24);

const RING_CAP: usize = 256; // must be power of two
const RING_MASK: u32 = (RING_CAP - 1) as u32;

/// Single-producer (driver/IRQ), single-consumer (reader task) ring buffer.
///
/// Overflow policy: when the ring is full the *oldest* event is silently
/// dropped and `tail` advanced, matching Linux evdev behaviour.  A synthetic
/// `SYN_DROPPED` event is prepended to the next batch so userspace knows it
/// missed events.
pub struct EvdevRingBuf {
    buf: [UnsafeCell<InputEvent>; RING_CAP],
    /// Index of the next slot to write (producer owns)
    head: AtomicU32,
    /// Index of the next slot to read (consumer owns)
    tail: AtomicU32,
    dropped: AtomicU32,
}

// SAFETY: The ring is accessed only through the atomic head/tail protocol.
// No two threads write to the same slot simultaneously.
unsafe impl Sync for EvdevRingBuf {}
unsafe impl Send for EvdevRingBuf {}

impl EvdevRingBuf {
    pub const fn new() -> Self {
        // SAFETY: InputEvent is POD; zero-init is valid.
        Self {
            buf: unsafe {
                core::mem::transmute([0u8; core::mem::size_of::<InputEvent>() * RING_CAP])
            },
            head: AtomicU32::new(0),
            tail: AtomicU32::new(0),
            dropped: AtomicU32::new(0),
        }
    }

    /// Push one event.  Called from interrupt context — must not allocate or
    /// block.  Drops the oldest event on overflow.
    pub fn push(&self, ev: InputEvent) {
        let head = self.head.load(Ordering::Relaxed);
        let tail = self.tail.load(Ordering::Acquire);
        let used = head.wrapping_sub(tail);
        if used >= RING_CAP as u32 {
            // Ring full: discard oldest event by advancing tail.
            self.tail.fetch_add(1, Ordering::Release);
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
        let slot = (head & RING_MASK) as usize;
        // SAFETY: slot is within bounds; no other writer touches this slot
        // because head is owned by the producer.
        unsafe {
            *self.buf[slot].get() = ev;
        }
        self.head.fetch_add(1, Ordering::Release);
    }

    /// Pop one event.  Returns `None` when the ring is empty.
    pub fn pop(&self) -> Option<InputEvent> {
        let tail = self.tail.load(Ordering::Relaxed);
        let head = self.head.load(Ordering::Acquire);
        if tail == head {
            return None;
        }
        let slot = (tail & RING_MASK) as usize;
        // SAFETY: slot is within bounds; the producer has finished writing
        // this slot (head > tail implies the Acquire on head synchronises
        // with the Release in push).
        let ev = unsafe { *self.buf[slot].get() };
        self.tail.fetch_add(1, Ordering::Release);
        Some(ev)
    }

    /// Returns `true` if at least one event is available to read.
    #[inline]
    pub fn is_readable(&self) -> bool {
        self.tail.load(Ordering::Relaxed) != self.head.load(Ordering::Acquire)
    }

    /// Number of events that were dropped due to ring overflow since the
    /// last call to `drain_dropped()`.
    pub fn drain_dropped(&self) -> u32 {
        self.dropped.swap(0, Ordering::Relaxed)
    }
}

#[derive(Clone, Debug)]
pub struct DeviceInfo {
    /// Kernel-visible name, e.g. "RustOS Virtual Keyboard"
    pub name: String,
    /// Input bus type (BUS_VIRTUAL = 0x06)
    pub bustype: u16,
    pub vendor: u16,
    pub product: u16,
    pub version: u16,
}

impl DeviceInfo {
    pub fn keyboard() -> Self {
        Self {
            name: String::from("RustOS Virtual Keyboard"),
            bustype: 0x06, // BUS_VIRTUAL
            vendor: 0x0001,
            product: 0x0001,
            version: 0x0111, // evdev protocol version
        }
    }

    pub fn mouse() -> Self {
        Self {
            name: String::from("RustOS Virtual Mouse"),
            bustype: 0x06,
            vendor: 0x0001,
            product: 0x0002,
            version: 0x0111,
        }
    }
}

/// Evdev capability bitmask for `EVIOCGBIT`.
///
/// Each bit N being set means the device can generate that event code.
/// We keep one `CapBits` per event type (EV_KEY, EV_REL, …).  The byte
/// count is `ceil((max_code + 1) / 8)`.
#[derive(Clone, Default)]
pub struct CapBits(Vec<u8>);

impl CapBits {
    pub fn new(bits: usize) -> Self {
        Self(alloc::vec![0u8; (bits + 7) / 8])
    }

    pub fn set(&mut self, code: u16) {
        let byte = (code / 8) as usize;
        let bit = code % 8;
        if byte < self.0.len() {
            self.0[byte] |= 1 << bit;
        }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

pub struct InputDevice {
    pub info: DeviceInfo,
    pub ring: EvdevRingBuf,
    /// Bitmask of supported event types (bit N = EV_* code N is supported)
    pub ev_bits: CapBits,
    /// Supported key codes (EVIOCGBIT(EV_KEY, …))
    pub key_bits: CapBits,
    /// Supported relative axes (EVIOCGBIT(EV_REL, …))
    pub rel_bits: CapBits,
    /// WaitQueue: readers that called `poll()` or blocking `read()` sleep
    /// here until the producer calls `wake_all()`.
    pub waitq: crate::sync::WaitQueue,
}

impl InputDevice {
    pub fn new_keyboard() -> Self {
        let mut ev = CapBits::new((EV_MAX + 1) as usize);
        ev.set(EV_SYN);
        ev.set(EV_KEY);
        ev.set(EV_MSC);

        // Set every key from KEY_ESC(1) through KEY_MICMUTE(248) plus the
        // function keys, media keys, and BTN_MISC range so xkbcommon does
        // not complain about missing capabilities.
        let mut key = CapBits::new((KEY_MAX + 1) as usize);
        for k in 1u16..=248 {
            key.set(k);
        } // KEY_ESC … KEY_MICMUTE
        for k in 256u16..=767 {
            key.set(k);
        } // BTN_MISC … KEY_MAX

        Self {
            info: DeviceInfo::keyboard(),
            ring: EvdevRingBuf::new(),
            ev_bits: ev,
            key_bits: key,
            rel_bits: CapBits::new(0),
            waitq: crate::sync::WaitQueue::new(),
        }
    }

    pub fn new_mouse() -> Self {
        let mut ev = CapBits::new((EV_MAX + 1) as usize);
        ev.set(EV_SYN);
        ev.set(EV_KEY);
        ev.set(EV_REL);

        let mut key = CapBits::new((BTN_MIDDLE + 1) as usize);
        key.set(BTN_LEFT);
        key.set(BTN_RIGHT);
        key.set(BTN_MIDDLE);

        let mut rel = CapBits::new((REL_WHEEL + 1) as usize);
        rel.set(REL_X);
        rel.set(REL_Y);
        rel.set(REL_WHEEL);

        Self {
            info: DeviceInfo::mouse(),
            ring: EvdevRingBuf::new(),
            ev_bits: ev,
            key_bits: key,
            rel_bits: rel,
            waitq: crate::sync::WaitQueue::new(),
        }
    }

    /// Push a single event and wake any sleeping readers.
    pub fn push_event(&self, ev: InputEvent) {
        self.ring.push(ev);
        self.waitq.wake_all();
    }

    /// Convenience: push a typed event then a SYN_REPORT.
    pub fn push_and_sync(&self, r#type: u16, code: u16, value: i32) {
        self.push_event(InputEvent {
            r#type,
            code,
            value,
            ..Default::default()
        });
        self.push_event(InputEvent {
            r#type: EV_SYN,
            code: SYN_REPORT,
            value: 0,
            ..Default::default()
        });
    }
}

const MAX_DEVICES: usize = 16;

/// Indices into `REGISTRY` for the two synthetic devices registered during
/// `init()`.  Exposed so the compositor's `WAYLAND_INPUT_FD` can open
/// `/dev/input/event0` (keyboard) and `/dev/input/event1` (mouse) by name.
pub const KBD_MINOR: usize = 0;
pub const MOUSE_MINOR: usize = 1;

struct Registry {
    devices: [Option<InputDevice>; MAX_DEVICES],
    count: usize,
}

impl Registry {
    const fn empty() -> Self {
        Self {
            devices: [
                None, None, None, None, None, None, None, None, None, None, None, None, None, None,
                None, None,
            ],
            count: 0,
        }
    }
}

// SAFETY: modified only before any other CPU can observe it (single-threaded
// init) and thereafter immutable for the device slots themselves.  The ring
// buffers are internally synchronised via atomics.
static mut REGISTRY: Registry = Registry::empty();

/// Register a new input device and return its minor number (0-based index
/// into `/dev/input/eventN`).
///
/// # Panics
/// Panics if more than `MAX_DEVICES` devices are registered.
pub fn register_device(dev: InputDevice) -> usize {
    // SAFETY: called only from init, before SMP is up.
    let reg = unsafe { &mut REGISTRY };
    assert!(reg.count < MAX_DEVICES, "too many input devices");
    let minor = reg.count;
    reg.devices[minor] = Some(dev);
    reg.count += 1;
    minor
}

/// Returns a reference to the device at `minor`, or `None`.
pub fn device(minor: usize) -> Option<&'static InputDevice> {
    // SAFETY: devices are inserted during init and never removed.
    unsafe { REGISTRY.devices[minor].as_ref() }
}

/// Number of registered devices (equals the highest minor + 1).
pub fn device_count() -> usize {
    unsafe { REGISTRY.count }
}

/// Dispatch a raw keyboard scancode to `/dev/input/event0` (KBD_MINOR).
///
/// `scancode` is the raw evdev key code (XT scancode translated to evdev).
/// `pressed` is `true` for key-down, `false` for key-up.
pub fn dispatch_key(scancode: u8, pressed: bool) {
    if let Some(dev) = device(KBD_MINOR) {
        dev.push_and_sync(EV_KEY, scancode as u16, if pressed { 1 } else { 0 });
    }
}

/// Dispatch a relative mouse movement + button state to `/dev/input/event1`.
///
/// `buttons` is a bitmask: bit 0 = left, bit 1 = right, bit 2 = middle.
pub fn dispatch_mouse(dx: i8, dy: i8, buttons: u8) {
    let Some(dev) = device(MOUSE_MINOR) else {
        return;
    };
    if dx != 0 {
        dev.push_event(InputEvent {
            r#type: EV_REL,
            code: REL_X,
            value: dx as i32,
            ..Default::default()
        });
    }
    if dy != 0 {
        dev.push_event(InputEvent {
            r#type: EV_REL,
            code: REL_Y,
            value: dy as i32,
            ..Default::default()
        });
    }
    // Emit button events for left, right, middle
    let btn_codes = [BTN_LEFT, BTN_RIGHT, BTN_MIDDLE];
    for (i, &code) in btn_codes.iter().enumerate() {
        let pressed = (buttons >> i) & 1;
        dev.push_event(InputEvent {
            r#type: EV_KEY,
            code,
            value: pressed as i32,
            ..Default::default()
        });
    }
    // Terminating SYN_REPORT
    dev.push_event(InputEvent {
        r#type: EV_SYN,
        code: SYN_REPORT,
        value: 0,
        ..Default::default()
    });
    dev.waitq.wake_all();
}

/// A file-description backed by one `InputDevice`.  One `EventNode` is
/// created per `open()` so each fd has its own read position (they all
/// share the device ring, but in practice only the compositor reads it).
///
/// This intentionally does **not** implement per-fd ring isolation.  A full
/// implementation would clone events into per-fd rings on `open()`; for an
/// MVP compositor that holds the single fd that is unnecessary.
pub struct EventNode {
    minor: usize,
}

impl EventNode {
    pub fn new(minor: usize) -> Self {
        Self { minor }
    }
}

use crate::fs::vfs_ops::{FileOps, PollFlags};
use crate::mm::UserBuffer;

impl FileOps for EventNode {
    /// Read as many `InputEvent` structs as fit in the user buffer.
    ///
    /// Behaviour:
    /// - If events are available, copies them out and returns the byte count.
    /// - If none are available and `O_NONBLOCK` is set, returns `EAGAIN`.
    /// - If none are available and the fd is blocking, sleeps on the device wait-queue until the
    ///   next `push_event` / `wake_all`.
    fn read(&self, buf: &mut UserBuffer, flags: u32) -> Result<usize, i32> {
        const EAGAIN: i32 = 11;
        const O_NONBLOCK: u32 = 0o4000;
        const EV_SIZE: usize = core::mem::size_of::<InputEvent>(); // 24

        let dev = device(self.minor).ok_or(-EAGAIN)?;

        // Emit a synthetic SYN_DROPPED at the front of the read if overflow
        // occurred since the last read.
        let dropped = dev.ring.drain_dropped();
        let mut n_written = 0usize;

        if dropped > 0 {
            let syn_drop = InputEvent {
                r#type: EV_SYN,
                code: SYN_DROPPED,
                value: dropped as i32,
                ..Default::default()
            };
            let bytes =
                unsafe { core::slice::from_raw_parts(&syn_drop as *const _ as *const u8, EV_SIZE) };
            if buf.remaining() >= EV_SIZE {
                buf.write_bytes(bytes)?;
                n_written += EV_SIZE;
            }
        }

        // Blocking loop: wait until at least one event is readable.
        loop {
            while dev.ring.is_readable() && buf.remaining() >= EV_SIZE {
                let ev = dev.ring.pop().unwrap();
                let bytes =
                    unsafe { core::slice::from_raw_parts(&ev as *const _ as *const u8, EV_SIZE) };
                buf.write_bytes(bytes)?;
                n_written += EV_SIZE;
            }

            if n_written > 0 {
                return Ok(n_written);
            }

            if flags & O_NONBLOCK != 0 {
                return Err(-EAGAIN);
            }

            // Sleep until the producer wakes us.
            dev.waitq.wait_until(|| dev.ring.is_readable());
        }
    }

    /// Returns `POLLIN | POLLRDNORM` when the ring has data, zero otherwise.
    fn poll(&self) -> PollFlags {
        match device(self.minor) {
            Some(dev) if dev.ring.is_readable() => PollFlags::POLLIN | PollFlags::POLLRDNORM,
            _ => PollFlags::empty(),
        }
    }

    /// Handle evdev-specific ioctls.
    ///
    /// Implemented:
    /// - `EVIOCGID`      (0x_8008_4502) — write `input_id` struct (8 bytes)
    /// - `EVIOCGNAME(N)` (0x_4NNN_4506) — copy device name, NUL-terminated
    /// - `EVIOCGBIT(0)`  (0x_41ff_4520) — event-type capability bitmask
    /// - `EVIOCGBIT(1)`  (0x_41ff_4521) — EV_KEY capability bitmask
    /// - `EVIOCGBIT(2)`  (0x_41ff_4522) — EV_REL capability bitmask
    fn ioctl(&self, request: u32, arg: usize) -> Result<i32, i32> {
        const ENOTTY: i32 = 25;
        let dev = device(self.minor).ok_or(-ENOTTY)?;

        // EVIOCGID  = _IOR('E', 0x02, struct input_id)  → 8 bytes
        //           = 0x80084502 on x86-64
        const EVIOCGID: u32 = 0x8008_4502;

        // EVIOCGBIT(ev_type, len) uses the upper 13 bits for len and is
        // typically 0x41ff4520 | ev_type for len=255.  We match on the
        // lower 16 bits (request & 0xffff) to be length-agnostic.
        const EVIOCGBIT_BASE: u32 = 0x4520; // & 0xffff
        const EVIOCGNAME_BASE: u32 = 0x4506; // & 0xffff

        match request {
            EVIOCGID => {
                // struct input_id { bustype, vendor, product, version } (4×u16)
                #[repr(C)]
                struct InputId {
                    bustype: u16,
                    vendor: u16,
                    product: u16,
                    version: u16,
                }
                let id = InputId {
                    bustype: dev.info.bustype,
                    vendor: dev.info.vendor,
                    product: dev.info.product,
                    version: dev.info.version,
                };
                unsafe {
                    let dst = arg as *mut InputId;
                    dst.write(id);
                }
                Ok(0)
            },
            r if (r & 0xffff) == EVIOCGNAME_BASE => {
                let max_len = ((r >> 16) & 0x3fff) as usize;
                let name = dev.info.name.as_bytes();
                let copy_len = name.len().min(max_len.saturating_sub(1));
                unsafe {
                    core::ptr::copy_nonoverlapping(name.as_ptr(), arg as *mut u8, copy_len);
                    *((arg + copy_len) as *mut u8) = 0; // NUL terminator
                }
                Ok((copy_len + 1) as i32)
            },
            r if (r & 0xffff) >= EVIOCGBIT_BASE
                && (r & 0xffff) <= EVIOCGBIT_BASE + EV_MAX as u32 =>
            {
                let ev_type = (r & 0xffff) - EVIOCGBIT_BASE;
                let max_bytes = ((r >> 16) & 0x3fff) as usize;
                let bits: &[u8] = match ev_type as u16 {
                    0 => dev.ev_bits.as_bytes(),
                    EV_KEY => dev.key_bits.as_bytes(),
                    EV_REL => dev.rel_bits.as_bytes(),
                    _ => return Err(-ENOTTY),
                };
                let copy_len = bits.len().min(max_bytes);
                unsafe {
                    core::ptr::copy_nonoverlapping(bits.as_ptr(), arg as *mut u8, copy_len);
                }
                Ok(copy_len as i32)
            },
            _ => Err(-ENOTTY),
        }
    }

    fn write(&self, _buf: &crate::mm::UserBuffer, _flags: u32) -> Result<usize, i32> {
        // evdev write (for LED / force-feedback) not yet implemented.
        Err(-1) // EPERM
    }

    fn close(&self) { // nothing to do; per-fd ring isolation not yet
                      // implemented
    }
}

/// Register the two synthetic input devices (keyboard + mouse) and return
/// their minor indices.  Called from `kernel_main` before `devfs::init()`.
pub fn init() {
    let kbd_minor = register_device(InputDevice::new_keyboard());
    let mouse_minor = register_device(InputDevice::new_mouse());
    assert_eq!(kbd_minor, KBD_MINOR);
    assert_eq!(mouse_minor, MOUSE_MINOR);
    log::info!(
        "input: registered {} devices (kbd=event{}, mouse=event{})",
        device_count(),
        KBD_MINOR,
        MOUSE_MINOR
    );
}
