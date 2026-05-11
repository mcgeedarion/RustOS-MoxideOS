//! GPIO (General-Purpose I/O) controller driver.
//!
//! Supports up to `MAX_BANKS` independent GPIO banks, each managing up to
//! 32 pins.  Each bank is a contiguous MMIO region following a simple
//! direction / data / set / clear / interrupt register layout that is
//! compatible with the SiFive GPIO IP, the QEMU `sifive,gpio0` device,
//! and many ARM PrimeCell PL061 / AXI-GPIO clones.
//!
//! ## Register map (per bank, relative to bank base)
//!
//! ```text
//!  Offset   Width   Name         Description
//!  0x00     32      INPUT_VAL    Current logic level on each pin (RO)
//!  0x04     32      INPUT_EN     Input enable (1 = pin is an input)
//!  0x08     32      OUTPUT_EN    Output enable (1 = pin is an output)
//!  0x0C     32      OUTPUT_VAL   Output data register (drive value)
//!  0x10     32      PUE          Pull-up enable
//!  0x14     32      DS           Drive strength (0 = low, 1 = high)
//!  0x18     32      RISE_IE      Rise interrupt enable
//!  0x1C     32      RISE_IP      Rise interrupt pending (write 1 to clear)
//!  0x20     32      FALL_IE      Fall interrupt enable
//!  0x24     32      FALL_IP      Fall interrupt pending
//!  0x28     32      HIGH_IE      High-level interrupt enable
//!  0x2C     32      HIGH_IP      High-level interrupt pending
//!  0x30     32      LOW_IE       Low-level interrupt enable
//!  0x34     32      LOW_IP       Low-level interrupt pending
//!  0x38     32      IOF_EN       I/O Function enable (mux to peripheral)
//!  0x3C     32      IOF_SEL      I/O Function select (0=IOF0, 1=IOF1)
//!  0x40     32      OUT_XOR      Output XOR / invert register
//! ```
//!
//! ## Usage
//!
//! ```rust
//! // Register bank 0 at the SiFive QEMU GPIO base:
//! gpio::add_bank(0, 0x1001_2000, 32, Some(gpio_irq_handler));
//!
//! // Configure pin 5 as output, drive low:
//! gpio::set_direction(0, 5, gpio::Direction::Output);
//! gpio::write_pin(0, 5, false);
//!
//! // Configure pin 3 as input with pull-up, rising-edge IRQ:
//! gpio::set_direction(0, 3, gpio::Direction::Input);
//! gpio::set_pull(0, 3, gpio::Pull::Up);
//! gpio::set_irq_edge(0, 3, gpio::Edge::Rising);
//! gpio::register_pin_callback(0, 3, my_callback);
//! ```

use core::sync::atomic::{AtomicBool, Ordering};
use spin::Mutex;

// ─────────────────────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────────────────────

pub const MAX_BANKS:    usize = 4;
pub const PINS_PER_BANK: usize = 32;

// Register offsets (bytes from bank base)
mod reg {
    pub const INPUT_VAL:  usize = 0x00;
    pub const INPUT_EN:   usize = 0x04;
    pub const OUTPUT_EN:  usize = 0x08;
    pub const OUTPUT_VAL: usize = 0x0C;
    pub const PUE:        usize = 0x10;
    pub const DS:         usize = 0x14;
    pub const RISE_IE:    usize = 0x18;
    pub const RISE_IP:    usize = 0x1C;
    pub const FALL_IE:    usize = 0x20;
    pub const FALL_IP:    usize = 0x24;
    pub const HIGH_IE:    usize = 0x28;
    pub const HIGH_IP:    usize = 0x2C;
    pub const LOW_IE:     usize = 0x30;
    pub const LOW_IP:     usize = 0x34;
    pub const IOF_EN:     usize = 0x38;
    pub const IOF_SEL:    usize = 0x3C;
    pub const OUT_XOR:    usize = 0x40;
}

// ─────────────────────────────────────────────────────────────────────────────
// Public types
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Direction {
    Input,
    Output,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Pull {
    None,
    Up,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Edge {
    None,
    Rising,
    Falling,
    Both,
    HighLevel,
    LowLevel,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum DriveStrength {
    Low,
    High,
}

// ─────────────────────────────────────────────────────────────────────────────
// Bank state
// ─────────────────────────────────────────────────────────────────────────────

type PinCallback = fn(bank: u8, pin: u8, high: bool);

struct GpioBank {
    /// MMIO base of this bank.
    base:      usize,
    /// Number of usable pins (1..=32).
    num_pins:  u8,
    /// Per-pin user callbacks (called from the IRQ handler).
    callbacks: [Option<PinCallback>; PINS_PER_BANK],
    /// IRQ number registered with the PLIC (0 = not registered).
    irq:       u32,
}

impl GpioBank {
    const fn empty() -> Self {
        GpioBank {
            base:      0,
            num_pins:  0,
            callbacks: [None; PINS_PER_BANK],
            irq:       0,
        }
    }

    #[inline]
    fn reg(&self, off: usize) -> usize { self.base + off }
}

struct BankTable {
    banks: [Option<GpioBank>; MAX_BANKS],
}

impl BankTable {
    const fn new() -> Self {
        BankTable {
            banks: [None, None, None, None],
        }
    }
}

static BANKS: Mutex<BankTable> = Mutex::new(BankTable::new());
static INITIALISED: AtomicBool = AtomicBool::new(false);

// ─────────────────────────────────────────────────────────────────────────────
// MMIO helpers
// ─────────────────────────────────────────────────────────────────────────────

#[inline]
unsafe fn r32(addr: usize) -> u32 {
    core::ptr::read_volatile(addr as *const u32)
}

#[inline]
unsafe fn w32(addr: usize, val: u32) {
    core::ptr::write_volatile(addr as *mut u32, val);
}

/// Set bits in register at `addr` where `mask` has 1s.
#[inline]
unsafe fn set_bits(addr: usize, mask: u32) {
    let prev = r32(addr);
    w32(addr, prev | mask);
}

/// Clear bits in register at `addr` where `mask` has 1s.
#[inline]
unsafe fn clr_bits(addr: usize, mask: u32) {
    let prev = r32(addr);
    w32(addr, prev & !mask);
}

// ─────────────────────────────────────────────────────────────────────────────
// Bank registration
// ─────────────────────────────────────────────────────────────────────────────

/// Register a GPIO bank.
///
/// - `bank_idx`  — 0 … MAX_BANKS-1
/// - `mmio_base` — physical (= kernel-virtual) address of the bank registers
/// - `num_pins`  — number of usable pins on this bank (1..=32)
/// - `irq`       — PLIC IRQ number for this bank, or 0 if not IRQ-capable
///
/// Returns `Ok(())` or `Err(-22)` (EINVAL) on bad arguments.
pub fn add_bank(
    bank_idx: usize,
    mmio_base: usize,
    num_pins: u8,
    irq: u32,
) -> Result<(), isize> {
    if bank_idx >= MAX_BANKS     { return Err(-22); }
    if num_pins == 0 || num_pins as usize > PINS_PER_BANK { return Err(-22); }
    if mmio_base == 0            { return Err(-22); }

    let mut tbl = BANKS.lock();
    tbl.banks[bank_idx] = Some(GpioBank {
        base:      mmio_base,
        num_pins,
        callbacks: [None; PINS_PER_BANK],
        irq,
    });

    // Register bank IRQ with the PLIC if an IRQ number was given.
    if irq != 0 {
        // Build a static dispatch closure per bank index.
        let handler: fn() = match bank_idx {
            0 => handle_irq_bank0,
            1 => handle_irq_bank1,
            2 => handle_irq_bank2,
            _ => handle_irq_bank3,
        };
        crate::drivers::plic::enable_irq(irq, handler);
    }
    Ok(())
}

/// Remove a previously-registered bank.  Disables its PLIC IRQ if registered.
pub fn remove_bank(bank_idx: usize) {
    if bank_idx >= MAX_BANKS { return; }
    let mut tbl = BANKS.lock();
    if let Some(ref b) = tbl.banks[bank_idx] {
        if b.irq != 0 { crate::drivers::plic::disable_irq(b.irq); }
    }
    tbl.banks[bank_idx] = None;
}

// ─────────────────────────────────────────────────────────────────────────────
// Pin direction, pull, and drive strength
// ─────────────────────────────────────────────────────────────────────────────

/// Set the direction of `pin` on `bank`.
pub fn set_direction(bank_idx: usize, pin: u8, dir: Direction) {
    with_bank(bank_idx, pin, |b, mask| unsafe {
        match dir {
            Direction::Input  => {
                clr_bits(b.reg(reg::OUTPUT_EN), mask);
                set_bits(b.reg(reg::INPUT_EN),  mask);
            }
            Direction::Output => {
                clr_bits(b.reg(reg::INPUT_EN),  mask);
                set_bits(b.reg(reg::OUTPUT_EN), mask);
            }
        }
    });
}

/// Read the direction of `pin` on `bank`.
pub fn get_direction(bank_idx: usize, pin: u8) -> Option<Direction> {
    let tbl = BANKS.lock();
    let b = tbl.banks.get(bank_idx)?.as_ref()?;
    if pin >= b.num_pins { return None; }
    let mask = 1u32 << pin;
    let oe = unsafe { r32(b.reg(reg::OUTPUT_EN)) };
    if oe & mask != 0 { Some(Direction::Output) } else { Some(Direction::Input) }
}

/// Enable or disable the pull-up resistor for `pin`.
pub fn set_pull(bank_idx: usize, pin: u8, pull: Pull) {
    with_bank(bank_idx, pin, |b, mask| unsafe {
        match pull {
            Pull::Up   => set_bits(b.reg(reg::PUE), mask),
            Pull::None => clr_bits(b.reg(reg::PUE), mask),
        }
    });
}

/// Set drive strength for `pin`.
pub fn set_drive(bank_idx: usize, pin: u8, ds: DriveStrength) {
    with_bank(bank_idx, pin, |b, mask| unsafe {
        match ds {
            DriveStrength::High => set_bits(b.reg(reg::DS), mask),
            DriveStrength::Low  => clr_bits(b.reg(reg::DS), mask),
        }
    });
}

/// Mux `pin` to its alternate peripheral function (`IOF_EN` + `IOF_SEL`).
///
/// `iof_sel`: `false` = IOF0, `true` = IOF1.
pub fn set_iof(bank_idx: usize, pin: u8, enable: bool, iof_sel: bool) {
    with_bank(bank_idx, pin, |b, mask| unsafe {
        if enable {
            if iof_sel { set_bits(b.reg(reg::IOF_SEL), mask); }
            else       { clr_bits(b.reg(reg::IOF_SEL), mask); }
            set_bits(b.reg(reg::IOF_EN), mask);
        } else {
            clr_bits(b.reg(reg::IOF_EN), mask);
        }
    });
}

/// Invert the output of `pin` via the XOR register.
pub fn set_output_invert(bank_idx: usize, pin: u8, invert: bool) {
    with_bank(bank_idx, pin, |b, mask| unsafe {
        if invert { set_bits(b.reg(reg::OUT_XOR), mask); }
        else      { clr_bits(b.reg(reg::OUT_XOR), mask); }
    });
}

// ─────────────────────────────────────────────────────────────────────────────
// Digital I/O
// ─────────────────────────────────────────────────────────────────────────────

/// Drive `pin` high (true) or low (false).  Pin must be configured as Output.
pub fn write_pin(bank_idx: usize, pin: u8, high: bool) {
    with_bank(bank_idx, pin, |b, mask| unsafe {
        if high { set_bits(b.reg(reg::OUTPUT_VAL), mask); }
        else    { clr_bits(b.reg(reg::OUTPUT_VAL), mask); }
    });
}

/// Read the current logic level on `pin` (reads INPUT_VAL register).
/// Returns `None` if the bank or pin is invalid.
pub fn read_pin(bank_idx: usize, pin: u8) -> Option<bool> {
    let tbl = BANKS.lock();
    let b   = tbl.banks.get(bank_idx)?.as_ref()?;
    if pin >= b.num_pins { return None; }
    let val = unsafe { r32(b.reg(reg::INPUT_VAL)) };
    Some(val & (1u32 << pin) != 0)
}

/// Read the current output register value for `pin`.
pub fn read_output(bank_idx: usize, pin: u8) -> Option<bool> {
    let tbl = BANKS.lock();
    let b   = tbl.banks.get(bank_idx)?.as_ref()?;
    if pin >= b.num_pins { return None; }
    let val = unsafe { r32(b.reg(reg::OUTPUT_VAL)) };
    Some(val & (1u32 << pin) != 0)
}

/// Toggle the output of `pin` (XOR with current output register).
pub fn toggle_pin(bank_idx: usize, pin: u8) {
    with_bank(bank_idx, pin, |b, mask| unsafe {
        let cur = r32(b.reg(reg::OUTPUT_VAL));
        w32(b.reg(reg::OUTPUT_VAL), cur ^ mask);
    });
}

/// Write the full 32-bit OUTPUT_VAL register of a bank in one operation.
/// Bits for pins beyond `num_pins` are masked out.
pub fn write_bank(bank_idx: usize, value: u32) {
    let tbl = BANKS.lock();
    if let Some(Some(ref b)) = tbl.banks.get(bank_idx) {
        let mask = if b.num_pins == 32 { u32::MAX } else { (1u32 << b.num_pins) - 1 };
        unsafe { w32(b.reg(reg::OUTPUT_VAL), value & mask); }
    }
}

/// Read the full 32-bit INPUT_VAL register for a bank.
/// Returns 0 if the bank index is invalid.
pub fn read_bank(bank_idx: usize) -> u32 {
    let tbl = BANKS.lock();
    if let Some(Some(ref b)) = tbl.banks.get(bank_idx) {
        unsafe { r32(b.reg(reg::INPUT_VAL)) }
    } else { 0 }
}

// ─────────────────────────────────────────────────────────────────────────────
// Interrupt configuration
// ─────────────────────────────────────────────────────────────────────────────

/// Configure which edge(s) / level(s) trigger an interrupt for `pin`.
pub fn set_irq_edge(bank_idx: usize, pin: u8, edge: Edge) {
    with_bank(bank_idx, pin, |b, mask| unsafe {
        // Clear all IE bits for this pin first.
        clr_bits(b.reg(reg::RISE_IE),  mask);
        clr_bits(b.reg(reg::FALL_IE),  mask);
        clr_bits(b.reg(reg::HIGH_IE),  mask);
        clr_bits(b.reg(reg::LOW_IE),   mask);
        match edge {
            Edge::None      => {}
            Edge::Rising    => { set_bits(b.reg(reg::RISE_IE), mask); }
            Edge::Falling   => { set_bits(b.reg(reg::FALL_IE), mask); }
            Edge::Both      => {
                set_bits(b.reg(reg::RISE_IE), mask);
                set_bits(b.reg(reg::FALL_IE), mask);
            }
            Edge::HighLevel => { set_bits(b.reg(reg::HIGH_IE), mask); }
            Edge::LowLevel  => { set_bits(b.reg(reg::LOW_IE),  mask); }
        }
    });
}

/// Register a callback invoked when `pin` fires an interrupt.
/// Pass `None` to deregister.
pub fn register_pin_callback(bank_idx: usize, pin: u8, cb: Option<PinCallback>) {
    if bank_idx >= MAX_BANKS || pin as usize >= PINS_PER_BANK { return; }
    let mut tbl = BANKS.lock();
    if let Some(Some(ref mut b)) = tbl.banks.get_mut(bank_idx) {
        if pin < b.num_pins {
            b.callbacks[pin as usize] = cb;
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// IRQ handlers (one per bank — registered with the PLIC)
// ─────────────────────────────────────────────────────────────────────────────

/// Shared IRQ dispatch logic for any bank index.
fn dispatch_bank_irq(bank_idx: usize) {
    let tbl = BANKS.lock();
    let b = match tbl.banks.get(bank_idx).and_then(|b| b.as_ref()) {
        Some(b) => b,
        None => return,
    };
    let base = b.base;
    let num_pins = b.num_pins;

    // Collect all pending interrupt bits (OR of all IP registers).
    let pending = unsafe {
          r32(base + reg::RISE_IP)
        | r32(base + reg::FALL_IP)
        | r32(base + reg::HIGH_IP)
        | r32(base + reg::LOW_IP)
    };

    if pending == 0 { return; }

    // Read current input values once for all callbacks.
    let input_val = unsafe { r32(base + reg::INPUT_VAL) };

    // Acknowledge all pending bits (write-1-to-clear).
    unsafe {
        w32(base + reg::RISE_IP, pending);
        w32(base + reg::FALL_IP, pending);
        w32(base + reg::HIGH_IP, pending);
        w32(base + reg::LOW_IP,  pending);
    }

    // Fire per-pin callbacks for every pending bit.
    // We release the lock before calling user callbacks to avoid deadlock.
    let callbacks = b.callbacks;
    drop(tbl);

    for pin in 0..num_pins {
        let mask = 1u32 << pin;
        if pending & mask != 0 {
            if let Some(cb) = callbacks[pin as usize] {
                let high = input_val & mask != 0;
                cb(bank_idx as u8, pin, high);
            }
        }
    }
}

fn handle_irq_bank0() { dispatch_bank_irq(0); }
fn handle_irq_bank1() { dispatch_bank_irq(1); }
fn handle_irq_bank2() { dispatch_bank_irq(2); }
fn handle_irq_bank3() { dispatch_bank_irq(3); }

// ─────────────────────────────────────────────────────────────────────────────
// Initialisation
// ─────────────────────────────────────────────────────────────────────────────

/// Initialise the GPIO subsystem.
///
/// Call once from `kernel_main` (or from the FDT walker after all GPIO nodes
/// have been parsed).  Idempotent.
pub fn init() {
    if INITIALISED.swap(true, Ordering::AcqRel) { return; }
    // Nothing global to set up; banks are registered individually via
    // `add_bank()`. This function exists as a consistent init entry point.
    crate::println!("gpio: subsystem ready ({} banks max)", MAX_BANKS);
}

// ─────────────────────────────────────────────────────────────────────────────
// FDT callback helper
// ─────────────────────────────────────────────────────────────────────────────

/// Called by the FDT walker when it finds a `sifive,gpio0` or `gpio-controller`
/// node.  `reg` is the MMIO base from the `reg` property, `ngpios` is the
/// pin count (defaults to 32 if absent from FDT), `irq` is the PLIC interrupt.
pub fn fdt_register(reg_base: usize, ngpios: u8, irq: u32) {
    // Find the first empty bank slot.
    let idx = {
        let tbl = BANKS.lock();
        (0..MAX_BANKS).find(|&i| tbl.banks[i].is_none())
    };
    if let Some(idx) = idx {
        match add_bank(idx, reg_base, ngpios.max(1).min(32), irq) {
            Ok(()) => crate::println!(
                "gpio: bank {} at {:#x} ({} pins, irq {})",
                idx, reg_base, ngpios, irq
            ),
            Err(e) => crate::println!("gpio: add_bank failed: {}", e),
        }
    } else {
        crate::println!("gpio: too many banks (max {})", MAX_BANKS);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Diagnostics
// ─────────────────────────────────────────────────────────────────────────────

/// Print the state of all registered banks to the kernel log.
pub fn print_status() {
    let tbl = BANKS.lock();
    for i in 0..MAX_BANKS {
        if let Some(ref b) = tbl.banks[i] {
            let ie = unsafe { r32(b.reg(reg::RISE_IE)) | r32(b.reg(reg::FALL_IE)) };
            let ov = unsafe { r32(b.reg(reg::OUTPUT_VAL)) };
            let iv = unsafe { r32(b.reg(reg::INPUT_VAL))  };
            let oe = unsafe { r32(b.reg(reg::OUTPUT_EN))  };
            crate::println!(
                "gpio: bank {} base={:#x} pins={} oe={:#010x} ov={:#010x} iv={:#010x} ie={:#010x} irq={}",
                i, b.base, b.num_pins, oe, ov, iv, ie, b.irq
            );
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Internal utility
// ─────────────────────────────────────────────────────────────────────────────

/// Run a closure with the bank and the pin bitmask.  No-op if the bank or pin
/// is invalid.  The lock is held for the duration of the closure.
fn with_bank<F: FnOnce(&GpioBank, u32)>(bank_idx: usize, pin: u8, f: F) {
    let tbl = BANKS.lock();
    if let Some(Some(ref b)) = tbl.banks.get(bank_idx) {
        if pin < b.num_pins {
            f(b, 1u32 << pin);
        }
    }
}
