//! GPIO (General-Purpose I/O) controller driver.
//!
//! Supports up to `MAX_BANKS` independent GPIO banks, each managing up to
//! 32 pins.  Each bank is a contiguous MMIO region following a simple
//! direction / data / set / clear / interrupt register layout that is
//! compatible with the SiFive GPIO IP (used on HiFive Unleashed / QEMU).
//!
//! ## Register layout (per bank, base = bank.mmio_base)
//!
//!   +0x00  INPUT_VAL   32-bit  read-only  current pin levels
//!   +0x04  INPUT_EN    32-bit  r/w        1 = pin is an input
//!   +0x08  OUTPUT_EN   32-bit  r/w        1 = pin is an output
//!   +0x0C  OUTPUT_VAL  32-bit  r/w        output level
//!   +0x10  RISE_IE     32-bit  r/w        rise interrupt enable
//!   +0x14  RISE_IP     32-bit  r/w1c      rise interrupt pending
//!   +0x18  FALL_IE     32-bit  r/w        fall interrupt enable
//!   +0x1C  FALL_IP     32-bit  r/w1c      fall interrupt pending
//!   +0x20  HIGH_IE     32-bit  r/w        high-level interrupt enable
//!   +0x24  HIGH_IP     32-bit  r/w1c      high-level interrupt pending
//!   +0x28  LOW_IE      32-bit  r/w        low-level interrupt enable
//!   +0x2C  LOW_IP      32-bit  r/w1c      low-level interrupt pending
//!   +0x30  IOF_EN      32-bit  r/w        1 = hardware IOF mux selected
//!   +0x34  IOF_SEL     32-bit  r/w        0 = IOF0, 1 = IOF1
//!   +0x38  OUT_XOR     32-bit  r/w        XOR output polarity invert

extern crate alloc;
use alloc::vec::Vec;
use core::ptr::{read_volatile, write_volatile};
use spin::Mutex;

const GPIO_INPUT_VAL: usize = 0x00;
const GPIO_INPUT_EN: usize = 0x04;
const GPIO_OUTPUT_EN: usize = 0x08;
const GPIO_OUTPUT_VAL: usize = 0x0C;
const GPIO_RISE_IE: usize = 0x10;
const GPIO_RISE_IP: usize = 0x14;
const GPIO_FALL_IE: usize = 0x18;
const GPIO_FALL_IP: usize = 0x1C;
const GPIO_HIGH_IE: usize = 0x20;
const GPIO_HIGH_IP: usize = 0x24;
const GPIO_LOW_IE: usize = 0x28;
const GPIO_LOW_IP: usize = 0x2C;
const GPIO_IOF_EN: usize = 0x30;
const GPIO_IOF_SEL: usize = 0x34;
const GPIO_OUT_XOR: usize = 0x38;

/// Maximum number of GPIO banks the driver manages.
pub const MAX_BANKS: usize = 4;

/// Pins per bank.
pub const PINS_PER_BANK: u8 = 32;

#[derive(Clone, Debug)]
pub struct GpioBank {
    /// Physical (identity-mapped) MMIO base address.
    pub mmio_base: usize,
    /// Human-readable label (e.g. "gpio0").
    pub label: &'static str,
    /// PLIC source IDs for this bank's interrupt line (one per bank).
    pub plic_src: u32,
}

static BANKS: Mutex<Vec<GpioBank>> = Mutex::new(Vec::new());

#[inline]
unsafe fn gpio_read(base: usize, off: usize) -> u32 {
    read_volatile((base + off) as *const u32)
}

#[inline]
unsafe fn gpio_write(base: usize, off: usize, val: u32) {
    write_volatile((base + off) as *mut u32, val);
}

#[inline]
unsafe fn gpio_set_bits(base: usize, off: usize, mask: u32) {
    let v = gpio_read(base, off);
    gpio_write(base, off, v | mask);
}

#[inline]
unsafe fn gpio_clear_bits(base: usize, off: usize, mask: u32) {
    let v = gpio_read(base, off);
    gpio_write(base, off, v & !mask);
}

/// Register a GPIO bank.  Called at boot from the platform init code.
/// Returns the bank index, or None if `MAX_BANKS` is exceeded.
pub fn register_bank(bank: GpioBank) -> Option<usize> {
    let mut banks = BANKS.lock();
    if banks.len() >= MAX_BANKS {
        return None;
    }
    let idx = banks.len();
    banks.push(bank);
    Some(idx)
}

/// Return a clone of all registered banks.
pub fn banks() -> Vec<GpioBank> {
    BANKS.lock().clone()
}

/// Configure pin `pin` on `bank` as an output.
pub fn set_output(bank: usize, pin: u8) {
    with_bank(bank, |base| unsafe {
        gpio_set_bits(base, GPIO_OUTPUT_EN, 1 << pin);
        gpio_clear_bits(base, GPIO_INPUT_EN, 1 << pin);
        gpio_clear_bits(base, GPIO_IOF_EN, 1 << pin);
    });
}

/// Configure pin `pin` on `bank` as an input.
pub fn set_input(bank: usize, pin: u8) {
    with_bank(bank, |base| unsafe {
        gpio_set_bits(base, GPIO_INPUT_EN, 1 << pin);
        gpio_clear_bits(base, GPIO_OUTPUT_EN, 1 << pin);
        gpio_clear_bits(base, GPIO_IOF_EN, 1 << pin);
    });
}

/// Assign pin to hardware I/O function (IOF) mux.
/// `iof` = 0 → IOF0, 1 → IOF1.
pub fn set_iof(bank: usize, pin: u8, iof: u8) {
    with_bank(bank, |base| unsafe {
        gpio_clear_bits(base, GPIO_OUTPUT_EN, 1 << pin);
        gpio_clear_bits(base, GPIO_INPUT_EN, 1 << pin);
        if iof == 1 {
            gpio_set_bits(base, GPIO_IOF_SEL, 1 << pin);
        } else {
            gpio_clear_bits(base, GPIO_IOF_SEL, 1 << pin);
        }
        gpio_set_bits(base, GPIO_IOF_EN, 1 << pin);
    });
}

/// Drive pin `pin` on `bank` high.
pub fn set_high(bank: usize, pin: u8) {
    with_bank(bank, |base| unsafe {
        gpio_set_bits(base, GPIO_OUTPUT_VAL, 1 << pin);
    });
}

/// Drive pin `pin` on `bank` low.
pub fn set_low(bank: usize, pin: u8) {
    with_bank(bank, |base| unsafe {
        gpio_clear_bits(base, GPIO_OUTPUT_VAL, 1 << pin);
    });
}

/// Toggle pin `pin` on `bank`.
pub fn toggle(bank: usize, pin: u8) {
    with_bank(bank, |base| unsafe {
        let v = gpio_read(base, GPIO_OUTPUT_VAL);
        gpio_write(base, GPIO_OUTPUT_VAL, v ^ (1 << pin));
    });
}

/// Write a whole 32-bit word to the output register of `bank`.
pub fn write_all(bank: usize, val: u32) {
    with_bank(bank, |base| unsafe {
        gpio_write(base, GPIO_OUTPUT_VAL, val);
    });
}

/// Invert the output polarity of `pin` via OUT_XOR.
pub fn set_polarity_invert(bank: usize, pin: u8, invert: bool) {
    with_bank(bank, |base| unsafe {
        if invert {
            gpio_set_bits(base, GPIO_OUT_XOR, 1 << pin);
        } else {
            gpio_clear_bits(base, GPIO_OUT_XOR, 1 << pin);
        }
    });
}

/// Read the current level of pin `pin` on `bank`.
/// Returns None if the bank index is invalid.
pub fn read(bank: usize, pin: u8) -> Option<bool> {
    let banks = BANKS.lock();
    let b = banks.get(bank)?;
    let val = unsafe { gpio_read(b.mmio_base, GPIO_INPUT_VAL) };
    Some(val & (1 << pin) != 0)
}

/// Read all 32 input pins of `bank` as a bitmask.
pub fn read_all(bank: usize) -> Option<u32> {
    let banks = BANKS.lock();
    let b = banks.get(bank)?;
    Some(unsafe { gpio_read(b.mmio_base, GPIO_INPUT_VAL) })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IrqTrigger {
    RisingEdge,
    FallingEdge,
    HighLevel,
    LowLevel,
    BothEdges,
}

/// Enable interrupt for `pin` on `bank` with trigger `trig`.
pub fn irq_enable(bank: usize, pin: u8, trig: IrqTrigger) {
    with_bank(bank, |base| unsafe {
        use IrqTrigger::*;
        let m = 1 << pin;
        match trig {
            RisingEdge => {
                gpio_set_bits(base, GPIO_RISE_IE, m);
            },
            FallingEdge => {
                gpio_set_bits(base, GPIO_FALL_IE, m);
            },
            HighLevel => {
                gpio_set_bits(base, GPIO_HIGH_IE, m);
            },
            LowLevel => {
                gpio_set_bits(base, GPIO_LOW_IE, m);
            },
            BothEdges => {
                gpio_set_bits(base, GPIO_RISE_IE, m);
                gpio_set_bits(base, GPIO_FALL_IE, m);
            },
        }
    });
}

/// Disable all interrupt triggers for `pin` on `bank`.
pub fn irq_disable(bank: usize, pin: u8) {
    with_bank(bank, |base| unsafe {
        let m = !(1u32 << pin);
        gpio_write(base, GPIO_RISE_IE, gpio_read(base, GPIO_RISE_IE) & m);
        gpio_write(base, GPIO_FALL_IE, gpio_read(base, GPIO_FALL_IE) & m);
        gpio_write(base, GPIO_HIGH_IE, gpio_read(base, GPIO_HIGH_IE) & m);
        gpio_write(base, GPIO_LOW_IE, gpio_read(base, GPIO_LOW_IE) & m);
    });
}

/// Read and clear pending interrupt bits for `bank`.
/// Returns a tuple (rise, fall, high, low) of 32-bit pending masks.
pub fn irq_pending(bank: usize) -> Option<(u32, u32, u32, u32)> {
    let banks = BANKS.lock();
    let b = banks.get(bank)?;
    let base = b.mmio_base;
    unsafe {
        let rise = gpio_read(base, GPIO_RISE_IP);
        let fall = gpio_read(base, GPIO_FALL_IP);
        let high = gpio_read(base, GPIO_HIGH_IP);
        let low = gpio_read(base, GPIO_LOW_IP);
        // Write 1 to clear pending bits.
        gpio_write(base, GPIO_RISE_IP, rise);
        gpio_write(base, GPIO_FALL_IP, fall);
        gpio_write(base, GPIO_HIGH_IP, high);
        gpio_write(base, GPIO_LOW_IP, low);
        Some((rise, fall, high, low))
    }
}

fn with_bank<F: FnOnce(usize)>(bank: usize, f: F) {
    let banks = BANKS.lock();
    if let Some(b) = banks.get(bank) {
        f(b.mmio_base);
    }
}
