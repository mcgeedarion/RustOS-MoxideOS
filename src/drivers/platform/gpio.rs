//! GPIO (General-Purpose I/O) controller driver.
//!
//! Supports up to `MAX_BANKS` independent GPIO banks, each managing up to
//! 32 pins.  Compatible with SiFive GPIO IP, QEMU `sifive,gpio0`, and
//! ARM PrimeCell PL061 / AXI-GPIO.
//!
//! ## Register map (per bank, relative to bank base)
//!
//! ```text
//!  Offset   Name         Description
//!  0x00     INPUT_VAL    Current logic level (RO)
//!  0x04     INPUT_EN     Input enable
//!  0x08     OUTPUT_EN    Output enable
//!  0x0C     OUTPUT_VAL   Output data register
//!  0x10     PUE          Pull-up enable
//!  0x14     DS           Drive strength
//!  0x18     RISE_IE      Rise interrupt enable
//!  0x1C     RISE_IP      Rise interrupt pending (write 1 to clear)
//!  0x20     FALL_IE      Fall interrupt enable
//!  0x24     FALL_IP      Fall interrupt pending
//!  0x28     HIGH_IE      High-level interrupt enable
//!  0x2C     HIGH_IP      High-level interrupt pending
//!  0x30     LOW_IE       Low-level interrupt enable
//!  0x34     LOW_IP       Low-level interrupt pending
//!  0x38     IOF_EN       I/O Function enable
//!  0x3C     IOF_SEL      I/O Function select
//!  0x40     OUT_XOR      Output XOR / invert
//! ```

use core::sync::atomic::{AtomicBool, Ordering};
use spin::Mutex;

pub const MAX_BANKS: usize = 4;
pub const PINS_PER_BANK: usize = 32;

mod reg {
    pub const INPUT_VAL:  usize = 0x00; pub const INPUT_EN:   usize = 0x04;
    pub const OUTPUT_EN:  usize = 0x08; pub const OUTPUT_VAL: usize = 0x0C;
    pub const PUE:        usize = 0x10; pub const DS:         usize = 0x14;
    pub const RISE_IE:    usize = 0x18; pub const RISE_IP:    usize = 0x1C;
    pub const FALL_IE:    usize = 0x20; pub const FALL_IP:    usize = 0x24;
    pub const HIGH_IE:    usize = 0x28; pub const HIGH_IP:    usize = 0x2C;
    pub const LOW_IE:     usize = 0x30; pub const LOW_IP:     usize = 0x34;
    pub const IOF_EN:     usize = 0x38; pub const IOF_SEL:    usize = 0x3C;
    pub const OUT_XOR:    usize = 0x40;
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)] pub enum Direction { Input, Output }
#[derive(Clone, Copy, PartialEq, Eq, Debug)] pub enum Pull { None, Up }
#[derive(Clone, Copy, PartialEq, Eq, Debug)] pub enum Edge { None, Rising, Falling, Both, HighLevel, LowLevel }
#[derive(Clone, Copy, PartialEq, Eq, Debug)] pub enum DriveStrength { Low, High }

type PinCallback = fn(bank: u8, pin: u8, high: bool);

struct GpioBank {
    base: usize, num_pins: u8,
    callbacks: [Option<PinCallback>; PINS_PER_BANK],
    irq: u32,
}
impl GpioBank {
    const fn empty() -> Self { GpioBank { base: 0, num_pins: 0, callbacks: [None; PINS_PER_BANK], irq: 0 } }
    #[inline] fn reg(&self, off: usize) -> usize { self.base + off }
}

struct BankTable { banks: [Option<GpioBank>; MAX_BANKS] }
impl BankTable { const fn new() -> Self { BankTable { banks: [None, None, None, None] } } }
static BANKS: Mutex<BankTable> = Mutex::new(BankTable::new());
static INITIALISED: AtomicBool = AtomicBool::new(false);

#[inline] unsafe fn r32(addr: usize) -> u32 { core::ptr::read_volatile(addr as *const u32) }
#[inline] unsafe fn w32(addr: usize, val: u32) { core::ptr::write_volatile(addr as *mut u32, val); }
#[inline] unsafe fn set_bits(addr: usize, mask: u32) { w32(addr, r32(addr) | mask); }
#[inline] unsafe fn clr_bits(addr: usize, mask: u32) { w32(addr, r32(addr) & !mask); }

pub fn add_bank(bank_idx: usize, mmio_base: usize, num_pins: u8, irq: u32) -> Result<(), isize> {
    if bank_idx >= MAX_BANKS { return Err(-22); }
    if num_pins == 0 || num_pins as usize > PINS_PER_BANK { return Err(-22); }
    if mmio_base == 0 { return Err(-22); }
    let mut tbl = BANKS.lock();
    tbl.banks[bank_idx] = Some(GpioBank { base: mmio_base, num_pins, callbacks: [None; PINS_PER_BANK], irq });
    if irq != 0 {
        let handler: fn() = match bank_idx { 0 => handle_irq_bank0, 1 => handle_irq_bank1, 2 => handle_irq_bank2, _ => handle_irq_bank3 };
        crate::drivers::platform::plic::enable_irq(irq, handler);
    }
    Ok(())
}

pub fn remove_bank(bank_idx: usize) {
    if bank_idx >= MAX_BANKS { return; }
    let mut tbl = BANKS.lock();
    if let Some(ref b) = tbl.banks[bank_idx] { if b.irq != 0 { crate::drivers::platform::plic::disable_irq(b.irq); } }
    tbl.banks[bank_idx] = None;
}

pub fn set_direction(bank_idx: usize, pin: u8, dir: Direction) {
    with_bank(bank_idx, pin, |b, mask| unsafe {
        match dir {
            Direction::Input  => { clr_bits(b.reg(reg::OUTPUT_EN), mask); set_bits(b.reg(reg::INPUT_EN),  mask); }
            Direction::Output => { clr_bits(b.reg(reg::INPUT_EN),  mask); set_bits(b.reg(reg::OUTPUT_EN), mask); }
        }
    });
}

pub fn get_direction(bank_idx: usize, pin: u8) -> Option<Direction> {
    let tbl = BANKS.lock(); let b = tbl.banks.get(bank_idx)?.as_ref()?;
    if pin >= b.num_pins { return None; }
    let oe = unsafe { r32(b.reg(reg::OUTPUT_EN)) };
    if oe & (1u32 << pin) != 0 { Some(Direction::Output) } else { Some(Direction::Input) }
}

pub fn set_pull(bank_idx: usize, pin: u8, pull: Pull) {
    with_bank(bank_idx, pin, |b, mask| unsafe {
        match pull { Pull::Up => set_bits(b.reg(reg::PUE), mask), Pull::None => clr_bits(b.reg(reg::PUE), mask) }
    });
}
pub fn set_drive(bank_idx: usize, pin: u8, ds: DriveStrength) {
    with_bank(bank_idx, pin, |b, mask| unsafe {
        match ds { DriveStrength::High => set_bits(b.reg(reg::DS), mask), DriveStrength::Low => clr_bits(b.reg(reg::DS), mask) }
    });
}
pub fn set_iof(bank_idx: usize, pin: u8, enable: bool, iof_sel: bool) {
    with_bank(bank_idx, pin, |b, mask| unsafe {
        if enable {
            if iof_sel { set_bits(b.reg(reg::IOF_SEL), mask); } else { clr_bits(b.reg(reg::IOF_SEL), mask); }
            set_bits(b.reg(reg::IOF_EN), mask);
        } else { clr_bits(b.reg(reg::IOF_EN), mask); }
    });
}
pub fn set_output_invert(bank_idx: usize, pin: u8, invert: bool) {
    with_bank(bank_idx, pin, |b, mask| unsafe {
        if invert { set_bits(b.reg(reg::OUT_XOR), mask); } else { clr_bits(b.reg(reg::OUT_XOR), mask); }
    });
}
pub fn write_pin(bank_idx: usize, pin: u8, high: bool) {
    with_bank(bank_idx, pin, |b, mask| unsafe {
        if high { set_bits(b.reg(reg::OUTPUT_VAL), mask); } else { clr_bits(b.reg(reg::OUTPUT_VAL), mask); }
    });
}
pub fn read_pin(bank_idx: usize, pin: u8) -> Option<bool> {
    let tbl = BANKS.lock(); let b = tbl.banks.get(bank_idx)?.as_ref()?;
    if pin >= b.num_pins { return None; }
    Some(unsafe { r32(b.reg(reg::INPUT_VAL)) } & (1u32 << pin) != 0)
}
pub fn read_output(bank_idx: usize, pin: u8) -> Option<bool> {
    let tbl = BANKS.lock(); let b = tbl.banks.get(bank_idx)?.as_ref()?;
    if pin >= b.num_pins { return None; }
    Some(unsafe { r32(b.reg(reg::OUTPUT_VAL)) } & (1u32 << pin) != 0)
}
pub fn toggle_pin(bank_idx: usize, pin: u8) {
    with_bank(bank_idx, pin, |b, mask| unsafe { w32(b.reg(reg::OUTPUT_VAL), r32(b.reg(reg::OUTPUT_VAL)) ^ mask); });
}
pub fn write_bank(bank_idx: usize, value: u32) {
    let tbl = BANKS.lock();
    if let Some(Some(ref b)) = tbl.banks.get(bank_idx) {
        let mask = if b.num_pins == 32 { u32::MAX } else { (1u32 << b.num_pins) - 1 };
        unsafe { w32(b.reg(reg::OUTPUT_VAL), value & mask); }
    }
}
pub fn read_bank(bank_idx: usize) -> u32 {
    let tbl = BANKS.lock();
    if let Some(Some(ref b)) = tbl.banks.get(bank_idx) { unsafe { r32(b.reg(reg::INPUT_VAL)) } } else { 0 }
}
pub fn set_irq_edge(bank_idx: usize, pin: u8, edge: Edge) {
    with_bank(bank_idx, pin, |b, mask| unsafe {
        clr_bits(b.reg(reg::RISE_IE), mask); clr_bits(b.reg(reg::FALL_IE), mask);
        clr_bits(b.reg(reg::HIGH_IE), mask); clr_bits(b.reg(reg::LOW_IE),  mask);
        match edge {
            Edge::None => {}
            Edge::Rising    => { set_bits(b.reg(reg::RISE_IE), mask); }
            Edge::Falling   => { set_bits(b.reg(reg::FALL_IE), mask); }
            Edge::Both      => { set_bits(b.reg(reg::RISE_IE), mask); set_bits(b.reg(reg::FALL_IE), mask); }
            Edge::HighLevel => { set_bits(b.reg(reg::HIGH_IE), mask); }
            Edge::LowLevel  => { set_bits(b.reg(reg::LOW_IE),  mask); }
        }
    });
}
pub fn register_pin_callback(bank_idx: usize, pin: u8, cb: Option<PinCallback>) {
    if bank_idx >= MAX_BANKS || pin as usize >= PINS_PER_BANK { return; }
    let mut tbl = BANKS.lock();
    if let Some(Some(ref mut b)) = tbl.banks.get_mut(bank_idx) { if pin < b.num_pins { b.callbacks[pin as usize] = cb; } }
}

fn dispatch_bank_irq(bank_idx: usize) {
    let tbl = BANKS.lock();
    let b = match tbl.banks.get(bank_idx).and_then(|b| b.as_ref()) { Some(b) => b, None => return };
    let base = b.base; let num_pins = b.num_pins;
    let pending = unsafe { r32(base + reg::RISE_IP) | r32(base + reg::FALL_IP) | r32(base + reg::HIGH_IP) | r32(base + reg::LOW_IP) };
    if pending == 0 { return; }
    let input_val = unsafe { r32(base + reg::INPUT_VAL) };
    unsafe { w32(base + reg::RISE_IP, pending); w32(base + reg::FALL_IP, pending); w32(base + reg::HIGH_IP, pending); w32(base + reg::LOW_IP, pending); }
    let callbacks = b.callbacks; drop(tbl);
    for pin in 0..num_pins {
        let mask = 1u32 << pin;
        if pending & mask != 0 { if let Some(cb) = callbacks[pin as usize] { cb(bank_idx as u8, pin, input_val & mask != 0); } }
    }
}

fn handle_irq_bank0() { dispatch_bank_irq(0); }
fn handle_irq_bank1() { dispatch_bank_irq(1); }
fn handle_irq_bank2() { dispatch_bank_irq(2); }
fn handle_irq_bank3() { dispatch_bank_irq(3); }

pub fn init() {
    if INITIALISED.swap(true, Ordering::AcqRel) { return; }
    crate::println!("gpio: subsystem ready ({} banks max)", MAX_BANKS);
}

pub fn fdt_register(reg_base: usize, ngpios: u8, irq: u32) {
    let idx = { let tbl = BANKS.lock(); (0..MAX_BANKS).find(|&i| tbl.banks[i].is_none()) };
    if let Some(idx) = idx {
        match add_bank(idx, reg_base, ngpios.max(1).min(32), irq) {
            Ok(()) => crate::println!("gpio: bank {} at {:#x} ({} pins, irq {})", idx, reg_base, ngpios, irq),
            Err(e) => crate::println!("gpio: add_bank failed: {}", e),
        }
    } else { crate::println!("gpio: too many banks (max {})", MAX_BANKS); }
}

pub fn print_status() {
    let tbl = BANKS.lock();
    for i in 0..MAX_BANKS {
        if let Some(ref b) = tbl.banks[i] {
            let ie = unsafe { r32(b.reg(reg::RISE_IE)) | r32(b.reg(reg::FALL_IE)) };
            let ov = unsafe { r32(b.reg(reg::OUTPUT_VAL)) };
            let iv = unsafe { r32(b.reg(reg::INPUT_VAL)) };
            let oe = unsafe { r32(b.reg(reg::OUTPUT_EN)) };
            crate::println!("gpio: bank {} base={:#x} pins={} oe={:#010x} ov={:#010x} iv={:#010x} ie={:#010x} irq={}", i, b.base, b.num_pins, oe, ov, iv, ie, b.irq);
        }
    }
}

fn with_bank<F: FnOnce(&GpioBank, u32)>(bank_idx: usize, pin: u8, f: F) {
    let tbl = BANKS.lock();
    if let Some(Some(ref b)) = tbl.banks.get(bank_idx) { if pin < b.num_pins { f(b, 1u32 << pin); } }
}
