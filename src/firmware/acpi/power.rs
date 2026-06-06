//! ACPI Power Management — FADT/DSDT parsing and runtime power control.

use core::sync::atomic::{AtomicU16, AtomicU8, Ordering};

use super::SdtHeader;
use crate::console::println;

const PM1_STS_PWRBTN: u16 = 1 << 8;
const PM1_STS_SLPBTN: u16 = 1 << 9;
const PM1_STS_RTC: u16 = 1 << 10;
const PM1_STS_WAK: u16 = 1 << 15;

const PM1_EN_PWRBTN: u16 = 1 << 8;
const PM1_EN_SLPBTN: u16 = 1 << 9;
const PM1_EN_RTC: u16 = 1 << 10;
const PM1_EN_WAK: u16 = 1 << 15;

const PM1_CNT_SCI_EN: u16 = 1 << 0;
const PM1_CNT_SLP_EN: u16 = 1 << 13;
const PM1_CNT_SLP_TYP_SHIFT: u16 = 10;

const FADT_OFF_DSDT: usize = 40;
const FADT_OFF_SCI_INT: usize = 46;
const FADT_OFF_SMI_CMD: usize = 48;
const FADT_OFF_ACPI_ENABLE: usize = 52;
const FADT_OFF_PM1A_EVT_BLK: usize = 56;
const FADT_OFF_PM1B_EVT_BLK: usize = 60;
const FADT_OFF_PM1A_CNT_BLK: usize = 64;
const FADT_OFF_PM1B_CNT_BLK: usize = 68;
const FADT_OFF_PM1_EVT_LEN: usize = 88;

// Cached ports
static PM1A_STS: AtomicU16 = AtomicU16::new(0);
static PM1A_EN: AtomicU16 = AtomicU16::new(0);
static PM1A_CNT: AtomicU16 = AtomicU16::new(0);
static PM1B_STS: AtomicU16 = AtomicU16::new(0);
static PM1B_EN: AtomicU16 = AtomicU16::new(0);
static PM1B_CNT: AtomicU16 = AtomicU16::new(0);
static SCI_VECTOR: AtomicU8 = AtomicU8::new(0);

// SLP_TYP values indexed by S-state number.
// Fallback S5 = 5 for common QEMU/Bochs setups; parse_dsdt() can override.
static SLP_TYP_A: [AtomicU8; 6] = [
    AtomicU8::new(0),
    AtomicU8::new(0),
    AtomicU8::new(0),
    AtomicU8::new(0),
    AtomicU8::new(0),
    AtomicU8::new(5),
];
static SLP_TYP_B: [AtomicU8; 6] = [
    AtomicU8::new(0),
    AtomicU8::new(0),
    AtomicU8::new(0),
    AtomicU8::new(0),
    AtomicU8::new(0),
    AtomicU8::new(5),
];

#[inline(always)]
unsafe fn outb(port: u16, val: u8) {
    core::arch::asm!("out dx, al", in("dx") port, in("al") val, options(nomem, nostack));
}

#[inline(always)]
unsafe fn outw(port: u16, val: u16) {
    core::arch::asm!("out dx, ax", in("dx") port, in("ax") val, options(nomem, nostack));
}

#[inline(always)]
unsafe fn inw(port: u16) -> u16 {
    let val: u16;
    core::arch::asm!("in ax, dx", out("ax") val, in("dx") port, options(nomem, nostack));
    val
}

unsafe fn fadt_u8(base: *const u8, off: usize) -> u8 {
    base.add(off).read_unaligned()
}

unsafe fn fadt_u16(base: *const u8, off: usize) -> u16 {
    (base.add(off) as *const u16).read_unaligned()
}

unsafe fn fadt_u32(base: *const u8, off: usize) -> u32 {
    (base.add(off) as *const u32).read_unaligned()
}

pub unsafe fn parse_fadt() -> Result<(), &'static str> {
    let hdr = super::find_table(b"FACP").ok_or("FADT not found")?;
    let total = (*hdr).len as usize;
    if total < FADT_OFF_PM1_EVT_LEN + 1 {
        return Err("FADT too short");
    }

    let base = hdr as *const u8;
    let sci_irq = fadt_u16(base, FADT_OFF_SCI_INT);
    let smi_cmd = fadt_u32(base, FADT_OFF_SMI_CMD);
    let acpi_enable = fadt_u8(base, FADT_OFF_ACPI_ENABLE);
    let pm1a_evt = fadt_u32(base, FADT_OFF_PM1A_EVT_BLK);
    let pm1b_evt = fadt_u32(base, FADT_OFF_PM1B_EVT_BLK);
    let pm1a_cnt = fadt_u32(base, FADT_OFF_PM1A_CNT_BLK);
    let pm1b_cnt = fadt_u32(base, FADT_OFF_PM1B_CNT_BLK);
    let evt_len = fadt_u8(base, FADT_OFF_PM1_EVT_LEN);

    if pm1a_evt == 0 || pm1a_cnt == 0 {
        return Err("missing PM1a blocks");
    }

    let half = (evt_len / 2) as u16;
    PM1A_STS.store(pm1a_evt as u16, Ordering::Relaxed);
    PM1A_EN.store((pm1a_evt as u16).wrapping_add(half), Ordering::Relaxed);
    PM1A_CNT.store(pm1a_cnt as u16, Ordering::Relaxed);

    if pm1b_evt != 0 {
        PM1B_STS.store(pm1b_evt as u16, Ordering::Relaxed);
        PM1B_EN.store((pm1b_evt as u16).wrapping_add(half), Ordering::Relaxed);
    }
    if pm1b_cnt != 0 {
        PM1B_CNT.store(pm1b_cnt as u16, Ordering::Relaxed);
    }

    let vector = (sci_irq as u8).wrapping_add(32);
    SCI_VECTOR.store(vector, Ordering::Relaxed);

    let cnt = inw(PM1A_CNT.load(Ordering::Relaxed));
    if cnt & PM1_CNT_SCI_EN == 0 && smi_cmd != 0 && acpi_enable != 0 {
        outb(smi_cmd as u16, acpi_enable);
        let mut spins = 0u32;
        while inw(PM1A_CNT.load(Ordering::Relaxed)) & PM1_CNT_SCI_EN == 0 {
            spins = spins.wrapping_add(1);
            if spins > 1_000_000 {
                break;
            }
            core::hint::spin_loop();
        }
    }

    Ok(())
}

unsafe fn scan_s5(aml: &[u8]) {
    let name = *b"_S5_";
    let mut i = 0;
    while i + 10 < aml.len() {
        if aml[i..i + 4] == name {
            let op = aml[i + 4];
            if (op == 0x12 || op == 0x10) && aml[i + 7] == 0x0A && aml[i + 9] == 0x0A {
                SLP_TYP_A[5].store(aml[i + 8], Ordering::Relaxed);
                SLP_TYP_B[5].store(aml[i + 10], Ordering::Relaxed);
                break;
            }
        }
        i += 1;
    }
}

pub unsafe fn parse_dsdt() -> Result<(), &'static str> {
    let fadt = super::find_table(b"FACP").ok_or("FADT absent")?;
    if (*fadt).len < 44 {
        return Err("FADT too short for DSDT pointer");
    }

    let base = fadt as *const u8;
    let dsdt_phys = fadt_u32(base, FADT_OFF_DSDT) as usize;
    if dsdt_phys == 0 {
        return Err("null DSDT");
    }

    let dsdt = &*(dsdt_phys as *const SdtHeader);
    if &dsdt.sig != b"DSDT" {
        return Err("bad DSDT signature");
    }

    let aml_start = dsdt_phys + core::mem::size_of::<SdtHeader>();
    let aml_len = (dsdt.len as usize).saturating_sub(core::mem::size_of::<SdtHeader>());
    let aml = core::slice::from_raw_parts(aml_start as *const u8, aml_len);
    scan_s5(aml);

    Ok(())
}

unsafe fn pm1_read_status() -> u16 {
    let mut v = inw(PM1A_STS.load(Ordering::Relaxed));
    let p = PM1B_STS.load(Ordering::Relaxed);
    if p != 0 {
        v |= inw(p);
    }
    v
}

unsafe fn pm1_ack_status(bits: u16) {
    let p = PM1A_STS.load(Ordering::Relaxed);
    if p != 0 {
        outw(p, bits);
    }
    let p = PM1B_STS.load(Ordering::Relaxed);
    if p != 0 {
        outw(p, bits);
    }
}

unsafe fn pm1_write_enable(bits: u16) {
    let p = PM1A_EN.load(Ordering::Relaxed);
    if p != 0 {
        outw(p, bits);
    }
    let p = PM1B_EN.load(Ordering::Relaxed);
    if p != 0 {
        outw(p, bits);
    }
}

fn handle_power_button() {
    println!("acpi/power: power button");
    shutdown();
}

fn handle_sleep_button() {
    println!("acpi/power: sleep button");
    unsafe {
        enter_sleep_state(3);
    }
}

fn handle_wake() {
    println!("acpi/power: wake event");
}

fn handle_rtc_alarm() {
    println!("acpi/power: rtc alarm");
}

fn sci_irq_handler(_frame: &mut crate::arch::x86_64::idt::InterruptFrame) {
    unsafe {
        let sts = pm1_read_status();
        pm1_ack_status(sts);

        if sts & PM1_STS_PWRBTN != 0 {
            handle_power_button();
        }
        if sts & PM1_STS_SLPBTN != 0 {
            handle_sleep_button();
        }
        if sts & PM1_STS_RTC != 0 {
            handle_rtc_alarm();
        }
        if sts & PM1_STS_WAK != 0 {
            handle_wake();
        }

        crate::arch::x86_64::apic::send_eoi();
    }
}

pub unsafe fn enter_sleep_state(sx: usize) {
    if sx > 5 {
        println!("acpi/power: invalid S-state {}", sx);
        return;
    }

    let typ_a = SLP_TYP_A[sx].load(Ordering::Relaxed) as u16;
    let typ_b = SLP_TYP_B[sx].load(Ordering::Relaxed) as u16;
    let cnt_a = PM1A_CNT.load(Ordering::Relaxed);
    let cnt_b = PM1B_CNT.load(Ordering::Relaxed);

    if cnt_a == 0 {
        println!("acpi/power: PM1A_CNT not initialized");
        return;
    }

    core::arch::asm!("cli", options(nomem, nostack));

    let val_a = PM1_CNT_SCI_EN | (typ_a << PM1_CNT_SLP_TYP_SHIFT) | PM1_CNT_SLP_EN;
    outw(cnt_a, val_a);

    if cnt_b != 0 {
        let val_b = PM1_CNT_SCI_EN | (typ_b << PM1_CNT_SLP_TYP_SHIFT) | PM1_CNT_SLP_EN;
        outw(cnt_b, val_b);
    }

    loop {
        core::arch::asm!("hlt", options(nomem, nostack));
    }
}

pub fn shutdown() {
    println!("acpi/power: shutdown");
    unsafe {
        enter_sleep_state(5);
        outw(0x604, 0x2000);
        outw(0x4004, 0x3400);
    }
    loop {
        unsafe {
            core::arch::asm!("hlt", options(nomem, nostack));
        }
    }
}

pub fn reboot() {
    println!("acpi/power: reboot");
    unsafe {
        outb(0xCF9, 0x02);
        outb(0xCF9, 0x06);

        for _ in 0..100_000u32 {
            core::hint::spin_loop();
        }

        outb(0x64, 0xFE);
    }

    loop {
        unsafe {
            core::arch::asm!("hlt", options(nomem, nostack));
        }
    }
}

pub fn init() {
    unsafe {
        if let Err(e) = parse_fadt() {
            println!("acpi/power: FADT parse failed: {}", e);
            return;
        }

        if let Err(e) = parse_dsdt() {
            println!("acpi/power: DSDT parse warning: {}", e);
        }

        pm1_ack_status(0xFFFF);
        pm1_write_enable(PM1_EN_PWRBTN | PM1_EN_SLPBTN | PM1_EN_RTC | PM1_EN_WAK);

        let vector = SCI_VECTOR.load(Ordering::Relaxed);
        if vector >= 32 {
            crate::arch::x86_64::idt::register_irq(vector, sci_irq_handler);
        }

        println!("acpi/power: initialized");
    }
}
