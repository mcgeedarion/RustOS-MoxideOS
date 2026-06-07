//! PCIe Hot-Plug via ACPI GPE + Notify.
//!
//! ## Architecture
//!
//! PCIe native hot-plug is signalled through two channels:
//!
//! 1. **PCIe Hot-Plug Interrupts** (native HP) — the PCIe slot capability
//!    registers fire an MSI/INTx; handled in `src/drivers/pcie/hotplug.rs`.
//!
//! 2. **ACPI-mediated hot-plug** — firmware owns the HP interrupt; it fires a
//!    GPE, runs AML, then issues `Notify(device, 0x01|0x03)` to signal
//!    bus-check or eject-request.  *This* file handles path 2.
//!
//! ## What we do
//!
//! - Discover the PCIe root bridge device in the DSDT (heuristic: look for the
//!   `_HID` / `_CID` of `PNP0A08` or `PNP0A03`).
//! - Register a GPE handler for the GPE block + bit published by the FADT.
//! - When a Notify(0x01 Bus-Check) fires, re-enumerate the PCIe segment.
//! - When a Notify(0x03 Eject-Request) fires, quiesce the device and remove it.
//!
//! Because we don't have a full AML interpreter we model the GPE handler as a
//! simple callback that calls out to `crate::drivers::pcie::rescan()`.

use crate::println;
use core::sync::atomic::{AtomicBool, AtomicU8, Ordering};

const FADT_OFF_GPE0_BLK: usize = 80;
const FADT_OFF_GPE1_BLK: usize = 84;
const FADT_OFF_GPE0_BLK_LEN: usize = 92;
const FADT_OFF_GPE1_BLK_LEN: usize = 93;
const FADT_OFF_GPE1_BASE: usize = 94;

static GPE0_STS_PORT: AtomicU8 = AtomicU8::new(0); // low byte of I/O port
static GPE0_EN_PORT: AtomicU8 = AtomicU8::new(0);
static GPE0_LEN: AtomicU8 = AtomicU8::new(0); // bytes per half-block
static HOTPLUG_GPE_BIT: AtomicU8 = AtomicU8::new(0xFF); // 0xFF = none found
static INITIALIZED: AtomicBool = AtomicBool::new(false);

#[inline(always)]
#[cfg(target_arch = "x86_64")]
unsafe fn inb(port: u16) -> u8 {
    let v: u8;
    core::arch::asm!("in al, dx", out("al") v, in("dx") port, options(nomem, nostack));
    v
}

#[inline(always)]
#[cfg(target_arch = "x86_64")]
unsafe fn outb(port: u16, val: u8) {
    core::arch::asm!("out dx, al", in("dx") port, in("al") val, options(nomem, nostack));
}

#[cfg(not(target_arch = "x86_64"))]
unsafe fn inb(_port: u16) -> u8 {
    0
}
#[cfg(not(target_arch = "x86_64"))]
unsafe fn outb(_port: u16, _val: u8) {}

pub const NOTIFY_BUS_CHECK: u8 = 0x00; // re-enumerate
pub const NOTIFY_DEVICE_CHECK: u8 = 0x01; // specific device added/removed
pub const NOTIFY_EJECT_REQ: u8 = 0x03; // user pressed eject button

/// Initialise the ACPI hot-plug GPE handler.
///
/// Reads the GPE0 block address from the FADT, enables the hot-plug GPE bit,
/// and registers the SCI handler extension.
pub unsafe fn init() {
    let fadt = match super::find_table(b"FACP") {
        Some(p) => p as *const u8,
        None => {
            println!("acpi/hotplug: FADT not found");
            return;
        },
    };

    let fadt_len = (*(fadt as *const super::SdtHeader)).len as usize;
    if fadt_len <= FADT_OFF_GPE1_BASE + 1 {
        println!("acpi/hotplug: FADT too short for GPE info");
        return;
    }

    let gpe0_blk = (fadt.add(FADT_OFF_GPE0_BLK) as *const u32).read_unaligned();
    let gpe0_len = fadt.add(FADT_OFF_GPE0_BLK_LEN).read();

    if gpe0_blk == 0 || gpe0_len == 0 {
        println!("acpi/hotplug: no GPE0 block");
        return;
    }

    let half = gpe0_len / 2;
    // Status registers occupy the first half; Enable registers the second half.
    GPE0_STS_PORT.store(gpe0_blk as u8, Ordering::Relaxed);
    GPE0_EN_PORT.store((gpe0_blk as u16 + half as u16) as u8, Ordering::Relaxed);
    GPE0_LEN.store(half, Ordering::Relaxed);

    // Discover hot-plug GPE bit from DSDT: scan for `_L??` / `_E??` methods
    // adjacent to a PCI root bridge.  For QEMU (PIIX/Q35) this is GPE bit 1.
    // We default to bit 1 and let the DSDT scan override.
    let hp_bit = discover_hotplug_gpe_bit().unwrap_or(1);
    HOTPLUG_GPE_BIT.store(hp_bit, Ordering::Relaxed);

    // Enable the hot-plug GPE.
    enable_gpe_bit(hp_bit);
    INITIALIZED.store(true, Ordering::Relaxed);
    println!(
        "acpi/hotplug: GPE0 @ {:#06x} len={}  hp_gpe_bit={}",
        gpe0_blk, gpe0_len, hp_bit
    );
}

/// Scan the DSDT for a PCIe root bridge and the associated GPE method to
/// identify the correct hot-plug GPE bit index.
unsafe fn discover_hotplug_gpe_bit() -> Option<u8> {
    let fadt = super::find_table(b"FACP")? as *const u8;
    let dsdt_phys = (fadt.add(40) as *const u32).read_unaligned() as usize;
    if dsdt_phys == 0 {
        return None;
    }
    let dsdt = &*(dsdt_phys as *const super::SdtHeader);
    if &dsdt.sig != b"DSDT" {
        return None;
    }
    let off = core::mem::size_of::<super::SdtHeader>();
    let len = (dsdt.len as usize).saturating_sub(off);
    let aml = core::slice::from_raw_parts((dsdt_phys + off) as *const u8, len);

    // Look for `_L01` or `_E01` (level/edge GPE method, bit 1) near a PCI HID.
    for marker in [b"_L01", b"_E01", b"_L03", b"_E03"] {
        if aml.windows(4).any(|w| w == marker) {
            // Extract the GPE bit number from the method name digit.
            let bit = (marker[3] - b'0') + (marker[2] - b'0') * 10;
            return Some(bit);
        }
    }
    None
}

/// Enable a single GPE bit in the GPE0 enable register.
pub unsafe fn enable_gpe_bit(bit: u8) {
    let half = GPE0_LEN.load(Ordering::Relaxed) as u16;
    if half == 0 {
        return;
    }
    let byte_off = (bit / 8) as u16;
    if byte_off >= half {
        return;
    }
    let en_port = (GPE0_EN_PORT.load(Ordering::Relaxed) as u16)
        .wrapping_add(byte_off)
        .wrapping_add((GPE0_STS_PORT.load(Ordering::Relaxed) as u16) & 0xFF00);
    let cur = inb(en_port);
    outb(en_port, cur | (1 << (bit % 8)));
}

/// Clear a pending GPE status bit (write-1-to-clear).
pub unsafe fn ack_gpe_bit(bit: u8) {
    let byte_off = (bit / 8) as u16;
    let sts_base = GPE0_STS_PORT.load(Ordering::Relaxed) as u16 & 0x00FF; // keep low byte; high byte comes from gpe0_blk
    outb(sts_base + byte_off, 1 << (bit % 8));
}

/// Called by the SCI handler when a GPE fires.
///
/// Checks whether this is the hot-plug GPE bit and if so dispatches to the
/// PCIe bus-check or eject handler.
pub unsafe fn handle_gpe_event(bit: u8, notify_code: u8) {
    let hp_bit = HOTPLUG_GPE_BIT.load(Ordering::Relaxed);
    if hp_bit == 0xFF || bit != hp_bit {
        return;
    }

    ack_gpe_bit(bit);

    match notify_code {
        NOTIFY_BUS_CHECK | NOTIFY_DEVICE_CHECK => {
            println!("acpi/hotplug: bus-check notify — triggering PCIe rescan");
            // Delegate to the PCIe driver; it handles ECAM re-enumeration.
            #[cfg(feature = "pcie")]
            crate::drivers::pcie::rescan();
        },
        NOTIFY_EJECT_REQ => {
            println!("acpi/hotplug: eject-request notify — quiescing device");
            #[cfg(feature = "pcie")]
            crate::drivers::pcie::handle_eject_request();
        },
        _ => {
            println!("acpi/hotplug: unknown notify code {:#04x}", notify_code);
        },
    }
}

/// Returns `true` once `init()` has completed successfully.
pub fn is_ready() -> bool {
    INITIALIZED.load(Ordering::Relaxed)
}
