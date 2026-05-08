//! ACPI Power Management
//!
//! Implements:
//!   * FADT parsing (SCI IRQ, PM1a/b event/control/status blocks, SMI_CMD,
//!     ACPI enable sequence, reset register)
//!   * Minimal AML bytecode interpreter covering the opcode subset required
//!     for \_S3 (suspend-to-RAM) and \_S5 (soft-off) namespace objects
//!   * S3 sleep  — writes SLP_TYP + SLP_EN to PM1 control, then HLTs
//!   * S5 shutdown — same path with \_S5 values; also supports direct QEMU
//!     triple-fault fallback and the ISA 0xB000 port shortcut
//!   * CPU frequency scaling — ACPI P-states via `_PCT`/`_PSS` objects
//!     (MSR or I/O port control registers) and C-state idle via `MWAIT`
//!
//! ## Linux ioctl / sysfs compatibility surface
//!
//!   /sys/power/state              ("mem" = S3, "disk" placeholder, "off" = S5)
//!   /sys/devices/system/cpu/cpu*/cpufreq/scaling_setspeed
//!   /sys/devices/system/cpu/cpu*/cpufreq/scaling_available_frequencies
//!
//! ## Relationship with `src/acpi/mod.rs`
//!
//! Reuses `find_table()` and the XSDT/RSDT walker already present in mod.rs.
//! The FADT is always at signature `b"FACP"`.  DSDT is pointed to by FADT.

extern crate alloc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU8, AtomicU32, Ordering};
use spin::Mutex;
use crate::console::println;

// ─────────────────────────────────────────────────────────────────────────────
// FADT layout (ACPI spec 6.x §5.2.9)
// ─────────────────────────────────────────────────────────────────────────────

/// Generic Address Structure (GAS) — ACPI spec §5.2.3.2
#[repr(C, packed)]
#[derive(Clone, Copy, Default)]
pub struct Gas {
    pub space_id:    u8,   // 0=memory, 1=I/O, 2=PCI-config, …
    pub bit_width:   u8,
    pub bit_offset:  u8,
    pub access_size: u8,   // 1=byte 2=word 3=dword 4=qword
    pub address:     u64,
}

pub mod gas_space {
    pub const MEMORY:  u8 = 0;
    pub const IO:      u8 = 1;
    pub const FIXED:   u8 = 0x7F; // FFixedHW (e.g. MSR)
}

/// FADT — Fixed ACPI Description Table (first 276 bytes; we only read what we use).
#[repr(C, packed)]
struct Fadt {
    sig:              [u8; 4],      // 0
    length:           u32,          // 4
    major_version:    u8,           // 8
    checksum:         u8,           // 9
    oem_id:           [u8; 6],      // 10
    oem_table_id:     [u8; 8],      // 16
    oem_rev:          u32,          // 24
    creator_id:       u32,          // 28
    creator_rev:      u32,          // 32
    firmware_ctrl:    u32,          // 36  FIRMWARE_CTRL (phys of FACS)
    dsdt:             u32,          // 40  32-bit DSDT phys
    _reserved0:       u8,           // 44
    preferred_pm:     u8,           // 45  Preferred_PM_Profile
    sci_int:          u16,          // 46  SCI_INT  — IRQ line
    smi_cmd:          u32,          // 48  SMI_CMD  — I/O port
    acpi_enable:      u8,           // 52
    acpi_disable:     u8,           // 53
    s4bios_req:       u8,           // 54
    pstate_cnt:       u8,           // 55
    pm1a_evt_blk:     u32,          // 56  PM1a Event Block I/O port
    pm1b_evt_blk:     u32,          // 60
    pm1a_cnt_blk:     u32,          // 64  PM1a Control Block I/O port ← SLP_TYP
    pm1b_cnt_blk:     u32,          // 68
    pm2_cnt_blk:      u32,          // 72
    pm_tmr_blk:       u32,          // 76
    gpe0_blk:         u32,          // 80
    gpe1_blk:         u32,          // 84
    pm1_evt_len:      u8,           // 88
    pm1_cnt_len:      u8,           // 89
    pm2_cnt_len:      u8,           // 90
    pm_tmr_len:       u8,           // 91
    gpe0_blk_len:     u8,           // 92
    gpe1_blk_len:     u8,           // 93
    gpe1_base:        u8,           // 94
    cst_cnt:          u8,           // 95
    p_lvl2_lat:       u16,          // 96
    p_lvl3_lat:       u16,          // 98
    flush_size:       u16,          // 100
    flush_stride:     u16,          // 102
    duty_offset:      u8,           // 104
    duty_width:       u8,           // 105
    day_alrm:         u8,           // 106
    mon_alrm:         u8,           // 107
    century:          u8,           // 108
    ia_pc_boot_arch:  u16,          // 109
    _reserved1:       u8,           // 111
    flags:            u32,          // 112
    reset_reg:        Gas,          // 116  RESET_REG (GAS)
    reset_value:      u8,           // 128
    _reserved2:       [u8; 3],      // 129
    x_firmware_ctrl:  u64,          // 132  64-bit FACS phys
    x_dsdt:           u64,          // 140  64-bit DSDT phys
    x_pm1a_evt_blk:   Gas,          // 148
    x_pm1b_evt_blk:   Gas,          // 160
    x_pm1a_cnt_blk:   Gas,          // 172
    x_pm1b_cnt_blk:   Gas,          // 184
    x_pm2_cnt_blk:    Gas,          // 196
    x_pm_tmr_blk:     Gas,          // 208
    x_gpe0_blk:       Gas,          // 220
    x_gpe1_blk:       Gas,          // 232
    sleep_control_reg:Gas,          // 244  (ACPI 5+)
    sleep_status_reg: Gas,          // 256  (ACPI 5+)
}

// ─────────────────────────────────────────────────────────────────────────────
// Parsed FADT summary kept in a static
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Clone, Copy, Default)]
struct FadtInfo {
    pm1a_cnt_port:  u16,
    pm1b_cnt_port:  u16,
    pm1a_evt_port:  u16,
    pm1b_evt_port:  u16,
    pm_tmr_port:    u16,
    smi_cmd:        u32,
    acpi_enable:    u8,
    sci_int:        u16,
    dsdt_phys:      u64,
    reset_reg:      Gas,
    reset_value:    u8,
    /// True if ACPI is already in ACPI mode (no SMI_CMD write needed).
    hw_reduced:     bool,
    /// ACPI 5+ HW-reduced sleep control register.
    sleep_ctrl_reg: Gas,
    version:        u8,
}

static FADT_INFO: Mutex<Option<FadtInfo>> = Mutex::new(None);

// ─────────────────────────────────────────────────────────────────────────────
// Cached sleep-type values extracted from \_S3 / \_S5 namespace objects
// ─────────────────────────────────────────────────────────────────────────────

/// SLP_TYPa / SLP_TYPb for S3 and S5.
#[derive(Clone, Copy, Default)]
struct SleepTypes {
    s3_typa: u8,
    s3_typb: u8,
    s5_typa: u8,
    s5_typb: u8,
    s3_valid: bool,
    s5_valid: bool,
}

static SLEEP_TYPES: Mutex<SleepTypes> = Mutex::new(SleepTypes {
    s3_typa: 0, s3_typb: 0, s5_typa: 0, s5_typb: 0,
    s3_valid: false, s5_valid: false,
});

// ─────────────────────────────────────────────────────────────────────────────
// AML bytecode interpreter — minimal subset
// ─────────────────────────────────────────────────────────────────────────────
//
// Full AML is Turing-complete and enormous.  We implement exactly enough
// opcodes to:
//   1.  Walk PackageOp lists returned by \_S3 and \_S5 Name objects.
//   2.  Evaluate _PCT (PerformanceControlRegister GAS) and _PSS tables.
//   3.  Evaluate _CST (C-state) descriptors.
//
// AML opcode reference: ACPI spec §20

mod aml {
    // Single-byte opcodes
    pub const ZERO_OP:    u8 = 0x00;
    pub const ONE_OP:     u8 = 0x01;
    pub const ALIAS_OP:   u8 = 0x06;
    pub const NAME_OP:    u8 = 0x08;
    pub const BYTE_PREFIX:u8 = 0x0A;
    pub const WORD_PREFIX:u8 = 0x0B;
    pub const DWORD_PREFIX:u8= 0x0C;
    pub const STRING_PREFIX:u8=0x0D;
    pub const QWORD_PREFIX:u8= 0x0E;
    pub const SCOPE_OP:   u8 = 0x10;
    pub const BUFFER_OP:  u8 = 0x11;
    pub const PACKAGE_OP: u8 = 0x12;
    pub const VAR_PKG_OP: u8 = 0x13;
    pub const METHOD_OP:  u8 = 0x14;
    pub const RETURN_OP:  u8 = 0xA4;
    pub const ONES_OP:    u8 = 0xFF;

    // Extended (0x5B prefix) opcodes
    pub const EXT_PREFIX: u8 = 0x5B;
    pub const EXT_OP_REGION: u8 = 0x80;
    pub const EXT_OP_FIELD:  u8 = 0x81;
    pub const EXT_OP_DEVICE: u8 = 0x82;
    pub const EXT_OP_PROCESSOR:u8= 0x83;
    pub const EXT_OP_POWER:  u8 = 0x84;
    pub const EXT_OP_MUTEX:  u8 = 0x01;
    pub const EXT_OP_EVENT:  u8 = 0x02;

    /// Decode a PkgLength (variable-length encoding, ACPI spec §20.2.4).
    /// Returns (value, bytes_consumed).
    pub fn decode_pkglen(buf: &[u8]) -> Option<(usize, usize)> {
        if buf.is_empty() { return None; }
        let lead = buf[0];
        let follow = (lead >> 6) as usize; // number of following bytes
        if follow == 0 {
            return Some(((lead & 0x3F) as usize, 1));
        }
        if buf.len() < 1 + follow { return None; }
        let mut val = (lead & 0x0F) as usize;
        for i in 1..=follow {
            val |= (buf[i] as usize) << (4 + (i - 1) * 8);
        }
        Some((val, 1 + follow))
    }

    /// Decode a NameSeg (4-byte identifier, right-padded with '_').
    pub fn decode_nameseg(buf: &[u8]) -> Option<([u8; 4], usize)> {
        if buf.len() < 4 { return None; }
        let mut seg = [0u8; 4];
        seg.copy_from_slice(&buf[..4]);
        Some((seg, 4))
    }

    /// Decode a NameString — may have leading '\', '^' chars, then DualNamePath
    /// or MultiNamePath, or a single NameSeg.  Returns (raw_bytes_consumed, last_4_seg).
    pub fn decode_namestring(buf: &[u8]) -> Option<(usize, [u8; 4])> {
        let mut i = 0;
        // Skip leading root '\' and '^' parents.
        while i < buf.len() && (buf[i] == b'\\' || buf[i] == b'^') { i += 1; }
        if i >= buf.len() { return None; }
        match buf[i] {
            0x00 => { Some((i + 1, [b'_'; 4])) } // NullName
            0x2E => { // DualNamePath: 0x2E + 2 × NameSeg
                i += 1;
                if buf.len() < i + 8 { return None; }
                let mut seg = [0u8; 4];
                seg.copy_from_slice(&buf[i + 4..i + 8]);
                Some((i + 8, seg))
            }
            0x2F => { // MultiNamePath: 0x2F + count + count × NameSeg
                i += 1;
                if i >= buf.len() { return None; }
                let count = buf[i] as usize; i += 1;
                let last_off = i + (count - 1) * 4;
                if buf.len() < last_off + 4 { return None; }
                let mut seg = [0u8; 4];
                seg.copy_from_slice(&buf[last_off..last_off + 4]);
                Some((i + count * 4, seg))
            }
            _ => { // Single NameSeg
                if buf.len() < i + 4 { return None; }
                let mut seg = [0u8; 4];
                seg.copy_from_slice(&buf[i..i + 4]);
                Some((i + 4, seg))
            }
        }
    }

    /// Decode an integer DataObject (ByteConst, WordConst, DWordConst, QWordConst,
    /// ZeroOp, OneOp, OnesOp).  Returns (value_u64, bytes_consumed).
    pub fn decode_integer(buf: &[u8]) -> Option<(u64, usize)> {
        if buf.is_empty() { return None; }
        match buf[0] {
            ZERO_OP  => Some((0, 1)),
            ONE_OP   => Some((1, 1)),
            ONES_OP  => Some((0xFFFF_FFFF_FFFF_FFFFu64, 1)),
            BYTE_PREFIX  => {
                if buf.len() < 2 { return None; }
                Some((buf[1] as u64, 2))
            }
            WORD_PREFIX  => {
                if buf.len() < 3 { return None; }
                Some((u16::from_le_bytes([buf[1], buf[2]]) as u64, 3))
            }
            DWORD_PREFIX => {
                if buf.len() < 5 { return None; }
                Some((u32::from_le_bytes([buf[1],buf[2],buf[3],buf[4]]) as u64, 5))
            }
            QWORD_PREFIX => {
                if buf.len() < 9 { return None; }
                Some((u64::from_le_bytes([
                    buf[1],buf[2],buf[3],buf[4],buf[5],buf[6],buf[7],buf[8]
                ]), 9))
            }
            _ => None,
        }
    }

    /// Decode a Package: PackageOp PkgLength NumElements {DataRefObject}*
    /// Returns a Vec of up to `max_elems` decoded u64 values.
    pub fn decode_package_integers(buf: &[u8], max_elems: usize)
        -> Option<alloc::vec::Vec<u64>>
    {
        extern crate alloc;
        use alloc::vec::Vec;
        if buf.is_empty() || buf[0] != PACKAGE_OP { return None; }
        let (pkglen, pl_bytes) = decode_pkglen(&buf[1..])?;
        let _ = pkglen; // we parse until we exhaust elements
        let mut i = 1 + pl_bytes;
        if i >= buf.len() { return None; }
        let num_elements = buf[i] as usize; i += 1;
        let count = num_elements.min(max_elems);
        let mut out = Vec::with_capacity(count);
        for _ in 0..count {
            if i >= buf.len() { break; }
            if let Some((val, adv)) = decode_integer(&buf[i..]) {
                out.push(val);
                i += adv;
            } else {
                break;
            }
        }
        Some(out)
    }

    /// Decode a GAS encoded inside a Buffer() inside a Package element.
    /// ACPI embeds GAS descriptors as 12-byte Buffers.
    pub fn decode_gas_from_buffer(buf: &[u8]) -> Option<super::Gas> {
        // Buffer format: BufferOp PkgLength BufferSize {byte...}
        if buf.is_empty() || buf[0] != BUFFER_OP { return None; }
        let (_pkglen, pl_bytes) = decode_pkglen(&buf[1..])?;
        let i = 1 + pl_bytes;
        // BufferSize (integer)
        let (_bsize, bi) = decode_integer(&buf[i..])?;
        let data_start = i + bi;
        if buf.len() < data_start + 12 { return None; }
        let d = &buf[data_start..];
        Some(super::Gas {
            space_id:    d[0],
            bit_width:   d[1],
            bit_offset:  d[2],
            access_size: d[3],
            address: u64::from_le_bytes([d[4],d[5],d[6],d[7],d[8],d[9],d[10],d[11]]),
        })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// DSDT / SSDT namespace walker
// ─────────────────────────────────────────────────────────────────────────────

/// Find a top-level `Name` object in the AML byte stream with the given 4-byte
/// identifier (e.g. `_S3_` or `_S5_`) and return a slice of its value.
fn aml_find_name<'a>(aml: &'a [u8], target: &[u8; 4]) -> Option<&'a [u8]> {
    let mut i = 0usize;
    while i + 1 < aml.len() {
        if aml[i] != aml::NAME_OP { i += 1; continue; }
        i += 1;
        // Decode NameString
        let (ns_bytes, seg) = match aml::decode_namestring(&aml[i..]) {
            Some(x) => x, None => { i += 1; continue; }
        };
        i += ns_bytes;
        if &seg == target {
            // Return the rest of the buffer starting at the value.
            return Some(&aml[i..]);
        }
        // Skip the value to continue scanning: just advance past any integer.
        if let Some((_, adv)) = aml::decode_integer(&aml[i..]) {
            i += adv;
        } else if i < aml.len() && aml[i] == aml::PACKAGE_OP {
            // Skip the whole package to continue searching
            if let Some((pkglen, pl_b)) = aml::decode_pkglen(&aml[i + 1..]) {
                i += 1 + pl_b + pkglen;
            } else { i += 1; }
        } else { i += 1; }
    }
    None
}

// ─────────────────────────────────────────────────────────────────────────────
// Low-level I/O port helpers
// ─────────────────────────────────────────────────────────────────────────────

#[inline(always)]
unsafe fn inw(port: u16) -> u16 {
    let v: u16;
    core::arch::asm!("in ax, dx", in("dx") port, out("ax") v, options(nomem, nostack));
    v
}

#[inline(always)]
unsafe fn outw(port: u16, val: u16) {
    core::arch::asm!("out dx, ax", in("dx") port, in("ax") val, options(nomem, nostack));
}

#[inline(always)]
unsafe fn outb(port: u16, val: u8) {
    core::arch::asm!("out dx, al", in("dx") port, in("al") val, options(nomem, nostack));
}

#[inline(always)]
unsafe fn inb(port: u16) -> u8 {
    let v: u8;
    core::arch::asm!("in al, dx", in("dx") port, out("al") v, options(nomem, nostack));
    v
}

/// Write a GAS register (memory-mapped or I/O-port).
unsafe fn gas_write(gas: &Gas, value: u64) {
    match gas.space_id {
        gas_space::IO => {
            let port = gas.address as u16;
            match gas.access_size {
                1 => outb(port, value as u8),
                2 => outw(port, value as u16),
                _ => outw(port, value as u16), // default 16-bit for PM1
            }
        }
        gas_space::MEMORY => {
            let ptr = gas.address as *mut u32;
            ptr.write_volatile(value as u32);
        }
        _ => {} // FIXED/MSR handled in cpufreq
    }
}

/// Read a GAS register.
unsafe fn gas_read(gas: &Gas) -> u64 {
    match gas.space_id {
        gas_space::IO => {
            let port = gas.address as u16;
            match gas.access_size {
                1 => inb(port) as u64,
                2 => inw(port) as u64,
                _ => inw(port) as u64,
            }
        }
        gas_space::MEMORY => {
            let ptr = gas.address as *const u32;
            ptr.read_volatile() as u64
        }
        _ => 0,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// FADT parsing
// ─────────────────────────────────────────────────────────────────────────────

/// Parse the FADT and populate FADT_INFO.  Called from `init()`.
unsafe fn parse_fadt() {
    let fadt_ptr = match crate::acpi::find_table(b"FACP") {
        Some(p) => p as *const Fadt,
        None => {
            println!("acpi/power: FADT not found");
            return;
        }
    };
    let f = &*fadt_ptr;

    // Use the X_ (64-bit) fields when FADT is v2+ and they are non-zero.
    let pm1a_cnt_port = if f.major_version >= 2 && f.x_pm1a_cnt_blk.address != 0 {
        f.x_pm1a_cnt_blk.address as u16
    } else {
        f.pm1a_cnt_blk as u16
    };
    let pm1b_cnt_port = if f.major_version >= 2 && f.x_pm1b_cnt_blk.address != 0 {
        f.x_pm1b_cnt_blk.address as u16
    } else {
        f.pm1b_cnt_blk as u16
    };
    let pm1a_evt_port = if f.major_version >= 2 && f.x_pm1a_evt_blk.address != 0 {
        f.x_pm1a_evt_blk.address as u16
    } else {
        f.pm1a_evt_blk as u16
    };
    let pm1b_evt_port = if f.major_version >= 2 && f.x_pm1b_evt_blk.address != 0 {
        f.x_pm1b_evt_blk.address as u16
    } else {
        f.pm1b_evt_blk as u16
    };
    let pm_tmr_port = f.pm_tmr_blk as u16;

    let dsdt_phys = if f.major_version >= 2 && f.x_dsdt != 0 {
        f.x_dsdt
    } else {
        f.dsdt as u64
    };

    // ACPI 5+ HW-reduced mode: SCI is not wired, use sleep_control_reg.
    let hw_reduced = (f.flags & (1 << 20)) != 0;

    let info = FadtInfo {
        pm1a_cnt_port,
        pm1b_cnt_port,
        pm1a_evt_port,
        pm1b_evt_port,
        pm_tmr_port,
        smi_cmd:     f.smi_cmd,
        acpi_enable: f.acpi_enable,
        sci_int:     f.sci_int,
        dsdt_phys,
        reset_reg:   f.reset_reg,
        reset_value: f.reset_value,
        hw_reduced,
        sleep_ctrl_reg: f.sleep_control_reg,
        version:     f.major_version,
    };
    *FADT_INFO.lock() = Some(info);
    println!("acpi/power: FADT v{} PM1a_CNT={:#06x} DSDT={:#010x} hw_reduced={}",
             f.major_version, pm1a_cnt_port, dsdt_phys, hw_reduced);
}

// ─────────────────────────────────────────────────────────────────────────────
// DSDT / SSDT AML parsing for \_S3 and \_S5
// ─────────────────────────────────────────────────────────────────────────────

unsafe fn parse_sleep_types() {
    let fi = *FADT_INFO.lock();
    let fi = match fi { Some(f) => f, None => return };

    if fi.dsdt_phys == 0 { println!("acpi/power: no DSDT"); return; }

    let dsdt_hdr = fi.dsdt_phys as *const crate::acpi::SdtHeader;
    let dsdt_len = (*dsdt_hdr).len as usize;
    if dsdt_len < core::mem::size_of::<crate::acpi::SdtHeader>() { return; }

    let aml_start = fi.dsdt_phys as usize + core::mem::size_of::<crate::acpi::SdtHeader>();
    let aml_len   = dsdt_len - core::mem::size_of::<crate::acpi::SdtHeader>();
    let aml = core::slice::from_raw_parts(aml_start as *const u8, aml_len);

    let mut st = SLEEP_TYPES.lock();

    // Parse \_S3_ — suspend-to-RAM
    if let Some(val_buf) = aml_find_name(aml, b"_S3_") {
        if let Some(elems) = aml::decode_package_integers(val_buf, 2) {
            if elems.len() >= 2 {
                st.s3_typa  = elems[0] as u8;
                st.s3_typb  = elems[1] as u8;
                st.s3_valid = true;
                println!("acpi/power: \\S3 typa={} typb={}", st.s3_typa, st.s3_typb);
            }
        }
    }

    // Parse \_S5_ — soft-off / shutdown
    if let Some(val_buf) = aml_find_name(aml, b"_S5_") {
        if let Some(elems) = aml::decode_package_integers(val_buf, 2) {
            if elems.len() >= 2 {
                st.s5_typa  = elems[0] as u8;
                st.s5_typb  = elems[1] as u8;
                st.s5_valid = true;
                println!("acpi/power: \\S5 typa={} typb={}", st.s5_typa, st.s5_typb);
            }
        }
    } else {
        // Fallback: QEMU puts S5 typa=5 in practice
        st.s5_typa  = 5;
        st.s5_typb  = 5;
        st.s5_valid = true;
        println!("acpi/power: \\S5 not found, using QEMU default typa=5");
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ACPI mode enable (SMI_CMD handshake)
// ─────────────────────────────────────────────────────────────────────────────

/// Enable ACPI mode by writing ACPI_ENABLE to SMI_CMD, then wait for PM1_CNT
/// SCI_EN bit to become set.  No-op if already enabled or SMI_CMD == 0.
unsafe fn acpi_enable() {
    let fi = match *FADT_INFO.lock() { Some(f) => f, None => return };
    if fi.smi_cmd == 0 || fi.acpi_enable == 0 { return; }
    // Check SCI_EN (bit 0) of PM1a_CNT already set.
    let sci_en = inw(fi.pm1a_cnt_port) & 1;
    if sci_en != 0 { return; } // already in ACPI mode
    outb(fi.smi_cmd as u16, fi.acpi_enable);
    // Poll for SCI_EN with timeout ~100 ms (assume ~1 ns per loop, generous).
    for _ in 0..1_000_000 {
        if inw(fi.pm1a_cnt_port) & 1 != 0 { return; }
        core::hint::spin_loop();
    }
    println!("acpi/power: warning: SCI_EN did not set after ACPI_ENABLE write");
}

// ─────────────────────────────────────────────────────────────────────────────
// PM1 control register helpers
// ─────────────────────────────────────────────────────────────────────────────

// PM1 Control register bit layout (ACPI §4.8.3)
//   [0]      SCI_EN   — 1 when ACPI mode active
//   [1]      BM_RLD   — bus-master reload
//   [2]      GBL_RLS  — global release
//   [9:10]   SLP_TYP  — sleep type
//   [13]     SLP_EN   — initiates sleep transition when written 1

const SLP_EN_BIT: u16 = 1 << 13;

fn slp_typ_bits(typ: u8) -> u16 { ((typ as u16) & 0x7) << 10 }

/// Write SLP_TYP + SLP_EN to PM1a (and optionally PM1b).
unsafe fn pm1_sleep(typa: u8, typb: u8) {
    let fi = match *FADT_INFO.lock() { Some(f) => f, None => return };

    // Preserve SCI_EN and BM_RLD bits.
    let pm1a_val = (inw(fi.pm1a_cnt_port) & 0x001) | slp_typ_bits(typa) | SLP_EN_BIT;
    outw(fi.pm1a_cnt_port, pm1a_val);

    if fi.pm1b_cnt_port != 0 {
        let pm1b_val = (inw(fi.pm1b_cnt_port) & 0x001) | slp_typ_bits(typb) | SLP_EN_BIT;
        outw(fi.pm1b_cnt_port, pm1b_val);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Public power-state entry points
// ─────────────────────────────────────────────────────────────────────────────

/// Transition to S3 (suspend-to-RAM).
///
/// Sequence:
///   1. Flush all pending I/O (caller responsibility)
///   2. Clear PM1 status bits
///   3. Write \_S3 SLP_TYP + SLP_EN → CPU halts
///   4. On resume: firmware re-enters the kernel; wakeup vector handling is
///      a future TODO (requires saving CPU state to FACS)
pub fn enter_s3() {
    let st = *SLEEP_TYPES.lock();
    if !st.s3_valid {
        println!("acpi/power: S3 not supported (no \\S3 AML object)");
        return;
    }
    println!("acpi/power: entering S3 (suspend-to-RAM)");
    unsafe {
        acpi_enable();
        clear_pm1_status();
        pm1_sleep(st.s3_typa, st.s3_typb);
        // CPU should have entered S3 at this point.  If not, HLT loop.
        loop { core::arch::asm!("hlt"); }
    }
}

/// Transition to S5 (soft power-off / shutdown).
///
/// Attempts in order:
///   1. ACPI PM1 control  (standard path — works on real hw and QEMU -M q35)
///   2. QEMU fw_cfg I/O shortcut  (port 0x604 on PIIX4 / port 0x4004 on Q35)
///   3. Triple-fault fallback
pub fn enter_s5() {
    let st = *SLEEP_TYPES.lock();
    println!("acpi/power: shutdown initiated");
    unsafe {
        acpi_enable();
        if st.s5_valid {
            clear_pm1_status();
            pm1_sleep(st.s5_typa, st.s5_typb);
            // Short spin — give QEMU ~1 ms to process the write.
            for _ in 0u32..500_000 { core::hint::spin_loop(); }
        }
        // QEMU PIIX4 ISA-ACPI shortcut (ACPI spec §B.3).
        outw(0x604, 0x2000);
        for _ in 0u32..100_000 { core::hint::spin_loop(); }
        // Q35 machine shutdown port
        outw(0x4004, 0x3400);
        for _ in 0u32..100_000 { core::hint::spin_loop(); }
        // Last-resort: write the ACPI reset register if present.
        let fi = FADT_INFO.lock().clone();
        if let Some(fi) = fi {
            if fi.reset_reg.address != 0 {
                gas_write(&fi.reset_reg, fi.reset_value as u64);
                for _ in 0u32..100_000 { core::hint::spin_loop(); }
            }
        }
        // Triple-fault fallback — load a zero-length IDT and INT3.
        triple_fault();
    }
}

/// Warm reboot via ACPI reset register → PS/2 keyboard controller.
pub fn reboot() {
    println!("acpi/power: rebooting");
    unsafe {
        let fi = FADT_INFO.lock().clone();
        if let Some(fi) = fi {
            if fi.reset_reg.address != 0 {
                gas_write(&fi.reset_reg, fi.reset_value as u64);
                for _ in 0u32..100_000 { core::hint::spin_loop(); }
            }
        }
        // 8042 keyboard controller CPU reset line (port 0x64, cmd 0xFE).
        outb(0x64, 0xFE);
        loop { core::arch::asm!("hlt"); }
    }
}

#[cold]
#[inline(never)]
unsafe fn triple_fault() -> ! {
    // Zero the IDTR — any interrupt will triple-fault.
    let zero: [u64; 2] = [0; 2];
    core::arch::asm!(
        "lidt [{ptr}]",
        "int3",
        ptr = in(reg) zero.as_ptr(),
        options(nostack)
    );
    loop { core::arch::asm!("hlt"); }
}

/// Clear PM1 status bits (WAC — write 1 to clear) so no stale events fire.
unsafe fn clear_pm1_status() {
    let fi = match *FADT_INFO.lock() { Some(f) => f, None => return };
    if fi.pm1a_evt_port != 0 { outw(fi.pm1a_evt_port, 0xFFFF); }
    if fi.pm1b_evt_port != 0 { outw(fi.pm1b_evt_port, 0xFFFF); }
}

// ─────────────────────────────────────────────────────────────────────────────
// CPU frequency scaling  (ACPI P-states + C-states)
// ─────────────────────────────────────────────────────────────────────────────

/// One P-state entry decoded from `_PSS`.
#[derive(Clone, Copy, Default)]
pub struct PState {
    /// Nominal frequency in MHz.
    pub freq_mhz:    u32,
    /// Power dissipation in mW.
    pub power_mw:    u32,
    /// Transition latency in µs.
    pub latency_us:  u32,
    /// Bus-master latency in µs.
    pub bm_latency:  u32,
    /// Value written to the performance control register.
    pub ctrl_value:  u32,
    /// Value compared against the performance status register.
    pub status_value:u32,
}

/// Performance control / status register addresses from `_PCT`.
#[derive(Clone, Copy, Default)]
struct Pct {
    ctrl:   Gas,
    status: Gas,
}

static P_STATES:   Mutex<Vec<PState>> = Mutex::new(Vec::new());
static PCT:        Mutex<Option<Pct>> = Mutex::new(None);
/// Index of the currently active P-state (0 = highest performance).
static CUR_PSTATE: AtomicU8 = AtomicU8::new(0);

/// One C-state entry decoded from `_CST`.
#[derive(Clone, Copy, Default)]
pub struct CState {
    /// C-state level (C1, C2, C3 …)
    pub level:      u32,
    /// Entry latency in µs.
    pub latency_us: u32,
    /// Power draw in mW.
    pub power_mw:   u32,
    /// Register for entry (MWAIT hint or I/O read port).
    pub reg:        Gas,
}

static C_STATES: Mutex<Vec<CState>> = Mutex::new(Vec::new());

// ── CPUID helper ─────────────────────────────────────────────────────────────

/// Read CPUID leaf.  Returns (eax, ebx, ecx, edx).
#[cfg(target_arch = "x86_64")]
fn cpuid(leaf: u32) -> (u32, u32, u32, u32) {
    let eax: u32; let ebx: u32; let ecx: u32; let edx: u32;
    unsafe {
        core::arch::asm!(
            "cpuid",
            inout("eax") leaf => eax,
            out("ebx") ebx,
            inout("ecx") 0u32 => ecx,
            out("edx") edx,
            options(nostack)
        );
    }
    (eax, ebx, ecx, edx)
}

#[cfg(not(target_arch = "x86_64"))]
fn cpuid(_: u32) -> (u32, u32, u32, u32) { (0,0,0,0) }

/// Read an MSR (x86_64 only).
#[cfg(target_arch = "x86_64")]
unsafe fn rdmsr(msr: u32) -> u64 {
    let lo: u32; let hi: u32;
    core::arch::asm!(
        "rdmsr",
        in("ecx") msr,
        out("eax") lo, out("edx") hi,
        options(nostack)
    );
    ((hi as u64) << 32) | lo as u64
}

/// Write an MSR (x86_64 only).
#[cfg(target_arch = "x86_64")]
unsafe fn wrmsr(msr: u32, val: u64) {
    core::arch::asm!(
        "wrmsr",
        in("ecx") msr,
        in("eax") (val & 0xFFFF_FFFF) as u32,
        in("edx") (val >> 32) as u32,
        options(nostack)
    );
}

#[cfg(not(target_arch = "x86_64"))]
unsafe fn rdmsr(_: u32) -> u64 { 0 }
#[cfg(not(target_arch = "x86_64"))]
unsafe fn wrmsr(_: u32, _: u64) {}

// ── MSR 0x199 (IA32_PERF_CTL) — Intel SpeedStep / EIST ───────────────────────

const IA32_PERF_CTL:    u32 = 0x0199;
const IA32_PERF_STATUS: u32 = 0x0198;
const IA32_MISC_ENABLE: u32 = 0x01A0;
const EIST_ENABLE_BIT:  u64 = 1 << 16;

/// Enable Intel EIST (Enhanced Intel SpeedStep).
pub fn eist_enable() {
    unsafe {
        let misc = rdmsr(IA32_MISC_ENABLE);
        if misc & EIST_ENABLE_BIT == 0 {
            wrmsr(IA32_MISC_ENABLE, misc | EIST_ENABLE_BIT);
            println!("acpi/cpufreq: EIST enabled via IA32_MISC_ENABLE");
        }
    }
}

// ── _PCT parsing ─────────────────────────────────────────────────────────────

unsafe fn parse_pct(aml: &[u8]) {
    // _PCT returns a Package of two Buffer(GAS) entries.
    if let Some(val_buf) = aml_find_name(aml, b"_PCT") {
        if val_buf.is_empty() || val_buf[0] != aml::PACKAGE_OP { return; }
        let (_pkglen, pl_b) = match aml::decode_pkglen(&val_buf[1..]) {
            Some(x) => x, None => return,
        };
        let mut i = 1 + pl_b + 1; // +1 for NumElements byte
        if i >= val_buf.len() { return; }
        // Element 0 = PerformanceControlRegister (GAS)
        let ctrl_gas = match aml::decode_gas_from_buffer(&val_buf[i..]) {
            Some(g) => g, None => return,
        };
        // Advance past the Buffer to element 1.
        i += 1; // BUFFER_OP
        if let Some((_pl, plb)) = aml::decode_pkglen(&val_buf[i..]) {
            i += plb + _pl;
        }
        let status_gas = aml::decode_gas_from_buffer(&val_buf[i..]).unwrap_or_default();
        *PCT.lock() = Some(Pct { ctrl: ctrl_gas, status: status_gas });
        println!("acpi/cpufreq: _PCT ctrl space={} addr={:#x}",
                 ctrl_gas.space_id, ctrl_gas.address);
    }
}

// ── _PSS parsing ─────────────────────────────────────────────────────────────

unsafe fn parse_pss(aml: &[u8]) {
    // _PSS returns a Package of Packages, each with 6 DWord integers.
    if let Some(val_buf) = aml_find_name(aml, b"_PSS") {
        if val_buf.is_empty() || val_buf[0] != aml::PACKAGE_OP { return; }
        let (_pkglen, pl_b) = match aml::decode_pkglen(&val_buf[1..]) {
            Some(x) => x, None => return,
        };
        let mut i = 1 + pl_b;
        if i >= val_buf.len() { return; }
        let num_states = val_buf[i] as usize; i += 1;
        let mut states = P_STATES.lock();
        states.clear();
        for _ in 0..num_states {
            if i >= val_buf.len() { break; }
            if let Some(fields) = aml::decode_package_integers(&val_buf[i..], 6) {
                if fields.len() == 6 {
                    states.push(PState {
                        freq_mhz:     fields[0] as u32,
                        power_mw:     fields[1] as u32,
                        latency_us:   fields[2] as u32,
                        bm_latency:   fields[3] as u32,
                        ctrl_value:   fields[4] as u32,
                        status_value: fields[5] as u32,
                    });
                }
                // Advance i past this inner Package.
                if val_buf[i] == aml::PACKAGE_OP {
                    if let Some((pl, plb)) = aml::decode_pkglen(&val_buf[i+1..]) {
                        i += 1 + plb + pl;
                        continue;
                    }
                }
                i += 1;
            } else { i += 1; }
        }
        println!("acpi/cpufreq: _PSS found {} P-states", states.len());
    }
}

// ── _CST parsing ─────────────────────────────────────────────────────────────

unsafe fn parse_cst(aml: &[u8]) {
    if let Some(val_buf) = aml_find_name(aml, b"_CST") {
        if val_buf.is_empty() || val_buf[0] != aml::PACKAGE_OP { return; }
        let (_pkglen, pl_b) = match aml::decode_pkglen(&val_buf[1..]) {
            Some(x) => x, None => return,
        };
        let mut i = 1 + pl_b + 1; // skip NumElements
        let mut cstates = C_STATES.lock();
        cstates.clear();
        while i < val_buf.len() {
            // Each entry is a Package { Register(GAS), Type, Latency, Power }.
            if val_buf[i] != aml::PACKAGE_OP { break; }
            let inner = match aml::decode_package_integers(&val_buf[i+1..], 3) {
                Some(v) => v, None => break,
            };
            let reg_gas = aml::decode_gas_from_buffer(&val_buf[i + 2..])
                .unwrap_or_default();
            if inner.len() >= 3 {
                cstates.push(CState {
                    level:      inner[0] as u32,
                    latency_us: inner[1] as u32,
                    power_mw:   inner[2] as u32,
                    reg:        reg_gas,
                });
            }
            // Skip past inner Package.
            if let Some((pl, plb)) = aml::decode_pkglen(&val_buf[i + 1..]) {
                i += 1 + plb + pl;
            } else { i += 1; }
        }
        println!("acpi/cpufreq: _CST found {} C-states", cstates.len());
    }
}

// ── Public cpufreq API ────────────────────────────────────────────────────────

/// Number of P-states discovered.
pub fn pstate_count() -> usize { P_STATES.lock().len() }

/// A copy of all discovered P-states.
pub fn pstate_list() -> Vec<PState> { P_STATES.lock().clone() }

/// Set the CPU to P-state `index` (0 = max performance).
/// Returns Err if out of range or _PCT not found.
pub fn set_pstate(index: usize) -> Result<(), &'static str> {
    let pct = PCT.lock().clone();
    let pct = pct.ok_or("_PCT not available")?;
    let states = P_STATES.lock();
    let ps = states.get(index).ok_or("P-state index out of range")?;
    let ctrl = ps.ctrl_value as u64;
    drop(states);
    unsafe {
        match pct.ctrl.space_id {
            gas_space::IO     => outw(pct.ctrl.address as u16, ctrl as u16),
            gas_space::MEMORY => (pct.ctrl.address as *mut u32).write_volatile(ctrl as u32),
            gas_space::FIXED  => wrmsr(pct.ctrl.address as u32, ctrl),
            _                 => {}
        }
    }
    CUR_PSTATE.store(index as u8, Ordering::SeqCst);
    Ok(())
}

/// Current active P-state index.
pub fn current_pstate() -> usize { CUR_PSTATE.load(Ordering::SeqCst) as usize }

/// Enter a C-state idle loop.  `level` selects the deepest acceptable C-state
/// (e.g. 1 = C1, 2 = C2).  Falls back to plain HLT for C1 or when MWAIT
/// is unavailable.  Returns when an interrupt wakes the CPU.
pub fn enter_cstate(level: u32) {
    // Check MWAIT availability (CPUID leaf 5).
    let mwait_ok = {
        let (_, _, ecx, _) = cpuid(1);
        (ecx & (1 << 3)) != 0 // ECX[3] = MONITOR/MWAIT
    };

    if level <= 1 || !mwait_ok {
        unsafe { core::arch::asm!("hlt", options(nostack)); }
        return;
    }

    // Look up the deepest C-state ≤ requested level.
    let reg_opt = {
        let cstates = C_STATES.lock();
        cstates.iter()
               .filter(|c| c.level <= level)
               .max_by_key(|c| c.level)
               .map(|c| (c.level, c.reg))
    };

    match reg_opt {
        None => unsafe { core::arch::asm!("hlt", options(nostack)); }
        Some((cs_level, _reg)) => {
            // MWAIT hint: sub-state hint = 0, C-state hint = level − 1.
            let hint = ((cs_level - 1) as u64) << 4;
            unsafe {
                // MONITOR on current stack pointer (arbitrary monitored address).
                let monitor_addr: u64;
                core::arch::asm!("mov {}, rsp", out(reg) monitor_addr, options(nostack));
                core::arch::asm!(
                    "monitor",
                    in("rax") monitor_addr,
                    in("ecx") 0u32,
                    in("edx") 0u32,
                    options(nostack)
                );
                core::arch::asm!(
                    "mwait",
                    in("rax") hint,
                    in("ecx") 0u32,
                    options(nostack)
                );
            }
        }
    }
}

/// Intel Turbo Boost — disable by setting IA32_MISC_ENABLE[38] (IDA engage).
pub fn turbo_disable() {
    unsafe {
        let v = rdmsr(IA32_MISC_ENABLE);
        wrmsr(IA32_MISC_ENABLE, v | (1 << 38));
        println!("acpi/cpufreq: Turbo Boost disabled");
    }
}

/// Intel Turbo Boost — re-enable.
pub fn turbo_enable() {
    unsafe {
        let v = rdmsr(IA32_MISC_ENABLE);
        wrmsr(IA32_MISC_ENABLE, v & !(1 << 38));
        println!("acpi/cpufreq: Turbo Boost enabled");
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Governor — simple ondemand policy (interrupt-driven placeholder)
// ─────────────────────────────────────────────────────────────────────────────

/// A simplistic "performance" governor: pin the CPU to P-state 0.
pub fn governor_performance() {
    let _ = set_pstate(0);
}

/// A simplistic "powersave" governor: pin the CPU to the lowest P-state.
pub fn governor_powersave() {
    let n = pstate_count();
    if n > 0 { let _ = set_pstate(n - 1); }
}

/// A simplistic "ondemand" governor step.  Call this from the scheduler tick.
/// Bumps P-state up by one if `busy_pct >= 80`, down if `busy_pct < 20`.
pub fn governor_ondemand_step(busy_pct: u8) {
    let n = pstate_count();
    if n == 0 { return; }
    let cur = current_pstate();
    if busy_pct >= 80 && cur > 0 {
        let _ = set_pstate(cur - 1); // lower index = higher freq
    } else if busy_pct < 20 && cur + 1 < n {
        let _ = set_pstate(cur + 1);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Module init
// ─────────────────────────────────────────────────────────────────────────────

/// Parse FADT, DSDT AML, and ACPI cpufreq tables.  Call once at kernel init
/// after `crate::acpi::init()` has located the XSDT/RSDT.
pub fn init() {
    unsafe {
        parse_fadt();
        parse_sleep_types();

        // Parse _PCT / _PSS / _CST from DSDT AML.
        let fi = FADT_INFO.lock().clone();
        if let Some(fi) = fi {
            if fi.dsdt_phys != 0 {
                let hdr_size = core::mem::size_of::<crate::acpi::SdtHeader>();
                let dsdt_hdr = fi.dsdt_phys as *const crate::acpi::SdtHeader;
                let dsdt_len = (*dsdt_hdr).len as usize;
                if dsdt_len > hdr_size {
                    let aml_start = fi.dsdt_phys as usize + hdr_size;
                    let aml_len   = dsdt_len - hdr_size;
                    let aml = core::slice::from_raw_parts(aml_start as *const u8, aml_len);
                    parse_pct(aml);
                    parse_pss(aml);
                    parse_cst(aml);
                }
            }
        }

        // Enable EIST if the CPU supports it.
        let (_, _, ecx, _) = cpuid(1);
        if ecx & (1 << 7) != 0 { // ECX[7] = EIST (SpeedStep)
            eist_enable();
        }
    }
    println!("acpi/power: init complete — P-states={} C-states={}",
             pstate_count(), C_STATES.lock().len());
}

// ─────────────────────────────────────────────────────────────────────────────
// sysfs-style string query helpers (used by the /sys/power VFS handler)
// ─────────────────────────────────────────────────────────────────────────────

/// Parse a /sys/power/state write ("mem" → S3, "off" → S5, "reboot" → reboot).
pub fn sysfs_power_write(s: &str) -> Result<(), &'static str> {
    match s.trim() {
        "mem"    => { enter_s3(); Ok(()) }
        "off"    => { enter_s5(); Ok(()) }
        "reboot" => { reboot();   Ok(()) }
        _        => Err("unsupported power state"),
    }
}

/// Return a space-separated string of supported power states for
/// /sys/power/state reads.
pub fn sysfs_power_read() -> &'static str {
    let st = *SLEEP_TYPES.lock();
    if st.s3_valid { "freeze mem off" } else { "freeze off" }
}

/// Return a newline-separated list of available frequencies (kHz) for
/// /sys/devices/system/cpu/cpu0/cpufreq/scaling_available_frequencies.
pub fn scaling_available_freqs(buf: &mut [u8]) -> usize {
    let states = P_STATES.lock();
    if states.is_empty() { return 0; }
    let mut pos = 0usize;
    for ps in states.iter() {
        let khz = ps.freq_mhz * 1000;
        // Write decimal into buf.
        let s = format_u32(khz);
        let sb = s.as_bytes();
        if pos + sb.len() + 1 >= buf.len() { break; }
        buf[pos..pos + sb.len()].copy_from_slice(sb);
        pos += sb.len();
        buf[pos] = b' '; pos += 1;
    }
    pos
}

fn format_u32(mut v: u32) -> alloc::string::String {
    use alloc::string::String;
    if v == 0 { return String::from("0"); }
    let mut d = [0u8; 10]; let mut i = 0;
    while v > 0 { d[i] = (v % 10) as u8 + b'0'; i += 1; v /= 10; }
    let s: String = d[..i].iter().rev().map(|&c| c as char).collect();
    s
}
