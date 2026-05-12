//! ACPI Power Management — see original file header for full documentation.
//! Canonical location: src/firmware/acpi/power.rs

extern crate alloc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU8, AtomicU32, Ordering};
use spin::Mutex;
use crate::console::println;

#[repr(C, packed)]
#[derive(Clone, Copy, Default)]
pub struct Gas {
    pub space_id:    u8,
    pub bit_width:   u8,
    pub bit_offset:  u8,
    pub access_size: u8,
    pub address:     u64,
}

pub mod gas_space {
    pub const MEMORY:  u8 = 0;
    pub const IO:      u8 = 1;
    pub const FIXED:   u8 = 0x7F;
}

#[repr(C, packed)]
struct Fadt {
    sig:              [u8; 4],
    length:           u32,
    major_version:    u8,
    checksum:         u8,
    oem_id:           [u8; 6],
    oem_table_id:     [u8; 8],
    oem_rev:          u32,
    creator_id:       u32,
    creator_rev:      u32,
    firmware_ctrl:    u32,
    dsdt:             u32,
    _reserved0:       u8,
    preferred_pm:     u8,
    sci_int:          u16,
    smi_cmd:          u32,
    acpi_enable:      u8,
    acpi_disable:     u8,
    s4bios_req:       u8,
    pstate_cnt:       u8,
    pm1a_evt_blk:     u32,
    pm1b_evt_blk:     u32,
    pm1a_cnt_blk:     u32,
    pm1b_cnt_blk:     u32,
    pm2_cnt_blk:      u32,
    pm_tmr_blk:       u32,
    gpe0_blk:         u32,
    gpe1_blk:         u32,
    pm1_evt_len:      u8,
    pm1_cnt_len:      u8,
    pm2_cnt_len:      u8,
    pm_tmr_len:       u8,
    gpe0_blk_len:     u8,
    gpe1_blk_len:     u8,
    gpe1_base:        u8,
    cst_cnt:          u8,
    p_lvl2_lat:       u16,
    p_lvl3_lat:       u16,
    flush_size:       u16,
    flush_stride:     u16,
    duty_offset:      u8,
    duty_width:       u8,
    day_alrm:         u8,
    mon_alrm:         u8,
    century:          u8,
    ia_pc_boot_arch:  u16,
    _reserved1:       u8,
    flags:            u32,
    reset_reg:        Gas,
    reset_value:      u8,
    _reserved2:       [u8; 3],
    x_firmware_ctrl:  u64,
    x_dsdt:           u64,
    x_pm1a_evt_blk:   Gas,
    x_pm1b_evt_blk:   Gas,
    x_pm1a_cnt_blk:   Gas,
    x_pm1b_cnt_blk:   Gas,
    x_pm2_cnt_blk:    Gas,
    x_pm_tmr_blk:     Gas,
    x_gpe0_blk:       Gas,
    x_gpe1_blk:       Gas,
    sleep_control_reg:Gas,
    sleep_status_reg: Gas,
}

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
    hw_reduced:     bool,
    sleep_ctrl_reg: Gas,
    version:        u8,
}

static FADT_INFO: Mutex<Option<FadtInfo>> = Mutex::new(None);

#[derive(Clone, Copy, Default)]
struct SleepTypes {
    s3_typa: u8, s3_typb: u8,
    s5_typa: u8, s5_typb: u8,
    s3_valid: bool, s5_valid: bool,
}

static SLEEP_TYPES: Mutex<SleepTypes> = Mutex::new(SleepTypes {
    s3_typa: 0, s3_typb: 0, s5_typa: 0, s5_typb: 0,
    s3_valid: false, s5_valid: false,
});

mod aml {
    pub const ZERO_OP:     u8 = 0x00;
    pub const ONE_OP:      u8 = 0x01;
    pub const NAME_OP:     u8 = 0x08;
    pub const BYTE_PREFIX: u8 = 0x0A;
    pub const WORD_PREFIX: u8 = 0x0B;
    pub const DWORD_PREFIX:u8 = 0x0C;
    pub const QWORD_PREFIX:u8 = 0x0E;
    pub const BUFFER_OP:   u8 = 0x11;
    pub const PACKAGE_OP:  u8 = 0x12;
    pub const ONES_OP:     u8 = 0xFF;

    pub fn decode_pkglen(buf: &[u8]) -> Option<(usize, usize)> {
        if buf.is_empty() { return None; }
        let lead = buf[0];
        let follow = (lead >> 6) as usize;
        if follow == 0 { return Some(((lead & 0x3F) as usize, 1)); }
        if buf.len() < 1 + follow { return None; }
        let mut val = (lead & 0x0F) as usize;
        for i in 1..=follow { val |= (buf[i] as usize) << (4 + (i - 1) * 8); }
        Some((val, 1 + follow))
    }

    pub fn decode_namestring(buf: &[u8]) -> Option<(usize, [u8; 4])> {
        let mut i = 0;
        while i < buf.len() && (buf[i] == b'\\' || buf[i] == b'^') { i += 1; }
        if i >= buf.len() { return None; }
        match buf[i] {
            0x00 => Some((i + 1, [b'_'; 4])),
            0x2E => { i += 1; if buf.len() < i + 8 { return None; } let mut s = [0u8;4]; s.copy_from_slice(&buf[i+4..i+8]); Some((i+8, s)) }
            0x2F => { i += 1; if i >= buf.len() { return None; } let c = buf[i] as usize; i += 1; let lo = i+(c-1)*4; if buf.len() < lo+4 { return None; } let mut s = [0u8;4]; s.copy_from_slice(&buf[lo..lo+4]); Some((i+c*4, s)) }
            _    => { if buf.len() < i+4 { return None; } let mut s = [0u8;4]; s.copy_from_slice(&buf[i..i+4]); Some((i+4, s)) }
        }
    }

    pub fn decode_integer(buf: &[u8]) -> Option<(u64, usize)> {
        if buf.is_empty() { return None; }
        match buf[0] {
            ZERO_OP  => Some((0, 1)),
            ONE_OP   => Some((1, 1)),
            ONES_OP  => Some((0xFFFF_FFFF_FFFF_FFFFu64, 1)),
            BYTE_PREFIX  => { if buf.len() < 2 { None } else { Some((buf[1] as u64, 2)) } }
            WORD_PREFIX  => { if buf.len() < 3 { None } else { Some((u16::from_le_bytes([buf[1],buf[2]]) as u64, 3)) } }
            DWORD_PREFIX => { if buf.len() < 5 { None } else { Some((u32::from_le_bytes([buf[1],buf[2],buf[3],buf[4]]) as u64, 5)) } }
            QWORD_PREFIX => { if buf.len() < 9 { None } else { Some((u64::from_le_bytes([buf[1],buf[2],buf[3],buf[4],buf[5],buf[6],buf[7],buf[8]]), 9)) } }
            _ => None,
        }
    }

    pub fn decode_package_integers(buf: &[u8], max: usize) -> Option<alloc::vec::Vec<u64>> {
        extern crate alloc; use alloc::vec::Vec;
        if buf.is_empty() || buf[0] != PACKAGE_OP { return None; }
        let (_, pl_b) = decode_pkglen(&buf[1..])?;
        let mut i = 1 + pl_b;
        if i >= buf.len() { return None; }
        let n = (buf[i] as usize).min(max); i += 1;
        let mut out = Vec::with_capacity(n);
        for _ in 0..n {
            if i >= buf.len() { break; }
            if let Some((v, a)) = decode_integer(&buf[i..]) { out.push(v); i += a; } else { break; }
        }
        Some(out)
    }

    pub fn decode_gas_from_buffer(buf: &[u8]) -> Option<super::Gas> {
        if buf.is_empty() || buf[0] != BUFFER_OP { return None; }
        let (_, pl_b) = decode_pkglen(&buf[1..])?;
        let i = 1 + pl_b;
        let (_, bi) = decode_integer(&buf[i..])?;
        let ds = i + bi;
        if buf.len() < ds + 12 { return None; }
        let d = &buf[ds..];
        Some(super::Gas { space_id: d[0], bit_width: d[1], bit_offset: d[2], access_size: d[3],
            address: u64::from_le_bytes([d[4],d[5],d[6],d[7],d[8],d[9],d[10],d[11]]) })
    }
}

fn aml_find_name<'a>(aml: &'a [u8], target: &[u8; 4]) -> Option<&'a [u8]> {
    let mut i = 0usize;
    while i + 1 < aml.len() {
        if aml[i] != aml::NAME_OP { i += 1; continue; }
        i += 1;
        let (ns_b, seg) = match aml::decode_namestring(&aml[i..]) { Some(x) => x, None => { i += 1; continue; } };
        i += ns_b;
        if &seg == target { return Some(&aml[i..]); }
        if let Some((_, adv)) = aml::decode_integer(&aml[i..]) { i += adv; }
        else if i < aml.len() && aml[i] == aml::PACKAGE_OP {
            if let Some((pl, plb)) = aml::decode_pkglen(&aml[i+1..]) { i += 1 + plb + pl; } else { i += 1; }
        } else { i += 1; }
    }
    None
}

#[inline(always)] unsafe fn inw(port: u16) -> u16 { let v: u16; core::arch::asm!("in ax, dx", in("dx") port, out("ax") v, options(nomem,nostack)); v }
#[inline(always)] unsafe fn outw(port: u16, val: u16) { core::arch::asm!("out dx, ax", in("dx") port, in("ax") val, options(nomem,nostack)); }
#[inline(always)] unsafe fn outb(port: u16, val: u8)  { core::arch::asm!("out dx, al", in("dx") port, in("al") val, options(nomem,nostack)); }
#[inline(always)] unsafe fn inb(port: u16) -> u8      { let v: u8; core::arch::asm!("in al, dx", in("dx") port, out("al") v, options(nomem,nostack)); v }

unsafe fn gas_write(gas: &Gas, value: u64) {
    match gas.space_id {
        gas_space::IO => { let p = gas.address as u16; match gas.access_size { 1 => outb(p, value as u8), _ => outw(p, value as u16) } }
        gas_space::MEMORY => { (gas.address as *mut u32).write_volatile(value as u32); }
        _ => {}
    }
}

unsafe fn gas_read(gas: &Gas) -> u64 {
    match gas.space_id {
        gas_space::IO => { let p = gas.address as u16; match gas.access_size { 1 => inb(p) as u64, _ => inw(p) as u64 } }
        gas_space::MEMORY => { (gas.address as *const u32).read_volatile() as u64 }
        _ => 0,
    }
}

unsafe fn parse_fadt() {
    let fp = match crate::firmware::acpi::find_table(b"FACP") { Some(p) => p as *const Fadt, None => { println!("acpi/power: FADT not found"); return; } };
    let f = &*fp;
    let pm1a_cnt_port = if f.major_version >= 2 && f.x_pm1a_cnt_blk.address != 0 { f.x_pm1a_cnt_blk.address as u16 } else { f.pm1a_cnt_blk as u16 };
    let pm1b_cnt_port = if f.major_version >= 2 && f.x_pm1b_cnt_blk.address != 0 { f.x_pm1b_cnt_blk.address as u16 } else { f.pm1b_cnt_blk as u16 };
    let pm1a_evt_port = if f.major_version >= 2 && f.x_pm1a_evt_blk.address != 0 { f.x_pm1a_evt_blk.address as u16 } else { f.pm1a_evt_blk as u16 };
    let pm1b_evt_port = if f.major_version >= 2 && f.x_pm1b_evt_blk.address != 0 { f.x_pm1b_evt_blk.address as u16 } else { f.pm1b_evt_blk as u16 };
    let dsdt_phys = if f.major_version >= 2 && f.x_dsdt != 0 { f.x_dsdt } else { f.dsdt as u64 };
    let hw_reduced = (f.flags & (1 << 20)) != 0;
    *FADT_INFO.lock() = Some(FadtInfo { pm1a_cnt_port, pm1b_cnt_port, pm1a_evt_port, pm1b_evt_port,
        pm_tmr_port: f.pm_tmr_blk as u16, smi_cmd: f.smi_cmd, acpi_enable: f.acpi_enable,
        sci_int: f.sci_int, dsdt_phys, reset_reg: f.reset_reg, reset_value: f.reset_value,
        hw_reduced, sleep_ctrl_reg: f.sleep_control_reg, version: f.major_version });
    println!("acpi/power: FADT v{} PM1a_CNT={:#06x} DSDT={:#010x} hw_reduced={}", f.major_version, pm1a_cnt_port, dsdt_phys, hw_reduced);
}

unsafe fn parse_sleep_types() {
    let fi = *FADT_INFO.lock(); let fi = match fi { Some(f) => f, None => return };
    if fi.dsdt_phys == 0 { println!("acpi/power: no DSDT"); return; }
    let hdr_size = core::mem::size_of::<crate::firmware::acpi::SdtHeader>();
    let dsdt_hdr = fi.dsdt_phys as *const crate::firmware::acpi::SdtHeader;
    let dsdt_len = (*dsdt_hdr).len as usize;
    if dsdt_len < hdr_size { return; }
    let aml = core::slice::from_raw_parts((fi.dsdt_phys as usize + hdr_size) as *const u8, dsdt_len - hdr_size);
    let mut st = SLEEP_TYPES.lock();
    if let Some(vb) = aml_find_name(aml, b"_S3_") {
        if let Some(e) = aml::decode_package_integers(vb, 2) { if e.len() >= 2 { st.s3_typa = e[0] as u8; st.s3_typb = e[1] as u8; st.s3_valid = true; println!("acpi/power: \\S3 typa={} typb={}", st.s3_typa, st.s3_typb); } }
    }
    if let Some(vb) = aml_find_name(aml, b"_S5_") {
        if let Some(e) = aml::decode_package_integers(vb, 2) { if e.len() >= 2 { st.s5_typa = e[0] as u8; st.s5_typb = e[1] as u8; st.s5_valid = true; println!("acpi/power: \\S5 typa={} typb={}", st.s5_typa, st.s5_typb); } }
    } else { st.s5_typa = 5; st.s5_typb = 5; st.s5_valid = true; println!("acpi/power: \\S5 not found, using QEMU default typa=5"); }
}

unsafe fn acpi_enable() {
    let fi = match *FADT_INFO.lock() { Some(f) => f, None => return };
    if fi.smi_cmd == 0 || fi.acpi_enable == 0 { return; }
    if inw(fi.pm1a_cnt_port) & 1 != 0 { return; }
    outb(fi.smi_cmd as u16, fi.acpi_enable);
    for _ in 0..1_000_000 { if inw(fi.pm1a_cnt_port) & 1 != 0 { return; } core::hint::spin_loop(); }
    println!("acpi/power: warning: SCI_EN did not set after ACPI_ENABLE write");
}

const SLP_EN_BIT: u16 = 1 << 13;
fn slp_typ_bits(typ: u8) -> u16 { ((typ as u16) & 0x7) << 10 }

unsafe fn pm1_sleep(typa: u8, typb: u8) {
    let fi = match *FADT_INFO.lock() { Some(f) => f, None => return };
    let a = (inw(fi.pm1a_cnt_port) & 0x001) | slp_typ_bits(typa) | SLP_EN_BIT;
    outw(fi.pm1a_cnt_port, a);
    if fi.pm1b_cnt_port != 0 { let b = (inw(fi.pm1b_cnt_port) & 0x001) | slp_typ_bits(typb) | SLP_EN_BIT; outw(fi.pm1b_cnt_port, b); }
}

pub fn enter_s3() {
    let st = *SLEEP_TYPES.lock();
    if !st.s3_valid { println!("acpi/power: S3 not supported (no \\S3 AML object)"); return; }
    println!("acpi/power: entering S3 (suspend-to-RAM)");
    unsafe { acpi_enable(); clear_pm1_status(); pm1_sleep(st.s3_typa, st.s3_typb); loop { core::arch::asm!("hlt"); } }
}

pub fn enter_s5() {
    let st = *SLEEP_TYPES.lock();
    println!("acpi/power: shutdown initiated");
    unsafe {
        acpi_enable();
        if st.s5_valid { clear_pm1_status(); pm1_sleep(st.s5_typa, st.s5_typb); for _ in 0u32..500_000 { core::hint::spin_loop(); } }
        outw(0x604, 0x2000); for _ in 0u32..100_000 { core::hint::spin_loop(); }
        outw(0x4004, 0x3400); for _ in 0u32..100_000 { core::hint::spin_loop(); }
        let fi = FADT_INFO.lock().clone();
        if let Some(fi) = fi { if fi.reset_reg.address != 0 { gas_write(&fi.reset_reg, fi.reset_value as u64); for _ in 0u32..100_000 { core::hint::spin_loop(); } } }
        triple_fault();
    }
}

pub fn reboot() {
    println!("acpi/power: rebooting");
    unsafe {
        let fi = FADT_INFO.lock().clone();
        if let Some(fi) = fi { if fi.reset_reg.address != 0 { gas_write(&fi.reset_reg, fi.reset_value as u64); for _ in 0u32..100_000 { core::hint::spin_loop(); } } }
        outb(0x64, 0xFE);
        loop { core::arch::asm!("hlt"); }
    }
}

#[cold] #[inline(never)]
unsafe fn triple_fault() -> ! {
    let zero: [u64; 2] = [0; 2];
    core::arch::asm!("lidt [{ptr}]", "int3", ptr = in(reg) zero.as_ptr(), options(nostack));
    loop { core::arch::asm!("hlt"); }
}

unsafe fn clear_pm1_status() {
    let fi = match *FADT_INFO.lock() { Some(f) => f, None => return };
    if fi.pm1a_evt_port != 0 { outw(fi.pm1a_evt_port, 0xFFFF); }
    if fi.pm1b_evt_port != 0 { outw(fi.pm1b_evt_port, 0xFFFF); }
}

#[derive(Clone, Copy, Default)]
pub struct PState { pub freq_mhz: u32, pub power_mw: u32, pub latency_us: u32, pub bm_latency: u32, pub ctrl_value: u32, pub status_value: u32 }
#[derive(Clone, Copy, Default)] struct Pct { ctrl: Gas, status: Gas }
static P_STATES: Mutex<Vec<PState>> = Mutex::new(Vec::new());
static PCT:      Mutex<Option<Pct>> = Mutex::new(None);
static CUR_PSTATE: AtomicU8 = AtomicU8::new(0);
#[derive(Clone, Copy, Default)]
pub struct CState { pub level: u32, pub latency_us: u32, pub power_mw: u32, pub reg: Gas }
static C_STATES: Mutex<Vec<CState>> = Mutex::new(Vec::new());

#[cfg(target_arch = "x86_64")] fn cpuid(leaf: u32) -> (u32,u32,u32,u32) { let a:u32;let b:u32;let c:u32;let d:u32; unsafe { core::arch::asm!("cpuid", inout("eax") leaf=>a, out("ebx") b, inout("ecx") 0u32=>c, out("edx") d, options(nostack)); } (a,b,c,d) }
#[cfg(not(target_arch = "x86_64"))] fn cpuid(_: u32) -> (u32,u32,u32,u32) { (0,0,0,0) }
#[cfg(target_arch = "x86_64")] unsafe fn rdmsr(msr: u32) -> u64 { let lo:u32;let hi:u32; core::arch::asm!("rdmsr", in("ecx") msr, out("eax") lo, out("edx") hi, options(nostack)); ((hi as u64)<<32)|lo as u64 }
#[cfg(target_arch = "x86_64")] unsafe fn wrmsr(msr: u32, val: u64) { core::arch::asm!("wrmsr", in("ecx") msr, in("eax") (val&0xFFFF_FFFF) as u32, in("edx") (val>>32) as u32, options(nostack)); }
#[cfg(not(target_arch = "x86_64"))] unsafe fn rdmsr(_: u32) -> u64 { 0 }
#[cfg(not(target_arch = "x86_64"))] unsafe fn wrmsr(_: u32, _: u64) {}

const IA32_PERF_CTL: u32 = 0x0199;
const IA32_MISC_ENABLE: u32 = 0x01A0;
const EIST_ENABLE_BIT: u64 = 1 << 16;

pub fn eist_enable() { unsafe { let m = rdmsr(IA32_MISC_ENABLE); if m & EIST_ENABLE_BIT == 0 { wrmsr(IA32_MISC_ENABLE, m | EIST_ENABLE_BIT); println!("acpi/cpufreq: EIST enabled via IA32_MISC_ENABLE"); } } }

unsafe fn parse_pct(aml: &[u8]) {
    if let Some(vb) = aml_find_name(aml, b"_PCT") {
        if vb.is_empty() || vb[0] != aml::PACKAGE_OP { return; }
        let (_, pl_b) = match aml::decode_pkglen(&vb[1..]) { Some(x) => x, None => return };
        let mut i = 1 + pl_b + 1;
        if i >= vb.len() { return; }
        let ctrl_gas = match aml::decode_gas_from_buffer(&vb[i..]) { Some(g) => g, None => return };
        i += 1; if let Some((pl, plb)) = aml::decode_pkglen(&vb[i..]) { i += plb + pl; }
        let status_gas = aml::decode_gas_from_buffer(&vb[i..]).unwrap_or_default();
        *PCT.lock() = Some(Pct { ctrl: ctrl_gas, status: status_gas });
        println!("acpi/cpufreq: _PCT ctrl space={} addr={:#x}", ctrl_gas.space_id, ctrl_gas.address);
    }
}

unsafe fn parse_pss(aml: &[u8]) {
    if let Some(vb) = aml_find_name(aml, b"_PSS") {
        if vb.is_empty() || vb[0] != aml::PACKAGE_OP { return; }
        let (_, pl_b) = match aml::decode_pkglen(&vb[1..]) { Some(x) => x, None => return };
        let mut i = 1 + pl_b; if i >= vb.len() { return; }
        let ns = vb[i] as usize; i += 1;
        let mut st = P_STATES.lock(); st.clear();
        for _ in 0..ns {
            if i >= vb.len() { break; }
            if let Some(f) = aml::decode_package_integers(&vb[i..], 6) {
                if f.len() == 6 { st.push(PState { freq_mhz: f[0] as u32, power_mw: f[1] as u32, latency_us: f[2] as u32, bm_latency: f[3] as u32, ctrl_value: f[4] as u32, status_value: f[5] as u32 }); }
                if vb[i] == aml::PACKAGE_OP { if let Some((pl,plb)) = aml::decode_pkglen(&vb[i+1..]) { i += 1+plb+pl; continue; } } i += 1;
            } else { i += 1; }
        }
        println!("acpi/cpufreq: _PSS found {} P-states", st.len());
    }
}

unsafe fn parse_cst(aml: &[u8]) {
    if let Some(vb) = aml_find_name(aml, b"_CST") {
        if vb.is_empty() || vb[0] != aml::PACKAGE_OP { return; }
        let (_, pl_b) = match aml::decode_pkglen(&vb[1..]) { Some(x) => x, None => return };
        let mut i = 1 + pl_b + 1;
        let mut cs = C_STATES.lock(); cs.clear();
        while i < vb.len() {
            if vb[i] != aml::PACKAGE_OP { break; }
            let inner = match aml::decode_package_integers(&vb[i+1..], 3) { Some(v) => v, None => break };
            let rg = aml::decode_gas_from_buffer(&vb[i+2..]).unwrap_or_default();
            if inner.len() >= 3 { cs.push(CState { level: inner[0] as u32, latency_us: inner[1] as u32, power_mw: inner[2] as u32, reg: rg }); }
            if let Some((pl,plb)) = aml::decode_pkglen(&vb[i+1..]) { i += 1+plb+pl; } else { i += 1; }
        }
        println!("acpi/cpufreq: _CST found {} C-states", cs.len());
    }
}

pub fn pstate_count() -> usize { P_STATES.lock().len() }
pub fn pstate_list() -> Vec<PState> { P_STATES.lock().clone() }

pub fn set_pstate(index: usize) -> Result<(), &'static str> {
    let pct = PCT.lock().clone().ok_or("_PCT not available")?;
    let states = P_STATES.lock();
    let ps = states.get(index).ok_or("P-state index out of range")?;
    let ctrl = ps.ctrl_value as u64;
    drop(states);
    unsafe { match pct.ctrl.space_id { gas_space::IO => outw(pct.ctrl.address as u16, ctrl as u16), gas_space::MEMORY => (pct.ctrl.address as *mut u32).write_volatile(ctrl as u32), gas_space::FIXED => wrmsr(pct.ctrl.address as u32, ctrl), _ => {} } }
    CUR_PSTATE.store(index as u8, Ordering::SeqCst);
    Ok(())
}

pub fn current_pstate() -> usize { CUR_PSTATE.load(Ordering::SeqCst) as usize }

pub fn enter_cstate(level: u32) {
    let mwait_ok = { let (_,_,ecx,_) = cpuid(1); (ecx & (1<<3)) != 0 };
    if level <= 1 || !mwait_ok { unsafe { core::arch::asm!("hlt", options(nostack)); } return; }
    let reg_opt = { let cs = C_STATES.lock(); cs.iter().filter(|c| c.level <= level).max_by_key(|c| c.level).map(|c| (c.level, c.reg)) };
    match reg_opt {
        None => unsafe { core::arch::asm!("hlt", options(nostack)); }
        Some((csl, _)) => unsafe {
            let hint = ((csl - 1) as u64) << 4;
            let ma: u64; core::arch::asm!("mov {}, rsp", out(reg) ma, options(nostack));
            core::arch::asm!("monitor", in("rax") ma, in("ecx") 0u32, in("edx") 0u32, options(nostack));
            core::arch::asm!("mwait",   in("rax") hint, in("ecx") 0u32, options(nostack));
        }
    }
}

pub fn turbo_disable() { unsafe { let v = rdmsr(IA32_MISC_ENABLE); wrmsr(IA32_MISC_ENABLE, v|(1<<38)); println!("acpi/cpufreq: Turbo Boost disabled"); } }
pub fn turbo_enable()  { unsafe { let v = rdmsr(IA32_MISC_ENABLE); wrmsr(IA32_MISC_ENABLE, v&!(1<<38)); println!("acpi/cpufreq: Turbo Boost enabled"); } }
pub fn governor_performance() { let _ = set_pstate(0); }
pub fn governor_powersave()  { let n = pstate_count(); if n > 0 { let _ = set_pstate(n-1); } }
pub fn governor_ondemand_step(busy: u8) { let n = pstate_count(); if n == 0 { return; } let c = current_pstate(); if busy >= 80 && c > 0 { let _ = set_pstate(c-1); } else if busy < 20 && c+1 < n { let _ = set_pstate(c+1); } }

pub fn init() {
    unsafe {
        parse_fadt();
        parse_sleep_types();
        let fi = FADT_INFO.lock().clone();
        if let Some(fi) = fi {
            if fi.dsdt_phys != 0 {
                let hs = core::mem::size_of::<crate::firmware::acpi::SdtHeader>();
                let dh = fi.dsdt_phys as *const crate::firmware::acpi::SdtHeader;
                let dl = (*dh).len as usize;
                if dl > hs {
                    let aml = core::slice::from_raw_parts((fi.dsdt_phys as usize + hs) as *const u8, dl - hs);
                    parse_pct(aml); parse_pss(aml); parse_cst(aml);
                }
            }
        }
        let (_,_,ecx,_) = cpuid(1);
        if ecx & (1<<7) != 0 { eist_enable(); }
    }
    println!("acpi/power: init complete — P-states={} C-states={}", pstate_count(), C_STATES.lock().len());
}

pub fn sysfs_power_write(s: &str) -> Result<(), &'static str> { match s.trim() { "mem" => { enter_s3(); Ok(()) } "off" => { enter_s5(); Ok(()) } "reboot" => { reboot(); Ok(()) } _ => Err("unsupported power state") } }
pub fn sysfs_power_read() -> &'static str { let st = *SLEEP_TYPES.lock(); if st.s3_valid { "freeze mem off" } else { "freeze off" } }

pub fn scaling_available_freqs(buf: &mut [u8]) -> usize {
    let states = P_STATES.lock(); if states.is_empty() { return 0; }
    let mut pos = 0usize;
    for ps in states.iter() { let s = fmt_u32(ps.freq_mhz * 1000); let sb = s.as_bytes(); if pos + sb.len() + 1 >= buf.len() { break; } buf[pos..pos+sb.len()].copy_from_slice(sb); pos += sb.len(); buf[pos] = b' '; pos += 1; }
    pos
}

fn fmt_u32(mut v: u32) -> alloc::string::String {
    use alloc::string::String;
    if v == 0 { return String::from("0"); }
    let mut d = [0u8;10]; let mut i = 0;
    while v > 0 { d[i] = (v%10) as u8 + b'0'; i += 1; v /= 10; }
    d[..i].iter().rev().map(|&c| c as char).collect()
}
