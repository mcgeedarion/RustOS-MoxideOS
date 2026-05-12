//! GDB Remote Serial Protocol engine — RISC-V rv64gc.
//!
//! ## Register numbering  (GDB RISC-V ABI, matches `g`/`G` packet order)
//!
//! | GDB # | ABI name | TrapFrame field / note      |
//! |-------|----------|-----------                  |
//! |  0    | zero     | always 0 (hardwired)        |
//! |  1    | ra       | TrapFrame::ra               |
//! |  2    | sp       | TrapFrame::sp               |
//! |  3    | gp       | TrapFrame::gp               |
//! |  4    | tp       | TrapFrame::tp               |
//! |  5    | t0       | TrapFrame::t0               |
//! |  6    | t1       | TrapFrame::t1               |
//! |  7    | t2       | TrapFrame::t2               |
//! |  8    | s0/fp    | TrapFrame::s0               |
//! |  9    | s1       | TrapFrame::s1               |
//! | 10    | a0       | TrapFrame::a0               |
//! | 11    | a1       | TrapFrame::a1               |
//! | 12    | a2       | TrapFrame::a2               |
//! | 13    | a3       | TrapFrame::a3               |
//! | 14    | a4       | TrapFrame::a4               |
//! | 15    | a5       | TrapFrame::a5               |
//! | 16    | a6       | TrapFrame::a6               |
//! | 17    | a7       | TrapFrame::a7               |
//! | 18    | s2       | TrapFrame::s2               |
//! | 19    | s3       | TrapFrame::s3               |
//! | 20    | s4       | TrapFrame::s4               |
//! | 21    | s5       | TrapFrame::s5               |
//! | 22    | s6       | TrapFrame::s6               |
//! | 23    | s7       | TrapFrame::s7               |
//! | 24    | s8       | TrapFrame::s8               |
//! | 25    | s9       | TrapFrame::s9               |
//! | 26    | s10      | TrapFrame::s10              |
//! | 27    | s11      | TrapFrame::s11              |
//! | 28    | t3       | TrapFrame::t3               |
//! | 29    | t4       | TrapFrame::t4               |
//! | 30    | t5       | TrapFrame::t5               |
//! | 31    | t6       | TrapFrame::t6               |
//! | 32    | pc       | TrapFrame::sepc             |
//!
//! Total: 33 registers × 8 bytes = 264 hex bytes for `g`/`G`.
//!
//! ## Single-step
//!
//! True S-mode single-step (via a temporary breakpoint at the next PC) is
//! not yet implemented.  The previous implementation set sstatus bit 1,
//! which is SIE (Supervisor Interrupt Enable), not a step control — this
//! would have enabled supervisor interrupts mid-session and silently
//! disabled them on resume.  That code has been removed.
//!
//! Until next-PC decode is implemented, `s` and `s` packets behave like
//! `c` (continue), which is safe: GDB will still stop at any breakpoint.
//! TODO: implement next-PC decode for RVC + RVI to support true step.
//!
//! ## Software breakpoints
//!
//! Z0/z0: inspects the existing instruction width before patching.
//! If the low 2 bits of the existing half-word are != 0b11 the slot is a
//! 16-bit compressed instruction; patch with c.ebreak (0x9002) and save
//! the original 2 bytes.  Otherwise patch with EBREAK (0x00100073) and
//! save 4 bytes.  A `fence.i` is issued after each patch.
//!
//! ## Stop-reply protocol
//!
//! Same as rsp.rs: s/c/vCont return false from dispatch() WITHOUT sending
//! a stop reply.  run_session() sends T05thread:<pid>; when the next trap
//! re-enters it.

extern crate alloc;
use alloc::vec::Vec;
use alloc::vec;
use crate::gdbstub::serial;

// ─── ebreak / c.ebreak encodings ────────────────────────────────────────────────
const EBREAK:   u32 = 0x0010_0073; // 32-bit EBREAK
const C_EBREAK: u16 = 0x9002;      // 16-bit c.ebreak (RVC)

// ─── Protocol constants ─────────────────────────────────────────────────────
const NUM_REGS:    usize = 33;
const MAX_BPS:     usize = 16;
const NAK_RETRIES: usize = 8;

// ─── SavedRegs ──────────────────────────────────────────────────────────────

#[repr(C)]
pub struct SavedRegs {
    pub ra:  usize,
    pub sp:  usize,
    pub gp:  usize,
    pub tp:  usize,
    pub t0:  usize,
    pub t1:  usize,
    pub t2:  usize,
    pub s0:  usize,
    pub s1:  usize,
    pub a0:  usize,
    pub a1:  usize,
    pub a2:  usize,
    pub a3:  usize,
    pub a4:  usize,
    pub a5:  usize,
    pub a6:  usize,
    pub a7:  usize,
    pub s2:  usize,
    pub s3:  usize,
    pub s4:  usize,
    pub s5:  usize,
    pub s6:  usize,
    pub s7:  usize,
    pub s8:  usize,
    pub s9:  usize,
    pub s10: usize,
    pub s11: usize,
    pub t3:  usize,
    pub t4:  usize,
    pub t5:  usize,
    pub t6:  usize,
    pub sepc:    usize,
    pub sstatus: usize, // saved for context restore only — NOT modified by stub
}

// ─── Register accessors ─────────────────────────────────────────────────────

unsafe fn reg_get(regs: *const SavedRegs, n: usize) -> Option<u64> {
    let r = &*regs;
    Some(match n {
        0  => 0,
        1  => r.ra  as u64,
        2  => r.sp  as u64,
        3  => r.gp  as u64,
        4  => r.tp  as u64,
        5  => r.t0  as u64,
        6  => r.t1  as u64,
        7  => r.t2  as u64,
        8  => r.s0  as u64,
        9  => r.s1  as u64,
        10 => r.a0  as u64,
        11 => r.a1  as u64,
        12 => r.a2  as u64,
        13 => r.a3  as u64,
        14 => r.a4  as u64,
        15 => r.a5  as u64,
        16 => r.a6  as u64,
        17 => r.a7  as u64,
        18 => r.s2  as u64,
        19 => r.s3  as u64,
        20 => r.s4  as u64,
        21 => r.s5  as u64,
        22 => r.s6  as u64,
        23 => r.s7  as u64,
        24 => r.s8  as u64,
        25 => r.s9  as u64,
        26 => r.s10 as u64,
        27 => r.s11 as u64,
        28 => r.t3  as u64,
        29 => r.t4  as u64,
        30 => r.t5  as u64,
        31 => r.t6  as u64,
        32 => r.sepc as u64,
        _  => return None,
    })
}

unsafe fn reg_set(regs: *mut SavedRegs, n: usize, v: u64) -> bool {
    let v = v as usize;
    let r = &mut *regs;
    match n {
        0  => {}
        1  => r.ra  = v,
        2  => r.sp  = v,
        3  => r.gp  = v,
        4  => r.tp  = v,
        5  => r.t0  = v,
        6  => r.t1  = v,
        7  => r.t2  = v,
        8  => r.s0  = v,
        9  => r.s1  = v,
        10 => r.a0  = v,
        11 => r.a1  = v,
        12 => r.a2  = v,
        13 => r.a3  = v,
        14 => r.a4  = v,
        15 => r.a5  = v,
        16 => r.a6  = v,
        17 => r.a7  = v,
        18 => r.s2  = v,
        19 => r.s3  = v,
        20 => r.s4  = v,
        21 => r.s5  = v,
        22 => r.s6  = v,
        23 => r.s7  = v,
        24 => r.s8  = v,
        25 => r.s9  = v,
        26 => r.s10 = v,
        27 => r.s11 = v,
        28 => r.t3  = v,
        29 => r.t4  = v,
        30 => r.t5  = v,
        31 => r.t6  = v,
        32 => r.sepc = v,
        _  => return false,
    }
    true
}

// ─── Breakpoint table ─────────────────────────────────────────────────────────

/// Saved bytes at a breakpoint site.  Records whether the original
/// instruction was 16-bit (RVC) or 32-bit so restore uses the right width.
enum BpKind {
    C16(u16), // c.ebreak was patched over a 16-bit instruction
    I32(u32), // EBREAK was patched over a 32-bit instruction
}

struct Breakpoint {
    addr:  usize,
    saved: BpKind,
}

fn bp_insert(bps: &mut [Option<Breakpoint>; MAX_BPS], addr: usize) -> bool {
    if bps.iter().flatten().any(|b| b.addr == addr) { return true; }
    let slot = match bps.iter_mut().find(|s| s.is_none()) {
        Some(s) => s,
        None    => return false,
    };

    // Read the low 16 bits of the existing instruction to determine width.
    // Per RISC-V ISA: if bits [1:0] != 0b11 the instruction is 16-bit (RVC).
    let first16 = unsafe { (addr as *const u16).read_volatile() };
    let kind = if (first16 & 0b11) != 0b11 {
        // 16-bit compressed instruction — patch with c.ebreak
        unsafe { (addr as *mut u16).write_volatile(C_EBREAK); }
        BpKind::C16(first16)
    } else {
        // 32-bit instruction — patch with EBREAK
        let saved32 = unsafe { (addr as *const u32).read_volatile() };
        unsafe { (addr as *mut u32).write_volatile(EBREAK); }
        BpKind::I32(saved32)
    };

    unsafe { core::arch::asm!("fence.i", options(nostack)); }
    *slot = Some(Breakpoint { addr, saved: kind });
    true
}

fn bp_remove(bps: &mut [Option<Breakpoint>; MAX_BPS], addr: usize) -> bool {
    for slot in bps.iter_mut() {
        if let Some(ref bp) = *slot {
            if bp.addr == addr {
                match bp.saved {
                    BpKind::C16(v) => unsafe { (addr as *mut u16).write_volatile(v); },
                    BpKind::I32(v) => unsafe { (addr as *mut u32).write_volatile(v); },
                }
                unsafe { core::arch::asm!("fence.i", options(nostack)); }
                *slot = None;
                return true;
            }
        }
    }
    true
}

fn bp_clear_all(bps: &mut [Option<Breakpoint>; MAX_BPS]) {
    for slot in bps.iter_mut() {
        if let Some(ref bp) = *slot {
            match bp.saved {
                BpKind::C16(v) => unsafe { (bp.addr as *mut u16).write_volatile(v); },
                BpKind::I32(v) => unsafe { (bp.addr as *mut u32).write_volatile(v); },
            }
        }
        *slot = None;
    }
    unsafe { core::arch::asm!("fence.i", options(nostack)); }
}

// ─── Checksum / hex helpers ──────────────────────────────────────────────────

fn checksum(data: &[u8]) -> u8 { data.iter().fold(0u8, |a, &b| a.wrapping_add(b)) }
fn hex_nibble(n: u8) -> u8 { if n < 10 { b'0' + n } else { b'a' + n - 10 } }
fn byte_to_hex(b: u8, out: &mut [u8; 2]) { out[0] = hex_nibble(b >> 4); out[1] = hex_nibble(b & 0xF); }
fn from_hex_nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}
fn parse_hex_u64(s: &[u8]) -> Option<u64> {
    if s.is_empty() { return None; }
    let mut v = 0u64;
    for &c in s { let n = from_hex_nibble(c)?; v = v.checked_shl(4)?.wrapping_add(n as u64); }
    Some(v)
}
fn hex_decode(src: &[u8], dst: &mut [u8]) -> bool {
    if src.len() != dst.len() * 2 { return false; }
    for i in 0..dst.len() {
        let hi = match from_hex_nibble(src[i*2])   { Some(v) => v, None => return false };
        let lo = match from_hex_nibble(src[i*2+1]) { Some(v) => v, None => return false };
        dst[i] = (hi << 4) | lo;
    }
    true
}
fn hex_encode(src: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(src.len() * 2);
    for &b in src { let mut h = [0u8; 2]; byte_to_hex(b, &mut h); out.extend_from_slice(&h); }
    out
}

// ─── Packet I/O ──────────────────────────────────────────────────────────────

fn recv_packet(buf: &mut Vec<u8>) -> usize {
    loop {
        loop { let b = serial::read_byte(); if b == b'$' { break; } if b == 0x03 { buf.clear(); return 0; } }
        buf.clear();
        let mut running_cs: u8 = 0;
        loop { let b = serial::read_byte(); if b == b'#' { break; } buf.push(b); running_cs = running_cs.wrapping_add(b); }
        let ch = serial::read_byte();
        let cl = serial::read_byte();
        let expected = match (from_hex_nibble(ch), from_hex_nibble(cl)) {
            (Some(h), Some(l)) => (h << 4) | l,
            _ => { serial::write_byte(b'-'); continue; }
        };
        if running_cs != expected { serial::write_byte(b'-'); continue; }
        serial::write_byte(b'+');
        return buf.len();
    }
}

fn send_packet(data: &[u8]) {
    let mut cs_hex = [0u8; 2];
    byte_to_hex(checksum(data), &mut cs_hex);
    for _ in 0..NAK_RETRIES {
        serial::write_byte(b'$');
        serial::write_bytes(data);
        serial::write_byte(b'#');
        serial::write_bytes(&cs_hex);
        loop { let b = serial::read_byte(); if b == b'+' { return; } if b == b'-' { break; } }
    }
}

fn send_ok()         { send_packet(b"OK"); }
fn send_empty()      { send_packet(b""); }
fn send_error(n: u8) { let mut h = [0u8; 2]; byte_to_hex(n, &mut h); send_packet(&[b'E', h[0], h[1]]); }

// ─── target.xml ──────────────────────────────────────────────────────────────

const TARGET_XML_RV: &[u8] = br#"<?xml version="1.0"?>
<!DOCTYPE target SYSTEM "gdb-target.dtd">
<target version="1.0">
  <architecture>riscv:rv64</architecture>
  <feature name="org.gnu.gdb.riscv.cpu">
    <reg name="zero" bitsize="64" regnum="0" type="int"/>
    <reg name="ra"   bitsize="64" regnum="1" type="code_ptr"/>
    <reg name="sp"   bitsize="64" regnum="2" type="data_ptr"/>
    <reg name="gp"   bitsize="64" regnum="3" type="data_ptr"/>
    <reg name="tp"   bitsize="64" regnum="4" type="data_ptr"/>
    <reg name="t0"   bitsize="64" regnum="5"/>
    <reg name="t1"   bitsize="64" regnum="6"/>
    <reg name="t2"   bitsize="64" regnum="7"/>
    <reg name="s0"   bitsize="64" regnum="8"/>
    <reg name="s1"   bitsize="64" regnum="9"/>
    <reg name="a0"   bitsize="64" regnum="10"/>
    <reg name="a1"   bitsize="64" regnum="11"/>
    <reg name="a2"   bitsize="64" regnum="12"/>
    <reg name="a3"   bitsize="64" regnum="13"/>
    <reg name="a4"   bitsize="64" regnum="14"/>
    <reg name="a5"   bitsize="64" regnum="15"/>
    <reg name="a6"   bitsize="64" regnum="16"/>
    <reg name="a7"   bitsize="64" regnum="17"/>
    <reg name="s2"   bitsize="64" regnum="18"/>
    <reg name="s3"   bitsize="64" regnum="19"/>
    <reg name="s4"   bitsize="64" regnum="20"/>
    <reg name="s5"   bitsize="64" regnum="21"/>
    <reg name="s6"   bitsize="64" regnum="22"/>
    <reg name="s7"   bitsize="64" regnum="23"/>
    <reg name="s8"   bitsize="64" regnum="24"/>
    <reg name="s9"   bitsize="64" regnum="25"/>
    <reg name="s10"  bitsize="64" regnum="26"/>
    <reg name="s11"  bitsize="64" regnum="27"/>
    <reg name="t3"   bitsize="64" regnum="28"/>
    <reg name="t4"   bitsize="64" regnum="29"/>
    <reg name="t5"   bitsize="64" regnum="30"/>
    <reg name="t6"   bitsize="64" regnum="31"/>
    <reg name="pc"   bitsize="64" regnum="32" type="code_ptr"/>
  </feature>
</target>
"#;

fn handle_qxfer_features_rv(args: &[u8]) -> Vec<u8> {
    let want_annex = b"features:read:target.xml:";
    if !args.starts_with(want_annex) { return b"E00".to_vec(); }
    let tail  = &args[want_annex.len()..];
    let comma = match tail.iter().position(|&b| b == b',') { Some(i) => i, None => return b"E00".to_vec() };
    let off = parse_hex_u64(&tail[..comma]).unwrap_or(0) as usize;
    let len = parse_hex_u64(&tail[comma+1..]).unwrap_or(256) as usize;
    let xml = TARGET_XML_RV;
    if off >= xml.len() { return b"l".to_vec(); }
    let end   = (off + len).min(xml.len());
    let chunk = &xml[off..end];
    let more  = end < xml.len();
    let mut out = Vec::with_capacity(1 + chunk.len());
    out.push(if more { b'm' } else { b'l' });
    out.extend_from_slice(chunk);
    out
}

fn handle_x_write(args: &[u8]) -> bool {
    let comma = match args.iter().position(|&b| b == b',') { Some(i) => i, None => return false };
    let colon = match args.iter().position(|&b| b == b':') { Some(i) => i, None => return false };
    let addr = match parse_hex_u64(&args[..comma])        { Some(v) => v as usize, None => return false };
    let len  = match parse_hex_u64(&args[comma+1..colon]) { Some(v) => v as usize, None => return false };
    if len == 0 { return true; }
    let raw = &args[colon+1..];
    let mut decoded: Vec<u8> = Vec::with_capacity(len);
    let mut i = 0;
    while i < raw.len() {
        if raw[i] == 0x7d && i + 1 < raw.len() { decoded.push(raw[i+1] ^ 0x20); i += 2; }
        else { decoded.push(raw[i]); i += 1; }
    }
    if decoded.len() != len { return false; }
    let ptr = addr as *mut u8;
    for (i, &b) in decoded.iter().enumerate() { unsafe { ptr.add(i).write_volatile(b); } }
    unsafe { core::arch::asm!("fence.i", options(nostack)); }
    true
}

fn live_pids() -> Vec<u32> {
    crate::proc::scheduler::with_procs_ro(|pl_vec| pl_vec.iter().map(|pl| pl.pid).collect())
}
fn pid_alive(pid: usize) -> bool {
    crate::proc::scheduler::with_proc(pid, |_| ()).is_some()
}
fn build_thread_list(pids: &[u32]) -> Vec<u8> {
    let mut out = Vec::new();
    if pids.is_empty() { out.push(b'l'); return out; }
    out.push(b'm');
    for (i, &pid) in pids.iter().enumerate() {
        if i > 0 { out.push(b','); }
        out.extend_from_slice(alloc::format!("{:x}", pid).as_bytes());
    }
    out
}

// ─── Session ────────────────────────────────────────────────────────────────────

struct Session {
    regs:        *mut SavedRegs,
    stopped_pid: u32,
    bps:         [Option<Breakpoint>; MAX_BPS],
    buf:         Vec<u8>,
    thread_list: Vec<u32>,
}

impl Session {
    fn new(regs: *mut SavedRegs, stopped_pid: u32) -> Self {
        Session {
            regs,
            stopped_pid,
            bps: [const { None }; MAX_BPS],
            buf: Vec::with_capacity(1024),
            thread_list: Vec::new(),
        }
    }

    // do_step: set optional PC override.  True single-step not yet
    // implemented (see module doc); for now falls through to continue.
    unsafe fn do_step(&mut self, set_pc: Option<u64>) {
        if let Some(addr) = set_pc { (*self.regs).sepc = addr as usize; }
        // TODO: patch a temporary breakpoint at the next PC.
    }

    unsafe fn do_continue(&mut self, set_pc: Option<u64>) {
        if let Some(addr) = set_pc { (*self.regs).sepc = addr as usize; }
    }

    unsafe fn dispatch(&mut self) -> bool {
        if self.buf.is_empty() { send_packet(b"S05"); return true; }

        let cmd  = self.buf[0];
        let args = &self.buf[1..];
        let buf_ptr: *const Vec<u8> = &self.buf;
        let full_buf = &*buf_ptr;

        match cmd {
            b'?' => { let r = alloc::format!("T05thread:{:x};", self.stopped_pid); send_packet(r.as_bytes()); }

            b'g' => {
                let mut out = Vec::with_capacity(NUM_REGS * 16);
                for n in 0..NUM_REGS {
                    let v = reg_get(self.regs, n).unwrap_or(0);
                    out.extend_from_slice(&hex_encode(&v.to_le_bytes()));
                }
                send_packet(&out);
            }

            b'G' => {
                let mut pos = 0usize;
                let mut ok  = true;
                for n in 0..NUM_REGS {
                    if pos + 16 > args.len() { ok = false; break; }
                    let mut raw = [0u8; 8];
                    if !hex_decode(&args[pos..pos+16], &mut raw) { ok = false; break; }
                    reg_set(self.regs, n, u64::from_le_bytes(raw));
                    pos += 16;
                }
                if ok { send_ok() } else { send_error(1) }
            }

            b'p' => {
                match parse_hex_u64(args).and_then(|n| reg_get(self.regs, n as usize)) {
                    Some(v) => send_packet(&hex_encode(&v.to_le_bytes())),
                    None    => send_error(2),
                }
            }

            b'P' => {
                if let Some(eq) = args.iter().position(|&b| b == b'=') {
                    let n = match parse_hex_u64(&args[..eq]) { Some(v) => v as usize, None => { send_error(1); return true; } };
                    let mut raw = [0u8; 8];
                    if hex_decode(&args[eq+1..], &mut raw) {
                        if reg_set(self.regs, n, u64::from_le_bytes(raw)) { send_ok(); } else { send_error(2); }
                    } else { send_error(1); }
                } else { send_error(1); }
            }

            b'm' => {
                if let Some(ci) = args.iter().position(|&b| b == b',') {
                    if let (Some(addr), Some(len)) = (parse_hex_u64(&args[..ci]), parse_hex_u64(&args[ci+1..])) {
                        let len = len as usize;
                        let mut out = Vec::with_capacity(len * 2);
                        let ptr = addr as *const u8;
                        for i in 0..len { let mut h = [0u8; 2]; byte_to_hex(ptr.add(i).read_volatile(), &mut h); out.extend_from_slice(&h); }
                        send_packet(&out);
                    } else { send_error(1); }
                } else { send_error(1); }
            }

            b'M' => {
                let comma = args.iter().position(|&b| b == b',');
                let colon = args.iter().position(|&b| b == b':');
                if let (Some(ci), Some(co)) = (comma, colon) {
                    if let (Some(addr), Some(len)) = (parse_hex_u64(&args[..ci]), parse_hex_u64(&args[ci+1..co])) {
                        let hex = &args[co+1..];
                        let len = len as usize;
                        if hex.len() == len * 2 {
                            let ptr = addr as *mut u8;
                            for i in 0..len {
                                if let (Some(h), Some(l)) = (from_hex_nibble(hex[i*2]), from_hex_nibble(hex[i*2+1])) {
                                    ptr.add(i).write_volatile((h << 4) | l);
                                }
                            }
                            unsafe { core::arch::asm!("fence.i", options(nostack)); }
                            send_ok();
                        } else { send_error(1); }
                    } else { send_error(1); }
                } else { send_error(1); }
            }

            b'X' => { if handle_x_write(args) { send_ok() } else { send_error(1) } }

            // No stop reply — see module doc.
            b's' => { self.do_step(parse_hex_u64(args));     return false; }
            b'c' => { self.do_continue(parse_hex_u64(args)); return false; }

            b'Z' | b'z' => {
                let bp_type = args.first().copied().unwrap_or(b'?');
                if bp_type != b'0' {
                    send_error(1);
                } else {
                    let rest = &args[1..];
                    let rest = rest.strip_prefix(b",").unwrap_or(rest);
                    let end  = rest.iter().position(|&b| b == b',').unwrap_or(rest.len());
                    if let Some(addr) = parse_hex_u64(&rest[..end]) {
                        let ok = if cmd == b'Z' { bp_insert(&mut self.bps, addr as usize) }
                                 else           { bp_remove(&mut self.bps, addr as usize) };
                        if ok { send_ok() } else { send_error(1) }
                    } else { send_error(1); }
                }
            }

            b'H' => send_ok(),

            b'T' => {
                if let Some(pid) = parse_hex_u64(args) {
                    if pid_alive(pid as usize) { send_ok() } else { send_error(1) }
                } else { send_error(1); }
            }

            b'q' => self.handle_q(full_buf),

            b'v' => { if !self.handle_v(full_buf) { return false; } }

            b'D' => { bp_clear_all(&mut self.bps); send_ok(); return false; }
            b'k' => { bp_clear_all(&mut self.bps); return false; }

            _ => send_empty(),
        }
        true
    }

    fn handle_q(&mut self, buf: &[u8]) {
        if buf.starts_with(b"qSupported") {
            send_packet(b"PacketSize=1000;swbreak+;hwbreak-;vContSupported+;qXfer:features:read+");
        } else if buf.starts_with(b"qAttached") {
            send_packet(b"1");
        } else if buf.starts_with(b"qC") {
            send_packet(alloc::format!("QC{:x}", self.stopped_pid).as_bytes());
        } else if buf.starts_with(b"qfThreadInfo") {
            self.thread_list = live_pids();
            send_packet(&build_thread_list(&self.thread_list));
        } else if buf.starts_with(b"qsThreadInfo") {
            send_packet(b"l");
        } else if buf.starts_with(b"qThreadExtraInfo") {
            let args = &buf[b"qThreadExtraInfo,".len()..];
            if let Some(pid) = parse_hex_u64(args) {
                let name = crate::proc::scheduler::with_proc(pid as usize, |p| {
                    p.exe_path.clone()
                        .and_then(|s| s.rsplit('/').next().map(|n| n.to_owned()))
                        .unwrap_or_else(|| alloc::format!("pid{}", pid))
                }).unwrap_or_else(|| alloc::format!("pid{}", pid));
                send_packet(&hex_encode(name.as_bytes()));
            } else { send_error(1); }
        } else if buf.starts_with(b"qXfer:") {
            send_packet(&handle_qxfer_features_rv(&buf[b"qXfer:".len()..]));
        } else if buf.starts_with(b"qTStatus") {
            send_empty();
        } else if buf.starts_with(b"qOffsets") {
            send_packet(b"Text=0;Data=0;Bss=0");
        } else {
            send_empty();
        }
    }

    unsafe fn handle_v(&mut self, buf: &[u8]) -> bool {
        if buf.starts_with(b"vCont?") {
            send_packet(b"vCont;s;c");
        } else if buf.starts_with(b"vCont;") {
            let rest   = &buf[b"vCont;".len()..];
            let action = rest[0];
            // rest[1..] may start with `:tid` (thread selector) or an address.
            // If byte 1 is ':' it is a thread selector, not an address.
            let set_addr = if rest.get(1).copied() == Some(b':') {
                None
            } else {
                rest.get(1..).and_then(|r| {
                    let end = r.iter().position(|&b| b == b';' || b == b':').unwrap_or(r.len());
                    if end > 0 { parse_hex_u64(&r[..end]) } else { None }
                })
            };
            match action {
                b's' => { self.do_step(set_addr);     return false; }
                b'c' => { self.do_continue(set_addr); return false; }
                _    => send_empty(),
            }
        } else if buf.starts_with(b"vKill") {
            bp_clear_all(&mut self.bps); send_ok(); return false;
        } else if buf.starts_with(b"vMustReplyEmpty") {
            send_empty();
        } else {
            send_empty();
        }
        true
    }
}

// ─── Public entry point ──────────────────────────────────────────────────────

pub unsafe fn run_session(regs: *mut SavedRegs, stopped_pid: u32) {
    // T05thread:<pid>; is the ONLY stop reply sent by the stub.
    // s/c/vCont return without sending one.
    send_packet(alloc::format!("T05thread:{:x};", stopped_pid).as_bytes());
    let mut sess = Session::new(regs, stopped_pid);
    loop {
        recv_packet(&mut sess.buf);
        if !sess.dispatch() { break; }
    }
}
