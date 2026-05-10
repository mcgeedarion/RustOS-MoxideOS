//! GDB Remote Serial Protocol engine.
//!
//! Implements packet framing and all handlers needed for `gdb` to attach,
//! inspect, and control the kernel.
//!
//! ## Register numbering (GDB x86_64 ABI)
//!
//! GDB assigns the following numbers to x86_64 registers:
//!   0=rax 1=rcx 2=rdx 3=rbx 4=rsp 5=rbp 6=rsi 7=rdi
//!   8=r8  9=r9  10=r10 11=r11 12=r12 13=r13 14=r14 15=r15  16=rip
//!
//! ## SavedRegs layout
//!
//! Must match the PUSH_ALL macro in `src/arch/x86_64/idt.rs` exactly:
//!   push rdi, rsi, rdx, rcx, rax, r8, r9, r10, r11, rbx, rbp, r12, r13, r14, r15
//!
//! The CPU interrupt frame (rip, cs, rflags, rsp, ss) lives above the error
//! code on the stack; rip and rflags are accessed via pointer arithmetic
//! relative to the SavedRegs pointer, not as struct fields.

extern crate alloc;
use alloc::vec::Vec;
use crate::gdbstub::serial;

// ── Register save-frame (GPRs only — matches PUSH_ALL push order) ────────────
//
// push rdi  → [rsp+0]   field 0
// push rsi  → [rsp+8]   field 1
// push rdx  → [rsp+16]  field 2
// push rcx  → [rsp+24]  field 3
// push rax  → [rsp+32]  field 4
// push r8   → [rsp+40]  field 5
// push r9   → [rsp+48]  field 6
// push r10  → [rsp+56]  field 7
// push r11  → [rsp+64]  field 8
// push rbx  → [rsp+72]  field 9
// push rbp  → [rsp+80]  field 10
// push r12  → [rsp+88]  field 11
// push r13  → [rsp+96]  field 12
// push r14  → [rsp+104] field 13
// push r15  → [rsp+112] field 14
//
// After the 15 pushes:
//   [rsp+120] = error_code (dummy 0 for #BP/#DB)
//   [rsp+128] = RIP  (CPU frame)
//   [rsp+136] = CS
//   [rsp+144] = RFLAGS
//   [rsp+152] = RSP (user)
//   [rsp+160] = SS

#[repr(C)]
pub struct SavedRegs {
    pub rdi: u64,  // 0
    pub rsi: u64,  // 1
    pub rdx: u64,  // 2
    pub rcx: u64,  // 3
    pub rax: u64,  // 4
    pub r8:  u64,  // 5
    pub r9:  u64,  // 6
    pub r10: u64,  // 7
    pub r11: u64,  // 8
    pub rbx: u64,  // 9
    pub rbp: u64,  // 10
    pub r12: u64,  // 11
    pub r13: u64,  // 12
    pub r14: u64,  // 13
    pub r15: u64,  // 14
}

impl SavedRegs {
    /// Read the RIP from the CPU interrupt frame sitting above the saved GPRs.
    /// Layout: SavedRegs (15×8=120 bytes) + error_code (8) + RIP.
    pub unsafe fn rip(ptr: *const Self) -> u64 {
        *((ptr as *const u64).add(15 + 1)) // skip 15 GPR slots + 1 error_code slot
    }
    pub unsafe fn set_rip(ptr: *mut Self, v: u64) {
        *((ptr as *mut u64).add(16)) = v;
    }
    /// RFLAGS is 2 slots above RIP in the CPU frame.
    pub unsafe fn rflags(ptr: *const Self) -> u64 {
        *((ptr as *const u64).add(18)) // 15 GPRs + error_code + RIP + CS + RFLAGS
    }
    pub unsafe fn set_rflags(ptr: *mut Self, v: u64) {
        *((ptr as *mut u64).add(18)) = v;
    }
}

const NUM_REGS: usize = 17; // rax..r15 + rip (GDB x86_64 ABI)
const RFLAGS_TF: u64 = 1 << 8;
const MAX_BPS: usize = 16;

struct Breakpoint { addr: usize, saved: u8 }

// ── Checksum / hex helpers ────────────────────────────────────────────────────

fn checksum(data: &[u8]) -> u8 {
    data.iter().fold(0u8, |a, &b| a.wrapping_add(b))
}
fn hex_nibble(n: u8) -> u8 { if n < 10 { b'0' + n } else { b'a' + n - 10 } }
fn byte_to_hex(b: u8, out: &mut [u8; 2]) {
    out[0] = hex_nibble(b >> 4);
    out[1] = hex_nibble(b & 0xF);
}
fn from_hex_nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}
fn parse_hex_u64(s: &[u8]) -> Option<u64> {
    let mut v = 0u64;
    for &c in s {
        let n = from_hex_nibble(c)?;
        v = v.checked_shl(4)?.wrapping_add(n as u64);
    }
    Some(v)
}
fn hex_decode(src: &[u8], dst: &mut [u8]) -> bool {
    if src.len() != dst.len() * 2 { return false; }
    for i in 0..dst.len() {
        let hi = from_hex_nibble(src[i*2])?;
        let lo = from_hex_nibble(src[i*2+1])?;
        dst[i] = (hi << 4) | lo;
    }
    true
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
    for &b in src {
        let mut h = [0u8; 2];
        byte_to_hex(b, &mut h);
        out.extend_from_slice(&h);
    }
    out
}

// ── Register accessors (GDB x86_64 numbering → SavedRegs fields) ─────────────
//
// GDB x86_64:  0=rax 1=rcx 2=rdx 3=rbx 4=rsp 5=rbp 6=rsi 7=rdi
//              8=r8  9=r9  10=r10 11=r11 12=r12 13=r13 14=r14 15=r15  16=rip

unsafe fn reg_get(regs: *const SavedRegs, n: usize) -> Option<u64> {
    let r = &*regs;
    Some(match n {
        0  => r.rax,
        1  => r.rcx,
        2  => r.rdx,
        3  => r.rbx,
        4  => 0,            // rsp: not in our pushed frame; return 0
        5  => r.rbp,
        6  => r.rsi,
        7  => r.rdi,
        8  => r.r8,
        9  => r.r9,
        10 => r.r10,
        11 => r.r11,
        12 => r.r12,
        13 => r.r13,
        14 => r.r14,
        15 => r.r15,
        16 => SavedRegs::rip(regs),
        _  => return None,
    })
}

unsafe fn reg_set(regs: *mut SavedRegs, n: usize, v: u64) -> bool {
    let r = &mut *regs;
    match n {
        0  => r.rax = v,
        1  => r.rcx = v,
        2  => r.rdx = v,
        3  => r.rbx = v,
        4  => {},           // rsp: ignore
        5  => r.rbp = v,
        6  => r.rsi = v,
        7  => r.rdi = v,
        8  => r.r8  = v,
        9  => r.r9  = v,
        10 => r.r10 = v,
        11 => r.r11 = v,
        12 => r.r12 = v,
        13 => r.r13 = v,
        14 => r.r14 = v,
        15 => r.r15 = v,
        16 => SavedRegs::set_rip(regs, v),
        _  => return false,
    }
    true
}

// ── Breakpoint helpers ────────────────────────────────────────────────────────

fn bp_insert(bps: &mut [Option<Breakpoint>; MAX_BPS], addr: usize) -> bool {
    if bps.iter().flatten().any(|b| b.addr == addr) { return true; }
    let slot = match bps.iter_mut().find(|s| s.is_none()) { Some(s) => s, None => return false };
    let saved = unsafe { *(addr as *const u8) };
    unsafe { *(addr as *mut u8) = 0xCC; }
    *slot = Some(Breakpoint { addr, saved });
    true
}

fn bp_remove(bps: &mut [Option<Breakpoint>; MAX_BPS], addr: usize) -> bool {
    for slot in bps.iter_mut() {
        if let Some(ref bp) = *slot {
            if bp.addr == addr {
                unsafe { *(addr as *mut u8) = bp.saved; }
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
            unsafe { *(bp.addr as *mut u8) = bp.saved; }
        }
        *slot = None;
    }
}

// ── Packet I/O ────────────────────────────────────────────────────────────────

fn recv_packet(buf: &mut Vec<u8>) -> usize {
    loop {
        loop {
            let b = serial::read_byte();
            if b == b'$' { break; }
            if b == 0x03 { buf.clear(); return 0; } // Ctrl-C
        }
        buf.clear();
        let mut csum_got: u8 = 0;
        loop {
            let b = serial::read_byte();
            if b == b'#' { break; }
            buf.push(b);
            csum_got = csum_got.wrapping_add(b);
        }
        let ch = serial::read_byte();
        let cl = serial::read_byte();
        let expected = match (from_hex_nibble(ch), from_hex_nibble(cl)) {
            (Some(h), Some(l)) => (h << 4) | l,
            _ => { serial::write_byte(b'-'); continue; }
        };
        if csum_got != expected { serial::write_byte(b'-'); continue; }
        serial::write_byte(b'+');
        return buf.len();
    }
}

fn send_packet(data: &[u8]) {
    loop {
        serial::write_byte(b'$');
        serial::write_bytes(data);
        serial::write_byte(b'#');
        let mut h = [0u8; 2];
        byte_to_hex(checksum(data), &mut h);
        serial::write_bytes(&h);
        loop {
            let b = serial::read_byte();
            if b == b'+' { return; }
            if b == b'-' { break; }
        }
    }
}

fn send_ok()    { send_packet(b"OK"); }
fn send_empty() { send_packet(b""); }
fn send_error(n: u8) {
    let mut h = [0u8; 2];
    byte_to_hex(n, &mut h);
    let mut p = Vec::with_capacity(3);
    p.push(b'E');
    p.extend_from_slice(&h);
    send_packet(&p);
}

// ── Session loop ──────────────────────────────────────────────────────────────

pub unsafe fn run_session(regs: *mut SavedRegs) {
    send_packet(b"S05"); // SIGTRAP — tell GDB we stopped

    let mut buf: Vec<u8> = Vec::with_capacity(512);
    let mut bps: [Option<Breakpoint>; MAX_BPS] = [const { None }; MAX_BPS];

    'session: loop {
        recv_packet(&mut buf);

        if buf.is_empty() {
            send_packet(b"S05");
            continue;
        }

        let cmd  = buf[0];
        let args = &buf[1..];

        match cmd {
            b'?' => send_packet(b"S05"),

            b'g' => {
                let mut out = Vec::with_capacity(NUM_REGS * 16);
                for n in 0..NUM_REGS {
                    let v = reg_get(regs, n).unwrap_or(0);
                    out.extend_from_slice(&hex_encode(&v.to_le_bytes()));
                }
                send_packet(&out);
            }

            b'G' => {
                if args.len() != NUM_REGS * 16 { send_error(1); }
                else {
                    let mut ok = true;
                    for n in 0..NUM_REGS {
                        let mut raw = [0u8; 8];
                        if !hex_decode(&args[n*16..(n+1)*16], &mut raw) { ok = false; break; }
                        reg_set(regs, n, u64::from_le_bytes(raw));
                    }
                    if ok { send_ok() } else { send_error(1) }
                }
            }

            b'p' => {
                match parse_hex_u64(args).and_then(|n| reg_get(regs, n as usize)) {
                    Some(v) => send_packet(&hex_encode(&v.to_le_bytes())),
                    None    => send_error(2),
                }
            }

            b'P' => {
                if let Some(eq) = args.iter().position(|&b| b == b'=') {
                    let mut raw = [0u8; 8];
                    if let Some(n) = parse_hex_u64(&args[..eq]) {
                        if hex_decode(&args[eq+1..], &mut raw) {
                            if reg_set(regs, n as usize, u64::from_le_bytes(raw)) {
                                send_ok();
                            } else { send_error(2); }
                        } else { send_error(1); }
                    } else { send_error(1); }
                } else { send_error(1); }
            }

            b'm' => {
                if let Some(ci) = args.iter().position(|&b| b == b',') {
                    if let (Some(addr), Some(len)) =
                        (parse_hex_u64(&args[..ci]), parse_hex_u64(&args[ci+1..]))
                    {
                        let ptr = addr as *const u8;
                        let mut out = Vec::with_capacity(len as usize * 2);
                        for i in 0..len as usize {
                            let mut h = [0u8; 2];
                            byte_to_hex(ptr.add(i).read_volatile(), &mut h);
                            out.extend_from_slice(&h);
                        }
                        send_packet(&out);
                    } else { send_error(1); }
                } else { send_error(1); }
            }

            b'M' => {
                let comma = args.iter().position(|&b| b == b',');
                let colon = args.iter().position(|&b| b == b':');
                if let (Some(ci), Some(co)) = (comma, colon) {
                    if let (Some(addr), Some(len)) =
                        (parse_hex_u64(&args[..ci]), parse_hex_u64(&args[ci+1..co]))
                    {
                        let hex = &args[co+1..];
                        let len = len as usize;
                        if hex.len() == len * 2 {
                            let ptr = addr as *mut u8;
                            for i in 0..len {
                                if let (Some(h), Some(l)) =
                                    (from_hex_nibble(hex[i*2]), from_hex_nibble(hex[i*2+1]))
                                {
                                    ptr.add(i).write_volatile((h << 4) | l);
                                }
                            }
                            send_ok();
                        } else { send_error(1); }
                    } else { send_error(1); }
                } else { send_error(1); }
            }

            b's' => {
                let rf = SavedRegs::rflags(regs);
                SavedRegs::set_rflags(regs, rf | RFLAGS_TF);
                send_packet(b"S05");
                break 'session;
            }

            b'c' => {
                let rf = SavedRegs::rflags(regs);
                SavedRegs::set_rflags(regs, rf & !RFLAGS_TF);
                send_packet(b"S05");
                break 'session;
            }

            b'z' | b'Z' => {
                if args.first() != Some(&b'0') {
                    send_empty();
                } else {
                    let rest = &args[1..];
                    if rest.first() == Some(&b',') {
                        let rest = &rest[1..];
                        let end  = rest.iter().position(|&b| b == b',').unwrap_or(rest.len());
                        if let Some(addr) = parse_hex_u64(&rest[..end]) {
                            let ok = if cmd == b'Z' {
                                bp_insert(&mut bps, addr as usize)
                            } else {
                                bp_remove(&mut bps, addr as usize)
                            };
                            if ok { send_ok() } else { send_error(1) }
                        } else { send_error(1); }
                    } else { send_error(1); }
                }
            }

            b'H' => send_ok(),

            b'q' => {
                if buf.starts_with(b"qSupported") {
                    send_packet(b"PacketSize=400;swbreak+;hwbreak-;vContSupported+");
                } else if buf.starts_with(b"qAttached") {
                    send_packet(b"1");
                } else if buf.starts_with(b"qC") {
                    send_packet(b"QC1");
                } else if buf.starts_with(b"qfThreadInfo") {
                    send_packet(b"m1");
                } else if buf.starts_with(b"qsThreadInfo") {
                    send_packet(b"l");
                } else if buf.starts_with(b"qTStatus") {
                    send_empty();
                } else if buf.starts_with(b"qOffsets") {
                    send_packet(b"Text=0;Data=0;Bss=0");
                } else {
                    send_empty();
                }
            }

            b'v' => {
                if buf.starts_with(b"vCont?") {
                    send_packet(b"vCont;s;c");
                } else if buf.starts_with(b"vCont;") {
                    match buf.get(6).copied().unwrap_or(0) {
                        b's' => {
                            let rf = SavedRegs::rflags(regs);
                            SavedRegs::set_rflags(regs, rf | RFLAGS_TF);
                            send_packet(b"S05"); break 'session;
                        }
                        b'c' => {
                            let rf = SavedRegs::rflags(regs);
                            SavedRegs::set_rflags(regs, rf & !RFLAGS_TF);
                            send_packet(b"S05"); break 'session;
                        }
                        _ => send_empty(),
                    }
                } else if buf.starts_with(b"vKill") {
                    bp_clear_all(&mut bps); send_ok(); break 'session;
                } else if buf.starts_with(b"vMustReplyEmpty") {
                    send_empty();
                } else {
                    send_empty();
                }
            }

            b'D' => { bp_clear_all(&mut bps); send_ok(); break 'session; }
            b'k' => { bp_clear_all(&mut bps); break 'session; } // no reply for 'k'

            _ => send_empty(),
        }
    }
}
