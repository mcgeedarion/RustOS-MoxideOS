//! GDB Remote Serial Protocol engine — x86_64.
#![cfg(target_arch = "x86_64")]
//!
//! ## Register numbering  (GDB x86_64 ABI, matches `g`/`G` packet order)
//!
//! | GDB # | Name   | Source              |
//! |-------|--------|---------------------|
//! |  0    | rax    | SavedRegs::rax      |
//! |  1    | rcx    | SavedRegs::rcx      |
//! |  2    | rdx    | SavedRegs::rdx      |
//! |  3    | rbx    | SavedRegs::rbx      |
//! |  4    | rsp    | CPU iframe +19*8    |
//! |  5    | rbp    | SavedRegs::rbp      |
//! |  6    | rsi    | SavedRegs::rsi      |
//! |  7    | rdi    | SavedRegs::rdi      |
//! |  8    | r8     | SavedRegs::r8       |
//! |  9    | r9     | SavedRegs::r9       |
//! | 10    | r10    | SavedRegs::r10      |
//! | 11    | r11    | SavedRegs::r11      |
//! | 12    | r12    | SavedRegs::r12      |
//! | 13    | r13    | SavedRegs::r13      |
//! | 14    | r14    | SavedRegs::r14      |
//! | 15    | r15    | SavedRegs::r15      |
//! | 16    | rip    | CPU iframe +16*8    |
//! | 17    | eflags | CPU iframe +18*8    |
//! | 18    | cs     | CPU iframe +17*8    |
//! | 19    | ss     | CPU iframe +20*8    |
//! | 20-23 | ds/es/fs/gs | 0 (not tracked) |
//!
//! Total: 24 registers, 8 bytes each = 192 hex bytes for `g`/`G`.
//!
//! ## CPU interrupt frame layout (above SavedRegs on stack)
//!
//! Byte offsets from the base of the SavedRegs struct:
//!
//!   [  0 ..112] = rdi,rsi,rdx,rcx,rax,r8..r15  (15 × 8 = 120 bytes)
//!   [120      ] = error_code (0 for #BP/#DB)
//!   [128      ] = rip   ← CPU pushes here
//!   [136      ] = cs
//!   [144      ] = rflags
//!   [152      ] = rsp   ← CPU pushes here (user or kernel RSP)
//!   [160      ] = ss
//!
//! In u64-slot terms (÷8): rip=16, cs=17, rflags=18, rsp=19, ss=20.
//!
//! ## Breakpoints
//!
//! Software breakpoints (Z0/z0): write/restore 0xCC at the target address.
//! Hardware breakpoints (Z1-Z4): return E01 so GDB falls back to SW.
//!
//! ## Thread model
//!
//! The stub presents all live kernel PIDs as GDB thread IDs.  Thread
//! enumeration uses `scheduler::with_procs_ro` so no scheduler lock is
//! held during UART I/O (the list is built, the lock released, then
//! the reply is sent).

extern crate alloc;
use alloc::vec::Vec;
use alloc::vec;
use crate::gdbstub::serial;

// ─── CPU frame slot offsets (in u64 units from &SavedRegs) ──────────────────

const SLOT_RIP:    usize = 16; // [128]
const SLOT_CS:     usize = 17; // [136]
const SLOT_RFLAGS: usize = 18; // [144]
const SLOT_RSP:    usize = 19; // [152]
const SLOT_SS:     usize = 20; // [160]

// ─── SavedRegs ───────────────────────────────────────────────────────────────
//
// Must match the PUSH_ALL macro in src/arch/x86_64/idt.rs exactly.
// Push order: rdi rsi rdx rcx rax r8 r9 r10 r11 rbx rbp r12 r13 r14 r15

#[repr(C)]
pub struct SavedRegs {
    pub rdi: u64,   // slot 0
    pub rsi: u64,   // slot 1
    pub rdx: u64,   // slot 2
    pub rcx: u64,   // slot 3
    pub rax: u64,   // slot 4
    pub r8:  u64,   // slot 5
    pub r9:  u64,   // slot 6
    pub r10: u64,   // slot 7
    pub r11: u64,   // slot 8
    pub rbx: u64,   // slot 9
    pub rbp: u64,   // slot 10
    pub r12: u64,   // slot 11
    pub r13: u64,   // slot 12
    pub r14: u64,   // slot 13
    pub r15: u64,   // slot 14
    // slot 15 = error_code (dummy 0 for #BP/#DB)
    // slots 16..20 = cpu iframe (rip, cs, rflags, rsp, ss)
}

impl SavedRegs {
    #[inline] unsafe fn frame_slot(ptr: *const Self, slot: usize) -> u64 {
        *((ptr as *const u64).add(slot))
    }
    #[inline] unsafe fn set_frame_slot(ptr: *mut Self, slot: usize, v: u64) {
        *((ptr as *mut u64).add(slot)) = v;
    }

    pub unsafe fn rip(p: *const Self)    -> u64 { Self::frame_slot(p, SLOT_RIP) }
    pub unsafe fn set_rip(p: *mut Self, v: u64) { Self::set_frame_slot(p, SLOT_RIP, v) }
    pub unsafe fn rsp(p: *const Self)    -> u64 { Self::frame_slot(p, SLOT_RSP) }
    pub unsafe fn set_rsp(p: *mut Self, v: u64) { Self::set_frame_slot(p, SLOT_RSP, v) }
    pub unsafe fn rflags(p: *const Self) -> u64 { Self::frame_slot(p, SLOT_RFLAGS) }
    pub unsafe fn set_rflags(p: *mut Self, v: u64) { Self::set_frame_slot(p, SLOT_RFLAGS, v) }
    pub unsafe fn cs(p: *const Self)     -> u64 { Self::frame_slot(p, SLOT_CS) }
    pub unsafe fn ss(p: *const Self)     -> u64 { Self::frame_slot(p, SLOT_SS) }
}

// ─── Protocol constants ──────────────────────────────────────────────────────

/// GDB x86_64 register count as seen in `g`/`G` packets.
/// rax..r15 (16) + rip (1) + eflags (1) + cs/ss/ds/es/fs/gs (6) = 24.
const NUM_REGS: usize = 24;

const RFLAGS_TF:   u64 = 1 << 8;  // single-step trap flag
const MAX_BPS:     usize = 16;    // max simultaneous SW breakpoints
const NAK_RETRIES: usize = 8;     // give up after this many NAKs

// ─── Breakpoint table ────────────────────────────────────────────────────────

struct Breakpoint { addr: usize, saved: u8 }

// ─── Checksum / hex helpers ──────────────────────────────────────────────────

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
    if s.is_empty() { return None; }
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
        let hi = match from_hex_nibble(src[i * 2])     { Some(v) => v, None => return false };
        let lo = match from_hex_nibble(src[i * 2 + 1]) { Some(v) => v, None => return false };
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

// ─── Register accessors ──────────────────────────────────────────────────────
//
// GDB x86_64 numbering (24 registers):
//   0=rax  1=rcx  2=rdx  3=rbx  4=rsp  5=rbp  6=rsi  7=rdi
//   8=r8   9=r9  10=r10 11=r11 12=r12 13=r13 14=r14 15=r15
//  16=rip 17=eflags 18=cs 19=ss 20=ds 21=es 22=fs 23=gs

unsafe fn reg_get(regs: *const SavedRegs, n: usize) -> Option<u64> {
    let r = &*regs;
    Some(match n {
        0  => r.rax,
        1  => r.rcx,
        2  => r.rdx,
        3  => r.rbx,
        4  => SavedRegs::rsp(regs),          // ← fixed: read CPU iframe
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
        17 => SavedRegs::rflags(regs),
        18 => SavedRegs::cs(regs),
        19 => SavedRegs::ss(regs),
        20..=23 => 0,                         // ds/es/fs/gs not tracked
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
        4  => SavedRegs::set_rsp(regs, v),   // ← fixed: write CPU iframe
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
        17 => SavedRegs::set_rflags(regs, v),
        18..=23 => {}                         // segment regs: ignore writes
        _  => return false,
    }
    true
}

// ─── Breakpoint helpers ──────────────────────────────────────────────────────

fn bp_insert(bps: &mut [Option<Breakpoint>; MAX_BPS], addr: usize) -> bool {
    if bps.iter().flatten().any(|b| b.addr == addr) { return true; }
    let slot = match bps.iter_mut().find(|s| s.is_none()) {
        Some(s) => s,
        None    => return false, // table full
    };
    let saved = unsafe { *(addr as *const u8) };
    unsafe { *(addr as *mut u8) = 0xCC; }
    // Flush i-cache on x86 (coherent; a serialising instruction is enough).
    unsafe { core::arch::x86_64::_mm_mfence(); }
    *slot = Some(Breakpoint { addr, saved });
    true
}

fn bp_remove(bps: &mut [Option<Breakpoint>; MAX_BPS], addr: usize) -> bool {
    for slot in bps.iter_mut() {
        if let Some(ref bp) = *slot {
            if bp.addr == addr {
                unsafe { *(addr as *mut u8) = bp.saved; }
                unsafe { core::arch::x86_64::_mm_mfence(); }
                *slot = None;
                return true;
            }
        }
    }
    true // already removed — not an error
}

fn bp_clear_all(bps: &mut [Option<Breakpoint>; MAX_BPS]) {
    for slot in bps.iter_mut() {
        if let Some(ref bp) = *slot {
            unsafe { *(bp.addr as *mut u8) = bp.saved; }
        }
        *slot = None;
    }
    unsafe { core::arch::x86_64::_mm_mfence(); }
}

// ─── Packet I/O ──────────────────────────────────────────────────────────────

/// Receive one RSP packet into `buf`.  Handles:
///   - Discards bytes before '$'.
///   - 0x03 (Ctrl-C / interrupt) → clears buf, returns 0.
///   - Checksum verification; sends '+' on pass, '-' on fail and retries.
fn recv_packet(buf: &mut Vec<u8>) -> usize {
    loop {
        // Wait for '$' (start of packet) or 0x03 (interrupt).
        loop {
            let b = serial::read_byte();
            if b == b'$'  { break; }
            if b == 0x03  { buf.clear(); return 0; }
        }
        buf.clear();
        let mut running_cs: u8 = 0;
        loop {
            let b = serial::read_byte();
            if b == b'#' { break; }
            buf.push(b);
            running_cs = running_cs.wrapping_add(b);
        }
        // Two hex digits of checksum follow '#'.
        let ch = serial::read_byte();
        let cl = serial::read_byte();
        let expected = match (from_hex_nibble(ch), from_hex_nibble(cl)) {
            (Some(h), Some(l)) => (h << 4) | l,
            _ => { serial::write_byte(b'-'); continue; }
        };
        if running_cs != expected {
            serial::write_byte(b'-');
            continue;
        }
        serial::write_byte(b'+');
        return buf.len();
    }
}

/// Send one RSP packet.  Retries up to NAK_RETRIES times on '-'.
fn send_packet(data: &[u8]) {
    let mut cs_hex = [0u8; 2];
    byte_to_hex(checksum(data), &mut cs_hex);
    for _ in 0..NAK_RETRIES {
        serial::write_byte(b'$');
        serial::write_bytes(data);
        serial::write_byte(b'#');
        serial::write_bytes(&cs_hex);
        loop {
            let b = serial::read_byte();
            if b == b'+' { return; }   // ACK
            if b == b'-' { break; }    // NAK — retry
            // Any other byte (e.g. stray 0x03) — discard and wait.
        }
    }
    // After NAK_RETRIES failures give up silently; GDB will time out and
    // retransmit the query itself.
}

fn send_ok()         { send_packet(b"OK"); }
fn send_empty()      { send_packet(b""); }
fn send_error(n: u8) {
    let mut h = [0u8; 2];
    byte_to_hex(n, &mut h);
    send_packet(&[b'E', h[0], h[1]]);
}

// ─── target.xml ──────────────────────────────────────────────────────────────
//
// A minimal but correct x86_64 feature XML.  GDB uses this to build its
// internal register table; without it it has to guess from the arch string.
// We only describe the registers we actually serve (regs 0..23).

const TARGET_XML: &[u8] = br#"<?xml version="1.0"?>
<!DOCTYPE target SYSTEM "gdb-target.dtd">
<target version="1.0">
  <architecture>i386:x86-64</architecture>
  <feature name="org.gnu.gdb.i386.core">
    <reg name="rax"    bitsize="64" regnum="0"/>
    <reg name="rcx"    bitsize="64" regnum="1"/>
    <reg name="rdx"    bitsize="64" regnum="2"/>
    <reg name="rbx"    bitsize="64" regnum="3"/>
    <reg name="rsp"    bitsize="64" regnum="4" type="data_ptr"/>
    <reg name="rbp"    bitsize="64" regnum="5" type="data_ptr"/>
    <reg name="rsi"    bitsize="64" regnum="6"/>
    <reg name="rdi"    bitsize="64" regnum="7"/>
    <reg name="r8"     bitsize="64" regnum="8"/>
    <reg name="r9"     bitsize="64" regnum="9"/>
    <reg name="r10"    bitsize="64" regnum="10"/>
    <reg name="r11"    bitsize="64" regnum="11"/>
    <reg name="r12"    bitsize="64" regnum="12"/>
    <reg name="r13"    bitsize="64" regnum="13"/>
    <reg name="r14"    bitsize="64" regnum="14"/>
    <reg name="r15"    bitsize="64" regnum="15"/>
    <reg name="rip"    bitsize="64" regnum="16" type="code_ptr"/>
    <reg name="eflags" bitsize="32" regnum="17"/>
    <reg name="cs"     bitsize="32" regnum="18"/>
    <reg name="ss"     bitsize="32" regnum="19"/>
    <reg name="ds"     bitsize="32" regnum="20"/>
    <reg name="es"     bitsize="32" regnum="21"/>
    <reg name="fs"     bitsize="32" regnum="22"/>
    <reg name="gs"     bitsize="32" regnum="23"/>
  </feature>
</target>
"#;

/// Handle `qXfer:features:read:target.xml:off,len`.
/// Returns the slice of TARGET_XML starting at `off` for at most `len` bytes.
/// Prefix 'l' = last chunk, 'm' = more to follow.
fn handle_qxfer_features(args: &[u8]) -> Vec<u8> {
    // args = "features:read:target.xml:off,len" (the 'q' and 'Xfer:' already stripped)
    // We only support the "target.xml" annex.
    let want_annex = b"features:read:target.xml:";
    if !args.starts_with(want_annex) {
        return b"E00".to_vec();
    }
    let tail = &args[want_annex.len()..];
    let comma = match tail.iter().position(|&b| b == b',') {
        Some(i) => i,
        None    => return b"E00".to_vec(),
    };
    let off = parse_hex_u64(&tail[..comma]).unwrap_or(0) as usize;
    let len = parse_hex_u64(&tail[comma+1..]).unwrap_or(256) as usize;

    let xml = TARGET_XML;
    if off >= xml.len() {
        return b"l".to_vec();
    }
    let end   = (off + len).min(xml.len());
    let chunk = &xml[off..end];
    let more  = end < xml.len();

    let mut out = Vec::with_capacity(1 + chunk.len());
    out.push(if more { b'm' } else { b'l' });
    out.extend_from_slice(chunk);
    out
}

// ─── Binary memory write (X packet) ─────────────────────────────────────────
//
// Packet format: X addr,len:BINARY
// Binary data may contain escape sequences: 0x7d followed by (byte XOR 0x20).

fn handle_x_write(args: &[u8]) -> bool {
    // Find the comma separating addr and len.
    let comma = match args.iter().position(|&b| b == b',') { Some(i) => i, None => return false };
    let colon = match args.iter().position(|&b| b == b':') { Some(i) => i, None => return false };
    let addr = match parse_hex_u64(&args[..comma])        { Some(v) => v as usize, None => return false };
    let len  = match parse_hex_u64(&args[comma+1..colon]) { Some(v) => v as usize, None => return false };
    if len == 0 { return true; } // zero-length write is a no-op

    let raw = &args[colon+1..];
    // Decode RSP binary escapes.
    let mut decoded: Vec<u8> = Vec::with_capacity(len);
    let mut i = 0;
    while i < raw.len() {
        if raw[i] == 0x7d && i + 1 < raw.len() {
            decoded.push(raw[i + 1] ^ 0x20);
            i += 2;
        } else {
            decoded.push(raw[i]);
            i += 1;
        }
    }
    if decoded.len() != len { return false; }
    let ptr = addr as *mut u8;
    for (i, &b) in decoded.iter().enumerate() {
        unsafe { ptr.add(i).write_volatile(b); }
    }
    unsafe { core::arch::x86_64::_mm_mfence(); }
    true
}

// ─── Thread enumeration helpers ──────────────────────────────────────────────

/// Collect all live PIDs from the process table.
/// Lock is held only during the collect; released before any UART I/O.
fn live_pids() -> Vec<u32> {
    crate::proc::scheduler::with_procs_ro(|pl_vec| {
        pl_vec.iter().map(|pl| pl.pid).collect()
    })
}

/// Returns true if `pid` is live in the process table.
fn pid_alive(pid: usize) -> bool {
    crate::proc::scheduler::with_proc(pid, |_| ()).is_some()
}

/// Build a comma-separated hex PID list for qfThreadInfo replies.
/// Format: `m pid1,pid2,...`
fn build_thread_list(pids: &[u32]) -> Vec<u8> {
    let mut out = Vec::new();
    if pids.is_empty() {
        out.push(b'l');
        return out;
    }
    out.push(b'm');
    for (i, &pid) in pids.iter().enumerate() {
        if i > 0 { out.push(b','); }
        // Encode PID as hex (GDB thread IDs are hex).
        let s = alloc::format!("{:x}", pid);
        out.extend_from_slice(s.as_bytes());
    }
    out
}

// ─── Session state ───────────────────────────────────────────────────────────

struct Session {
    regs:        *mut SavedRegs,
    stopped_pid: u32,
    bps:         [Option<Breakpoint>; MAX_BPS],
    buf:         Vec<u8>,
    /// Cached thread list for qfThreadInfo / qsThreadInfo handshake.
    thread_list: Vec<u32>,
    /// Whether we have already sent the first qfThreadInfo batch.
    tlist_sent:  bool,
}

impl Session {
    fn new(regs: *mut SavedRegs, stopped_pid: u32) -> Self {
        Session {
            regs,
            stopped_pid,
            bps: [const { None }; MAX_BPS],
            buf: Vec::with_capacity(1024),
            thread_list: Vec::new(),
            tlist_sent:  false,
        }
    }

    // ── step / continue helpers ─────────────────────────────────────────

    unsafe fn do_step(&mut self, set_addr: Option<u64>) {
        if let Some(addr) = set_addr {
            SavedRegs::set_rip(self.regs, addr);
        }
        let rf = SavedRegs::rflags(self.regs);
        SavedRegs::set_rflags(self.regs, rf | RFLAGS_TF);
    }

    unsafe fn do_continue(&mut self, set_addr: Option<u64>) {
        if let Some(addr) = set_addr {
            SavedRegs::set_rip(self.regs, addr);
        }
        let rf = SavedRegs::rflags(self.regs);
        SavedRegs::set_rflags(self.regs, rf & !RFLAGS_TF);
    }

    // ── main dispatch ───────────────────────────────────────────────────

    /// Process one packet in `self.buf`.  Returns `false` to end the session.
    unsafe fn dispatch(&mut self) -> bool {
        if self.buf.is_empty() {
            // Ctrl-C or empty packet — report stopped.
            send_packet(b"S05");
            return true;
        }

        let cmd  = self.buf[0];
        let args = &self.buf[1..];
        // Keep a raw pointer so we can pass sub-slices from args below
        // without lifetime trouble from borrowing self.buf.
        let buf_ptr: *const Vec<u8> = &self.buf;
        let full_buf = &*buf_ptr;

        match cmd {
            // ── Stop-reason ─────────────────────────────────────────────
            b'?' => {
                let mut reply = alloc::format!("T05thread:{:x};", self.stopped_pid);
                send_packet(reply.as_bytes());
            }

            // ── Read all registers ──────────────────────────────────────
            b'g' => {
                let mut out = Vec::with_capacity(NUM_REGS * 16);
                for n in 0..NUM_REGS {
                    let v = reg_get(self.regs, n).unwrap_or(0);
                    // eflags and segment registers are 32-bit in GDB's view.
                    let bytes: usize = if n >= 17 { 4 } else { 8 };
                    out.extend_from_slice(&hex_encode(&v.to_le_bytes()[..bytes]));
                }
                send_packet(&out);
            }

            // ── Write all registers ─────────────────────────────────────
            b'G' => {
                // Accept variable-width encoding (matches what we send in 'g').
                let mut pos = 0usize;
                let mut ok  = true;
                for n in 0..NUM_REGS {
                    let bytes: usize = if n >= 17 { 4 } else { 8 };
                    let hex_bytes = bytes * 2;
                    if pos + hex_bytes > args.len() { ok = false; break; }
                    let mut raw = [0u8; 8];
                    if !hex_decode(&args[pos..pos + hex_bytes], &mut raw[..bytes]) {
                        ok = false; break;
                    }
                    reg_set(self.regs, n, u64::from_le_bytes(raw));
                    pos += hex_bytes;
                }
                if ok { send_ok() } else { send_error(1) }
            }

            // ── Read single register ────────────────────────────────────
            b'p' => {
                match parse_hex_u64(args).and_then(|n| reg_get(self.regs, n as usize)) {
                    Some(v) => {
                        let n = parse_hex_u64(args).unwrap_or(99) as usize;
                        let bytes = if n >= 17 && n <= 23 { 4 } else { 8 };
                        send_packet(&hex_encode(&v.to_le_bytes()[..bytes]));
                    }
                    None => send_error(2),
                }
            }

            // ── Write single register ───────────────────────────────────
            b'P' => {
                if let Some(eq) = args.iter().position(|&b| b == b'=') {
                    let n_opt = parse_hex_u64(&args[..eq]);
                    let n = match n_opt { Some(v) => v as usize, None => { send_error(1); return true; } };
                    let bytes = if n >= 17 && n <= 23 { 4 } else { 8 };
                    let mut raw = [0u8; 8];
                    if hex_decode(&args[eq+1..], &mut raw[..bytes]) {
                        if reg_set(self.regs, n, u64::from_le_bytes(raw)) {
                            send_ok();
                        } else { send_error(2); }
                    } else { send_error(1); }
                } else { send_error(1); }
            }

            // ── Read memory ─────────────────────────────────────────────
            b'm' => {
                if let Some(ci) = args.iter().position(|&b| b == b',') {
                    if let (Some(addr), Some(len)) =
                        (parse_hex_u64(&args[..ci]), parse_hex_u64(&args[ci+1..]))
                    {
                        let len = len as usize;
                        let mut out = Vec::with_capacity(len * 2);
                        let ptr = addr as *const u8;
                        for i in 0..len {
                            let mut h = [0u8; 2];
                            byte_to_hex(ptr.add(i).read_volatile(), &mut h);
                            out.extend_from_slice(&h);
                        }
                        send_packet(&out);
                    } else { send_error(1); }
                } else { send_error(1); }
            }

            // ── Write memory (hex) ──────────────────────────────────────
            b'M' => {
                let comma = args.iter().position(|&b| b == b',');
                let colon = args.iter().position(|&b| b == b':');
                if let (Some(ci), Some(co)) = (comma, colon) {
                    if let (Some(addr), Some(len)) =
                        (parse_hex_u64(&args[..ci]),
                         parse_hex_u64(&args[ci+1..co]))
                    {
                        let hex = &args[co+1..];
                        let len = len as usize;
                        if hex.len() == len * 2 {
                            let ptr = addr as *mut u8;
                            for i in 0..len {
                                if let (Some(h), Some(l)) =
                                    (from_hex_nibble(hex[i*2]),
                                     from_hex_nibble(hex[i*2+1]))
                                {
                                    ptr.add(i).write_volatile((h << 4) | l);
                                }
                            }
                            send_ok();
                        } else { send_error(1); }
                    } else { send_error(1); }
                } else { send_error(1); }
            }

            // ── Write memory (binary) ───────────────────────────────────
            b'X' => {
                if handle_x_write(args) { send_ok() } else { send_error(1) }
            }

            // ── Single-step ─────────────────────────────────────────────
            // 's' or 's addr'
            b's' => {
                let addr = parse_hex_u64(args);
                self.do_step(addr);
                send_packet(b"S05");
                return false;
            }

            // ── Continue ────────────────────────────────────────────────
            // 'c' or 'c addr'
            b'c' => {
                let addr = parse_hex_u64(args);
                self.do_continue(addr);
                send_packet(b"S05");
                return false;
            }

            // ── Breakpoints ─────────────────────────────────────────────
            // Z0/z0 = SW breakpoint; Z1-Z4/z1-z4 = HW (return E01)
            b'Z' | b'z' => {
                let bp_type = args.first().copied().unwrap_or(b'?');
                if bp_type != b'0' {
                    // Hardware breakpoints/watchpoints not implemented.
                    // E01 tells GDB to fall back to software immediately.
                    send_error(1);
                } else {
                    // z0,addr,kind — parse addr
                    let rest = &args[1..];
                    let rest = rest.strip_prefix(b",").unwrap_or(rest);
                    let end  = rest.iter().position(|&b| b == b',').unwrap_or(rest.len());
                    if let Some(addr) = parse_hex_u64(&rest[..end]) {
                        let ok = if cmd == b'Z' {
                            bp_insert(&mut self.bps, addr as usize)
                        } else {
                            bp_remove(&mut self.bps, addr as usize)
                        };
                        if ok { send_ok() } else { send_error(1) }
                    } else { send_error(1); }
                }
            }

            // ── Thread-selection (H) ────────────────────────────────────
            // Hg<tid> / Hc<tid>: we ignore the selected thread (single
            // register context per session) but must reply OK.
            b'H' => send_ok(),

            // ── Thread alive (T) ────────────────────────────────────────
            b'T' => {
                if let Some(pid) = parse_hex_u64(args) {
                    if pid_alive(pid as usize) { send_ok() } else { send_error(1) }
                } else { send_error(1); }
            }

            // ── Query packets (q) ───────────────────────────────────────
            b'q' => self.handle_q(full_buf),

            // ── vCont / vKill / v* ──────────────────────────────────────
            b'v' => {
                let cont = self.handle_v(full_buf);
                if !cont { return false; }
            }

            // ── Detach ──────────────────────────────────────────────────
            b'D' => {
                bp_clear_all(&mut self.bps);
                send_ok();
                return false;
            }

            // ── Kill ────────────────────────────────────────────────────
            b'k' => {
                bp_clear_all(&mut self.bps);
                return false;
            }

            _ => send_empty(),
        }
        true // keep session alive
    }

    // ── q-packet handler ─────────────────────────────────────────────────────

    fn handle_q(&mut self, buf: &[u8]) {
        if buf.starts_with(b"qSupported") {
            // Advertise our capabilities.
            send_packet(
                b"PacketSize=1000;\
                  swbreak+;hwbreak-;\
                  vContSupported+;\
                  qXfer:features:read+"
            );
        } else if buf.starts_with(b"qAttached") {
            send_packet(b"1");
        } else if buf.starts_with(b"qC") {
            // Current thread = the stopped PID.
            let r = alloc::format!("QC{:x}", self.stopped_pid);
            send_packet(r.as_bytes());
        } else if buf.starts_with(b"qfThreadInfo") {
            // First batch: collect all live PIDs, send them all in one packet.
            // (We always have few enough PIDs to fit in PacketSize=0x1000.)
            self.thread_list = live_pids();
            self.tlist_sent  = true;
            let reply = build_thread_list(&self.thread_list);
            send_packet(&reply);
        } else if buf.starts_with(b"qsThreadInfo") {
            // Subsequent batch: always empty (we sent everything in qf).
            send_packet(b"l");
        } else if buf.starts_with(b"qThreadExtraInfo") {
            // Optional: return a human-readable string for the thread.
            // Format: qThreadExtraInfo,tid
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
            let inner = &buf[b"qXfer:".len()..];
            let reply = handle_qxfer_features(inner);
            send_packet(&reply);
        } else if buf.starts_with(b"qTStatus") {
            send_empty();
        } else if buf.starts_with(b"qOffsets") {
            send_packet(b"Text=0;Data=0;Bss=0");
        } else {
            send_empty();
        }
    }

    // ── v-packet handler ─────────────────────────────────────────────────────
    // Returns false if the session should end (continue/step/kill).

    unsafe fn handle_v(&mut self, buf: &[u8]) -> bool {
        if buf.starts_with(b"vCont?") {
            send_packet(b"vCont;s;c");
        } else if buf.starts_with(b"vCont;") {
            // vCont;action[:tid][;action[:tid]...]
            // We process the *first* action only (sufficient for single-CPU
            // debugging).  Thread IDs are hex after ':'.
            let rest = &buf[b"vCont;".len()..];
            // Trim off optional ':tid' to get the action character.
            let action = rest[0];
            let addr_part = rest.get(1..).and_then(|r| {
                // 'saddr' or 'caddr' — optional address after action char,
                // before optional ';' separator.
                let end = r.iter().position(|&b| b == b';' || b == b':').unwrap_or(r.len());
                if end > 0 { parse_hex_u64(&r[..end]) } else { None }
            });
            match action {
                b's' => { self.do_step(addr_part);     send_packet(b"S05"); return false; }
                b'c' => { self.do_continue(addr_part); send_packet(b"S05"); return false; }
                _    => send_empty(),
            }
        } else if buf.starts_with(b"vKill") {
            bp_clear_all(&mut self.bps);
            send_ok();
            return false;
        } else if buf.starts_with(b"vMustReplyEmpty") {
            send_empty();
        } else {
            send_empty();
        }
        true
    }
}

// ─── Public entry point ──────────────────────────────────────────────────────

/// Entry point from the #BP / #DB handler.
///
/// Blocks on COM1 until GDB sends `D` (detach) or `k` (kill), then
/// returns so the interrupt handler can resume the interrupted context.
///
/// `stopped_pid`: the PID of the task that hit the trap (used for `?` and
/// `qC` replies).  Pass `scheduler::current_pid()` from the trap handler.
///
/// # Safety
/// `regs` must point to the live, writable register save area on the
/// interrupted stack and remain valid for the duration of the session.
pub unsafe fn run_session(regs: *mut SavedRegs, stopped_pid: u32) {
    // Announce ourselves as stopped with SIGTRAP on the stopped thread.
    let stop_msg = alloc::format!("T05thread:{:x};", stopped_pid);
    send_packet(stop_msg.as_bytes());

    let mut sess = Session::new(regs, stopped_pid);

    loop {
        recv_packet(&mut sess.buf);
        if !sess.dispatch() { break; }
    }
}
