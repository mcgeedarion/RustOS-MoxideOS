//! GDB Remote Serial Protocol engine.
//!
//! Implements the packet framing loop and all packet handlers needed
//! for `gdb` to attach, inspect, and control the kernel.
//!
//! ## Supported packets
//!
//! | Packet          | Direction | Description                              |
//! |-----------------|-----------|------------------------------------------|
//! | `?`             | → stub    | Why did you stop? (always SIGTRAP)       |
//! | `g`             | → stub    | Read all registers                       |
//! | `G<hex>`        | → stub    | Write all registers                      |
//! | `p<n>`          | → stub    | Read register n                          |
//! | `P<n>=<v>`      | → stub    | Write register n                         |
//! | `m<addr>,<len>` | → stub    | Read memory                              |
//! | `M<addr>,<len>:<hex>` | → stub | Write memory                          |
//! | `s`             | → stub    | Single-step                              |
//! | `c`             | → stub    | Continue                                 |
//! | `z0/<Z0>`       | → stub    | Insert / remove software breakpoint      |
//! | `H*`            | → stub    | Thread select (no-op, single-thread)     |
//! | `qSupported`    | → stub    | Feature negotiation                      |
//! | `qAttached`     | → stub    | Query: attached to existing process?     |
//! | `vCont?`        | → stub    | Query supported vCont actions            |
//! | `vCont;s`       | → stub    | vCont single-step                        |
//! | `vCont;c`       | → stub    | vCont continue                           |
//! | `D`             | → stub    | Detach                                   |
//! | `k`             | → stub    | Kill (bare-metal: same as detach)        |

extern crate alloc;
use alloc::vec::Vec;
use crate::gdbstub::serial;

// ── Register save-frame layout ────────────────────────────────────────────────
//
// Must match the push order in the arch trap-entry stubs.
// x86_64: rax rbx rcx rdx rsi rdi rbp r8 r9 r10 r11 r12 r13 r14 r15 rip rflags
// (17 × 8 bytes = 136 bytes)

#[repr(C)]
pub struct SavedRegs {
    pub rax:    u64,
    pub rbx:    u64,
    pub rcx:    u64,
    pub rdx:    u64,
    pub rsi:    u64,
    pub rdi:    u64,
    pub rbp:    u64,
    pub r8:     u64,
    pub r9:     u64,
    pub r10:    u64,
    pub r11:    u64,
    pub r12:    u64,
    pub r13:    u64,
    pub r14:    u64,
    pub r15:    u64,
    pub rip:    u64,
    pub rflags: u64,
}

const NUM_REGS: usize = 17;

// x86_64 RFLAGS Trap Flag
const RFLAGS_TF: u64 = 1 << 8;

// Maximum breakpoints tracked simultaneously
const MAX_BPS: usize = 16;

struct Breakpoint {
    addr:  usize,
    saved: u8,   // byte that was overwritten by INT3 (0xCC)
}

// ── Checksum helpers ──────────────────────────────────────────────────────────

fn checksum(data: &[u8]) -> u8 {
    data.iter().fold(0u8, |acc, &b| acc.wrapping_add(b))
}

fn hex_nibble(n: u8) -> u8 {
    if n < 10 { b'0' + n } else { b'a' + n - 10 }
}

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
    let mut v: u64 = 0;
    for &c in s {
        let n = from_hex_nibble(c)?;
        v = v.checked_shl(4)?.wrapping_add(n as u64);
    }
    Some(v)
}

// Decode a hex string of length 2*N into N bytes (little-endian u64 → LE bytes)
fn hex_decode(src: &[u8], dst: &mut [u8]) -> bool {
    if src.len() != dst.len() * 2 { return false; }
    for i in 0..dst.len() {
        let hi = match from_hex_nibble(src[i*2])   { Some(v) => v, None => return false };
        let lo = match from_hex_nibble(src[i*2+1]) { Some(v) => v, None => return false };
        dst[i] = (hi << 4) | lo;
    }
    true
}

// Encode bytes as hex into a Vec<u8>
fn hex_encode(src: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(src.len() * 2);
    for &b in src {
        let mut h = [0u8; 2];
        byte_to_hex(b, &mut h);
        out.extend_from_slice(&h);
    }
    out
}

// ── Packet I/O ───────────────────────────────────────────────────────────────

/// Read one RSP packet into `buf`. Retries on bad checksum (sends '-').
/// Returns the payload slice length.
fn recv_packet(buf: &mut Vec<u8>) -> usize {
    loop {
        // Discard anything until '$'
        loop {
            let b = serial::read_byte();
            if b == b'$' { break; }
            // Handle Ctrl-C interrupt (0x03) — treat as a bare stop request.
            // We surface it by synthesising a zero-length packet so the caller
            // can send a stop reply.
            if b == 0x03 {
                buf.clear();
                return 0;
            }
        }

        buf.clear();
        let mut csum_got: u8 = 0;

        // Read payload until '#'
        loop {
            let b = serial::read_byte();
            if b == b'#' { break; }
            buf.push(b);
            csum_got = csum_got.wrapping_add(b);
        }

        // Read two-nibble checksum
        let ch = serial::read_byte();
        let cl = serial::read_byte();
        let expected = match (from_hex_nibble(ch), from_hex_nibble(cl)) {
            (Some(h), Some(l)) => (h << 4) | l,
            _ => { serial::write_byte(b'-'); continue; }
        };

        if csum_got != expected {
            serial::write_byte(b'-');
            continue;
        }

        serial::write_byte(b'+');
        return buf.len();
    }
}

/// Send a RSP packet `$<data>#<checksum>` and wait for '+' ACK.
fn send_packet(data: &[u8]) {
    loop {
        serial::write_byte(b'$');
        serial::write_bytes(data);
        serial::write_byte(b'#');
        let cs = checksum(data);
        let mut h = [0u8; 2];
        byte_to_hex(cs, &mut h);
        serial::write_bytes(&h);

        // Wait for ACK
        loop {
            let b = serial::read_byte();
            if b == b'+' { return; }
            if b == b'-' { break; } // NAK → retransmit
            // ignore other noise
        }
    }
}

fn send_ok()    { send_packet(b"OK"); }
fn send_empty() { send_packet(b""); }
fn send_error(n: u8) {
    let mut h = [0u8; 2];
    byte_to_hex(n, &mut h);
    let mut pkt = Vec::with_capacity(3);
    pkt.push(b'E');
    pkt.extend_from_slice(&h);
    send_packet(&pkt);
}

// ── Register accessors ────────────────────────────────────────────────────────

unsafe fn reg_get(regs: *const SavedRegs, n: usize) -> Option<u64> {
    let r = &*regs;
    match n {
        0  => Some(r.rax),
        1  => Some(r.rbx),
        2  => Some(r.rcx),
        3  => Some(r.rdx),
        4  => Some(r.rsi),
        5  => Some(r.rdi),
        6  => Some(r.rbp),
        7  => Some(0),       // rsp — not saved in our frame; return 0
        8  => Some(r.r8),
        9  => Some(r.r9),
        10 => Some(r.r10),
        11 => Some(r.r11),
        12 => Some(r.r12),
        13 => Some(r.r13),
        14 => Some(r.r14),
        15 => Some(r.r15),
        16 => Some(r.rip),
        _  => None,
    }
}

unsafe fn reg_set(regs: *mut SavedRegs, n: usize, v: u64) -> bool {
    let r = &mut *regs;
    match n {
        0  => r.rax = v,
        1  => r.rbx = v,
        2  => r.rcx = v,
        3  => r.rdx = v,
        4  => r.rsi = v,
        5  => r.rdi = v,
        6  => r.rbp = v,
        7  => {}             // rsp — ignore
        8  => r.r8  = v,
        9  => r.r9  = v,
        10 => r.r10 = v,
        11 => r.r11 = v,
        12 => r.r12 = v,
        13 => r.r13 = v,
        14 => r.r14 = v,
        15 => r.r15 = v,
        16 => r.rip = v,
        _  => return false,
    }
    true
}

// ── Breakpoint helpers ────────────────────────────────────────────────────────

fn bp_insert(bps: &mut [Option<Breakpoint>; MAX_BPS], addr: usize) -> bool {
    // Don't insert twice
    if bps.iter().flatten().any(|b| b.addr == addr) { return true; }
    let slot = match bps.iter_mut().find(|s| s.is_none()) {
        Some(s) => s,
        None    => return false,
    };
    let saved = unsafe { *(addr as *const u8) };
    unsafe { *(addr as *mut u8) = 0xCC; } // INT3
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
    true // not found is still "OK" per RSP spec
}

fn bp_clear_all(bps: &mut [Option<Breakpoint>; MAX_BPS]) {
    for slot in bps.iter_mut() {
        if let Some(ref bp) = *slot {
            unsafe { *(bp.addr as *mut u8) = bp.saved; }
        }
        *slot = None;
    }
}

// ── Session loop ──────────────────────────────────────────────────────────────

/// Run a GDB RSP session until GDB detaches or kills.
/// `regs` is the interrupted context; modified in-place by `G`/`P` packets.
pub unsafe fn run_session(regs: *mut SavedRegs) {
    // We're inside a trap — send stop reply immediately so GDB knows we halted.
    send_packet(b"S05"); // SIGTRAP

    let mut buf: Vec<u8> = Vec::with_capacity(512);
    // Use a const-size array so we stay no_std (no HashMap needed).
    let mut bps: [Option<Breakpoint>; MAX_BPS] = [const { None }; MAX_BPS];

    'session: loop {
        recv_packet(&mut buf);

        if buf.is_empty() {
            // Ctrl-C / empty packet → stop reply
            send_packet(b"S05");
            continue;
        }

        let cmd = buf[0];
        let args = &buf[1..];

        match cmd {
            // ── ? : stop reason ───────────────────────────────────────────
            b'?' => send_packet(b"S05"),

            // ── g : read all registers ────────────────────────────────────
            b'g' => {
                let mut out: Vec<u8> = Vec::with_capacity(NUM_REGS * 16);
                for n in 0..NUM_REGS {
                    let v = reg_get(regs, n).unwrap_or(0);
                    // GDB expects little-endian bytes, 8 bytes per 64-bit reg
                    let le = v.to_le_bytes();
                    out.extend_from_slice(&hex_encode(&le));
                }
                send_packet(&out);
            }

            // ── G<hex> : write all registers ──────────────────────────────
            b'G' => {
                if args.len() != NUM_REGS * 16 {
                    send_error(1);
                } else {
                    let mut ok = true;
                    for n in 0..NUM_REGS {
                        let chunk = &args[n*16..(n+1)*16];
                        let mut raw = [0u8; 8];
                        if !hex_decode(chunk, &mut raw) { ok = false; break; }
                        let v = u64::from_le_bytes(raw);
                        reg_set(regs, n, v);
                    }
                    if ok { send_ok() } else { send_error(1) }
                }
            }

            // ── p<n> : read single register ───────────────────────────────
            b'p' => {
                if let Some(n) = parse_hex_u64(args) {
                    if let Some(v) = reg_get(regs, n as usize) {
                        let le = v.to_le_bytes();
                        send_packet(&hex_encode(&le));
                    } else {
                        send_error(2);
                    }
                } else {
                    send_error(1);
                }
            }

            // ── P<n>=<v> : write single register ──────────────────────────
            b'P' => {
                // Format: <n>=<16-hex-digits>
                if let Some(eq) = args.iter().position(|&b| b == b'=') {
                    let n_part = &args[..eq];
                    let v_part = &args[eq+1..];
                    let mut raw = [0u8; 8];
                    if let Some(n) = parse_hex_u64(n_part) {
                        if hex_decode(v_part, &mut raw) {
                            let v = u64::from_le_bytes(raw);
                            if reg_set(regs, n as usize, v) {
                                send_ok();
                            } else {
                                send_error(2);
                            }
                        } else { send_error(1); }
                    } else { send_error(1); }
                } else { send_error(1); }
            }

            // ── m<addr>,<len> : read memory ───────────────────────────────
            b'm' => {
                if let Some(comma) = args.iter().position(|&b| b == b',') {
                    let addr_part = &args[..comma];
                    let len_part  = &args[comma+1..];
                    if let (Some(addr), Some(len)) =
                        (parse_hex_u64(addr_part), parse_hex_u64(len_part))
                    {
                        let len = len as usize;
                        // Validate via uaccess before touching the pointer.
                        // For kernel addresses we just read directly.
                        let ptr = addr as *const u8;
                        // Safety: GDB is trusted; this is a debug-only feature.
                        let mut out = Vec::with_capacity(len * 2);
                        for i in 0..len {
                            let b = unsafe { ptr.add(i).read_volatile() };
                            let mut h = [0u8; 2];
                            byte_to_hex(b, &mut h);
                            out.extend_from_slice(&h);
                        }
                        send_packet(&out);
                    } else { send_error(1); }
                } else { send_error(1); }
            }

            // ── M<addr>,<len>:<hex> : write memory ────────────────────────
            b'M' => {
                // find ','
                let comma = args.iter().position(|&b| b == b',');
                let colon = args.iter().position(|&b| b == b':');
                if let (Some(ci), Some(co)) = (comma, colon) {
                    let addr = parse_hex_u64(&args[..ci]);
                    let len  = parse_hex_u64(&args[ci+1..co]);
                    if let (Some(addr), Some(len)) = (addr, len) {
                        let hex = &args[co+1..];
                        let len = len as usize;
                        if hex.len() == len * 2 {
                            let ptr = addr as *mut u8;
                            for i in 0..len {
                                let hi = from_hex_nibble(hex[i*2]);
                                let lo = from_hex_nibble(hex[i*2+1]);
                                if let (Some(h), Some(l)) = (hi, lo) {
                                    unsafe { ptr.add(i).write_volatile((h << 4) | l); }
                                }
                            }
                            send_ok();
                        } else { send_error(1); }
                    } else { send_error(1); }
                } else { send_error(1); }
            }

            // ── s : single-step ───────────────────────────────────────────
            b's' => {
                (*regs).rflags |= RFLAGS_TF;
                // Return from session; the next #DB trap will re-enter.
                // Send stop reply first so GDB knows we're running.
                send_packet(b"S05");
                break 'session;
            }

            // ── c : continue ─────────────────────────────────────────────
            b'c' => {
                (*regs).rflags &= !RFLAGS_TF;
                send_packet(b"S05");
                break 'session;
            }

            // ── z0 / Z0 : software breakpoints ───────────────────────────
            b'z' | b'Z' => {
                // Format: z0,<addr>,<kind>  or  Z0,<addr>,<kind>
                // We only handle type 0 (software breakpoint).
                if args.first() != Some(&b'0') {
                    send_empty(); // unsupported type
                } else {
                    let rest = &args[1..]; // skip '0'
                    if rest.first() == Some(&b',') {
                        let rest = &rest[1..]; // skip ','
                        let addr_end = rest.iter().position(|&b| b == b',')
                            .unwrap_or(rest.len());
                        if let Some(addr) = parse_hex_u64(&rest[..addr_end]) {
                            let success = if cmd == b'Z' {
                                bp_insert(&mut bps, addr as usize)
                            } else {
                                bp_remove(&mut bps, addr as usize)
                            };
                            if success { send_ok() } else { send_error(1) }
                        } else { send_error(1); }
                    } else { send_error(1); }
                }
            }

            // ── H* : set thread (no-op — single-threaded) ────────────────
            b'H' => send_ok(),

            // ── q : general query packets ─────────────────────────────────
            b'q' => {
                if buf.starts_with(b"qSupported") {
                    send_packet(b"PacketSize=400;swbreak+;hwbreak-;vContSupported+");
                } else if buf.starts_with(b"qAttached") {
                    send_packet(b"1"); // attached to existing process
                } else if buf.starts_with(b"qC") {
                    // current thread — we only have thread 1
                    send_packet(b"QC1");
                } else if buf.starts_with(b"qfThreadInfo") {
                    send_packet(b"m1"); // one thread
                } else if buf.starts_with(b"qsThreadInfo") {
                    send_packet(b"l");  // end of thread list
                } else if buf.starts_with(b"qTStatus") {
                    send_empty(); // no tracing
                } else if buf.starts_with(b"qOffsets") {
                    send_packet(b"Text=0;Data=0;Bss=0");
                } else {
                    send_empty();
                }
            }

            // ── v : verbose packets ───────────────────────────────────────
            b'v' => {
                if buf.starts_with(b"vCont?") {
                    send_packet(b"vCont;s;c");
                } else if buf.starts_with(b"vCont;") {
                    let action = buf.get(6).copied().unwrap_or(0);
                    match action {
                        b's' => {
                            (*regs).rflags |= RFLAGS_TF;
                            send_packet(b"S05");
                            break 'session;
                        }
                        b'c' => {
                            (*regs).rflags &= !RFLAGS_TF;
                            send_packet(b"S05");
                            break 'session;
                        }
                        _ => send_empty(),
                    }
                } else if buf.starts_with(b"vKill") {
                    bp_clear_all(&mut bps);
                    send_ok();
                    break 'session;
                } else if buf.starts_with(b"vMustReplyEmpty") {
                    send_empty();
                } else {
                    send_empty();
                }
            }

            // ── D : detach ────────────────────────────────────────────────
            b'D' => {
                bp_clear_all(&mut bps);
                send_ok();
                break 'session;
            }

            // ── k : kill (bare-metal: same as detach) ────────────────────
            b'k' => {
                bp_clear_all(&mut bps);
                // No reply for 'k' per spec
                break 'session;
            }

            // ── unknown packet: empty reply per RSP spec ──────────────────
            _ => send_empty(),
        }
    }
}
