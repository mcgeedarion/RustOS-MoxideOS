//! GDB Remote Serial Protocol — x86-64 packet handler.
//!
//! Dispatches RSP packets received from GDB over the serial/TCP transport.
//! All process inspection uses GdbTarget (proc_debug fds); no ptrace calls.
//!
//! ## Packets handled
//!   `?`           → stop reason
//!   `g`           → read all registers
//!   `G<hex>`      → write all registers
//!   `m<addr>,<len>` → read memory
//!   `M<addr>,<len>:<hex>` → write memory
//!   `c[addr]`     → continue
//!   `s[addr]`     → single-step
//!   `k`           → kill
//!   `q*`          → qSupported / qAttached stubs

extern crate alloc;
use alloc::string::String;
use alloc::vec::Vec;

use super::target::GdbTarget;
use crate::proc::ptrace::{
    UREG_COUNT, UREG_RIP, UREG_RSP, UREG_EFLAGS,
    UREG_RAX, UREG_RBX, UREG_RCX, UREG_RDX,
    UREG_RSI, UREG_RDI, UREG_RBP,
    UREG_R8, UREG_R9, UREG_R10, UREG_R11,
    UREG_R12, UREG_R13, UREG_R14, UREG_R15,
    UREG_CS, UREG_SS,
};

// ── RSP framing helpers ───────────────────────────────────────────────────────

/// Wrap a response body in RSP `+$<body>#<checksum>`.
pub fn rsp_packet(body: &str) -> String {
    let csum: u8 = body.bytes().fold(0u8, |acc, b| acc.wrapping_add(b));
    alloc::format!("+${}#{:02x}", body, csum)
}

/// Decode a hex digit.
fn from_hex(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

fn decode_hex_bytes(s: &str) -> Vec<u8> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len() / 2);
    let mut i = 0;
    while i + 1 < b.len() {
        if let (Some(hi), Some(lo)) = (from_hex(b[i]), from_hex(b[i+1])) {
            out.push((hi << 4) | lo);
        }
        i += 2;
    }
    out
}

fn encode_hex_bytes(data: &[u8]) -> String {
    let mut s = String::with_capacity(data.len() * 2);
    for &b in data {
        let hi = b >> 4;
        let lo = b & 0xf;
        s.push(char::from_digit(hi as u32, 16).unwrap_or('0'));
        s.push(char::from_digit(lo as u32, 16).unwrap_or('0'));
    }
    s
}

fn u64_le_hex(v: u64) -> String {
    encode_hex_bytes(&v.to_le_bytes())
}

fn parse_hex_u64(s: &str) -> u64 {
    u64::from_str_radix(s, 16).unwrap_or(0)
}

// ── GDB x86-64 register order (matches gdb's i386:x86-64 target.xml) ────────
// 0-7: rax rcx rdx rbx rsp rbp rsi rdi
// 8-15: r8..r15
// 16: rip  17: eflags  18: cs  19: ss
// (We send 32 × 8-byte regs; regs 20-31 are zero-padded segment regs)

const GDB_REG_COUNT: usize = 32;

fn gdb_reg_order() -> [usize; GDB_REG_COUNT] {
    [
        UREG_RAX, UREG_RCX, UREG_RDX, UREG_RBX,
        UREG_RSP, UREG_RBP, UREG_RSI, UREG_RDI,
        UREG_R8,  UREG_R9,  UREG_R10, UREG_R11,
        UREG_R12, UREG_R13, UREG_R14, UREG_R15,
        UREG_RIP, UREG_EFLAGS, UREG_CS, UREG_SS,
        // regs 20-31: fs/gs/ds/es + 8 padding
        UREG_COUNT, UREG_COUNT, UREG_COUNT, UREG_COUNT,
        UREG_COUNT, UREG_COUNT, UREG_COUNT, UREG_COUNT,
        UREG_COUNT, UREG_COUNT, UREG_COUNT, UREG_COUNT,
    ]
}

// ── Packet dispatch ───────────────────────────────────────────────────────────

/// Process one RSP packet body (without the `$` prefix and `#XX` suffix).
/// Returns the response string (already framed with `rsp_packet`).
pub fn handle_packet(body: &str, target: &mut GdbTarget) -> String {
    if body.is_empty() { return rsp_packet(""); }

    match body.as_bytes()[0] {
        // ── ? — stop reason ──────────────────────────────────────────────────
        b'?' => {
            let status = target.poll_status();
            if status.starts_with('T') {
                // Already in RSP stop-reply format: "T05" etc.
                rsp_packet(&status)
            } else {
                rsp_packet("T05")
            }
        }

        // ── g — read all registers ────────────────────────────────────────────
        b'g' => {
            let regs = target.read_regs();
            let order = gdb_reg_order();
            let mut hex = String::with_capacity(GDB_REG_COUNT * 16);
            for &idx in &order {
                let val = if idx < UREG_COUNT { regs[idx] } else { 0u64 };
                hex.push_str(&u64_le_hex(val));
            }
            rsp_packet(&hex)
        }

        // ── G — write all registers ───────────────────────────────────────────
        b'G' => {
            let hex = &body[1..];
            let bytes = decode_hex_bytes(hex);
            let order = gdb_reg_order();
            let mut regs = target.read_regs(); // start from current
            for (i, &idx) in order.iter().enumerate() {
                if idx >= UREG_COUNT { continue; }
                let off = i * 8;
                if off + 8 > bytes.len() { break; }
                regs[idx] = u64::from_le_bytes(bytes[off..off+8].try_into().unwrap());
            }
            target.write_regs(&regs);
            rsp_packet("OK")
        }

        // ── m — read memory ───────────────────────────────────────────────────
        b'm' => {
            // format: m<addr>,<len>
            let rest = &body[1..];
            let mut parts = rest.splitn(2, ',');
            let addr = parse_hex_u64(parts.next().unwrap_or(""));
            let len  = parse_hex_u64(parts.next().unwrap_or("")) as usize;
            let data = target.read_mem(addr, len);
            rsp_packet(&encode_hex_bytes(&data))
        }

        // ── M — write memory ──────────────────────────────────────────────────
        b'M' => {
            // format: M<addr>,<len>:<hexdata>
            let rest = &body[1..];
            let colon = rest.find(':').unwrap_or(rest.len());
            let addr_len = &rest[..colon];
            let hex_data = if colon < rest.len() { &rest[colon+1..] } else { "" };
            let mut al = addr_len.splitn(2, ',');
            let addr = parse_hex_u64(al.next().unwrap_or(""));
            let data = decode_hex_bytes(hex_data);
            target.write_mem(addr, &data);
            rsp_packet("OK")
        }

        // ── c — continue ──────────────────────────────────────────────────────
        b'c' => {
            // optional address: set RIP before continuing
            let rest = &body[1..];
            if !rest.is_empty() {
                let addr = parse_hex_u64(rest);
                let mut regs = target.read_regs();
                regs[UREG_RIP] = addr;
                target.write_regs(&regs);
            }
            target.ctl("cont");
            // GDB expects no reply for 'c' until the next stop
            String::new()
        }

        // ── s — single-step ───────────────────────────────────────────────────
        b's' => {
            let rest = &body[1..];
            if !rest.is_empty() {
                let addr = parse_hex_u64(rest);
                let mut regs = target.read_regs();
                regs[UREG_RIP] = addr;
                target.write_regs(&regs);
            }
            target.ctl("step");
            String::new()
        }

        // ── k — kill ──────────────────────────────────────────────────────────
        b'k' => {
            crate::proc::signal::send_signal(target.pid, 9);
            rsp_packet("OK")
        }

        // ── q — query packets ─────────────────────────────────────────────────
        b'q' => {
            if body.starts_with("qSupported") {
                rsp_packet("PacketSize=4000")
            } else if body.starts_with("qAttached") {
                rsp_packet("1")
            } else if body.starts_with("qC") {
                let pid = target.pid;
                rsp_packet(&alloc::format!("QC{:x}", pid))
            } else {
                rsp_packet("") // unsupported query
            }
        }

        _ => rsp_packet(""), // unsupported
    }
}
