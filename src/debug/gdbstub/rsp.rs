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
//!   `Z<t>,<addr>,<len>` → insert breakpoint / watchpoint
//!   `z<t>,<addr>,<len>` → remove breakpoint / watchpoint

extern crate alloc;
use alloc::string::String;
use alloc::vec::Vec;

use super::breakpoints::{
    riscv_add_trigger, riscv_remove_trigger, HwBreakpointTable, SwBreakpointTable, WatchKind,
    WatchpointTable, RISCV_TRIG_EXEC, RISCV_TRIG_LOAD, RISCV_TRIG_STORE,
};
use super::target::GdbTarget;
use crate::proc::ptrace::{
    UREG_COUNT, UREG_CS, UREG_EFLAGS, UREG_R10, UREG_R11, UREG_R12, UREG_R13, UREG_R14, UREG_R15,
    UREG_R8, UREG_R9, UREG_RAX, UREG_RBP, UREG_RBX, UREG_RCX, UREG_RDI, UREG_RDX, UREG_RIP,
    UREG_RSI, UREG_RSP, UREG_SS,
};

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
        if let (Some(hi), Some(lo)) = (from_hex(b[i]), from_hex(b[i + 1])) {
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

// 0-7: rax rcx rdx rbx rsp rbp rsi rdi
// 8-15: r8..r15
// 16: rip  17: eflags  18: cs  19: ss
// (We send 32 × 8-byte regs; regs 20-31 are zero-padded segment regs)

const GDB_REG_COUNT: usize = 32;

fn gdb_reg_order() -> [usize; GDB_REG_COUNT] {
    [
        UREG_RAX,
        UREG_RCX,
        UREG_RDX,
        UREG_RBX,
        UREG_RSP,
        UREG_RBP,
        UREG_RSI,
        UREG_RDI,
        UREG_R8,
        UREG_R9,
        UREG_R10,
        UREG_R11,
        UREG_R12,
        UREG_R13,
        UREG_R14,
        UREG_R15,
        UREG_RIP,
        UREG_EFLAGS,
        UREG_CS,
        UREG_SS,
        // regs 20-31: fs/gs/ds/es + 8 padding
        UREG_COUNT,
        UREG_COUNT,
        UREG_COUNT,
        UREG_COUNT,
        UREG_COUNT,
        UREG_COUNT,
        UREG_COUNT,
        UREG_COUNT,
        UREG_COUNT,
        UREG_COUNT,
        UREG_COUNT,
        UREG_COUNT,
    ]
}

/// Parse `<type>,<addr>,<len>` from a Z or z packet body (after the leading
/// `Z`/`z` byte has been stripped).
fn parse_zpacket(rest: &str) -> Option<(u8, u64, usize)> {
    let mut it = rest.splitn(3, ',');
    let t = u8::from_str_radix(it.next()?, 16).ok()?;
    let addr = parse_hex_u64(it.next()?);
    let len = usize::from_str_radix(it.next()?, 16).unwrap_or(1);
    Some((t, addr, len))
}

// `handle_packet` is stateless for every packet *except* Z/z which must
// consult the per-session breakpoint tables.  Pass a `Session` alongside
// the target so the tables survive across calls.

pub struct Session {
    pub sw_bps: SwBreakpointTable,
    pub hw_bps: HwBreakpointTable,
    pub watches: WatchpointTable,
}

impl Session {
    pub fn new() -> Self {
        Session {
            sw_bps: SwBreakpointTable::new(),
            hw_bps: HwBreakpointTable::new(),
            watches: WatchpointTable::new(),
        }
    }

    /// Remove every bp/watchpoint — call on detach or kill.
    pub fn detach(&mut self, target: &mut GdbTarget) {
        self.sw_bps.remove_all(target);
        self.hw_bps.remove_all(target);
        self.watches.remove_all(target);
    }
}

/// Process one RSP packet body (without the `$` prefix and `#XX` suffix).
/// Returns the response string (already framed with `rsp_packet`), or an
/// empty string for packets where GDB expects no reply until the next stop
/// event (e.g. `c`, `s`).
pub fn handle_packet(body: &str, target: &mut GdbTarget, session: &mut Session) -> String {
    if body.is_empty() {
        return rsp_packet("");
    }

    match body.as_bytes()[0] {
        b'?' => {
            let status = target.poll_status();
            if status.starts_with('T') {
                rsp_packet(&status)
            } else {
                rsp_packet("T05")
            }
        },

        b'g' => {
            let regs = target.read_regs();
            let order = gdb_reg_order();
            let mut hex = String::with_capacity(GDB_REG_COUNT * 16);
            for &idx in &order {
                let val = if idx < UREG_COUNT { regs[idx] } else { 0u64 };
                hex.push_str(&u64_le_hex(val));
            }
            rsp_packet(&hex)
        },

        b'G' => {
            let hex = &body[1..];
            let bytes = decode_hex_bytes(hex);
            let order = gdb_reg_order();
            let mut regs = target.read_regs();
            for (i, &idx) in order.iter().enumerate() {
                if idx >= UREG_COUNT {
                    continue;
                }
                let off = i * 8;
                if off + 8 > bytes.len() {
                    break;
                }
                regs[idx] = u64::from_le_bytes(bytes[off..off + 8].try_into().unwrap());
            }
            target.write_regs(&regs);
            rsp_packet("OK")
        },

        b'm' => {
            let rest = &body[1..];
            let mut parts = rest.splitn(2, ',');
            let addr = parse_hex_u64(parts.next().unwrap_or(""));
            let len = parse_hex_u64(parts.next().unwrap_or("")) as usize;
            let data = target.read_mem(addr, len);
            rsp_packet(&encode_hex_bytes(&data))
        },

        b'M' => {
            let rest = &body[1..];
            let colon = rest.find(':').unwrap_or(rest.len());
            let addr_len = &rest[..colon];
            let hex_data = if colon < rest.len() {
                &rest[colon + 1..]
            } else {
                ""
            };
            let mut al = addr_len.splitn(2, ',');
            let addr = parse_hex_u64(al.next().unwrap_or(""));
            let data = decode_hex_bytes(hex_data);
            target.write_mem(addr, &data);
            rsp_packet("OK")
        },

        b'c' => {
            let rest = &body[1..];
            if !rest.is_empty() {
                let addr = parse_hex_u64(rest);
                let mut regs = target.read_regs();
                regs[UREG_RIP] = addr;
                target.write_regs(&regs);
            }
            target.ctl("cont");
            String::new() // no reply until next stop
        },

        b's' => {
            let rest = &body[1..];
            if !rest.is_empty() {
                let addr = parse_hex_u64(rest);
                let mut regs = target.read_regs();
                regs[UREG_RIP] = addr;
                target.write_regs(&regs);
            }
            target.ctl("step");
            String::new() // no reply until next stop
        },

        b'k' => {
            session.detach(target);
            crate::proc::signal::send_signal(target.pid, 9);
            rsp_packet("OK")
        },

        // Z0,addr,len  software breakpoint
        // Z1,addr,len  hardware execution breakpoint
        // Z2,addr,len  write watchpoint
        // Z3,addr,len  read watchpoint
        // Z4,addr,len  access (read/write) watchpoint
        b'Z' => {
            let ok = match parse_zpacket(&body[1..]) {
                None => false,
                Some((0, addr, _len)) => session.sw_bps.add(target, addr),
                Some((1, addr, _len)) => session.hw_bps.add_exec(target, addr),
                Some((2, addr, len)) => session.watches.add(target, addr, len, WatchKind::Write),
                Some((3, addr, len)) => session.watches.add(target, addr, len, WatchKind::Read),
                Some((4, addr, len)) => session.watches.add(target, addr, len, WatchKind::Access),
                Some(_) => false,
            };
            if ok {
                rsp_packet("OK")
            } else {
                rsp_packet("E01")
            }
        },

        b'z' => {
            let ok = match parse_zpacket(&body[1..]) {
                None => false,
                Some((0, addr, _)) => session.sw_bps.remove(target, addr),
                Some((1, addr, _)) => session.hw_bps.remove(target, addr),
                Some((2, addr, _)) | Some((3, addr, _)) | Some((4, addr, _)) => {
                    session.watches.remove(target, addr)
                },
                Some(_) => false,
            };
            if ok {
                rsp_packet("OK")
            } else {
                rsp_packet("E01")
            }
        },

        b'q' => {
            if body.starts_with("qSupported") {
                // Advertise Z/z support alongside PacketSize
                rsp_packet("PacketSize=4000;swbreak+;hwbreak+")
            } else if body.starts_with("qAttached") {
                rsp_packet("1")
            } else if body.starts_with("qC") {
                let pid = target.pid;
                rsp_packet(&alloc::format!("QC{:x}", pid))
            } else {
                rsp_packet("") // unsupported query
            }
        },

        _ => rsp_packet(""), // unsupported
    }
}
