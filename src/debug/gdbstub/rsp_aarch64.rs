//! GDB Remote Serial Protocol — AArch64 packet handler.
//!
//! Same structure as rsp_riscv.rs / rsp_x86_64.rs but uses AArch64 register
//! naming.
//!
//! GDB AArch64 target: 34 registers × 8 bytes each (little-endian):
//!   Index  0–30   x0–x30 (general-purpose)
//!   Index  31     sp
//!   Index  32     pc
//!   Index  33     cpsr  (GDB uses 8-byte slot; upper 4 bytes are zero)
//!
//! Single-step is implemented by injecting a `BRK #0` (0xd4200000) at the
//! current PC, executing it, then restoring the original word — the same
//! pattern used by the RISC-V handler with `ebreak`.
//!
//! Breakpoints and watchpoints use the `SwBreakpointTable`,
//! `HwBreakpointTable`, and `WatchpointTable` helpers from `breakpoints.rs`,
//! mirroring the x86-64 handler.

extern crate alloc;
use alloc::string::String;
use alloc::vec::Vec;

use super::breakpoints::{HwBreakpointTable, SwBreakpointTable, WatchKind, WatchpointTable};
use super::target::GdbTarget;

// GDB AArch64 register count: x0-x30, sp, pc, cpsr = 34
pub const AARCH64_REG_COUNT: usize = 34;

// Our trap-frame flat layout (u64 each):
//   [0..30]  x0–x30
//   [31]     sp
//   [32]     pc
//   [33]     spsr  (maps to GDB's cpsr slot)
pub const AARCH64_FRAME_SIZE: usize = 34;

fn build_gdb_regs(frame: &[u64; AARCH64_FRAME_SIZE]) -> [u64; AARCH64_REG_COUNT] {
    // Frame layout already matches GDB order 1:1.
    *frame
}

fn unpack_gdb_regs(gdb_regs: &[u64; AARCH64_REG_COUNT]) -> [u64; AARCH64_FRAME_SIZE] {
    *gdb_regs
}

// ---------------------------------------------------------------------------
// Helpers shared across all arch handlers
// ---------------------------------------------------------------------------

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
        s.push(char::from_digit((b >> 4) as u32, 16).unwrap_or('0'));
        s.push(char::from_digit((b & 0xf) as u32, 16).unwrap_or('0'));
    }
    s
}

fn u64_le_hex(v: u64) -> String {
    encode_hex_bytes(&v.to_le_bytes())
}

fn parse_hex_u64(s: &str) -> u64 {
    u64::from_str_radix(s, 16).unwrap_or(0)
}

fn rsp_packet(body: &str) -> String {
    let csum: u8 = body.bytes().fold(0u8, |acc, b| acc.wrapping_add(b));
    alloc::format!("+${}#{:02x}", body, csum)
}

// ---------------------------------------------------------------------------
// Register I/O
// ---------------------------------------------------------------------------

fn read_raw_regs(target: &GdbTarget) -> [u64; AARCH64_FRAME_SIZE] {
    use crate::fs::proc_debug::{is_proc_debug_fd, proc_debug_read};
    let bfd = crate::fs::process_fd::proc_fd_backing(
        crate::proc::scheduler::current_pid(),
        target.regs_fd,
    );
    let mut frame = [0u64; AARCH64_FRAME_SIZE];
    if bfd < 0 {
        return frame;
    }
    let bfd = bfd as usize;
    if !is_proc_debug_fd(bfd) {
        return frame;
    }
    let mut buf = [0u8; AARCH64_FRAME_SIZE * 8];
    proc_debug_read(bfd, &mut buf, 0);
    for i in 0..AARCH64_FRAME_SIZE {
        frame[i] = u64::from_le_bytes(buf[i * 8..(i + 1) * 8].try_into().unwrap());
    }
    frame
}

fn write_raw_regs(target: &GdbTarget, frame: &[u64; AARCH64_FRAME_SIZE]) {
    use crate::fs::proc_debug::{is_proc_debug_fd, proc_debug_write};
    let bfd = crate::fs::process_fd::proc_fd_backing(
        crate::proc::scheduler::current_pid(),
        target.regs_fd,
    );
    if bfd < 0 {
        return;
    }
    let bfd = bfd as usize;
    if !is_proc_debug_fd(bfd) {
        return;
    }
    let mut buf = [0u8; AARCH64_FRAME_SIZE * 8];
    for i in 0..AARCH64_FRAME_SIZE {
        buf[i * 8..(i + 1) * 8].copy_from_slice(&frame[i].to_le_bytes());
    }
    proc_debug_write(bfd, &buf, 0);
}

// ---------------------------------------------------------------------------
// Single-step via BRK #0 injection
// ---------------------------------------------------------------------------

/// State saved when a `BRK #0` is injected for single-step.
pub struct BrkState {
    pub addr: u64,
    pub original: [u8; 4],
}

/// Inject `BRK #0` (0xd4200000, LE: 00 00 20 d4) at the current PC.
pub fn step_inject_brk(target: &mut GdbTarget) -> Option<BrkState> {
    let raw = read_raw_regs(target);
    let pc = raw[32]; // frame[32] = pc
    let original_bytes = target.read_mem(pc, 4);
    if original_bytes.len() < 4 {
        return None;
    }
    let original: [u8; 4] = original_bytes[..4].try_into().ok()?;
    // BRK #0 = 0xd4200000 little-endian
    target.write_mem(pc, &[0x00, 0x00, 0x20, 0xd4]);
    Some(BrkState { addr: pc, original })
}

/// Restore the original instruction after single-step.
pub fn step_restore_brk(target: &mut GdbTarget, state: &BrkState) {
    target.write_mem(state.addr, &state.original);
}

// ---------------------------------------------------------------------------
// Session state
// ---------------------------------------------------------------------------

pub struct Aarch64Session {
    pub sw_bps: SwBreakpointTable,
    pub hw_bps: HwBreakpointTable,
    pub watches: WatchpointTable,
}

impl Aarch64Session {
    pub fn new() -> Self {
        Aarch64Session {
            sw_bps: SwBreakpointTable::new(),
            hw_bps: HwBreakpointTable::new(),
            watches: WatchpointTable::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// Z/z packet handler
// ---------------------------------------------------------------------------

// GDB breakpoint kinds:
//   Z0 / z0  software breakpoint
//   Z1 / z1  hardware execution breakpoint
//   Z2 / z2  write watchpoint
//   Z3 / z3  read watchpoint
//   Z4 / z4  access (read/write) watchpoint

fn handle_z_packet(body: &str, target: &mut GdbTarget, session: &mut Aarch64Session) -> String {
    let insert = body.as_bytes()[0] == b'Z';
    let rest = &body[1..];
    let mut parts = rest.splitn(3, ',');
    let kind = parts.next().unwrap_or("");
    let addr = parse_hex_u64(parts.next().unwrap_or(""));
    let _size = parse_hex_u64(parts.next().unwrap_or("")) as usize;

    match kind {
        "0" => {
            if insert {
                if session.sw_bps.add(target, addr) {
                    rsp_packet("OK")
                } else {
                    rsp_packet("E01")
                }
            } else {
                if session.sw_bps.remove(target, addr) {
                    rsp_packet("OK")
                } else {
                    rsp_packet("E01")
                }
            }
        },
        "1" => {
            if insert {
                if session.hw_bps.add_exec(target, addr) {
                    rsp_packet("OK")
                } else {
                    rsp_packet("E01")
                }
            } else {
                if session.hw_bps.remove(target, addr) {
                    rsp_packet("OK")
                } else {
                    rsp_packet("E01")
                }
            }
        },
        "2" => {
            if insert {
                if session.watches.add(target, addr, _size, WatchKind::Write) {
                    rsp_packet("OK")
                } else {
                    rsp_packet("E01")
                }
            } else {
                if session.watches.remove(target, addr) {
                    rsp_packet("OK")
                } else {
                    rsp_packet("E01")
                }
            }
        },
        "3" => {
            if insert {
                if session.watches.add(target, addr, _size, WatchKind::Read) {
                    rsp_packet("OK")
                } else {
                    rsp_packet("E01")
                }
            } else {
                if session.watches.remove(target, addr) {
                    rsp_packet("OK")
                } else {
                    rsp_packet("E01")
                }
            }
        },
        "4" => {
            if insert {
                if session.watches.add(target, addr, _size, WatchKind::Access) {
                    rsp_packet("OK")
                } else {
                    rsp_packet("E01")
                }
            } else {
                if session.watches.remove(target, addr) {
                    rsp_packet("OK")
                } else {
                    rsp_packet("E01")
                }
            }
        },
        _ => rsp_packet(""),
    }
}

// ---------------------------------------------------------------------------
// Main packet dispatcher
// ---------------------------------------------------------------------------

pub fn handle_packet(body: &str, target: &mut GdbTarget, session: &mut Aarch64Session) -> String {
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
        // Read all registers
        b'g' => {
            let raw = read_raw_regs(target);
            let regs = build_gdb_regs(&raw);
            let mut hex = String::with_capacity(AARCH64_REG_COUNT * 16);
            for &v in &regs {
                hex.push_str(&u64_le_hex(v));
            }
            rsp_packet(&hex)
        },
        // Write all registers
        b'G' => {
            let bytes = decode_hex_bytes(&body[1..]);
            let mut gdb_regs = [0u64; AARCH64_REG_COUNT];
            for i in 0..AARCH64_REG_COUNT {
                let off = i * 8;
                if off + 8 > bytes.len() {
                    break;
                }
                gdb_regs[i] = u64::from_le_bytes(bytes[off..off + 8].try_into().unwrap());
            }
            let frame = unpack_gdb_regs(&gdb_regs);
            write_raw_regs(target, &frame);
            rsp_packet("OK")
        },
        // Read single register  'p<regnum>'
        b'p' => {
            let idx = parse_hex_u64(&body[1..]) as usize;
            if idx >= AARCH64_REG_COUNT {
                return rsp_packet("E01");
            }
            let raw = read_raw_regs(target);
            let regs = build_gdb_regs(&raw);
            rsp_packet(&u64_le_hex(regs[idx]))
        },
        // Write single register  'P<regnum>=<val>'
        b'P' => {
            let rest = &body[1..];
            let eq = rest.find('=').unwrap_or(rest.len());
            let idx = parse_hex_u64(&rest[..eq]) as usize;
            let val = parse_hex_u64(&rest[eq + 1..]);
            if idx >= AARCH64_REG_COUNT {
                return rsp_packet("E01");
            }
            let mut frame = read_raw_regs(target);
            frame[idx] = val;
            write_raw_regs(target, &frame);
            rsp_packet("OK")
        },
        // Read memory  'm<addr>,<len>'
        b'm' => {
            let rest = &body[1..];
            let mut parts = rest.splitn(2, ',');
            let addr = parse_hex_u64(parts.next().unwrap_or(""));
            let len = parse_hex_u64(parts.next().unwrap_or("")) as usize;
            let data = target.read_mem(addr, len);
            rsp_packet(&encode_hex_bytes(&data))
        },
        // Write memory  'M<addr>,<len>:<hex>'
        b'M' => {
            let rest = &body[1..];
            let colon = rest.find(':').unwrap_or(rest.len());
            let addr = parse_hex_u64(&rest[..rest.find(',').unwrap_or(colon)]);
            let hex_data = if colon < rest.len() {
                &rest[colon + 1..]
            } else {
                ""
            };
            target.write_mem(addr, &decode_hex_bytes(hex_data));
            rsp_packet("OK")
        },
        // Continue
        b'c' => {
            target.ctl("cont");
            String::new()
        },
        // Single-step: inject BRK #0 then continue
        b's' => {
            let _ = step_inject_brk(target);
            target.ctl("cont");
            String::new()
        },
        // Breakpoints / watchpoints
        b'Z' | b'z' => handle_z_packet(body, target, session),
        b'k' => {
            crate::proc::signal::send_signal(target.pid, 9);
            rsp_packet("OK")
        },
        b'q' => {
            if body.starts_with("qSupported") {
                rsp_packet("PacketSize=4000;swbreak+;hwbreak+;watchpoint+")
            } else if body.starts_with("qAttached") {
                rsp_packet("1")
            } else {
                rsp_packet("")
            }
        },
        _ => rsp_packet(""),
    }
}
