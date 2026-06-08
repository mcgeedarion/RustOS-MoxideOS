//! GDB Remote Serial Protocol — x86-64 packet handler.
//!
//! Register serialisation is now entirely delegated to
//! `arch::X86_64: GdbArch` (see `arch.rs`). This file retains:
//!
//! - The `GDB_TO_UREG` mapping and `build_gdb_regs` / `unpack_gdb_regs`
//!   helpers used by `ptrace` (they work on `user_regs_struct`, not
//!   `TrapFrame`, so they live here, not in the trait).
//! - `step_set_tf` / `step_clear_tf` (x86-specific TF manipulation).
//! - `X86Session` + `handle_packet` packet dispatch loop.
//! - All `Z`/`z` breakpoint / watchpoint handling.
//!
//! `g`/`G`/`p`/`P` packets now call `arch::X86_64::read_regs` /
//! `arch::X86_64::write_regs` through the `GdbArch` trait, eliminating the
//! local hex helpers that have been moved to `arch.rs`.

extern crate alloc;
use alloc::string::String;

use super::arch::{encode_hex_bytes, decode_hex_bytes, parse_hex_u64, GdbArch, X86_64};
use super::breakpoints::{HwBreakpointTable, SwBreakpointTable, WatchKind, WatchpointTable};
use super::target::GdbTarget;
use crate::proc::ptrace::UREG_COUNT;

// ---------------------------------------------------------------------------
// GDB register index → user_regs_struct index mapping (ptrace path)
// ---------------------------------------------------------------------------

pub const X86_REG_COUNT: usize = 24;

const GDB_TO_UREG: [usize; X86_REG_COUNT] = [
    10, 5, 11, 12, 13, 14, 4, 19,  // rax rbx rcx rdx rsi rdi rbp rsp
     9,  8,  7,  6,  3,  2,  1,  0, // r8-r15
    16, 18, 17, 20, 23, 24, 25, 26, // rip eflags cs ss ds es fs gs
];

pub fn build_gdb_regs(ureg: &[u64; UREG_COUNT]) -> [u64; X86_REG_COUNT] {
    let mut out = [0u64; X86_REG_COUNT];
    for (gdb_idx, &ureg_idx) in GDB_TO_UREG.iter().enumerate() {
        if ureg_idx < UREG_COUNT {
            out[gdb_idx] = ureg[ureg_idx];
        }
    }
    out
}

pub fn unpack_gdb_regs(gdb_regs: &[u64; X86_REG_COUNT], ureg: &mut [u64; UREG_COUNT]) {
    for (gdb_idx, &ureg_idx) in GDB_TO_UREG.iter().enumerate() {
        if ureg_idx < UREG_COUNT {
            ureg[ureg_idx] = gdb_regs[gdb_idx];
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn u64_le_hex(v: u64) -> String {
    encode_hex_bytes(&v.to_le_bytes())
}

fn rsp_packet(body: &str) -> String {
    let csum: u8 = body.bytes().fold(0u8, |a, b| a.wrapping_add(b));
    alloc::format!("+${}#{:02x}", body, csum)
}

// ---------------------------------------------------------------------------
// Single-step: RFLAGS.TF
// ---------------------------------------------------------------------------

const RFLAGS_TF: u64 = 1 << 8;

/// Set RFLAGS.TF so the CPU single-steps the next instruction.
pub fn step_set_tf(target: &mut GdbTarget) {
    let mut regs = target.read_regs();
    regs[18] |= RFLAGS_TF; // ureg[18] = eflags
    target.write_regs(&regs);
}

/// Clear RFLAGS.TF (call from the #DB / SIGTRAP handler).
pub fn step_clear_tf(target: &mut GdbTarget) {
    let mut regs = target.read_regs();
    regs[18] &= !RFLAGS_TF;
    target.write_regs(&regs);
}

// ---------------------------------------------------------------------------
// Session state
// ---------------------------------------------------------------------------

pub struct X86Session {
    pub sw_bps:  SwBreakpointTable,
    pub hw_bps:  HwBreakpointTable,
    pub watches: WatchpointTable,
}

impl X86Session {
    pub fn new() -> Self {
        X86Session {
            sw_bps:  SwBreakpointTable::new(),
            hw_bps:  HwBreakpointTable::new(),
            watches: WatchpointTable::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// Packet dispatch
// ---------------------------------------------------------------------------

pub fn handle_packet(body: &str, target: &mut GdbTarget, session: &mut X86Session) -> String {
    if body.is_empty() {
        return rsp_packet("");
    }
    match body.as_bytes()[0] {
        b'?' => {
            let status = target.poll_status();
            rsp_packet(if status.starts_with('T') { &status } else { "T05" })
        },

        // Read all registers via GdbArch trait
        b'g' => {
            let trap = target.trap_frame();
            let mut buf = alloc::vec![0u8; X86_64::reg_buf_len()];
            X86_64::read_regs(trap, &mut buf);
            rsp_packet(&encode_hex_bytes(&buf))
        },

        // Write all registers via GdbArch trait
        b'G' => {
            let buf = decode_hex_bytes(&body[1..]);
            if buf.len() < X86_64::reg_buf_len() {
                return rsp_packet("E01");
            }
            let trap = target.trap_frame_mut();
            X86_64::write_regs(trap, &buf);
            rsp_packet("OK")
        },

        // Read single register 'p<regnum>'
        b'p' => {
            let idx = parse_hex_u64(&body[1..]) as usize;
            if idx >= X86_REG_COUNT {
                return rsp_packet("E01");
            }
            let trap = target.trap_frame();
            let mut buf = alloc::vec![0u8; X86_64::reg_buf_len()];
            X86_64::read_regs(trap, &mut buf);
            rsp_packet(&encode_hex_bytes(&buf[idx * 8..(idx + 1) * 8]))
        },

        // Write single register 'P<regnum>=<val>'
        b'P' => {
            let rest = &body[1..];
            let eq = rest.find('=').unwrap_or(rest.len());
            let idx = parse_hex_u64(&rest[..eq]) as usize;
            if idx >= X86_REG_COUNT {
                return rsp_packet("E01");
            }
            let val = parse_hex_u64(&rest[eq + 1..]);
            let trap = target.trap_frame_mut();
            let mut buf = alloc::vec![0u8; X86_64::reg_buf_len()];
            X86_64::read_regs(trap, &mut buf); // read-modify-write
            buf[idx * 8..(idx + 1) * 8].copy_from_slice(&val.to_le_bytes());
            X86_64::write_regs(trap, &buf);
            rsp_packet("OK")
        },

        b'm' => {
            let rest = &body[1..];
            let mut parts = rest.splitn(2, ',');
            let addr = parse_hex_u64(parts.next().unwrap_or(""));
            let len  = parse_hex_u64(parts.next().unwrap_or("")) as usize;
            rsp_packet(&encode_hex_bytes(&target.read_mem(addr, len)))
        },

        b'M' => {
            let rest = &body[1..];
            let colon = rest.find(':').unwrap_or(rest.len());
            let addr  = parse_hex_u64(&rest[..rest.find(',').unwrap_or(colon)]);
            let data  = if colon < rest.len() { decode_hex_bytes(&rest[colon + 1..]) } else { alloc::vec![] };
            target.write_mem(addr, &data);
            rsp_packet("OK")
        },

        b'c' => { target.ctl("cont"); String::new() },
        b's' => { step_set_tf(target); target.ctl("cont"); String::new() },

        b'Z' | b'z' => handle_z_packet(body, target, session),

        b'k' => { crate::proc::signal::send_signal(target.pid, 9); rsp_packet("OK") },

        b'q' => {
            if body.starts_with("qSupported") {
                rsp_packet("PacketSize=4000;swbreak+;hwbreak+;watchpoint+;vContSupported+")
            } else if body.starts_with("qAttached") {
                rsp_packet("1")
            } else {
                rsp_packet("")
            }
        },

        _ => rsp_packet(""),
    }
}

// ---------------------------------------------------------------------------
// Z/z breakpoint / watchpoint handler
// ---------------------------------------------------------------------------

fn handle_z_packet(body: &str, target: &mut GdbTarget, session: &mut X86Session) -> String {
    let insert = body.as_bytes()[0] == b'Z';
    let rest = &body[1..];
    let mut parts = rest.splitn(3, ',');
    let kind  = parts.next().unwrap_or("");
    let addr  = parse_hex_u64(parts.next().unwrap_or(""));
    let _size = parse_hex_u64(parts.next().unwrap_or("")) as usize;

    macro_rules! bp {
        ($op:expr) => { if $op { rsp_packet("OK") } else { rsp_packet("E01") } };
    }

    match kind {
        "0" => bp!(if insert { session.sw_bps.add(target, addr)       } else { session.sw_bps.remove(target, addr) }),
        "1" => bp!(if insert { session.hw_bps.add_exec(target, addr)  } else { session.hw_bps.remove(target, addr) }),
        "2" => bp!(if insert { session.watches.add(target, addr, _size, WatchKind::Write)  } else { session.watches.remove(target, addr) }),
        "3" => bp!(if insert { session.watches.add(target, addr, _size, WatchKind::Read)   } else { session.watches.remove(target, addr) }),
        "4" => bp!(if insert { session.watches.add(target, addr, _size, WatchKind::Access) } else { session.watches.remove(target, addr) }),
        _   => rsp_packet(""),
    }
}
