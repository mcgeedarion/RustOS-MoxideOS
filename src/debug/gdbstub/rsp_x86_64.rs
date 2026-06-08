//! GDB Remote Serial Protocol — x86-64 packet handler.
//!
//! Register serialisation is delegated to `arch::X86_64: GdbArch`.
//! Z/z breakpoint dispatch is delegated to `breakpoints::handle_z_packet`
//! via the `ZSession` trait impl on `X86Session`.
//!
//! This file retains:
//! - `GDB_TO_UREG` / `build_gdb_regs` / `unpack_gdb_regs` (ptrace path;
//!   maps `user_regs_struct` indices — not `TrapFrame` — so out of scope for
//!   `GdbArch`).
//! - `step_set_tf` / `step_clear_tf` (x86-specific RFLAGS.TF manipulation).
//! - `X86Session` + `handle_packet` packet dispatch.

extern crate alloc;
use alloc::string::String;

use super::arch::{encode_hex_bytes, decode_hex_bytes, parse_hex_u64, GdbArch, X86_64};
use super::breakpoints::{
    handle_z_packet, HwBreakpointTable, SwBreakpointTable, WatchpointTable, ZSession,
};
use super::target::GdbTarget;
use crate::proc::ptrace::UREG_COUNT;

// ---------------------------------------------------------------------------
// GDB register index → user_regs_struct index (ptrace path only)
// ---------------------------------------------------------------------------

pub const X86_REG_COUNT: usize = 24;

const GDB_TO_UREG: [usize; X86_REG_COUNT] = [
    10, 5, 11, 12, 13, 14, 4, 19,
     9,  8,  7,  6,  3,  2,  1,  0,
    16, 18, 17, 20, 23, 24, 25, 26,
];

pub fn build_gdb_regs(ureg: &[u64; UREG_COUNT]) -> [u64; X86_REG_COUNT] {
    let mut out = [0u64; X86_REG_COUNT];
    for (i, &ui) in GDB_TO_UREG.iter().enumerate() {
        if ui < UREG_COUNT { out[i] = ureg[ui]; }
    }
    out
}

pub fn unpack_gdb_regs(gdb: &[u64; X86_REG_COUNT], ureg: &mut [u64; UREG_COUNT]) {
    for (i, &ui) in GDB_TO_UREG.iter().enumerate() {
        if ui < UREG_COUNT { ureg[ui] = gdb[i]; }
    }
}

// ---------------------------------------------------------------------------
// Single-step via RFLAGS.TF
// ---------------------------------------------------------------------------

const RFLAGS_TF: u64 = 1 << 8;

pub fn step_set_tf(target: &mut GdbTarget) {
    let mut regs = target.read_regs();
    regs[18] |= RFLAGS_TF;
    target.write_regs(&regs);
}

pub fn step_clear_tf(target: &mut GdbTarget) {
    let mut regs = target.read_regs();
    regs[18] &= !RFLAGS_TF;
    target.write_regs(&regs);
}

fn rsp_packet(body: &str) -> String {
    let csum: u8 = body.bytes().fold(0u8, |a, b| a.wrapping_add(b));
    alloc::format!("+${}#{:02x}", body, csum)
}

// ---------------------------------------------------------------------------
// Session
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

impl ZSession for X86Session {
    fn sw_bps(&mut self)  -> &mut SwBreakpointTable { &mut self.sw_bps  }
    fn hw_bps(&mut self)  -> &mut HwBreakpointTable { &mut self.hw_bps  }
    fn watches(&mut self) -> &mut WatchpointTable   { &mut self.watches }
}

// ---------------------------------------------------------------------------
// Packet dispatch
// ---------------------------------------------------------------------------

pub fn handle_packet(body: &str, target: &mut GdbTarget, session: &mut X86Session) -> String {
    if body.is_empty() { return rsp_packet(""); }
    match body.as_bytes()[0] {
        b'?' => {
            let s = target.poll_status();
            rsp_packet(if s.starts_with('T') { &s } else { "T05" })
        },
        b'g' => {
            let mut buf = alloc::vec![0u8; X86_64::reg_buf_len()];
            X86_64::read_regs(target.trap_frame(), &mut buf);
            rsp_packet(&encode_hex_bytes(&buf))
        },
        b'G' => {
            let buf = decode_hex_bytes(&body[1..]);
            if buf.len() < X86_64::reg_buf_len() { return rsp_packet("E01"); }
            X86_64::write_regs(target.trap_frame_mut(), &buf);
            rsp_packet("OK")
        },
        b'p' => {
            let idx = parse_hex_u64(&body[1..]) as usize;
            if idx >= X86_REG_COUNT { return rsp_packet("E01"); }
            let mut buf = alloc::vec![0u8; X86_64::reg_buf_len()];
            X86_64::read_regs(target.trap_frame(), &mut buf);
            rsp_packet(&encode_hex_bytes(&buf[idx * 8..(idx + 1) * 8]))
        },
        b'P' => {
            let rest = &body[1..];
            let eq  = rest.find('=').unwrap_or(rest.len());
            let idx = parse_hex_u64(&rest[..eq]) as usize;
            if idx >= X86_REG_COUNT { return rsp_packet("E01"); }
            let val  = parse_hex_u64(&rest[eq + 1..]);
            let trap = target.trap_frame_mut();
            let mut buf = alloc::vec![0u8; X86_64::reg_buf_len()];
            X86_64::read_regs(trap, &mut buf);
            buf[idx * 8..(idx + 1) * 8].copy_from_slice(&val.to_le_bytes());
            X86_64::write_regs(trap, &buf);
            rsp_packet("OK")
        },
        b'm' => {
            let rest = &body[1..];
            let mut p = rest.splitn(2, ',');
            let addr = parse_hex_u64(p.next().unwrap_or(""));
            let len  = parse_hex_u64(p.next().unwrap_or("")) as usize;
            rsp_packet(&encode_hex_bytes(&target.read_mem(addr, len)))
        },
        b'M' => {
            let rest  = &body[1..];
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
