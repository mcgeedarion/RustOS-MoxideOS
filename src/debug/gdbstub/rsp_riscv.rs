//! GDB Remote Serial Protocol — RISC-V 64-bit packet handler.
//!
//! Register serialisation delegated to `arch::RiscV64: GdbArch`.
//! Z/z dispatch delegated to `breakpoints::handle_z_packet` via `ZSession`.

extern crate alloc;
use alloc::string::String;

use super::arch::{decode_hex_bytes, encode_hex_bytes, parse_hex_u64, GdbArch, RiscV64};
use super::breakpoints::{
    handle_z_packet, HwBreakpointTable, SwBreakpointTable, WatchpointTable, ZSession,
};
use super::target::GdbTarget;

pub const RISCV_REG_COUNT: usize = 33;

fn rsp_packet(body: &str) -> String {
    let csum: u8 = body.bytes().fold(0u8, |a, b| a.wrapping_add(b));
    alloc::format!("+${}#{:02x}", body, csum)
}

pub struct RiscVSession {
    pub sw_bps: SwBreakpointTable,
    pub hw_bps: HwBreakpointTable,
    pub watches: WatchpointTable,
}

impl RiscVSession {
    pub fn new() -> Self {
        RiscVSession {
            sw_bps: SwBreakpointTable::new(),
            hw_bps: HwBreakpointTable::new(),
            watches: WatchpointTable::new(),
        }
    }
}

impl ZSession for RiscVSession {
    fn sw_bps(&mut self) -> &mut SwBreakpointTable {
        &mut self.sw_bps
    }
    fn hw_bps(&mut self) -> &mut HwBreakpointTable {
        &mut self.hw_bps
    }
    fn watches(&mut self) -> &mut WatchpointTable {
        &mut self.watches
    }
}

pub fn handle_packet(body: &str, target: &mut GdbTarget, session: &mut RiscVSession) -> String {
    if body.is_empty() {
        return rsp_packet("");
    }
    match body.as_bytes()[0] {
        b'?' => {
            let s = target.poll_status();
            rsp_packet(if s.starts_with('T') { &s } else { "T05" })
        },
        b'g' => {
            let mut buf = alloc::vec![0u8; RiscV64::reg_buf_len()];
            RiscV64::read_regs(target.trap_frame(), &mut buf);
            rsp_packet(&encode_hex_bytes(&buf))
        },
        b'G' => {
            let buf = decode_hex_bytes(&body[1..]);
            if buf.len() < RiscV64::reg_buf_len() {
                return rsp_packet("E01");
            }
            RiscV64::write_regs(target.trap_frame_mut(), &buf);
            rsp_packet("OK")
        },
        b'p' => {
            let idx = parse_hex_u64(&body[1..]) as usize;
            if idx >= RISCV_REG_COUNT {
                return rsp_packet("E01");
            }
            let mut buf = alloc::vec![0u8; RiscV64::reg_buf_len()];
            RiscV64::read_regs(target.trap_frame(), &mut buf);
            rsp_packet(&encode_hex_bytes(&buf[idx * 8..(idx + 1) * 8]))
        },
        b'P' => {
            let rest = &body[1..];
            let eq = rest.find('=').unwrap_or(rest.len());
            let idx = parse_hex_u64(&rest[..eq]) as usize;
            if idx >= RISCV_REG_COUNT {
                return rsp_packet("E01");
            }
            let val = parse_hex_u64(&rest[eq + 1..]);
            let trap = target.trap_frame_mut();
            let mut buf = alloc::vec![0u8; RiscV64::reg_buf_len()];
            RiscV64::read_regs(trap, &mut buf);
            buf[idx * 8..(idx + 1) * 8].copy_from_slice(&val.to_le_bytes());
            RiscV64::write_regs(trap, &buf);
            rsp_packet("OK")
        },
        b'm' => {
            let mut p = body[1..].splitn(2, ',');
            let addr = parse_hex_u64(p.next().unwrap_or(""));
            let len = parse_hex_u64(p.next().unwrap_or("")) as usize;
            rsp_packet(&encode_hex_bytes(&target.read_mem(addr, len)))
        },
        b'M' => {
            let rest = &body[1..];
            let colon = rest.find(':').unwrap_or(rest.len());
            let addr = parse_hex_u64(&rest[..rest.find(',').unwrap_or(colon)]);
            let data = if colon < rest.len() {
                decode_hex_bytes(&rest[colon + 1..])
            } else {
                alloc::vec![]
            };
            target.write_mem(addr, &data);
            rsp_packet("OK")
        },
        b'c' => {
            target.ctl("cont");
            String::new()
        },
        b's' => {
            target.ctl("step");
            String::new()
        },
        b'Z' | b'z' => handle_z_packet(body, target, session),
        b'k' => {
            crate::proc::signal::send_signal(target.pid, 9);
            rsp_packet("OK")
        },
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
