//! GDB Remote Serial Protocol — RISC-V 64-bit packet handler.
//!
//! Register serialisation is now delegated to `arch::RiscV64: GdbArch`.
//! Packet framing, memory access, breakpoints, and the `qSupported` response
//! are handled here; hex helpers come from `arch.rs`.

extern crate alloc;
use alloc::string::String;

use super::arch::{decode_hex_bytes, encode_hex_bytes, parse_hex_u64, GdbArch, RiscV64};
use super::breakpoints::{HwBreakpointTable, SwBreakpointTable, WatchKind, WatchpointTable};
use super::target::GdbTarget;

// 32 GPRs + pc
pub const RISCV_REG_COUNT: usize = 33;

fn rsp_packet(body: &str) -> String {
    let csum: u8 = body.bytes().fold(0u8, |a, b| a.wrapping_add(b));
    alloc::format!("+${}#{:02x}", body, csum)
}

// ---------------------------------------------------------------------------
// Session state
// ---------------------------------------------------------------------------

pub struct RiscVSession {
    pub sw_bps:  SwBreakpointTable,
    pub hw_bps:  HwBreakpointTable,
    pub watches: WatchpointTable,
}

impl RiscVSession {
    pub fn new() -> Self {
        RiscVSession {
            sw_bps:  SwBreakpointTable::new(),
            hw_bps:  HwBreakpointTable::new(),
            watches: WatchpointTable::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// Packet dispatch
// ---------------------------------------------------------------------------

pub fn handle_packet(body: &str, target: &mut GdbTarget, session: &mut RiscVSession) -> String {
    if body.is_empty() {
        return rsp_packet("");
    }
    match body.as_bytes()[0] {
        b'?' => {
            let status = target.poll_status();
            rsp_packet(if status.starts_with('T') { &status } else { "T05" })
        },

        b'g' => {
            let trap = target.trap_frame();
            let mut buf = alloc::vec![0u8; RiscV64::reg_buf_len()];
            RiscV64::read_regs(trap, &mut buf);
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
            let eq  = rest.find('=').unwrap_or(rest.len());
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
            let rest = &body[1..];
            let mut parts = rest.splitn(2, ',');
            let addr = parse_hex_u64(parts.next().unwrap_or(""));
            let len  = parse_hex_u64(parts.next().unwrap_or("")) as usize;
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

        // RISC-V single-step: set dcsr.step via a debug-mode CSR write.
        // For now we delegate to the sw-breakpoint approach in the target.
        b'c' => { target.ctl("cont");  String::new() },
        b's' => { target.ctl("step");  String::new() },

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

fn handle_z_packet(body: &str, target: &mut GdbTarget, session: &mut RiscVSession) -> String {
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
