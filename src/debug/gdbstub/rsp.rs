//! GDB Remote Serial Protocol — primary packet handler.
//!
//! This is the architecture-neutral RSP dispatcher used by `session.rs`.
//! Register serialisation (`g`/`G`/`p`/`P`) is delegated to the
//! `GdbArch` trait so this file contains no per-arch hex offsets.
//!
//! Hex helpers (`encode_hex_bytes`, `decode_hex_bytes`, `parse_hex_u64`) are
//! exported from `arch.rs` and re-used here — there are no local copies.

extern crate alloc;
use alloc::string::String;
use alloc::vec::Vec;

use super::arch::{decode_hex_bytes, encode_hex_bytes, parse_hex_u64};
use super::breakpoints::{
    handle_z_packet, HwBreakpointTable, SwBreakpointTable, WatchpointTable, ZSession,
};
use super::target::GdbTarget;

/// Wrap a response body in RSP `+$<body>#<checksum>`.
pub fn rsp_packet(body: &str) -> String {
    let csum: u8 = body.bytes().fold(0u8, |a, b| a.wrapping_add(b));
    alloc::format!("+${}#{:02x}", body, csum)
}

// ---------------------------------------------------------------------------
// Register count per arch (for bounds-checking p/P)
// ---------------------------------------------------------------------------

#[cfg(target_arch = "x86_64")]
const ARCH_REG_COUNT: usize = 24;
#[cfg(target_arch = "riscv64")]
const ARCH_REG_COUNT: usize = 33; // 32 GPR + pc
#[cfg(target_arch = "aarch64")]
const ARCH_REG_COUNT: usize = 34; // x0-x30 + sp + pc + pstate
#[cfg(not(any(
    target_arch = "x86_64",
    target_arch = "riscv64",
    target_arch = "aarch64"
)))]
const ARCH_REG_COUNT: usize = 32;

// ---------------------------------------------------------------------------
// Arch dispatch helpers — call the right GdbArch impl at compile time
// ---------------------------------------------------------------------------

fn arch_reg_buf_len() -> usize {
    #[cfg(target_arch = "x86_64")]
    {
        crate::debug::gdbstub::arch::X86_64::reg_buf_len()
    }
    #[cfg(target_arch = "riscv64")]
    {
        crate::debug::gdbstub::arch::RiscV64::reg_buf_len()
    }
    #[cfg(target_arch = "aarch64")]
    {
        crate::debug::gdbstub::arch::AArch64::reg_buf_len()
    }
    #[cfg(not(any(
        target_arch = "x86_64",
        target_arch = "riscv64",
        target_arch = "aarch64"
    )))]
    {
        ARCH_REG_COUNT * 8
    }
}

fn arch_read_regs(trap: &crate::debug::AnyTrapFrame, buf: &mut [u8]) {
    #[cfg(target_arch = "x86_64")]
    {
        crate::debug::gdbstub::arch::X86_64::read_regs(trap, buf);
    }
    #[cfg(target_arch = "riscv64")]
    {
        crate::debug::gdbstub::arch::RiscV64::read_regs(trap, buf);
    }
    #[cfg(target_arch = "aarch64")]
    {
        crate::debug::gdbstub::arch::AArch64::read_regs(trap, buf);
    }
    #[cfg(not(any(
        target_arch = "x86_64",
        target_arch = "riscv64",
        target_arch = "aarch64"
    )))]
    {
        let _ = (trap, buf);
    }
}

fn arch_write_regs(trap: &mut crate::debug::AnyTrapFrame, buf: &[u8]) {
    #[cfg(target_arch = "x86_64")]
    {
        crate::debug::gdbstub::arch::X86_64::write_regs(trap, buf);
    }
    #[cfg(target_arch = "riscv64")]
    {
        crate::debug::gdbstub::arch::RiscV64::write_regs(trap, buf);
    }
    #[cfg(target_arch = "aarch64")]
    {
        crate::debug::gdbstub::arch::AArch64::write_regs(trap, buf);
    }
    #[cfg(not(any(
        target_arch = "x86_64",
        target_arch = "riscv64",
        target_arch = "aarch64"
    )))]
    {
        let _ = (trap, buf);
    }
}

// ---------------------------------------------------------------------------
// Session
// ---------------------------------------------------------------------------

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

    pub fn detach(&mut self, target: &mut GdbTarget) {
        self.sw_bps.remove_all(target);
        self.hw_bps.remove_all(target);
        self.watches.remove_all(target);
    }
}

impl ZSession for Session {
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

// ---------------------------------------------------------------------------
// Packet dispatch
// ---------------------------------------------------------------------------

pub fn handle_packet(body: &str, target: &mut GdbTarget, session: &mut Session) -> String {
    if body.is_empty() {
        return rsp_packet("");
    }

    match body.as_bytes()[0] {
        b'?' => {
            let status = target.poll_status();
            rsp_packet(if status.starts_with('T') {
                &status
            } else {
                "T05"
            })
        },

        // Read all registers
        b'g' => {
            let trap = target.trap_frame();
            let mut buf = alloc::vec![0u8; arch_reg_buf_len()];
            arch_read_regs(trap, &mut buf);
            rsp_packet(&encode_hex_bytes(&buf))
        },

        // Write all registers
        b'G' => {
            let raw = decode_hex_bytes(&body[1..]);
            if raw.len() < arch_reg_buf_len() {
                return rsp_packet("E01");
            }
            arch_write_regs(target.trap_frame_mut(), &raw);
            rsp_packet("OK")
        },

        // Read single register
        b'p' => {
            let idx = parse_hex_u64(&body[1..]) as usize;
            if idx >= ARCH_REG_COUNT {
                return rsp_packet("E01");
            }
            let mut buf = alloc::vec![0u8; arch_reg_buf_len()];
            arch_read_regs(target.trap_frame(), &mut buf);
            rsp_packet(&encode_hex_bytes(&buf[idx * 8..(idx + 1) * 8]))
        },

        // Write single register
        b'P' => {
            let rest = &body[1..];
            let eq = rest.find('=').unwrap_or(rest.len());
            let idx = parse_hex_u64(&rest[..eq]) as usize;
            if idx >= ARCH_REG_COUNT {
                return rsp_packet("E01");
            }
            let val = parse_hex_u64(&rest[eq + 1..]);
            let trap = target.trap_frame_mut();
            let mut buf = alloc::vec![0u8; arch_reg_buf_len()];
            arch_read_regs(trap, &mut buf);
            buf[idx * 8..(idx + 1) * 8].copy_from_slice(&val.to_le_bytes());
            arch_write_regs(trap, &buf);
            rsp_packet("OK")
        },

        b'm' => {
            let rest = &body[1..];
            let mut parts = rest.splitn(2, ',');
            let addr = parse_hex_u64(parts.next().unwrap_or(""));
            let len = parse_hex_u64(parts.next().unwrap_or("")) as usize;
            rsp_packet(&encode_hex_bytes(&target.read_mem(addr, len)))
        },

        b'M' => {
            let rest = &body[1..];
            let colon = rest.find(':').unwrap_or(rest.len());
            let addr = parse_hex_u64(&rest[..rest.find(',').unwrap_or(colon)]);
            let data = if colon < rest.len() {
                decode_hex_bytes(&rest[colon + 1..])
            } else {
                Vec::new()
            };
            target.write_mem(addr, &data);
            rsp_packet("OK")
        },

        b'c' => {
            let rest = &body[1..];
            if !rest.is_empty() {
                // optional resume address — write into PC
                let addr = parse_hex_u64(rest);
                let trap = target.trap_frame_mut();
                let mut buf = alloc::vec![0u8; arch_reg_buf_len()];
                arch_read_regs(trap, &mut buf);
                // PC is always the last register in our GdbArch serialisation
                let pc_off = (ARCH_REG_COUNT - 1) * 8;
                buf[pc_off..pc_off + 8].copy_from_slice(&addr.to_le_bytes());
                arch_write_regs(trap, &buf);
            }
            target.ctl("cont");
            String::new()
        },

        b's' => {
            let rest = &body[1..];
            if !rest.is_empty() {
                let addr = parse_hex_u64(rest);
                let trap = target.trap_frame_mut();
                let mut buf = alloc::vec![0u8; arch_reg_buf_len()];
                arch_read_regs(trap, &mut buf);
                let pc_off = (ARCH_REG_COUNT - 1) * 8;
                buf[pc_off..pc_off + 8].copy_from_slice(&addr.to_le_bytes());
                arch_write_regs(trap, &buf);
            }
            target.ctl("step");
            String::new()
        },

        b'k' => {
            session.detach(target);
            crate::proc::signal::send_signal(target.pid, 9);
            rsp_packet("OK")
        },

        b'Z' | b'z' => handle_z_packet(body, target, session),

        b'q' => {
            if body.starts_with("qSupported") {
                rsp_packet("PacketSize=4000;swbreak+;hwbreak+;watchpoint+;vContSupported+")
            } else if body.starts_with("qAttached") {
                rsp_packet("1")
            } else if body.starts_with("qC") {
                rsp_packet(&alloc::format!("QC{:x}", target.pid))
            } else {
                rsp_packet("")
            }
        },

        b'D' => {
            session.detach(target);
            rsp_packet("OK")
        },

        _ => rsp_packet(""),
    }
}
