//! GDB Remote Serial Protocol — RISC-V 64 packet handler.
//!
//! Same structure as rsp.rs but uses RISC-V register naming.
//! GDB RISC-V target: 32 integer regs (x0-x31) + pc = 33 × 8-byte regs.
//!
//! The register layout in /proc/<pid>/regs for RISC-V follows the SBI trap
//! frame: pc at offset 0, x1-x31 at offsets 1-31 (zero is hardwired 0).

extern crate alloc;
use alloc::string::String;
use alloc::vec::Vec;

use super::target::GdbTarget;

// RISC-V regs in /proc/<pid>/regs (u64 each, little-endian)
// Our trap frame: [pc, ra, sp, gp, tp, t0-t2, s0-s1, a0-a7, s2-s11, t3-t6]
// Matches Linux uapi riscv/ptrace.h struct user_regs_struct layout.
pub const RISCV_REG_COUNT: usize = 33; // pc + x1..x31 + padding to 33

// GDB RISC-V register order: x0(zero) x1(ra) … x31  then pc
// x0 is always 0, pc is last.
fn build_gdb_regs(frame: &[u64]) -> [u64; RISCV_REG_COUNT] {
    // frame[0] = pc, frame[1..32] = x1..x31
    let mut out = [0u64; RISCV_REG_COUNT];
    out[0] = 0; // x0 (zero)
    for i in 1..32 {
        out[i] = if i < frame.len() { frame[i] } else { 0 };
    }
    out[32] = frame[0]; // pc
    out
}

fn unpack_gdb_regs(gdb_regs: &[u64; RISCV_REG_COUNT]) -> [u64; 33] {
    let mut frame = [0u64; 33];
    frame[0] = gdb_regs[32]; // pc
    for i in 1..32 {
        frame[i] = gdb_regs[i]; // x1..x31 (x0 ignored)
    }
    frame
}

// ── helpers (same as rsp.rs) ─────────────────────────────────────────────────

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

// ── RISC-V ebreak single-step injection ──────────────────────────────────────
//
// RISC-V has no hardware trap-flag. Single-step is implemented by injecting
// an `ebreak` (0x00100073) at the current PC, executing it, then restoring
// the original word and decrementing PC back by 4.
//
// The GDB stub calls step_inject_ebreak before "cont" and
// step_restore_ebreak in the SIGTRAP handler.

pub struct EbreakState {
    pub addr: u64,
    pub original: [u8; 4],
}

pub fn step_inject_ebreak(target: &mut GdbTarget) -> Option<EbreakState> {
    // Read PC from regs fd
    let raw = read_raw_regs(target);
    let pc = raw[0]; // frame[0] = pc
    let original_bytes = target.read_mem(pc, 4);
    if original_bytes.len() < 4 {
        return None;
    }
    let original: [u8; 4] = original_bytes[..4].try_into().ok()?;
    // ebreak = 0x00100073 (little-endian: 73 00 10 00)
    target.write_mem(pc, &[0x73, 0x00, 0x10, 0x00]);
    Some(EbreakState { addr: pc, original })
}

pub fn step_restore_ebreak(target: &mut GdbTarget, state: &EbreakState) {
    target.write_mem(state.addr, &state.original);
}

fn read_raw_regs(target: &GdbTarget) -> [u64; 33] {
    use crate::fs::proc_debug::{is_proc_debug_fd, proc_debug_read};
    let bfd = crate::fs::process_fd::proc_fd_backing(
        crate::proc::scheduler::current_pid(),
        target.regs_fd,
    );
    let mut frame = [0u64; 33];
    if bfd < 0 {
        return frame;
    }
    let bfd = bfd as usize;
    if !is_proc_debug_fd(bfd) {
        return frame;
    }
    let mut buf = [0u8; 33 * 8];
    proc_debug_read(bfd, &mut buf, 0);
    for i in 0..33 {
        frame[i] = u64::from_le_bytes(buf[i * 8..(i + 1) * 8].try_into().unwrap());
    }
    frame
}

// ── Packet dispatch ───────────────────────────────────────────────────────────

pub fn handle_packet(body: &str, target: &mut GdbTarget) -> String {
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
        }
        b'g' => {
            let raw = read_raw_regs(target);
            let regs = build_gdb_regs(&raw);
            let mut hex = String::with_capacity(RISCV_REG_COUNT * 16);
            for &v in &regs {
                hex.push_str(&u64_le_hex(v));
            }
            rsp_packet(&hex)
        }
        b'G' => {
            let bytes = decode_hex_bytes(&body[1..]);
            let mut gdb_regs = [0u64; RISCV_REG_COUNT];
            for i in 0..RISCV_REG_COUNT {
                let off = i * 8;
                if off + 8 > bytes.len() {
                    break;
                }
                gdb_regs[i] = u64::from_le_bytes(bytes[off..off + 8].try_into().unwrap());
            }
            let frame = unpack_gdb_regs(&gdb_regs);
            // Write back via regs_fd
            use crate::fs::proc_debug::{is_proc_debug_fd, proc_debug_write};
            let bfd = crate::fs::process_fd::proc_fd_backing(
                crate::proc::scheduler::current_pid(),
                target.regs_fd,
            );
            if bfd >= 0 {
                let bfd = bfd as usize;
                if is_proc_debug_fd(bfd) {
                    let mut buf = [0u8; 33 * 8];
                    for i in 0..33 {
                        buf[i * 8..(i + 1) * 8].copy_from_slice(&frame[i].to_le_bytes());
                    }
                    proc_debug_write(bfd, &buf, 0);
                }
            }
            rsp_packet("OK")
        }
        b'm' => {
            let rest = &body[1..];
            let mut parts = rest.splitn(2, ',');
            let addr = parse_hex_u64(parts.next().unwrap_or(""));
            let len = parse_hex_u64(parts.next().unwrap_or("")) as usize;
            let data = target.read_mem(addr, len);
            rsp_packet(&encode_hex_bytes(&data))
        }
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
        }
        b'c' => {
            target.ctl("cont");
            String::new()
        }
        b's' => {
            // Inject ebreak for single-step on RISC-V
            let _ = step_inject_ebreak(target);
            target.ctl("cont");
            String::new()
        }
        b'k' => {
            crate::proc::signal::send_signal(target.pid, 9);
            rsp_packet("OK")
        }
        b'q' => {
            if body.starts_with("qSupported") {
                rsp_packet("PacketSize=4000")
            } else if body.starts_with("qAttached") {
                rsp_packet("1")
            } else {
                rsp_packet("")
            }
        }
        _ => rsp_packet(""),
    }
}
