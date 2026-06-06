//! GDB Remote Serial Protocol — x86-64 packet handler.
//!
//! GDB x86-64 target: 16 GPRs + rip + eflags + cs/ss/ds/es/fs/gs = 24 × u64.
//! Register order matches the Linux `user_regs_struct` layout used by
//! `target.rs` (`UREG_COUNT = 27`; we expose 24 to GDB, skipping the 3
//! kernel-internal fields at the end).
//!
//! Register index → `user_regs_struct` field mapping (GDB order):
//!  0  rax   1  rbx   2  rcx   3  rdx
//!  4  rsi   5  rdi   6  rbp   7  rsp
//!  8  r8    9  r9   10  r10  11  r11
//! 12  r12  13  r13  14  r14  15  r15
//! 16  rip  17  eflags  18 cs  19 ss  20 ds  21 es  22 fs  23 gs

extern crate alloc;
use alloc::string::String;
use alloc::vec::Vec;

use super::breakpoints::{HwBreakpointTable, SwBreakpointTable, WatchpointTable};
use super::target::GdbTarget;
use crate::proc::ptrace::UREG_COUNT;

// Number of registers GDB expects for x86-64.
pub const X86_REG_COUNT: usize = 24;

// Map from GDB register index → user_regs_struct index.
// Linux x86-64 user_regs_struct order (see <sys/user.h>):
//   r15=0  r14=1  r13=2  r12=3  rbp=4  rbx=5
//   r11=6  r10=7  r9=8   r8=9   rax=10 rcx=11
//   rdx=12 rsi=13 rdi=14 orig_rax=15  rip=16  cs=17
//   eflags=18  rsp=19  ss=20  fs_base=21  gs_base=22  ds=23  es=24  fs=25
// gs=26
const GDB_TO_UREG: [usize; X86_REG_COUNT] = [
    10, // 0  rax
    5,  // 1  rbx
    11, // 2  rcx
    12, // 3  rdx
    13, // 4  rsi
    14, // 5  rdi
    4,  // 6  rbp
    19, // 7  rsp
    9,  // 8  r8
    8,  // 9  r9
    7,  // 10 r10
    6,  // 11 r11
    3,  // 12 r12
    2,  // 13 r13
    1,  // 14 r14
    0,  // 15 r15
    16, // 16 rip
    18, // 17 eflags
    17, // 18 cs
    20, // 19 ss
    23, // 20 ds
    24, // 21 es
    25, // 22 fs
    26, // 23 gs
];

fn build_gdb_regs(ureg: &[u64; UREG_COUNT]) -> [u64; X86_REG_COUNT] {
    let mut out = [0u64; X86_REG_COUNT];
    for (gdb_idx, &ureg_idx) in GDB_TO_UREG.iter().enumerate() {
        out[gdb_idx] = if ureg_idx < UREG_COUNT {
            ureg[ureg_idx]
        } else {
            0
        };
    }
    out
}

fn unpack_gdb_regs(gdb_regs: &[u64; X86_REG_COUNT], ureg: &mut [u64; UREG_COUNT]) {
    for (gdb_idx, &ureg_idx) in GDB_TO_UREG.iter().enumerate() {
        if ureg_idx < UREG_COUNT {
            ureg[ureg_idx] = gdb_regs[gdb_idx];
        }
    }
}

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

// On x86-64 we set the Trap Flag (bit 8) in RFLAGS before continuing.
// The CPU delivers a #DB exception after the next instruction, which the
// kernel translates to SIGTRAP.  We clear TF again in the trap handler.

const RFLAGS_TF: u64 = 1 << 8;

/// Set RFLAGS.TF so the CPU single-steps the next instruction.
pub fn step_set_tf(target: &mut GdbTarget) {
    let mut regs = target.read_regs();
    regs[18] |= RFLAGS_TF; // ureg index 18 = eflags
    target.write_regs(&regs);
}

/// Clear RFLAGS.TF (call from the #DB / SIGTRAP handler).
pub fn step_clear_tf(target: &mut GdbTarget) {
    let mut regs = target.read_regs();
    regs[18] &= !RFLAGS_TF;
    target.write_regs(&regs);
}

pub struct X86Session {
    pub sw_bps: SwBreakpointTable,
    pub hw_bps: HwBreakpointTable,
    pub watches: WatchpointTable,
}

impl X86Session {
    pub fn new() -> Self {
        X86Session {
            sw_bps: SwBreakpointTable::new(),
            hw_bps: HwBreakpointTable::new(),
            watches: WatchpointTable::new(),
        }
    }
}

pub fn handle_packet(body: &str, target: &mut GdbTarget, session: &mut X86Session) -> String {
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
            let ureg = target.read_regs();
            let regs = build_gdb_regs(&ureg);
            let mut hex = String::with_capacity(X86_REG_COUNT * 16);
            for &v in &regs {
                hex.push_str(&u64_le_hex(v));
            }
            rsp_packet(&hex)
        },
        // Write all registers
        b'G' => {
            let bytes = decode_hex_bytes(&body[1..]);
            let mut gdb_regs = [0u64; X86_REG_COUNT];
            for i in 0..X86_REG_COUNT {
                let off = i * 8;
                if off + 8 > bytes.len() {
                    break;
                }
                gdb_regs[i] = u64::from_le_bytes(bytes[off..off + 8].try_into().unwrap());
            }
            let mut ureg = target.read_regs();
            unpack_gdb_regs(&gdb_regs, &mut ureg);
            target.write_regs(&ureg);
            rsp_packet("OK")
        },
        // Read single register  'p<regnum>'
        b'p' => {
            let idx = parse_hex_u64(&body[1..]) as usize;
            if idx >= X86_REG_COUNT {
                return rsp_packet("E01");
            }
            let ureg = target.read_regs();
            let regs = build_gdb_regs(&ureg);
            rsp_packet(&u64_le_hex(regs[idx]))
        },
        // Write single register  'P<regnum>=<val>'
        b'P' => {
            let rest = &body[1..];
            let eq = rest.find('=').unwrap_or(rest.len());
            let idx = parse_hex_u64(&rest[..eq]) as usize;
            let val = parse_hex_u64(&rest[eq + 1..]);
            if idx >= X86_REG_COUNT {
                return rsp_packet("E01");
            }
            let mut ureg = target.read_regs();
            let mut gdb_regs = build_gdb_regs(&ureg);
            gdb_regs[idx] = val;
            unpack_gdb_regs(&gdb_regs, &mut ureg);
            target.write_regs(&ureg);
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
        // Single-step: set TF then continue
        b's' => {
            step_set_tf(target);
            target.ctl("cont");
            String::new()
        },
        // Breakpoints / watchpoints  'Z<type>,<addr>,<kind>'  /  'z<type>,...'
        b'Z' | b'z' => handle_z_packet(body, target, session),
        b'k' => {
            crate::proc::signal::send_signal(target.pid, 9);
            rsp_packet("OK")
        },
        b'q' => {
            if body.starts_with("qSupported") {
                // Advertise sw + hw breakpoints and watchpoints
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

// GDB breakpoint kinds:
//   Z0 / z0  software breakpoint
//   Z1 / z1  hardware execution breakpoint
//   Z2 / z2  write watchpoint
//   Z3 / z3  read watchpoint
//   Z4 / z4  access (read/write) watchpoint

fn handle_z_packet(body: &str, target: &mut GdbTarget, session: &mut X86Session) -> String {
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

pub use super::breakpoints::WatchKind;
