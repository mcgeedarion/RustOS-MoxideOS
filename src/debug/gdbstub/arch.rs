//! Arch-agnostic register helpers for the GDB RSP implementation.
//!
//! Centralises register serialisation/deserialisation behind the [`GdbArch`]
//! trait so the per-architecture RSP files only contain a thin `impl` each.
//! Common packet utilities (`vCont` parser, hex helpers) also live here so
//! `rsp.rs` and the arch files share a single copy.

extern crate alloc;
use alloc::vec::Vec;

// ── vCont ────────────────────────────────────────────────────────────────────

/// Decoded action from a `vCont` packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VContAction {
    /// `vCont;c` — continue execution.
    Continue,
    /// `vCont;s` — single-step one instruction.
    Step,
    /// `vCont;t` — stop (send stop reply immediately).
    Stop,
    /// `vCont;r<start>,<end>` — range-step: step until PC leaves `[start, end)`.
    RangeStep { start: u64, end: u64 },
}

/// Parse the first action from a `vCont` packet body (the part after `vCont`).
///
/// Returns `None` for `vCont?` (capability query) or unrecognised actions.
/// Thread-id suffixes (`:tid`) are stripped before matching.
pub fn parse_vcont(body: &str) -> Option<VContAction> {
    if body == "vCont?" {
        return None;
    }
    let rest = body.strip_prefix("vCont;")?;
    let action = rest.split(';').next().unwrap_or("");
    let action = action.split(':').next().unwrap_or("");

    if let Some(range) = action.strip_prefix('r') {
        let mut it = range.splitn(2, ',');
        let start = parse_hex_u64(it.next().unwrap_or(""));
        let end   = parse_hex_u64(it.next().unwrap_or(""));
        return Some(VContAction::RangeStep { start, end });
    }

    match action.as_bytes().first().copied() {
        Some(b'c') => Some(VContAction::Continue),
        Some(b's') => Some(VContAction::Step),
        Some(b't') => Some(VContAction::Stop),
        _           => None,
    }
}

// ── Shared hex helpers ───────────────────────────────────────────────────────

#[inline]
pub fn parse_hex_u64(s: &str) -> u64 {
    u64::from_str_radix(s, 16).unwrap_or(0)
}

#[inline]
fn from_hex(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

pub fn decode_hex_bytes(s: &str) -> Vec<u8> {
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

pub fn encode_hex_bytes(data: &[u8]) -> alloc::string::String {
    let mut s = alloc::string::String::with_capacity(data.len() * 2);
    for &b in data {
        let hi = b >> 4;
        let lo = b & 0xf;
        s.push(char::from_digit(hi as u32, 16).unwrap_or('0'));
        s.push(char::from_digit(lo as u32, 16).unwrap_or('0'));
    }
    s
}

// ── GdbArch trait ────────────────────────────────────────────────────────────

/// Architecture-specific register serialisation for the GDB `g`/`G` packets.
///
/// Implement this trait for each supported architecture so `rsp.rs` can
/// dispatch generically without duplicating packet framing or hex-encode logic.
pub trait GdbArch {
    /// Total byte length of the `g`/`G` register packet buffer.
    fn reg_buf_len() -> usize;

    /// Serialise all registers into `buf` in GDB's expected little-endian order.
    fn read_regs(frame: &crate::arch::TrapFrame, buf: &mut [u8]);

    /// Deserialise registers from `buf` back into `frame`.
    fn write_regs(frame: &mut crate::arch::TrapFrame, buf: &[u8]);

    /// Return the program counter from `frame`.
    fn pc(frame: &crate::arch::TrapFrame) -> u64;

    /// Set the program counter in `frame`.
    fn set_pc(frame: &mut crate::arch::TrapFrame, pc: u64);

    /// GDB signal number reported in the stop reply (default: 5 = SIGTRAP).
    fn trap_signal() -> u8 { 5 }
}

// ── x86_64 ───────────────────────────────────────────────────────────────────

pub struct X86_64;

#[cfg(target_arch = "x86_64")]
impl GdbArch for X86_64 {
    fn reg_buf_len() -> usize { 32 * 8 }

    fn read_regs(frame: &crate::arch::TrapFrame, buf: &mut [u8]) {
        let regs: [u64; 32] = [
            frame.rax, frame.rcx, frame.rdx, frame.rbx,
            frame.rsp, frame.rbp, frame.rsi, frame.rdi,
            frame.r8,  frame.r9,  frame.r10, frame.r11,
            frame.r12, frame.r13, frame.r14, frame.r15,
            frame.rip, frame.rflags, frame.cs, frame.ss,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        for (i, &v) in regs.iter().enumerate() {
            buf[i * 8..(i + 1) * 8].copy_from_slice(&v.to_le_bytes());
        }
    }

    fn write_regs(frame: &mut crate::arch::TrapFrame, buf: &[u8]) {
        macro_rules! rd { ($i:expr) => { u64::from_le_bytes(buf[$i*8..$i*8+8].try_into().unwrap()) }; }
        frame.rax=rd!(0); frame.rcx=rd!(1); frame.rdx=rd!(2); frame.rbx=rd!(3);
        frame.rsp=rd!(4); frame.rbp=rd!(5); frame.rsi=rd!(6); frame.rdi=rd!(7);
        frame.r8=rd!(8);  frame.r9=rd!(9);  frame.r10=rd!(10); frame.r11=rd!(11);
        frame.r12=rd!(12); frame.r13=rd!(13); frame.r14=rd!(14); frame.r15=rd!(15);
        frame.rip=rd!(16); frame.rflags=rd!(17); frame.cs=rd!(18); frame.ss=rd!(19);
    }

    fn pc(frame: &crate::arch::TrapFrame) -> u64 { frame.rip }
    fn set_pc(frame: &mut crate::arch::TrapFrame, pc: u64) { frame.rip = pc; }
}

// ── RISC-V ───────────────────────────────────────────────────────────────────

pub struct RiscV64;

#[cfg(target_arch = "riscv64")]
impl GdbArch for RiscV64 {
    fn reg_buf_len() -> usize { 33 * 8 }

    fn read_regs(frame: &crate::arch::TrapFrame, buf: &mut [u8]) {
        let gprs: [u64; 32] = [
            0, frame.ra, frame.sp, frame.gp, frame.tp,
            frame.t0, frame.t1, frame.t2,
            frame.s0, frame.s1,
            frame.a0, frame.a1, frame.a2, frame.a3,
            frame.a4, frame.a5, frame.a6, frame.a7,
            frame.s2, frame.s3, frame.s4, frame.s5,
            frame.s6, frame.s7, frame.s8, frame.s9,
            frame.s10, frame.s11,
            frame.t3, frame.t4, frame.t5, frame.t6,
        ];
        for (i, &v) in gprs.iter().enumerate() {
            buf[i * 8..(i + 1) * 8].copy_from_slice(&v.to_le_bytes());
        }
        buf[32*8..33*8].copy_from_slice(&frame.sepc.to_le_bytes());
    }

    fn write_regs(frame: &mut crate::arch::TrapFrame, buf: &[u8]) {
        macro_rules! rd { ($i:expr) => { u64::from_le_bytes(buf[$i*8..$i*8+8].try_into().unwrap()) }; }
        frame.ra=rd!(1); frame.sp=rd!(2); frame.gp=rd!(3); frame.tp=rd!(4);
        frame.t0=rd!(5); frame.t1=rd!(6); frame.t2=rd!(7);
        frame.s0=rd!(8); frame.s1=rd!(9);
        frame.a0=rd!(10); frame.a1=rd!(11); frame.a2=rd!(12); frame.a3=rd!(13);
        frame.a4=rd!(14); frame.a5=rd!(15); frame.a6=rd!(16); frame.a7=rd!(17);
        frame.s2=rd!(18); frame.s3=rd!(19); frame.s4=rd!(20); frame.s5=rd!(21);
        frame.s6=rd!(22); frame.s7=rd!(23); frame.s8=rd!(24); frame.s9=rd!(25);
        frame.s10=rd!(26); frame.s11=rd!(27);
        frame.t3=rd!(28); frame.t4=rd!(29); frame.t5=rd!(30); frame.t6=rd!(31);
        frame.sepc=rd!(32);
    }

    fn pc(frame: &crate::arch::TrapFrame) -> u64 { frame.sepc }
    fn set_pc(frame: &mut crate::arch::TrapFrame, pc: u64) { frame.sepc = pc; }
}

// ── AArch64 ──────────────────────────────────────────────────────────────────

pub struct AArch64;

#[cfg(target_arch = "aarch64")]
impl GdbArch for AArch64 {
    fn reg_buf_len() -> usize { 34 * 8 }

    fn read_regs(frame: &crate::arch::TrapFrame, buf: &mut [u8]) {
        for i in 0..=30usize {
            buf[i*8..(i+1)*8].copy_from_slice(&frame.x[i].to_le_bytes());
        }
        buf[31*8..32*8].copy_from_slice(&frame.sp.to_le_bytes());
        buf[32*8..33*8].copy_from_slice(&frame.pc.to_le_bytes());
        buf[33*8..34*8].copy_from_slice(&frame.spsr.to_le_bytes());
    }

    fn write_regs(frame: &mut crate::arch::TrapFrame, buf: &[u8]) {
        for i in 0..=30usize {
            frame.x[i] = u64::from_le_bytes(buf[i*8..(i+1)*8].try_into().unwrap());
        }
        frame.sp   = u64::from_le_bytes(buf[31*8..32*8].try_into().unwrap());
        frame.pc   = u64::from_le_bytes(buf[32*8..33*8].try_into().unwrap());
        frame.spsr = u64::from_le_bytes(buf[33*8..34*8].try_into().unwrap());
    }

    fn pc(frame: &crate::arch::TrapFrame) -> u64 { frame.pc }
    fn set_pc(frame: &mut crate::arch::TrapFrame, pc: u64) { frame.pc = pc; }
}
