//! Software breakpoints, hardware execution breakpoints, and memory
//! watchpoints.
//!
//! # x86-64
//! Software breakpoints patch `0xCC` (INT3) into the target and restore the
//! original byte on removal.  A maximum of 256 active SW breakpoints are
//! tracked per session.
//!
//! Hardware execution breakpoints and watchpoints use DR0–DR3 (address)
//! and DR7 (control).  DR7 is read/written via the `/proc/<pid>/debug`
//! pseudo-file which the kernel exposes through `proc_debug_read/write`
//! at a well-known offset (PROC_DEBUG_DR_OFFSET).
//!
//! DR7 bit layout used here:
//!   Bits 0,1  = L0,G0 (local/global enable for DR0)
//!   Bits 2,3  = L1,G1
//!   Bits 4,5  = L2,G2
//!   Bits 6,7  = L3,G3
//!   Bits 16,17 = R/W0  (condition: 00=exec 01=write 11=rw)
//!   Bits 18,19 = LEN0  (length: 00=1 01=2 11=4 10=8)
//!   (similar at bits 20-23 for DR1, 24-27 for DR2, 28-31 for DR3)
//!
//! # RISC-V
//! RISC-V Tcontrol / tselect / tdata CSRs are written via the
//! `/proc/<pid>/debug` pseudo-file at `PROC_DEBUG_RISCV_TRIG_OFFSET`.
//! We use type-2 (mcontrol) triggers for both execution and data watchpoints.
//!
//! # Shared Z/z dispatcher
//!
//! `handle_z_packet` is the single canonical implementation of `Z`/`z`
//! packet dispatch shared by all per-architecture RSP handlers.  Each arch
//! file passes its own `&mut Session`-like struct (which carries the three
//! tables) via the `ZSession` trait, keeping Z/z logic in exactly one place.

extern crate alloc;
use alloc::string::String;
use alloc::vec::Vec;

use super::target::GdbTarget;

// ---------------------------------------------------------------------------
// DR register I/O
// ---------------------------------------------------------------------------

const DR_IDX_DR7: usize = 5;

const fn dr7_len_bits(len: usize) -> u64 {
    match len {
        1 => 0b00,
        2 => 0b01,
        8 => 0b10,
        _ => 0b11, // 4 bytes
    }
}

const DR7_RW_EXEC:  u64 = 0b00;
const DR7_RW_WRITE: u64 = 0b01;
const DR7_RW_RW:    u64 = 0b11;

fn read_debug_regs(target: &GdbTarget) -> [u64; 6] {
    use crate::fs::proc_debug::{is_proc_debug_fd, proc_debug_read};
    const DR_VIRT_OFFSET: usize = 0xFFFF_0000;
    let bfd = crate::fs::process_fd::proc_fd_backing(
        crate::proc::scheduler::current_pid(),
        target.mem_fd,
    );
    let mut buf = [0u8; 6 * 8];
    if bfd >= 0 {
        let bfd = bfd as usize;
        if is_proc_debug_fd(bfd) {
            proc_debug_read(bfd, &mut buf, DR_VIRT_OFFSET);
        }
    }
    let mut out = [0u64; 6];
    for i in 0..6 {
        out[i] = u64::from_le_bytes(buf[i * 8..(i + 1) * 8].try_into().unwrap());
    }
    out
}

fn write_debug_regs(target: &GdbTarget, dr: &[u64; 6]) {
    use crate::fs::proc_debug::{is_proc_debug_fd, proc_debug_write};
    const DR_VIRT_OFFSET: usize = 0xFFFF_0000;
    let bfd = crate::fs::process_fd::proc_fd_backing(
        crate::proc::scheduler::current_pid(),
        target.mem_fd,
    );
    if bfd < 0 { return; }
    let bfd = bfd as usize;
    if !is_proc_debug_fd(bfd) { return; }
    let mut buf = [0u8; 6 * 8];
    for i in 0..6 {
        buf[i * 8..(i + 1) * 8].copy_from_slice(&dr[i].to_le_bytes());
    }
    proc_debug_write(bfd, &buf, DR_VIRT_OFFSET);
}

// ---------------------------------------------------------------------------
// Software breakpoints
// ---------------------------------------------------------------------------

struct SwBreakpoint {
    addr:     u64,
    original: u8,
}

pub struct SwBreakpointTable {
    bps: Vec<SwBreakpoint>,
}

impl SwBreakpointTable {
    pub fn new() -> Self { SwBreakpointTable { bps: Vec::new() } }

    pub fn add(&mut self, target: &mut GdbTarget, addr: u64) -> bool {
        if self.bps.iter().any(|b| b.addr == addr) { return false; }
        let orig = target.read_mem(addr, 1);
        if orig.is_empty() { return false; }
        if target.write_mem(addr, &[0xCC]) == 0 { return false; }
        self.bps.push(SwBreakpoint { addr, original: orig[0] });
        true
    }

    pub fn remove(&mut self, target: &mut GdbTarget, addr: u64) -> bool {
        if let Some(idx) = self.bps.iter().position(|b| b.addr == addr) {
            let orig = self.bps[idx].original;
            target.write_mem(addr, &[orig]);
            self.bps.swap_remove(idx);
            true
        } else { false }
    }

    pub fn remove_all(&mut self, target: &mut GdbTarget) {
        let addrs: Vec<u64> = self.bps.iter().map(|b| b.addr).collect();
        for addr in addrs { self.remove(target, addr); }
    }
}

// ---------------------------------------------------------------------------
// Hardware execution breakpoints
// ---------------------------------------------------------------------------

struct HwBreakpoint { slot: usize, addr: u64 }

pub struct HwBreakpointTable { bps: Vec<HwBreakpoint> }

impl HwBreakpointTable {
    pub fn new() -> Self { HwBreakpointTable { bps: Vec::new() } }

    fn free_slot(&self) -> Option<usize> {
        (0..4).find(|&s| !self.bps.iter().any(|b| b.slot == s))
    }

    pub fn add_exec(&mut self, target: &mut GdbTarget, addr: u64) -> bool {
        if self.bps.iter().any(|b| b.addr == addr) { return false; }
        let slot = self.free_slot()?;
        let mut dr = read_debug_regs(target);
        dr[slot] = addr;
        dr[DR_IDX_DR7] |= 1 << (slot * 2);
        let cond_shift = 16 + slot * 4;
        dr[DR_IDX_DR7] &= !(0b1111u64 << cond_shift);
        write_debug_regs(target, &dr);
        self.bps.push(HwBreakpoint { slot, addr });
        true
    }

    pub fn remove(&mut self, target: &mut GdbTarget, addr: u64) -> bool {
        if let Some(idx) = self.bps.iter().position(|b| b.addr == addr) {
            let slot = self.bps[idx].slot;
            let mut dr = read_debug_regs(target);
            dr[slot] = 0;
            dr[DR_IDX_DR7] &= !(1 << (slot * 2));
            dr[DR_IDX_DR7] &= !(0b1111u64 << (16 + slot * 4));
            write_debug_regs(target, &dr);
            self.bps.swap_remove(idx);
            true
        } else { false }
    }

    pub fn remove_all(&mut self, target: &mut GdbTarget) {
        let addrs: Vec<u64> = self.bps.iter().map(|b| b.addr).collect();
        for addr in addrs { self.remove(target, addr); }
    }
}

// ---------------------------------------------------------------------------
// Watchpoints
// ---------------------------------------------------------------------------

#[derive(Copy, Clone, PartialEq)]
pub enum WatchKind { Write, Read, Access }

struct Watchpoint { slot: usize, addr: u64 }

pub struct WatchpointTable { wps: Vec<Watchpoint> }

impl WatchpointTable {
    pub fn new() -> Self { WatchpointTable { wps: Vec::new() } }

    pub fn add(&mut self, target: &mut GdbTarget, addr: u64, len: usize, kind: WatchKind) -> bool {
        if self.wps.iter().any(|w| w.addr == addr) { return false; }
        let slot = (0..4usize).find(|&s| !self.wps.iter().any(|w| w.slot == s))?;
        let rw_bits: u64 = match kind {
            WatchKind::Write  => DR7_RW_WRITE,
            WatchKind::Read   => DR7_RW_RW,
            WatchKind::Access => DR7_RW_RW,
        };
        let len_bits = dr7_len_bits(len);
        let mut dr = read_debug_regs(target);
        dr[slot] = addr;
        dr[DR_IDX_DR7] |= 1 << (slot * 2);
        let cond_shift = 16 + slot * 4;
        dr[DR_IDX_DR7] &= !(0b1111u64 << cond_shift);
        dr[DR_IDX_DR7] |= (rw_bits | (len_bits << 2)) << cond_shift;
        write_debug_regs(target, &dr);
        self.wps.push(Watchpoint { slot, addr });
        true
    }

    pub fn remove(&mut self, target: &mut GdbTarget, addr: u64) -> bool {
        if let Some(idx) = self.wps.iter().position(|w| w.addr == addr) {
            let slot = self.wps[idx].slot;
            let mut dr = read_debug_regs(target);
            dr[slot] = 0;
            dr[DR_IDX_DR7] &= !(1 << (slot * 2));
            dr[DR_IDX_DR7] &= !(0b1111u64 << (16 + slot * 4));
            write_debug_regs(target, &dr);
            self.wps.swap_remove(idx);
            true
        } else { false }
    }

    pub fn remove_all(&mut self, target: &mut GdbTarget) {
        let addrs: Vec<u64> = self.wps.iter().map(|w| w.addr).collect();
        for addr in addrs { self.remove(target, addr); }
    }
}

// ---------------------------------------------------------------------------
// RISC-V debug triggers
// ---------------------------------------------------------------------------

const RISCV_TRIG_VIRT_OFFSET: usize = 0xFFFF_1000;
const TDATA1_TYPE2:  u64 = 2u64 << 60;
const TDATA1_M_MODE: u64 = 1 << 6;
pub const TDATA1_EXEC:  u64 = 1 << 2;
pub const TDATA1_STORE: u64 = 1 << 1;
pub const TDATA1_LOAD:  u64 = 1 << 0;

fn read_riscv_triggers(target: &GdbTarget) -> [[u64; 2]; 4] {
    use crate::fs::proc_debug::{is_proc_debug_fd, proc_debug_read};
    let bfd = crate::fs::process_fd::proc_fd_backing(
        crate::proc::scheduler::current_pid(),
        target.mem_fd,
    );
    let mut buf = [0u8; 4 * 2 * 8];
    if bfd >= 0 {
        let bfd = bfd as usize;
        if is_proc_debug_fd(bfd) {
            proc_debug_read(bfd, &mut buf, RISCV_TRIG_VIRT_OFFSET);
        }
    }
    let mut out = [[0u64; 2]; 4];
    for s in 0..4 {
        for w in 0..2 {
            let off = (s * 2 + w) * 8;
            out[s][w] = u64::from_le_bytes(buf[off..off + 8].try_into().unwrap());
        }
    }
    out
}

fn write_riscv_triggers(target: &GdbTarget, trig: &[[u64; 2]; 4]) {
    use crate::fs::proc_debug::{is_proc_debug_fd, proc_debug_write};
    let bfd = crate::fs::process_fd::proc_fd_backing(
        crate::proc::scheduler::current_pid(),
        target.mem_fd,
    );
    if bfd < 0 { return; }
    let bfd = bfd as usize;
    if !is_proc_debug_fd(bfd) { return; }
    let mut buf = [0u8; 4 * 2 * 8];
    for s in 0..4 {
        for w in 0..2 {
            let off = (s * 2 + w) * 8;
            buf[off..off + 8].copy_from_slice(&trig[s][w].to_le_bytes());
        }
    }
    proc_debug_write(bfd, &buf, RISCV_TRIG_VIRT_OFFSET);
}

pub fn riscv_add_trigger(target: &GdbTarget, addr: u64, kind_bits: u64) -> bool {
    let mut trig = read_riscv_triggers(target);
    let slot = (0..4).find(|&s| trig[s][0] == 0)?;
    trig[slot][0] = TDATA1_TYPE2 | TDATA1_M_MODE | kind_bits;
    trig[slot][1] = addr;
    write_riscv_triggers(target, &trig);
    true
}

pub fn riscv_remove_trigger(target: &GdbTarget, addr: u64) -> bool {
    let mut trig = read_riscv_triggers(target);
    for s in 0..4 {
        if trig[s][1] == addr && trig[s][0] != 0 {
            trig[s] = [0, 0];
            write_riscv_triggers(target, &trig);
            return true;
        }
    }
    false
}

pub use TDATA1_EXEC  as RISCV_TRIG_EXEC;
pub use TDATA1_LOAD  as RISCV_TRIG_LOAD;
pub use TDATA1_STORE as RISCV_TRIG_STORE;

// ---------------------------------------------------------------------------
// Shared Z/z packet dispatcher
//
// All three per-arch RSP handlers (rsp_x86_64, rsp_riscv, rsp_aarch64) hold
// a struct that contains the same three tables.  Rather than duplicating the
// match arm, they implement `ZSession` and call `handle_z_packet` once.
// ---------------------------------------------------------------------------

/// Minimal view of a session needed to service Z/z packets.
pub trait ZSession {
    fn sw_bps(&mut self)  -> &mut SwBreakpointTable;
    fn hw_bps(&mut self)  -> &mut HwBreakpointTable;
    fn watches(&mut self) -> &mut WatchpointTable;
}

/// Parse `<type>,<addr>,<len>` (the body after the leading `Z`/`z` byte).
fn parse_z(rest: &str) -> Option<(u8, u64, usize)> {
    let mut it = rest.splitn(3, ',');
    let t    = u8::from_str_radix(it.next()?, 16).ok()?;
    let addr = u64::from_str_radix(it.next()?, 16).ok()?;
    let len  = usize::from_str_radix(it.next()?, 16).unwrap_or(1);
    Some((t, addr, len))
}

/// Single canonical Z/z handler — call from every per-arch `handle_packet`.
///
/// `body` is the full packet body including the leading `Z` or `z` byte.
pub fn handle_z_packet(
    body:    &str,
    target:  &mut GdbTarget,
    session: &mut dyn ZSession,
) -> String {
    let insert = body.as_bytes()[0] == b'Z';
    let ok = match parse_z(&body[1..]) {
        None => false,
        Some((0, addr, _))    => if insert { session.sw_bps().add(target, addr)              } else { session.sw_bps().remove(target, addr) },
        Some((1, addr, _))    => if insert { session.hw_bps().add_exec(target, addr)         } else { session.hw_bps().remove(target, addr) },
        Some((2, addr, len))  => if insert { session.watches().add(target, addr, len, WatchKind::Write)  } else { session.watches().remove(target, addr) },
        Some((3, addr, len))  => if insert { session.watches().add(target, addr, len, WatchKind::Read)   } else { session.watches().remove(target, addr) },
        Some((4, addr, len))  => if insert { session.watches().add(target, addr, len, WatchKind::Access) } else { session.watches().remove(target, addr) },
        Some(_) => false,
    };
    // Inline rsp_packet to avoid a cross-module dep on the arch-specific helper.
    let body = if ok { "OK" } else { "E01" };
    let csum: u8 = body.bytes().fold(0u8, |a, b| a.wrapping_add(b));
    alloc::format!("+${}#{:02x}", body, csum)
}
