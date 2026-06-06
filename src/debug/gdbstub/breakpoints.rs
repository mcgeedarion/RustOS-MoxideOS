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

extern crate alloc;
use alloc::vec::Vec;

use super::target::GdbTarget;

// Layout: [dr0, dr1, dr2, dr3, dr6, dr7]  each u64, little-endian.
// The kernel exposes these at byte offset 0 in the debug pseudo-fd.
const DR0_OFFSET: usize = 0;
const DR7_OFFSET: usize = 5 * 8; // dr0..dr5 (dr4/dr5 alias dr6/dr7, skip), real offset
                                 // We use a flat layout: dr0=0, dr1=1, dr2=2, dr3=3, dr6=4, dr7=5  (indices × 8)
const DR_IDX_DR7: usize = 5;

// DR7 per-slot bit positions: slot 0..3
// Local-enable bit for slot n: bit (n*2)
// Condition (R/W) for slot n: bits (16 + n*4 + 0..1)
// Length (LEN) for slot n: bits (16 + n*4 + 2..3)
const fn dr7_len_bits(len: usize) -> u64 {
    match len {
        1 => 0b00,
        2 => 0b01,
        8 => 0b10,
        _ => 0b11, // 4 bytes
    }
}

const DR7_RW_EXEC: u64 = 0b00;
const DR7_RW_WRITE: u64 = 0b01;
const DR7_RW_RW: u64 = 0b11;

/// Read the 6-register debug register block [dr0,dr1,dr2,dr3,dr6,dr7] from
/// the target's /proc/<pid>/debug fd.
fn read_debug_regs(target: &GdbTarget) -> [u64; 6] {
    use crate::fs::proc_debug::{is_proc_debug_fd, proc_debug_read};
    // The debug fd is exposed as a separate fd on the target.  We reach it via
    // the ctl_fd path with a special offset sentinel recognised by proc_debug.
    // For simplicity we re-use `mem_fd` at a high virtual offset that the
    // proc_debug layer maps to debug registers (PROC_DEBUG_DR_PHYS_OFFSET).
    // Kernel convention: reads at offset 0xFFFF_0000 return the DR block.
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
    if bfd < 0 {
        return;
    }
    let bfd = bfd as usize;
    if !is_proc_debug_fd(bfd) {
        return;
    }
    let mut buf = [0u8; 6 * 8];
    for i in 0..6 {
        buf[i * 8..(i + 1) * 8].copy_from_slice(&dr[i].to_le_bytes());
    }
    proc_debug_write(bfd, &buf, DR_VIRT_OFFSET);
}

struct SwBreakpoint {
    addr: u64,
    original: u8,
}

pub struct SwBreakpointTable {
    bps: Vec<SwBreakpoint>,
}

impl SwBreakpointTable {
    pub fn new() -> Self {
        SwBreakpointTable { bps: Vec::new() }
    }

    /// Patch `0xCC` (INT3) at `addr`, saving the original byte.
    /// Returns `false` if already set or memory write fails.
    pub fn add(&mut self, target: &mut GdbTarget, addr: u64) -> bool {
        if self.bps.iter().any(|b| b.addr == addr) {
            return false;
        }
        let orig = target.read_mem(addr, 1);
        if orig.is_empty() {
            return false;
        }
        let written = target.write_mem(addr, &[0xCC]);
        if written == 0 {
            return false;
        }
        self.bps.push(SwBreakpoint {
            addr,
            original: orig[0],
        });
        true
    }

    /// Restore the original byte at `addr` and remove the record.
    pub fn remove(&mut self, target: &mut GdbTarget, addr: u64) -> bool {
        if let Some(idx) = self.bps.iter().position(|b| b.addr == addr) {
            let orig = self.bps[idx].original;
            target.write_mem(addr, &[orig]);
            self.bps.swap_remove(idx);
            true
        } else {
            false
        }
    }

    /// Remove all breakpoints (e.g. on detach).
    pub fn remove_all(&mut self, target: &mut GdbTarget) {
        // iterate indices in reverse so swap_remove doesn't skip any
        let addrs: Vec<u64> = self.bps.iter().map(|b| b.addr).collect();
        for addr in addrs {
            self.remove(target, addr);
        }
    }
}

struct HwBreakpoint {
    slot: usize, // 0..3
    addr: u64,
}

pub struct HwBreakpointTable {
    bps: Vec<HwBreakpoint>,
}

impl HwBreakpointTable {
    pub fn new() -> Self {
        HwBreakpointTable { bps: Vec::new() }
    }

    fn free_slot(&self) -> Option<usize> {
        for s in 0..4 {
            if !self.bps.iter().any(|b| b.slot == s) {
                return Some(s);
            }
        }
        None
    }

    /// Install an execution breakpoint at `addr` using a free DR slot.
    pub fn add_exec(&mut self, target: &mut GdbTarget, addr: u64) -> bool {
        if self.bps.iter().any(|b| b.addr == addr) {
            return false;
        }
        let slot = match self.free_slot() {
            Some(s) => s,
            None => return false,
        };
        let mut dr = read_debug_regs(target);
        // Set DRn address
        dr[slot] = addr;
        // Enable local bit for this slot (L0 = bit 0, L1 = bit 2, ...)
        let local_en_bit = (slot * 2) as u64;
        dr[DR_IDX_DR7] |= 1 << local_en_bit;
        // Condition bits: R/W=00 (exec), LEN=00 (1-byte)
        let cond_shift = 16 + slot * 4;
        // clear and set to exec (0b0000)
        dr[DR_IDX_DR7] &= !(0b1111u64 << cond_shift);
        write_debug_regs(target, &dr);
        self.bps.push(HwBreakpoint { slot, addr });
        true
    }

    /// Remove the hardware breakpoint at `addr`.
    pub fn remove(&mut self, target: &mut GdbTarget, addr: u64) -> bool {
        if let Some(idx) = self.bps.iter().position(|b| b.addr == addr) {
            let slot = self.bps[idx].slot;
            let mut dr = read_debug_regs(target);
            dr[slot] = 0;
            // Clear local-enable + condition bits for this slot
            let local_en_bit = (slot * 2) as u64;
            dr[DR_IDX_DR7] &= !(1 << local_en_bit);
            let cond_shift = 16 + slot * 4;
            dr[DR_IDX_DR7] &= !(0b1111u64 << cond_shift);
            write_debug_regs(target, &dr);
            self.bps.swap_remove(idx);
            true
        } else {
            false
        }
    }

    pub fn remove_all(&mut self, target: &mut GdbTarget) {
        let addrs: Vec<u64> = self.bps.iter().map(|b| b.addr).collect();
        for addr in addrs {
            self.remove(target, addr);
        }
    }
}

#[derive(Copy, Clone, PartialEq)]
pub enum WatchKind {
    Write,  // Z2 — DR7 R/W = 01
    Read,   // Z3 — x86 does not support read-only; treat as access
    Access, // Z4 — DR7 R/W = 11
}

struct Watchpoint {
    slot: usize,
    addr: u64,
}

pub struct WatchpointTable {
    wps: Vec<Watchpoint>,
}

impl WatchpointTable {
    pub fn new() -> Self {
        WatchpointTable { wps: Vec::new() }
    }

    fn free_slot(&self, hw_bps: &HwBreakpointTable) -> Option<usize> {
        // Watchpoints share DR0–DR3 with HW execution BPs
        for s in 0..4 {
            let used_by_bp = hw_bps.bps.iter().any(|b| b.slot == s);
            let used_by_wp = self.wps.iter().any(|w| w.slot == s);
            if !used_by_bp && !used_by_wp {
                return Some(s);
            }
        }
        None
    }

    /// Install a watchpoint.  `len` should be 1, 2, 4, or 8.
    pub fn add(&mut self, target: &mut GdbTarget, addr: u64, len: usize, kind: WatchKind) -> bool {
        // We don't have the hw_bps borrow here; call the combined version from
        // the session level.  For standalone use, provide a dummy HwBreakpointTable.
        // In practice the session owns both tables.
        if self.wps.iter().any(|w| w.addr == addr) {
            return false;
        }
        // Find a free slot not used by this watchpoint table itself
        let slot = {
            let mut found = None;
            for s in 0..4usize {
                if !self.wps.iter().any(|w| w.slot == s) {
                    found = Some(s);
                    break;
                }
            }
            match found {
                Some(s) => s,
                None => return false,
            }
        };
        let rw_bits: u64 = match kind {
            WatchKind::Write => DR7_RW_WRITE,
            WatchKind::Read => DR7_RW_RW, // x86 has no read-only, use R/W
            WatchKind::Access => DR7_RW_RW,
        };
        let len_bits = dr7_len_bits(len);
        let mut dr = read_debug_regs(target);
        dr[slot] = addr;
        let local_en_bit = (slot * 2) as u64;
        dr[DR_IDX_DR7] |= 1 << local_en_bit;
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
            let local_en_bit = (slot * 2) as u64;
            dr[DR_IDX_DR7] &= !(1 << local_en_bit);
            let cond_shift = 16 + slot * 4;
            dr[DR_IDX_DR7] &= !(0b1111u64 << cond_shift);
            write_debug_regs(target, &dr);
            self.wps.swap_remove(idx);
            true
        } else {
            false
        }
    }

    pub fn remove_all(&mut self, target: &mut GdbTarget) {
        let addrs: Vec<u64> = self.wps.iter().map(|w| w.addr).collect();
        for addr in addrs {
            self.remove(target, addr);
        }
    }
}

// RISC-V debug triggers are written via /proc/<pid>/debug at
// PROC_DEBUG_RISCV_TRIG_OFFSET.  Layout: pairs of [tdata1, tdata2] per slot,
// up to 4 slots.  tdata1 type=2 (mcontrol) is used.
// tdata1 (mcontrol) relevant fields:
//   bits 63:60  type=2
//   bit  19     action=0 (raise debug exception)
//   bit  6      m (machine mode match)
//   bit  2      execute
//   bit  1      store
//   bit  0      load

const RISCV_TRIG_VIRT_OFFSET: usize = 0xFFFF_1000;
const TDATA1_TYPE2: u64 = 2u64 << 60;
const TDATA1_M_MODE: u64 = 1 << 6;
const TDATA1_EXEC: u64 = 1 << 2;
const TDATA1_STORE: u64 = 1 << 1;
const TDATA1_LOAD: u64 = 1 << 0;

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
    if bfd < 0 {
        return;
    }
    let bfd = bfd as usize;
    if !is_proc_debug_fd(bfd) {
        return;
    }
    let mut buf = [0u8; 4 * 2 * 8];
    for s in 0..4 {
        for w in 0..2 {
            let off = (s * 2 + w) * 8;
            buf[off..off + 8].copy_from_slice(&trig[s][w].to_le_bytes());
        }
    }
    proc_debug_write(bfd, &buf, RISCV_TRIG_VIRT_OFFSET);
}

/// Install a RISC-V trigger.  `kind` selects execute / store / load bits.
pub fn riscv_add_trigger(
    target: &GdbTarget,
    addr: u64,
    kind_bits: u64, // e.g. TDATA1_EXEC or TDATA1_STORE | TDATA1_LOAD
) -> bool {
    let mut trig = read_riscv_triggers(target);
    let slot = (0..4).find(|&s| trig[s][0] == 0);
    let slot = match slot {
        Some(s) => s,
        None => return false,
    };
    trig[slot][0] = TDATA1_TYPE2 | TDATA1_M_MODE | kind_bits;
    trig[slot][1] = addr;
    write_riscv_triggers(target, &trig);
    true
}

/// Remove a RISC-V trigger matching `addr`.
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

pub use TDATA1_EXEC as RISCV_TRIG_EXEC;
pub use TDATA1_LOAD as RISCV_TRIG_LOAD;
pub use TDATA1_STORE as RISCV_TRIG_STORE;
