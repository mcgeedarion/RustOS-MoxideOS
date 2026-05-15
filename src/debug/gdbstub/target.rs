//! GdbTarget — attaches to a stopped process via /proc/<pid>/mem|regs|ctl
//! and provides typed memory/register read-write without touching ptrace.
//!
//! Usage:
//! ```rust
//! let mut t = GdbTarget::attach(pid);
//! let regs  = t.read_regs();              // full user_regs_struct
//! t.write_mem(rip, &[0xcc]);              // insert breakpoint
//! t.ctl("step");                          // single-step
//! let stop  = t.wait_stop();              // block until T<sig> on ctl fd
//! ```
//!
//! All fd I/O goes through `proc_fd_open` / pread64 / pwrite64 so the
//! GDB stub never references ptrace internals.

extern crate alloc;
use alloc::string::String;
use alloc::vec::Vec;

use crate::fs::process_fd::{proc_fd_close, proc_fd_open};
use crate::proc::ptrace::UREG_COUNT;

// O_RDWR
const O_RDWR: u32 = 2;

// ── GdbTarget ────────────────────────────────────────────────────────────────

pub struct GdbTarget {
    pub pid: usize,
    pub mem_fd: usize,
    pub regs_fd: usize,
    pub ctl_fd: usize,
    /// Pid of the debugger process (owner of the fds in its fd table).
    debugger_pid: usize,
}

impl GdbTarget {
    /// Attach to `pid`. Must be called from the debugger task context.
    /// The target must already be in `PtraceState::Stopped` (i.e. the
    /// debugger attached it via SIGSTOP before calling this).
    pub fn attach(pid: usize) -> Option<Self> {
        let debugger_pid = crate::proc::scheduler::current_pid();

        let mem_path = alloc::format!("/proc/{}/mem", pid);
        let regs_path = alloc::format!("/proc/{}/regs", pid);
        let ctl_path = alloc::format!("/proc/{}/ctl", pid);

        let mem_fd = proc_fd_open(debugger_pid, &mem_path, O_RDWR, 0);
        let regs_fd = proc_fd_open(debugger_pid, &regs_path, O_RDWR, 0);
        let ctl_fd = proc_fd_open(debugger_pid, &ctl_path, O_RDWR, 0);

        if mem_fd < 0 || regs_fd < 0 || ctl_fd < 0 {
            // Clean up any fds that did open
            if mem_fd >= 0 {
                proc_fd_close(debugger_pid, mem_fd as usize);
            }
            if regs_fd >= 0 {
                proc_fd_close(debugger_pid, regs_fd as usize);
            }
            if ctl_fd >= 0 {
                proc_fd_close(debugger_pid, ctl_fd as usize);
            }
            return None;
        }

        Some(GdbTarget {
            pid,
            mem_fd: mem_fd as usize,
            regs_fd: regs_fd as usize,
            ctl_fd: ctl_fd as usize,
            debugger_pid,
        })
    }

    // ── memory ───────────────────────────────────────────────────────────────

    /// Read `len` bytes from the target's virtual address space at `vaddr`.
    pub fn read_mem(&self, vaddr: u64, len: usize) -> Vec<u8> {
        use crate::fs::proc_debug::{is_proc_debug_fd, proc_debug_read};
        let bfd = crate::fs::process_fd::proc_fd_backing(self.debugger_pid, self.mem_fd);
        if bfd < 0 {
            return alloc::vec![0u8; len];
        }
        let bfd = bfd as usize;
        if !is_proc_debug_fd(bfd) {
            return alloc::vec![0u8; len];
        }
        let mut buf = alloc::vec![0u8; len];
        proc_debug_read(bfd, &mut buf, vaddr as usize);
        buf
    }

    /// Write `data` to the target's virtual address space at `vaddr`.
    /// Returns the number of bytes actually written.
    pub fn write_mem(&self, vaddr: u64, data: &[u8]) -> usize {
        use crate::fs::proc_debug::{is_proc_debug_fd, proc_debug_write};
        let bfd = crate::fs::process_fd::proc_fd_backing(self.debugger_pid, self.mem_fd);
        if bfd < 0 {
            return 0;
        }
        let bfd = bfd as usize;
        if !is_proc_debug_fd(bfd) {
            return 0;
        }
        let n = proc_debug_write(bfd, data, vaddr as usize);
        if n < 0 {
            0
        } else {
            n as usize
        }
    }

    // ── registers ────────────────────────────────────────────────────────────

    /// Read the full `user_regs_struct` for the target (x86-64, 27 × u64).
    pub fn read_regs(&self) -> [u64; UREG_COUNT] {
        use crate::fs::proc_debug::{is_proc_debug_fd, proc_debug_read};
        let bfd = crate::fs::process_fd::proc_fd_backing(self.debugger_pid, self.regs_fd);
        let mut regs = [0u64; UREG_COUNT];
        if bfd < 0 {
            return regs;
        }
        let bfd = bfd as usize;
        if !is_proc_debug_fd(bfd) {
            return regs;
        }
        let mut buf = [0u8; UREG_COUNT * 8];
        proc_debug_read(bfd, &mut buf, 0);
        for i in 0..UREG_COUNT {
            regs[i] = u64::from_le_bytes(buf[i * 8..(i + 1) * 8].try_into().unwrap());
        }
        regs
    }

    /// Write a modified `user_regs_struct` back to the target.
    pub fn write_regs(&self, regs: &[u64; UREG_COUNT]) {
        use crate::fs::proc_debug::{is_proc_debug_fd, proc_debug_write};
        let bfd = crate::fs::process_fd::proc_fd_backing(self.debugger_pid, self.regs_fd);
        if bfd < 0 {
            return;
        }
        let bfd = bfd as usize;
        if !is_proc_debug_fd(bfd) {
            return;
        }
        let mut buf = [0u8; UREG_COUNT * 8];
        for i in 0..UREG_COUNT {
            buf[i * 8..(i + 1) * 8].copy_from_slice(&regs[i].to_le_bytes());
        }
        proc_debug_write(bfd, &buf, 0);
    }

    // ── control ──────────────────────────────────────────────────────────────

    /// Send a control command to the target ("stop", "cont", "step").
    pub fn ctl(&self, cmd: &str) {
        use crate::fs::proc_debug::{is_proc_debug_fd, proc_debug_write};
        let bfd = crate::fs::process_fd::proc_fd_backing(self.debugger_pid, self.ctl_fd);
        if bfd < 0 {
            return;
        }
        let bfd = bfd as usize;
        if !is_proc_debug_fd(bfd) {
            return;
        }
        proc_debug_write(bfd, cmd.as_bytes(), 0);
    }

    /// Poll the ctl fd for a stop-reply string ("T<sig>", "running", …).
    pub fn poll_status(&self) -> String {
        use crate::fs::proc_debug::{is_proc_debug_fd, proc_debug_read};
        let bfd = crate::fs::process_fd::proc_fd_backing(self.debugger_pid, self.ctl_fd);
        if bfd < 0 {
            return String::from("none");
        }
        let bfd = bfd as usize;
        if !is_proc_debug_fd(bfd) {
            return String::from("none");
        }
        let mut buf = [0u8; 16];
        let n = proc_debug_read(bfd, &mut buf, 0);
        if n <= 0 {
            return String::from("none");
        }
        String::from_utf8_lossy(&buf[..n as usize]).into_owned()
    }
}

impl Drop for GdbTarget {
    fn drop(&mut self) {
        proc_fd_close(self.debugger_pid, self.mem_fd);
        proc_fd_close(self.debugger_pid, self.regs_fd);
        proc_fd_close(self.debugger_pid, self.ctl_fd);
    }
}
