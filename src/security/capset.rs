//! Capability set  (Linux-compatible 64-bit bitmask per UAPI v3).
//!
//! Each process owns one `CapSet` with three masks:
//!   - `permitted`   — the ceiling of what the thread may ever have
//!   - `effective`   — capabilities actively enforced right now
//!   - `inheritable` — preserved across execve when the binary has them
//!
//! ## Linux capability constants
//!
//! The constants below match `linux/capability.h` (CAP_* values 0-40+).
//! All 64 bits of the bitmask are reserved; unused high bits are zeroed.

#[derive(Clone, Copy, Default, Debug)]
pub struct CapSet {
    pub permitted: u64,
    pub effective: u64,
    pub inheritable: u64,
}

pub mod cap {
    pub const CHOWN: u8 = 0;
    pub const DAC_OVERRIDE: u8 = 1;
    pub const DAC_READ_SEARCH: u8 = 2;
    pub const FOWNER: u8 = 3;
    pub const FSETID: u8 = 4;
    pub const KILL: u8 = 5;
    pub const SETGID: u8 = 6;
    pub const SETUID: u8 = 7;
    pub const SETPCAP: u8 = 8;
    pub const LINUX_IMMUTABLE: u8 = 9;
    pub const NET_BIND_SERVICE: u8 = 10;
    pub const NET_BROADCAST: u8 = 11;
    pub const NET_ADMIN: u8 = 12;
    pub const NET_RAW: u8 = 13;
    pub const IPC_LOCK: u8 = 14;
    pub const IPC_OWNER: u8 = 15;
    pub const SYS_MODULE: u8 = 16;
    pub const SYS_RAWIO: u8 = 17;
    pub const SYS_CHROOT: u8 = 18;
    pub const SYS_PTRACE: u8 = 19;
    pub const SYS_PACCT: u8 = 20;
    pub const SYS_ADMIN: u8 = 21;
    pub const SYS_BOOT: u8 = 22;
    pub const SYS_NICE: u8 = 23;
    pub const SYS_RESOURCE: u8 = 24;
    pub const SYS_TIME: u8 = 25;
    pub const SYS_TTY_CONFIG: u8 = 26;
    pub const MKNOD: u8 = 27;
    pub const LEASE: u8 = 28;
    pub const AUDIT_WRITE: u8 = 29;
    pub const AUDIT_CONTROL: u8 = 30;
    pub const SETFCAP: u8 = 31;
    pub const MAC_OVERRIDE: u8 = 32;
    pub const MAC_ADMIN: u8 = 33;
    pub const SYSLOG: u8 = 34;
    pub const WAKE_ALARM: u8 = 35;
    pub const BLOCK_SUSPEND: u8 = 36;
    pub const AUDIT_READ: u8 = 37;
    pub const PERFMON: u8 = 38;
    pub const BPF: u8 = 39;
    pub const CHECKPOINT_RESTORE: u8 = 40;
}

impl CapSet {
    /// `CapSet` with all capabilities — used for kernel-internal operations
    /// and uid-0 processes in the initial user namespace.
    pub const fn all() -> Self {
        CapSet {
            permitted: u64::MAX,
            effective: u64::MAX,
            inheritable: 0,
        }
    }

    /// Empty `CapSet` — unprivileged starting point.
    pub const fn empty() -> Self {
        CapSet {
            permitted: 0,
            effective: 0,
            inheritable: 0,
        }
    }

    /// Check whether `cap` is in the effective set.
    #[inline]
    pub fn has(&self, cap: u8) -> bool {
        self.effective & (1u64 << cap) != 0
    }

    /// Raise `cap` in effective (only if it is in permitted).
    #[inline]
    pub fn raise(&mut self, cap: u8) -> Result<(), &'static str> {
        let bit = 1u64 << cap;
        if self.permitted & bit == 0 {
            return Err("not permitted");
        }
        self.effective |= bit;
        Ok(())
    }

    /// Drop `cap` from effective.
    #[inline]
    pub fn drop_cap(&mut self, cap: u8) {
        self.effective &= !(1u64 << cap);
    }

    /// Drop `cap` from permitted and effective (irreversible).
    #[inline]
    pub fn drop_permitted(&mut self, cap: u8) {
        let bit = !(1u64 << cap);
        self.permitted &= bit;
        self.effective &= bit;
    }

    /// execve capability transformation — RFC 2.6.24+ Linux semantics.
    ///
    /// Variables:
    ///   P  = process set (self)        F  = file capability set
    ///   P' = new process set after execve
    ///
    /// Correct formulae (matches dac.rs and Linux kernel):
    ///   P'(permitted)   = (F(permitted) & P(permitted))
    ///                   | (F(inheritable) & P(inheritable))
    ///   P'(effective)   = P'(permitted) & (F(permitted) | P(inheritable))
    ///   P'(inheritable) = P(inheritable) & F(inheritable)
    ///
    /// The old formula used `(file_permitted | file_inheritable) &
    /// self.permitted` for new_permitted, which was over-broad: it let
    /// F(inheritable) bypass the P(inheritable) gate, allowing privilege
    /// escalation to capabilities the process never held in its own
    /// inheritable set.
    pub fn exec_transform(&self, file_permitted: u64, file_inheritable: u64) -> Self {
        // P1 fix: use the correct two-term formula, aligning with dac.rs.
        // Previously: new_permitted = (file_permitted | file_inheritable) &
        // self.permitted That allowed F(inheritable) to grant capabilities not
        // in P(inheritable), diverging from dac.rs and creating a
        // privilege-escalation race depending on which call path reached execve
        // first.
        let proc_permitted = self.permitted;
        let proc_inheritable = self.inheritable;

        let new_permitted =
            (file_permitted & proc_permitted) | (file_inheritable & proc_inheritable);
        let new_effective = new_permitted & (file_permitted | proc_inheritable);
        let new_inheritable = proc_inheritable & file_inheritable;
        CapSet {
            permitted: new_permitted,
            effective: new_effective,
            inheritable: new_inheritable,
        }
    }

    /// True if all three masks are zero.
    pub fn is_empty(&self) -> bool {
        self.permitted == 0 && self.effective == 0 && self.inheritable == 0
    }
}
