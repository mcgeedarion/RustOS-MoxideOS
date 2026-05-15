//! UTS namespace  —  hostname and NIS domainname isolation.
//!
//! ## Linux syscall semantics modelled
//!
//!   clone(CLONE_NEWUTS) / unshare(CLONE_NEWUTS)
//!   sethostname(2) / gethostname(2)
//!   setdomainname(2) / getdomainname(2)
//!   uname(2) — reads from the calling process's UtsNs

extern crate alloc;
use crate::security::ns::alloc_ns_id;
use alloc::{string::String, sync::Arc};
use spin::Mutex;

/// Maximum length of hostname / domainname (matches Linux HOST_NAME_MAX = 64).
pub const HOST_NAME_MAX: usize = 64;

/// The utsname fields exposed to userspace via `uname(2)`.
#[derive(Clone)]
pub struct Utsname {
    pub sysname: String,    // "Linux"
    pub nodename: String,   // hostname
    pub release: String,    // kernel version string
    pub version: String,    // build timestamp / extra info
    pub machine: String,    // "x86_64" | "riscv64"
    pub domainname: String, // NIS domainname
}

impl Utsname {
    fn default_init() -> Self {
        Utsname {
            sysname: String::from("Linux"),
            nodename: String::from("rustos"),
            release: String::from("6.1.0-rustos"),
            version: String::from("#1 SMP 2026"),
            machine: String::from(if cfg!(target_arch = "x86_64") {
                "x86_64"
            } else {
                "riscv64"
            }),
            domainname: String::from("(none)"),
        }
    }
}

pub struct UtsNs {
    pub id: u64,
    inner: Mutex<Utsname>,
}

impl UtsNs {
    pub fn new_init() -> Self {
        UtsNs {
            id: alloc_ns_id(),
            inner: Mutex::new(Utsname::default_init()),
        }
    }

    pub fn copy_of(parent: &Arc<UtsNs>) -> Self {
        let u = parent.inner.lock().clone();
        UtsNs {
            id: alloc_ns_id(),
            inner: Mutex::new(u),
        }
    }

    // ── sethostname(2) ──────────────────────────────────────────────────────

    /// Set hostname.  Returns EINVAL if `name` exceeds HOST_NAME_MAX.
    pub fn set_hostname(&self, name: &str) -> Result<(), isize> {
        if name.len() > HOST_NAME_MAX {
            return Err(-22);
        }
        self.inner.lock().nodename = String::from(name);
        Ok(())
    }

    pub fn hostname(&self) -> String {
        self.inner.lock().nodename.clone()
    }

    // ── setdomainname(2) ────────────────────────────────────────────────────

    pub fn set_domainname(&self, name: &str) -> Result<(), isize> {
        if name.len() > HOST_NAME_MAX {
            return Err(-22);
        }
        self.inner.lock().domainname = String::from(name);
        Ok(())
    }

    pub fn domainname(&self) -> String {
        self.inner.lock().domainname.clone()
    }

    // ── uname(2) ────────────────────────────────────────────────────────────

    /// Fill a caller-provided `Utsname` snapshot (for uname(2)).
    pub fn uname(&self) -> Utsname {
        self.inner.lock().clone()
    }

    /// Override the kernel release string (useful for containers to report
    /// a different kernel version than the host).
    pub fn set_release(&self, release: &str) {
        self.inner.lock().release = String::from(release);
    }
}
