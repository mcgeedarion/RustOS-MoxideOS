//! Scheme registration syscalls for userspace service servers.

extern crate alloc;

use alloc::{collections::BTreeMap, string::String, sync::Arc, vec::Vec};
use scheme_api::IpcEndpoint;
use spin::Mutex;

use crate::{
    fs::{ipc_proxy_scheme::IpcProxyScheme, scheme_table::SCHEME_TABLE},
    security::{cap, CapSet},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i64)]
pub enum SchemeSysError {
    PermissionDenied = -1,
    InvalidName = -2,
    AlreadyExists = -3,
    NotFound = -4,
    BadAddress = -14,
}

impl SchemeSysError {
    #[inline]
    fn as_isize(self) -> isize {
        self as i64 as isize
    }
}

#[derive(Clone, Debug)]
struct SchemeOwner {
    pid: usize,
    endpoint: IpcEndpoint,
}

static SCHEME_OWNERS: Mutex<BTreeMap<String, SchemeOwner>> = Mutex::new(BTreeMap::new());

#[inline]
fn current_pid() -> usize {
    crate::proc::scheduler::current_pid() as usize
}

fn current_caps() -> CapSet {
    crate::proc::scheduler::with_proc(current_pid(), |p| p.caps).unwrap_or_else(CapSet::empty)
}

fn has_driver_capability() -> bool {
    let caps = current_caps();
    caps.has(cap::DRIVER) || caps.has(cap::SYS_ADMIN)
}

fn valid_scheme_name(name: &str) -> bool {
    !name.is_empty()
        && !name.contains(':')
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

pub fn sys_scheme_register(name: &str, endpoint: IpcEndpoint) -> Result<(), SchemeSysError> {
    if !has_driver_capability() {
        return Err(SchemeSysError::PermissionDenied);
    }
    if !valid_scheme_name(name) {
        return Err(SchemeSysError::InvalidName);
    }
    if !crate::ipc::endpoint_owned_by_current(endpoint) {
        return Err(SchemeSysError::PermissionDenied);
    }

    let pid = current_pid();
    {
        let mut owners = SCHEME_OWNERS.lock();
        if let Some(owner) = owners.get(name) {
            if owner.pid != pid {
                return Err(SchemeSysError::AlreadyExists);
            }
        }
        owners.insert(String::from(name), SchemeOwner { pid, endpoint });
    }

    SCHEME_TABLE.register(
        name,
        Arc::new(IpcProxyScheme::with_endpoint(name, endpoint)),
    );
    Ok(())
}

pub fn sys_scheme_unregister(name: &str) -> Result<(), SchemeSysError> {
    let pid = current_pid();
    let mut owners = SCHEME_OWNERS.lock();
    match owners.get(name) {
        Some(owner) if owner.pid == pid => {},
        _ => return Err(SchemeSysError::NotFound),
    }
    owners.remove(name);
    SCHEME_TABLE.unregister(name);
    Ok(())
}

pub fn cleanup_pid(pid: usize) {
    let names: Vec<String> = SCHEME_OWNERS
        .lock()
        .iter()
        .filter_map(|(name, owner)| (owner.pid == pid).then(|| name.clone()))
        .collect();

    for name in names {
        SCHEME_OWNERS.lock().remove(&name);
        SCHEME_TABLE.unregister(&name);
    }
}

fn copy_scheme_name(name_ptr: usize, name_len: usize) -> Result<String, SchemeSysError> {
    if name_len == 0 || name_len > 64 || !crate::uaccess::validate_user_ptr(name_ptr, name_len) {
        return Err(SchemeSysError::BadAddress);
    }
    let mut bytes = alloc::vec![0u8; name_len];
    crate::uaccess::copy_from_user(bytes.as_mut_ptr(), name_ptr, name_len)
        .map_err(|_| SchemeSysError::BadAddress)?;
    core::str::from_utf8(&bytes)
        .map(String::from)
        .map_err(|_| SchemeSysError::InvalidName)
}

pub fn dispatch_scheme_register(name_ptr: usize, name_len: usize, endpoint: u64) -> isize {
    let name = match copy_scheme_name(name_ptr, name_len) {
        Ok(name) => name,
        Err(e) => return e.as_isize(),
    };
    sys_scheme_register(&name, IpcEndpoint(endpoint))
        .map(|_| 0)
        .unwrap_or_else(|e| e.as_isize())
}

pub fn dispatch_scheme_unregister(name_ptr: usize, name_len: usize) -> isize {
    let name = match copy_scheme_name(name_ptr, name_len) {
        Ok(name) => name,
        Err(e) => return e.as_isize(),
    };
    sys_scheme_unregister(&name)
        .map(|_| 0)
        .unwrap_or_else(|e| e.as_isize())
}
