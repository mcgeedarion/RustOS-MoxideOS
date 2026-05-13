//! Scheme registration syscall — allows a userspace driver process to
//! publish itself as the handler for a named scheme prefix.
//!
//! # Syscall number (provisional)
//!
//! | Number | Name                  |
//! |--------|-----------------------|
//! | 403    | `sys_scheme_register` |
//! | 404    | `sys_scheme_unregister` |
//!
//! # Flow
//!
//! 1. Driver starts, initialises hardware via its `DriverHandle`.
//! 2. Driver creates an IPC endpoint: `ep = sys_ipc_endpoint_create()`.
//! 3. Driver calls `sys_scheme_register("blk", ep)`.
//! 4. Kernel wraps `ep` in an `IpcProxyScheme` and inserts it into
//!    `SCHEME_TABLE` under the key `"blk"`.
//! 5. Any process that calls `open("blk:vda", ...)` now routes through
//!    the driver transparently.
//! 6. When the driver exits (or calls `sys_scheme_unregister`), the
//!    kernel removes the entry; subsequent opens return `ENOENT`.

use alloc::sync::Arc;

use scheme_api::IpcEndpoint;

use crate::{
    proc::current_process,
    kernel::capabilities::Capability,
    fs::{
        scheme_table::SCHEME_TABLE,
        ipc_proxy_scheme::IpcProxyScheme,
    },
};

/// Error codes for scheme syscalls.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i64)]
pub enum SchemeSysError {
    /// Caller does not hold `CAP_DRIVER` (required to register a scheme).
    PermissionDenied = -1,
    /// `name` contains illegal characters or is empty.
    InvalidName      = -2,
    /// A scheme with this name is already registered by a different process.
    AlreadyExists    = -3,
    /// No scheme with this name is registered by the calling process.
    NotFound         = -4,
}

// ---------------------------------------------------------------------------
// sys_scheme_register
// ---------------------------------------------------------------------------

/// Register `endpoint` as the handler for scheme `name`.
///
/// After this returns, any `open("<name>:...", ...)` call anywhere in the
/// system is forwarded to the calling driver process via `endpoint`.
///
/// Only one process may own a given scheme name at a time.  Attempting to
/// register a name already owned by a *different* process returns
/// `AlreadyExists`; a process may re-register the same name to replace
/// its endpoint (e.g. after a restart).
///
/// # Arguments
/// - `name`     — scheme prefix, e.g. `"blk"` or `"net"`.  ASCII
///               alphanumeric + `_` + `-` only; must not contain `':'`.
/// - `endpoint` — IPC endpoint that will receive `SchemeRequest` messages.
pub fn sys_scheme_register(
    name:     &str,
    endpoint: IpcEndpoint,
) -> Result<(), SchemeSysError> {
    let proc = current_process();

    // Only privileged (driver) processes may publish schemes.
    if !proc.capabilities().has(Capability::Driver) {
        return Err(SchemeSysError::PermissionDenied);
    }

    // Validate the name.
    if name.is_empty()
        || name.contains(':')
        || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    {
        return Err(SchemeSysError::InvalidName);
    }

    // Build the proxy and register it.
    let proxy = Arc::new(IpcProxyScheme::new(name, endpoint));
    SCHEME_TABLE.register(name, proxy);

    // Record the association in the process descriptor so the kernel can
    // auto-unregister the scheme when the process exits.
    proc.register_owned_scheme(alloc::string::String::from(name));

    log::info!("[scheme] process {} registered scheme \"{}\"\n",
               proc.pid(), name);
    Ok(())
}

// ---------------------------------------------------------------------------
// sys_scheme_unregister
// ---------------------------------------------------------------------------

/// Remove a scheme previously registered by the calling process.
///
/// After this returns, `open("<name>:...")` will return `ENOENT` until
/// another process registers the same name.
///
/// The kernel also calls this automatically from the process exit path.
pub fn sys_scheme_unregister(name: &str) -> Result<(), SchemeSysError> {
    let proc = current_process();

    // Verify the calling process actually owns this scheme.
    if !proc.owns_scheme(name) {
        return Err(SchemeSysError::NotFound);
    }

    SCHEME_TABLE.unregister(name);
    proc.unregister_owned_scheme(name);

    log::info!("[scheme] process {} unregistered scheme \"{}\"\n",
               proc.pid(), name);
    Ok(())
}
