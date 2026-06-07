//! Minimal userspace service supervisor for the hybrid service plane.

extern crate alloc;

use alloc::{collections::BTreeMap, string::String, vec::Vec};
use spin::Mutex;

use crate::security::{cap, CapSet};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RestartPolicy {
    Never,
    OnExit,
}

#[derive(Clone, Debug)]
pub struct ServiceSpec {
    pub name: String,
    pub path: String,
    pub caps: CapSet,
    pub restart: RestartPolicy,
}

#[derive(Clone, Debug)]
pub struct ServiceState {
    pub spec: ServiceSpec,
    pub pid: Option<usize>,
    pub restart_pending: bool,
    pub last_exit_code: Option<i32>,
}

static SERVICES: Mutex<BTreeMap<String, ServiceState>> = Mutex::new(BTreeMap::new());

/// Construct a capability set suitable for a userspace driver/service.
pub fn driver_service_caps() -> CapSet {
    let mut caps = CapSet::empty();
    caps.permitted = (1u64 << cap::DRIVER) | (1u64 << cap::NET_ADMIN) | (1u64 << cap::NET_RAW);
    caps.effective = caps.permitted;
    caps
}

/// Register service metadata.  This does not move code between kernel and
/// userspace; it records the user's already-chosen userspace services.
pub fn register_service(spec: ServiceSpec) {
    SERVICES.lock().insert(
        spec.name.clone(),
        ServiceState {
            spec,
            pid: None,
            restart_pending: false,
            last_exit_code: None,
        },
    );
}

/// Mark a service as launched by PID 1 after fork/exec succeeds.
pub fn mark_started(name: &str, pid: usize) -> bool {
    if let Some(state) = SERVICES.lock().get_mut(name) {
        state.pid = Some(pid);
        state.restart_pending = false;
        true
    } else {
        false
    }
}

/// Apply the service's declared capabilities to its process.
pub fn apply_capabilities(name: &str, pid: usize) -> bool {
    let caps = match SERVICES.lock().get(name) {
        Some(state) => state.spec.caps,
        None => return false,
    };
    crate::proc::scheduler::with_proc_mut(pid, |pcb, _| {
        pcb.caps = caps;
    })
    .is_some()
}

/// Called from the process exit path before endpoints/schemes are destroyed.
pub fn on_process_exit(pid: usize, code: i32) {
    for state in SERVICES.lock().values_mut() {
        if state.pid == Some(pid) {
            state.pid = None;
            state.last_exit_code = Some(code);
            state.restart_pending = matches!(state.spec.restart, RestartPolicy::OnExit);
        }
    }
}

/// Return restartable services that have exited and need PID 1 to relaunch
/// them.
pub fn pending_restarts() -> Vec<ServiceSpec> {
    SERVICES
        .lock()
        .values()
        .filter(|state| state.restart_pending)
        .map(|state| state.spec.clone())
        .collect()
}

/// Snapshot for `/proc` or diagnostics.
pub fn list_services() -> Vec<ServiceState> {
    SERVICES.lock().values().cloned().collect()
}
