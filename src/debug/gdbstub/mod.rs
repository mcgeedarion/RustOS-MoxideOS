// GDB stub — canonical implementation lives here.

pub mod breakpoints;
pub mod rsp;
pub mod rsp_aarch64;
pub mod rsp_riscv;
pub mod rsp_x86_64;
pub mod serial;
pub mod session;
pub mod target;

use spin::Mutex;

/// Minimal trap-register marker used by architecture exception handlers.
///
/// The concrete register layout is architecture-specific; handlers pass their
/// native interrupt frame pointer through this opaque type until the full GDB
/// stop-reply path is wired.
#[repr(C)]
pub struct SavedRegs {
    _private: [u8; 0],
}

/// Architecture-independent trap handoff hook.
///
/// Architecture trap code can call `gdb_trap(regs, pid)`. The active GDB
/// session/debug target installs a hook with `set_trap_handler`; if no session
/// is attached, the trap is ignored and normal exception routing can continue.
pub type TrapHandler = fn(regs: *mut SavedRegs, pid: usize);

static TRAP_HANDLER: Mutex<Option<TrapHandler>> = Mutex::new(None);

pub fn set_trap_handler(handler: TrapHandler) {
    *TRAP_HANDLER.lock() = Some(handler);
}

pub fn clear_trap_handler() {
    *TRAP_HANDLER.lock() = None;
}

pub fn gdb_trap(regs: *mut SavedRegs, pid: usize) {
    let handler = *TRAP_HANDLER.lock();

    if let Some(handler) = handler {
        handler(regs, pid);
    }
}