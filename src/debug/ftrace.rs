//! ftrace-style function entry/exit tracing via LLVM `-Z instrument-functions`.
//!
//! When the `trace` Cargo feature is active, rustc is instructed (in
//! `build.rs`) to pass `-Z instrument-functions` to every compilation unit.
//! LLVM then inserts calls to `__cyg_profile_func_enter` / `__cyg_profile_func_exit`
//! at every function prologue and epilogue — the same ABI used by GCC's
//! `-finstrument-functions`.
//!
//! # Recursion guard
//!
//! The hook itself must not be instrumented. A thread-local `TRACING` flag
//! (approximated here with a per-CPU atomic since we have no TLS) prevents
//! the hooks from calling themselves.
//!
//! # Symbol resolution
//!
//! Function pointers are emitted as raw addresses. Resolve them to names at
//! drain time via `crate::debug::oops::resolve_symbol` — **not** inside the
//! hook (hot path must stay minimal).
//!
//! Enabled only when **both** `debug` and `trace` features are active.

#[cfg(all(feature = "debug", feature = "trace"))]
pub mod inner {
    use core::sync::atomic::{AtomicBool, Ordering};
    use super::super::trace::{emit, TraceEvent, TraceKind};

    /// Per-CPU recursion guard. We use a single global bool here; replace with
    /// a per-hart/per-core array once SMP hart-ID helpers are available.
    static IN_HOOK: AtomicBool = AtomicBool::new(false);

    /// Called by LLVM at every function entry when `-Z instrument-functions` is active.
    ///
    /// # Safety
    /// Raw function pointers; must not unwind; must not allocate.
    #[no_mangle]
    #[inline(never)]
    pub unsafe extern "C" fn __cyg_profile_func_enter(
        func:      *const (),
        _callsite: *const (),
    ) {
        // Guard against recursion.
        if IN_HOOK.compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed).is_err() {
            return;
        }
        emit(TraceEvent {
            kind:  TraceKind::FuncEnter,
            id:    0,
            arg:   func as u64,
            ticks: crate::arch::time::read_ticks(),
        });
        IN_HOOK.store(false, Ordering::Release);
    }

    /// Called by LLVM at every function exit when `-Z instrument-functions` is active.
    #[no_mangle]
    #[inline(never)]
    pub unsafe extern "C" fn __cyg_profile_func_exit(
        func:      *const (),
        _callsite: *const (),
    ) {
        if IN_HOOK.compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed).is_err() {
            return;
        }
        emit(TraceEvent {
            kind:  TraceKind::FuncExit,
            id:    0,
            arg:   func as u64,
            ticks: crate::arch::time::read_ticks(),
        });
        IN_HOOK.store(false, Ordering::Release);
    }
}
