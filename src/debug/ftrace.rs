//! ftrace-style function entry/exit tracing via LLVM `-Z instrument-functions`.
//!
//! When the `trace` Cargo feature is active, rustc is instructed (in
//! `build.rs`) to pass `-Z instrument-functions` to every compilation unit.
//! LLVM then inserts calls to `__cyg_profile_func_enter` /
//! `__cyg_profile_func_exit` at every function prologue and epilogue — the same
//! ABI used by GCC's `-finstrument-functions`.
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
    use super::super::trace::{drain_last_n as ring_drain_last_n, emit, TraceEvent, TraceKind};
    use core::sync::atomic::{AtomicBool, Ordering};

    /// Per-CPU recursion guard. We use a single global bool here; replace with
    /// a per-hart/per-core array once SMP hart-ID helpers are available.
    static IN_HOOK: AtomicBool = AtomicBool::new(false);

    /// Called by LLVM at every function entry when `-Z instrument-functions` is
    /// active.
    ///
    /// # Safety
    /// Raw function pointers; must not unwind; must not allocate.
    #[no_mangle]
    #[inline(never)]
    pub unsafe extern "C" fn __cyg_profile_func_enter(func: *const (), _callsite: *const ()) {
        // Guard against recursion.
        if IN_HOOK
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            return;
        }
        emit(TraceEvent {
            kind: TraceKind::FuncEnter,
            id: 0,
            arg: func as u64,
            ticks: crate::arch::time::read_ticks(),
        });
        IN_HOOK.store(false, Ordering::Release);
    }

    /// Called by LLVM at every function exit when `-Z instrument-functions` is
    /// active.
    #[no_mangle]
    #[inline(never)]
    pub unsafe extern "C" fn __cyg_profile_func_exit(func: *const (), _callsite: *const ()) {
        if IN_HOOK
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            return;
        }
        emit(TraceEvent {
            kind: TraceKind::FuncExit,
            id: 0,
            arg: func as u64,
            ticks: crate::arch::time::read_ticks(),
        });
        IN_HOOK.store(false, Ordering::Release);
    }

    /// Drain the last `n` function-trace events (FuncEnter / FuncExit only),
    /// calling `f` for each in chronological order.
    ///
    /// This is a filtered view over the shared trace ring — it does **not**
    /// advance the consumer cursor, so `trace::drain` still sees all events.
    /// Intended for crash/oops output to show the call history leading up to
    /// the fault.
    pub fn drain_last_n(n: usize, mut f: impl FnMut(&TraceEvent)) {
        ring_drain_last_n(n, |ev| {
            if matches!(ev.kind, TraceKind::FuncEnter | TraceKind::FuncExit) {
                f(ev);
            }
        });
    }
}

// Public re-exports: when the feature gate is active, expose inner::drain_last_n
// at the module level so callers can write `crate::debug::ftrace::drain_last_n`.
#[cfg(all(feature = "debug", feature = "trace"))]
pub use inner::drain_last_n;

/// Stub for builds without `debug` + `trace` features active, so call-sites in
/// `oops.rs` compile unconditionally under `#[cfg(feature = "trace")]`.
#[cfg(not(all(feature = "debug", feature = "trace")))]
#[inline(always)]
pub fn drain_last_n(_n: usize, _f: impl FnMut(&crate::debug::trace::TraceEvent)) {}
