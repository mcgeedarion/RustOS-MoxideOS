# Game Plan: Futex & Signal Fixes for Issue #82

This document details the remaining futex and signal handling bugs from issue #82 and the high-level fixes needed.

## Tasks

1. **Non‑atomic compare‑and‑swap in `futex_lock_pi`** (`src/proc/futex.rs`): replace the read‑then‑write sequence with a hardware CAS or re‑validate the value immediately before writing to ensure atomicity.

2. **`FUTEX_REQUEUE` waiters sleep on wrong `WaitQueue`** (`src/proc/futex.rs`): when requeuing waiters from one futex to another, re-register each waiter on the destination queue or hand the tasks off so that they wake up on `uaddr2`.

3. **Signal handlers keyed by PID instead of TGID** (`src/proc/signal.rs`): normalise the key used in `SIGACTIONS` so that handlers are stored and looked up by thread‑group ID (TGID), not by individual thread ID.

4. **`push_sigframe_x86` clobbers registers** (`src/proc/signal.rs`): save `r8`, `r9`, `r10`, and `r11` in `SyscallFrame` on syscall entry and restore them when constructing the signal frame.

5. **`apply_default` SIGSTOP does not update `state_atom`** (`src/proc/signal.rs`): use `pl.set_state(&mut inner, State::Stopped)` within a `with_proc_mut` closure to update both `state` and `state_atom`.

6. **Lost wake‑ups in `futex_wait_bitset`** (`src/proc/futex.rs`): introduce a prepare‑to‑wait step on the futex’s `WaitQueue` so that a wake arriving between the value check and the call to `wait()` is still visible.
