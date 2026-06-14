# Game Plan: Scheduler & Process Fixes for Issue #82

This plan outlines the remaining scheduler and process-related bugs from issue #82 and describes the high-level changes needed to resolve them. Each item refers back to its description in the issue.

## Tasks

1. **MmReadGuard use-after-free** (`src/proc/scheduler.rs`): reorder the fields in `MmReadGuard` so that the `RwLockReadGuard` is dropped before the `Arc`, preventing a use-after-free.

2. **Remote RunQueue mutation without synchronisation** (`src/proc/scheduler.rs`): protect each CPU’s `RunQueue` with a spinlock or try-lock to ensure that `load_balance` does not concurrently mutate a remote queue.

3. **Misaligned stack pointer in clone** (`src/proc/clone.rs`): adjust `user_sp` to be 16‑byte aligned as required by the x86‑64 ABI when `clone3` is called with a custom stack.

4. **Incorrect `waitpid(0, …)` semantics** (`src/proc/wait.rs`): update `matches_pid` so that a pid of 0 only matches children in the caller’s process group.

5. **Cold‑start vruntime spike** (`src/proc/scheduler.rs`): initialise `curr_vruntime_start` to the current time during scheduler init or clamp the first `elapsed` value to `TICK_NS`.

6. **Wrong target for reschedule IPI** (`src/proc/scheduler.rs`): when stealing a task in `load_balance`, send the reschedule IPI to `busiest_cpu` rather than `this_cpu`.

7. **Busy-spin on zombies under `WNOWAIT`** (`src/proc/wait.rs`): return immediately after reporting a zombie when `WNOWAIT` is specified to avoid spinning on the same zombie.

8. **Round-robin timeslice measured from the wrong time** (`src/proc/scheduler.rs`): track a separate `rr_slice_start` timestamp that is only reset on actual context-switch.

9. **CFS wake-up lag bound** (`src/proc/scheduler.rs`): limit `vruntime` clamping on wake-up using `max(task.vruntime, min_vruntime - MAX_LAG_NS)` as Linux does.
