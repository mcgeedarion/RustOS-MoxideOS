# RustOS Design Optimization Suggestions (Actionable v2)

This revision turns the prior add/move/delete ideas into a concrete plan with:
- immediate low-risk cleanups,
- explicit candidates found in the current tree,
- sequencing to avoid large destabilizing refactors.

## Snapshot: Concrete opportunities observed

### Naming / placement mismatches to fix first

1. **`src/drivers/net/virtio_blk.rs` appears miscategorized**
   - `virtio_blk` is a block concept but currently sits in the net driver tree.
   - Action: move to `src/drivers/block/` or delete if dead after reference audit.

2. **Two block-oriented trees exist (`src/block/*` and `src/drivers/block/*`)**
   - This makes ownership and layering unclear (service layer vs hardware backend).
   - Action: codify one as hardware backend and one as generic block service.

3. **Potentially overlapping COW/fault ownership**
   - COW/fault logic exists in `src/mm/cow_fault.rs`, `src/mm/mmap/fault.rs`, and `src/proc/cow_fault.rs`.
   - Action: set `mm` as the sole fault-policy owner and make `proc` call a stable `mm` API.

4. **VFS surface appears fragmented**
   - `src/fs/vfs.rs`, `src/fs/vfs_ops.rs`, `src/fs/vfs_extras.rs`, `src/fs/vfs_uring.rs` indicate layering drift.
   - Action: define one public VFS façade and merge/remove thin pass-through wrappers.

## Add

1. **Architecture capability matrix (`docs/arch_capability_matrix.md`)**
   - Track x86_64 vs riscv64 parity for boot, trap/irq, paging, syscall ABI, SMP, timers.
   - Suggested columns:
     - subsystem,
     - x86_64 status,
     - riscv64 status,
     - test coverage,
     - owner,
     - risk/notes.

2. **Syscall conformance matrix + generators**
   - Add a source-of-truth syscall expectation table and generate:
     - positive behavior tests,
     - errno/negative tests (EINVAL/ENOSYS/EFAULT),
     - ABI-width edge tests.
   - Start with high-churn families: fs, proc, mmap, signal, socket.

3. **`xtask` performance baseline workflow**
   - Add `cargo xtask bench-kernel` that runs:
     - boot smoke,
     - scheduler latency test,
     - pipe throughput test,
     - mmap fault microbench.
   - Store benchmark output with machine + config metadata for comparability.

4. **Subsystem ownership map (`docs/owners.md`)**
   - Create explicit maintainership for `mm/proc/fs/net/drivers/arch`.
   - Add backup reviewer and escalation path per subsystem.

5. **Feature-gating for heavyweight optional components**
   - Gate lower-priority subsystems (e.g., experimental fs/drivers) to reduce CI/build time.
   - Rule: features default off until test coverage and support maturity pass threshold.

## Move

1. **Networking layering reorganization (incremental, not big-bang)**
   - Target shape:
     - `src/net/l2` (eth/arp),
     - `src/net/l3` (ipv4/ipv6/icmp/icmpv6),
     - `src/net/l4` (tcp/udp),
     - `src/net/socket` (POSIX/user ABI façade).
   - Execute with adapter modules first, then internal path moves.

2. **Block stack boundary clarification**
   - `src/drivers/block/*`: hardware/device backends.
   - `src/block/*`: queueing, request model, generic block service contracts.
   - Add module docs describing allowed dependency direction.

3. **Init path phase split**
   - Normalize init pipeline into:
     - `early_boot` (arch bring-up),
     - `kernel_init` (common subsystems),
     - `userspace_handoff` (initramfs/init process handoff).
   - Keep per-arch entry stubs thin.

4. **Security tree restructuring**
   - Split `src/security/*` into policy vs mechanism buckets:
     - `policy/` (DAC, LSM, cap checks, seccomp policies),
     - `isolation/` (namespaces/cgroups integration points),
     - `hw_hardening/` (SMEP/SMAP/PTI/canary/aslr low-level hooks).

## Delete / Merge

1. **Delete stale or duplicate modules after reference audit**
   - Use reference checks before deletion (`rg` callsites + `mod` graph checks).
   - Start with misnamed/misplaced candidates.

2. **Merge duplicate COW/fault decision paths**
   - Keep one policy engine in `mm`; route process-level callsites through that API.

3. **Collapse redundant VFS wrappers**
   - Merge files that only re-export or forward without adding invariants.
   - Keep one canonical location for each concern: API, ops, async integration.

4. **Reduce silent stubs**
   - Make ENOSYS behavior explicit and table-driven instead of scattered stubs.
   - Add CI check that no newly introduced syscall stub lacks tracking metadata.

## Execution roadmap (safer order)

### Phase 0 (1 week): visibility and guardrails
- Add `docs/arch_capability_matrix.md` template.
- Add `docs/owners.md`.
- Add lightweight module-lint in `xtask`:
  - duplicate basename detector,
  - oversized module warning,
  - missing module-level docs warning.

### Phase 1 (1–2 weeks): low-risk cleanup
- Fix miscategorized files and naming issues.
- Remove dead wrappers/stubs with strict compile/test validation per change.

### Phase 2 (2–3 weeks): structural moves with compatibility shims
- Network + block layout refactor via intermediate re-export modules.
- Preserve external callsites until final cutover.

### Phase 3 (ongoing): regression prevention
- Enable syscall conformance table-driven tests.
- Enable `xtask` perf baselines in CI periodic jobs.
- Review arch parity dashboard each release.

## What to add, move, delete (short answer)

### Add now
- `docs/arch_capability_matrix.md`
- `docs/owners.md`
- `xtask` module-lint + bench harness skeleton
- syscall expectation table + first generated tests

### Move next
- `src/drivers/net/virtio_blk.rs` to block domain (or delete if unused)
- clarify `src/block` vs `src/drivers/block` responsibilities
- gradual `src/net` layering split (l2/l3/l4 + socket façade)

### Delete when verified
- stale miscategorized modules
- duplicate COW/fault policy branches
- thin VFS forwarding wrappers
- untracked syscall stubs
