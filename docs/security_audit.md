# Security audit notes

This document records the current identity/security attack surface found while
reviewing the kernel security code.  It is intentionally concrete: every item
contains an exploit route and the mitigation status so regressions can be
triaged quickly.

## Fixed in this patch

### LSM current-credential snapshots referenced a stale PCB layout

* **Route:** any call path using `LsmCtx::for_current_task()` attempted to read
  `p.creds.euid`, `p.creds.egid`, and `p.creds.caps_effective`, but the live
  process control block stores these as `p.euid`, `p.egid`, and
  `p.caps.effective`.
* **Impact:** LSM hooks could not reliably construct current-task security
  contexts.  Depending on build configuration this is either a hard build break
  or a fail-open risk if a later compatibility shim introduced default/root
  credentials.
* **Mitigation:** `for_current_task()` now snapshots the live PCB credential
  fields and carries supplemental groups into the LSM context.

### DAC group checks ignored supplemental groups

* **Route:** create a file or IPC object owned by a group that is present only in
  the caller's supplemental group list, then access it through a DAC hook.
* **Impact:** group permissions were evaluated only against `egid`; legitimate
  group members fell through to the `other` mode bits.  This is primarily an
  authorization correctness bug, and it can become a security bug when policy
  assumes group-only access is consistently enforced across kernel subsystems.
* **Mitigation:** DAC file and IPC checks now treat `egid` and all supplemental
  groups as group membership.

## Open high-risk findings

### Signal syscalls need end-to-end credential checks

* **Route:** user process calls `tkill` or `tgkill` against another task ID.
  The current thread syscall wrappers directly enqueue the signal after checking
  only target existence/range.
* **Impact:** cross-UID denial of service via `SIGKILL`/`SIGSTOP`, and possible
  process manipulation via other signals.
* **Expected mitigation:** centralize `kill`/`tkill`/`tgkill` authorization with
  Linux-style rules: allow same real/effective/saved UID or `CAP_KILL`; keep
  signal `0` as an existence/permission probe; dispatch the LSM `TaskKill` hook
  before enqueue.

### Credential-changing syscalls bypass the LSM hook layer

* **Route:** call `setuid`, `setgid`, `setresuid`, `setresgid`, `setreuid`, or
  `setregid` directly.  These functions enforce local POSIX-like checks but do
  not call `Hook::TaskSetuid` or `Hook::TaskSetgid`.
* **Impact:** future MAC/LSM modules cannot deny identity transitions, and the
  existing DAC module's capability-aware `task_setuid`/`task_setgid` hooks are
  dead code.
* **Expected mitigation:** invoke the task identity hooks after syscall argument
  normalization and before mutating the PCB, with enough context for saved-ID
  restore cases.

### File-open authorization must account for requested access mode

* **Route:** open a path for write through a call path that dispatches only
  `Hook::FileOpen`.  The DAC module's `file_open()` currently checks read
  permission unconditionally.
* **Impact:** if VFS integration relies on `FileOpen` as the sole access check,
  write-only or read-write opens may be authorized by read bits alone.
* **Expected mitigation:** plumb normalized open flags into `LsmCtx::flags` and
  have `file_open()` check read, write, append/truncate, and execute/search
  requirements according to the requested mode.
