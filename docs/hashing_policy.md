# Hashing policy and performance audit

This kernel now provides `KernelFastMap`, a small FxHash-style hash table for
trusted, bounded, kernel-internal keys. Most keyed registries still use
`BTreeMap`, and the remaining "hash-like" code paths are protocol or integrity
checksums. If a future change converts another registry from `BTreeMap` to a fast
hash table, use the policy below to choose the map.

## Rule of thumb

Use a fast, non-cryptographic hash such as `KernelFastMap`, `FxHash`, or `AHash`
only when all of the following are true:

1. The key is kernel-generated, bounded, or otherwise not chosen in bulk by an
   untrusted user or network peer.
2. Hash collision patterns cannot be used to deny service to a shared kernel
   resource.
3. The hash output is never used for authentication, authorization, address
   randomization, stack canaries, secret generation, persistent integrity, or a
   wire-format checksum.
4. Iteration order is not part of an ABI or user-visible deterministic output.

Prefer a collision-resistant or randomized hasher, or keep `BTreeMap`, whenever
keys are attacker-controlled strings, paths, socket names, namespace names,
packet fields, or other externally supplied values that can be sprayed in bulk.
Never replace cryptographic/security randomness or required protocol checksums
with `KernelFastMap`/`FxHash`/`AHash`.

## Good candidates for fast hashing

These areas are performance-sensitive and are normally non-security-critical if
the key remains a small numeric kernel handle rather than attacker-controlled
bytes:

| Area | Current examples | Why it can be safe |
| --- | --- | --- |
| File-descriptor and synthetic descriptor tables | `RAW_FDS`, `PROC_FD_TABLES`, timerfd/pidfd/proc-debug fd tables, scheme fd maps, pipe tables, eventfd/procfs tables | Keys are kernel-assigned descriptor numbers or process ids; values are protected by kernel synchronization. Several of these now use `KernelFastMap`. |
| Scheduler/process bookkeeping | task-group maps, per-pid restart blocks, signal queues, itimer tables | Keys are kernel process or group ids; collision attacks are not the security boundary. |
| Futex and wait bookkeeping | futex table and priority-inheritance records keyed by normalized futex addresses | The lookup is a synchronization accelerator; do not hash raw unvalidated user bytes. |
| In-memory filesystem caches | dcache `(parent, name)` cache, tmpfs/ramfs inode-number maps, mount tables with trusted/generated names | Numeric inode keys are safe; path/name keys need the caution below because names can be user supplied. |
| Network neighbor/session caches | NDP/ARP-style caches and socket fd registries keyed by parsed addresses or numeric handles | Suitable only when packet parsing and rate limits prevent untrusted peers from forcing unbounded hash state. |
| Debug and tracing registries | ftrace/debug fd/session state | Debug-only or developer-controlled state is not a security boundary. |
| Build tooling | `xtask` host-side grouping maps | Host build-time performance only; not part of the kernel attack surface. |

## Keep security-oriented or deterministic code out of fast hashing

Do not replace the following with `KernelFastMap`/`FxHash`/`AHash`:

| Area | Current examples | Reason |
| --- | --- | --- |
| Security randomness and hardening | ASLR layout selection, stack canary generation/audit, KASAN/security modules | These rely on entropy or security invariants, not hash-table speed. |
| Packet and firmware checksums | IPv4, TCP, UDP, ICMP/ICMPv6, ACPI and GDB RSP checksums | These are specified algorithms and must remain wire/protocol compatible. |
| User-visible deterministic listings | scheme listing, procfs output sorted by map order, any ABI that promises stable ordering | Hash maps do not preserve sorted `BTreeMap` iteration order. |
| User-controlled names and paths | Unix socket bind names, tmpfs/ramfs path maps, namespace names, POSIX message queues, mount paths | Attackers can create many colliding strings unless the hasher is randomized and DoS-resistant. |
| Authorization and namespace maps | user namespace mappings, cgroup ownership, credential/capability/security namespace tables | These are policy state; prefer deterministic trees or a DoS-resistant keyed hasher. |

## Implementation guidance

* Use `crate::core::fast_hash::KernelFastMap` for approved non-security-critical
  tables instead of open-coding new hashers or ad-hoc hash tables.
* Keep attacker-controlled keys on `BTreeMap` or a future `KernelSafeMap`, so
  review can distinguish performance-only lookups from security-sensitive or
  externally keyed maps.
* Add a short comment at each conversion explaining why the key is trusted,
  bounded, and not part of deterministic output.
* Benchmark or profile before replacing `BTreeMap`; for tiny tables, tree maps
  may be fast enough and simpler to audit.
