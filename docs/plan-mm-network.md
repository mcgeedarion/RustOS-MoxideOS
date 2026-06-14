# Game Plan: Memory, Exit & Networking Fixes for Issue #82

This plan covers the remaining memory‑management, exit, networking and miscellaneous bugs from issue #82.

## Tasks

1. **`put_page` called before remote TLB acknowledgement** (`src/mm/cow_fault.rs`): ensure that `tlb_shootdown` blocks until all targeted CPUs have acknowledged the invalidation before freeing the old physical page.

2. **`next_va` not validated against existing VMAs** (`src/mm/mmap/mapping.rs`): when choosing a hint‑free virtual address, check for VMA overlaps and advance `next_va` past any existing mapping before mapping the new region.

3. **Framebuffer mappings use write‑back caching** (`src/mm/mmap/mapping.rs`): extend `PageFlags` with `WRITE_COMBINING` or `UNCACHED` and use it for device and framebuffer `PhysMap` mappings.

4. **TLB shootdowns use `asid == 0` (flush all address spaces)** (`src/mm/cow_fault.rs`): pass the process’s actual ASID/PCID to `tlb_shootdown` so that only CPUs with that address space flush their TLB.

5. **TCP retransmission timer never polled** (`src/net/tcp.rs`): call `tcp::on_tick()` from the scheduler’s `tick()` handler or integrate the retransmission timer into a timer wheel so that lost segments are retransmitted.

6. **`sys_exit_group` runs cgroup hooks too early** (`src/proc/exit.rs`): defer cgroup exit callbacks until after `free_address_space` has run, or ensure that the hooks do not dereference the process’s VMA table.

7. **`CLONE_SETTLS` with `tls == 0` indistinguishable from no TLS** (`src/proc/clone.rs`): treat the presence of the `CLONE_SETTLS` flag as authoritative, even if `tls == 0`, so that a TLS base of 0 can be explicitly requested.

8. **`PageFlags::NX` is not arch‑neutral** (`src/mm/page_fault.rs` and `src/arch/api.rs`): define a positive `EXEC` flag to represent executable pages and update architecture‑specific page mapping code to set or clear the appropriate bits instead of copying `NX` directly.
