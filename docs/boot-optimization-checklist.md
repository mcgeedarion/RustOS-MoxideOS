# RustOS Boot Optimization Checklist

A structured checklist for profiling and optimizing the x86_64 UEFI boot path in RustOS. Work through sections in order — measurement comes first so every subsequent change is validated against data.

---

## 1. Measurement Infrastructure

Before changing anything, establish a timing baseline.

- [ ] Add `boot_timer::mark(tag)` calls around each boot phase in `src/arch/x86_64/uefi_entry.rs`:
  - `FIRMWARE_ENTRY` — first instruction in `uefi_start`
  - `MMAP_CAPTURED` — after UEFI memory map is read and `ExitBootServices()` returns
  - `INITRAMFS_LOCATED` — after initramfs range is resolved from the ESP
  - `BOOT_INFO_BUILT` — after `BootInfo` is fully populated
  - `KERNEL_MAIN_ENTER` — first line of `kernel_main`
  - `ARCH_INIT_DONE` — after `arch::init()` returns
- [ ] Emit all timing marks to the serial log in a parseable format, e.g. `[BOOT_PERF] MMAP_CAPTURED +2ms`
- [ ] Add a CI step in `kernel-test.yml` that greps the serial log for `[BOOT_PERF]` markers and records them as job annotations
- [ ] Record a cold-boot baseline in `docs/boot-perf-baseline.txt` so future PRs can diff against it
- [ ] Use identical QEMU flags for every measurement run to eliminate timing noise

---

## 2. UEFI Entry Path (`src/arch/x86_64/uefi_entry.rs`)

Keep the pre-`ExitBootServices()` window as short as possible.

- [ ] Audit every UEFI protocol handle open/close — close handles as soon as they are no longer needed
- [ ] Remove any `BootServices::stall()` or `BootServices::set_watchdog_timer()` calls that add delay
- [ ] Eliminate repeated GOP framebuffer probes; probe once and cache the result
- [ ] Do not iterate all loaded images unless the cmdline requires it
- [ ] Confirm `ExitBootServices()` is called exactly once with no retry loop unless firmware requires it
- [ ] Ensure the stack switch (if any) happens after `ExitBootServices()`, not before

---

## 3. BootInfo Construction (`src/init/boot_info.rs`)

The handoff struct should be built with zero heap allocation and no redundant copies.

- [ ] Verify all `BootRange` fields are physical addresses — no virtual translation during boot
- [ ] Confirm `EfiMemoryMapInfo` stores only the pointer and sizes, not a copied slice
- [ ] Remove any `memcpy` or `clone()` of the UEFI memory descriptor buffer before `kernel_main`
- [ ] Confirm `BootInfo` fits in a single cache line or is at minimum `#[repr(C, align(64))]`

---

## 4. Memory Map Processing (`src/mm/memmap.rs`, `src/arch/x86_64/memory.rs`)

Parsing the memory map is often the single most expensive operation during early boot.

- [ ] Use a single-pass iterator over the UEFI descriptor buffer — no sort, no dedup, no Vec allocation
- [ ] Remove the now-dead `BootSource::Multiboot2` arm (already done) — confirm no dead branches remain
- [ ] Cap the number of regions processed early; defer full map walk to the PMM initialisation path
- [ ] Consider a `#[inline(never)]` boundary between the boot map walk and PMM init to isolate profiling

---

## 5. Initramfs Discovery (`src/init/initramfs/mod.rs`)

- [ ] Use the `LoadFile2` protocol pointer stored by the UEFI stub — do not scan the ESP directory
- [ ] Confirm `set_initramfs_range()` is called exactly once before the heap is initialised
- [ ] If the initramfs is not present, `set_initramfs_range()` should be a no-op with no filesystem probe

---

## 6. Serial / Logging Overhead

Debug output is often the largest single source of boot latency.

- [ ] Gate all `log::debug!` and `log::trace!` calls in the boot path behind a `cfg(feature = "boot_debug")` feature flag
- [ ] Ensure `log::info!` boot banners are flushed synchronously only once (not per-region)
- [ ] Remove any spinloop-based serial flush that polls longer than one character time
- [ ] In CI smoke runs, pipe QEMU serial output to a file rather than a terminal to avoid PTY buffering

---

## 7. Build and Image Size

A smaller boot image loads faster from the virtual disk.

- [ ] Run `cargo bloat --release --target targets/x86_64-kernel.json` and review the top 20 functions
- [ ] Strip `.comment` and `.eh_frame` sections (already in `linker/x86_64.ld` — verify they stay stripped on release builds)
- [ ] Confirm `opt-level = "z"` or `opt-level = 3` is set in `[profile.release]` in the root `Cargo.toml`
- [ ] Confirm LTO is enabled: `lto = "thin"` at minimum for the release profile
- [ ] Keep `boot-x86_64.img` under 2 MB for CI; add a size check step to `kernel-test.yml`

---

## 8. QEMU / CI Tuning

Reduce overhead in the test environment without masking real-hardware issues.

- [ ] Use `-cpu host` when KVM is available; fall back to `-cpu Skylake-Client` for consistency
- [ ] Add `-m 256M` as the floor; do not allocate more than needed for smoke/kmtest runs
- [ ] Add `-no-reboot -no-shutdown` so QEMU exits immediately on triple fault rather than waiting
- [ ] Pass `-serial stdio` and redirect to a log file; do not use `-serial mon:stdio` in CI
- [ ] Set an explicit QEMU timeout in `run_qemu.sh` (e.g. `--timeout 30` for smoke, `--timeout 90` for kmtest)

---

## 9. Regression Gate

- [ ] Add a `boot-perf` job to `ci.yml` that fails if any phase exceeds its baseline by more than 20%
- [ ] Store the baseline in `docs/boot-perf-baseline.txt` and update it intentionally via a `[perf-update]` commit flag
- [ ] Run the full smoke boot on every PR, not just pushes to `main`

---

## Priority Order

| # | Item | Expected win | Effort |
|---|------|-------------|--------|
| 1 | Add timing markers | Baseline only | Low |
| 2 | Gate debug logging behind feature flag | Medium | Low |
| 3 | Single-pass memory map walk | Medium | Medium |
| 4 | Remove redundant UEFI protocol probes | Small–Medium | Low |
| 5 | Enable LTO + `opt-level=3` | Medium | Low |
| 6 | Add CI size and perf regression checks | Long-term safety | Medium |
| 7 | `LoadFile2` initramfs (vs ESP scan) | Large if scanning | Medium |
| 8 | BootInfo zero-copy handoff | Small | Low |
