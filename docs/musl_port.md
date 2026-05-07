# musl libc Port for RustOS

RustOS uses a lightly patched **musl libc 1.2.5** as its standard C library
for userspace programs.  Statically-linked ELF binaries built with the musl
toolchain run directly on RustOS without a compatibility layer.

---

## Architecture

```
userspace program (C / Rust via cc-rs)
        │
        ▼
  musl libc 1.2.5 (statically linked, patched)
        │
        │  syscall instruction (x86_64) / ecall (riscv64)
        ▼
  RustOS kernel syscall dispatch  (src/syscall/mod.rs)
        │
        ├─ POSIX syscalls ──────── src/syscall/stubs.rs
        ├─ musl compat layer ───── src/syscall/musl_compat.rs
        └─ arch_prctl / TLS ────── src/syscall/musl_compat.rs
```

---

## Patches Applied

| Patch | Purpose |
|---|---|
| `0001-rustos-sysdep.patch` | `errno` in TLS at offset 0 (not a global); matches RustOS TCB layout |
| `0002-rustos-time.patch` | `clock_gettime` prefers the RustOS vDSO fast path before falling back to syscall |

The kernel syscall ABI is **identical to Linux x86_64 / riscv64** (number in
`rax`/`a7`, args in `rdi rsi rdx r10 r8 r9` / `a0..a5`, return in `rax`/`a0`).
No further musl patches are needed for syscall dispatch.

---

## Building the Toolchain

### Prerequisites

```bash
# Debian/Ubuntu
sudo apt install clang lld wget make python3
```

### Build musl for both architectures

```bash
cd userspace/musl
make all          # builds sysroot/x86_64/ and sysroot/riscv64/
make sysroot      # copies RustOS extension headers into both sysroots
```

This produces:

```
userspace/musl/sysroot/
├── x86_64/
│   ├── lib/libc.a          ← static musl
│   ├── lib/libmusl.a       ← alias
│   └── include/            ← musl headers + rustos/ extension headers
└── riscv64/
    ├── lib/libc.a
    └── include/
```

---

## Compiling a C Program Against RustOS musl

```bash
# x86_64 static binary
clang --target=x86_64-unknown-linux-musl \
    -static \
    -nostdlib \
    -D__rustos__=1 \
    -isystem userspace/musl/sysroot/x86_64/include \
    -L userspace/musl/sysroot/x86_64/lib \
    -o hello hello.c \
    -lc

# riscv64
clang --target=riscv64-unknown-linux-musl \
    -static -nostdlib -march=rv64gc -mabi=lp64d \
    -D__rustos__=1 \
    -isystem userspace/musl/sysroot/riscv64/include \
    -L userspace/musl/sysroot/riscv64/lib \
    -o hello_rv hello.c -lc
```

---

## TLS Layout

RustOS sets up the TLS block at `execve` time and passes its address to
userspace via `AT_BASE_PLATFORM` in the aux vector.  The layout matches
glibc's `tcbhead_t`:

| Offset | Field | Notes |
|--------|-------|-------|
| `+0x00` | `errno` | musl reads/writes errno here via `fs:0x00` (x86_64) or `*(tp+0)` (riscv64) |
| `+0x08` | `locale` | unused, zero-filled |
| `+0x10` | `dtv` | dynamic thread vector (static = single entry) |
| `+0x18` | reserved | |
| `+0x28` | `stack_guard` | stack canary — see `security/canary.rs` (`CANARY_TLS_OFFSET`) |
| `+0x30` | `pointer_guard` | pointer mangling key (future) |

---

## vDSO

The kernel maps a single 4 KiB vDSO page into every process via
`security/aslr.rs::aslr_vdso_base()`.  It exports two functions:

| Symbol | Signature | Purpose |
|--------|-----------|--------|
| `__vdso_clock_gettime` | `(clockid_t, timespec*) -> int` | Fast wall/monotonic clock |
| `__vdso_gettimeofday`  | `(timeval*, void*) -> int` | Legacy gettimeofday |

musl's `clock_gettime` wrapper (patched by `0002-rustos-time.patch`) reads
the vDSO function pointer from `AT_SYSINFO_EHDR + 0x1000` on startup and
caches it in a `constructor`-attributed function.  If the pointer is NULL
(vDSO absent) it falls back to the `clock_gettime` syscall.

---

## Syscalls Required by musl Startup

See `src/syscall/musl_compat.rs` for full implementations.

| Syscall | # | musl use |
|---------|---|----------|
| `arch_prctl(ARCH_SET_FS)` | 158 | Install TLS base in FS.base (x86_64) |
| `set_tid_address` | 218 | Register `clear_child_tid` for pthread exit |
| `set_robust_list` | 273 | Register robust futex list |
| `rt_sigprocmask` | 14 | Query/clear signal mask |
| `prlimit64` | 302 | Query `RLIMIT_STACK` for guard page size |
| `mprotect` | 10 | Install stack guard page |
| `getrandom` | 318 | Seed internal PRNG (musl ≥ 1.2.1) |
| `mmap` | 9 | Allocate TLS, thread stacks |
| `clock_gettime` | 228 | `libc` time initialisation |
| `futex` | 202 | `pthread_create` / `pthread_join` |

---

## Known Gaps

- **`dlopen` / dynamic linking**: RustOS only supports static ELF binaries.
  `ld-musl-*.so.1` is not built or mapped.  All programs must be compiled
  `-static`.
- **`pthread_create`**: the `clone(CLONE_VM|CLONE_THREAD)` path is wired up
  in `stubs.rs` but thread-local storage for the new thread is not fully
  initialised before the thread function runs.  Single-threaded programs are
  fully supported.
- **`locale` / `iconv`**: stub-only; always returns `"C"`/`"POSIX"`.
- **Floating-point env** (`fenv.h`): no `SIGFPE` delivery yet.
