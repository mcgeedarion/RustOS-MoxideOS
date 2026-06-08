# `src/debug` — Kernel Debug Subsystem

The `debug` module is compiled only when the `debug` Cargo feature is active.
Enable it in `.cargo/config.toml` or pass `--features debug` to `cargo build`.

```toml
# Cargo.toml (feature dependency graph)
[features]
debug      = ["trace"]          # enables oops, gdbstub, trace ring buffer
trace      = ["debug_stub"]     # enables ftrace + trace ring
debug_stub = []                 # bare serial debug stub (no ring, no ftrace)
```

---

## Modules

### `oops` — Kernel Panic Enricher

**Feature gate:** `debug`

Called from the `#[panic_handler]` in `src/kernel_main.rs`. Adds:

- Register dump via `AnyTrapFrame<'_>` (x86_64 / RISC-V / AArch64)
- Frame-pointer backtrace with symbol+offset resolution
- Persistent `CrashLog` written to `.crash_log` ELF section
- ftrace event drain (last 32 function-trace events leading to crash)

**Linker script addition required:**

```ld
.crash_log (NOLOAD) : {
    KEEP(*(.crash_log))
}
```

Place at a stable physical address that survives a warm reboot (not zeroed by
the bootloader on cold boot). Suggested: just below `0x000A_0000` on x86_64,
or a reserved page in the SBI memory map on RISC-V.

**Usage:**

```rust
// Bare Rust panic (no TrapFrame available):
crate::debug::oops::oops("allocation failed", None);

// From a trap/exception handler:
crate::debug::oops::oops(
    "page fault",
    Some(crate::debug::oops::AnyTrapFrame::X86_64(trap_frame)),
);

// Early boot — detect previous crash:
crate::debug::oops::check_crash_log();
```

---

### `trace` — Lock-Free Ring Buffer

**Feature gate:** `debug` (implied by `trace`)

A 4096-slot lock-free ring buffer for kernel trace events. Supports:

| Event kind      | Description                          |
|-----------------|--------------------------------------|
| `SyscallEnter`  | Syscall dispatch entry               |
| `SyscallExit`   | Syscall return                       |
| `IrqDispatch`   | IRQ handler entry                    |
| `SchedSwitch`   | Scheduler context switch             |
| `FuncEnter`     | Function prologue (ftrace)           |
| `FuncExit`      | Function epilogue (ftrace)           |

**Key functions:**

```rust
trace::emit(TraceEvent { kind, id, arg, ticks });
trace::drain(|ev| { /* consume all pending events */ });
trace::drain_last_n(32, |ev| { /* non-destructive look-back */ });
trace::pending() -> usize;
```

`drain_last_n` does **not** advance the consumer cursor — it is safe to call
from the oops path before `drain` without losing events.

---

### `ftrace` — Function Entry/Exit Tracing

**Feature gate:** `debug` + `trace`

Uses LLVM `-Z instrument-functions` (enabled in `build.rs`) to inject
`__cyg_profile_func_enter` / `__cyg_profile_func_exit` at every function
boundary. Events are written into the shared `trace` ring.

A per-CPU `IN_HOOK` atomic prevents re-entrant instrumentation.

**Usage:**

```rust
// Drain the last N function-trace events (FuncEnter/FuncExit only):
crate::debug::ftrace::drain_last_n(32, |ev| {
    let (sym, off) = crate::debug::oops::resolve_symbol(ev.arg as usize);
    serial_println!("ftrace: {}+{:#x}", sym, off);
});
```

`build.rs` must pass the instrumentation flag:

```rust
// build.rs
println!("cargo:rustc-flag=-Zinstrument-functions");
```

---

### `gdbstub` — GDB Remote Serial Protocol Stub

**Feature gate:** `debug`

A minimal GDB RSP server that speaks over the kernel serial port. Connect with:

```bash
gdb -ex 'target remote localhost:1234' target/kernel
# or via QEMU:
qemu-system-x86_64 -s -S ...
```

#### `arch.rs` — `GdbArch` Trait

Implement [`GdbArch`] for each supported architecture to provide:

- `read_regs` / `write_regs` — `g`/`G` packet register serialisation
- `pc` / `set_pc` — program counter access
- `reg_buf_len` — byte length of the register packet
- `trap_signal` — GDB signal number (default 5 = SIGTRAP)

Pre-built implementations: `X86_64`, `RiscV64`, `AArch64`.

Shared utilities in `arch.rs`:

```rust
arch::parse_vcont(body)   -> Option<VContAction>
arch::encode_hex_bytes(&[u8]) -> String
arch::decode_hex_bytes(&str)  -> Vec<u8>
arch::parse_hex_u64(&str)     -> u64
```

#### `rsp_vcont.rs` — `vCont` Handler

Handles `vCont;c`, `vCont;s`, `vCont;t`, and `vCont;r<start>,<end>`.
Reply to `vCont?` with `vCont;c;s;t;r`.

```rust
use crate::debug::gdbstub::rsp_vcont::{handle_vcont, range_step_done, RspState};

let mut state = RspState::new();

// In the RSP packet dispatch loop:
if pkt.starts_with("vCont") {
    let reply = handle_vcont(pkt, trap_frame, &mut state);
    if !reply.is_empty() {
        rsp_send(&reply);
    }
    continue;
}

// In the single-step debug-trap handler:
if !range_step_done(&state, current_pc) {
    arch_enable_single_step(frame); // re-arm
} else {
    state.halted = true;
    rsp_send("T05");               // stop reply
}
```

---

## Symbol Table Generation

`oops::resolve_symbol` requires a sorted `(address, name)` table embedded at
build time. Add to `build.rs`:

```rust
use std::process::Command;

let out = Command::new("llvm-nm")
    .args(["--numeric-sort", "--defined-only", "-f", "posix"])
    .arg(&kernel_elf_path)
    .output()
    .expect("llvm-nm not found");

// Parse output: "symbol_name T 0000000000001234 0000000000000010"
let mut entries = vec![];
for line in String::from_utf8_lossy(&out.stdout).lines() {
    let mut it = line.split_whitespace();
    if let (Some(name), Some(_kind), Some(addr_str)) = (it.next(), it.next(), it.next()) {
        if let Ok(addr) = usize::from_str_radix(addr_str, 16) {
            entries.push(format!("    ({addr:#x}, \"{name}\"),\n"));
        }
    }
}

let content = format!(
    "static SYMBOLS: &[(usize, &str)] = &[\n{}];\n",
    entries.concat()
);
std::fs::write(
    std::path::Path::new(&std::env::var("OUT_DIR").unwrap()).join("symbols.rs"),
    content,
).unwrap();
println!("cargo:rustc-cfg=has_symbol_table");
```

Include in `oops.rs` (already wired):

```rust
#[cfg(has_symbol_table)]
include!(concat!(env!("OUT_DIR"), "/symbols.rs"));
```
