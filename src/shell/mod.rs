// src/shell/ has been dissolved.
//
// Former contents have been moved to their correct homes:
//
//   shell/tty.rs       → src/tty/serial_ldisc.rs
//                        (early serial-backed TTY line discipline)
//
//   shell/commands.rs  → src/debug/commands.rs
//                        (debug REPL commands; gated by `debug` feature)
//
//   shell/debugcon.rs  → src/debug/debugcon.rs
//                        (QEMU 0xe9 debugcon port; x86_64 only)
//
// This file intentionally left as a tombstone so the compiler surfaces
// any remaining `crate::shell::*` call-sites as errors rather than
// silently dropping the module.  Delete this file once all references
// have been updated.
//
// Migration guide:
//   crate::shell::tty::*       → crate::tty::serial_ldisc::*
//   crate::shell::commands::*  → crate::debug::commands::*
//   crate::shell::debugcon::*  → crate::debug::debugcon::*
//   dprint!/dprintln!           → unchanged (re-exported from crate root)
