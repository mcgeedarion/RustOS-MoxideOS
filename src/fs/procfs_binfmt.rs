//! Synthetic procfs sub-tree: /proc/sys/fs/binfmt_misc/
//!
//! ## Layout
//!
//! ```
//! /proc/sys/fs/binfmt_misc/
//!   register         (wo) — write a registration string to add an entry
//!   status           (rw) — global enable/disable: read "enabled"/"disabled",
//!                           write "enable"/"disable"/"0"/"1"
//!   <name>           (rw) — per-entry file; read shows details, write:
//!                             "0"       → disable entry
//!                             "1"       → enable  entry
//!                             "-1"      → remove  entry
//! ```
//!
//! This module is called from the main procfs read/write dispatch in
//! `procfs.rs` for any path under `/proc/sys/fs/binfmt_misc`.

extern crate alloc;
use alloc::{
    format,
    string::{String, ToString},
    vec::Vec,
};
use spin::Mutex;

use crate::fs::binfmt_misc::{self, BinfmtEntry, MatchType, FLAG_CREDENTIALS, FLAG_FIX_BINARY, FLAG_OPEN_BINARY};

// Global "master" switch — mirrors `echo 0 > /proc/sys/fs/binfmt_misc/status`.
static BINFMT_ENABLED: Mutex<bool> = Mutex::new(true);

pub fn is_globally_enabled() -> bool {
    *BINFMT_ENABLED.lock()
}

// ── VFS entry points ────────────────────────────────────────────────────────

/// Decide whether `path` is inside our sub-tree.
pub fn owns_path(path: &str) -> bool {
    path.starts_with("/proc/sys/fs/binfmt_misc")
}

/// Read handler — returns `Some(content)` or `None` on ENOENT.
pub fn read(path: &str) -> Option<String> {
    let rel = path
        .strip_prefix("/proc/sys/fs/binfmt_misc")
        .unwrap_or("")
        .trim_start_matches('/');

    match rel {
        // Directory listing.
        "" | "." => {
            let mut out = String::from("register\nstatus\n");
            for e in binfmt_misc::list() {
                out.push_str(&e.name);
                out.push('\n');
            }
            Some(out)
        }
        "register" => {
            // Write-only; reading returns an empty string rather than ENOENT.
            Some(String::new())
        }
        "status" => {
            let s = if is_globally_enabled() { "enabled\n" } else { "disabled\n" };
            Some(s.to_string())
        }
        name => {
            // Per-entry file.
            let entries = binfmt_misc::list();
            let entry = entries.iter().find(|e| e.name == name)?;
            Some(render_entry(entry))
        }
    }
}

/// Write handler — returns `Ok(len)` or `Err(errno)`.
pub fn write(path: &str, data: &[u8]) -> Result<usize, isize> {
    let text = core::str::from_utf8(data).unwrap_or("").trim();
    let rel = path
        .strip_prefix("/proc/sys/fs/binfmt_misc")
        .unwrap_or("")
        .trim_start_matches('/');

    match rel {
        "register" => {
            let entry = binfmt_misc::parse_register_string(text)
                .map_err(|_| -22isize)?; // EINVAL
            binfmt_misc::register(entry);
            Ok(data.len())
        }
        "status" => {
            match text {
                "enable" | "1" => *BINFMT_ENABLED.lock() = true,
                "disable" | "0" => *BINFMT_ENABLED.lock() = false,
                _ => return Err(-22),
            }
            Ok(data.len())
        }
        name if !name.is_empty() => {
            match text {
                "1" => {
                    if binfmt_misc::set_enabled(name, true) {
                        Ok(data.len())
                    } else {
                        Err(-2) // ENOENT
                    }
                }
                "0" => {
                    if binfmt_misc::set_enabled(name, false) {
                        Ok(data.len())
                    } else {
                        Err(-2)
                    }
                }
                "-1" => {
                    if binfmt_misc::remove(name) {
                        Ok(data.len())
                    } else {
                        Err(-2)
                    }
                }
                _ => Err(-22), // EINVAL
            }
        }
        _ => Err(-2), // ENOENT
    }
}

// ── Per-entry rendering ─────────────────────────────────────────────────────

fn render_entry(e: &BinfmtEntry) -> String {
    let state = if e.enabled { "enabled" } else { "disabled" };
    let flags = render_flags(e.flags);
    let match_info = match &e.match_type {
        MatchType::Magic { offset, magic, mask } => {
            let magic_hex: String = magic.iter().map(|b| format!("{:02x}", b)).collect();
            let mask_hex:  String = mask .iter().map(|b| format!("{:02x}", b)).collect();
            format!("magic offset {offset}\nmagic        {magic_hex}\nmask         {mask_hex}\n")
        }
        MatchType::Extension(ext) => format!("extension    {ext}\n"),
    };
    format!(
        "{}\ninterpreter  {}\nflags        {}\n{}\n",
        state, e.interpreter, flags, match_info
    )
}

fn render_flags(f: u8) -> String {
    let mut out = String::new();
    if f & FLAG_OPEN_BINARY  != 0 { out.push('O'); }
    if f & FLAG_CREDENTIALS  != 0 { out.push('C'); }
    if f & FLAG_FIX_BINARY   != 0 { out.push('F'); }
    if out.is_empty() { out.push('-'); }
    out
}
