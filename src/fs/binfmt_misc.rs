//! binfmt_misc — kernel binary format table.
//!
//! This module owns the global `BinfmtTable` and exposes the lookup used by
//! `proc::exec` to redirect non-native ELF binaries through a user-space
//! interpreter (e.g. qemu-user, wine, mono, …).
//!
//! ## Registration protocol
//!
//! Entries are registered by writing a description string to
//! `/proc/sys/fs/binfmt_misc/register` (handled by `procfs_binfmt.rs`).
//! The format mirrors Linux:
//!
//! ```text
//! :name:type:offset:magic:mask:interpreter:flags
//! ```
//!
//! Only `type=M` (magic-byte match) is currently supported.  `type=E`
//! (extension match) is parsed but not yet wired into execve.
//!
//! ## Flags (OCF subset)
//!
//! | Flag | Meaning |
//! |------|---------|
//! | `O`  | Open — pass the binary as an open fd to the interpreter |
//! | `C`  | Credentials — apply set-uid/gid from the interpreter |
//! | `F`  | Fix binary — keep entry alive across `mount --bind` moves |

extern crate alloc;
use alloc::{
    string::{String, ToString},
    vec::Vec,
};
use spin::Mutex;

// ── Flags ──────────────────────────────────────────────────────────────────

/// `O` — pass binary as an open fd (fd is appended after `--` in argv).
pub const FLAG_OPEN_BINARY: u8 = 1 << 0;
/// `C` — use interpreter credentials (setuid/setgid from interpreter inode).
pub const FLAG_CREDENTIALS: u8 = 1 << 1;
/// `F` — "fix binary": entry survives `mount --bind` remounts.
pub const FLAG_FIX_BINARY: u8 = 1 << 2;

// ── Entry type ──────────────────────────────────────────────────────────────

#[derive(Clone, Debug, PartialEq)]
pub enum MatchType {
    /// Match by magic bytes at a fixed file offset.
    Magic {
        offset: usize,
        magic: Vec<u8>,
        mask: Vec<u8>, // same length as magic; all-0xFF ⇒ exact match
    },
    /// Match by filename extension (e.g. ".jar").
    Extension(String),
}

#[derive(Clone, Debug)]
pub struct BinfmtEntry {
    /// Human-readable name shown under `/proc/sys/fs/binfmt_misc/<name>`.
    pub name: String,
    pub match_type: MatchType,
    /// Absolute path to the user-space interpreter (e.g.
    /// `/usr/bin/qemu-x86_64`).
    pub interpreter: String,
    pub flags: u8,
    /// Whether this entry is active.  Toggled by writing `0`/`1` to the
    /// per-entry proc file.
    pub enabled: bool,
}

// ── Table ──────────────────────────────────────────────────────────────────

pub struct BinfmtTable {
    entries: Vec<BinfmtEntry>,
}

impl BinfmtTable {
    const fn new() -> Self {
        BinfmtTable {
            entries: Vec::new(),
        }
    }

    /// Add a new entry.  Duplicate names overwrite the existing entry so that
    /// a repeated `register` write behaves like an update.
    pub fn register(&mut self, entry: BinfmtEntry) {
        if let Some(pos) = self.entries.iter().position(|e| e.name == entry.name) {
            self.entries[pos] = entry;
        } else {
            self.entries.push(entry);
        }
    }

    /// Remove the entry with the given name.  Returns `true` if found.
    pub fn remove(&mut self, name: &str) -> bool {
        let before = self.entries.len();
        self.entries.retain(|e| e.name != name);
        self.entries.len() != before
    }

    /// Enable or disable an entry by name.
    pub fn set_enabled(&mut self, name: &str, on: bool) -> bool {
        for e in &mut self.entries {
            if e.name == name {
                e.enabled = on;
                return true;
            }
        }
        false
    }

    /// Probe `file_header` against every enabled entry.
    ///
    /// Returns a reference to the first matching `BinfmtEntry`, or `None` if
    /// the file should be handled natively.
    pub fn probe<'a>(&'a self, file_header: &[u8]) -> Option<&'a BinfmtEntry> {
        for entry in &self.entries {
            if !entry.enabled {
                continue;
            }
            let matched = match &entry.match_type {
                MatchType::Magic {
                    offset,
                    magic,
                    mask,
                } => probe_magic(file_header, *offset, magic, mask),
                MatchType::Extension(_) => false, // probed at path level, not here
            };
            if matched {
                return Some(entry);
            }
        }
        None
    }

    /// Return a snapshot of all entries for procfs rendering.
    pub fn entries(&self) -> Vec<BinfmtEntry> {
        self.entries.clone()
    }
}

fn probe_magic(header: &[u8], offset: usize, magic: &[u8], mask: &[u8]) -> bool {
    let end = offset.saturating_add(magic.len());
    if end > header.len() {
        return false;
    }
    let window = &header[offset..end];
    for i in 0..magic.len() {
        let m = if i < mask.len() { mask[i] } else { 0xFF };
        if window[i] & m != magic[i] & m {
            return false;
        }
    }
    true
}

// ── Global instance ────────────────────────────────────────────────────────

static BINFMT_TABLE: Mutex<BinfmtTable> = Mutex::new(BinfmtTable::new());

/// Lock-free read probe used from execve hot-path.
/// Returns `Some((interpreter_path, flags))` when a matching entry is found.
pub fn probe_header(file_header: &[u8]) -> Option<(String, u8)> {
    let tbl = BINFMT_TABLE.lock();
    tbl.probe(file_header)
        .map(|e| (e.interpreter.clone(), e.flags))
}

/// Register a new entry from a parsed description string.
/// Returns `Err` with a short reason string on parse failure.
pub fn register(entry: BinfmtEntry) {
    BINFMT_TABLE.lock().register(entry);
}

pub fn remove(name: &str) -> bool {
    BINFMT_TABLE.lock().remove(name)
}

pub fn set_enabled(name: &str, on: bool) -> bool {
    BINFMT_TABLE.lock().set_enabled(name, on)
}

/// Snapshot of all entries (used by procfs).
pub fn list() -> Vec<BinfmtEntry> {
    BINFMT_TABLE.lock().entries()
}

// ── Registration-string parser ─────────────────────────────────────────────
//
// Accepts the Linux-compatible format:
//   :name:type:offset:magic:mask:interpreter:flags
//
// type  := 'M' | 'E'
// magic := hex string (e.g. "7f454c46")
// mask  := hex string or empty (defaults to all-0xFF)
// flags := subset of "OCF"

pub fn parse_register_string(s: &str) -> Result<BinfmtEntry, &'static str> {
    let s = s.trim();
    if s.is_empty() {
        return Err("empty");
    }
    // The first character is the chosen delimiter.
    let delim = s.chars().next().unwrap();
    let parts: Vec<&str> = s[delim.len_utf8()..].split(delim).collect();
    // Expected 7 fields after the leading delimiter:
    //  name | type | offset | magic | mask | interpreter | flags
    if parts.len() < 7 {
        return Err("too few fields");
    }
    let name = parts[0];
    let kind = parts[1];
    let offset_str = parts[2];
    let magic_str = parts[3];
    let mask_str = parts[4];
    let interpreter = parts[5];
    let flags_str = parts[6];

    if name.is_empty() {
        return Err("empty name");
    }
    if interpreter.is_empty() {
        return Err("empty interpreter");
    }

    let flags = parse_flags(flags_str);

    let match_type = match kind {
        "M" | "m" => {
            let offset = offset_str.parse::<usize>().unwrap_or(0);
            let magic = decode_hex(magic_str).ok_or("bad magic hex")?;
            let mask = if mask_str.is_empty() {
                alloc::vec![0xFF; magic.len()]
            } else {
                let m = decode_hex(mask_str).ok_or("bad mask hex")?;
                if m.len() != magic.len() {
                    return Err("mask/magic length mismatch");
                }
                m
            };
            MatchType::Magic {
                offset,
                magic,
                mask,
            }
        },
        "E" | "e" => {
            // magic_str is the extension, offset/mask are ignored.
            MatchType::Extension(magic_str.to_string())
        },
        _ => return Err("unknown type; expected M or E"),
    };

    Ok(BinfmtEntry {
        name: name.to_string(),
        match_type,
        interpreter: interpreter.to_string(),
        flags,
        enabled: true,
    })
}

fn parse_flags(s: &str) -> u8 {
    let mut f = 0u8;
    for c in s.chars() {
        match c {
            'O' | 'o' => f |= FLAG_OPEN_BINARY,
            'C' | 'c' => f |= FLAG_CREDENTIALS,
            'F' | 'f' => f |= FLAG_FIX_BINARY,
            _ => {},
        }
    }
    f
}

fn decode_hex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    let mut i = 0;
    while i + 1 < bytes.len() {
        let hi = hex_nibble(bytes[i])?;
        let lo = hex_nibble(bytes[i + 1])?;
        out.push((hi << 4) | lo);
        i += 2;
    }
    Some(out)
}

fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}
