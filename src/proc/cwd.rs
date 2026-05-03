//! Per-process current working directory.
//!
//! For now the CWD is a global (single-address-space, single-shell).
//! A per-PCB string field should replace this once threads are stable.

extern crate alloc;
use alloc::string::{String, ToString};
use spin::Mutex;

static CWD: Mutex<String> = Mutex::new(String::new());

pub fn get_cwd() -> String {
    let g = CWD.lock();
    if g.is_empty() { "/".to_string() } else { g.clone() }
}

pub fn set_cwd(path: &str) {
    *CWD.lock() = path.to_string();
}
