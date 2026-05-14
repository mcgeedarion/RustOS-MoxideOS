//! Boot-time scheme registration.
//!
//! Called once from `kernel_main` (both x86_64 and RISC-V paths), **after**
//! all hardware drivers have been initialised and **before** pid 1 is spawned.
//!
//! Every subsystem that wants to be reachable via `SCHEME_TABLE.open_url()`
//! registers itself here. The order is intentional: lower-level schemes
//! (`blk`, `tty`) come before higher-level ones (`net`, `tcp`) so that log
//! messages appear in dependency order.
//!
//! # Boot integration
//!
//! ```rust
//! // After drivers::nic::init(), before pid-1 spawn:
//! crate::init::schemes::init();
//! ```

extern crate alloc;
use alloc::sync::Arc;

use crate::fs::scheme_table::SCHEME_TABLE;

pub fn init() {
    // ── Storage ───────────────────────────────────────────────────────────────
    // Registered early so schemes that open config files (e.g. /etc/resolv.conf)
    // can use open_url before network init.
    SCHEME_TABLE.register("blk",  Arc::new(crate::block::BlkScheme::new()));
    SCHEME_TABLE.register("file", Arc::new(crate::fs::vfs::VfsScheme::new()));

    // ── TTY ───────────────────────────────────────────────────────────────────
    SCHEME_TABLE.register("tty",  Arc::new(crate::tty::TtyScheme::new()));

    // ── Networking ────────────────────────────────────────────────────────────
    SCHEME_TABLE.register("net",  Arc::new(crate::net::NetScheme::new()));
    SCHEME_TABLE.register("tcp",  Arc::new(crate::net::tcp::TcpScheme::new()));
    SCHEME_TABLE.register("udp",  Arc::new(crate::net::udp::UdpScheme::new()));

    // ── IPC ───────────────────────────────────────────────────────────────────
    SCHEME_TABLE.register("pipe", Arc::new(crate::ipc::pipe_scheme::PipeScheme));

    log::info!("[schemes] registered: {:?}", SCHEME_TABLE.list());
}
