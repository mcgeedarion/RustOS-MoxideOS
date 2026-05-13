//! Boot-time scheme registration.
//!
//! Called once from `kernel_main` (both x86_64 and RISC-V paths), **after**
//! all hardware drivers have been initialised and **before** pid 1 is spawned.
//!
//! Every subsystem that wants to be reachable via `SCHEME_TABLE.open_url()`
//! registers itself here.  The order within this function is intentional:
//! lower-level schemes (blk, tty) come before higher-level ones (net, tcp)
//! so that log messages appear in dependency order.
//!
//! # Boot integration
//!
//! In `kernel_main.rs`, after `drivers::nic::init()` and before the pid-1
//! spawn, add:
//!
//! ```rust
//! crate::init::schemes::init();
//! ```
//!
//! # Verifying at runtime
//!
//! Once pid 1 is up:
//!
//! ```sh
//! cat /proc/schemes
//! # blk
//! # file
//! # net
//! # pipe
//! # tcp
//! # tty
//! # udp
//! ```

extern crate alloc;
use alloc::sync::Arc;

use crate::fs::scheme_table::SCHEME_TABLE;

pub fn init() {
    // -- Storage ----------------------------------------------------------
    // Block device scheme: blk:vda  blk:vda/0  blk:nvme0n1p2
    SCHEME_TABLE.register("blk", Arc::new(crate::block::BlkScheme::new()));

    // Ordinary VFS file scheme: file:/etc/passwd  file:/dev/null
    // Registered early so that any scheme that internally opens config files
    // (e.g. net reading /etc/resolv.conf) can do so via open_url.
    SCHEME_TABLE.register("file", Arc::new(crate::fs::vfs::VfsScheme::new()));

    // -- TTY --------------------------------------------------------------
    // tty:0  tty:pts/3  tty:console
    SCHEME_TABLE.register("tty", Arc::new(crate::tty::TtyScheme::new()));

    // -- Networking -------------------------------------------------------
    // Raw network socket scheme (L2/L3 access)
    SCHEME_TABLE.register("net", Arc::new(crate::net::NetScheme::new()));

    // TCP stream scheme: tcp:192.168.1.1:80
    SCHEME_TABLE.register("tcp", Arc::new(crate::net::tcp::TcpScheme::new()));

    // UDP datagram scheme: udp:0.0.0.0:5000
    SCHEME_TABLE.register("udp", Arc::new(crate::net::udp::UdpScheme::new()));

    // -- IPC --------------------------------------------------------------
    // Anonymous pipe scheme: open("pipe:", O_RDWR) → (read_fd, write_fd)
    // See src/ipc/pipe_scheme.rs for details.
    SCHEME_TABLE.register("pipe", Arc::new(crate::ipc::pipe_scheme::PipeScheme));

    log::info!("[schemes] registered: {:?}", SCHEME_TABLE.list());
}
