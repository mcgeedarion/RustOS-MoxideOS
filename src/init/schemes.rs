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
    // Registered early so schemes that open config files (e.g. /etc/resolv.conf)
    // can use open_url before network init.
    SCHEME_TABLE.register("blk", Arc::new(crate::block::BlkScheme::new()));
    SCHEME_TABLE.register("file", Arc::new(crate::fs::vfs::VfsScheme::new()));

    SCHEME_TABLE.register("tty", Arc::new(crate::tty::TtyScheme::new()));

    // devfs must come before procfs/sysfs because /proc and /sys may emit
    // references to devices that userspace resolves through /dev.
    SCHEME_TABLE.register("dev", Arc::new(crate::fs::url_dispatch::DevFs::new()));
    SCHEME_TABLE.register("proc", Arc::new(crate::fs::procfs::ProcFs::new()));
    SCHEME_TABLE.register("sys", Arc::new(crate::fs::sysfs::SysFs::new()));

    // ramfs is the simpler, unbounded variant used as an early-boot root overlay
    // or initrd scratch space; tmpfs adds size limits and swap backing.
    SCHEME_TABLE.register("ram", Arc::new(crate::fs::ramfs::RamFs::new()));
    SCHEME_TABLE.register("tmp", Arc::new(crate::fs::tmpfs::TmpFs::new()));

    SCHEME_TABLE.register("net", Arc::new(crate::net::NetScheme::new()));
    SCHEME_TABLE.register("tcp", Arc::new(crate::net::tcp::TcpScheme::new()));
    SCHEME_TABLE.register("udp", Arc::new(crate::net::udp::UdpScheme::new()));

    // NFS client: registered after the network stack is online so that the
    // scheme constructor can probe the default NIC/route if needed.
    SCHEME_TABLE.register("nfs", Arc::new(crate::fs::url_dispatch::NfsScheme::new()));

    // ipc_proxy_scheme provides the kernel-side endpoint for cross-process
    // message-passing; pipe is the simpler, anonymous half-duplex variant.
    SCHEME_TABLE.register(
        "ipc",
        Arc::new(crate::fs::ipc_proxy_scheme::IpcProxyScheme::new()),
    );
    SCHEME_TABLE.register("pipe", Arc::new(crate::ipc::pipe_scheme::PipeScheme));

    // Registered after IPC because cgroup controllers may publish their state
    // via the IPC bus (e.g. memory-pressure notifications to userspace daemons).
    SCHEME_TABLE.register("cgroup", Arc::new(crate::fs::url_dispatch::CgroupFs::new()));

    // overlayfs requires at least one lower layer already registered in the VFS
    // before it is useful; registering last ensures all lower-layer schemes are
    // in place so an early open_url("overlay:…") fails cleanly rather than
    // silently missing a dependency.
    SCHEME_TABLE.register("overlay", Arc::new(crate::fs::url_dispatch::OverlayFs::new()));

    log::info!("[schemes] registered: {:?}", SCHEME_TABLE.list());
}
