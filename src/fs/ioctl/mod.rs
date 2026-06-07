//! sys_ioctl dispatcher.
//!
//! Routes ioctl requests to the appropriate handler submodule:
//!   consts.rs  — all request number constants
//!   tty.rs     — TIOC* / termios / FION* on tty fds
//!   net.rs     — SIOC* network interface ioctls
//!   block.rs   — BLK* block device ioctls
//!   file.rs    — generic fd helpers (FIONREAD, FIONBIO)

pub mod block;
pub mod consts;
pub mod file;
pub mod net;
pub mod tty;

use crate::uaccess::{copy_from_user, copy_to_user, copy_to_user_value};
use consts::*;

pub fn sys_ioctl(fd: usize, req: usize, arg: usize) -> isize {
    // Pipe / epoll FDs
    if crate::ipc::pipe::is_pipe_fd(fd) {
        match req {
            FIONREAD => return file::pipe_fionread(fd, arg),
            FIONBIO => return file::set_nonblock(fd, arg),
            _ => return -25,
        }
    }

    // Socket FDs
    if crate::net::socket::is_socket_fd(fd) {
        return match req {
            req if req >= SIOCGIFNAME && req <= SIOCETHTOOL => net::sioc_ioctl(req, arg),
            FIONREAD => file::vfs_fionread(fd, arg),
            FIONBIO => file::set_nonblock(fd, arg),
            _ => -25,
        };
    }

    // Block device FDs (virtio-blk)
    if crate::drivers::virtio_blk::is_blk_fd(fd) {
        return block::blk_ioctl(fd, req, arg);
    }

    // GPU / framebuffer FDs
    if crate::drivers::gop::is_fb_fd(fd) {
        match req {
            // FBIOGET_VSCREENINFO (0x4600)
            0x4600 => {
                if let Some(info) = crate::drivers::gop::get() {
                    let mut vi = [0u8; 160];
                    vi[0..4].copy_from_slice(&(info.horizontal_resolution as u32).to_ne_bytes());
                    vi[4..8].copy_from_slice(&(info.vertical_resolution as u32).to_ne_bytes());
                    vi[8..12].copy_from_slice(&(info.horizontal_resolution as u32).to_ne_bytes());
                    vi[12..16].copy_from_slice(&(info.vertical_resolution as u32).to_ne_bytes());
                    vi[24..28].copy_from_slice(&32u32.to_ne_bytes()); // bits_per_pixel
                    crate::uaccess::copy_to_user_value(arg, &vi);
                }
                return 0;
            },
            // FBIOGET_FSCREENINFO (0x4602)
            0x4602 => {
                if let Some(info) = crate::drivers::gop::get() {
                    let mut fi = [0u8; 80];
                    let fb_phys: u64 = info.fb_phys as u64;
                    fi[16..24].copy_from_slice(&fb_phys.to_ne_bytes());
                    let line_len: u32 = info.pixels_per_scan_line * 4;
                    fi[48..52].copy_from_slice(&line_len.to_ne_bytes());
                    crate::uaccess::copy_to_user_value(arg, &fi);
                }
                return 0;
            },
            // FBIOPAN_DISPLAY (0x4606) — no-op
            0x4606 => return 0,
            _ => return -25,
        }
    }

    // Epoll FDs
    if crate::io_uring::epoll::is_epoll_fd(fd) {
        return match req {
            FIONBIO => {
                file::set_nonblock(fd, arg);
                0
            },
            _ => -25,
        };
    }

    // Default: treat as tty/vfs
    let is_tty = crate::tty::is_tty_fd(fd);
    match req {
        req if is_tty
            && (req == TCGETS
                || req == TCSETS
                || req == TCSETSW
                || req == TCSETSF
                || req == TIOCGPGRP
                || req == TIOCSPGRP
                || req == TIOCGWINSZ
                || req == TIOCSWINSZ
                || req == TIOCGPTPEER
                || req == TIOCSPTLCK
                || req == TIOCGPTN
                || req == TIOCNOTTY
                || req == TIOCSCTTY
                || req == TIOCEXCL
                || req == TIOCNXCL
                || req == TIOCOUTQ
                || req == TIOCSTI) =>
        {
            tty::tty_ioctl(fd, req, arg)
        },
        FIONREAD => file::vfs_fionread(fd, arg),
        FIONBIO => file::set_nonblock(fd, arg),
        FIOCLEX | FIONCLEX | FIOASYNC => 0,
        _ if req >= SIOCGIFNAME && req <= SIOCETHTOOL => net::sioc_ioctl(req, arg),
        _ => -25,
    }
}
