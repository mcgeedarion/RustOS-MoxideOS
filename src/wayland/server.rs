#![cfg(feature = "wayland")]
//! Wayland compositor event loop.
//!
//! Runs as a kernel thread launched from kernel_main when the
//! `wayland` feature is active. Listens on /run/wayland-0.
//!
//! ## Event loop
//!   1. accept() new connections, create Client objects
//!   2. recv() + parse + dispatch each client's messages
//!   3. Poll HID devices for input events, forward to focused client
//!   4. Check vblank counter — fire deferred wl_callback.done
//!   5. sleep_ms(1) — yield to scheduler

extern crate alloc;
use alloc::vec::Vec;
use super::Client;
use crate::ipc::unix_socket as unix;

pub const WAYLAND_SOCKET_PATH: &str = "/run/wayland-0";

static mut CLIENTS:      Vec<Client> = Vec::new();
static mut SERVER_SOCK:  usize       = 0;
static mut LAST_VBLANK:  u64         = 0;

pub fn init() {
    let sock = unix::sys_socket() as usize;
    unix::sys_bind(sock, WAYLAND_SOCKET_PATH);
    unix::sys_listen(sock, 128);
    unsafe { SERVER_SOCK = sock; }
    crate::proc::env::set_global("WAYLAND_DISPLAY", "wayland-0");
    crate::proc::env::set_global("XDG_RUNTIME_DIR", "/run");
    crate::serial_println!("[wayland] listening on {}", WAYLAND_SOCKET_PATH);
}

pub fn run() -> ! {
    init();
    loop {
        let server = unsafe { SERVER_SOCK };
        while let Ok(client_sock) = unix_accept(server) {
            unsafe { CLIENTS.push(Client::new(client_sock)); }
            crate::serial_println!("[wayland] client connected fd={}", client_sock);
        }

        let mut recv_buf = [0u8; 4096];
        for client in unsafe { CLIENTS.iter_mut() } {
            let n = unix::sys_recv(client.sock_idx, &mut recv_buf);
            if n > 0 {
                let msgs = super::parse_messages(&recv_buf[..n as usize]);
                for msg in &msgs { client.dispatch(msg); }
                client.flush();
            }
        }

        poll_input();

        let current_vblank = crate::drivers::amdgpu_irq::vblank_count();
        if current_vblank != unsafe { LAST_VBLANK } {
            unsafe { LAST_VBLANK = current_vblank; }
            crate::wayland::compositor::fire_frame_callbacks(unsafe { &mut CLIENTS });
        }

        crate::proc::scheduler::sleep_ms(1);
    }
}

fn unix_accept(server: usize) -> Result<usize, ()> {
    let fd = unix::sys_accept(server);
    if fd >= 0 { Ok(fd as usize) } else { Err(()) }
}

fn poll_input() {
    while let Some(ev) = crate::drivers::usb_hid::dequeue_event() {
        let clients = unsafe { &mut CLIENTS };
        match ev.kind {
            crate::drivers::usb_hid::EvKind::Key { code, pressed } =>
                super::seat::send_key_event(clients, 0, code as u32, pressed),
            crate::drivers::usb_hid::EvKind::RelMouse { dx, dy } =>
                super::seat::send_pointer_motion(clients, dx as i32, dy as i32),
            _ => {}
        }
    }
}
