//! AF_UNIX SOCK_STREAM implementation.
extern crate alloc;
use alloc::string::String;
use alloc::sync::Arc;
use spin::Mutex;
use super::super::types::{SocketState, SockAddr, AF_UNIX, SOCK_STREAM};
use super::super::buffer::{UnixConn, UnixListener, PendingUnix};
use super::super::core::SOCKETS;

static UNIX_BINDS: spin::Mutex<alloc::collections::BTreeMap<String, usize>> =
    spin::Mutex::new(alloc::collections::BTreeMap::new());

pub fn unix_bind(fd: usize, path: String) -> isize {
    let mut binds = UNIX_BINDS.lock();
    if binds.contains_key(&path) { return -98; } // EADDRINUSE
    binds.insert(path.clone(), fd);
    drop(binds);
    let mut sockets = SOCKETS.lock();
    if let Some(Some(s)) = sockets.get_mut(fd) {
        s.local = Some(SockAddr::Unix(path));
        s.state = SocketState::Bound;
    }
    0
}

pub fn unix_listen(fd: usize, backlog: usize) -> isize {
    let mut sockets = SOCKETS.lock();
    if let Some(Some(s)) = sockets.get_mut(fd) {
        s.unix_listener = Some(Arc::new(Mutex::new(UnixListener {
            backlog: alloc::collections::VecDeque::new(),
            max_backlog: backlog,
        })));
        s.state = SocketState::Listening;
    }
    0
}

pub fn unix_accept(fd: usize) -> isize {
    let listener = {
        let sockets = SOCKETS.lock();
        let Some(Some(s)) = sockets.get(fd) else { return -9; };
        s.unix_listener.clone()
    };
    let Some(ul) = listener else { return -22; };
    let pending = ul.lock().backlog.pop_front();
    let Some(p) = pending else { return -11; }; // EAGAIN
    let mut sockets = SOCKETS.lock();
    for (i, slot) in sockets.iter_mut().enumerate() {
        if slot.is_none() {
            let mut s = super::super::core::new_socket(AF_UNIX, SOCK_STREAM, 0);
            s.state = SocketState::Connected;
            s.unix_conn = Some(Arc::new(p.server_conn));
            *slot = Some(s);
            return i as isize;
        }
    }
    -24 // EMFILE
}

pub fn unix_connect(fd: usize, path: &str) -> isize {
    let server_fd = *UNIX_BINDS.lock().get(path).unwrap_or(&usize::MAX);
    if server_fd == usize::MAX { return -2; }
    let (client_conn, server_conn) = UnixConn::new_pair();
    let listener = {
        let sockets = SOCKETS.lock();
        let Some(Some(s)) = sockets.get(server_fd) else { return -111; };
        s.unix_listener.clone()
    };
    let Some(ul) = listener else { return -111; };
    let mut ul_guard = ul.lock();
    if ul_guard.backlog.len() >= ul_guard.max_backlog { return -111; }
    ul_guard.backlog.push_back(PendingUnix { server_conn });
    drop(ul_guard);
    let mut sockets = SOCKETS.lock();
    if let Some(Some(s)) = sockets.get_mut(fd) {
        s.state = SocketState::Connected;
        s.unix_conn = Some(Arc::new(client_conn));
        s.peer = Some(SockAddr::Unix(path.into()));
    }
    0
}