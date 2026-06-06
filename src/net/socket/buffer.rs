extern crate alloc;
use alloc::collections::VecDeque;
use alloc::sync::Arc;
use alloc::vec::Vec;
use spin::Mutex;

pub struct UnixPipe {
    pub buf: VecDeque<u8>,
    pub closed: bool,
}

pub struct UnixConn {
    pub rx: Arc<Mutex<UnixPipe>>,
    pub tx: Arc<Mutex<UnixPipe>>,
}

impl UnixConn {
    pub fn new_pair() -> (UnixConn, UnixConn) {
        let a_to_b = Arc::new(Mutex::new(UnixPipe {
            buf: VecDeque::new(),
            closed: false,
        }));
        let b_to_a = Arc::new(Mutex::new(UnixPipe {
            buf: VecDeque::new(),
            closed: false,
        }));
        let a = UnixConn {
            rx: b_to_a.clone(),
            tx: a_to_b.clone(),
        };
        let b = UnixConn {
            rx: a_to_b,
            tx: b_to_a,
        };
        (a, b)
    }
    pub fn write(&self, data: &[u8]) {
        self.tx.lock().buf.extend(data.iter().copied());
    }
    pub fn read(&self, len: usize) -> Vec<u8> {
        let mut p = self.rx.lock();
        let n = len.min(p.buf.len());
        p.buf.drain(..n).collect()
    }
    pub fn is_readable(&self) -> bool {
        let p = self.rx.lock();
        !p.buf.is_empty() || p.closed
    }
    pub fn close_tx(&self) {
        self.tx.lock().closed = true;
    }
}

pub struct PendingUnix {
    pub server_conn: UnixConn,
}

pub struct UnixListener {
    pub backlog: VecDeque<PendingUnix>,
    pub max_backlog: usize,
}
