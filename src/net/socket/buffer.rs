extern crate alloc;
use alloc::{collections::VecDeque, sync::Arc, vec::Vec};
use spin::Mutex;

pub struct UnixPipe {
    pub buf: VecDeque<u8>,
    pub closed_write: bool,
    pub closed_read:  bool,
}

impl UnixPipe {
    pub fn new() -> Self {
        UnixPipe { buf: VecDeque::new(), closed_write: false, closed_read: false }
    }
    pub fn readable_bytes(&self) -> usize { self.buf.len() }
    pub fn write(&mut self, data: &[u8]) -> usize {
        for &b in data { self.buf.push_back(b); }
        data.len()
    }
    pub fn read(&mut self, into: &mut [u8]) -> usize {
        let n = into.len().min(self.buf.len());
        for b in &mut into[..n] { *b = self.buf.pop_front().unwrap(); }
        n
    }
}

pub type SharedPipe = Arc<Mutex<UnixPipe>>;
