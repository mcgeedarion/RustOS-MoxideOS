//! IPC-proxy scheme — forwards `Scheme` trait calls to a userspace
//! driver process over an `IpcEndpoint`.

use alloc::vec::Vec;
use spin::Mutex;

use scheme_api::{
    IpcEndpoint, OpenFlags, SchemeError, SchemeFileId, SchemeRequest, SchemeResponse,
};

use crate::ipc::{endpoint_recv, endpoint_send};

use super::scheme_table::Scheme;

/// A `Scheme` implementation that transparently proxies every call to a
/// registered userspace driver process.
pub struct IpcProxyScheme {
    name: alloc::string::String,
    endpoint: IpcEndpoint,
    lock: Mutex<()>,
}

impl IpcProxyScheme {
    /// Construct a placeholder proxy for schemes that are intentionally
    /// unavailable until a userspace service registers a real endpoint.
    pub fn new() -> Self {
        Self::with_endpoint("ipc", IpcEndpoint(0))
    }

    pub fn with_endpoint(name: &str, endpoint: IpcEndpoint) -> Self {
        Self {
            name: alloc::string::String::from(name),
            endpoint,
            lock: Mutex::new(()),
        }
    }

    /// Send `req` to the driver and wait for a `SchemeResponse`.
    fn call(&self, req: SchemeRequest) -> Result<SchemeResponse, SchemeError> {
        // Serialise: only one in-flight call at a time per scheme.
        let _guard = self.lock.lock();

        // Serialise request to bytes and send.
        let msg = encode_request(&req);
        endpoint_send(self.endpoint, &msg).map_err(|_| SchemeError::Unreachable)?;

        // Block until the driver responds.
        let resp_bytes = endpoint_recv(self.endpoint).map_err(|_| SchemeError::Unreachable)?;

        decode_response(&resp_bytes).ok_or(SchemeError::Io)
    }
}

impl Scheme for IpcProxyScheme {
    fn open(&self, path: &str, flags: OpenFlags) -> Result<SchemeFileId, SchemeError> {
        let req = SchemeRequest::Open {
            path: alloc::string::String::from(path),
            flags,
        };
        match self.call(req)? {
            SchemeResponse::Fd(fid) => Ok(fid),
            SchemeResponse::Err(e) => Err(e),
            _ => Err(SchemeError::Io),
        }
    }

    fn read(&self, fd: SchemeFileId, buf: &mut [u8]) -> Result<usize, SchemeError> {
        let req = SchemeRequest::Read { fd, len: buf.len() };
        match self.call(req)? {
            SchemeResponse::Data(data) => {
                let n = data.len().min(buf.len());
                buf[..n].copy_from_slice(&data[..n]);
                Ok(n)
            },
            SchemeResponse::Err(e) => Err(e),
            _ => Err(SchemeError::Io),
        }
    }

    fn write(&self, fd: SchemeFileId, buf: &[u8]) -> Result<usize, SchemeError> {
        let req = SchemeRequest::Write {
            fd,
            data: buf.to_vec(),
        };
        match self.call(req)? {
            SchemeResponse::Count(n) => Ok(n),
            SchemeResponse::Err(e) => Err(e),
            _ => Err(SchemeError::Io),
        }
    }

    fn ioctl(&self, fd: SchemeFileId, cmd: u64, arg: usize) -> Result<usize, SchemeError> {
        let req = SchemeRequest::Ioctl { fd, cmd, arg };
        match self.call(req)? {
            SchemeResponse::Count(n) => Ok(n),
            SchemeResponse::Err(e) => Err(e),
            _ => Err(SchemeError::Io),
        }
    }

    fn seek(&self, fd: SchemeFileId, offset: i64, whence: u8) -> Result<u64, SchemeError> {
        use scheme_api::SeekWhence;
        let whence = match whence {
            0 => SeekWhence::Start,
            1 => SeekWhence::Current,
            2 => SeekWhence::End,
            _ => return Err(SchemeError::InvalidArg),
        };
        let req = SchemeRequest::Seek { fd, offset, whence };
        match self.call(req)? {
            SchemeResponse::SeekPos(pos) if pos >= 0 => Ok(pos as u64),
            SchemeResponse::SeekPos(_) => Err(SchemeError::InvalidArg),
            SchemeResponse::Err(e) => Err(e),
            _ => Err(SchemeError::Io),
        }
    }

    fn close(&self, fd: SchemeFileId) -> Result<(), SchemeError> {
        let req = SchemeRequest::Close { fd };
        match self.call(req)? {
            SchemeResponse::Ok => Ok(()),
            SchemeResponse::Err(e) => Err(e),
            _ => Err(SchemeError::Io),
        }
    }
}

///
const TAG_OPEN: u8 = 1;
const TAG_READ: u8 = 2;
const TAG_WRITE: u8 = 3;
const TAG_IOCTL: u8 = 4;
const TAG_SEEK: u8 = 5;
const TAG_CLOSE: u8 = 6;

const RESP_FD: u8 = 0x80;
const RESP_DATA: u8 = 0x81;
const RESP_COUNT: u8 = 0x82;
const RESP_SEEK: u8 = 0x83;
const RESP_OK: u8 = 0x84;
const RESP_ERR: u8 = 0xFF;

fn encode_request(req: &SchemeRequest) -> Vec<u8> {
    let mut buf = Vec::new();
    match req {
        SchemeRequest::Open { path, flags } => {
            buf.push(TAG_OPEN);
            push_u32(&mut buf, flags.bits());
            push_str(&mut buf, path);
        },
        SchemeRequest::Read { fd, len } => {
            buf.push(TAG_READ);
            push_u64(&mut buf, fd.0);
            push_u64(&mut buf, *len as u64);
        },
        SchemeRequest::Write { fd, data } => {
            buf.push(TAG_WRITE);
            push_u64(&mut buf, fd.0);
            push_bytes(&mut buf, data);
        },
        SchemeRequest::Ioctl { fd, cmd, arg } => {
            buf.push(TAG_IOCTL);
            push_u64(&mut buf, fd.0);
            push_u64(&mut buf, *cmd);
            push_u64(&mut buf, *arg as u64);
        },
        SchemeRequest::Seek { fd, offset, whence } => {
            buf.push(TAG_SEEK);
            push_u64(&mut buf, fd.0);
            push_u64(&mut buf, *offset as u64);
            buf.push(*whence as u8);
        },
        SchemeRequest::Close { fd } => {
            buf.push(TAG_CLOSE);
            push_u64(&mut buf, fd.0);
        },
    }
    buf
}

fn decode_response(buf: &[u8]) -> Option<SchemeResponse> {
    let (&tag, rest) = buf.split_first()?;
    match tag {
        RESP_FD => Some(SchemeResponse::Fd(SchemeFileId(read_u64(rest)?))),
        RESP_DATA => Some(SchemeResponse::Data(rest.to_vec())),
        RESP_COUNT => Some(SchemeResponse::Count(read_u64(rest)? as usize)),
        RESP_SEEK => Some(SchemeResponse::SeekPos(read_u64(rest)? as i64)),
        RESP_OK => Some(SchemeResponse::Ok),
        RESP_ERR => {
            let code = read_u32(rest)? as u32;
            let e = scheme_error_from_u32(code);
            Some(SchemeResponse::Err(e))
        },
        _ => None,
    }
}

fn push_u32(v: &mut Vec<u8>, n: u32) {
    v.extend_from_slice(&n.to_le_bytes());
}
fn push_u64(v: &mut Vec<u8>, n: u64) {
    v.extend_from_slice(&n.to_le_bytes());
}
fn push_str(v: &mut Vec<u8>, s: &str) {
    push_u32(v, s.len() as u32);
    v.extend_from_slice(s.as_bytes());
}
fn push_bytes(v: &mut Vec<u8>, b: &[u8]) {
    push_u32(v, b.len() as u32);
    v.extend_from_slice(b);
}
fn read_u32(b: &[u8]) -> Option<u32> {
    b.get(..4)
        .map(|s| u32::from_le_bytes(s.try_into().unwrap()))
}
fn read_u64(b: &[u8]) -> Option<u64> {
    b.get(..8)
        .map(|s| u64::from_le_bytes(s.try_into().unwrap()))
}
fn scheme_error_from_u32(n: u32) -> SchemeError {
    match n {
        1 => SchemeError::NoSuchScheme,
        2 => SchemeError::NotFound,
        3 => SchemeError::PermissionDenied,
        4 => SchemeError::InvalidArg,
        5 => SchemeError::WouldBlock,
        6 => SchemeError::Io,
        7 => SchemeError::Unreachable,
        _ => SchemeError::Other,
    }
}
