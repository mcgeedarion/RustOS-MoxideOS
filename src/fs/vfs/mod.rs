//! Virtual filesystem core.

pub mod fd;
pub mod ops;
pub mod uring;

// Preserve the historical `crate::fs::vfs::*` facade after moving the raw
// descriptor implementation into `fd.rs`.
pub use fd::*;

/// Compatibility helper for older callers that create and populate a file in
/// one step.
pub fn create_file(path: &str, data: &[u8]) -> Result<(), isize> {
    match ops::create(path) {
        Ok(()) | Err(-17) => {},
        Err(e) => return Err(e),
    }
    ops::write_all(path, data)
}

fn errno_to_scheme_error(errno: isize) -> scheme_api::SchemeError {
    match errno {
        -2 => scheme_api::SchemeError::NotFound,
        -5 => scheme_api::SchemeError::Io,
        -9 => scheme_api::SchemeError::InvalidArg,
        -11 => scheme_api::SchemeError::WouldBlock,
        -13 => scheme_api::SchemeError::PermissionDenied,
        -22 => scheme_api::SchemeError::InvalidArg,
        -30 => scheme_api::SchemeError::PermissionDenied,
        _ => scheme_api::SchemeError::Other,
    }
}

fn flags_to_raw(flags: scheme_api::OpenFlags) -> u32 {
    const O_WRONLY: u32 = 1;
    const O_RDWR: u32 = 2;
    const O_CREAT: u32 = 0o100;
    const O_TRUNC: u32 = 0o1000;
    const O_APPEND: u32 = 0o2000;

    let mut out = if flags.contains(scheme_api::OpenFlags::READ)
        && flags.contains(scheme_api::OpenFlags::WRITE)
    {
        O_RDWR
    } else if flags.contains(scheme_api::OpenFlags::WRITE) {
        O_WRONLY
    } else {
        0
    };

    if flags.contains(scheme_api::OpenFlags::CREATE) {
        out |= O_CREAT;
    }
    if flags.contains(scheme_api::OpenFlags::TRUNCATE) {
        out |= O_TRUNC;
    }
    if flags.contains(scheme_api::OpenFlags::APPEND) {
        out |= O_APPEND;
    }

    out
}

/// VFS scheme adapter.
///
/// `file:<path>` routes into the normal VFS raw-fd table. The returned
/// `SchemeFileId` is the raw backing fd from `vfs::fd`.
pub struct VfsScheme;

impl VfsScheme {
    pub const fn new() -> Self {
        Self
    }
}

impl crate::fs::scheme_table::Scheme for VfsScheme {
    fn open(
        &self,
        path: &str,
        flags: scheme_api::OpenFlags,
    ) -> Result<scheme_api::SchemeFileId, scheme_api::SchemeError> {
        let path = if path.is_empty() { "/" } else { path };
        let fd = fd::open_raw(path, flags_to_raw(flags)).map_err(errno_to_scheme_error)?;
        Ok(scheme_api::SchemeFileId(fd as u64))
    }

    fn read(
        &self,
        fid: scheme_api::SchemeFileId,
        buf: &mut [u8],
    ) -> Result<usize, scheme_api::SchemeError> {
        let n = fd::read_raw(fid.0 as usize, buf);
        if n < 0 {
            return Err(errno_to_scheme_error(n));
        }
        Ok(n as usize)
    }

    fn write(
        &self,
        fid: scheme_api::SchemeFileId,
        buf: &[u8],
    ) -> Result<usize, scheme_api::SchemeError> {
        let n = fd::write_raw(fid.0 as usize, buf);
        if n < 0 {
            return Err(errno_to_scheme_error(n));
        }
        Ok(n as usize)
    }

    fn seek(
        &self,
        fid: scheme_api::SchemeFileId,
        offset: i64,
        whence: u8,
    ) -> Result<u64, scheme_api::SchemeError> {
        let n = fd::seek_raw(fid.0 as usize, offset, whence as i32);
        if n < 0 {
            return Err(errno_to_scheme_error(n));
        }
        Ok(n as u64)
    }

    fn close(&self, fid: scheme_api::SchemeFileId) -> Result<(), scheme_api::SchemeError> {
        let n = fd::close_raw(fid.0 as usize);
        if n < 0 {
            return Err(errno_to_scheme_error(n));
        }
        Ok(())
    }
}