//! Concrete URL dispatch adapters for filesystem-backed schemes.
//!
//! These adapters implement the `Scheme` trait for filesystems that already
//! expose VFS-facing helpers but previously registered placeholder URL handlers.

extern crate alloc;

use alloc::{collections::BTreeMap, format, string::String, sync::Arc, vec::Vec};
use core::sync::atomic::{AtomicU64, Ordering};
use spin::Mutex;

use crate::fs::scheme_table::Scheme;
use scheme_api::{OpenFlags, SchemeError, SchemeFileId};

#[inline]
fn errno_to_scheme_error(errno: isize) -> SchemeError {
    match errno {
        -2 => SchemeError::NotFound,
        -11 => SchemeError::WouldBlock,
        -13 | -30 => SchemeError::PermissionDenied,
        -20 | -21 | -22 => SchemeError::InvalidArg,
        _ => SchemeError::Io,
    }
}

#[inline]
fn access_from_flags(flags: OpenFlags) -> (bool, bool) {
    let writable = flags.intersects(
        OpenFlags::WRITE | OpenFlags::CREATE | OpenFlags::TRUNCATE | OpenFlags::APPEND,
    );
    let readable = flags.contains(OpenFlags::READ) || !writable;
    (readable, writable)
}

fn checked_seek(current: usize, size: usize, offset: i64, whence: u8) -> Result<usize, SchemeError> {
    let base = match whence {
        0 => 0i64,
        1 => current as i64,
        2 => size as i64,
        _ => return Err(SchemeError::InvalidArg),
    };

    let next = base.checked_add(offset).ok_or(SchemeError::InvalidArg)?;
    if next < 0 {
        return Err(SchemeError::InvalidArg);
    }

    Ok(next as usize)
}

// ---------------------------------------------------------------------------
// overlay:<path>
// ---------------------------------------------------------------------------

struct OverlaySchemeFd {
    mount: crate::fs::overlayfs::OverlayMount,
    rel: String,
    offset: usize,
    readable: bool,
    writable: bool,
}

static OVERLAY_SCHEME_FDS: Mutex<BTreeMap<u64, OverlaySchemeFd>> = Mutex::new(BTreeMap::new());
static OVERLAY_SCHEME_NEXT_FID: AtomicU64 = AtomicU64::new(1);

pub struct OverlayFs;

impl OverlayFs {
    pub const fn new() -> Self {
        Self
    }
}

fn overlay_scheme_path(path: &str) -> String {
    let p = path.trim();
    if p.is_empty() {
        String::from("/")
    } else if p.starts_with('/') {
        String::from(p)
    } else {
        format!("/{}", p)
    }
}

fn overlay_scheme_resolve(
    path: &str,
) -> Result<(crate::fs::overlayfs::OverlayMount, String), SchemeError> {
    let full = overlay_scheme_path(path);
    let mounts = crate::fs::overlayfs::OVERLAY_MOUNTS.lock();

    let mut best: Option<(&String, &crate::fs::overlayfs::OverlayMount)> = None;
    for (mp, mount) in mounts.iter() {
        let matches = if mp == "/" {
            full.starts_with('/')
        } else {
            full == *mp || full.starts_with(&format!("{}/", mp.trim_end_matches('/')))
        };

        if matches
            && best
                .as_ref()
                .map(|(best_mp, _)| mp.len() > best_mp.len())
                .unwrap_or(true)
        {
            best = Some((mp, mount));
        }
    }

    let (mp, mount) = best.ok_or(SchemeError::NotFound)?;
    let rel = if mp == "/" {
        full.trim_start_matches('/').to_string()
    } else if full == *mp {
        String::from("/")
    } else {
        full[mp.len()..].trim_start_matches('/').to_string()
    };

    let rel = if rel.is_empty() || rel == "/" {
        String::from("/")
    } else {
        format!("/{}", rel)
    };

    Ok((mount.clone(), rel))
}

fn overlay_dir_listing(
    mount: &crate::fs::overlayfs::OverlayMount,
    rel: &str,
) -> Result<Vec<u8>, SchemeError> {
    let entries = crate::fs::overlayfs::readdir(mount, rel).map_err(errno_to_scheme_error)?;
    let mut out = Vec::new();

    for entry in entries {
        out.extend_from_slice(entry.name.as_bytes());
        out.push(b'\n');
    }

    Ok(out)
}

impl Scheme for OverlayFs {
    fn open(&self, path: &str, flags: OpenFlags) -> Result<SchemeFileId, SchemeError> {
        let (mount, rel) = overlay_scheme_resolve(path)?;
        let (readable, writable) = access_from_flags(flags);

        match crate::fs::overlayfs::stat(&mount, &rel) {
            Ok(st) => {
                if st.is_dir && !flags.contains(OpenFlags::DIRECTORY) {
                    return Err(SchemeError::InvalidArg);
                }
            },
            Err(-2) if flags.contains(OpenFlags::CREATE) => {
                crate::fs::overlayfs::create(&mount, &rel).map_err(errno_to_scheme_error)?;
            },
            Err(e) => return Err(errno_to_scheme_error(e)),
        }

        if flags.contains(OpenFlags::TRUNCATE) {
            crate::fs::overlayfs::truncate(&mount, &rel, 0).map_err(errno_to_scheme_error)?;
        }

        let offset = if flags.contains(OpenFlags::APPEND) {
            crate::fs::overlayfs::stat(&mount, &rel)
                .map(|st| st.size as usize)
                .unwrap_or(0)
        } else {
            0
        };

        let fid = OVERLAY_SCHEME_NEXT_FID.fetch_add(1, Ordering::Relaxed);
        OVERLAY_SCHEME_FDS.lock().insert(
            fid,
            OverlaySchemeFd {
                mount,
                rel,
                offset,
                readable,
                writable,
            },
        );

        Ok(SchemeFileId(fid))
    }

    fn read(&self, fid: SchemeFileId, buf: &mut [u8]) -> Result<usize, SchemeError> {
        let (mount, rel, offset, readable) = {
            let fds = OVERLAY_SCHEME_FDS.lock();
            let fd = fds.get(&fid.0).ok_or(SchemeError::NotFound)?;
            (fd.mount.clone(), fd.rel.clone(), fd.offset, fd.readable)
        };

        if !readable {
            return Err(SchemeError::PermissionDenied);
        }

        let st = crate::fs::overlayfs::stat(&mount, &rel).map_err(errno_to_scheme_error)?;
        let data = if st.is_dir {
            overlay_dir_listing(&mount, &rel)?
        } else {
            let mut data = Vec::new();
            crate::fs::overlayfs::read(&mount, &rel, &mut data).map_err(errno_to_scheme_error)?;
            data
        };

        let start = offset.min(data.len());
        let n = buf.len().min(data.len().saturating_sub(start));
        buf[..n].copy_from_slice(&data[start..start + n]);

        if n > 0 {
            if let Some(fd) = OVERLAY_SCHEME_FDS.lock().get_mut(&fid.0) {
                fd.offset = fd.offset.saturating_add(n);
            }
        }

        Ok(n)
    }

    fn write(&self, fid: SchemeFileId, buf: &[u8]) -> Result<usize, SchemeError> {
        let (mount, rel, offset, writable) = {
            let fds = OVERLAY_SCHEME_FDS.lock();
            let fd = fds.get(&fid.0).ok_or(SchemeError::NotFound)?;
            (fd.mount.clone(), fd.rel.clone(), fd.offset, fd.writable)
        };

        if !writable {
            return Err(SchemeError::PermissionDenied);
        }

        let mut full = {
            let mut data = Vec::new();
            match crate::fs::overlayfs::read(&mount, &rel, &mut data) {
                Ok(_) => data,
                Err(-2) => Vec::new(),
                Err(e) => return Err(errno_to_scheme_error(e)),
            }
        };

        let end = offset.saturating_add(buf.len());
        if offset > full.len() {
            full.resize(offset, 0);
        }
        if end > full.len() {
            full.resize(end, 0);
        }

        full[offset..end].copy_from_slice(buf);
        crate::fs::overlayfs::write(&mount, &rel, &full).map_err(errno_to_scheme_error)?;

        if let Some(fd) = OVERLAY_SCHEME_FDS.lock().get_mut(&fid.0) {
            fd.offset = fd.offset.saturating_add(buf.len());
        }

        Ok(buf.len())
    }

    fn seek(&self, fid: SchemeFileId, offset: i64, whence: u8) -> Result<u64, SchemeError> {
        let mut fds = OVERLAY_SCHEME_FDS.lock();
        let fd = fds.get_mut(&fid.0).ok_or(SchemeError::NotFound)?;
        let size = crate::fs::overlayfs::stat(&fd.mount, &fd.rel)
            .map_err(errno_to_scheme_error)?
            .size as usize;

        fd.offset = checked_seek(fd.offset, size, offset, whence)?;
        Ok(fd.offset as u64)
    }

    fn close(&self, fid: SchemeFileId) -> Result<(), SchemeError> {
        OVERLAY_SCHEME_FDS.lock().remove(&fid.0);
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// cgroup:<path>
// ---------------------------------------------------------------------------

struct CgroupSchemeFd {
    path: String,
    offset: usize,
    readable: bool,
    writable: bool,
}

static CGROUP_SCHEME_FDS: Mutex<BTreeMap<u64, CgroupSchemeFd>> = Mutex::new(BTreeMap::new());
static CGROUP_SCHEME_NEXT_FID: AtomicU64 = AtomicU64::new(1);

pub struct CgroupFs;

impl CgroupFs {
    pub const fn new() -> Self {
        Self
    }
}

fn cgroup_scheme_path(path: &str) -> String {
    let p = path.trim_start_matches('/');

    if p.is_empty() {
        String::from("/sys/fs/cgroup")
    } else if p == "sys/fs/cgroup" || p.starts_with("sys/fs/cgroup/") {
        format!("/{}", p)
    } else {
        format!("/sys/fs/cgroup/{}", p)
    }
}

fn cgroup_scheme_read_all(path: &str) -> Result<Vec<u8>, SchemeError> {
    match crate::fs::cgroupfs::cgroupfs_exists(path) {
        Some(true) => {
            let entries = crate::fs::cgroupfs::cgroupfs_list_dir_by_path(path)
                .ok_or(SchemeError::InvalidArg)?;
            let mut out = Vec::new();

            for entry in entries {
                out.extend_from_slice(entry.name.as_bytes());
                out.push(b'\n');
            }

            Ok(out)
        },
        Some(false) => {
            let fd = crate::fs::cgroupfs::cgroupfs_open(path);
            if fd < 0 {
                return Err(errno_to_scheme_error(fd));
            }

            let fd = fd as usize;
            let mut out = Vec::new();
            let mut chunk = [0u8; 4096];

            loop {
                let n = crate::fs::cgroupfs::cgroupfs_read(fd, &mut chunk);
                if n < 0 {
                    crate::fs::cgroupfs::cgroupfs_close(fd);
                    return Err(errno_to_scheme_error(n));
                }
                if n == 0 {
                    break;
                }

                out.extend_from_slice(&chunk[..n as usize]);

                if n < chunk.len() as isize {
                    break;
                }
            }

            crate::fs::cgroupfs::cgroupfs_close(fd);
            Ok(out)
        },
        None => Err(SchemeError::NotFound),
    }
}

impl Scheme for CgroupFs {
    fn open(&self, path: &str, flags: OpenFlags) -> Result<SchemeFileId, SchemeError> {
        if flags.intersects(OpenFlags::CREATE | OpenFlags::TRUNCATE | OpenFlags::APPEND) {
            return Err(SchemeError::InvalidArg);
        }

        let full_path = cgroup_scheme_path(path);
        let is_dir = crate::fs::cgroupfs::cgroupfs_exists(&full_path).ok_or(SchemeError::NotFound)?;

        if is_dir && flags.contains(OpenFlags::WRITE) {
            return Err(SchemeError::InvalidArg);
        }
        if is_dir && !flags.contains(OpenFlags::DIRECTORY) {
            return Err(SchemeError::InvalidArg);
        }

        let writable = flags.contains(OpenFlags::WRITE);
        let readable = flags.contains(OpenFlags::READ) || !writable;
        let fid = CGROUP_SCHEME_NEXT_FID.fetch_add(1, Ordering::Relaxed);

        CGROUP_SCHEME_FDS.lock().insert(
            fid,
            CgroupSchemeFd {
                path: full_path,
                offset: 0,
                readable,
                writable,
            },
        );

        Ok(SchemeFileId(fid))
    }

    fn read(&self, fid: SchemeFileId, buf: &mut [u8]) -> Result<usize, SchemeError> {
        let (path, offset, readable) = {
            let fds = CGROUP_SCHEME_FDS.lock();
            let fd = fds.get(&fid.0).ok_or(SchemeError::NotFound)?;
            (fd.path.clone(), fd.offset, fd.readable)
        };

        if !readable {
            return Err(SchemeError::PermissionDenied);
        }

        let data = cgroup_scheme_read_all(&path)?;
        let start = offset.min(data.len());
        let n = buf.len().min(data.len().saturating_sub(start));

        buf[..n].copy_from_slice(&data[start..start + n]);

        if n > 0 {
            if let Some(fd) = CGROUP_SCHEME_FDS.lock().get_mut(&fid.0) {
                fd.offset = fd.offset.saturating_add(n);
            }
        }

        Ok(n)
    }

    fn write(&self, fid: SchemeFileId, buf: &[u8]) -> Result<usize, SchemeError> {
        let (path, writable) = {
            let fds = CGROUP_SCHEME_FDS.lock();
            let fd = fds.get(&fid.0).ok_or(SchemeError::NotFound)?;
            (fd.path.clone(), fd.writable)
        };

        if !writable {
            return Err(SchemeError::PermissionDenied);
        }

        crate::fs::vfs_ops::write_all(&path, buf).map_err(errno_to_scheme_error)?;

        if let Some(fd) = CGROUP_SCHEME_FDS.lock().get_mut(&fid.0) {
            fd.offset = fd.offset.saturating_add(buf.len());
        }

        Ok(buf.len())
    }

    fn seek(&self, fid: SchemeFileId, offset: i64, whence: u8) -> Result<u64, SchemeError> {
        let mut fds = CGROUP_SCHEME_FDS.lock();
        let fd = fds.get_mut(&fid.0).ok_or(SchemeError::NotFound)?;
        let size = cgroup_scheme_read_all(&fd.path)?.len();

        fd.offset = checked_seek(fd.offset, size, offset, whence)?;
        Ok(fd.offset as u64)
    }

    fn close(&self, fid: SchemeFileId) -> Result<(), SchemeError> {
        CGROUP_SCHEME_FDS.lock().remove(&fid.0);
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// dev:<path>
// ---------------------------------------------------------------------------

enum DevSchemeKind {
    Directory {
        data: Vec<u8>,
        offset: usize,
    },
    InputEvent {
        minor: usize,
        nonblock: bool,
        ops: Arc<dyn crate::fs::vfs_ops::FileOps + Send + Sync>,
    },
}

static DEV_SCHEME_FDS: Mutex<BTreeMap<u64, DevSchemeKind>> = Mutex::new(BTreeMap::new());
static DEV_SCHEME_NEXT_FID: AtomicU64 = AtomicU64::new(1);

pub struct DevFs;

impl DevFs {
    pub const fn new() -> Self {
        Self
    }
}

fn dev_scheme_path(path: &str) -> String {
    let p = path.trim_start_matches('/');

    if p.is_empty() {
        String::from("/dev")
    } else if p == "dev" || p.starts_with("dev/") {
        format!("/{}", p)
    } else if p.starts_with("event") {
        format!("/dev/input/{}", p)
    } else {
        format!("/dev/{}", p)
    }
}

fn dev_parse_input_minor(path: &str) -> Option<usize> {
    let rel = path.strip_prefix("/dev/input/event")?;
    rel.parse::<usize>().ok()
}

fn dev_dir_listing(path: &str) -> Option<Vec<u8>> {
    if path == "/dev" || path == "/dev/" {
        return Some(b"input\n".to_vec());
    }

    if path == "/dev/input" || path == "/dev/input/" {
        let mut out = Vec::new();
        for minor in 0..crate::input::device_count() {
            out.extend_from_slice(format!("event{}\n", minor).as_bytes());
        }
        return Some(out);
    }

    None
}

fn dev_read_dir(data: &[u8], offset: &mut usize, buf: &mut [u8]) -> usize {
    let start = (*offset).min(data.len());
    let n = buf.len().min(data.len().saturating_sub(start));
    buf[..n].copy_from_slice(&data[start..start + n]);
    *offset = (*offset).saturating_add(n);
    n
}

fn dev_read_input_event(minor: usize, nonblock: bool, buf: &mut [u8]) -> Result<usize, SchemeError> {
    const EV_SIZE: usize = core::mem::size_of::<crate::input::InputEvent>();

    if buf.len() < EV_SIZE {
        return Err(SchemeError::InvalidArg);
    }

    let dev = crate::input::device(minor).ok_or(SchemeError::NotFound)?;
    let mut written = 0usize;

    let dropped = dev.ring.drain_dropped();
    if dropped > 0 && buf.len().saturating_sub(written) >= EV_SIZE {
        let ev = crate::input::InputEvent {
            r#type: crate::input::EV_SYN,
            code: crate::input::SYN_DROPPED,
            value: dropped as i32,
            ..Default::default()
        };

        let bytes = unsafe {
            core::slice::from_raw_parts(
                (&ev as *const crate::input::InputEvent).cast::<u8>(),
                EV_SIZE,
            )
        };
        buf[written..written + EV_SIZE].copy_from_slice(bytes);
        written += EV_SIZE;
    }

    loop {
        while dev.ring.is_readable() && buf.len().saturating_sub(written) >= EV_SIZE {
            let ev = dev.ring.pop().ok_or(SchemeError::Io)?;
            let bytes = unsafe {
                core::slice::from_raw_parts(
                    (&ev as *const crate::input::InputEvent).cast::<u8>(),
                    EV_SIZE,
                )
            };

            buf[written..written + EV_SIZE].copy_from_slice(bytes);
            written += EV_SIZE;
        }

        if written > 0 {
            return Ok(written);
        }

        if nonblock {
            return Err(SchemeError::WouldBlock);
        }

        dev.waitq.wait_until(|| dev.ring.is_readable());
    }
}

fn dev_ioctl_error(errno: i32) -> SchemeError {
    errno_to_scheme_error(errno as isize)
}

impl Scheme for DevFs {
    fn open(&self, path: &str, flags: OpenFlags) -> Result<SchemeFileId, SchemeError> {
        if flags.intersects(OpenFlags::WRITE | OpenFlags::CREATE | OpenFlags::TRUNCATE | OpenFlags::APPEND) {
            return Err(SchemeError::PermissionDenied);
        }

        let full_path = dev_scheme_path(path);
        let kind = if let Some(data) = dev_dir_listing(&full_path) {
            if !flags.contains(OpenFlags::DIRECTORY) {
                return Err(SchemeError::InvalidArg);
            }

            DevSchemeKind::Directory { data, offset: 0 }
        } else {
            let minor = dev_parse_input_minor(&full_path).ok_or(SchemeError::NotFound)?;
            let ops = crate::fs::devfs::devfs_open(&full_path).ok_or(SchemeError::NotFound)?;

            DevSchemeKind::InputEvent {
                minor,
                nonblock: flags.contains(OpenFlags::NON_BLOCK),
                ops,
            }
        };

        let fid = DEV_SCHEME_NEXT_FID.fetch_add(1, Ordering::Relaxed);
        DEV_SCHEME_FDS.lock().insert(fid, kind);
        Ok(SchemeFileId(fid))
    }

    fn read(&self, fid: SchemeFileId, buf: &mut [u8]) -> Result<usize, SchemeError> {
        let (minor, nonblock) = {
            let mut fds = DEV_SCHEME_FDS.lock();
            let fd = fds.get_mut(&fid.0).ok_or(SchemeError::NotFound)?;

            match fd {
                DevSchemeKind::Directory { data, offset } => {
                    return Ok(dev_read_dir(data, offset, buf));
                },
                DevSchemeKind::InputEvent {
                    minor, nonblock, ..
                } => (*minor, *nonblock),
            }
        };

        dev_read_input_event(minor, nonblock, buf)
    }

    fn ioctl(&self, fid: SchemeFileId, cmd: u64, arg: usize) -> Result<usize, SchemeError> {
        let ops = {
            let fds = DEV_SCHEME_FDS.lock();
            let fd = fds.get(&fid.0).ok_or(SchemeError::NotFound)?;

            match fd {
                DevSchemeKind::InputEvent { ops, .. } => Arc::clone(ops),
                DevSchemeKind::Directory { .. } => return Err(SchemeError::InvalidArg),
            }
        };

        ops.ioctl(cmd as u32, arg)
            .map(|n| n as usize)
            .map_err(dev_ioctl_error)
    }

    fn seek(&self, fid: SchemeFileId, offset: i64, whence: u8) -> Result<u64, SchemeError> {
        let mut fds = DEV_SCHEME_FDS.lock();
        let fd = fds.get_mut(&fid.0).ok_or(SchemeError::NotFound)?;

        match fd {
            DevSchemeKind::Directory { data, offset: cur } => {
                *cur = checked_seek(*cur, data.len(), offset, whence)?;
                Ok(*cur as u64)
            },
            DevSchemeKind::InputEvent { .. } => Err(SchemeError::InvalidArg),
        }
    }

    fn close(&self, fid: SchemeFileId) -> Result<(), SchemeError> {
        if let Some(DevSchemeKind::InputEvent { ops, .. }) = DEV_SCHEME_FDS.lock().remove(&fid.0) {
            ops.close();
        }

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// nfs:<path>
// ---------------------------------------------------------------------------

struct NfsSchemeFd {
    fh: crate::fs::nfs::Fh,
    offset: usize,
    readable: bool,
    writable: bool,
    is_dir: bool,
}

static NFS_SCHEME_FDS: Mutex<BTreeMap<u64, NfsSchemeFd>> = Mutex::new(BTreeMap::new());
static NFS_SCHEME_NEXT_FID: AtomicU64 = AtomicU64::new(1);

pub struct NfsScheme;

impl NfsScheme {
    pub const fn new() -> Self {
        Self
    }
}

fn nfs_scheme_path(path: &str) -> String {
    let p = path.trim();

    if p.is_empty() {
        String::from("/")
    } else if p.starts_with('/') {
        String::from(p)
    } else {
        format!("/{}", p)
    }
}

fn nfs_is_dir(st: &crate::fs::nfs::NfsStat) -> bool {
    st.ftype == 2
}

fn nfs_parent_name(path: &str) -> Option<(&str, &str)> {
    let p = path.trim_end_matches('/');

    if p.is_empty() || p == "/" {
        return None;
    }

    match p.rfind('/') {
        Some(0) => Some(("/", &p[1..])),
        Some(idx) => Some((&p[..idx], &p[idx + 1..])),
        None => Some(("/", p)),
    }
}

fn nfs_dir_listing(fh: &crate::fs::nfs::Fh) -> Vec<u8> {
    let mut out = Vec::new();

    for entry in crate::fs::nfs::readdirplus(fh) {
        out.extend_from_slice(entry.name.as_bytes());
        out.push(b'\n');
    }

    out
}

impl Scheme for NfsScheme {
    fn open(&self, path: &str, flags: OpenFlags) -> Result<SchemeFileId, SchemeError> {
        if !crate::fs::nfs::is_mounted() {
            return Err(SchemeError::Unreachable);
        }

        if flags.contains(OpenFlags::TRUNCATE) {
            return Err(SchemeError::InvalidArg);
        }

        let path = nfs_scheme_path(path);
        let fh = match crate::fs::nfs::path_to_fh(&path) {
            Some(fh) => {
                if flags.contains(OpenFlags::EXCLUSIVE) && flags.contains(OpenFlags::CREATE) {
                    return Err(SchemeError::InvalidArg);
                }
                fh
            },
            None if flags.contains(OpenFlags::CREATE) => {
                let (parent, name) = nfs_parent_name(&path).ok_or(SchemeError::InvalidArg)?;
                let parent_fh = crate::fs::nfs::path_to_fh(parent).ok_or(SchemeError::NotFound)?;
                crate::fs::nfs::create(&parent_fh, name, 0o644).ok_or(SchemeError::Io)?
            },
            None => return Err(SchemeError::NotFound),
        };

        let st = crate::fs::nfs::getattr(&fh).ok_or(SchemeError::Io)?;
        let is_dir = nfs_is_dir(&st);

        if is_dir && !flags.contains(OpenFlags::DIRECTORY) {
            return Err(SchemeError::InvalidArg);
        }
        if is_dir && flags.intersects(OpenFlags::WRITE | OpenFlags::APPEND) {
            return Err(SchemeError::InvalidArg);
        }

        let (readable, writable) = access_from_flags(flags);
        let offset = if flags.contains(OpenFlags::APPEND) {
            st.size as usize
        } else {
            0
        };

        let fid = NFS_SCHEME_NEXT_FID.fetch_add(1, Ordering::Relaxed);
        NFS_SCHEME_FDS.lock().insert(
            fid,
            NfsSchemeFd {
                fh,
                offset,
                readable,
                writable,
                is_dir,
            },
        );

        Ok(SchemeFileId(fid))
    }

    fn read(&self, fid: SchemeFileId, buf: &mut [u8]) -> Result<usize, SchemeError> {
        let (fh, offset, readable, is_dir) = {
            let fds = NFS_SCHEME_FDS.lock();
            let fd = fds.get(&fid.0).ok_or(SchemeError::NotFound)?;
            (fd.fh.clone(), fd.offset, fd.readable, fd.is_dir)
        };

        if !readable {
            return Err(SchemeError::PermissionDenied);
        }

        let n = if is_dir {
            let data = nfs_dir_listing(&fh);
            let start = offset.min(data.len());
            let n = buf.len().min(data.len().saturating_sub(start));
            buf[..n].copy_from_slice(&data[start..start + n]);
            n
        } else {
            let data = crate::fs::nfs::read(&fh, offset as u64, buf.len() as u32)
                .ok_or(SchemeError::Io)?;
            let n = data.len().min(buf.len());
            buf[..n].copy_from_slice(&data[..n]);
            n
        };

        if n > 0 {
            if let Some(fd) = NFS_SCHEME_FDS.lock().get_mut(&fid.0) {
                fd.offset = fd.offset.saturating_add(n);
            }
        }

        Ok(n)
    }

    fn write(&self, fid: SchemeFileId, buf: &[u8]) -> Result<usize, SchemeError> {
        let (fh, offset, writable, is_dir) = {
            let fds = NFS_SCHEME_FDS.lock();
            let fd = fds.get(&fid.0).ok_or(SchemeError::NotFound)?;
            (fd.fh.clone(), fd.offset, fd.writable, fd.is_dir)
        };

        if !writable {
            return Err(SchemeError::PermissionDenied);
        }
        if is_dir {
            return Err(SchemeError::InvalidArg);
        }

        let written = crate::fs::nfs::write(&fh, offset as u64, buf)
            .ok_or(SchemeError::Io)? as usize;

        if written > 0 {
            if let Some(fd) = NFS_SCHEME_FDS.lock().get_mut(&fid.0) {
                fd.offset = fd.offset.saturating_add(written);
            }
        }

        Ok(written)
    }

    fn seek(&self, fid: SchemeFileId, offset: i64, whence: u8) -> Result<u64, SchemeError> {
        let mut fds = NFS_SCHEME_FDS.lock();
        let fd = fds.get_mut(&fid.0).ok_or(SchemeError::NotFound)?;

        let size = if fd.is_dir {
            nfs_dir_listing(&fd.fh).len()
        } else {
            crate::fs::nfs::getattr(&fd.fh).ok_or(SchemeError::Io)?.size as usize
        };

        fd.offset = checked_seek(fd.offset, size, offset, whence)?;
        Ok(fd.offset as u64)
    }

    fn close(&self, fid: SchemeFileId) -> Result<(), SchemeError> {
        NFS_SCHEME_FDS.lock().remove(&fid.0);
        Ok(())
    }
}
