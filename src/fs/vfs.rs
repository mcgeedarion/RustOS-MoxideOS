//! Virtual filesystem — file descriptor table + multi-backend dispatch.
//!
//! Backends (tried in order on open):
//!   1. Ext2 image mounted by `mount_ext2()`
//!   2. In-memory ramfs (initramfs + runtime-created files)
//!
//! File descriptor table:
//!   FDs 0/1/2 are reserved (stdin/stdout/stderr — console I/O).
//!   FDs 3..MAX_FDS are heap-allocated per-process.
//!   The table lives in kernel global space for now; a production kernel
//!   would move it into the PCB.

extern crate alloc;
use alloc::{string::String, vec::Vec};
use spin::Mutex;

pub struct RamfsInode {
    pub name: String,
    pub data: Vec<u8>,
}

static RAMFS: Mutex<Vec<RamfsInode>> = Mutex::new(Vec::new());

pub fn create_file(name: &str, data: &[u8]) {
    let mut ram = RAMFS.lock();
    if let Some(f) = ram.iter_mut().find(|f| f.name == name) {
        f.data = data.to_vec();
    } else {
        ram.push(RamfsInode { name: String::from(name), data: data.to_vec() });
    }
}

pub fn lookup(name: &str) -> Option<Vec<u8>> {
    RAMFS.lock().iter().find(|f| f.name == name).map(|f| f.data.clone())
}

pub const O_RDONLY: u32 = 0;
pub const O_WRONLY: u32 = 1;
pub const O_RDWR:   u32 = 2;
pub const O_CREAT:  u32 = 0o100;
pub const O_TRUNC:  u32 = 0o1000;
pub const O_APPEND: u32 = 0o2000;

#[derive(Clone)]
enum FdBacking {
    Ramfs(String),
    Ext2(u32),
    Pipe(alloc::sync::Arc<Mutex<Vec<u8>>>),
}

#[derive(Clone)]
pub struct Fd {
    pub flags:    u32,
    pub pos:      usize,
    backing:      FdBacking,
    write_buf:    Option<Vec<u8>>,
}

const MAX_FDS: usize = 64;
static FD_TABLE: Mutex<[Option<Fd>; MAX_FDS]> = Mutex::new([const { None }; MAX_FDS]);

fn alloc_fd(fd: Fd) -> Option<usize> {
    let mut tbl = FD_TABLE.lock();
    for i in 3..MAX_FDS {
        if tbl[i].is_none() { tbl[i] = Some(fd); return Some(i); }
    }
    None
}

pub fn open(path: &str, flags: u32) -> Result<usize, i32> {
    if path == "/proc/self/maps" || path == "/proc/maps" {
        return Ok(alloc_fd_for_data(crate::fs::procfs::proc_self_maps()));
    }
    if path == "/proc/self/exe" {
        return Ok(alloc_fd_for_data(crate::fs::procfs::proc_self_exe()));
    }
    if let Some(rest) = path.strip_prefix("/proc/") {
        if let Some((pid_str, tail)) = rest.split_once('/') {
            if tail == "status" {
                if let Ok(pid) = pid_str.parse::<u32>() {
                    return Ok(alloc_fd_for_data(crate::fs::procfs::proc_pid_status(pid)));
                }
            }
        }
    }
    if let Some(rest) = path.strip_prefix("/proc/self/fd/") {
        if let Ok(fd_n) = rest.parse::<usize>() {
            return Ok(alloc_fd_for_data(crate::fs::procfs::proc_fd_link(fd_n)));
        }
    }
    if crate::fs::sysfs::is_sys_path(path) {
        let data = crate::fs::sysfs::read(path).ok_or(-2i32)?;
        let name = alloc::format!("__sys_{}", path);
        create_file(&name, &data);
        return alloc_fd(Fd { flags: O_RDONLY, pos: 0, backing: FdBacking::Ramfs(name), write_buf: None }).ok_or(-23);
    }
    if path.starts_with("/dev/input/") {
        if let Some(fd) = crate::fs::devfs::open_input(path) { return Ok(fd); }
    }
    if crate::fs::devfs::is_dev_path(path) {
        if path == "/dev" {
            let data = crate::fs::devfs::readdir();
            let name = alloc::string::String::from("__dev_dir");
            create_file(&name, &data);
            return alloc_fd(Fd { flags: O_RDONLY, pos: 0, backing: FdBacking::Ramfs(name), write_buf: None }).ok_or(-23);
        }
        return crate::fs::devfs::open(path).ok_or(-2);
    }
    if crate::fs::procfs::is_proc_path(path) {
        let data = crate::fs::procfs::read(path).ok_or(-2i32)?;
        let name = alloc::format!("__proc_{}", path);
        create_file(&name, &data);
        return alloc_fd(Fd { flags: O_RDONLY, pos: 0, backing: FdBacking::Ramfs(name), write_buf: None }).ok_or(-23);
    }
    let write = flags & (O_WRONLY | O_RDWR) != 0;
    let creat  = flags & O_CREAT != 0;
    if let Some(ino) = crate::fs::ext2::stat(path) {
        return alloc_fd(Fd { flags, pos: 0, backing: FdBacking::Ext2(ino), write_buf: None }).ok_or(-23);
    }
    {
        let ram = RAMFS.lock();
        if ram.iter().any(|f| f.name == path) {
            drop(ram);
            let wb = if write { Some(if flags & O_TRUNC != 0 { Vec::new() } else { lookup(path).unwrap_or_default() }) } else { None };
            return alloc_fd(Fd { flags, pos: 0, backing: FdBacking::Ramfs(String::from(path)), write_buf: wb }).ok_or(-23);
        }
    }
    if creat {
        create_file(path, &[]);
        return alloc_fd(Fd { flags, pos: 0, backing: FdBacking::Ramfs(String::from(path)), write_buf: Some(Vec::new()) }).ok_or(-23);
    }
    Err(-2)
}

pub fn read(fdno: usize, buf: &mut [u8]) -> isize {
    if crate::fs::devfs::get_dev_fd(fdno).is_some() { return crate::fs::devfs::read(fdno, buf); }
    let mut tbl = FD_TABLE.lock();
    let fd = match tbl[fdno].as_mut() { Some(f) => f, None => return -9 };
    if fd.flags & O_WRONLY != 0 { return -9; }
    let data: Vec<u8> = match &fd.backing {
        FdBacking::Ramfs(name) => {
            match RAMFS.lock().iter().find(|f| f.name == *name) { Some(f) => f.data.clone(), None => return -2 }
        }
        FdBacking::Ext2(ino) => match crate::fs::ext2::read_file_by_ino(*ino) { Some(d) => d, None => return -5 },
        FdBacking::Pipe(p) => p.lock().clone(),
    };
    let available = data.len().saturating_sub(fd.pos);
    let n = buf.len().min(available);
    buf[..n].copy_from_slice(&data[fd.pos..fd.pos + n]);
    fd.pos += n;
    n as isize
}

pub fn write(fdno: usize, buf: &[u8]) -> isize {
    if crate::fs::devfs::get_dev_fd(fdno).is_some() { return crate::fs::devfs::write(fdno, buf); }
    let mut tbl = FD_TABLE.lock();
    let fd = match tbl[fdno].as_mut() { Some(f) => f, None => return -9 };
    let n = buf.len();
    match &mut fd.backing {
        FdBacking::Ramfs(name) => {
            if let Some(wb) = fd.write_buf.as_mut() {
                if fd.flags & O_APPEND != 0 { wb.extend_from_slice(buf); }
                else { let end = fd.pos + n; if end > wb.len() { wb.resize(end, 0); } wb[fd.pos..end].copy_from_slice(buf); }
                fd.pos += n;
                let name = name.clone(); let data = wb.clone();
                drop(tbl);
                create_file(&name, &data);
                return n as isize;
            }
        }
        FdBacking::Pipe(p) => { p.lock().extend_from_slice(buf); fd.pos += n; return n as isize; }
        FdBacking::Ext2(_) => return -1,
    }
    -1
}

pub const SEEK_SET: i32 = 0;
pub const SEEK_CUR: i32 = 1;
pub const SEEK_END: i32 = 2;

pub fn seek(fdno: usize, offset: i64, whence: i32) -> isize {
    let mut tbl = FD_TABLE.lock();
    let fd = match tbl[fdno].as_mut() { Some(f) => f, None => return -9 };
    let file_size = match &fd.backing {
        FdBacking::Ramfs(name) => RAMFS.lock().iter().find(|f| f.name == *name).map_or(0, |f| f.data.len()),
        FdBacking::Ext2(ino)   => crate::fs::ext2::file_size(*ino).unwrap_or(0),
        FdBacking::Pipe(_)     => 0,
    };
    let new_pos = match whence {
        SEEK_SET => offset as isize,
        SEEK_CUR => fd.pos as isize + offset as isize,
        SEEK_END => file_size as isize + offset as isize,
        _        => return -22,
    };
    if new_pos < 0 { return -22; }
    fd.pos = new_pos as usize;
    new_pos
}

pub fn close(fdno: usize) -> isize {
    if crate::fs::devfs::close_dev_fd(fdno) { return 0; }
    if fdno < 3 { return -9; }
    FD_TABLE.lock()[fdno] = None;
    0
}

pub fn fstat(fdno: usize) -> Option<usize> {
    let tbl = FD_TABLE.lock();
    let fd = tbl[fdno].as_ref()?;
    let sz = match &fd.backing {
        FdBacking::Ramfs(name) => RAMFS.lock().iter().find(|f| f.name == *name).map_or(0, |f| f.data.len()),
        FdBacking::Ext2(ino)   => crate::fs::ext2::file_size(*ino).unwrap_or(0),
        FdBacking::Pipe(_)     => 0,
    };
    Some(sz)
}

pub fn pread(fdno: usize, buf: *mut u8, count: usize, offset: i64) -> isize {
    let old_pos = { let tbl = FD_TABLE.lock(); tbl[fdno].as_ref().map_or(0, |f| f.pos) };
    seek(fdno, offset, SEEK_SET);
    let mut tmp = alloc::vec![0u8; count];
    let n = read(fdno, &mut tmp);
    if n > 0 { unsafe { core::ptr::copy_nonoverlapping(tmp.as_ptr(), buf, n as usize); } }
    seek(fdno, old_pos as i64, SEEK_SET);
    n
}

pub fn access(path: &str, _mode: u32) -> isize {
    if crate::fs::procfs::is_proc_path(path) || crate::fs::devfs::is_dev_path(path) || crate::fs::sysfs::is_sys_path(path) { return 0; }
    match open(path, O_RDONLY) { Ok(fd) => { close(fd); 0 } Err(e) => e as isize }
}

// ── stat ────────────────────────────────────────────────────────────────

#[repr(C)]
struct Stat {
    st_dev:     u64,
    st_ino:     u64,
    st_nlink:   u64,
    st_mode:    u32,
    st_uid:     u32,
    st_gid:     u32,
    _pad0:      u32,
    st_rdev:    u64,
    st_size:    i64,
    st_blksize: i64,
    st_blocks:  i64,
    st_atim:    [u64; 2],
    st_mtim:    [u64; 2],
    st_ctim:    [u64; 2],
    _unused:    [i64; 3],
}

pub fn stat(path: &str, stat_va: usize) -> isize {
    if stat_va == 0 { return -14; }
    if crate::fs::procfs::is_proc_path(path) || crate::fs::devfs::is_dev_path(path) || crate::fs::sysfs::is_sys_path(path) {
        let s = Stat { st_dev: 1, st_ino: 1, st_nlink: 1, st_mode: 0o040755, st_uid: 0, st_gid: 0, _pad0: 0,
            st_rdev: 0, st_size: 0, st_blksize: 4096, st_blocks: 0, st_atim: [0;2], st_mtim: [0;2], st_ctim: [0;2], _unused: [0;3] };
        unsafe { core::ptr::write(stat_va as *mut Stat, s); }
        return 0;
    }
    match open(path, O_RDONLY) {
        Ok(fd) => {
            let size = fstat(fd).unwrap_or(0) as i64;
            let s = Stat { st_dev: 2, st_ino: fd as u64, st_nlink: 1, st_mode: 0o100644, st_uid: 0, st_gid: 0, _pad0: 0,
                st_rdev: 0, st_size: size, st_blksize: 4096, st_blocks: (size + 511) / 512,
                st_atim: [0;2], st_mtim: [0;2], st_ctim: [0;2], _unused: [0;3] };
            unsafe { core::ptr::write(stat_va as *mut Stat, s); }
            close(fd);
            0
        }
        Err(e) => e as isize,
    }
}

/// Extended stat returning (size_bytes, is_directory, inode_number).
/// Used by sys_newfstatat to fill struct stat.
pub fn stat_path(path: &str) -> Option<(u64, bool, u64)> {
    if path.starts_with("/proc") || path.starts_with("/sys") {
        return Some((0, path.ends_with('/') || !path.contains('.'), 0));
    }
    match open(path, 0) {
        Ok(fd) => {
            let sz  = fstat(fd).unwrap_or(0);
            let ino = fd as u64;
            close(fd);
            Some((sz as u64, false, ino))
        }
        Err(_) => {
            if path.ends_with('/') || is_dir(path) { Some((4096, true, 0)) }
            else { None }
        }
    }
}

/// Compat shim for callers that only need the file size.
pub fn stat_path_legacy(path: &str) -> Option<u64> {
    stat_path(path).map(|(sz,_,_)| sz)
}

pub fn inotify_notify(path: &str, mask: u32, name: Option<&str>) {
    crate::fs::inotify::notify_event(path, mask, name);
}

pub fn dup_fd(old_fd: usize, min_fd: usize) -> Option<usize> {
    if let Some(vfd) = get_fd(old_fd) {
        let new_fd = alloc_fd_for_data(vfd.data().to_vec());
        if new_fd >= min_fd { return Some(new_fd); }
    }
    if crate::ipc::unix_socket::is_unix_sock(old_fd) { return Some(old_fd); }
    if is_dri_fd(old_fd) { return Some(alloc_dri_fd()); }
    if is_zero_fd(old_fd) { return Some(alloc_zero_fd()); }
    if is_rng_fd(old_fd) { return Some(alloc_rng_fd()); }
    None
}

pub fn truncate(_fd: usize, _size: u64) -> isize { 0 }

pub struct DirEntry {
    pub name: alloc::string::String,
    pub kind: u8,
}

pub fn list_dir(fd: usize) -> Option<alloc::vec::Vec<DirEntry>> {
    extern crate alloc;
    use alloc::{vec::Vec, string::String};
    if let Some(path) = get_fd_path(fd) {
        if path == "/proc/self/fd" || path == "/proc/1/fd" {
            let mut entries = Vec::new();
            for candidate in 0..256usize {
                if is_open(candidate) { entries.push(DirEntry { name: alloc::format!("{}", candidate), kind: 10 }); }
            }
            return Some(entries);
        }
        if path == "/dev/dri" || path == "/dev/dri/" {
            return Some(alloc::vec![
                DirEntry { name: String::from("card0"), kind: 2 },
                DirEntry { name: String::from("renderD128"), kind: 2 },
            ]);
        }
        if path == "/dev/input" || path == "/dev/input/" {
            return Some(alloc::vec![
                DirEntry { name: String::from("event0"), kind: 2 },
                DirEntry { name: String::from("event1"), kind: 2 },
            ]);
        }
    }
    if let Some(entries) = crate::fs::ext2::readdir(fd) {
        return Some(entries.into_iter().map(|e| DirEntry {
            name: e.name, kind: if e.is_dir { 4 } else { 8 },
        }).collect());
    }
    None
}

fn is_open(fd: usize) -> bool {
    get_fd(fd).is_some()
    || is_dri_fd(fd)
    || crate::ipc::unix_socket::is_unix_sock(fd)
    || crate::fs::signalfd::is_signalfd(fd)
    || crate::fs::timerfd::is_timerfd(fd)
    || crate::fs::eventfd::is_eventfd(fd)
    || crate::fs::inotify::is_inotify_fd(fd)
}

pub fn readlink_fd(n: usize) -> Option<alloc::string::String> {
    crate::fs::procfs::proc_fd_link(n)
}

/// Check whether a path refers to a directory.
/// Uses a prefix table of known VFS mount points.
pub fn is_dir(path: &str) -> bool {
    let dirs = ["/proc", "/sys", "/dev", "/tmp", "/etc", "/usr", "/lib",
                "/bin", "/var", "/run", "/home", "/root"];
    dirs.iter().any(|d| path.starts_with(d) && (path.len() == d.len() || path[d.len()..].starts_with('/')))
        || (!path.contains('.') && path.ends_with('/'))
}

// Stubs for functions referenced from syscall layer that may not exist in all build configs

#[inline(always)]
pub fn dup_as(oldfd: usize, newfd: usize) -> isize {
    let tbl = FD_TABLE.lock();
    if tbl.get(oldfd).and_then(|s| s.as_ref()).is_none() { return -9; }
    drop(tbl);
    let fd_clone = { FD_TABLE.lock()[oldfd].clone() };
    FD_TABLE.lock()[newfd] = fd_clone;
    newfd as isize
}

#[inline(always)]
pub fn dup_from(oldfd: usize, min_fd: usize) -> isize {
    let fd_clone = { FD_TABLE.lock()[oldfd].clone() };
    if fd_clone.is_none() { return -9; }
    let mut tbl = FD_TABLE.lock();
    for i in min_fd..MAX_FDS {
        if tbl[i].is_none() { tbl[i] = fd_clone; return i as isize; }
    }
    -23
}

fn alloc_fd_for_data(data: Vec<u8>) -> usize {
    let name = alloc::format!("__vfs_tmp_{}", crate::time::monotonic_ns());
    {
        let mut ram = RAMFS.lock();
        ram.push(RamfsInode { name: name.clone(), data });
    }
    let fd = Fd { flags: O_RDONLY, pos: 0, backing: FdBacking::Ramfs(name), write_buf: None };
    alloc_fd(fd).unwrap_or(0)
}

fn get_fd(_fd: usize) -> Option<FdRef> { None }
fn get_fd_path(_fd: usize) -> Option<String> { None }
fn is_dri_fd(_fd: usize) -> bool { false }
fn alloc_dri_fd() -> usize { 0 }
fn is_zero_fd(_fd: usize) -> bool { false }
fn alloc_zero_fd() -> usize { 0 }
fn is_rng_fd(_fd: usize) -> bool { false }
fn alloc_rng_fd() -> usize { 0 }

struct FdRef;
impl FdRef {
    fn data(&self) -> &[u8] { &[] }
}
