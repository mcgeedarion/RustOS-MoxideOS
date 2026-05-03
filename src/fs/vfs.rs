//! Virtual filesystem — file descriptor table + multi-backend dispatch.

extern crate alloc;
use alloc::{string::String, vec::Vec};
use spin::Mutex;

pub struct RamfsInode {
    pub name: String,
    pub data: Vec<u8>,
    pub is_dir: bool,
}

static RAMFS: Mutex<Vec<RamfsInode>> = Mutex::new(Vec::new());

pub fn create_file(name: &str, data: &[u8]) {
    let mut ram = RAMFS.lock();
    if let Some(f) = ram.iter_mut().find(|f| f.name == name) { f.data = data.to_vec(); }
    else { ram.push(RamfsInode { name: String::from(name), data: data.to_vec(), is_dir: false }); }
}

pub fn lookup(name: &str) -> Option<Vec<u8>> {
    RAMFS.lock().iter().find(|f| f.name == name).map(|f| f.data.clone())
}

pub fn mkdir(path: &str, _mode: u32) -> isize {
    { let ram = RAMFS.lock(); if ram.iter().any(|f| f.name == path) { return -17; } }
    RAMFS.lock().push(RamfsInode { name: String::from(path), data: Vec::new(), is_dir: true });
    0
}

pub fn unlink(path: &str) -> isize {
    let mut ram = RAMFS.lock();
    let before = ram.len();
    ram.retain(|f| f.name != path);
    if ram.len() < before { 0 } else { -2 }
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
    pub path:     Option<String>,
}

const MAX_FDS: usize = 64;
static FD_TABLE: Mutex<[Option<Fd>; MAX_FDS]> = Mutex::new([const { None }; MAX_FDS]);

fn alloc_fd(fd: Fd) -> Option<usize> {
    let mut tbl = FD_TABLE.lock();
    for i in 3..MAX_FDS { if tbl[i].is_none() { tbl[i] = Some(fd); return Some(i); } }
    None
}

pub fn fd_exists(fdno: usize) -> bool {
    if fdno >= MAX_FDS { return false; }
    FD_TABLE.lock()[fdno].is_some()
}

pub fn fd_to_path(fdno: usize) -> Option<String> {
    let tbl = FD_TABLE.lock();
    let fd = tbl.get(fdno)?.as_ref()?;
    fd.path.clone()
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
        return alloc_fd(Fd { flags: O_RDONLY, pos: 0, backing: FdBacking::Ramfs(name), write_buf: None, path: Some(String::from(path)) }).ok_or(-23);
    }
    if path.starts_with("/dev/input/") {
        if let Some(fd) = crate::fs::devfs::open_input(path) { return Ok(fd); }
    }
    if crate::fs::devfs::is_dev_path(path) {
        if path == "/dev" {
            let data = crate::fs::devfs::readdir();
            let name = alloc::string::String::from("__dev_dir");
            create_file(&name, &data);
            return alloc_fd(Fd { flags: O_RDONLY, pos: 0, backing: FdBacking::Ramfs(name), write_buf: None, path: Some(String::from("/dev")) }).ok_or(-23);
        }
        return crate::fs::devfs::open(path).ok_or(-2);
    }
    if crate::fs::procfs::is_proc_path(path) {
        let data = crate::fs::procfs::read(path).ok_or(-2i32)?;
        let name = alloc::format!("__proc_{}", path);
        create_file(&name, &data);
        return alloc_fd(Fd { flags: O_RDONLY, pos: 0, backing: FdBacking::Ramfs(name), write_buf: None, path: Some(String::from(path)) }).ok_or(-23);
    }
    let write = flags & (O_WRONLY | O_RDWR) != 0;
    let creat  = flags & O_CREAT != 0;
    if let Some(ino) = crate::fs::ext2::stat(path) {
        return alloc_fd(Fd { flags, pos: 0, backing: FdBacking::Ext2(ino), write_buf: None, path: Some(String::from(path)) }).ok_or(-23);
    }
    {
        let ram = RAMFS.lock();
        if ram.iter().any(|f| f.name == path) {
            drop(ram);
            let wb = if write { Some(if flags & O_TRUNC != 0 { Vec::new() } else { lookup(path).unwrap_or_default() }) } else { None };
            return alloc_fd(Fd { flags, pos: 0, backing: FdBacking::Ramfs(String::from(path)), write_buf: wb, path: Some(String::from(path)) }).ok_or(-23);
        }
    }
    if creat {
        create_file(path, &[]);
        return alloc_fd(Fd { flags, pos: 0, backing: FdBacking::Ramfs(String::from(path)), write_buf: Some(Vec::new()), path: Some(String::from(path)) }).ok_or(-23);
    }
    Err(-2)
}

pub fn read(fdno: usize, buf: &mut [u8]) -> isize {
    if crate::fs::pipe::is_pipe_fd(fdno)  { return crate::fs::pipe::pipe_read(fdno, buf); }
    if crate::fs::devfs::get_dev_fd(fdno).is_some() { return crate::fs::devfs::read(fdno, buf); }
    let mut tbl = FD_TABLE.lock();
    let fd = match tbl[fdno].as_mut() { Some(f) => f, None => return -9 };
    if fd.flags & O_WRONLY != 0 { return -9; }
    let data: Vec<u8> = match &fd.backing {
        FdBacking::Ramfs(name) => {
            match RAMFS.lock().iter().find(|f| f.name == *name) { Some(f) => f.data.clone(), None => return -2 }
        }
        FdBacking::Ext2(ino) => match crate::fs::ext2::read_file_by_ino(*ino) { Some(d) => d, None => return -5 },
        FdBacking::Pipe(p)   => p.lock().clone(),
    };
    let available = data.len().saturating_sub(fd.pos);
    let n = buf.len().min(available);
    buf[..n].copy_from_slice(&data[fd.pos..fd.pos + n]);
    fd.pos += n;
    n as isize
}

pub fn write(fdno: usize, buf: &[u8]) -> isize {
    if crate::fs::pipe::is_pipe_fd(fdno) { return crate::fs::pipe::pipe_write(fdno, buf); }
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
    if crate::fs::pipe::pipe_close(fdno)   { return 0; }
    if crate::fs::poll::epoll_close(fdno)  { return 0; }
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

#[repr(C)]
struct Stat {
    st_dev: u64, st_ino: u64, st_nlink: u64, st_mode: u32, st_uid: u32, st_gid: u32,
    _pad0: u32, st_rdev: u64, st_size: i64, st_blksize: i64, st_blocks: i64,
    st_atim: [u64; 2], st_mtim: [u64; 2], st_ctim: [u64; 2], _unused: [i64; 3],
}

pub fn stat(path: &str, stat_va: usize) -> isize {
    if stat_va == 0 { return -14; }
    if crate::fs::procfs::is_proc_path(path) || crate::fs::devfs::is_dev_path(path) || crate::fs::sysfs::is_sys_path(path) {
        let s = Stat { st_dev: 1, st_ino: 1, st_nlink: 1, st_mode: 0o040755, st_uid: 0, st_gid: 0, _pad0: 0,
            st_rdev: 0, st_size: 0, st_blksize: 4096, st_blocks: 0, st_atim: [0;2], st_mtim: [0;2], st_ctim: [0;2], _unused: [0;3] };
        unsafe { core::ptr::write(stat_va as *mut Stat, s); }
        return 0;
    }
    if let Some(ino) = crate::fs::ext2::stat(path) {
        let size = crate::fs::ext2::file_size(ino).unwrap_or(0) as i64;
        let is_dir = crate::fs::ext2::is_dir(path);
        let mode: u32 = if is_dir { 0o040755 } else { 0o100644 };
        let s = Stat { st_dev: 2, st_ino: ino as u64, st_nlink: 1, st_mode: mode, st_uid: 0, st_gid: 0, _pad0: 0,
            st_rdev: 0, st_size: size, st_blksize: 4096, st_blocks: (size + 511) / 512,
            st_atim: [0;2], st_mtim: [0;2], st_ctim: [0;2], _unused: [0;3] };
        unsafe { core::ptr::write(stat_va as *mut Stat, s); }
        return 0;
    }
    match open(path, O_RDONLY) {
        Ok(fd) => {
            let size = fstat(fd).unwrap_or(0) as i64;
            let is_dir = { RAMFS.lock().iter().find(|f| f.name == path).map_or(false, |f| f.is_dir) };
            let mode: u32 = if is_dir { 0o040755 } else { 0o100644 };
            let s = Stat { st_dev: 2, st_ino: fd as u64, st_nlink: 1, st_mode: mode, st_uid: 0, st_gid: 0, _pad0: 0,
                st_rdev: 0, st_size: size, st_blksize: 4096, st_blocks: (size + 511) / 512,
                st_atim: [0;2], st_mtim: [0;2], st_ctim: [0;2], _unused: [0;3] };
            close(fd);
            unsafe { core::ptr::write(stat_va as *mut Stat, s); }
            0
        }
        Err(e) => e as isize,
    }
}

pub fn stat_path(path: &str) -> Option<(u64, bool, u64)> {
    if let Some(ino) = crate::fs::ext2::stat(path) {
        let size = crate::fs::ext2::file_size(ino).unwrap_or(0) as u64;
        return Some((size, crate::fs::ext2::is_dir(path), ino as u64));
    }
    let ram = RAMFS.lock();
    ram.iter().find(|f| f.name == path).map(|f| (f.data.len() as u64, f.is_dir, 0u64))
}

pub fn stat_path_legacy(path: &str) -> Option<u64> { stat_path(path).map(|(s, _, _)| s) }

pub fn inotify_notify(_path: &str, _mask: u32, _name: Option<&str>) {}

pub fn dup_fd(old_fd: usize, min_fd: usize) -> Option<usize> {
    dup_from(old_fd, min_fd).try_into().ok()
}

pub fn truncate(_fd: usize, _size: u64) -> isize { 0 }

pub fn list_dir(fd: usize) -> Option<alloc::vec::Vec<DirEntry>> {
    let tbl = FD_TABLE.lock();
    let f = tbl.get(fd)?.as_ref()?;
    let path = f.path.clone().unwrap_or_default();
    drop(tbl);
    let prefix = if path == "/" { alloc::string::String::new() } else {
        alloc::format!("{}/", path.trim_end_matches('/'))
    };
    let ram = RAMFS.lock();
    let entries: Vec<DirEntry> = ram.iter()
        .filter(|e| {
            if prefix.is_empty() { !e.name.is_empty() && !e.name.starts_with('_') }
            else { e.name.starts_with(&*prefix) && e.name != path }
        })
        .map(|e| DirEntry { name: e.name.clone(), is_dir: e.is_dir })
        .collect();
    Some(entries)
}

pub struct DirEntry { pub name: String, pub is_dir: bool }

pub fn readlink_fd(_n: usize) -> Option<alloc::string::String> { None }

pub fn is_dir(path: &str) -> bool {
    if crate::fs::ext2::is_dir(path) { return true; }
    RAMFS.lock().iter().any(|f| f.name == path && f.is_dir)
}

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

pub fn dup(oldfd: usize) -> isize { dup_from(oldfd, 0) }

fn alloc_fd_for_data(data: Vec<u8>) -> usize {
    let name = alloc::format!("__vfs_tmp_{}", crate::time::monotonic_ns());
    { RAMFS.lock().push(RamfsInode { name: name.clone(), data, is_dir: false }); }
    alloc_fd(Fd { flags: O_RDONLY, pos: 0, backing: FdBacking::Ramfs(name), write_buf: None, path: None }).unwrap_or(0)
}
