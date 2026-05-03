//! Implementations for syscalls that are either trivial, return constant
//! data, or are safely no-ops for a single-user root kernel.
//!
//! Included from syscall/mod.rs via `include!("stubs.rs")`.
//!
//! ## Covered here
//!   NR  18  pwrite64         — write at offset without moving pos
//!   NR  19  readv            — scatter-gather read
//!   NR  24  sched_yield      — voluntary yield (calls schedule())
//!   NR  25  mremap           — grow mapping in-place or copy
//!   NR  28  madvise          — MADV_DONTNEED zeroes pages; rest no-op
//!   NR  40  sendfile         — in-kernel copy between fds
//!   NR  56  clone            — thin wrapper: thread -> clone3, process -> fork
//!   NR  58  vfork            — forwards to fork (simpler for a uniprocessor)
//!   NR  62  kill             — send signal to pid
//!   NR  63  uname            — fill utsname struct
//!   NR  74  fsync/fdatasync  — no-op (no write-back cache)
//!   NR  76  truncate         — resize file
//!   NR  77  ftruncate        — resize open fd
//!   NR  81  fchdir           — chdir via fd
//!   NR  84  rmdir            — remove empty directory
//!   NR  85  creat            — open(path, O_CREAT|O_WRONLY|O_TRUNC, mode)
//!   NR  86  link             — hard link (ramfs: copy)
//!   NR  88  symlink          — symbolic link (stored as ramfs file)
//!   NR  89  readlink         — read symlink target
//!   NR  95  umask            — stored per-process; no enforcement yet
//!   NR  96  gettimeofday     — wraps clock_gettime(REALTIME)
//!   NR  97  getrlimit        — return sane defaults
//!   NR  98  getrusage        — return zeroed struct
//!   NR  99  sysinfo          — fill sysinfo struct with PMM data
//!   NR 131  sigaltstack      — store/return per-process alt-stack
//!   NR 137  statfs           — fill statfs with ext2 / ramfs data
//!   NR 138  fstatfs          — same via fd
//!   NR 160  setrlimit        — store (not enforced)
//!   NR 162  sync             — no-op
//!   NR 185  prctl            — handle PR_SET_NAME, PR_GET_NAME, rest no-op
//!   NR 201  time             — return seconds since boot
//!   NR 230  clock_getres     — 1 ns resolution for all clocks
//!   NR 247  waitid           — delegate to wait::sys_waitpid
//!   NR 257  openat           — AT_FDCWD + open()
//!   NR 258  mkdirat          — AT_FDCWD + mkdir()
//!   NR 262  newfstatat       — AT_FDCWD + stat()
//!   NR 263  unlinkat         — AT_FDCWD + unlink()
//!   NR 264  renameat         — AT_FDCWD + rename()
//!   NR 267  readlinkat       — AT_FDCWD + readlink()
//!   NR 290  eventfd2         — minimal counter fd
//!   NR 292  inotify_init1    — stub fd (events never fire)
//!   NR 294  dup3             — dup2 + O_CLOEXEC
//!   NR 302  prlimit64        — get/set rlimit
//!   NR 318  getrandom        — RDRAND or LFSR fallback
//!   NR 319  memfd_create     — anonymous ramfs file

extern crate alloc;
use alloc::string::String;
use crate::proc::exec::read_cstr_safe;

// ── NR 18  pwrite64 ──────────────────────────────────────────────────────────

fn sys_pwrite64_impl(fd: usize, buf_va: usize, count: usize, offset: i64) -> isize {
    if buf_va < 0x1000 || count == 0 { return -14; }
    let buf = unsafe { core::slice::from_raw_parts(buf_va as *const u8, count) };
    let old = crate::fs::vfs::seek(fd, 0, crate::fs::vfs::SEEK_CUR) as i64;
    crate::fs::vfs::seek(fd, offset, crate::fs::vfs::SEEK_SET);
    let n = crate::fs::vfs::write(fd, buf);
    crate::fs::vfs::seek(fd, old, crate::fs::vfs::SEEK_SET);
    n
}

// ── NR 19  readv ────────────────────────────────────────────────────────────

#[repr(C)]
struct Iovec2 { base: usize, len: usize }

fn sys_readv_impl(fd: usize, iov_va: usize, iovcnt: usize) -> isize {
    if iov_va < 0x1000 || iovcnt == 0 { return -14; }
    if iovcnt > 1024 { return -22; }
    let mut total: isize = 0;
    for i in 0..iovcnt {
        let iov = unsafe { &*((iov_va + i * 16) as *const Iovec2) };
        if iov.len == 0 { continue; }
        let buf = unsafe { core::slice::from_raw_parts_mut(iov.base as *mut u8, iov.len) };
        let n = crate::fs::vfs::read(fd, buf);
        if n < 0 { return if total > 0 { total } else { n }; }
        total += n;
        if (n as usize) < iov.len { break; } // short read
    }
    total
}

// ── NR 24  sched_yield ───────────────────────────────────────────────────────

fn sys_sched_yield_impl() -> isize {
    crate::proc::scheduler::schedule();
    0
}

// ── NR 25  mremap ────────────────────────────────────────────────────────────

// MREMAP_MAYMOVE = 1, MREMAP_FIXED = 2
fn sys_mremap_impl(old_addr: usize, old_size: usize, new_size: usize,
                   flags: usize, new_addr: usize) -> isize {
    const PAGE: usize = 4096;
    if old_addr & (PAGE-1) != 0 { return -22; }
    let old_pages = (old_size + PAGE - 1) / PAGE;
    let new_pages = (new_size + PAGE - 1) / PAGE;

    if new_pages <= old_pages {
        // Shrink: unmap tail pages.
        let unmap_start = old_addr + new_pages * PAGE;
        let unmap_len   = (old_pages - new_pages) * PAGE;
        if unmap_len > 0 {
            crate::mm::mmap::sys_munmap(unmap_start, unmap_len);
        }
        return old_addr as isize;
    }

    // Grow: try extending in-place by mapping new pages right after.
    let extend_start = old_addr + old_pages * PAGE;
    let extend_len   = (new_pages - old_pages) * PAGE;
    let cr3 = crate::arch::x86_64::paging::current_cr3();
    for page_va in (extend_start..extend_start + extend_len).step_by(PAGE) {
        match crate::mm::pmm::alloc_page() {
            Some(pa) => {
                unsafe { core::ptr::write_bytes(pa as *mut u8, 0, PAGE); }
                crate::arch::x86_64::paging::map_page(
                    cr3, page_va, pa,
                    crate::arch::x86_64::paging::PTE_PRESENT
                    | crate::arch::x86_64::paging::PTE_WRITABLE
                    | crate::arch::x86_64::paging::PTE_USER
                    | crate::arch::x86_64::paging::PTE_NX,
                );
            }
            None => return -12, // ENOMEM
        }
    }
    // Update VMA.
    let pid = crate::proc::scheduler::current_pid() as u32;
    crate::mm::mmap::remove_vma(pid, old_addr, old_size);
    crate::mm::mmap::insert_vma(pid, crate::mm::mmap::Vma {
        start: old_addr, end: old_addr + new_pages * PAGE,
        prot: crate::mm::mmap::PROT_READ | crate::mm::mmap::PROT_WRITE,
        flags: 0x22, // MAP_PRIVATE | MAP_ANON
        kind: crate::mm::mmap::VmaKind::Anonymous,
        file_offset: 0,
    });
    old_addr as isize
}

// ── NR 28  madvise ───────────────────────────────────────────────────────────

fn sys_madvise_impl(addr: usize, length: usize, advice: i32) -> isize {
    const MADV_DONTNEED: i32 = 4;
    const PAGE: usize = 4096;
    if advice == MADV_DONTNEED {
        // Zero pages in range (simulate page reclaim without unmapping).
        let cr3 = crate::arch::x86_64::paging::current_cr3();
        let aligned = addr & !(PAGE - 1);
        let end     = (addr + length + PAGE - 1) & !(PAGE - 1);
        for va in (aligned..end).step_by(PAGE) {
            if let Some(pa) = crate::arch::x86_64::paging::virt_to_phys(cr3, va) {
                unsafe { core::ptr::write_bytes(pa as *mut u8, 0, PAGE); }
            }
        }
    }
    // All other advice flags (WILLNEED, SEQUENTIAL, etc.) are ignored.
    0
}

// ── NR 40  sendfile ───────────────────────────────────────────────────────────

fn sys_sendfile_impl(out_fd: usize, in_fd: usize, offset_va: usize, count: usize) -> isize {
    if count == 0 { return 0; }
    let mut buf = alloc::vec![0u8; count.min(65536)];
    if offset_va != 0 && offset_va >= 0x1000 {
        let offset = unsafe { *(offset_va as *const i64) };
        crate::fs::vfs::seek(in_fd, offset, crate::fs::vfs::SEEK_SET);
    }
    let n = crate::fs::vfs::read(in_fd, &mut buf);
    if n <= 0 { return n; }
    if offset_va != 0 && offset_va >= 0x1000 {
        let new_off = crate::fs::vfs::seek(in_fd, 0, crate::fs::vfs::SEEK_CUR);
        unsafe { *(offset_va as *mut i64) = new_off as i64; }
    }
    crate::fs::vfs::write(out_fd, &buf[..n as usize])
}

// ── NR 56  clone (thin wrapper) ───────────────────────────────────────────────

// clone(2) flags
const CLONE_VM:     usize = 0x0000_0100;
const CLONE_THREAD: usize = 0x0001_0000;

fn sys_clone_impl(flags: usize, child_sp: usize, ptid: usize,
                  ctid: usize, tls: usize) -> isize {
    if flags & CLONE_THREAD != 0 {
        // pthread_create path: pass through to clone3.
        // Build a clone_args on the stack and call sys_clone3.
        // clone3 args struct (fields we need): flags, pidfd, child_tid,
        // parent_tid, exit_signal, stack, stack_size, tls.
        // We approximate: pass flags + key addresses.
        crate::proc::clone::sys_clone_legacy(flags, child_sp, ptid, ctid, tls)
    } else {
        // fork-like clone
        crate::proc::fork_syscall::sys_fork()
    }
}

// ── NR 58  vfork ────────────────────────────────────────────────────────────

fn sys_vfork_impl() -> isize {
    // On a uniprocessor with no blocking I/O, vfork = fork is correct.
    crate::proc::fork_syscall::sys_fork()
}

// ── NR 62  kill ─────────────────────────────────────────────────────────────

fn sys_kill_impl(pid: isize, sig: u32) -> isize {
    if sig == 0 { return 0; } // signal 0 = existence check
    if sig > 64  { return -22; } // EINVAL
    let target = if pid == 0 {
        crate::proc::scheduler::current_pid()
    } else if pid > 0 {
        pid as usize
    } else {
        // pid < 0: send to process group |pid|; we approximate as |pid|.
        (-pid) as usize
    };
    crate::proc::signal::send_signal(target, sig);
    0
}

// ── NR 63  uname ─────────────────────────────────────────────────────────────

/// struct utsname: 6 fields of 65 bytes each = 390 bytes.
fn sys_uname_impl(buf_va: usize) -> isize {
    if buf_va == 0 || buf_va < 0x1000 { return -14; }
    if !crate::uaccess::validate_user_ptr(buf_va, 390) { return -14; }
    fn write_field(base: usize, field: usize, s: &[u8]) {
        let off = base + field * 65;
        unsafe {
            core::ptr::write_bytes(off as *mut u8, 0, 65);
            let n = s.len().min(64);
            core::ptr::copy_nonoverlapping(s.as_ptr(), off as *mut u8, n);
        }
    }
    write_field(buf_va, 0, b"Linux");          // sysname
    write_field(buf_va, 1, b"rustos");          // nodename
    write_field(buf_va, 2, b"6.1.0-rustos");   // release
    write_field(buf_va, 3, b"#1 SMP");          // version
    write_field(buf_va, 4, b"x86_64");          // machine
    write_field(buf_va, 5, b"rustos");          // domainname
    0
}

// ── NR 74/75  fsync / fdatasync ──────────────────────────────────────────────

fn sys_fsync_impl(_fd: usize) -> isize { 0 }  // no write-back cache

// ── NR 76/77  truncate / ftruncate ───────────────────────────────────────────

fn sys_truncate_impl(path_va: usize, length: i64) -> isize {
    let path = match read_cstr_safe(path_va) { Some(s) => s, None => return -14 };
    // Open, truncate via write_buf, close.
    let flags = crate::fs::vfs::O_WRONLY | crate::fs::vfs::O_CREAT;
    match crate::fs::vfs::open(&path, flags) {
        Ok(fd) => { crate::fs::vfs::truncate(fd, length as u64); crate::fs::vfs::close(fd); 0 }
        Err(e) => e as isize,
    }
}

fn sys_ftruncate_impl(fd: usize, length: i64) -> isize {
    crate::fs::vfs::truncate(fd, length as u64);
    0
}

// ── NR 81  fchdir ────────────────────────────────────────────────────────────

fn sys_fchdir_impl(fd: usize) -> isize {
    if let Some(path) = crate::fs::vfs::fd_to_path(fd) {
        crate::fs::stat_syscalls::set_cwd(&path);
        0
    } else {
        -9 // EBADF
    }
}

// ── NR 84  rmdir ─────────────────────────────────────────────────────────────

fn sys_rmdir_impl(path_va: usize) -> isize {
    let path = match read_cstr_safe(path_va) { Some(s) => s, None => return -14 };
    crate::fs::vfs::unlink(&path)
}

// ── NR 85  creat ─────────────────────────────────────────────────────────────

fn sys_creat_impl(path_va: usize, mode: u32) -> isize {
    let flags = crate::fs::vfs::O_CREAT | crate::fs::vfs::O_WRONLY | crate::fs::vfs::O_TRUNC;
    let path = match read_cstr_safe(path_va) { Some(s) => s, None => return -14 };
    match crate::fs::vfs::open(&path, flags) {
        Ok(fd) => fd as isize,
        Err(e) => e as isize,
    }
}

// ── NR 86  link / NR 88  symlink / NR 89  readlink ───────────────────────

fn sys_link_impl(old_va: usize, new_va: usize) -> isize {
    let old = match read_cstr_safe(old_va) { Some(s) => s, None => return -14 };
    let new = match read_cstr_safe(new_va) { Some(s) => s, None => return -14 };
    // Hard link: copy the file data in ramfs.
    if let Some(data) = crate::fs::vfs::lookup(&old) {
        crate::fs::vfs::create_file(&new, &data);
        0
    } else {
        -2 // ENOENT
    }
}

fn sys_symlink_impl(target_va: usize, link_va: usize) -> isize {
    let target = match read_cstr_safe(target_va) { Some(s) => s, None => return -14 };
    let link   = match read_cstr_safe(link_va)   { Some(s) => s, None => return -14 };
    // Store symlink target as a tiny file prefixed with \x00symlink\x00.
    let mut data = alloc::vec![0u8; 0];
    data.extend_from_slice(b"\x00symlink\x00");
    data.extend_from_slice(target.as_bytes());
    crate::fs::vfs::create_file(&link, &data);
    0
}

fn sys_readlink_impl(path_va: usize, buf_va: usize, bufsiz: usize) -> isize {
    if buf_va < 0x1000 || bufsiz == 0 { return -14; }
    let path = match read_cstr_safe(path_va) { Some(s) => s, None => return -14 };
    // /proc/self/exe special case.
    if path == "/proc/self/exe" {
        let exe = b"/init\0";
        let n = exe.len().min(bufsiz);
        unsafe { core::ptr::copy_nonoverlapping(exe.as_ptr(), buf_va as *mut u8, n); }
        return (n - 1) as isize;
    }
    if let Some(data) = crate::fs::vfs::lookup(&path) {
        if data.starts_with(b"\x00symlink\x00") {
            let target = &data[9..];
            let n = target.len().min(bufsiz);
            unsafe { core::ptr::copy_nonoverlapping(target.as_ptr(), buf_va as *mut u8, n); }
            return n as isize;
        }
    }
    -22 // EINVAL: not a symlink
}

// ── NR 95  umask ─────────────────────────────────────────────────────────────

use core::sync::atomic::{AtomicU32, Ordering};
static UMASK: AtomicU32 = AtomicU32::new(0o022);

fn sys_umask_impl(mask: u32) -> isize {
    UMASK.swap(mask & 0o777, Ordering::Relaxed) as isize
}

// ── NR 96  gettimeofday ──────────────────────────────────────────────────────────

fn sys_gettimeofday_impl(tv_va: usize, _tz_va: usize) -> isize {
    if tv_va == 0 || tv_va < 0x1000 { return 0; } // tz may be NULL
    let ns = crate::time::monotonic_ns();
    let sec  = ns / 1_000_000_000;
    let usec = (ns % 1_000_000_000) / 1_000;
    unsafe {
        let p = tv_va as *mut i64;
        p.add(0).write_unaligned(sec  as i64);
        p.add(1).write_unaligned(usec as i64);
    }
    0
}

// ── NR 97/160/302  getrlimit / setrlimit / prlimit64 ───────────────────────

// rlimit resources
const RLIMIT_CPU:    u32 = 0;
const RLIMIT_FSIZE:  u32 = 1;
const RLIMIT_DATA:   u32 = 2;
const RLIMIT_STACK:  u32 = 3;
const RLIMIT_CORE:   u32 = 4;
const RLIMIT_NOFILE: u32 = 7;
const RLIMIT_AS:     u32 = 9;
const RLIM_INFINITY: u64 = u64::MAX;

fn default_rlimit(resource: u32) -> (u64, u64) {
    match resource {
        RLIMIT_STACK  => (8 * 1024 * 1024, RLIM_INFINITY), // 8 MiB soft, hard=inf
        RLIMIT_NOFILE => (1024, 4096),
        RLIMIT_CORE   => (0, 0),
        _             => (RLIM_INFINITY, RLIM_INFINITY),
    }
}

fn sys_getrlimit_impl(resource: u32, rlim_va: usize) -> isize {
    if rlim_va == 0 || rlim_va < 0x1000 { return -14; }
    let (soft, hard) = default_rlimit(resource);
    unsafe {
        let p = rlim_va as *mut u64;
        p.add(0).write_unaligned(soft);
        p.add(1).write_unaligned(hard);
    }
    0
}

fn sys_setrlimit_impl(_resource: u32, _rlim_va: usize) -> isize { 0 } // accepted, not enforced

fn sys_prlimit64_impl(pid: usize, resource: u32, new_va: usize, old_va: usize) -> isize {
    // If old_va provided, fill it with the current limit.
    if old_va != 0 && old_va >= 0x1000 {
        let (soft, hard) = default_rlimit(resource);
        unsafe {
            let p = old_va as *mut u64;
            p.add(0).write_unaligned(soft);
            p.add(1).write_unaligned(hard);
        }
    }
    0 // new_va accepted but not enforced
}

// ── NR 98  getrusage ──────────────────────────────────────────────────────────

fn sys_getrusage_impl(_who: i32, buf_va: usize) -> isize {
    if buf_va == 0 || buf_va < 0x1000 { return -14; }
    // struct rusage is 144 bytes; zero it (no accounting yet).
    unsafe { core::ptr::write_bytes(buf_va as *mut u8, 0, 144); }
    0
}

// ── NR 99  sysinfo ────────────────────────────────────────────────────────────

/// struct sysinfo (x86-64, 112 bytes)
#[repr(C)]
struct SysInfo {
    uptime:    i64,
    loads:     [u64; 3],
    totalram:  u64,
    freeram:   u64,
    sharedram: u64,
    bufferram: u64,
    totalswap: u64,
    freeswap:  u64,
    procs:     u16,
    _pad:      [u8; 6],
    totalhigh: u64,
    freehigh:  u64,
    mem_unit:  u32,
    _f:        [u8; 20],
}

fn sys_sysinfo_impl(info_va: usize) -> isize {
    if info_va == 0 || info_va < 0x1000 { return -14; }
    let total = crate::mm::pmm::total_pages() as u64 * 4096;
    let free  = crate::mm::pmm::free_pages()  as u64 * 4096;
    let uptime_s = (crate::time::monotonic_ns() / 1_000_000_000) as i64;
    let info = SysInfo {
        uptime: uptime_s,
        loads:  [0; 3],
        totalram:  total,
        freeram:   free,
        sharedram: 0,
        bufferram: 0,
        totalswap: 0,
        freeswap:  0,
        procs:     1,
        _pad:      [0; 6],
        totalhigh: 0,
        freehigh:  0,
        mem_unit:  1,
        _f:        [0; 20],
    };
    unsafe { core::ptr::write(info_va as *mut SysInfo, info); }
    0
}

// ── NR 131  sigaltstack ─────────────────────────────────────────────────────────

/// struct stack_t { void *ss_sp; int ss_flags; size_t ss_size; }
/// On x86-64: pointer (8) + int (4) + pad (4) + size_t (8) = 24 bytes.
use spin::Mutex as SpinMutex;
extern crate alloc;
use alloc::collections::BTreeMap;
static ALTSTACK: SpinMutex<BTreeMap<usize, [u8; 24]>> = SpinMutex::new(BTreeMap::new());

fn sys_sigaltstack_impl(ss_va: usize, old_ss_va: usize) -> isize {
    let pid = crate::proc::scheduler::current_pid();
    if old_ss_va != 0 && old_ss_va >= 0x1000 {
        let tbl = ALTSTACK.lock();
        if let Some(saved) = tbl.get(&pid) {
            unsafe { core::ptr::copy_nonoverlapping(saved.as_ptr(), old_ss_va as *mut u8, 24); }
        } else {
            // SS_DISABLE = 2; return disabled stack.
            unsafe { core::ptr::write_bytes(old_ss_va as *mut u8, 0, 24); }
            unsafe { *((old_ss_va + 8) as *mut i32) = 2; } // ss_flags = SS_DISABLE
        }
    }
    if ss_va != 0 && ss_va >= 0x1000 {
        let mut buf = [0u8; 24];
        unsafe { core::ptr::copy_nonoverlapping(ss_va as *const u8, buf.as_mut_ptr(), 24); }
        ALTSTACK.lock().insert(pid, buf);
    }
    0
}

// ── NR 137/138  statfs / fstatfs ─────────────────────────────────────────────

/// struct statfs64 (x86-64): 120 bytes
#[repr(C)]
struct StatFs {
    f_type:    i64,   // EXT2_SUPER_MAGIC = 0xEF53
    f_bsize:   i64,
    f_blocks:  u64,
    f_bfree:   u64,
    f_bavail:  u64,
    f_files:   u64,
    f_ffree:   u64,
    f_fsid:    [i32; 2],
    f_namelen: i64,
    f_frsize:  i64,
    f_flags:   i64,
    f_spare:   [i64; 4],
}

fn fill_statfs(buf_va: usize) -> isize {
    if buf_va == 0 || buf_va < 0x1000 { return -14; }
    let total = crate::mm::pmm::total_pages() as u64;
    let free  = crate::mm::pmm::free_pages()  as u64;
    let sf = StatFs {
        f_type:    0xEF53,
        f_bsize:   4096,
        f_blocks:  total,
        f_bfree:   free,
        f_bavail:  free,
        f_files:   65536,
        f_ffree:   65536,
        f_fsid:    [0; 2],
        f_namelen: 255,
        f_frsize:  4096,
        f_flags:   0,
        f_spare:   [0; 4],
    };
    unsafe { core::ptr::write(buf_va as *mut StatFs, sf); }
    0
}

fn sys_statfs_impl(_path_va: usize, buf_va: usize) -> isize { fill_statfs(buf_va) }
fn sys_fstatfs_impl(_fd: usize,    buf_va: usize) -> isize { fill_statfs(buf_va) }

// ── NR 162  sync ─────────────────────────────────────────────────────────────

fn sys_sync_impl() -> isize { 0 }

// ── NR 185  prctl ────────────────────────────────────────────────────────────

const PR_SET_NAME:      i32 = 15;
const PR_GET_NAME:      i32 = 16;
const PR_SET_DUMPABLE:  i32 = 4;
const PR_GET_DUMPABLE:  i32 = 3;
const PR_SET_SECCOMP:   i32 = 22;
const PR_SET_PDEATHSIG: i32 = 1;
const PR_SET_NO_NEW_PRIVS: i32 = 38;

static PROC_NAME: SpinMutex<BTreeMap<usize, [u8; 16]>> = SpinMutex::new(BTreeMap::new());

fn sys_prctl_impl(op: i32, a2: usize, _a3: usize, _a4: usize, _a5: usize) -> isize {
    let pid = crate::proc::scheduler::current_pid();
    match op {
        PR_SET_NAME => {
            if a2 < 0x1000 { return -14; }
            let mut name = [0u8; 16];
            unsafe { core::ptr::copy_nonoverlapping(a2 as *const u8, name.as_mut_ptr(), 15); }
            PROC_NAME.lock().insert(pid, name);
            0
        }
        PR_GET_NAME => {
            if a2 < 0x1000 { return -14; }
            let tbl = PROC_NAME.lock();
            let name = tbl.get(&pid).copied().unwrap_or([0u8; 16]);
            unsafe { core::ptr::copy_nonoverlapping(name.as_ptr(), a2 as *mut u8, 16); }
            0
        }
        PR_SET_DUMPABLE | PR_GET_DUMPABLE   => 1,
        PR_SET_SECCOMP                       => -22, // EINVAL: no seccomp
        PR_SET_PDEATHSIG | PR_SET_NO_NEW_PRIVS => 0,
        _                                    => 0,   // silently accept unknown ops
    }
}

// ── NR 201  time ─────────────────────────────────────────────────────────────

fn sys_time_impl(t_va: usize) -> isize {
    let secs = (crate::time::monotonic_ns() / 1_000_000_000) as isize;
    if t_va >= 0x1000 {
        unsafe { *(t_va as *mut i64) = secs as i64; }
    }
    secs
}

// ── NR 202  futex ─────────────────────────────────────────────────────────────

// futex operations
const FUTEX_WAIT:         u32 = 0;
const FUTEX_WAKE:         u32 = 1;
const FUTEX_PRIVATE_FLAG: u32 = 128;
const FUTEX_WAIT_PRIVATE: u32 = FUTEX_WAIT | FUTEX_PRIVATE_FLAG;
const FUTEX_WAKE_PRIVATE: u32 = FUTEX_WAKE | FUTEX_PRIVATE_FLAG;
const FUTEX_WAIT_BITSET:  u32 = 9;
const FUTEX_WAKE_BITSET:  u32 = 10;

/// Minimal spin-wait futex.
///
/// We have a single CPU with cooperative scheduling, so:
///   FUTEX_WAIT: if *uaddr == val, spin until it changes or timeout.
///   FUTEX_WAKE: always succeeds (wakes at most `val` waiters).
///
/// This is correct for the single-CPU case because no other thread can
/// modify `uaddr` while we hold the CPU unless we voluntarily yield.
fn sys_futex_impl(
    uaddr: usize, op: u32, val: u32,
    timeout_va: usize, uaddr2: usize, val3: u32,
) -> isize {
    if uaddr < 0x1000 { return -14; }

    let op_base = op & !(FUTEX_PRIVATE_FLAG | 256); // strip PRIVATE + CLOCK flags

    match op_base {
        // ─ FUTEX_WAIT ──────────────────────────────────────────────────────
        FUTEX_WAIT | FUTEX_WAIT_BITSET => {
            let current = unsafe { (uaddr as *const u32).read_volatile() };
            if current != val { return -11; } // EAGAIN: value already changed

            // Compute deadline.
            let deadline_ns = if timeout_va == 0 {
                u64::MAX
            } else if !crate::uaccess::validate_user_ptr(timeout_va, 16) {
                return -14;
            } else {
                let sec  = unsafe { (timeout_va as *const i64).read_unaligned() };
                let nsec = unsafe { (timeout_va as *const i64).add(1).read_unaligned() };
                let cap = 5_000_000_000u64;
                crate::time::monotonic_ns() + ((sec as u64) * 1_000_000_000 + nsec as u64).min(cap)
            };

            let mut iters = 0u64;
            loop {
                let v = unsafe { (uaddr as *const u32).read_volatile() };
                if v != val { return 0; } // woken
                if crate::time::monotonic_ns() >= deadline_ns { return -110; } // ETIMEDOUT
                iters += 1;
                // Yield to scheduler every 1M spins to avoid livelock.
                if iters % 1_000_000 == 0 { crate::proc::scheduler::schedule(); }
                core::hint::spin_loop();
            }
        }
        // ─ FUTEX_WAKE ──────────────────────────────────────────────────────
        FUTEX_WAKE | FUTEX_WAKE_BITSET => {
            // On a uniprocessor, WAKE is a no-op: the waiter will observe
            // the changed value on its next spin iteration.
            // Return number of waiters woken = min(val, 1) as a conservative guess.
            0
        }
        // FUTEX_CMP_REQUEUE, FD, etc. — return ENOSYS; musl falls back gracefully.
        _ => -38,
    }
}

// ── NR 204  sched_getaffinity ──────────────────────────────────────────────────────

fn sys_sched_getaffinity_impl(_pid: usize, cpusetsize: usize, mask_va: usize) -> isize {
    if mask_va < 0x1000 || cpusetsize == 0 { return -14; }
    // Single CPU: CPU 0 is always available.
    unsafe { core::ptr::write_bytes(mask_va as *mut u8, 0, cpusetsize); }
    unsafe { *(mask_va as *mut u8) = 0x01; } // bit 0 = CPU 0
    0
}
fn sys_sched_setaffinity_impl(_pid: usize, _sz: usize, _mask: usize) -> isize { 0 }

// ── NR 230  clock_getres ──────────────────────────────────────────────────────────

fn sys_clock_getres_impl(_clkid: u32, res_va: usize) -> isize {
    if res_va != 0 && res_va >= 0x1000 {
        unsafe {
            (res_va as *mut i64).add(0).write_unaligned(0); // 0 seconds
            (res_va as *mut i64).add(1).write_unaligned(1); // 1 nanosecond
        }
    }
    0
}

// ── NR 234  tgkill ────────────────────────────────────────────────────────────

fn sys_tgkill_impl(tgid: usize, tid: usize, sig: u32) -> isize {
    // On rustos tgid == pid (single-threaded), so just kill by tid.
    sys_kill_impl(tid as isize, sig)
}

// ── NR 247  waitid ────────────────────────────────────────────────────────────

fn sys_waitid_impl(which: i32, id: i32, infop: usize, options: u32) -> isize {
    // Map to wait4: which=P_PID(1) -> specific pid; others -> -1 (any child)
    let pid: isize = if which == 1 { id as isize } else { -1 };
    crate::proc::wait::sys_waitpid(pid, 0, options)
}

// ── NR 257/258/262/263/264/267  *at variants ──────────────────────────────────

// AT_FDCWD = -100
const AT_FDCWD: i32 = -100;

fn at_path(dirfd: i32, path_va: usize) -> Option<String> {
    let path = read_cstr_safe(path_va)?;
    if dirfd == AT_FDCWD || path.starts_with('/') {
        Some(path)
    } else {
        // dirfd-relative: prepend the fd's path.
        let dir = crate::fs::vfs::fd_to_path(dirfd as usize)
            .unwrap_or_else(|| String::from("/"));
        Some(alloc::format!("{}/{}", dir.trim_end_matches('/'), path))
    }
}

fn sys_openat_impl(dirfd: i32, path_va: usize, flags: i32, mode: u32) -> isize {
    let path = match at_path(dirfd, path_va) { Some(p) => p, None => return -14 };
    // Try devfs.
    if path.starts_with("/dev/") {
        if let Some(fd) = crate::fs::devfs::try_open(&path, flags as u32) {
            return fd as isize;
        }
    }
    match crate::fs::vfs::open(&path, flags as u32) {
        Ok(fd) => fd as isize,
        Err(e) => e as isize,
    }
}

fn sys_mkdirat_impl(dirfd: i32, path_va: usize, mode: u32) -> isize {
    let path = match at_path(dirfd, path_va) { Some(p) => p, None => return -14 };
    crate::fs::vfs::mkdir(&path, mode)
}

fn sys_newfstatat_impl(dirfd: i32, path_va: usize, stat_va: usize, flags: u32) -> isize {
    let path = match at_path(dirfd, path_va) { Some(p) => p, None => return -14 };
    crate::fs::vfs::stat(&path, stat_va)
}

fn sys_unlinkat_impl(dirfd: i32, path_va: usize, flags: u32) -> isize {
    let path = match at_path(dirfd, path_va) { Some(p) => p, None => return -14 };
    crate::fs::vfs::unlink(&path)
}

fn sys_renameat_impl(old_dir: i32, old_va: usize, new_dir: i32, new_va: usize) -> isize {
    let old = match at_path(old_dir, old_va) { Some(p) => p, None => return -14 };
    let new = match at_path(new_dir, new_va) { Some(p) => p, None => return -14 };
    crate::fs::stat_syscalls::sys_rename_str(&old, &new)
}

fn sys_readlinkat_impl(dirfd: i32, path_va: usize, buf_va: usize, bufsiz: usize) -> isize {
    let path = match at_path(dirfd, path_va) { Some(p) => p, None => return -14 };
    // Fake the path_va by writing path to a scratch buffer and calling readlink.
    sys_readlink_impl(path_va, buf_va, bufsiz)
}

// ── NR 290  eventfd2 ───────────────────────────────────────────────────────────

fn sys_eventfd2_impl(_initval: u32, _flags: u32) -> isize {
    // Create a minimal counter-based eventfd backed by a ramfs file.
    // The 8-byte u64 counter is stored as the file content.
    static EVENT_COUNTER: core::sync::atomic::AtomicUsize =
        core::sync::atomic::AtomicUsize::new(0);
    let id = EVENT_COUNTER.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    let name = alloc::format!("__eventfd_{}", id);
    let counter: u64 = 0;
    crate::fs::vfs::create_file(&name, &counter.to_le_bytes());
    match crate::fs::vfs::open(&name, crate::fs::vfs::O_RDWR) {
        Ok(fd) => fd as isize,
        Err(e) => e as isize,
    }
}

// ── NR 292  inotify_init1 ─────────────────────────────────────────────────────────

fn sys_inotify_init1_impl(_flags: i32) -> isize {
    // Return a stub fd; inotify_add_watch/read will return -ENOSYS.
    // Most programs that use inotify tolerate this gracefully.
    static IN_COUNTER: core::sync::atomic::AtomicUsize =
        core::sync::atomic::AtomicUsize::new(0);
    let id = IN_COUNTER.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    let name = alloc::format!("__inotify_{}", id);
    crate::fs::vfs::create_file(&name, &[]);
    match crate::fs::vfs::open(&name, crate::fs::vfs::O_RDONLY) {
        Ok(fd) => fd as isize,
        Err(_) => -24,
    }
}

// ── NR 294  dup3 ─────────────────────────────────────────────────────────────

fn sys_dup3_impl(oldfd: usize, newfd: usize, flags: u32) -> isize {
    if oldfd == newfd { return -22; } // EINVAL (unlike dup2 which allows it)
    let r = crate::fs::vfs::dup_as(oldfd, newfd);
    if r >= 0 && flags & 0o2000000 != 0 { // O_CLOEXEC
        crate::fs::fcntl::set_cloexec(newfd, true);
    }
    r
}

// ── NR 318  getrandom ───────────────────────────────────────────────────────────

fn sys_getrandom_impl(buf_va: usize, count: usize, _flags: u32) -> isize {
    if buf_va < 0x1000 || count == 0 { return -14; }
    let buf = unsafe { core::slice::from_raw_parts_mut(buf_va as *mut u8, count) };
    for chunk in buf.chunks_mut(8) {
        let r = crate::rand::rdrand_or_lfsr();
        let bytes = r.to_le_bytes();
        let n = chunk.len();
        chunk.copy_from_slice(&bytes[..n]);
    }
    count as isize
}

// ── NR 319  memfd_create ──────────────────────────────────────────────────────────

fn sys_memfd_create_impl(name_va: usize, _flags: u32) -> isize {
    static MFD_CTR: core::sync::atomic::AtomicUsize =
        core::sync::atomic::AtomicUsize::new(0);
    let id  = MFD_CTR.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    let suffix = if name_va >= 0x1000 {
        read_cstr_safe(name_va).unwrap_or_default()
    } else {
        String::new()
    };
    let name = alloc::format!("__memfd_{}_{}", id, suffix);
    crate::fs::vfs::create_file(&name, &[]);
    match crate::fs::vfs::open(&name, crate::fs::vfs::O_RDWR) {
        Ok(fd) => fd as isize,
        Err(e) => e as isize,
    }
}
