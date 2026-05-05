//! Implementations for syscalls that are either trivial, return constant
//! data, or are safely no-ops for a single-user root kernel.
//!
//! Included from syscall/mod.rs via `include!("stubs.rs")`.

extern crate alloc;
use alloc::string::String;
use crate::proc::exec::read_cstr_safe;
use crate::uaccess::{copy_from_user, copy_to_user};
use crate::arch::{Arch, api::{Paging, PageFlags}};

// ── NR 18  pwrite64 ──────────────────────────────────────────────────────────────

fn sys_pwrite64_impl(fd: usize, buf_va: usize, count: usize, offset: i64) -> isize {
    if count == 0 { return 0; }
    let mut buf = alloc::vec![0u8; count];
    if copy_from_user(&mut buf, buf_va).is_err() { return -14; }
    let old = crate::fs::vfs::seek(fd, 0, crate::fs::vfs::SEEK_CUR) as i64;
    crate::fs::vfs::seek(fd, offset, crate::fs::vfs::SEEK_SET);
    let n = crate::fs::vfs::write(fd, &buf);
    crate::fs::vfs::seek(fd, old, crate::fs::vfs::SEEK_SET);
    n
}

// ── NR 19  readv ──────────────────────────────────────────────────────────────────

fn sys_readv_impl(fd: usize, iov_va: usize, iovcnt: usize) -> isize {
    if iovcnt == 0 { return 0; }
    if iovcnt > 1024 { return -22; } // EINVAL
    // Validate the entire iovec array before touching any element.
    if !crate::uaccess::validate_user_ptr(iov_va, iovcnt * 16) { return -14; }
    let mut total: isize = 0;
    for i in 0..iovcnt {
        // Copy one iovec {base: usize, len: usize} from user.
        let mut iov_buf = [0u8; 16];
        if copy_from_user(&mut iov_buf, iov_va + i * 16).is_err() { return -14; }
        let base = usize::from_le_bytes(iov_buf[0..8].try_into().unwrap());
        let len  = usize::from_le_bytes(iov_buf[8..16].try_into().unwrap());
        if len == 0 { continue; }
        let mut buf = alloc::vec![0u8; len];
        let n = crate::fs::vfs::read(fd, &mut buf);
        if n <= 0 { return if total > 0 { total } else { n }; }
        // Write bytes read back to user iov buffer.
        if copy_to_user(base, &buf[..n as usize]).is_err() { return -14; }
        total += n;
        if (n as usize) < len { break; }
    }
    total
}

// ── NR 24  sched_yield ──────────────────────────────────────────────────────────

fn sys_sched_yield_impl() -> isize {
    crate::proc::scheduler::schedule();
    0
}

// ── NR 25  mremap ──────────────────────────────────────────────────────────────

fn sys_mremap_impl(old_addr: usize, old_size: usize, new_size: usize,
                   _flags: usize, _new_addr: usize) -> isize {
    const PAGE: usize = 4096;
    if old_addr & (PAGE - 1) != 0 { return -22; }
    let old_pages = (old_size + PAGE - 1) / PAGE;
    let new_pages = (new_size + PAGE - 1) / PAGE;
    let pid = crate::proc::scheduler::current_pid();

    if new_pages <= old_pages {
        let unmap_start = old_addr + new_pages * PAGE;
        let unmap_len   = (old_pages - new_pages) * PAGE;
        if unmap_len > 0 { crate::mm::mmap::sys_munmap(unmap_start, unmap_len); }
        return old_addr as isize;
    }

    // Get current process CR3 via the Paging trait.
    let cr3 = crate::proc::scheduler::with_procs(|procs| {
        procs.iter().find(|p| p.pid == pid).map_or(0, |p| p.user_satp)
    });
    if cr3 == 0 { return -12; }

    let extend_start = old_addr + old_pages * PAGE;
    let extend_len   = (new_pages - old_pages) * PAGE;
    for va in (extend_start..extend_start + extend_len).step_by(PAGE) {
        match crate::mm::pmm::alloc_page() {
            Some(pa) => {
                unsafe { core::ptr::write_bytes(pa as *mut u8, 0, PAGE); }
                <Arch as Paging>::map_page(
                    cr3, va, pa,
                    PageFlags::PRESENT | PageFlags::WRITE
                    | PageFlags::USER  | PageFlags::NX,
                );
            }
            None => return -12,
        }
    }
    crate::mm::mmap::remove_vma(pid, old_addr, old_size);
    crate::mm::mmap::insert_vma(pid, crate::mm::mmap::Vma {
        start: old_addr,
        end:   old_addr + new_pages * PAGE,
        prot:  crate::mm::mmap::PROT_READ | crate::mm::mmap::PROT_WRITE,
        flags: 0x22,
        kind:  crate::mm::mmap::VmaKind::Anonymous,
        file_offset: 0,
    });
    old_addr as isize
}

// ── NR 28  madvise ─────────────────────────────────────────────────────────────

fn sys_madvise_impl(addr: usize, length: usize, advice: i32) -> isize {
    const MADV_DONTNEED: i32 = 4;
    const PAGE: usize = 4096;
    if advice == MADV_DONTNEED {
        let pid = crate::proc::scheduler::current_pid();
        let cr3 = crate::proc::scheduler::with_procs(|procs| {
            procs.iter().find(|p| p.pid == pid).map_or(0, |p| p.user_satp)
        });
        if cr3 == 0 { return 0; }
        let aligned = addr & !(PAGE - 1);
        let end     = (addr + length + PAGE - 1) & !(PAGE - 1);
        for va in (aligned..end).step_by(PAGE) {
            if let Some(pa) = <Arch as Paging>::virt_to_phys(cr3, va) {
                unsafe { core::ptr::write_bytes(pa as *mut u8, 0, PAGE); }
            }
        }
    }
    0
}

// ── NR 40  sendfile ─────────────────────────────────────────────────────────────

fn sys_sendfile_impl(out_fd: usize, in_fd: usize, offset_va: usize, count: usize) -> isize {
    if count == 0 { return 0; }
    if offset_va != 0 {
        let mut off_buf = [0u8; 8];
        if copy_from_user(&mut off_buf, offset_va).is_err() { return -14; }
        let offset = i64::from_le_bytes(off_buf);
        crate::fs::vfs::seek(in_fd, offset, crate::fs::vfs::SEEK_SET);
    }
    let mut buf = alloc::vec![0u8; count.min(65536)];
    let n = crate::fs::vfs::read(in_fd, &mut buf);
    if n <= 0 { return n; }
    if offset_va != 0 {
        let new_off = crate::fs::vfs::seek(in_fd, 0, crate::fs::vfs::SEEK_CUR) as i64;
        if copy_to_user(offset_va, &new_off.to_le_bytes()).is_err() { return -14; }
    }
    crate::fs::vfs::write(out_fd, &buf[..n as usize])
}

// ── NR 56  clone ────────────────────────────────────────────────────────────────

const CLONE_THREAD: usize = 0x0001_0000;

fn sys_clone_impl(flags: usize, child_sp: usize, ptid: usize,
                  ctid: usize, tls: usize) -> isize {
    if flags & CLONE_THREAD != 0 {
        crate::proc::clone::sys_clone_legacy(flags, child_sp, ptid, ctid, tls)
    } else {
        crate::proc::fork_syscall::sys_fork()
    }
}

// ── NR 58  vfork ────────────────────────────────────────────────────────────────

fn sys_vfork_impl() -> isize {
    crate::proc::fork_syscall::sys_fork()
}

// ── NR 62  kill ───────────────────────────────────────────────────────────────

fn sys_kill_impl(pid: isize, sig: u32) -> isize {
    if sig == 0 { return 0; }
    if sig > 64  { return -22; }
    let target = if pid == 0 {
        crate::proc::scheduler::current_pid()
    } else if pid > 0 {
        pid as usize
    } else {
        (-pid) as usize
    };
    crate::proc::signal::send_signal(target, sig);
    0
}

// ── NR 63  uname ──────────────────────────────────────────────────────────────

fn sys_uname_impl(buf_va: usize) -> isize {
    // struct utsname: 6 fields × 65 bytes = 390 bytes.
    let mut kbuf = [0u8; 390];
    fn fill(kbuf: &mut [u8; 390], field: usize, s: &[u8]) {
        let off = field * 65;
        let n   = s.len().min(64);
        kbuf[off..off + n].copy_from_slice(&s[..n]);
    }
    fill(&mut kbuf, 0, b"Linux");
    fill(&mut kbuf, 1, b"rustos");
    fill(&mut kbuf, 2, b"6.1.0-rustos");
    fill(&mut kbuf, 3, b"#1 SMP");
    fill(&mut kbuf, 4, b"x86_64");
    fill(&mut kbuf, 5, b"rustos");
    if copy_to_user(buf_va, &kbuf).is_err() { return -14; }
    0
}

// ── NR 74/75  fsync / fdatasync ──────────────────────────────────────────────

fn sys_fsync_impl(_fd: usize) -> isize { 0 }

// ── NR 76/77  truncate / ftruncate ────────────────────────────────────────────

fn sys_truncate_impl(path_va: usize, length: i64) -> isize {
    let path  = match read_cstr_safe(path_va) { Some(s) => s, None => return -14 };
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

// ── NR 81  fchdir ─────────────────────────────────────────────────────────────

fn sys_fchdir_impl(fd: usize) -> isize {
    if let Some(path) = crate::fs::vfs::fd_to_path(fd) {
        crate::fs::stat_syscalls::set_cwd(&path); 0
    } else { -9 }
}

// ── NR 84  rmdir ──────────────────────────────────────────────────────────────

fn sys_rmdir_impl(path_va: usize) -> isize {
    let path = match read_cstr_safe(path_va) { Some(s) => s, None => return -14 };
    crate::fs::vfs::unlink(&path)
}

// ── NR 85  creat ─────────────────────────────────────────────────────────────

fn sys_creat_impl(path_va: usize, _mode: u32) -> isize {
    let flags = crate::fs::vfs::O_CREAT | crate::fs::vfs::O_WRONLY | crate::fs::vfs::O_TRUNC;
    let path  = match read_cstr_safe(path_va) { Some(s) => s, None => return -14 };
    match crate::fs::vfs::open(&path, flags) {
        Ok(fd) => fd as isize,
        Err(e) => e as isize,
    }
}

// ── NR 86/88/89  link / symlink / readlink ───────────────────────────────────

fn sys_link_impl(old_va: usize, new_va: usize) -> isize {
    let old = match read_cstr_safe(old_va) { Some(s) => s, None => return -14 };
    let new = match read_cstr_safe(new_va) { Some(s) => s, None => return -14 };
    if let Some(data) = crate::fs::vfs::lookup(&old) {
        crate::fs::vfs::create_file(&new, &data); 0
    } else { -2 }
}

fn sys_symlink_impl(target_va: usize, link_va: usize) -> isize {
    let target = match read_cstr_safe(target_va) { Some(s) => s, None => return -14 };
    let link   = match read_cstr_safe(link_va)   { Some(s) => s, None => return -14 };
    let mut data = alloc::vec![0u8; 0];
    data.extend_from_slice(b"\x00symlink\x00");
    data.extend_from_slice(target.as_bytes());
    crate::fs::vfs::create_file(&link, &data);
    0
}

fn sys_readlink_impl(path_va: usize, buf_va: usize, bufsiz: usize) -> isize {
    if bufsiz == 0 { return -14; }
    let path = match read_cstr_safe(path_va) { Some(s) => s, None => return -14 };
    let data: Option<alloc::vec::Vec<u8>> = if path == "/proc/self/exe" {
        Some(b"/init".to_vec())
    } else {
        crate::fs::vfs::lookup(&path).and_then(|d| {
            if d.starts_with(b"\x00symlink\x00") { Some(d[9..].to_vec()) } else { None }
        })
    };
    match data {
        Some(target) => {
            let n = target.len().min(bufsiz);
            if copy_to_user(buf_va, &target[..n]).is_err() { return -14; }
            n as isize
        }
        None => -22,
    }
}

// ── NR 95  umask ─────────────────────────────────────────────────────────────

use core::sync::atomic::{AtomicU32, Ordering};
static UMASK: AtomicU32 = AtomicU32::new(0o022);

fn sys_umask_impl(mask: u32) -> isize {
    UMASK.swap(mask & 0o777, Ordering::Relaxed) as isize
}

// ── NR 96  gettimeofday ─────────────────────────────────────────────────────────

fn sys_gettimeofday_impl(tv_va: usize, _tz_va: usize) -> isize {
    if tv_va == 0 { return 0; }
    let ns   = crate::time::monotonic_ns();
    let sec  = (ns / 1_000_000_000) as i64;
    let usec = ((ns % 1_000_000_000) / 1_000) as i64;
    let mut buf = [0u8; 16];
    buf[0..8].copy_from_slice(&sec.to_le_bytes());
    buf[8..16].copy_from_slice(&usec.to_le_bytes());
    if copy_to_user(tv_va, &buf).is_err() { return -14; }
    0
}

// ── NR 97/160/302  getrlimit / setrlimit / prlimit64 ───────────────────────────

const RLIMIT_STACK:  u32 = 3;
const RLIMIT_CORE:   u32 = 4;
const RLIMIT_NOFILE: u32 = 7;
const RLIM_INFINITY: u64 = u64::MAX;

fn default_rlimit(resource: u32) -> (u64, u64) {
    match resource {
        RLIMIT_STACK  => (8 * 1024 * 1024, RLIM_INFINITY),
        RLIMIT_NOFILE => (1024, 4096),
        RLIMIT_CORE   => (0, 0),
        _             => (RLIM_INFINITY, RLIM_INFINITY),
    }
}

fn sys_getrlimit_impl(resource: u32, rlim_va: usize) -> isize {
    let (soft, hard) = default_rlimit(resource);
    let mut buf = [0u8; 16];
    buf[0..8].copy_from_slice(&soft.to_le_bytes());
    buf[8..16].copy_from_slice(&hard.to_le_bytes());
    if copy_to_user(rlim_va, &buf).is_err() { return -14; }
    0
}

fn sys_setrlimit_impl(_resource: u32, _rlim_va: usize) -> isize { 0 }

fn sys_prlimit64_impl(_pid: usize, resource: u32, _new_va: usize, old_va: usize) -> isize {
    if old_va != 0 {
        let (soft, hard) = default_rlimit(resource);
        let mut buf = [0u8; 16];
        buf[0..8].copy_from_slice(&soft.to_le_bytes());
        buf[8..16].copy_from_slice(&hard.to_le_bytes());
        if copy_to_user(old_va, &buf).is_err() { return -14; }
    }
    0
}

// ── NR 98  getrusage ────────────────────────────────────────────────────────────

fn sys_getrusage_impl(_who: i32, buf_va: usize) -> isize {
    if copy_to_user(buf_va, &[0u8; 144]).is_err() { return -14; }
    0
}

// ── NR 99  sysinfo ─────────────────────────────────────────────────────────────

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
    let total    = crate::mm::pmm::total_pages() as u64 * 4096;
    let free     = crate::mm::pmm::free_pages()  as u64 * 4096;
    let uptime_s = (crate::time::monotonic_ns() / 1_000_000_000) as i64;
    let info = SysInfo {
        uptime: uptime_s, loads: [0; 3],
        totalram: total, freeram: free,
        sharedram: 0, bufferram: 0, totalswap: 0, freeswap: 0,
        procs: 1, _pad: [0; 6], totalhigh: 0, freehigh: 0,
        mem_unit: 1, _f: [0; 20],
    };
    let bytes = unsafe {
        core::slice::from_raw_parts(
            &info as *const SysInfo as *const u8,
            core::mem::size_of::<SysInfo>(),
        )
    };
    if copy_to_user(info_va, bytes).is_err() { return -14; }
    0
}

// ── NR 131  sigaltstack ─────────────────────────────────────────────────────────

use spin::Mutex as SpinMutex;
extern crate alloc;
use alloc::collections::BTreeMap;

// ALTSTACK is keyed by pid (usize). Entries must be removed on process exit
// by calling altstack_clear_pid(pid) from do_exit.
static ALTSTACK: SpinMutex<BTreeMap<usize, [u8; 24]>> = SpinMutex::new(BTreeMap::new());

/// Called from do_exit to prevent per-pid leak.
pub fn altstack_clear_pid(pid: usize) { ALTSTACK.lock().remove(&pid); }

fn sys_sigaltstack_impl(ss_va: usize, old_ss_va: usize) -> isize {
    let pid = crate::proc::scheduler::current_pid();
    if old_ss_va != 0 {
        let saved = ALTSTACK.lock().get(&pid).copied();
        let mut buf = saved.unwrap_or_else(|| {
            let mut b = [0u8; 24];
            // SS_DISABLE flag at offset 8
            b[8..12].copy_from_slice(&2i32.to_le_bytes());
            b
        });
        if copy_to_user(old_ss_va, &buf).is_err() { return -14; }
        let _ = buf; // suppress unused warning
    }
    if ss_va != 0 {
        let mut buf = [0u8; 24];
        if copy_from_user(&mut buf, ss_va).is_err() { return -14; }
        ALTSTACK.lock().insert(pid, buf);
    }
    0
}

// ── NR 137/138  statfs / fstatfs ──────────────────────────────────────────────

#[repr(C)]
struct StatFs {
    f_type:    i64, f_bsize:   i64,
    f_blocks:  u64, f_bfree:   u64, f_bavail:  u64,
    f_files:   u64, f_ffree:   u64,
    f_fsid:    [i32; 2],
    f_namelen: i64, f_frsize:  i64, f_flags:   i64,
    f_spare:   [i64; 4],
}

fn fill_statfs(buf_va: usize) -> isize {
    let total = crate::mm::pmm::total_pages() as u64;
    let free  = crate::mm::pmm::free_pages()  as u64;
    let sf = StatFs {
        f_type: 0xEF53, f_bsize: 4096,
        f_blocks: total, f_bfree: free, f_bavail: free,
        f_files: 65536, f_ffree: 65536,
        f_fsid: [0; 2], f_namelen: 255, f_frsize: 4096, f_flags: 0,
        f_spare: [0; 4],
    };
    let bytes = unsafe {
        core::slice::from_raw_parts(
            &sf as *const StatFs as *const u8,
            core::mem::size_of::<StatFs>(),
        )
    };
    if copy_to_user(buf_va, bytes).is_err() { return -14; }
    0
}

fn sys_statfs_impl(_path_va: usize, buf_va: usize) -> isize { fill_statfs(buf_va) }
fn sys_fstatfs_impl(_fd: usize,    buf_va: usize) -> isize { fill_statfs(buf_va) }

// ── NR 162  sync ─────────────────────────────────────────────────────────────

fn sys_sync_impl() -> isize { 0 }

// ── NR 185  prctl ────────────────────────────────────────────────────────────

const PR_SET_NAME:        i32 = 15;
const PR_GET_NAME:        i32 = 16;
const PR_SET_DUMPABLE:    i32 = 4;
const PR_GET_DUMPABLE:    i32 = 3;
const PR_SET_SECCOMP:     i32 = 22;
const PR_SET_PDEATHSIG:   i32 = 1;
const PR_SET_NO_NEW_PRIVS: i32 = 38;

// PROC_NAME keyed by pid. Must be cleaned up on exit via proc_name_clear(pid).
static PROC_NAME: SpinMutex<BTreeMap<usize, [u8; 16]>> = SpinMutex::new(BTreeMap::new());

/// Called from do_exit to prevent per-pid leak.
pub fn proc_name_clear(pid: usize) { PROC_NAME.lock().remove(&pid); }

fn sys_prctl_impl(op: i32, a2: usize, _a3: usize, _a4: usize, _a5: usize) -> isize {
    let pid = crate::proc::scheduler::current_pid();
    match op {
        PR_SET_NAME => {
            let mut name = [0u8; 16];
            // Copy at most 15 bytes (name is NUL-terminated, max 16 with NUL).
            if copy_from_user(&mut name[..15], a2).is_err() { return -14; }
            PROC_NAME.lock().insert(pid, name);
            0
        }
        PR_GET_NAME => {
            let name = PROC_NAME.lock().get(&pid).copied().unwrap_or([0u8; 16]);
            if copy_to_user(a2, &name).is_err() { return -14; }
            0
        }
        PR_SET_DUMPABLE | PR_GET_DUMPABLE     => 1,
        PR_SET_SECCOMP                         => -22,
        PR_SET_PDEATHSIG | PR_SET_NO_NEW_PRIVS => 0,
        _                                      => 0,
    }
}

// ── NR 201  time ─────────────────────────────────────────────────────────────

fn sys_time_impl(t_va: usize) -> isize {
    let secs = (crate::time::monotonic_ns() / 1_000_000_000) as i64;
    if t_va != 0 {
        if copy_to_user(t_va, &secs.to_le_bytes()).is_err() { return -14; }
    }
    secs as isize
}

// ── NR 202  futex ─────────────────────────────────────────────────────────────

const FUTEX_WAIT:         u32 = 0;
const FUTEX_WAKE:         u32 = 1;
const FUTEX_REQUEUE:      u32 = 3;
const FUTEX_CMP_REQUEUE:  u32 = 4;
const FUTEX_WAKE_OP:      u32 = 5;
const FUTEX_WAIT_BITSET:  u32 = 9;
const FUTEX_WAKE_BITSET:  u32 = 10;
const FUTEX_PRIVATE_FLAG: u32 = 128;
const FUTEX_CMD_MASK:     u32 = !(FUTEX_PRIVATE_FLAG | 256);
const BITSET_ANY:         u32 = 0xFFFF_FFFF;

fn sys_futex_impl(
    uaddr: usize, op: u32, val: u32,
    timeout_va: usize, uaddr2: usize, val3: u32,
) -> isize {
    if uaddr < 0x1000 { return -14; }
    let op_base = op & FUTEX_CMD_MASK;
    match op_base {
        FUTEX_WAIT | FUTEX_WAIT_BITSET => {
            let bitset = if op_base == FUTEX_WAIT_BITSET { val3 } else { BITSET_ANY };
            if bitset == 0 { return -22; }
            let deadline_ns = if timeout_va == 0 {
                u64::MAX
            } else if !crate::uaccess::validate_user_ptr(timeout_va, 16) {
                return -14;
            } else {
                let mut buf = [0u8; 16];
                if copy_from_user(&mut buf, timeout_va).is_err() { return -14; }
                let tv_sec  = i64::from_le_bytes(buf[0..8].try_into().unwrap());
                let tv_nsec = i64::from_le_bytes(buf[8..16].try_into().unwrap());
                if tv_sec < 0 || tv_nsec < 0 || tv_nsec >= 1_000_000_000 { return -22; }
                crate::time::monotonic_ns()
                    .saturating_add((tv_sec as u64) * 1_000_000_000 + tv_nsec as u64)
            };
            crate::sync::futex::futex_wait(uaddr, val, bitset, deadline_ns)
        }
        FUTEX_WAKE | FUTEX_WAKE_BITSET => {
            let bitset = if op_base == FUTEX_WAKE_BITSET { val3 } else { BITSET_ANY };
            if bitset == 0 { return -22; }
            crate::sync::futex::futex_wake(uaddr, val, bitset)
        }
        FUTEX_REQUEUE     => crate::sync::futex::futex_requeue(uaddr, val, uaddr2, timeout_va as u32, None),
        FUTEX_CMP_REQUEUE => crate::sync::futex::futex_requeue(uaddr, val, uaddr2, timeout_va as u32, Some(val3)),
        FUTEX_WAKE_OP     => crate::sync::futex::futex_wake_op(uaddr, val, uaddr2, timeout_va as u32, val3),
        _ => -38,
    }
}

// ── NR 203/204  sched_setaffinity / sched_getaffinity ────────────────────────

fn sys_sched_getaffinity_impl(_pid: usize, cpusetsize: usize, mask_va: usize) -> isize {
    if cpusetsize == 0 { return -14; }
    let sz  = cpusetsize.min(128); // cap at 1024-bit cpu mask
    let mut buf = alloc::vec![0u8; sz];
    if sz > 0 { buf[0] = 0x01; } // CPU 0 only
    if copy_to_user(mask_va, &buf).is_err() { return -14; }
    0
}
fn sys_sched_setaffinity_impl(_pid: usize, _sz: usize, _mask: usize) -> isize { 0 }

// ── NR 230  clock_getres ────────────────────────────────────────────────────────

fn sys_clock_getres_impl(_clkid: u32, res_va: usize) -> isize {
    if res_va != 0 {
        // timespec { tv_sec: 0, tv_nsec: 1 }
        let mut buf = [0u8; 16];
        buf[8..16].copy_from_slice(&1i64.to_le_bytes());
        if copy_to_user(res_va, &buf).is_err() { return -14; }
    }
    0
}

// ── NR 234  tgkill ────────────────────────────────────────────────────────────

fn sys_tgkill_impl(_tgid: usize, tid: usize, sig: u32) -> isize {
    sys_kill_impl(tid as isize, sig)
}

// ── NR 247  waitid ────────────────────────────────────────────────────────────

fn sys_waitid_impl(which: i32, id: i32, _infop: usize, options: u32) -> isize {
    let pid: isize = if which == 1 { id as isize } else { -1 };
    crate::proc::wait::sys_waitpid(pid, 0, options)
}

// ── NR 257-267  *at variants ─────────────────────────────────────────────────────

const AT_FDCWD: i32 = -100;

fn at_path(dirfd: i32, path_va: usize) -> Option<String> {
    let path = read_cstr_safe(path_va)?;
    if dirfd == AT_FDCWD || path.starts_with('/') {
        Some(path)
    } else {
        let dir = crate::fs::vfs::fd_to_path(dirfd as usize)
            .unwrap_or_else(|| String::from("/"));
        Some(alloc::format!("{}/{}", dir.trim_end_matches('/'), path))
    }
}

fn sys_openat_impl(dirfd: i32, path_va: usize, flags: i32, mode: u32) -> isize {
    let path = match at_path(dirfd, path_va) { Some(p) => p, None => return -14 };
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

fn sys_newfstatat_impl(dirfd: i32, path_va: usize, stat_va: usize, _flags: u32) -> isize {
    let path = match at_path(dirfd, path_va) { Some(p) => p, None => return -14 };
    crate::fs::vfs::stat(&path, stat_va)
}

fn sys_unlinkat_impl(dirfd: i32, path_va: usize, _flags: u32) -> isize {
    let path = match at_path(dirfd, path_va) { Some(p) => p, None => return -14 };
    crate::fs::vfs::unlink(&path)
}

fn sys_renameat_impl(old_dir: i32, old_va: usize, new_dir: i32, new_va: usize) -> isize {
    let old = match at_path(old_dir, old_va) { Some(p) => p, None => return -14 };
    let new = match at_path(new_dir, new_va) { Some(p) => p, None => return -14 };
    crate::fs::stat_syscalls::sys_rename_str(&old, &new)
}

fn sys_readlinkat_impl(dirfd: i32, path_va: usize, buf_va: usize, bufsiz: usize) -> isize {
    let _path = match at_path(dirfd, path_va) { Some(p) => p, None => return -14 };
    sys_readlink_impl(path_va, buf_va, bufsiz)
}

// ── NR 290  eventfd2 ────────────────────────────────────────────────────────────

fn sys_eventfd2_impl(_initval: u32, _flags: u32) -> isize {
    static EVENT_COUNTER: core::sync::atomic::AtomicUsize =
        core::sync::atomic::AtomicUsize::new(0);
    let id   = EVENT_COUNTER.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    let name = alloc::format!("__eventfd_{}", id);
    let counter: u64 = 0;
    crate::fs::vfs::create_file(&name, &counter.to_le_bytes());
    match crate::fs::vfs::open(&name, crate::fs::vfs::O_RDWR) {
        Ok(fd) => fd as isize,
        Err(e) => e as isize,
    }
}

// ── NR 292  inotify_init1 ────────────────────────────────────────────────────────

fn sys_inotify_init1_impl(_flags: i32) -> isize {
    static IN_COUNTER: core::sync::atomic::AtomicUsize =
        core::sync::atomic::AtomicUsize::new(0);
    let id   = IN_COUNTER.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    let name = alloc::format!("__inotify_{}", id);
    crate::fs::vfs::create_file(&name, &[]);
    match crate::fs::vfs::open(&name, crate::fs::vfs::O_RDONLY) {
        Ok(fd) => fd as isize,
        Err(_) => -24,
    }
}

// ── NR 294  dup3 ─────────────────────────────────────────────────────────────

fn sys_dup3_impl(oldfd: usize, newfd: usize, flags: u32) -> isize {
    if oldfd == newfd { return -22; }
    let r = crate::fs::vfs::dup_as(oldfd, newfd);
    if r >= 0 && flags & 0o2000000 != 0 {
        crate::fs::fcntl::set_cloexec(newfd, true);
    }
    r
}

// ── NR 318  getrandom ──────────────────────────────────────────────────────────

const GETRANDOM_MAX: usize = 4096; // cap per-call; caller loops if needed

fn sys_getrandom_impl(buf_va: usize, count: usize, _flags: u32) -> isize {
    if count == 0 { return 0; }
    let n = count.min(GETRANDOM_MAX);
    let mut buf = alloc::vec![0u8; n];
    for chunk in buf.chunks_mut(8) {
        let r     = crate::rand::rdrand_or_lfsr();
        let bytes = r.to_le_bytes();
        chunk.copy_from_slice(&bytes[..chunk.len()]);
    }
    if copy_to_user(buf_va, &buf).is_err() { return -14; }
    n as isize
}

// ── NR 319  memfd_create ─────────────────────────────────────────────────────────

fn sys_memfd_create_impl(name_va: usize, _flags: u32) -> isize {
    static MFD_CTR: core::sync::atomic::AtomicUsize =
        core::sync::atomic::AtomicUsize::new(0);
    let id     = MFD_CTR.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    let suffix = if name_va != 0 {
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
