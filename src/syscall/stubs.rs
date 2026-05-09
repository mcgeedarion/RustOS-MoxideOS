// Implementations for syscalls that are either trivial, return constant
// data, or are safely no-ops for a single-user root kernel.
//
// Included from syscall/mod.rs via `include!("stubs.rs")`.

use alloc::string::String;
use crate::proc::exec::read_cstr_safe;
use crate::uaccess::{copy_from_user, copy_to_user};
use crate::arch::{Arch, api::{Paging, PageFlags}};

// ── NR 18  pwrite64 ───────────────────────────────────────────────────────────────

const PWRITE_MAX: usize = 4 * 1024 * 1024;

fn sys_pwrite64_impl(fd: usize, buf_va: usize, count: usize, offset: i64) -> isize {
    if count == 0 { return 0; }
    let count = count.min(PWRITE_MAX);
    let mut buf = alloc::vec![0u8; count];
    if copy_from_user(&mut buf, buf_va).is_err() { return -14; }
    let old = crate::fs::vfs::seek(fd, 0, crate::fs::vfs::SEEK_CUR) as i64;
    crate::fs::vfs::seek(fd, offset, crate::fs::vfs::SEEK_SET);
    let n = crate::fs::vfs::write(fd, &buf);
    crate::fs::vfs::seek(fd, old, crate::fs::vfs::SEEK_SET);
    n
}

// ── NR 19  readv ───────────────────────────────────────────────────────────────

const IOV_STACK_BUF: usize = 4096;

fn sys_readv_impl(fd: usize, iov_va: usize, iovcnt: usize) -> isize {
    if iovcnt == 0 { return 0; }
    if iovcnt > 1024 { return -22; }
    if !crate::uaccess::validate_user_ptr(iov_va, iovcnt * 16) { return -14; }

    const IOV_MAX_LEN: usize = 64 * 1024;

    let mut max_len: usize = 0;
    for i in 0..iovcnt {
        let mut iov_buf = [0u8; 16];
        if copy_from_user(&mut iov_buf, iov_va + i * 16).is_err() { return -14; }
        let len = usize::from_le_bytes(iov_buf[8..16].try_into().unwrap());
        if len > max_len { max_len = len; }
    }
    let max_len = max_len.min(IOV_MAX_LEN);

    let mut stack_buf = [0u8; IOV_STACK_BUF];
    let mut heap_buf: alloc::vec::Vec<u8> = if max_len > IOV_STACK_BUF {
        alloc::vec![0u8; max_len]
    } else {
        alloc::vec::Vec::new()
    };

    let mut total: isize = 0;
    for i in 0..iovcnt {
        let mut iov_buf = [0u8; 16];
        if copy_from_user(&mut iov_buf, iov_va + i * 16).is_err() { return -14; }
        let base = usize::from_le_bytes(iov_buf[0..8].try_into().unwrap());
        let len  = usize::from_le_bytes(iov_buf[8..16].try_into().unwrap());
        if len == 0 { continue; }
        let capped = len.min(IOV_MAX_LEN);

        let n = if capped <= IOV_STACK_BUF {
            let buf = &mut stack_buf[..capped];
            let n = crate::fs::vfs::read(fd, buf);
            if n > 0 { if copy_to_user(base, &buf[..n as usize]).is_err() { return -14; } }
            n
        } else {
            let buf = &mut heap_buf[..capped];
            let n = crate::fs::vfs::read(fd, buf);
            if n > 0 { if copy_to_user(base, &buf[..n as usize]).is_err() { return -14; } }
            n
        };

        if n <= 0 { return if total > 0 { total } else { n }; }
        total += n;
        if (n as usize) < capped { break; }
    }
    total
}

// ── NR 24  sched_yield ────────────────────────────────────────────

fn sys_sched_yield_impl() -> isize {
    crate::proc::scheduler::schedule();
    0
}

// ── NR 25  mremap ────────────────────────────────────────────────────────

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

    let cr3 = crate::proc::scheduler::with_proc(pid, |p| p.user_satp).unwrap_or(0);
    if cr3 == 0 { return -12; }

    let extend_start = old_addr + old_pages * PAGE;
    let extend_len   = (new_pages - old_pages