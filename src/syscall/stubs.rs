// Implementations for syscalls that are either trivial, return constant
// data, or are safely no-ops for a single-user root kernel.
//
// Included from syscall/mod.rs via `include!("stubs.rs")`.

use alloc::string::String;
use crate::proc::exec::read_cstr_safe;
use crate::uaccess::{copy_from_user, copy_to_user};
use crate::arch::{Arch, api::{Paging, PageFlags}};

// ── NR 18  pwrite64 ──────────────────────────────────────────────────────────────

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

// ── NR 19  readv ────────────────────────────────────────────────────────────────

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
            if n > 0 {
                if copy_to_user(base, &buf[..n as usize]).is_err() { return -14; }
            }
            n
        } else {
            let buf = &mut heap_buf[..capped];
            let n = crate::fs::vfs::read(fd, buf);
            if n > 0 {
                if copy_to_user(base, &buf[..n as usize]).is_err() { return -14; }
            }
            n
        };

        if n <= 0 { return if total > 0 { total } else { n }; }
        total += n;
        if (n as usize) < capped { break; }
    }
    total
}

// ── NR 24  sched_yield ───────────────────────────────────────────────────────

fn sys_sched_yield_impl() -> isize {
    crate::proc::scheduler::schedule();
    0
}

// ── NR 25  mremap ──────────────────────────────────────────────────────────────
//
// Linux mremap semantics:
//
//   mremap(old_addr, old_size, new_size, flags[, new_addr])
//
//   flags:
//     MREMAP_MAYMOVE  (1) — allowed to relocate when in-place grow fails
//     MREMAP_FIXED    (2) — new_addr must be used (implies MAYMOVE)
//     MREMAP_DONTUNMAP(4) — keep old mapping after move (not implemented → EINVAL)
//
// Strategy
// ────────
// 1. Validate alignment and sizes.
// 2. Shrink:       unmap tail pages + shrink VMA.  Always succeeds.
// 3. Same size:    no-op.
// 4. Grow in-place:
//    a. Check that [old_end, old_end+delta) is free.
//    b. Allocate PMM pages there, map them, extend VMA.
//    c. On OOM fall through to move if MAYMOVE, else -ENOMEM.
// 5. Move (MREMAP_MAYMOVE or MREMAP_FIXED):
//    a. Pick destination (hint if FIXED, else bump next_va).
//    b. Re-point each present PTE: map at dst_va, unmap at src_va
//       (the physical frame is NOT freed — we just reuse it at the new VA).
//    c. Zero-fill the extension pages with fresh PMM frames.
//    d. Replace the VMA record.
//
// MREMAP_DONTUNMAP is not implemented (rare; added in Linux 5.7).

const MREMAP_MAYMOVE:   usize = 1;
const MREMAP_FIXED:     usize = 2;
const MREMAP_DONTUNMAP: usize = 4;

fn sys_mremap_impl(
    old_addr: usize,
    old_size: usize,
    new_size: usize,
    flags:    usize,
    new_addr: usize,
) -> isize {
    const PAGE: usize = 4096;

    if old_addr & (PAGE - 1) != 0 { return -22; }
    if new_size == 0               { return -22; }
    if flags & MREMAP_DONTUNMAP != 0 { return -22; }
    if flags & MREMAP_FIXED != 0 && flags & MREMAP_MAYMOVE == 0 { return -22; }

    let old_len = (old_size + PAGE - 1) & !(PAGE - 1);
    let new_len = (new_size + PAGE - 1) & !(PAGE - 1);
    let pid     = crate::proc::scheduler::current_pid();
    let cr3     = crate::proc::scheduler::with_proc(pid, |p| p.user_satp).unwrap_or(0);
    if cr3 == 0 { return -12; }

    // Source VMA must cover the entire old range.
    let vma = match crate::mm::mmap::find_vma(pid, old_addr) {
        Some(v) if v.start <= old_addr && v.end >= old_addr + old_len => v,
        _ => return -22,
    };
    let is_phys = matches!(vma.kind, crate::mm::mmap::VmaKind::PhysMap(_));

    // ── Shrink ──────────────────────────────────────────────────────────
    if new_len < old_len {
        let tail_start = old_addr + new_len;
        let tail_len   = old_len  - new_len;
        for va in (tail_start..tail_start + tail_len).step_by(PAGE) {
            if let Some(pa) = <Arch as Paging>::virt_to_phys(cr3, va) {
                <Arch as Paging>::unmap_page(va);
                <Arch as Paging>::flush_va(va);
                if !is_phys { crate::mm::pmm::free_page(pa); }
            }
        }
        crate::mm::mmap::remove_vma(pid, old_addr, old_len);
        crate::mm::mmap::insert_vma(pid, crate::mm::mmap::Vma {
            start: vma.start, end: old_addr + new_len,
            prot: vma.prot, flags: vma.flags,
            kind: vma.kind, file_offset: vma.file_offset,
        });
        return old_addr as isize;
    }

    // ── Same size ────────────────────────────────────────────────────────
    if new_len == old_len { return old_addr as isize; }

    // ── Grow ─────────────────────────────────────────────────────────────
    let delta   = new_len - old_len;
    let old_end = old_addr + old_len;

    // If MREMAP_FIXED, skip in-place attempt and go straight to move.
    if flags & MREMAP_FIXED == 0 {
        // Check that [old_end, old_end+delta) is completely free.
        let range_free = crate::proc::scheduler::with_proc(pid, |p| {
            !p.vmas.iter().any(|v| v.start < old_end + delta && v.end > old_end)
        }).unwrap_or(false);

        if range_free {
            let pte_flags = prot_to_flags_mremap(vma.prot);
            let mut mapped = 0usize;
            let mut oom = false;
            for va in (old_end..old_end + delta).step_by(PAGE) {
                match crate::mm::pmm::alloc_page() {
                    Some(pa) => {
                        unsafe { core::ptr::write_bytes(pa as *mut u8, 0, PAGE); }
                        <Arch as Paging>::map_page(cr3, va, pa, pte_flags);
                        <Arch as Paging>::flush_va(va);
                        mapped += 1;
                    }
                    None => { oom = true; break; }
                }
            }
            if !oom {
                crate::mm::mmap::remove_vma(pid, old_addr, old_len);
                crate::mm::mmap::insert_vma(pid, crate::mm::mmap::Vma {
                    start: vma.start, end: old_addr + new_len,
                    prot: vma.prot, flags: vma.flags,
                    kind: vma.kind, file_offset: vma.file_offset,
                });
                return old_addr as isize;
            }
            // OOM rollback of partial in-place extension.
            for j in 0..mapped {
                let rva = old_end + j * PAGE;
                if let Some(pa) = <Arch as Paging>::virt_to_phys(cr3, rva) {
                    <Arch as Paging>::unmap_page(rva);
                    <Arch as Paging>::flush_va(rva);
                    crate::mm::pmm::free_page(pa);
                }
            }
            // Fall through to move if MAYMOVE.
        }
    }

    // ── Move ─────────────────────────────────────────────────────────────
    if flags & MREMAP_MAYMOVE != 0 || flags & MREMAP_FIXED != 0 {
        return mremap_move(pid, cr3, old_addr, old_len, new_len, flags, new_addr, &vma);
    }
    -12 // ENOMEM: can't grow and MAYMOVE not permitted
}

/// Copy the mapping from `old_addr..old_addr+old_len` to a new location and
/// extend to `new_len` bytes (zero-filling the extension with PMM pages).
fn mremap_move(
    pid:      usize,
    cr3:      usize,
    old_addr: usize,
    old_len:  usize,
    new_len:  usize,
    flags:    usize,
    hint:     usize,
    vma:      &crate::mm::mmap::Vma,
) -> isize {
    const PAGE: usize = 4096;
    let is_phys = matches!(vma.kind, crate::mm::mmap::VmaKind::PhysMap(_));

    // Choose the destination VA.
    let dst = if flags & MREMAP_FIXED != 0 {
        if hint == 0 || hint & (PAGE - 1) != 0 { return -22; }
        // Remove any existing mapping at the destination.
        crate::mm::mmap::sys_munmap(hint, new_len);
        hint
    } else {
        crate::proc::scheduler::with_proc_mut(pid, |p, _pl| {
            let v = p.next_va;
            p.next_va = (v + new_len + PAGE * 2 + PAGE - 1) & !(PAGE - 1);
            v
        }).unwrap_or(0)
    };
    if dst == 0 { return -12; }
    if dst == old_addr { return old_addr as isize; }

    let pte_flags = prot_to_flags_mremap(vma.prot);

    // Re-point existing PTEs (physical frames are reused, not copied).
    for i in 0..(old_len / PAGE) {
        let src_va = old_addr + i * PAGE;
        let dst_va = dst      + i * PAGE;
        if let Some(pa) = <Arch as Paging>::virt_to_phys(cr3, src_va) {
            <Arch as Paging>::map_page(cr3, dst_va, pa, pte_flags);
            <Arch as Paging>::flush_va(dst_va);
            // Invalidate old PTE without freeing the frame.
            <Arch as Paging>::unmap_page(src_va);
            <Arch as Paging>::flush_va(src_va);
        }
    }

    // Zero-fill extension pages.
    for i in (old_len / PAGE)..(new_len / PAGE) {
        let dst_va = dst + i * PAGE;
        match crate::mm::pmm::alloc_page() {
            Some(pa) => {
                unsafe { core::ptr::write_bytes(pa as *mut u8, 0, PAGE); }
                <Arch as Paging>::map_page(cr3, dst_va, pa, pte_flags);
                <Arch as Paging>::flush_va(dst_va);
            }
            None => return -12, // ENOMEM (partial mapping left; POSIX-undefined)
        }
    }

    // Replace VMA record.
    crate::mm::mmap::remove_vma(pid, old_addr, old_len);
    crate::mm::mmap::insert_vma(pid, crate::mm::mmap::Vma {
        start: dst, end: dst + new_len,
        prot: vma.prot, flags: vma.flags,
        kind: vma.kind.clone(), file_offset: vma.file_offset,
    });

    dst as isize
}

/// Prot-to-PageFlags translation matching mmap.rs::prot_to_flags.
/// Duplicated here so stubs.rs has no cross-module import cycle.
#[inline]
fn prot_to_flags_mremap(prot: u32) -> PageFlags {
    let mut f = PageFlags::PRESENT | PageFlags::USER;
    if prot & crate::mm::mmap::PROT_WRITE != 0 { f |= PageFlags::WRITE; }
    if prot & crate::mm::mmap::PROT_EXEC  == 0 { f |= PageFlags::NX; }
    f
}

// ── NR 28  madvise ─────────────────────────────────────────────────────────────
//
// Linux madvise semantics for the advices we implement:
//
//   MADV_NORMAL      (0) — no-op: reset to default readahead behaviour
//   MADV_DONTNEED    (4) — free the physical pages and mark the VMA
//                          demand-pageable; subsequent reads return zeroes
//   MADV_FREE       (8)  — lazily free pages (we treat as DONTNEED)
//   MADV_WILLNEED   (3)  — prefetch (no-op; we have no readahead)
//   MADV_SEQUENTIAL (2)  — no-op
//   MADV_RANDOM     (1)  — no-op
//   MADV_DONTFORK  (10)  — no-op (CoW fork handles this adequately)
//   MADV_DOFORK    (11)  — no-op
//   MADV_DONTDUMP  (16)  — no-op
//   MADV_DODUMP    (17)  — no-op
//   MADV_MERGEABLE  (12) — no-op (no KSM)
//   MADV_HUGEPAGE   (14) — no-op (no THP yet)
//   MADV_NOHUGEPAGE (15) — no-op
//   Anything else        — return -EINVAL
//
// The critical difference from the old stub: MADV_DONTNEED now actually
// releases physical frames and unmaps the PTEs so subsequent accesses fault
// back through the demand-paging handler and see zeroes.  The old code
// merely zero-filled the pages in place, which wasted memory and could
// cause glibc malloc to misuse "freed" heap memory.

fn sys_madvise_impl(addr: usize, length: usize, advice: i32) -> isize {
    const PAGE: usize = 4096;

    // Align addr down, end up (Linux rounds inward for addr, outward for end).
    let aligned_addr = addr & !(PAGE - 1);
    let end          = (addr + length + PAGE - 1) & !(PAGE - 1);
    if aligned_addr >= end && length != 0 { return -22; }

    match advice {
        // No-op advices — accepted silently.
        0  | // MADV_NORMAL
        1  | // MADV_RANDOM
        2  | // MADV_SEQUENTIAL
        3  | // MADV_WILLNEED
        10 | // MADV_DONTFORK
        11 | // MADV_DOFORK
        12 | // MADV_MERGEABLE
        13 | // MADV_UNMERGEABLE
        14 | // MADV_HUGEPAGE
        15 | // MADV_NOHUGEPAGE
        16 | // MADV_DONTDUMP
        17   // MADV_DODUMP
        => return 0,

        4 | // MADV_DONTNEED
        8   // MADV_FREE — lazily free; we treat as DONTNEED for simplicity
        => {
            let pid = crate::proc::scheduler::current_pid();
            let cr3 = crate::proc::scheduler::with_proc(pid, |p| p.user_satp)
                .unwrap_or(0);
            if cr3 == 0 { return 0; }

            // Only free pages that belong to PMM-owned VMAs.  PhysMap
            // VMAs (MMIO/framebuffer) must never have their pages freed.
            let is_phys_range = |va: usize| -> bool {
                matches!(
                    crate::mm::mmap::find_vma(pid, va),
                    Some(v) if matches!(v.kind, crate::mm::mmap::VmaKind::PhysMap(_))
                )
            };

            for va in (aligned_addr..end).step_by(PAGE) {
                if is_phys_range(va) { continue; }
                if let Some(pa) = <Arch as Paging>::virt_to_phys(cr3, va) {
                    // Unmap the PTE — the next access will demand-fault
                    // through page_fault::handle_demand_fault and return
                    // a fresh zero page (Anonymous/Heap/Stack) or re-read
                    // the file page (FileBacked).
                    <Arch as Paging>::unmap_page(va);
                    <Arch as Paging>::flush_va(va);
                    crate::mm::pmm::free_page(pa);
                }
            }
            0
        }

        _ => -22, // EINVAL
    }
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

// ── NR 62  kill ────────────────────────────────────────────────────────────────

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

// ── NR 63  uname ───────────────────────────────────────────────────────────────

fn sys_uname_impl(buf_va: usize) -> isize {
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

// ── NR 86/88  link / symlink ──────────────────────────────────────────────────

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

// ── NR 89  readlink ──────────────────────────────────────────────────────────

fn sys_readlink_impl(path_va: usize, buf_va: usize, bufsiz: usize) -> isize {
    if bufsiz == 0 { return -22; }
    let path = match read_cstr_safe(path_va) { Some(s) => s, None => return -14 };
    if path.starts_with("/proc/") || path == "/proc/self" {
        let mut kbuf = alloc::vec![0u8; bufsiz];
        let n = crate::fs::procfs::procfs_readlink(&path, &mut kbuf);
        if n < 0 { return n; }
        if copy_to_user(buf_va, &kbuf[..n as usize]).is_err() { return -14; }
        return n;
    }
    match crate::fs::vfs::lookup(&path) {
        Some(d) if d.starts_with(b"\x00symlink\x00") => {
            let target = &d[9..];
            let n = target.len().min(bufsiz);
            if copy_to_user(buf_va, &target[..n]).is_err() { return -14; }
            n as isize
        }
        _ => -22,
    }
}

// ── NR 95  umask ─────────────────────────────────────────────────────────────

use core::sync::atomic::{AtomicU32, Ordering};
static UMASK: AtomicU32 = AtomicU32::new(0o022);

fn sys_umask_impl(mask: u32) -> isize {
    UMASK.swap(mask & 0o777, Ordering::Relaxed) as isize
}

// ── NR 96  gettimeofday ──────────────────────────────────────────────────────────

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

// ── NR 97/160/302  getrlimit / setrlimit / prlimit64 ─────────────────────────

fn sys_getrlimit_impl(resource: u32, rlim_va: usize) -> isize {
    let (soft, hard) = crate::proc::rlimit::getrlimit_for(0, resource as usize);
    let mut buf = [0u8; 16];
    buf[0..8].copy_from_slice(&soft.to_le_bytes());
    buf[8..16].copy_from_slice(&hard.to_le_bytes());
    if copy_to_user(rlim_va, &buf).is_err() { return -14; }
    0
}

fn sys_setrlimit_impl(resource: u32, rlim_va: usize) -> isize {
    let mut buf = [0u8; 16];
    if copy_from_user(&mut buf, rlim_va).is_err() { return -14; }
    let soft = u64::from_le_bytes(buf[0..8].try_into().unwrap());
    let hard = u64::from_le_bytes(buf[8..16].try_into().unwrap());
    crate::proc::rlimit::setrlimit_for(0, resource as usize, soft, hard)
}

fn sys_prlimit64_impl(pid: usize, resource: u32, new_va: usize, old_va: usize) -> isize {
    if old_va != 0 {
        let (soft, hard) = crate::proc::rlimit::getrlimit_for(pid, resource as usize);
        let mut buf = [0u8; 16];
        buf[0..8].copy_from_slice(&soft.to_le_bytes());
        buf[8..16].copy_from_slice(&hard.to_le_bytes());
        if copy_to_user(old_va, &buf).is_err() { return -14; }
    }
    if new_va != 0 {
        let mut buf = [0u8; 16];
        if copy_from_user(&mut buf, new_va).is_err() { return -14; }
        let soft = u64::from_le_bytes(buf[0..8].try_into().unwrap());
        let hard = u64::from_le_bytes(buf[8..16].try_into().unwrap());
        let r = crate::proc::rlimit::setrlimit_for(pid, resource as usize, soft, hard);
        if r < 0 { return r; }
    }
    0
}

// ── NR 98  getrusage ────────────────────────────────────────────────────────────

fn sys_getrusage_impl(who: i32, buf_va: usize) -> isize {
    let mut kbuf = [0u8; 144];
    if who == 0 /* RUSAGE_SELF */ {
        let pid = crate::proc::scheduler::current_pid();
        let cpu_ns = crate::proc::scheduler::with_proc(pid, |p| p.cpu_time_ns)
            .unwrap_or(0);
        let sec  = (cpu_ns / 1_000_000_000) as i64;
        let usec = ((cpu_ns % 1_000_000_000) / 1_000) as i64;
        kbuf[0..8].copy_from_slice(&sec.to_le_bytes());
        kbuf[8..16].copy_from_slice(&usec.to_le_bytes());
    }
    if copy_to_user(buf_va, &kbuf).is_err() { return -14; }
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
    let nprocs   = crate::proc::scheduler::proc_count().min(u16::MAX as usize) as u16;
    let info = SysInfo {
        uptime: uptime_s, loads: [0; 3],
        totalram: total, freeram: free,
        sharedram: 0, bufferram: 0, totalswap: 0, freeswap: 0,
        procs: nprocs, _pad: [0; 6], totalhigh: 0, freehigh: 0,
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

// ── NR 100  times ─────────────────────────────────────────────────────────────

fn sys_times_impl(buf_va: usize) -> isize {
    const CLOCKS_PER_SEC: u64 = 100;
    const NS_PER_TICK:    u64 = 1_000_000_000 / CLOCKS_PER_SEC;

    let now_ns   = crate::time::monotonic_ns();
    let elapsed  = (now_ns / NS_PER_TICK) as i64;

    if buf_va != 0 {
        let pid    = crate::proc::scheduler::current_pid();
        let cpu_ns = crate::proc::scheduler::with_proc(pid, |p| p.cpu_time_ns)
            .unwrap_or(0);
        let utime  = (cpu_ns / NS_PER_TICK) as i64;

        let mut kbuf = [0u8; 32];
        kbuf[0..8].copy_from_slice(&utime.to_le_bytes());
        if copy_to_user(buf_va, &kbuf).is_err() { return -14; }
    }
    elapsed
}

// ── NR 101  ptrace ────────────────────────────────────────────────────────────

fn sys_ptrace_impl(req: i32, pid: i32, addr: usize, data: usize) -> isize {
    crate::proc::ptrace::sys_ptrace(req, pid, addr, data)
}

// ── NR 131  sigaltstack ───────────────────────────────────────────────────────────

use spin::Mutex as SpinMutex;
use alloc::collections::BTreeMap;

static ALTSTACK: SpinMutex<BTreeMap<usize, [u8; 24]>> = SpinMutex::new(BTreeMap::new());

pub fn altstack_clear_pid(pid: usize) { ALTSTACK.lock().remove(&pid); }

fn sys_sigaltstack_impl(ss_va: usize, old_ss_va: usize) -> isize {
    let pid = crate::proc::scheduler::current_pid();
    if old_ss_va != 0 {
        let saved = ALTSTACK.lock().get(&pid).copied();
        let mut buf = saved.unwrap_or_else(|| {
            let mut b = [0u8; 24];
            b[8..12].copy_from_slice(&2i32.to_le_bytes());
            b
        });
        if copy_to_user(old_ss_va, &buf).is_err() { return -14; }
        let _ = buf;
    }
    if ss_va != 0 {
        let mut buf = [0u8; 24];
        if copy_from_user(&mut buf, ss_va).is_err() { return -14; }
        ALTSTACK.lock().insert(pid, buf);
    }
    0
}

// ── NR 137/138  statfs / fstatfs ───────────────────────────────────────────────

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

// ── NR 185  prctl ─────────────────────────────────────────────────────────────

const PR_SET_NAME:        i32 = 15;
const PR_GET_NAME:        i32 = 16;
const PR_SET_DUMPABLE:    i32 = 4;
const PR_GET_DUMPABLE:    i32 = 3;
const PR_SET_SECCOMP:     i32 = 22;
const PR_SET_PDEATHSIG:   i32 = 1;
const PR_SET_NO_NEW_PRIVS: i32 = 38;

static PROC_NAME: SpinMutex<BTreeMap<usize, [u8; 16]>> = SpinMutex::new(BTreeMap::new());

pub fn proc_name_clear(pid: usize) { PROC_NAME.lock().remove(&pid); }

fn sys_prctl_impl(op: i32, a2: usize, _a3: usize, _a4: usize, _a5: usize) -> isize {
    let pid = crate::proc::scheduler::current_pid();
    match op {
        PR_SET_NAME => {
            let mut name = [0u8; 16];
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

// ── NR 203/204  sched_setaffinity / sched_getaffinity ───────────────────────────

fn sys_sched_getaffinity_impl(_pid: usize, cpusetsize: usize, mask_va: usize) -> isize {
    if cpusetsize == 0 { return -14; }
    let sz  = cpusetsize.min(128);
    let mut buf = alloc::vec![0u8; sz];
    if sz > 0 { buf[0] = 0x01; }
    if copy_to_user(mask_va, &buf).is_err() { return -14; }
    0
}
fn sys_sched_setaffinity_impl(_pid: usize, _sz: usize, _mask: usize) -> isize { 0 }

// ── NR 230  clock_getres ──────────────────────────────────────────────────────────

fn sys_clock_getres_impl(_clkid: u32, res_va: usize) -> isize {
    if res_va != 0 {
        let mut buf = [0u8; 16];
        buf[8..16].copy_from_slice(&1i64.to_le_bytes());
        if copy_to_user(res_va, &buf).is_err() { return -14; }
    }
    0
}

// ── NR 247  waitid ─────────────────────────────────────────────────────────────

fn sys_waitid_impl(which: i32, id: i32, _infop: usize, options: u32) -> isize {
    let pid: isize = if which == 1 { id as isize } else { -1 };
    crate::proc::wait::sys_waitpid(pid, 0, options)
}

// ── NR 257-267  *at variants ───────────────────────────────────────────────────────

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

// ── NR 267  readlinkat ───────────────────────────────────────────────────────

fn sys_readlinkat_impl(dirfd: i32, path_va: usize, buf_va: usize, bufsiz: usize) -> isize {
    if bufsiz == 0 { return -22; }
    let path = match at_path(dirfd, path_va) { Some(p) => p, None => return -14 };
    if path.starts_with("/proc/") || path == "/proc/self" {
        let mut kbuf = alloc::vec![0u8; bufsiz];
        let n = crate::fs::procfs::procfs_readlink(&path, &mut kbuf);
        if n < 0 { return n; }
        if copy_to_user(buf_va, &kbuf[..n as usize]).is_err() { return -14; }
        return n;
    }
    match crate::fs::vfs::lookup(&path) {
        Some(d) if d.starts_with(b"\x00symlink\x00") => {
            let target = &d[9..];
            let n = target.len().min(bufsiz);
            if copy_to_user(buf_va, &target[..n]).is_err() { return -14; }
            n as isize
        }
        _ => -22,
    }
}

// ── NR 280  utimensat ─────────────────────────────────────────────────────────

fn sys_utimensat_impl(_dirfd: i32, _path_va: usize, _times_va: usize, _flags: i32) -> isize { 0 }

// ── NR 318  getrandom ────────────────────────────────────────────────────────

const GETRANDOM_MAX: usize = 4096;

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

// ── NR 319  memfd_create ─────────────────────────────────────────────────────

const MFD_CLOEXEC:       u32 = 0x0001;
const MFD_ALLOW_SEALING: u32 = 0x0002;
const MFD_HUGETLB:       u32 = 0x0004;

fn sys_memfd_create_impl(name_va: usize, flags: u32) -> isize {
    if flags & MFD_HUGETLB != 0 { return -22; }
    if flags & !(MFD_CLOEXEC | MFD_ALLOW_SEALING) != 0 { return -22; }
    crate::fs::ramfs::tmpfs_mount("/dev/shm", 64 * 1024 * 1024);
    let anon_path = match crate::fs::ramfs::tmpfs_create_anon("/dev/shm") {
        Ok(p)  => p,
        Err(e) => return e,
    };
    let fd = match crate::fs::vfs::open(&anon_path, crate::fs::vfs::O_RDWR) {
        Ok(fd)  => fd,
        Err(e)  => return e as isize,
    };
    if flags & MFD_CLOEXEC != 0 {
        crate::fs::fcntl::set_cloexec(fd, true);
    }
    if name_va != 0 {
        if let Some(name) = read_cstr_safe(name_va) {
            crate::fs::vfs::fd_set_debug_name(fd, alloc::format!("memfd:{}", name));
        }
    }
    fd as isize
}

// ── Misc stubs ────────────────────────────────────────────────────────────────

fn sys_chmod_impl(_path_va: usize, _mode: u32) -> isize { 0 }
fn sys_fchmod_impl(_fd: usize, _mode: u32) -> isize { 0 }
fn sys_chown_impl(_path_va: usize, _uid: u32, _gid: u32) -> isize { 0 }
fn sys_fchown_impl(_fd: usize, _uid: u32, _gid: u32) -> isize { 0 }
fn sys_mlock_impl(_addr: usize, _len: usize) -> isize { 0 }
fn sys_munlock_impl(_addr: usize, _len: usize) -> isize { 0 }
fn sys_mount_impl(_src: usize, _tgt: usize, _fs: usize, _flags: u64, _data: usize) -> isize { 0 }
fn sys_syslog_impl(_t: i32, _buf: usize, _len: i32) -> isize { 0 }
