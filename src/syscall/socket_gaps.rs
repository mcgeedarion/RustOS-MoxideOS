//! openat2 RESOLVE_* enforcement + VMA-aware sys_mincore.
//!
//! Included from mod.rs via `include!("socket_gaps.rs")`.
//! Shares the mod.rs namespace — can call read_cstr_safe, copy_to_user, etc.

// ── openat2 + RESOLVE_* enforcement ──────────────────────────────────────
//
// Enforces the subset of RESOLVE_* flags that are meaningful with rustos's
// single-root VFS.  Callers setting unknown bits get EINVAL(-22) so future
// semantics are never silently ignored.

const RESOLVE_NO_XDEV:       u64 = 0x01;
const RESOLVE_NO_MAGICLINKS: u64 = 0x02;
const RESOLVE_NO_SYMLINKS:   u64 = 0x04;
const RESOLVE_BENEATH:       u64 = 0x08;
const RESOLVE_IN_ROOT:       u64 = 0x10;
const RESOLVE_CACHED:        u64 = 0x20;
const RESOLVE_ALL_KNOWN:     u64 = 0x3f;

const OPENAT2_STRUCT_SIZE: usize = 24; // sizeof(struct open_how)

#[repr(C)]
struct OpenHow { flags: u64, mode: u64, resolve: u64 }

fn sys_openat2_impl(dirfd: i32, path_va: usize, how_va: usize, size: usize) -> isize {
    // 1. size must cover the full open_how struct
    if size < OPENAT2_STRUCT_SIZE { return -22; } // EINVAL

    // 2. Validate + copy open_how from user
    if !crate::uaccess::validate_user_ptr(how_va, OPENAT2_STRUCT_SIZE) { return -14; } // EFAULT
    let how = unsafe { &*(how_va as *const OpenHow) };

    // 3. Reject any unknown resolve bits — future-proof
    if how.resolve & !RESOLVE_ALL_KNOWN != 0 { return -22; } // EINVAL

    // 4. RESOLVE_CACHED: rustos has no dcache — always a miss
    if how.resolve & RESOLVE_CACHED != 0 { return -11; } // EAGAIN

    // 5. Read and validate the path
    let path = read_cstr_safe(path_va);
    if path.is_empty() { return -2; } // ENOENT

    // 6. RESOLVE_BENEATH / RESOLVE_IN_ROOT — reject any ".." component
    if how.resolve & (RESOLVE_BENEATH | RESOLVE_IN_ROOT) != 0 {
        if path.split('/').any(|c| c == "..") {
            return -1; // EPERM — would escape the root/dirfd scope
        }
    }

    // 7. RESOLVE_NO_SYMLINKS — reject /proc virtual paths (only symlink layer)
    if how.resolve & RESOLVE_NO_SYMLINKS != 0 {
        if path.starts_with("/proc/") {
            return -40; // ELOOP — symlink encountered
        }
    }

    // 8. RESOLVE_NO_MAGICLINKS — same: magic links live under /proc
    if how.resolve & RESOLVE_NO_MAGICLINKS != 0 {
        if path.starts_with("/proc/") {
            return -40; // ELOOP
        }
    }

    // 9. RESOLVE_NO_XDEV: single VFS, no device boundaries — always passes.

    // 10. All checks passed — delegate to the regular openat path
    sys_openat(dirfd, path_va, how.flags as i32, how.mode as u32)
}

// ── sys_mincore ───────────────────────────────────────────────────────────
//
// Walk [addr, addr+length) page by page and write 1 into vec[i] if a VMA
// covers that page, 0 otherwise.  More accurate than always returning 0
// (every page "not in core") which caused some allocators to over-aggressively
// call madvise(DONTNEED).

fn sys_mincore(addr: usize, length: usize, vec_va: usize) -> isize {
    use crate::mm::pmm::PAGE_SIZE;
    if vec_va == 0 { return -14; } // EFAULT
    let pages = (length + PAGE_SIZE - 1) / PAGE_SIZE;
    if !crate::uaccess::validate_user_ptr(vec_va, pages) { return -14; }
    for i in 0..pages {
        let va = addr + i * PAGE_SIZE;
        let present: u8 = if crate::mm::mmap::vma_contains(va) { 1 } else { 0 };
        unsafe { *((vec_va + i) as *mut u8) = present; }
    }
    0
}
