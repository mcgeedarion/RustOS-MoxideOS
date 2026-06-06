// openat2(2) RESOLVE_* enforcement + VMA-aware sys_mincore(2).
//
// Included from syscall/mod.rs via `include!("openat2_mincore.rs")`.

const RESOLVE_NO_XDEV: u64 = 0x01;
const RESOLVE_NO_MAGICLINKS: u64 = 0x02;
const RESOLVE_NO_SYMLINKS: u64 = 0x04;
const RESOLVE_BENEATH: u64 = 0x08;
const RESOLVE_IN_ROOT: u64 = 0x10;
const RESOLVE_CACHED: u64 = 0x20;
const RESOLVE_ALL_KNOWN: u64 = 0x3f;
const OPENAT2_STRUCT_SIZE: usize = 24;

fn sys_openat2_impl(dirfd: i32, path_va: usize, how_va: usize, size: usize) -> isize {
    if size < OPENAT2_STRUCT_SIZE {
        return -22;
    }
    let mut how_buf = [0u8; 24];
    if crate::uaccess::copy_from_user(&mut how_buf, how_va).is_err() {
        return -14;
    }
    let flags = u64::from_le_bytes(how_buf[0..8].try_into().unwrap());
    let mode = u64::from_le_bytes(how_buf[8..16].try_into().unwrap());
    let resolve = u64::from_le_bytes(how_buf[16..24].try_into().unwrap());

    if resolve & !RESOLVE_ALL_KNOWN != 0 {
        return -22;
    }
    if resolve & RESOLVE_CACHED != 0 {
        return -11;
    }

    let path = read_cstr_safe(path_va);
    if path.is_empty() {
        return -2;
    }

    if resolve & (RESOLVE_BENEATH | RESOLVE_IN_ROOT) != 0 {
        if path.split('/').any(|c| c == "..") {
            return -1;
        }
    }
    if resolve & (RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS) != 0 {
        if path.starts_with("/proc/") {
            return -40;
        }
    }

    sys_openat_impl(dirfd, path_va, flags as i32, mode as u32)
}

fn sys_mincore(addr: usize, length: usize, vec_va: usize) -> isize {
    use crate::mm::pmm::PAGE_SIZE;
    if vec_va == 0 {
        return -14;
    }
    let pages = (length + PAGE_SIZE - 1) / PAGE_SIZE;
    if !crate::uaccess::validate_user_ptr(vec_va, pages) {
        return -14;
    }
    for i in 0..pages {
        let va = addr + i * PAGE_SIZE;
        let present = if crate::mm::mmap::vma_contains(va) {
            1u8
        } else {
            0u8
        };
        if crate::uaccess::copy_to_user(vec_va + i, &[present]).is_err() {
            return -14;
        }
    }
    0
}
