//! Safe wrappers for copying data between kernel and userspace.
//! Canonical location: src/kernel/uaccess.rs

extern crate alloc;
use crate::arch::{api::Paging, Arch};
use core::slice;

pub const USER_SPACE_END: usize = 0x0000_8000_0000_0000;
const PAGE_SIZE: usize = 4096;

#[inline]
fn user_range_valid(va: usize, len: usize) -> bool {
    if va == 0 || len == 0 {
        return false;
    }
    match va.checked_add(len) {
        Some(end) => end <= USER_SPACE_END,
        None => false,
    }
}

fn pages_mapped(va: usize, len: usize) -> bool {
    let _guard = if crate::proc::scheduler::has_current_user_proc() {
        Some(crate::proc::scheduler::with_current_mm_read())
    } else {
        None
    };
    let cr3 =
        crate::proc::scheduler::with_proc(crate::proc::scheduler::current_pid(), |p| p.user_satp)
            .unwrap_or(0);
    if cr3 == 0 {
        return false;
    }
    let first_page = va & !(PAGE_SIZE - 1);
    let last_page = (va + len - 1) & !(PAGE_SIZE - 1);
    let mut page = first_page;
    while page <= last_page {
        if <Arch as Paging>::virt_to_phys(cr3, page).is_none() {
            return false;
        }
        page = match page.checked_add(PAGE_SIZE) {
            Some(n) => n,
            None => break,
        };
    }
    true
}

#[inline]
pub fn validate_user_ptr(va: usize, len: usize) -> bool {
    user_range_valid(va, len) && pages_mapped(va, len)
}

pub fn copy_from_user(dst: &mut [u8], src_va: usize) -> Result<(), ()> {
    if !user_range_valid(src_va, dst.len()) {
        return Err(());
    }
    if !pages_mapped(src_va, dst.len()) {
        return Err(());
    }
    let src = unsafe { slice::from_raw_parts(src_va as *const u8, dst.len()) };
    dst.copy_from_slice(src);
    Ok(())
}

pub fn copy_to_user(dst_va: usize, src: &[u8]) -> bool {
    if !user_range_valid(dst_va, src.len()) {
        return false;
    }
    if !pages_mapped(dst_va, src.len()) {
        return false;
    }
    let dst = unsafe { slice::from_raw_parts_mut(dst_va as *mut u8, src.len()) };
    dst.copy_from_slice(src);
    true
}

pub fn read_path(ptr: *const u8) -> Option<alloc::string::String> {
    if ptr.is_null() {
        return None;
    }
    let base = ptr as usize;
    if !user_range_valid(base, 1) {
        return None;
    }
    let _guard = if crate::proc::scheduler::has_current_user_proc() {
        Some(crate::proc::scheduler::with_current_mm_read())
    } else {
        None
    };
    let cr3 =
        crate::proc::scheduler::with_proc(crate::proc::scheduler::current_pid(), |p| p.user_satp)
            .unwrap_or(0);
    if cr3 == 0 {
        return None;
    }
    const PATH_MAX: usize = 4095;
    let mut len = 0usize;
    let mut next_page_check = 0usize;
    loop {
        if len > PATH_MAX {
            return None;
        }
        if len >= next_page_check {
            if !user_range_valid(base + len, 1) {
                return None;
            }
            let ps = (base + len) & !(PAGE_SIZE - 1);
            if <Arch as Paging>::virt_to_phys(cr3, ps).is_none() {
                return None;
            }
            next_page_check = ps + PAGE_SIZE - base;
        }
        if unsafe { *ptr.add(len) } == 0 {
            break;
        }
        len += 1;
    }
    let bytes = unsafe { core::slice::from_raw_parts(ptr, len) };
    core::str::from_utf8(bytes)
        .ok()
        .map(alloc::string::String::from)
}
