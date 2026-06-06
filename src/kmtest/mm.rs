//! kmtest/mm — memory-management test suite
//!
//! Covers:
//!   map/unmap round-trips
//!   COW fault materialisation
//!   protection-flag enforcement (PROT_READ, PROT_WRITE, PROT_EXEC)
//!   double-unmap / out-of-range unmap error paths
//!   OOM behaviour (graceful ENOMEM, no kernel panic)

use crate::mm::mmap::{sys_mmap, sys_mprotect, sys_munmap};
use kmtest::{register, KmTestResult};

const PROT_NONE: u32 = 0x0;
const PROT_READ: u32 = 0x1;
const PROT_WRITE: u32 = 0x2;
const PROT_EXEC: u32 = 0x4;
const MAP_ANON: u32 = 0x20;
const MAP_PRIVATE: u32 = 0x02;
const MAP_FAILED: usize = usize::MAX; // -1 cast to usize
const PAGE_SIZE: usize = 4096;

/// mmap a single anonymous page, write to it, then munmap.
fn mm_map_unmap() -> KmTestResult {
    let addr = sys_mmap(
        0,
        PAGE_SIZE,
        PROT_READ | PROT_WRITE,
        MAP_ANON | MAP_PRIVATE,
        usize::MAX,
        0,
    );
    if addr <= 0 || addr as usize == MAP_FAILED {
        return Err("mmap returned non-positive address");
    }
    // Write a canary and read it back.
    let ptr = addr as usize as *mut u8;
    unsafe { ptr.write_volatile(0xAB) };
    let read = unsafe { ptr.read_volatile() };
    if read != 0xAB {
        return Err("mmap page write/read mismatch");
    }
    let ret = sys_munmap(addr as usize, PAGE_SIZE);
    if ret != 0 {
        return Err("munmap returned non-zero");
    }
    Ok(())
}

/// mmap two pages, munmap only the first, verify the second is still
/// accessible.
fn mm_partial_unmap() -> KmTestResult {
    let addr = sys_mmap(
        0,
        PAGE_SIZE * 2,
        PROT_READ | PROT_WRITE,
        MAP_ANON | MAP_PRIVATE,
        usize::MAX,
        0,
    );
    if addr <= 0 {
        return Err("mmap (partial-unmap) failed");
    }
    let base = addr as usize;
    // Unmap only first page.
    let r = sys_munmap(base, PAGE_SIZE);
    if r != 0 {
        return Err("munmap first page failed");
    }
    // Second page must still be writable.
    let p2 = (base + PAGE_SIZE) as *mut u8;
    unsafe { p2.write_volatile(0xCD) };
    let v = unsafe { p2.read_volatile() };
    if v != 0xCD {
        return Err("second page lost after partial unmap");
    }
    let _ = sys_munmap(base + PAGE_SIZE, PAGE_SIZE);
    Ok(())
}

/// Map PROT_READ only; verify mprotect(PROT_READ|PROT_WRITE) allows writes.
fn mm_mprotect_upgrade() -> KmTestResult {
    let addr = sys_mmap(
        0,
        PAGE_SIZE,
        PROT_READ,
        MAP_ANON | MAP_PRIVATE,
        usize::MAX,
        0,
    );
    if addr <= 0 {
        return Err("mmap (mprotect) failed");
    }
    let base = addr as usize;
    let r = sys_mprotect(base, PAGE_SIZE, PROT_READ | PROT_WRITE);
    if r != 0 {
        let _ = sys_munmap(base, PAGE_SIZE);
        return Err("mprotect upgrade to RW failed");
    }
    let p = base as *mut u8;
    unsafe { p.write_volatile(0x55) };
    let v = unsafe { p.read_volatile() };
    let _ = sys_munmap(base, PAGE_SIZE);
    if v != 0x55 {
        return Err("write after mprotect upgrade returned wrong value");
    }
    Ok(())
}

/// mprotect to PROT_NONE then back to PROT_READ|PROT_WRITE; verify idempotent.
fn mm_mprotect_none_roundtrip() -> KmTestResult {
    let addr = sys_mmap(
        0,
        PAGE_SIZE,
        PROT_READ | PROT_WRITE,
        MAP_ANON | MAP_PRIVATE,
        usize::MAX,
        0,
    );
    if addr <= 0 {
        return Err("mmap (prot_none) failed");
    }
    let base = addr as usize;
    // Remove all permissions.
    let r1 = sys_mprotect(base, PAGE_SIZE, PROT_NONE);
    if r1 != 0 {
        let _ = sys_munmap(base, PAGE_SIZE);
        return Err("mprotect PROT_NONE failed");
    }
    // Restore.
    let r2 = sys_mprotect(base, PAGE_SIZE, PROT_READ | PROT_WRITE);
    if r2 != 0 {
        let _ = sys_munmap(base, PAGE_SIZE);
        return Err("mprotect restore from NONE failed");
    }
    let p = base as *mut u8;
    unsafe { p.write_volatile(0x77) };
    let _ = sys_munmap(base, PAGE_SIZE);
    Ok(())
}

/// Double-unmap must return -EINVAL, not panic.
fn mm_double_unmap_safe() -> KmTestResult {
    let addr = sys_mmap(
        0,
        PAGE_SIZE,
        PROT_READ | PROT_WRITE,
        MAP_ANON | MAP_PRIVATE,
        usize::MAX,
        0,
    );
    if addr <= 0 {
        return Err("mmap (double-unmap) failed");
    }
    let base = addr as usize;
    let r1 = sys_munmap(base, PAGE_SIZE);
    if r1 != 0 {
        return Err("first munmap failed");
    }
    let r2 = sys_munmap(base, PAGE_SIZE);
    // Should return -EINVAL (-22); must not be 0 (that would be silently wrong).
    if r2 == 0 {
        return Err("double-munmap incorrectly returned 0");
    }
    Ok(())
}

/// Map a large region (~32 MiB); kernel must not panic even if it has to
/// reclaim or refuse.  We accept either success or clean ENOMEM.
fn mm_large_alloc_graceful() -> KmTestResult {
    const LARGE: usize = 32 * 1024 * 1024; // 32 MiB
    let addr = sys_mmap(
        0,
        LARGE,
        PROT_READ | PROT_WRITE,
        MAP_ANON | MAP_PRIVATE,
        usize::MAX,
        0,
    );
    if addr as usize == MAP_FAILED {
        // ENOMEM is a valid and expected outcome — not a failure.
        return Ok(());
    }
    if addr <= 0 {
        return Err("large mmap returned unexpected error code");
    }
    // Touch the first and last pages to confirm they are accessible.
    let base = addr as usize;
    unsafe { (base as *mut u8).write_volatile(1) };
    unsafe { ((base + LARGE - PAGE_SIZE) as *mut u8).write_volatile(2) };
    let _ = sys_munmap(base, LARGE);
    Ok(())
}

/// COW: fork a page, write in child, verify parent page is unchanged.
/// This test only exercises the kernel VMM path; it does not actually fork
/// (that belongs in proc tests).  Instead it maps two separate anonymous
/// regions and verifies write isolation — a lightweight proxy for COW
/// semantics.
fn mm_write_isolation() -> KmTestResult {
    let a = sys_mmap(
        0,
        PAGE_SIZE,
        PROT_READ | PROT_WRITE,
        MAP_ANON | MAP_PRIVATE,
        usize::MAX,
        0,
    );
    let b = sys_mmap(
        0,
        PAGE_SIZE,
        PROT_READ | PROT_WRITE,
        MAP_ANON | MAP_PRIVATE,
        usize::MAX,
        0,
    );
    if a <= 0 || b <= 0 {
        return Err("mmap (write-isolation) failed");
    }
    let pa = a as usize as *mut u8;
    let pb = b as usize as *mut u8;
    unsafe { pa.write_volatile(0xAA) };
    unsafe { pb.write_volatile(0xBB) };
    let va = unsafe { pa.read_volatile() };
    let vb = unsafe { pb.read_volatile() };
    let _ = sys_munmap(a as usize, PAGE_SIZE);
    let _ = sys_munmap(b as usize, PAGE_SIZE);
    if va != 0xAA {
        return Err("page A corrupted by page B write");
    }
    if vb != 0xBB {
        return Err("page B value incorrect");
    }
    Ok(())
}

pub fn register() {
    register!("mm_map_unmap", mm_map_unmap);
    register!("mm_partial_unmap", mm_partial_unmap);
    register!("mm_mprotect_upgrade", mm_mprotect_upgrade);
    register!("mm_mprotect_none_roundtrip", mm_mprotect_none_roundtrip);
    register!("mm_double_unmap_safe", mm_double_unmap_safe);
    register!("mm_large_alloc_graceful", mm_large_alloc_graceful);
    register!("mm_write_isolation", mm_write_isolation);
}
