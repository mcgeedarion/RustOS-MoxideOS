//! System V shared memory.
//!
//! ## API
//!
//! | Function                          | Returns      |
//! |-----------------------------------|--------------|
//! | `shmget(key, size, shmflg)`       | `shmid`      |
//! | `shmat(shmid, shmaddr, shmflg)`   | `*void` (VA) |
//! | `shmdt(shmaddr)`                  | `0`          |
//! | `shmctl(shmid, cmd, buf)`         | varies       |
//!
//! ## Implementation
//!
//! Physical pages are allocated via `pmm::alloc_frames(n)` when the segment
//! is created.  `shmat` maps the frames into the calling process's address
//! space using `vmm::map_range`.  `shmdt` removes the mapping but does not
//! free the frames (the last detach is tracked by `nattch`).
//!
//! The segment is freed when `IPC_RMID` has been issued AND `nattch == 0`.
//!
//! ## Address hint
//!
//! If `shmaddr == NULL`, the kernel chooses a free region.  The current
//! implementation uses a bump allocator in the process's mmap region
//! (integration point: replace with `vmm::find_free_region`).

extern crate alloc;
use crate::ipc::{
    check_perm, IpcPerm, IPC_CREAT, IPC_EXCL, IPC_PRIVATE, IPC_RMID, IPC_SET, IPC_STAT,
};
use alloc::{collections::BTreeMap, vec::Vec};
use spin::Mutex;

// ── SHM_* flags ──────────────────────────────────────────────────────────────

pub const SHM_RDONLY: i32 = 0o10000;
pub const SHM_RND: i32 = 0o20000;
pub const SHM_EXEC: i32 = 0o100000;

const PAGE_SIZE: usize = 4096;

// ── Data structures ──────────────────────────────────────────────────────────

/// Kernel-side shared memory segment.
struct ShmSegment {
    perm: IpcPerm,
    size: usize,
    frames: Vec<usize>, // physical page addresses
    nattch: usize,      // number of current attaches
    cpid: u32,
    lpid: u32,
    removed: bool, // IPC_RMID was issued; free on last detach
}

// ── Global tables ────────────────────────────────────────────────────────────

use alloc::sync::Arc;
static SHM_TABLE: Mutex<BTreeMap<i32, Arc<Mutex<ShmSegment>>>> = Mutex::new(BTreeMap::new());
static NEXT_ID: Mutex<i32> = Mutex::new(1);

/// Per-process attach table: `(shmid, va)` pairs.
static ATTACH_TABLE: Mutex<BTreeMap<(usize, usize), i32>> = Mutex::new(BTreeMap::new());

#[inline]
fn alloc_id() -> i32 {
    let mut id = NEXT_ID.lock();
    let v = *id;
    *id += 1;
    v
}

// ── shmget ───────────────────────────────────────────────────────────────────

pub fn shmget(key: i32, size: usize, shmflg: i32) -> Result<i32, isize> {
    if size == 0 {
        return Err(-22);
    } // EINVAL
    let pages = size.div_ceil(PAGE_SIZE);
    let mut tbl = SHM_TABLE.lock();

    if key == IPC_PRIVATE {
        let frames = alloc_frames(pages)?;
        let id = alloc_id();
        tbl.insert(
            id,
            Arc::new(Mutex::new(ShmSegment {
                perm: IpcPerm::new(IPC_PRIVATE, 0, 0, (shmflg & 0o777) as u16),
                size: pages * PAGE_SIZE,
                frames,
                nattch: 0,
                cpid: crate::proc::scheduler::current_pid() as u32,
                lpid: 0,
                removed: false,
            })),
        );
        return Ok(id);
    }

    if let Some((&id, _)) = tbl.iter().find(|(_, s)| s.lock().perm.key == key) {
        if shmflg & IPC_CREAT != 0 && shmflg & IPC_EXCL != 0 {
            return Err(-17);
        } // EEXIST
        return Ok(id);
    }
    if shmflg & IPC_CREAT == 0 {
        return Err(-2);
    } // ENOENT

    let frames = alloc_frames(pages)?;
    let id = alloc_id();
    tbl.insert(
        id,
        Arc::new(Mutex::new(ShmSegment {
            perm: IpcPerm::new(key, 0, 0, (shmflg & 0o777) as u16),
            size: pages * PAGE_SIZE,
            frames,
            nattch: 0,
            cpid: crate::proc::scheduler::current_pid() as u32,
            lpid: 0,
            removed: false,
        })),
    );
    Ok(id)
}

// ── shmat ────────────────────────────────────────────────────────────────────

pub fn shmat(shmid: i32, shmaddr: usize, shmflg: i32) -> Result<usize, isize> {
    let arc = {
        let tbl = SHM_TABLE.lock();
        tbl.get(&shmid).cloned().ok_or(-22isize)? // EINVAL
    };
    let mut seg = arc.lock();

    if !check_perm(
        &seg.perm,
        0,
        0,
        if shmflg & SHM_RDONLY != 0 { 0o4 } else { 0o6 },
    ) {
        return Err(-13); // EACCES
    }

    let prot = if shmflg & SHM_RDONLY != 0 {
        crate::mm::mmap::PROT_READ
    } else {
        crate::mm::mmap::PROT_READ | crate::mm::mmap::PROT_WRITE
    };

    let hint = if shmaddr == 0 {
        crate::proc::scheduler::current_mmap_base()
    } else {
        if shmflg & SHM_RND != 0 {
            shmaddr & !(65536 - 1)
        } else {
            shmaddr
        }
    };

    let va = crate::mm::vmm::map_range(hint, seg.size, prot, &seg.frames)?;

    seg.nattch += 1;
    seg.lpid = crate::proc::scheduler::current_pid() as u32;

    let pid = crate::proc::scheduler::current_pid();
    ATTACH_TABLE.lock().insert((pid, va), shmid);
    Ok(va)
}

// ── shmdt ────────────────────────────────────────────────────────────────────

pub fn shmdt(shmaddr: usize) -> Result<(), isize> {
    let pid = crate::proc::scheduler::current_pid();
    let shmid = ATTACH_TABLE
        .lock()
        .remove(&(pid, shmaddr))
        .ok_or(-22isize)?;

    crate::mm::vmm::unmap_range(shmaddr);

    let should_free = {
        let tbl = SHM_TABLE.lock();
        let arc = tbl.get(&shmid).ok_or(-22isize)?;
        let mut seg = arc.lock();
        seg.nattch = seg.nattch.saturating_sub(1);
        seg.lpid = pid as u32;
        seg.removed && seg.nattch == 0
    };

    if should_free {
        if let Some(arc) = SHM_TABLE.lock().remove(&shmid) {
            let seg = arc.lock();
            for &pa in &seg.frames {
                unsafe {
                    crate::mm::pmm::free_page(pa as *mut u8);
                }
            }
        }
    }
    Ok(())
}

// ── shmctl ───────────────────────────────────────────────────────────────────

pub fn shmctl(shmid: i32, cmd: i32) -> Result<i32, isize> {
    let arc = {
        let tbl = SHM_TABLE.lock();
        tbl.get(&shmid).cloned().ok_or(-22isize)?
    };
    match cmd {
        c if c == IPC_RMID => {
            let mut seg = arc.lock();
            seg.removed = true;
            if seg.nattch == 0 {
                drop(seg);
                SHM_TABLE.lock().remove(&shmid);
            }
            Ok(0)
        }
        c if c == IPC_STAT => Ok(0),
        c if c == IPC_SET => Ok(0),
        _ => Err(-22),
    }
}

// ── Physical frame allocator helper ──────────────────────────────────────────

fn alloc_frames(n: usize) -> Result<Vec<usize>, isize> {
    let mut frames = Vec::with_capacity(n);
    for _ in 0..n {
        let pa = crate::mm::pmm::alloc_page().ok_or(-12isize)? as usize;
        frames.push(pa);
    }
    Ok(frames)
}
