//! System V shared memory.
//!
//! ## API
//!
//!   shmget(key, size, shmflg)       -> shmid
//!   shmat(shmid, shmaddr, shmflg)   -> *void  (virtual address)
//!   shmdt(shmaddr)                  -> 0
//!   shmctl(shmid, cmd, buf)         -> varies
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
use alloc::vec::Vec;
use spin::Mutex;
use alloc::collections::BTreeMap;
use crate::ipc::{IpcPerm, IPC_PRIVATE, IPC_CREAT, IPC_EXCL, IPC_RMID, IPC_SET, IPC_STAT, check_perm};

// ── Flags ────────────────────────────────────────────────────────────────────────────
pub const SHM_RDONLY: i32 = 0o010000;
pub const SHM_RND:    i32 = 0o020000;
pub const SHM_REMAP:  i32 = 0o040000;
pub const SHM_EXEC:   i32 = 0o100000;
pub const SHMLBA:     usize = 4096;

// ── Limits ────────────────────────────────────────────────────────────────────────────
pub const SHMMIN:  usize = 1;
pub const SHMMAX:  usize = 0x1000_0000; // 256 MiB hard cap
pub const SHMMNI:  usize = 4096;

// ── shmctl extra commands ──────────────────────────────────────────────────────────
pub const SHM_LOCK:   i32 = 11;
pub const SHM_UNLOCK: i32 = 12;
pub const SHM_STAT:   i32 = 13;
pub const SHM_INFO:   i32 = 14;

// ── Data structures ───────────────────────────────────────────────────────────────────

/// `struct shmid_ds` (Linux x86_64 UAPI).
#[repr(C)]
#[derive(Clone, Copy, Default, Debug)]
pub struct ShmidDs {
    pub shm_perm:   IpcPerm,
    pub shm_segsz:  u64,
    pub shm_atime:  i64,
    pub shm_dtime:  i64,
    pub shm_ctime:  i64,
    pub shm_cpid:   u32,
    pub shm_lpid:   u32,
    pub shm_nattch: u64,
    _pad: [u8; 16],
}

/// Kernel-internal segment descriptor.
struct ShmSeg {
    ds:       ShmidDs,
    key:      i32,
    /// Physical frame base addresses (one per PAGE_SIZE page).
    frames:   Vec<u64>,
    /// True once IPC_RMID is issued; freed when nattch hits 0.
    marked_for_removal: bool,
}

/// Per-process attachment record (stored in proc::Task).
#[derive(Clone, Copy, Debug)]
pub struct ShmAttach {
    pub shmid:  i32,
    pub vaddr:  usize,
    pub size:   usize,
    pub rdonly: bool,
}

static SEGS: Mutex<BTreeMap<i32, ShmSeg>> = Mutex::new(BTreeMap::new());
static NEXT_ID: spin::Mutex<i32> = spin::Mutex::new(1);
fn alloc_id() -> i32 { let mut n = NEXT_ID.lock(); let id = *n; *n += 1; id }

// ── shmget ────────────────────────────────────────────────────────────────────────────

pub fn shmget(key: i32, size: usize, shmflg: i32) -> Result<i32, isize> {
    let mut segs = SEGS.lock();
    if key != IPC_PRIVATE {
        if let Some((&id, _)) = segs.iter().find(|(_, s)| s.key == key) {
            if shmflg & IPC_CREAT != 0 && shmflg & IPC_EXCL != 0 {
                return Err(-17);
            }
            return Ok(id);
        }
        if shmflg & IPC_CREAT == 0 { return Err(-2); }
    }
    if size < SHMMIN || size > SHMMAX { return Err(-22); }
    if segs.len() >= SHMMNI { return Err(-28); }

    // Allocate physical frames.
    let n_pages = (size + 4095) / 4096;
    let frames  = alloc_frames(n_pages)?;

    let id   = alloc_id();
    let mode = (shmflg & 0o777) as u16;
    let perm = IpcPerm::new(key, 0, 0, mode);
    let now  = crate::time::clock::time_secs();
    let ds   = ShmidDs {
        shm_perm:  perm,
        shm_segsz: size as u64,
        shm_ctime: now,
        shm_cpid:  current_pid(),
        ..Default::default()
    };
    segs.insert(id, ShmSeg { ds, key, frames, marked_for_removal: false });
    Ok(id)
}

// ── shmat ────────────────────────────────────────────────────────────────────────────

/// Map shared memory into the current process's address space.
/// Returns the virtual address the segment was mapped at.
pub fn shmat(shmid: i32, shmaddr: usize, shmflg: i32) -> Result<usize, isize> {
    let mut segs = SEGS.lock();
    let seg = segs.get_mut(&shmid).ok_or(-22isize)?;
    if !check_perm(&seg.ds.shm_perm, 0, 0, 0o4) { return Err(-13); }
    let rdonly = shmflg & SHM_RDONLY != 0;
    let size   = seg.ds.shm_segsz as usize;
    let frames = seg.frames.clone();

    // Choose virtual address.
    let vaddr = if shmaddr == 0 {
        find_free_vaddr(size)
    } else if shmflg & SHM_RND != 0 {
        shmaddr & !(SHMLBA - 1)
    } else {
        if shmaddr % 4096 != 0 { return Err(-22); }
        shmaddr
    };

    // Map each frame into the process's page table.
    let flags = if rdonly { vmm_flags::READ } else { vmm_flags::READ | vmm_flags::WRITE };
    map_frames(vaddr, &frames, flags)?;

    seg.ds.shm_nattch += 1;
    seg.ds.shm_atime   = crate::time::clock::time_secs();
    seg.ds.shm_lpid    = current_pid();
    Ok(vaddr)
}

// ── shmdt ────────────────────────────────────────────────────────────────────────────

pub fn shmdt(shmaddr: usize) -> Result<(), isize> {
    // Look up by vaddr in the calling process's attach list.
    // Integration point: walk crate::proc::current().shm_attaches.
    let shmid = vaddr_to_shmid(shmaddr).ok_or(-22isize)?;
    let mut segs = SEGS.lock();
    let seg = segs.get_mut(&shmid).ok_or(-22isize)?;
    let size = seg.ds.shm_segsz as usize;
    unmap_range(shmaddr, size);
    seg.ds.shm_nattch  = seg.ds.shm_nattch.saturating_sub(1);
    seg.ds.shm_dtime   = crate::time::clock::time_secs();
    seg.ds.shm_lpid    = current_pid();
    let remove = seg.marked_for_removal && seg.ds.shm_nattch == 0;
    if remove {
        let frames = seg.frames.clone();
        drop(segs);
        free_frames(&frames);
        SEGS.lock().remove(&shmid);
    }
    Ok(())
}

// ── shmctl ────────────────────────────────────────────────────────────────────────────

pub fn shmctl(shmid: i32, cmd: i32) -> Result<ShmidDs, isize> {
    let mut segs = SEGS.lock();
    match cmd {
        IPC_RMID => {
            let seg = segs.get_mut(&shmid).ok_or(-22isize)?;
            seg.marked_for_removal = true;
            if seg.ds.shm_nattch == 0 {
                let frames = seg.frames.clone();
                drop(segs);
                free_frames(&frames);
                SEGS.lock().remove(&shmid);
            }
            Ok(ShmidDs::default())
        }
        IPC_STAT | SHM_STAT => {
            Ok(segs.get(&shmid).ok_or(-22isize)?.ds)
        }
        SHM_LOCK | SHM_UNLOCK => Ok(ShmidDs::default()), // no-op for now
        _ => Err(-22),
    }
}

pub fn shmctl_set(shmid: i32, new_ds: ShmidDs) -> Result<(), isize> {
    let mut segs = SEGS.lock();
    let seg = segs.get_mut(&shmid).ok_or(-22isize)?;
    seg.ds.shm_perm.uid  = new_ds.shm_perm.uid;
    seg.ds.shm_perm.gid  = new_ds.shm_perm.gid;
    seg.ds.shm_perm.mode = new_ds.shm_perm.mode & 0o777;
    seg.ds.shm_ctime     = crate::time::clock::time_secs();
    Ok(())
}

// ── VMM / PMM stubs ──────────────────────────────────────────────────────────────────

mod vmm_flags {
    pub const READ:  u32 = 1;
    pub const WRITE: u32 = 2;
}

/// Allocate `n` 4 KiB physical frames.  Returns their physical addresses.
fn alloc_frames(n: usize) -> Result<Vec<u64>, isize> {
    // crate::mem::pmm::alloc_frames(n).ok_or(-12) // ENOMEM
    Ok((0..n).map(|_| 0u64).collect()) // stub
}

fn free_frames(_frames: &[u64]) {
    // crate::mem::pmm::free_frames(frames);
}

fn map_frames(vaddr: usize, frames: &[u64], _flags: u32) -> Result<(), isize> {
    // crate::mem::vmm::map_range(vaddr, frames, flags)
    let _ = (vaddr, frames);
    Ok(())
}

fn unmap_range(vaddr: usize, size: usize) {
    // crate::mem::vmm::unmap_range(vaddr, size);
    let _ = (vaddr, size);
}

fn find_free_vaddr(size: usize) -> usize {
    // crate::proc::current().mmap_bump(size)
    let _ = size;
    0x7000_0000_0000 // placeholder
}

fn vaddr_to_shmid(vaddr: usize) -> Option<i32> {
    // Walk crate::proc::current().shm_attaches
    let _ = vaddr;
    None
}

fn current_pid() -> u32 { 0 }
