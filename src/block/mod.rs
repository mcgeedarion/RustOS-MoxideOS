//! Block device abstraction.

extern crate alloc;

use alloc::vec::Vec;
use spin::Mutex;

pub mod virtio_blk;

pub trait BlockDev {
    fn read(&self, lba: u64, buf: &mut [u8]);
    fn write(&self, lba: u64, buf: &[u8]);
    fn sector_size(&self) -> usize {
        512
    }
}

const SECTOR_SIZE: usize = 512;

struct BlkHandle {
    offset: u64,
}

static BLK_HANDLES: Mutex<Vec<Option<BlkHandle>>> = Mutex::new(Vec::new());

fn alloc_handle(handle: BlkHandle) -> scheme_api::SchemeFileId {
    let mut handles = BLK_HANDLES.lock();

    for (idx, slot) in handles.iter_mut().enumerate() {
        if slot.is_none() {
            *slot = Some(handle);
            return scheme_api::SchemeFileId((idx + 1) as u64);
        }
    }

    handles.push(Some(handle));
    scheme_api::SchemeFileId(handles.len() as u64)
}

fn fid_index(fid: scheme_api::SchemeFileId) -> Result<usize, scheme_api::SchemeError> {
    fid.0
        .checked_sub(1)
        .map(|v| v as usize)
        .ok_or(scheme_api::SchemeError::InvalidArg)
}

fn read_at(offset: u64, buf: &mut [u8]) -> Result<usize, scheme_api::SchemeError> {
    let mut done = 0usize;
    let mut sector = [0u8; SECTOR_SIZE];

    while done < buf.len() {
        let abs = offset + done as u64;
        let lba = abs / SECTOR_SIZE as u64;
        let sector_off = (abs % SECTOR_SIZE as u64) as usize;
        let n = (SECTOR_SIZE - sector_off).min(buf.len() - done);

        if !virtio_blk::read_sector(lba, &mut sector) {
            return if done == 0 {
                Err(scheme_api::SchemeError::Io)
            } else {
                Ok(done)
            };
        }

        buf[done..done + n].copy_from_slice(&sector[sector_off..sector_off + n]);
        done += n;
    }

    Ok(done)
}

fn write_at(offset: u64, buf: &[u8]) -> Result<usize, scheme_api::SchemeError> {
    let mut done = 0usize;
    let mut sector = [0u8; SECTOR_SIZE];

    while done < buf.len() {
        let abs = offset + done as u64;
        let lba = abs / SECTOR_SIZE as u64;
        let sector_off = (abs % SECTOR_SIZE as u64) as usize;
        let n = (SECTOR_SIZE - sector_off).min(buf.len() - done);

        if n != SECTOR_SIZE {
            if !virtio_blk::read_sector(lba, &mut sector) {
                return if done == 0 {
                    Err(scheme_api::SchemeError::Io)
                } else {
                    Ok(done)
                };
            }
        }

        sector[sector_off..sector_off + n].copy_from_slice(&buf[done..done + n]);

        if !virtio_blk::write_sector(lba, &sector) {
            return if done == 0 {
                Err(scheme_api::SchemeError::Io)
            } else {
                Ok(done)
            };
        }

        done += n;
    }

    Ok(done)
}

/// Block scheme backed by the currently wired virtio-blk device.
///
/// Supported paths:
/// - `blk:`
/// - `blk:0`
/// - `blk:virtio0`
/// - `blk:disk0`
///
/// Use `seek` to choose a byte offset. Reads and writes are translated into
/// 512-byte sector requests, including read-modify-write for partial sectors.
pub struct BlkScheme;

impl BlkScheme {
    pub const fn new() -> Self {
        Self
    }
}

impl crate::fs::scheme_table::Scheme for BlkScheme {
    fn open(
        &self,
        path: &str,
        _flags: scheme_api::OpenFlags,
    ) -> Result<scheme_api::SchemeFileId, scheme_api::SchemeError> {
        match path.trim_matches('/') {
            "" | "0" | "virtio0" | "disk0" => Ok(alloc_handle(BlkHandle { offset: 0 })),
            _ => Err(scheme_api::SchemeError::NotFound),
        }
    }

    fn read(
        &self,
        fid: scheme_api::SchemeFileId,
        buf: &mut [u8],
    ) -> Result<usize, scheme_api::SchemeError> {
        let idx = fid_index(fid)?;

        let offset = {
            let handles = BLK_HANDLES.lock();
            let Some(Some(handle)) = handles.get(idx) else {
                return Err(scheme_api::SchemeError::InvalidArg);
            };
            handle.offset
        };

        let n = read_at(offset, buf)?;

        if let Some(Some(handle)) = BLK_HANDLES.lock().get_mut(idx) {
            handle.offset = handle.offset.saturating_add(n as u64);
        }

        Ok(n)
    }

    fn write(
        &self,
        fid: scheme_api::SchemeFileId,
        buf: &[u8],
    ) -> Result<usize, scheme_api::SchemeError> {
        let idx = fid_index(fid)?;

        let offset = {
            let handles = BLK_HANDLES.lock();
            let Some(Some(handle)) = handles.get(idx) else {
                return Err(scheme_api::SchemeError::InvalidArg);
            };
            handle.offset
        };

        let n = write_at(offset, buf)?;

        if let Some(Some(handle)) = BLK_HANDLES.lock().get_mut(idx) {
            handle.offset = handle.offset.saturating_add(n as u64);
        }

        Ok(n)
    }

    fn seek(
        &self,
        fid: scheme_api::SchemeFileId,
        offset: i64,
        whence: u8,
    ) -> Result<u64, scheme_api::SchemeError> {
        let idx = fid_index(fid)?;
        let mut handles = BLK_HANDLES.lock();

        let Some(Some(handle)) = handles.get_mut(idx) else {
            return Err(scheme_api::SchemeError::InvalidArg);
        };

        let base = match whence {
            0 => 0i128,
            1 => handle.offset as i128,
            2 => return Err(scheme_api::SchemeError::InvalidArg), // unknown disk size
            _ => return Err(scheme_api::SchemeError::InvalidArg),
        };

        let new = base + offset as i128;
        if new < 0 {
            return Err(scheme_api::SchemeError::InvalidArg);
        }

        handle.offset = new as u64;
        Ok(handle.offset)
    }

    fn close(&self, fid: scheme_api::SchemeFileId) -> Result<(), scheme_api::SchemeError> {
        let idx = fid_index(fid)?;
        let mut handles = BLK_HANDLES.lock();

        if let Some(slot) = handles.get_mut(idx) {
            *slot = None;
            Ok(())
        } else {
            Err(scheme_api::SchemeError::InvalidArg)
        }
    }
}
