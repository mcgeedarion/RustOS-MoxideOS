//! Block device abstraction.

pub mod virtio_blk;

pub trait BlockDev {
    fn read(&self, lba: u64, buf: &mut [u8]);
    fn write(&self, lba: u64, buf: &[u8]);
    fn sector_size(&self) -> usize {
        512
    }
}

/// Placeholder block scheme registered during early scheme-table bring-up until
/// block-device URL dispatch is wired to the concrete block layer.
pub struct BlkScheme;

impl BlkScheme {
    pub const fn new() -> Self {
        Self
    }
}

impl crate::fs::scheme_table::Scheme for BlkScheme {
    fn open(
        &self,
        _path: &str,
        _flags: scheme_api::OpenFlags,
    ) -> Result<scheme_api::SchemeFileId, scheme_api::SchemeError> {
        Err(scheme_api::SchemeError::NoSuchScheme)
    }

    fn close(&self, _fid: scheme_api::SchemeFileId) -> Result<(), scheme_api::SchemeError> {
        Ok(())
    }
}
