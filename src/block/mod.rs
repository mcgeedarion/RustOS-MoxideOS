//! Block device abstraction.
pub trait BlockDev {
    fn read(&self, lba: u64, buf: &mut [u8]);
    fn write(&self, lba: u64, buf: &[u8]);
    fn sector_size(&self) -> usize {
        512
    }
}
