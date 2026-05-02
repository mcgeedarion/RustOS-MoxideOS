//! Ext2 read-write filesystem driver.
//!
//! Revision 0 and revision 1 (dynamic inode sizes) are supported.
//! Block sizes of 1024, 2048 and 4096 bytes are supported.
//!
//! ## On-disk mutation model
//!
//! All mutations are applied to the in-memory copy (`Ext2Fs::data: Vec<u8>`).
//! After every write the affected blocks are marked dirty and flushed to the
//! VirtIO-blk device via `virtio_blk::write_sectors`.  This makes the disk
//! image durable across reboots.
