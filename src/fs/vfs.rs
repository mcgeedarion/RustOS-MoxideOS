//! Virtual filesystem — file descriptor table + multi-backend dispatch.
//!
//! Backends (tried in order on open):
//!   1. Ext2 image mounted by `mount_ext2()`
//!   2. In-memory ramfs (initramfs + runtime-created files)
