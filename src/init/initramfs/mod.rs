//! CPIO newc initramfs parser + kernel-facing `load()` entry point.
//!
//! ## Boot-protocol initramfs discovery
//!
//! On **RISC-V / OpenSBI**: QEMU passes the initrd physical address and size
//! in FDT node `/chosen`, properties `linux,initrd-start` and
//! `linux,initrd-end`. `pmm::init_from_fdt()` stores those values via
//! `set_initramfs_range()` before the heap is initialised, so no allocation is
//! needed.
//!
//! On **x86_64 / multiboot2**: the multiboot2 tag type 3 (module) carries the
//! initrd start/end physical addresses.  The x86_64 boot stub calls
//! `set_initramfs_range()` after parsing the multiboot2 header.
//!
//! ## Public API
//!
//! ```rust
//! let ram = initramfs::load();
//! if let Some(bytes) = ram.file("/init") { /* load ELF */ }
//! for entry in ram.entries() { /* walk archive */ }
//! ```

const NEWC_MAGIC: &[u8; 6] = b"070701";
const HEADER_LEN: usize = 110;
const TRAILER: &str = "TRAILER!!!";

// We store the physical address and byte length in two static atomics so they
// can be written once by the early boot code (before the allocator is up) and
// read later by `load()`.

use core::sync::atomic::{AtomicUsize, Ordering};

static INITRAMFS_PA: AtomicUsize = AtomicUsize::new(0);
static INITRAMFS_LEN: AtomicUsize = AtomicUsize::new(0);

/// Called by the boot stub (FDT walker on RISC-V, multiboot2 tag parser on
/// x86_64) to record where QEMU placed the initramfs image in physical memory.
///
/// Must be called **before** `heap::init()` and **before** `load()`.
pub fn set_initramfs_range(phys_start: usize, byte_len: usize) {
    INITRAMFS_PA.store(phys_start, Ordering::Relaxed);
    INITRAMFS_LEN.store(byte_len, Ordering::Relaxed);
}

/// Borrowed view of the in-memory CPIO archive.  Returned by `load()`.
///
/// The underlying bytes are not copied — this is a zero-copy reference into
/// the physical memory where QEMU (or the bootloader) placed the initrd image.
pub struct InitramfsHandle<'a> {
    cpio: &'a [u8],
}

impl<'a> InitramfsHandle<'a> {
    /// Return the raw file content bytes for `path`, or `None` if not found.
    ///
    /// Accepts paths with or without a leading `/` or `./` prefix:
    /// `"/init"`, `"init"`, and `"./init"` all resolve to the same entry.
    pub fn file(&self, path: &str) -> Option<&'a [u8]> {
        find_file(self.cpio, path)
    }

    /// Iterate every non-directory entry in the archive.
    pub fn entries(&self) -> CpioIter<'a> {
        iter(self.cpio)
    }
}

/// Obtain a zero-copy handle to the initramfs CPIO archive.
///
/// Panics (kernel panic via the `!` diverge) if `set_initramfs_range()` was
/// never called (i.e. the boot stub forgot to record the initrd location).
///
/// # Safety
/// The physical memory at `[pa, pa+len)` must be valid, readable, and must
/// remain mapped for the lifetime of the returned handle.  On both RISC-V
/// (Sv39 identity map) and x86_64 (direct-map region) this is guaranteed by
/// the time `kernel_main` calls this function.
pub fn load() -> InitramfsHandle<'static> {
    let pa = INITRAMFS_PA.load(Ordering::Relaxed);
    let len = INITRAMFS_LEN.load(Ordering::Relaxed);

    if pa == 0 || len == 0 {
        crate::println!("initramfs: FATAL: initramfs physical address not set.");
        crate::println!("initramfs: Pass -initrd <file> to QEMU and ensure");
        crate::println!("initramfs: the boot stub calls set_initramfs_range().");
        loop {
            #[cfg(target_arch = "riscv64")]
            unsafe {
                core::arch::asm!("wfi");
            }
            #[cfg(target_arch = "x86_64")]
            unsafe {
                core::arch::asm!("hlt");
            }
            #[cfg(not(any(target_arch = "riscv64", target_arch = "x86_64")))]
            core::hint::spin_loop();
        }
    }

    // SAFETY: the boot stub guarantees [pa, pa+len) is valid mapped memory.
    let cpio: &'static [u8] = unsafe { core::slice::from_raw_parts(pa as *const u8, len) };

    if cpio.len() < HEADER_LEN || &cpio[..6] != NEWC_MAGIC {
        crate::println!(
            "initramfs: WARN: cpio magic not found at {:#x} (len={})",
            pa,
            len
        );
        crate::println!(
            "initramfs: the archive may be compressed — pass an uncompressed cpio to QEMU."
        );
    }

    InitramfsHandle { cpio }
}

/// One file/directory entry inside the CPIO archive.
#[derive(Debug, Clone, Copy)]
pub struct CpioEntry<'a> {
    /// File path, with leading `./` and `/` stripped.
    pub name: &'a str,
    /// Raw file content (empty for directories / special files).
    pub data: &'a [u8],
    /// Unix mode word (type + permission bits, e.g. `0o100755`).
    pub mode: u32,
    /// File size in bytes — always `data.len()`.
    pub size: usize,
    /// Unix UID (owner).
    pub uid: u32,
    /// Unix GID (group).
    pub gid: u32,
    /// Modification timestamp (seconds since epoch).
    pub mtime: u32,
    /// Number of hard links.
    pub nlink: u32,
}

impl<'a> CpioEntry<'a> {
    #[inline]
    pub fn is_file(&self) -> bool {
        self.mode & 0o170000 == 0o100000
    }
    #[inline]
    pub fn is_dir(&self) -> bool {
        self.mode & 0o170000 == 0o040000
    }
    #[inline]
    pub fn is_symlink(&self) -> bool {
        self.mode & 0o170000 == 0o120000
    }
    #[inline]
    pub fn permissions(&self) -> u32 {
        self.mode & 0o007777
    }
}

#[inline]
fn parse_hex8(bytes: &[u8]) -> u32 {
    let mut val: u32 = 0;
    for &b in bytes.iter().take(8) {
        let digit = match b {
            b'0'..=b'9' => b - b'0',
            b'a'..=b'f' => b - b'a' + 10,
            b'A'..=b'F' => b - b'A' + 10,
            _ => return 0,
        };
        val = val.wrapping_shl(4) | digit as u32;
    }
    val
}

#[inline]
fn align_up(n: usize, align: usize) -> usize {
    (n + align - 1) & !(align - 1)
}

/// Iterator over entries in a newc CPIO archive.
pub struct CpioIter<'a> {
    data: &'a [u8],
    offset: usize,
}

impl<'a> Iterator for CpioIter<'a> {
    type Item = CpioEntry<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        let buf = self.data;

        loop {
            let off = self.offset;
            if off + HEADER_LEN > buf.len() {
                return None;
            }
            if &buf[off..off + 6] != NEWC_MAGIC {
                return None;
            }

            let mode = parse_hex8(&buf[off + 14..off + 22]);
            let uid = parse_hex8(&buf[off + 22..off + 30]);
            let gid = parse_hex8(&buf[off + 30..off + 38]);
            let nlink = parse_hex8(&buf[off + 38..off + 46]);
            let mtime = parse_hex8(&buf[off + 46..off + 54]);
            let filesize = parse_hex8(&buf[off + 54..off + 62]) as usize;
            let namesize = parse_hex8(&buf[off + 94..off + 102]) as usize;

            let name_start = off + HEADER_LEN;
            let name_end = name_start + namesize;
            if name_end > buf.len() {
                return None;
            }

            let raw_name = core::str::from_utf8(&buf[name_start..name_end])
                .unwrap_or("")
                .trim_end_matches('\0');
            let name = raw_name.trim_start_matches("./").trim_start_matches('/');

            let data_start = align_up(name_end, 4);
            let data_end = data_start + filesize;
            if data_end > buf.len() {
                return None;
            }

            self.offset = align_up(data_end, 4);

            if name == TRAILER {
                return None;
            }

            return Some(CpioEntry {
                name,
                data: &buf[data_start..data_end],
                mode,
                size: filesize,
                uid,
                gid,
                mtime,
                nlink,
            });
        }
    }
}

/// Return an iterator over every entry in a newc CPIO archive slice.
pub fn iter(cpio: &[u8]) -> CpioIter<'_> {
    CpioIter {
        data: cpio,
        offset: 0,
    }
}

/// Find a file by path and return its content bytes.
pub fn find_file<'a>(cpio: &'a [u8], path: &str) -> Option<&'a [u8]> {
    let needle = path.trim_start_matches("./").trim_start_matches('/');
    for entry in iter(cpio) {
        if entry.name == needle && entry.is_file() {
            return Some(entry.data);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_record(name: &str, mode: u32, data: &[u8]) -> alloc::vec::Vec<u8> {
        extern crate alloc;
        use alloc::{format, vec::Vec};
        let namesize = name.len() + 1;
        let filesize = data.len();
        let header =
            format!(
            "070701{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}",
            1u32, mode, 0u32, 0u32, 1u32, 0u32, filesize as u32,
            0u32, 0u32, 0u32, 0u32, namesize as u32, 0u32,
        );
        let mut rec: Vec<u8> = header.into_bytes();
        rec.extend_from_slice(name.as_bytes());
        rec.push(0);
        while rec.len() % 4 != 0 {
            rec.push(0);
        }
        rec.extend_from_slice(data);
        while rec.len() % 4 != 0 {
            rec.push(0);
        }
        rec
    }

    fn trailer() -> alloc::vec::Vec<u8> {
        make_record("TRAILER!!!", 0, b"")
    }

    #[test]
    fn find_init_slash_prefix() {
        extern crate alloc;
        let mut a = make_record("init", 0o100755, b"ELF");
        a.extend(trailer());
        assert_eq!(find_file(&a, "/init"), Some(b"ELF".as_ref()));
        assert_eq!(find_file(&a, "init"), Some(b"ELF".as_ref()));
        assert_eq!(find_file(&a, "./init"), Some(b"ELF".as_ref()));
    }

    #[test]
    fn dirs_not_returned_by_find_file() {
        extern crate alloc;
        let mut a = make_record("etc", 0o040755, b"");
        a.extend(make_record("etc/passwd", 0o100644, b"root:x:0:0\n"));
        a.extend(trailer());
        assert!(find_file(&a, "etc").is_none());
        assert!(find_file(&a, "etc/passwd").is_some());
    }

    #[test]
    fn iter_all_entries_including_dirs() {
        extern crate alloc;
        let mut a = make_record("etc", 0o040755, b"");
        a.extend(make_record("etc/passwd", 0o100644, b"..."));
        a.extend(make_record("bin/sh", 0o100755, b"ELF"));
        a.extend(trailer());
        assert_eq!(iter(&a).count(), 3);
    }

    #[test]
    fn entry_type_helpers() {
        extern crate alloc;
        let mut a = make_record("dir", 0o040755, b"");
        a.extend(make_record("file", 0o100644, b"x"));
        a.extend(make_record("link", 0o120777, b"target"));
        a.extend(trailer());
        let entries: alloc::vec::Vec<_> = iter(&a).collect();
        assert!(entries[0].is_dir());
        assert!(entries[1].is_file());
        assert!(entries[2].is_symlink());
    }

    #[test]
    fn not_found_returns_none() {
        extern crate alloc;
        let mut a = make_record("other", 0o100644, b"DATA");
        a.extend(trailer());
        assert!(find_file(&a, "/init").is_none());
    }
}
