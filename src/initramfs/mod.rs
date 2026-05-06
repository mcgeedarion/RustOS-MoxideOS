//! CPIO newc initramfs parser.
//!
//! Parses the CPIO "newc" (SVR4, magic `070701`) format that QEMU places in
//! memory when you pass `-initrd <file>`.  The kernel receives the base
//! physical address and byte length from the boot protocol (multiboot2
//! module tag or UEFI config table) and passes a `&[u8]` slice here.
//!
//! ## Public API
//!
//! ```rust
//! // Locate a file by path and get its content bytes:
//! if let Some(data) = initramfs::find_file(cpio_bytes, "/init") {
//!     // data is a sub-slice of cpio_bytes — zero-copy
//! }
//!
//! // Iterate every entry:
//! for entry in initramfs::iter(cpio_bytes) {
//!     // entry.name : &str
//!     // entry.data : &[u8]
//!     // entry.mode : u32  (Unix permission bits)
//!     // entry.size : usize
//! }
//! ```
//!
//! ## Format reference
//! Each record:
//!   - 110-byte ASCII header (all fields zero-padded hex)
//!   - name (namesize bytes, NUL-terminated)
//!   - padding to 4-byte boundary
//!   - file data (filesize bytes)
//!   - padding to 4-byte boundary
//! The archive ends with an entry whose name is `TRAILER!!!`.

/// Parsed view of one CPIO entry.  Borrows from the underlying archive slice.
#[derive(Debug, Clone, Copy)]
pub struct CpioEntry<'a> {
    /// File path as stored in the archive (e.g. `"./init"`, `"init"`, `"/init"`).
    pub name: &'a str,
    /// Raw file content bytes (empty for directories / device nodes).
    pub data: &'a [u8],
    /// Unix mode word (type + permission bits).
    pub mode: u32,
    /// File size in bytes (same as `data.len()`).
    pub size: usize,
}

// ── Internal constants ────────────────────────────────────────────────────

const NEWC_MAGIC:  &[u8; 6] = b"070701";
const HEADER_LEN:  usize    = 110;
const TRAILER:     &str     = "TRAILER!!!";

// ── Helpers ───────────────────────────────────────────────────────────────

/// Parse a zero-padded 8-digit ASCII hex field from the CPIO header.
/// Returns 0 on any parse error rather than panicking.
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

/// Round `n` up to the next multiple of `align` (must be power of two).
#[inline]
fn align_up(n: usize, align: usize) -> usize {
    (n + align - 1) & !(align - 1)
}

// ── Iterator ─────────────────────────────────────────────────────────────

/// Iterator over CPIO entries in a newc archive.
pub struct CpioIter<'a> {
    data:   &'a [u8],
    offset: usize,
}

impl<'a> Iterator for CpioIter<'a> {
    type Item = CpioEntry<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        let buf = self.data;

        loop {
            let off = self.offset;

            // Need at least a full header.
            if off + HEADER_LEN > buf.len() { return None; }

            // Verify magic.
            if &buf[off..off + 6] != NEWC_MAGIC { return None; }

            // ── Parse header fields (all 8-digit hex, positions per spec) ──
            // Offsets within the 110-byte header:
            //   [0..6]   magic
            //   [6..14]  ino
            //   [14..22] mode
            //   [22..30] uid
            //   [30..38] gid
            //   [38..46] nlink
            //   [46..54] mtime
            //   [54..62] filesize
            //   [62..70] devmajor
            //   [70..78] devminor
            //   [78..86] rdevmajor
            //   [86..94] rdevminor
            //   [94..102] namesize
            //   [102..110] check
            let mode      = parse_hex8(&buf[off + 14..off + 22]);
            let filesize  = parse_hex8(&buf[off + 54..off + 62]) as usize;
            let namesize  = parse_hex8(&buf[off + 94..off + 102]) as usize;

            // Name immediately follows header.
            let name_start = off + HEADER_LEN;
            let name_end   = name_start + namesize;
            if name_end > buf.len() { return None; }

            // Name is NUL-terminated; strip the NUL and any leading "./".
            let raw_name = core::str::from_utf8(&buf[name_start..name_end])
                .unwrap_or("")
                .trim_end_matches('\0');
            let name = raw_name
                .trim_start_matches("./")
                .trim_start_matches('/');

            // File data follows name, both padded to 4-byte boundary.
            let data_start = align_up(name_end, 4);
            let data_end   = data_start + filesize;
            if data_end > buf.len() { return None; }

            // Advance offset past this record.
            self.offset = align_up(data_end, 4);

            // End-of-archive sentinel.
            if name == TRAILER { return None; }

            let data = &buf[data_start..data_end];

            return Some(CpioEntry { name, data, mode, size: filesize });
        }
    }
}

// ── Public API ────────────────────────────────────────────────────────────

/// Return an iterator over every entry in a newc CPIO archive.
pub fn iter(cpio: &[u8]) -> CpioIter<'_> {
    CpioIter { data: cpio, offset: 0 }
}

/// Find a file by path in a newc CPIO archive and return its content bytes.
///
/// Accepts paths with or without leading `/` or `./` (all normalised).
/// Returns `None` if not found or if the archive is malformed.
pub fn find_file<'a>(cpio: &'a [u8], path: &str) -> Option<&'a [u8]> {
    // Normalise query: strip leading slashes and "./".
    let needle = path
        .trim_start_matches("./")
        .trim_start_matches('/');

    for entry in iter(cpio) {
        if entry.name == needle && entry.size > 0 {
            return Some(entry.data);
        }
    }
    None
}

// ── Tests (run with `cargo test` on host) ────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal newc CPIO record by hand.
    fn make_record(name: &str, data: &[u8]) -> alloc::vec::Vec<u8> {
        extern crate alloc;
        use alloc::vec::Vec;

        let namesize = name.len() + 1; // include NUL
        let filesize = data.len();

        let header = alloc::format!(
            "070701"
            "{:08x}" // ino
            "{:08x}" // mode
            "{:08x}" // uid
            "{:08x}" // gid
            "{:08x}" // nlink
            "{:08x}" // mtime
            "{:08x}" // filesize
            "{:08x}" // devmajor
            "{:08x}" // devminor
            "{:08x}" // rdevmajor
            "{:08x}" // rdevminor
            "{:08x}" // namesize
            "{:08x}", // check
            1u32, 0o100644u32, 0u32, 0u32, 1u32, 0u32,
            filesize as u32,
            0u32, 0u32, 0u32, 0u32,
            namesize as u32, 0u32,
        );
        let mut rec: Vec<u8> = header.into_bytes();
        rec.extend_from_slice(name.as_bytes());
        rec.push(0); // NUL
        while rec.len() % 4 != 0 { rec.push(0); }
        rec.extend_from_slice(data);
        while rec.len() % 4 != 0 { rec.push(0); }
        rec
    }

    fn make_trailer() -> alloc::vec::Vec<u8> {
        make_record("TRAILER!!!", b"")
    }

    #[test]
    fn find_init() {
        extern crate alloc;
        let mut archive = make_record("init", b"ELF_FAKE_DATA");
        archive.extend(make_trailer());
        let found = find_file(&archive, "/init").unwrap();
        assert_eq!(found, b"ELF_FAKE_DATA");
    }

    #[test]
    fn find_dotslash_prefix() {
        extern crate alloc;
        let mut archive = make_record("./bin/hello", b"HELLO");
        archive.extend(make_trailer());
        assert!(find_file(&archive, "bin/hello").is_some());
        assert!(find_file(&archive, "/bin/hello").is_some());
    }

    #[test]
    fn not_found() {
        extern crate alloc;
        let mut archive = make_record("other", b"DATA");
        archive.extend(make_trailer());
        assert!(find_file(&archive, "/init").is_none());
    }

    #[test]
    fn iter_count() {
        extern crate alloc;
        let mut archive = make_record("a", b"1");
        archive.extend(make_record("b", b"2"));
        archive.extend(make_trailer());
        assert_eq!(iter(&archive).count(), 2);
    }
}
