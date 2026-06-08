//! Btrfs logical space allocator.

pub use super::superblock::BtrfsFs;

const ENOSPC: isize = -28;
const FALLBACK_ALIGNMENT: u64 = 4096;

#[inline]
fn align_up(value: u64, align: u64) -> Option<u64> {
    if align <= 1 {
        return Some(value);
    }

    let rem = value % align;
    if rem == 0 {
        Some(value)
    } else {
        value.checked_add(align - rem)
    }
}

impl BtrfsFs {
    /// Return the allocator alignment used for new logical reservations.
    ///
    /// Btrfs metadata allocations should be node-aligned. If the image has a
    /// malformed zero node size, fall back to sectorsize, then 4 KiB.
    pub(crate) fn alloc_alignment(&self) -> u64 {
        let nodesize = self.superblock.nodesize as u64;
        if nodesize != 0 {
            return nodesize;
        }

        let sectorsize = self.superblock.sectorsize as u64;
        if sectorsize != 0 {
            return sectorsize;
        }

        FALLBACK_ALIGNMENT
    }

    /// Normalize the allocation cursor after mount.
    ///
    /// Some mount paths seed `alloc_cursor` with `total_bytes`. That is not a
    /// valid allocatable logical address inside a mapped chunk, so the allocator
    /// lazily moves the cursor to at least `bytes_used`.
    pub(crate) fn init_alloc_cursor(&mut self) {
        let align = self.alloc_alignment();

        let floor = self
            .superblock
            .bytes_used
            .max(
                self.root_tree_root
                    .saturating_add(self.superblock.nodesize as u64),
            )
            .max(
                self.fs_tree_root
                    .saturating_add(self.superblock.nodesize as u64),
            );

        self.alloc_cursor = self
            .find_alloc_candidate(floor, align, align)
            .unwrap_or_else(|| align_up(floor, align).unwrap_or(floor));
    }

    /// Reserve a logical range for CoW writes.
    ///
    /// Returns the starting logical byte offset, or `-ENOSPC` if no mapped chunk
    /// can satisfy the allocation.
    pub(crate) fn try_alloc_logical_block(&mut self, size: usize) -> Result<u64, isize> {
        let align = self.alloc_alignment();

        let requested = if size == 0 { align } else { size as u64 };
        let len = align_up(requested, align).ok_or(ENOSPC)?;

        let mut floor = self.alloc_cursor;
        if floor == 0 || floor >= self.superblock.total_bytes {
            floor = self.superblock.bytes_used;
        }

        let logical = self
            .find_alloc_candidate(floor, len, align)
            .ok_or(ENOSPC)?;

        self.alloc_cursor = logical.checked_add(len).ok_or(ENOSPC)?;

        Ok(logical)
    }

    /// Compatibility wrapper for older call sites that expect a bare `u64`.
    ///
    /// New write-path code should prefer `try_alloc_logical_block` so `ENOSPC`
    /// can be returned cleanly.
    pub(crate) fn alloc_logical_block(&mut self, size: usize) -> u64 {
        self.try_alloc_logical_block(size)
            .expect("btrfs: logical allocation failed")
    }

    /// Return true if the entire logical range is backed by one mapped chunk.
    pub(crate) fn logical_range_is_mapped(&self, logical: u64, len: u64) -> bool {
        let Some(end) = logical.checked_add(len) else {
            return false;
        };

        self.chunk_map
            .iter()
            .any(|(start, chunk_end, _)| logical >= *start && end <= *chunk_end)
    }

    fn find_alloc_candidate(&self, floor: u64, len: u64, align: u64) -> Option<u64> {
        let mut best = None;

        for (chunk_start, chunk_end, _) in self.chunk_map.iter() {
            if chunk_end <= chunk_start {
                continue;
            }

            let base = floor.max(*chunk_start);

            let Some(candidate) = align_up(base, align) else {
                continue;
            };

            let Some(end) = candidate.checked_add(len) else {
                continue;
            };

            if end <= *chunk_end && best.map_or(true, |old| candidate < old) {
                best = Some(candidate);
            }
        }

        best
    }
}