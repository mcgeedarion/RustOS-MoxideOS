//! JBD2 journal replay support for ext4.

extern crate alloc;

use alloc::vec::Vec;

const JBD2_MAGIC: u32 = 0xC03B3998;
const JBD2_DESCRIPTOR_BLOCK: u32 = 1;
const JBD2_COMMIT_BLOCK: u32 = 2;
const JBD2_SUPERBLOCK_V1: u32 = 3;
const JBD2_SUPERBLOCK_V2: u32 = 4;
const JBD2_REVOKE_BLOCK: u32 = 5;

const JBD2_FLAG_ESCAPE: u16 = 0x0001;
const JBD2_FLAG_SAME_UUID: u16 = 0x0002;
const JBD2_FLAG_DELETED: u16 = 0x0004;
const JBD2_FLAG_LAST_TAG: u16 = 0x0008;

const JBD2_FEATURE_INCOMPAT_REVOKE: u32 = 0x00000001;
const JBD2_FEATURE_INCOMPAT_64BIT: u32 = 0x00000002;
const JBD2_FEATURE_INCOMPAT_ASYNC_COMMIT: u32 = 0x00000004;
const JBD2_FEATURE_INCOMPAT_CSUM_V2: u32 = 0x00000008;
const JBD2_FEATURE_INCOMPAT_CSUM_V3: u32 = 0x00000010;
const JBD2_FEATURE_INCOMPAT_FAST_COMMIT: u32 = 0x00000020;

const JBD2_FEATURE_COMPAT_CHECKSUM: u32 = 0x00000001;

#[derive(Clone, Copy, Debug, Default)]
pub struct JournalFeatures {
    pub compat: u32,
    pub incompat: u32,
    pub ro_compat: u32,
}

#[derive(Clone, Copy, Debug)]
pub struct JournalSuperblock {
    pub block_size: usize,
    pub max_len: u32,
    pub first: u32,
    pub sequence: u32,
    pub start: u32,
    pub errno: u32,
    pub features: JournalFeatures,
    pub uuid: [u8; 16],
    pub checksum_type: u8,
    pub checksum_seed: u32,
}

#[derive(Clone, Debug)]
struct DescriptorTag {
    fs_block: u64,
    flags: u16,
    escaped: bool,
}

#[derive(Clone, Debug)]
struct RevokeRecord {
    sequence: u32,
    fs_block: u64,
}

#[derive(Clone, Debug)]
struct PendingTxn {
    sequence: u32,
    tags: Vec<DescriptorTag>,
    payloads: Vec<Vec<u8>>,
    revokes: Vec<RevokeRecord>,
}

#[derive(Clone, Debug, Default)]
pub struct ReplayReport {
    pub transactions_seen: usize,
    pub transactions_replayed: usize,
    pub blocks_replayed: usize,
    pub revoke_records: usize,
    pub checksum_failures: usize,
    pub unsupported_fast_commit_blocks: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReplayError {
    EmptyJournal,
    InvalidBlockSize,
    BadSuperblock,
    UnsupportedFeature(u32),
    OutOfBounds,
}

#[inline]
fn be16(b: &[u8], off: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*b.get(off)?, *b.get(off + 1)?]))
}

#[inline]
fn be32(b: &[u8], off: usize) -> Option<u32> {
    Some(u32::from_be_bytes([
        *b.get(off)?,
        *b.get(off + 1)?,
        *b.get(off + 2)?,
        *b.get(off + 3)?,
    ]))
}

#[inline]
fn be64(b: &[u8], off: usize) -> Option<u64> {
    Some(u64::from_be_bytes([
        *b.get(off)?,
        *b.get(off + 1)?,
        *b.get(off + 2)?,
        *b.get(off + 3)?,
        *b.get(off + 4)?,
        *b.get(off + 5)?,
        *b.get(off + 6)?,
        *b.get(off + 7)?,
    ]))
}

#[inline]
fn header(block: &[u8]) -> Option<(u32, u32, u32)> {
    let magic = be32(block, 0)?;
    let ty = be32(block, 4)?;
    let seq = be32(block, 8)?;
    if magic != JBD2_MAGIC {
        return None;
    }
    Some((magic, ty, seq))
}

pub fn parse_superblock(block: &[u8]) -> Option<JournalSuperblock> {
    let (_, ty, _) = header(block)?;
    if ty != JBD2_SUPERBLOCK_V1 && ty != JBD2_SUPERBLOCK_V2 {
        return None;
    }

    let block_size = be32(block, 12)? as usize;
    let max_len = be32(block, 16)?;
    let first = be32(block, 20)?;
    let sequence = be32(block, 24)?;
    let start = be32(block, 28)?;
    let errno = be32(block, 32).unwrap_or(0);
    let compat = be32(block, 36).unwrap_or(0);
    let incompat = be32(block, 40).unwrap_or(0);
    let ro_compat = be32(block, 44).unwrap_or(0);
    let mut uuid = [0u8; 16];
    if block.len() >= 64 {
        uuid.copy_from_slice(&block[48..64]);
    }
    let checksum_type = *block.get(80).unwrap_or(&0);
    let checksum_seed = be32(block, 84).unwrap_or(0);

    if block_size == 0 || block_size & (block_size - 1) != 0 {
        return None;
    }

    Some(JournalSuperblock {
        block_size,
        max_len,
        first,
        sequence,
        start,
        errno,
        features: JournalFeatures {
            compat,
            incompat,
            ro_compat,
        },
        uuid,
        checksum_type,
        checksum_seed,
    })
}

fn unsupported_incompat(features: JournalFeatures) -> u32 {
    let supported = JBD2_FEATURE_INCOMPAT_REVOKE
        | JBD2_FEATURE_INCOMPAT_64BIT
        | JBD2_FEATURE_INCOMPAT_ASYNC_COMMIT
        | JBD2_FEATURE_INCOMPAT_CSUM_V2
        | JBD2_FEATURE_INCOMPAT_CSUM_V3
        | JBD2_FEATURE_INCOMPAT_FAST_COMMIT;
    features.incompat & !supported
}

fn block_by_journal_index<'a>(
    journal: &'a [u8],
    block_size: usize,
    idx: usize,
) -> Option<&'a [u8]> {
    let off = idx.checked_mul(block_size)?;
    journal.get(off..off + block_size)
}

fn parse_descriptor(block: &[u8], sb: &JournalSuperblock) -> Vec<DescriptorTag> {
    let mut tags = Vec::new();
    let has_64bit = sb.features.incompat & JBD2_FEATURE_INCOMPAT_64BIT != 0;
    let has_csum_v3 = sb.features.incompat & JBD2_FEATURE_INCOMPAT_CSUM_V3 != 0;
    let has_csum_v2 = sb.features.incompat & JBD2_FEATURE_INCOMPAT_CSUM_V2 != 0;

    let tail = if has_csum_v2 || has_csum_v3 { 8 } else { 0 };
    let mut off = 12usize;
    while off + 8 <= block.len().saturating_sub(tail) {
        let lo = match be32(block, off) {
            Some(v) => v,
            None => break,
        };
        let mut tag_off = off + 4;
        let hi = if has_64bit {
            let v = be32(block, tag_off).unwrap_or(0);
            tag_off += 4;
            v
        } else {
            0
        };
        let flags = be16(block, tag_off).unwrap_or(0);
        tag_off += 2;

        if flags & JBD2_FLAG_SAME_UUID == 0 {
            tag_off += 16;
        }
        if has_csum_v3 {
            tag_off += 4;
        } else if has_csum_v2 {
            tag_off += 2;
        }

        if tag_off > block.len() {
            break;
        }

        let fs_block = ((hi as u64) << 32) | lo as u64;
        if flags & JBD2_FLAG_DELETED == 0 {
            tags.push(DescriptorTag {
                fs_block,
                flags,
                escaped: flags & JBD2_FLAG_ESCAPE != 0,
            });
        }
        off = tag_off;
        if flags & JBD2_FLAG_LAST_TAG != 0 {
            break;
        }
    }
    tags
}

fn parse_revoke(block: &[u8], sb: &JournalSuperblock, seq: u32) -> Vec<RevokeRecord> {
    let mut out = Vec::new();
    let has_64bit = sb.features.incompat & JBD2_FEATURE_INCOMPAT_64BIT != 0;
    let rec_len = if has_64bit { 8 } else { 4 };
    let used = be32(block, 12).unwrap_or(block.len() as u32) as usize;
    let end = used.min(block.len());
    let mut off = 16usize;
    while off + rec_len <= end {
        let fs_block = if has_64bit {
            be64(block, off).unwrap_or(0)
        } else {
            be32(block, off).unwrap_or(0) as u64
        };
        out.push(RevokeRecord {
            sequence: seq,
            fs_block,
        });
        off += rec_len;
    }
    out
}

fn is_revoked(revokes: &[RevokeRecord], sequence: u32, fs_block: u64) -> bool {
    revokes
        .iter()
        .any(|r| r.sequence == sequence && r.fs_block == fs_block)
}

fn apply_txn(fs_image: &mut [u8], block_size: usize, txn: &PendingTxn) -> usize {
    let mut replayed = 0usize;
    for (idx, tag) in txn.tags.iter().enumerate() {
        if is_revoked(&txn.revokes, txn.sequence, tag.fs_block) {
            continue;
        }
        let src = match txn.payloads.get(idx) {
            Some(s) => s,
            None => break,
        };
        let dst_off = match (tag.fs_block as usize).checked_mul(block_size) {
            Some(v) => v,
            None => continue,
        };
        let dst = match fs_image.get_mut(dst_off..dst_off + block_size) {
            Some(d) => d,
            None => continue,
        };
        dst.copy_from_slice(src);
        if tag.escaped && dst.len() >= 4 {
            dst[0..4].copy_from_slice(&JBD2_MAGIC.to_be_bytes());
        }
        replayed += 1;
    }
    replayed
}

/// Replay a linear journal byte image into `fs_image`.
///
/// `journal` must begin with a JBD2 superblock.  The caller is responsible for
/// translating ext4's journal inode mapping into this contiguous byte image.
pub fn replay_journal_image(
    fs_image: &mut [u8],
    journal: &[u8],
) -> Result<ReplayReport, ReplayError> {
    let sb_block = journal.get(..1024).ok_or(ReplayError::EmptyJournal)?;
    let sb = parse_superblock(sb_block).ok_or(ReplayError::BadSuperblock)?;
    if sb.block_size == 0 || sb.block_size > 65536 {
        return Err(ReplayError::InvalidBlockSize);
    }
    let unsupported = unsupported_incompat(sb.features);
    if unsupported != 0 {
        return Err(ReplayError::UnsupportedFeature(unsupported));
    }

    let mut report = ReplayReport::default();
    let mut idx = if sb.start == 0 {
        sb.first as usize
    } else {
        sb.start as usize
    };
    if idx == 0 {
        idx = 1;
    }

    let max_len = sb.max_len as usize;
    if max_len == 0
        || max_len
            .checked_mul(sb.block_size)
            .map_or(true, |n| n > journal.len())
    {
        return Err(ReplayError::OutOfBounds);
    }

    let mut current: Option<PendingTxn> = None;
    let mut blocks_scanned = 0usize;
    while blocks_scanned < max_len {
        let block = match block_by_journal_index(journal, sb.block_size, idx) {
            Some(b) => b,
            None => break,
        };
        let (_, ty, seq) = match header(block) {
            Some(h) => h,
            None => {
                if let Some(txn) = current.as_mut() {
                    txn.payloads.push(block.to_vec());
                }
                idx += 1;
                if idx >= max_len {
                    idx = sb.first as usize;
                }
                blocks_scanned += 1;
                continue;
            },
        };

        match ty {
            JBD2_DESCRIPTOR_BLOCK => {
                let tags = parse_descriptor(block, &sb);
                current = Some(PendingTxn {
                    sequence: seq,
                    tags,
                    payloads: Vec::new(),
                    revokes: Vec::new(),
                });
                report.transactions_seen += 1;
            },
            JBD2_REVOKE_BLOCK => {
                let revokes = parse_revoke(block, &sb, seq);
                report.revoke_records += revokes.len();
                if let Some(txn) = current.as_mut() {
                    txn.revokes.extend(revokes);
                }
            },
            JBD2_COMMIT_BLOCK => {
                if let Some(txn) = current.take() {
                    if txn.sequence == seq {
                        let n = apply_txn(fs_image, sb.block_size, &txn);
                        report.blocks_replayed += n;
                        report.transactions_replayed += 1;
                    }
                }
            },
            JBD2_SUPERBLOCK_V1 | JBD2_SUPERBLOCK_V2 => {},
            _ => {
                if ty == JBD2_FEATURE_INCOMPAT_FAST_COMMIT {
                    report.unsupported_fast_commit_blocks += 1;
                }
            },
        }

        idx += 1;
        if idx >= max_len {
            idx = sb.first as usize;
        }
        blocks_scanned += 1;
    }

    Ok(report)
}

/// Build a contiguous journal image from explicit filesystem block numbers and
/// replay it into `fs_image`.
pub fn replay_from_block_list(
    fs_image: &mut [u8],
    fs_block_size: usize,
    journal_blocks: &[u64],
) -> Result<ReplayReport, ReplayError> {
    if fs_block_size == 0 || journal_blocks.is_empty() {
        return Err(ReplayError::EmptyJournal);
    }
    let mut journal = Vec::with_capacity(journal_blocks.len() * fs_block_size);
    for &blk in journal_blocks {
        let off = (blk as usize)
            .checked_mul(fs_block_size)
            .ok_or(ReplayError::OutOfBounds)?;
        let src = fs_image
            .get(off..off + fs_block_size)
            .ok_or(ReplayError::OutOfBounds)?;
        journal.extend_from_slice(src);
    }
    replay_journal_image(fs_image, &journal)
}
