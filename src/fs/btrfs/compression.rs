//! Btrfs inline compression support.

#![allow(clippy::cognitive_complexity)]

extern crate alloc;

use alloc::{vec, vec::Vec};

const BTRFS_COMPRESS_NONE: u8 = 0;
const BTRFS_COMPRESS_ZLIB: u8 = 1;
const BTRFS_COMPRESS_LZO: u8 = 2;
const BTRFS_COMPRESS_ZSTD: u8 = 3;

const BTRFS_LZO_SECTOR_SIZE: usize = 4096;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DecompressError {
    UnsupportedAlgorithm,
    InvalidHeader,
    UnexpectedEof,
    InvalidHuffmanCode,
    InvalidBackReference,
    OutputOverflow,
}

pub fn decompress(algo: u8, data: &[u8], uncompressed_size: usize) -> Vec<u8> {
    match try_decompress(algo, data, uncompressed_size) {
        Ok(decoded) => decoded,
        Err(_) => vec![0u8; uncompressed_size],
    }
}

pub fn try_decompress(
    algo: u8,
    data: &[u8],
    uncompressed_size: usize,
) -> Result<Vec<u8>, DecompressError> {
    let decoded = match algo {
        BTRFS_COMPRESS_NONE => copy_uncompressed(data, uncompressed_size),
        BTRFS_COMPRESS_ZLIB => zlib::decompress(data, uncompressed_size)?,
        BTRFS_COMPRESS_LZO => lzo::decompress(data, uncompressed_size)?,
        BTRFS_COMPRESS_ZSTD => return Err(DecompressError::UnsupportedAlgorithm),
        _ => return Err(DecompressError::UnsupportedAlgorithm),
    };
    normalize_output(decoded, uncompressed_size)
}

fn copy_uncompressed(data: &[u8], expected: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(expected);
    let n = core::cmp::min(data.len(), expected);
    out.extend_from_slice(&data[..n]);
    out
}

fn normalize_output(mut data: Vec<u8>, expected: usize) -> Result<Vec<u8>, DecompressError> {
    if data.len() > expected {
        data.truncate(expected);
    } else if data.len() < expected {
        data.resize(expected, 0);
    }
    Ok(data)
}

fn push_capped(out: &mut Vec<u8>, byte: u8, expected: usize) -> Result<(), DecompressError> {
    if out.len() >= expected {
        return Err(DecompressError::OutputOverflow);
    }
    out.push(byte);
    Ok(())
}

fn copy_match(
    out: &mut Vec<u8>,
    distance: usize,
    length: usize,
    expected: usize,
) -> Result<(), DecompressError> {
    if distance == 0 || distance > out.len() {
        return Err(DecompressError::InvalidBackReference);
    }

    for _ in 0..length {
        let src = out.len() - distance;
        let byte = out[src];
        push_capped(out, byte, expected)?;
    }
    Ok(())
}

mod zlib {
    use super::{copy_match, push_capped, DecompressError};
    use alloc::{vec, vec::Vec};

    const LENGTH_BASE: [usize; 29] = [
        3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115,
        131, 163, 195, 227, 258,
    ];
    const LENGTH_EXTRA: [u8; 29] = [
        0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0,
    ];
    const DIST_BASE: [usize; 30] = [
        1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537,
        2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577,
    ];
    const DIST_EXTRA: [u8; 30] = [
        0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12,
        13, 13,
    ];

    pub fn decompress(data: &[u8], expected: usize) -> Result<Vec<u8>, DecompressError> {
        if expected == 0 {
            return Ok(Vec::new());
        }

        let payload = if has_zlib_header(data) {
            if data.len() < 6 {
                return Err(DecompressError::InvalidHeader);
            }
            &data[2..data.len() - 4]
        } else {
            data
        };

        inflate(payload, expected)
    }

    fn has_zlib_header(data: &[u8]) -> bool {
        if data.len() < 2 {
            return false;
        }
        let cmf = data[0];
        let flg = data[1];
        let compression_method = cmf & 0x0f;
        let window_log = cmf >> 4;
        let checksum_ok = (((cmf as u16) << 8) | flg as u16) % 31 == 0;
        compression_method == 8 && window_log <= 7 && checksum_ok && (flg & 0x20) == 0
    }

    fn inflate(data: &[u8], expected: usize) -> Result<Vec<u8>, DecompressError> {
        let mut reader = BitReader::new(data);
        let mut out = Vec::with_capacity(expected);

        loop {
            let final_block = reader.read_bit()? != 0;
            let block_type = reader.read_bits(2)? as u8;
            match block_type {
                0 => read_stored_block(&mut reader, &mut out, expected)?,
                1 => {
                    let (litlen, dist) = fixed_tables()?;
                    read_compressed_block(&mut reader, &mut out, expected, &litlen, &dist)?;
                },
                2 => {
                    let (litlen, dist) = dynamic_tables(&mut reader)?;
                    read_compressed_block(&mut reader, &mut out, expected, &litlen, &dist)?;
                },
                _ => return Err(DecompressError::InvalidHeader),
            }

            if final_block {
                break;
            }
        }

        Ok(out)
    }

    fn read_stored_block(
        reader: &mut BitReader<'_>,
        out: &mut Vec<u8>,
        expected: usize,
    ) -> Result<(), DecompressError> {
        reader.align_to_byte();
        let len = reader.read_aligned_u16()? as usize;
        let nlen = reader.read_aligned_u16()?;
        if nlen != !(len as u16) {
            return Err(DecompressError::InvalidHeader);
        }

        for _ in 0..len {
            let byte = reader.read_aligned_byte()?;
            push_capped(out, byte, expected)?;
        }
        Ok(())
    }

    fn read_compressed_block(
        reader: &mut BitReader<'_>,
        out: &mut Vec<u8>,
        expected: usize,
        litlen: &Huffman,
        dist: &Huffman,
    ) -> Result<(), DecompressError> {
        loop {
            let sym = litlen.decode(reader)?;
            match sym {
                0..=255 => push_capped(out, sym as u8, expected)?,
                256 => return Ok(()),
                257..=285 => {
                    let length = length_for_symbol(sym, reader)?;
                    let distance = distance_for_symbol(dist.decode(reader)?, reader)?;
                    copy_match(out, distance, length, expected)?;
                },
                _ => return Err(DecompressError::InvalidHuffmanCode),
            }
        }
    }

    fn length_for_symbol(sym: u16, reader: &mut BitReader<'_>) -> Result<usize, DecompressError> {
        let idx = sym as usize - 257;
        if idx >= LENGTH_BASE.len() {
            return Err(DecompressError::InvalidHuffmanCode);
        }
        Ok(LENGTH_BASE[idx] + reader.read_bits(LENGTH_EXTRA[idx])? as usize)
    }

    fn distance_for_symbol(sym: u16, reader: &mut BitReader<'_>) -> Result<usize, DecompressError> {
        let idx = sym as usize;
        if idx >= DIST_BASE.len() {
            return Err(DecompressError::InvalidHuffmanCode);
        }
        Ok(DIST_BASE[idx] + reader.read_bits(DIST_EXTRA[idx])? as usize)
    }

    fn fixed_tables() -> Result<(Huffman, Huffman), DecompressError> {
        let mut litlen_lengths = vec![0u8; 288];
        for item in litlen_lengths.iter_mut().take(144) {
            *item = 8;
        }
        for item in litlen_lengths.iter_mut().take(256).skip(144) {
            *item = 9;
        }
        for item in litlen_lengths.iter_mut().take(280).skip(256) {
            *item = 7;
        }
        for item in litlen_lengths.iter_mut().take(288).skip(280) {
            *item = 8;
        }

        let dist_lengths = vec![5u8; 32];
        Ok((
            Huffman::from_lengths(&litlen_lengths)?,
            Huffman::from_lengths(&dist_lengths)?,
        ))
    }

    fn dynamic_tables(reader: &mut BitReader<'_>) -> Result<(Huffman, Huffman), DecompressError> {
        let hlit = reader.read_bits(5)? as usize + 257;
        let hdist = reader.read_bits(5)? as usize + 1;
        let hclen = reader.read_bits(4)? as usize + 4;
        let order = [
            16u8, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15,
        ];
        let mut code_lengths = [0u8; 19];

        for idx in order.iter().take(hclen) {
            code_lengths[*idx as usize] = reader.read_bits(3)? as u8;
        }

        let code_tree = Huffman::from_lengths(&code_lengths)?;
        let mut lengths = Vec::with_capacity(hlit + hdist);
        while lengths.len() < hlit + hdist {
            let sym = code_tree.decode(reader)?;
            match sym {
                0..=15 => lengths.push(sym as u8),
                16 => repeat_previous_length(reader, &mut lengths, hlit + hdist)?,
                17 => repeat_zero_length(reader, &mut lengths, 3, hlit + hdist)?,
                18 => repeat_zero_length(reader, &mut lengths, 11, hlit + hdist)?,
                _ => return Err(DecompressError::InvalidHuffmanCode),
            }
        }

        let litlen = Huffman::from_lengths(&lengths[..hlit])?;
        let dist = Huffman::from_lengths(&lengths[hlit..])?;
        Ok((litlen, dist))
    }

    fn repeat_previous_length(
        reader: &mut BitReader<'_>,
        lengths: &mut Vec<u8>,
        total: usize,
    ) -> Result<(), DecompressError> {
        let prev = *lengths.last().ok_or(DecompressError::InvalidHuffmanCode)?;
        let repeat = reader.read_bits(2)? as usize + 3;
        push_repeated_length(lengths, prev, repeat, total)
    }

    fn repeat_zero_length(
        reader: &mut BitReader<'_>,
        lengths: &mut Vec<u8>,
        base: usize,
        total: usize,
    ) -> Result<(), DecompressError> {
        let extra_bits = if base == 3 { 3 } else { 7 };
        let repeat = reader.read_bits(extra_bits)? as usize + base;
        push_repeated_length(lengths, 0, repeat, total)
    }

    fn push_repeated_length(
        lengths: &mut Vec<u8>,
        value: u8,
        repeat: usize,
        total: usize,
    ) -> Result<(), DecompressError> {
        if lengths.len() + repeat > total {
            return Err(DecompressError::InvalidHuffmanCode);
        }
        for _ in 0..repeat {
            lengths.push(value);
        }
        Ok(())
    }

    struct BitReader<'a> {
        data: &'a [u8],
        byte_pos: usize,
        bit_buf: u8,
        bit_left: u8,
    }

    impl<'a> BitReader<'a> {
        fn new(data: &'a [u8]) -> Self {
            Self {
                data,
                byte_pos: 0,
                bit_buf: 0,
                bit_left: 0,
            }
        }

        fn read_bit(&mut self) -> Result<u8, DecompressError> {
            if self.bit_left == 0 {
                self.bit_buf = *self
                    .data
                    .get(self.byte_pos)
                    .ok_or(DecompressError::UnexpectedEof)?;
                self.byte_pos += 1;
                self.bit_left = 8;
            }

            let bit = self.bit_buf & 1;
            self.bit_buf >>= 1;
            self.bit_left -= 1;
            Ok(bit)
        }

        fn read_bits(&mut self, count: u8) -> Result<u32, DecompressError> {
            let mut value = 0u32;
            for bit in 0..count {
                value |= (self.read_bit()? as u32) << bit;
            }
            Ok(value)
        }

        fn align_to_byte(&mut self) {
            self.bit_buf = 0;
            self.bit_left = 0;
        }

        fn read_aligned_byte(&mut self) -> Result<u8, DecompressError> {
            if self.bit_left != 0 {
                return Err(DecompressError::InvalidHeader);
            }
            let byte = *self
                .data
                .get(self.byte_pos)
                .ok_or(DecompressError::UnexpectedEof)?;
            self.byte_pos += 1;
            Ok(byte)
        }

        fn read_aligned_u16(&mut self) -> Result<u16, DecompressError> {
            let lo = self.read_aligned_byte()? as u16;
            let hi = self.read_aligned_byte()? as u16;
            Ok(lo | (hi << 8))
        }
    }

    #[derive(Clone, Copy)]
    struct HuffmanEntry {
        code: u16,
        len: u8,
        sym: u16,
    }

    struct Huffman {
        entries: Vec<HuffmanEntry>,
        max_len: u8,
    }

    fn reverse_bits(mut code: u16, len: u8) -> u16 {
        let mut reversed = 0u16;
        for _ in 0..len {
            reversed = (reversed << 1) | (code & 1);
            code >>= 1;
        }
        reversed
    }

    impl Huffman {
        fn from_lengths(lengths: &[u8]) -> Result<Self, DecompressError> {
            let mut counts = [0u16; 16];
            let mut max_len = 0u8;
            for &len in lengths {
                if len > 15 {
                    return Err(DecompressError::InvalidHuffmanCode);
                }
                if len != 0 {
                    counts[len as usize] += 1;
                    max_len = core::cmp::max(max_len, len);
                }
            }
            if max_len == 0 {
                return Err(DecompressError::InvalidHuffmanCode);
            }

            let mut next_code = [0u16; 16];
            let mut code = 0u16;
            for bits in 1..=15 {
                code = (code + counts[bits - 1]) << 1;
                next_code[bits] = code;
            }

            let mut entries = Vec::new();
            for (sym, &len) in lengths.iter().enumerate() {
                if len == 0 {
                    continue;
                }
                let code = next_code[len as usize];
                next_code[len as usize] += 1;
                entries.push(HuffmanEntry {
                    code: reverse_bits(code, len),
                    len,
                    sym: sym as u16,
                });
            }

            Ok(Self { entries, max_len })
        }

        fn decode(&self, reader: &mut BitReader<'_>) -> Result<u16, DecompressError> {
            let mut code = 0u16;
            for len in 1..=self.max_len {
                code |= (reader.read_bit()? as u16) << (len - 1);
                for entry in &self.entries {
                    if entry.len == len && entry.code == code {
                        return Ok(entry.sym);
                    }
                }
            }
            Err(DecompressError::InvalidHuffmanCode)
        }
    }
}

mod lzo {
    use super::{copy_match, push_capped, DecompressError, BTRFS_LZO_SECTOR_SIZE};
    use alloc::vec::Vec;

    pub fn decompress(data: &[u8], expected: usize) -> Result<Vec<u8>, DecompressError> {
        if expected == 0 {
            return Ok(Vec::new());
        }
        framed_decompress(data, expected).or_else(|_| raw_lzo1x_decompress(data, expected))
    }

    fn framed_decompress(data: &[u8], expected: usize) -> Result<Vec<u8>, DecompressError> {
        if data.len() < 8 {
            return Err(DecompressError::InvalidHeader);
        }

        let total_len = read_le32(data, 0)? as usize;
        if total_len > data.len() || total_len < 8 {
            return Err(DecompressError::InvalidHeader);
        }

        let mut pos = 4;
        let mut out = Vec::with_capacity(expected);
        while pos + 4 <= total_len && out.len() < expected {
            let compressed_len = read_le32(data, pos)? as usize;
            pos += 4;
            if compressed_len == 0 || pos + compressed_len > total_len {
                return Err(DecompressError::InvalidHeader);
            }

            let chunk_expected = core::cmp::min(BTRFS_LZO_SECTOR_SIZE, expected - out.len());
            let chunk = raw_lzo1x_decompress(&data[pos..pos + compressed_len], chunk_expected)?;
            out.extend_from_slice(&chunk);
            pos += compressed_len;
        }
        Ok(out)
    }

    fn raw_lzo1x_decompress(data: &[u8], expected: usize) -> Result<Vec<u8>, DecompressError> {
        let mut input = LzoInput::new(data);
        let mut out = Vec::with_capacity(expected);

        if input.peek()? > 17 {
            let literal_count = input.read()? as usize - 17;
            copy_literals(&mut input, &mut out, literal_count, expected)?;
            if literal_count < 4 {
                return read_match_loop(&mut input, &mut out, expected);
            }
        }

        read_match_loop(&mut input, &mut out, expected)
    }

    fn read_match_loop(
        input: &mut LzoInput<'_>,
        out: &mut Vec<u8>,
        expected: usize,
    ) -> Result<Vec<u8>, DecompressError> {
        loop {
            let mut token = input.read()?;
            if token < 16 {
                let literal_count = lzo_literal_count(input, token)?;
                copy_literals(input, out, literal_count, expected)?;
                token = input.read()?;
                if token < 16 {
                    let distance = m2_distance(input, token, true)?;
                    copy_match(out, distance, 3, expected)?;
                    copy_literals(input, out, (token & 3) as usize, expected)?;
                    continue;
                }
            }

            let tail = read_match(input, out, token, expected)?;
            if out.len() >= expected {
                return Ok(core::mem::take(out));
            }
            copy_literals(input, out, tail, expected)?;
        }
    }

    fn read_match(
        input: &mut LzoInput<'_>,
        out: &mut Vec<u8>,
        token: u8,
        expected: usize,
    ) -> Result<usize, DecompressError> {
        if token >= 64 {
            let distance = m2_distance(input, token, false)?;
            copy_match(out, distance, ((token >> 5) as usize) + 1, expected)?;
            Ok((token & 3) as usize)
        } else if token >= 32 {
            let length = extended_match_len(input, token & 31, 31)? + 2;
            let low = input.read()?;
            let high = input.read()?;
            let distance = 1 + ((low as usize) >> 2) + ((high as usize) << 6);
            copy_match(out, distance, length, expected)?;
            Ok((low & 3) as usize)
        } else if token >= 16 {
            let length = extended_match_len(input, token & 7, 7)? + 2;
            let low = input.read()?;
            let high = input.read()?;
            let distance = 0x4000
                + (((token as usize) & 8) << 11)
                + ((low as usize) >> 2)
                + ((high as usize) << 6);
            if distance == 0x4000 && length == 3 {
                return Ok(0);
            }
            copy_match(out, distance, length, expected)?;
            Ok((low & 3) as usize)
        } else {
            let distance = m2_distance(input, token, true)?;
            copy_match(out, distance, 2, expected)?;
            Ok((token & 3) as usize)
        }
    }

    fn lzo_literal_count(input: &mut LzoInput<'_>, token: u8) -> Result<usize, DecompressError> {
        if token != 0 {
            return Ok(token as usize + 3);
        }

        let mut count = 15usize;
        while input.peek()? == 0 {
            input.read()?;
            count += 255;
        }
        Ok(count + input.read()? as usize + 3)
    }

    fn extended_match_len(
        input: &mut LzoInput<'_>,
        token_len: u8,
        base: usize,
    ) -> Result<usize, DecompressError> {
        if token_len != 0 {
            return Ok(token_len as usize);
        }

        let mut len = base;
        while input.peek()? == 0 {
            input.read()?;
            len += 255;
        }
        Ok(len + input.read()? as usize)
    }

    fn m2_distance(
        input: &mut LzoInput<'_>,
        token: u8,
        include_marker_offset: bool,
    ) -> Result<usize, DecompressError> {
        let marker_offset = if include_marker_offset { 1 + 0x0800 } else { 1 };
        Ok(marker_offset + ((token as usize >> 2) & 7) + ((input.read()? as usize) << 3))
    }

    fn copy_literals(
        input: &mut LzoInput<'_>,
        out: &mut Vec<u8>,
        count: usize,
        expected: usize,
    ) -> Result<(), DecompressError> {
        for _ in 0..count {
            push_capped(out, input.read()?, expected)?;
        }
        Ok(())
    }

    fn read_le32(data: &[u8], pos: usize) -> Result<u32, DecompressError> {
        let bytes = data
            .get(pos..pos + 4)
            .ok_or(DecompressError::UnexpectedEof)?;
        Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    struct LzoInput<'a> {
        data: &'a [u8],
        pos: usize,
    }

    impl<'a> LzoInput<'a> {
        fn new(data: &'a [u8]) -> Self {
            Self { data, pos: 0 }
        }

        fn peek(&self) -> Result<u8, DecompressError> {
            self.data
                .get(self.pos)
                .copied()
                .ok_or(DecompressError::UnexpectedEof)
        }

        fn read(&mut self) -> Result<u8, DecompressError> {
            let byte = self.peek()?;
            self.pos += 1;
            Ok(byte)
        }
    }
}
