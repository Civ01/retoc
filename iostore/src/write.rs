//! Chunk encoding as `FIoStoreWriter` does it (IoStoreWriter.cpp): fixed-size blocks, each
//! compressed if that makes it smaller (else stored), padded to 16 bytes by repeating its own
//! start, then AES-256-ECB when the container is encrypted. The TOC keeps the unpadded size.

use crate::crypto::AesKey;
use crate::error::{Error, Result};
use crate::types::HashAlgorithm;
use sha1::Digest;
use std::io::{Read, Write};

/// Compression for new blocks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Compressor {
    /// flate2 level 0–9.
    Zlib(u32),
    Gzip(u32),
    Lz4,
    Oodle(OodleCompressor, OodleLevel),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OodleCompressor {
    Kraken,
    Mermaid,
    Selkie,
    Leviathan,
}

/// Oodle levels as UE names them (`ECompressionLevel`, -4 … 9 in UE; the negative "hyper" levels
/// aren't offered).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OodleLevel {
    SuperFast,
    VeryFast,
    Fast,
    Normal,
    Optimal1,
    Optimal2,
    Optimal3,
    Optimal4,
    Optimal5,
}

impl Compressor {
    /// The method name UE writes into the TOC.
    pub fn toc_name(&self) -> &'static str {
        match self {
            Self::Zlib(_) => "Zlib",
            Self::Gzip(_) => "gzip",
            Self::Lz4 => "LZ4",
            Self::Oodle(..) => "Oodle",
        }
    }

    /// Compressed form of `block`, or `None` if it isn't smaller (stored instead, as UE).
    pub fn compress(&self, block: &[u8]) -> Result<Option<Vec<u8>>> {
        let io = |e: std::io::Error| Error::Compress(e.to_string());
        let out = match *self {
            Self::Zlib(level) => {
                let mut e = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::new(level.min(9)));
                e.write_all(block).map_err(io)?;
                e.finish().map_err(io)?
            }
            Self::Gzip(level) => {
                let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::new(level.min(9)));
                e.write_all(block).map_err(io)?;
                e.finish().map_err(io)?
            }
            Self::Lz4 => lz4_flex::block::compress(block),
            Self::Oodle(c, l) => {
                use oodle_loader::{CompressionLevel as L, Compressor as C};
                let oodle = oodle_loader::oodle().map_err(|e| Error::Compress(format!("Oodle: {e}")))?;
                let c = match c {
                    OodleCompressor::Kraken => C::Kraken,
                    OodleCompressor::Mermaid => C::Mermaid,
                    OodleCompressor::Selkie => C::Selkie,
                    OodleCompressor::Leviathan => C::Leviathan,
                };
                let l = match l {
                    OodleLevel::SuperFast => L::SuperFast,
                    OodleLevel::VeryFast => L::VeryFast,
                    OodleLevel::Fast => L::Fast,
                    OodleLevel::Normal => L::Normal,
                    OodleLevel::Optimal1 => L::Optimal1,
                    OodleLevel::Optimal2 => L::Optimal2,
                    OodleLevel::Optimal3 => L::Optimal3,
                    OodleLevel::Optimal4 => L::Optimal4,
                    OodleLevel::Optimal5 => L::Optimal5,
                };
                oodle.compress(block, c, l).map_err(|e| Error::Compress(format!("Oodle: {e}")))?
            }
        };
        Ok((!out.is_empty() && out.len() < block.len()).then_some(out))
    }
}

/// One encoded block: `disk` is what goes into the `.ucas` (padded, maybe encrypted).
#[derive(Debug, Clone)]
pub struct EncodedBlock {
    pub disk: Vec<u8>,
    pub compressed_size: u32,
    pub uncompressed_size: u32,
    /// True if compressed with the chunk's compressor; false if stored.
    pub compressed: bool,
}

/// UE's block padding: up to a multiple of 16, repeating the block's own first bytes.
pub fn pad_block(data: &mut Vec<u8>) {
    let len = data.len();
    if len == 0 || len.is_multiple_of(16) {
        return;
    }
    for i in len..len.next_multiple_of(16) {
        data.push(data[(i - len) % len]);
    }
}

/// Encodes one block of uncompressed data.
pub fn encode_block(block: &[u8], compressor: Option<&Compressor>, key: Option<&AesKey>) -> Result<EncodedBlock> {
    let compressed = match compressor {
        Some(c) => c.compress(block)?,
        None => None,
    };
    let is_compressed = compressed.is_some();
    let mut disk = compressed.unwrap_or_else(|| block.to_vec());
    let compressed_size = disk.len() as u32;
    pad_block(&mut disk);
    if let Some(key) = key {
        key.encrypt_ecb(&mut disk);
    }
    Ok(EncodedBlock {
        disk,
        compressed_size,
        uncompressed_size: block.len() as u32,
        compressed: is_compressed,
    })
}

/// Running chunk hash: SHA-1 (TOC ≤ 3) or BLAKE3 truncated to 20 bytes.
pub enum ChunkHasher {
    Sha1(sha1::Sha1),
    Blake3(Box<blake3::Hasher>),
}

impl ChunkHasher {
    pub fn new(algorithm: HashAlgorithm) -> Self {
        match algorithm {
            HashAlgorithm::Sha1 => Self::Sha1(sha1::Sha1::new()),
            HashAlgorithm::Blake3 => Self::Blake3(Box::new(blake3::Hasher::new())),
        }
    }
    pub fn update(&mut self, data: &[u8]) {
        match self {
            Self::Sha1(h) => h.update(data),
            Self::Blake3(h) => {
                h.update(data);
            }
        }
    }
    pub fn finish(self) -> [u8; 20] {
        let mut out = [0u8; 20];
        match self {
            Self::Sha1(h) => out.copy_from_slice(&h.finalize()),
            Self::Blake3(h) => out.copy_from_slice(&h.finalize().as_bytes()[..20]),
        }
        out
    }
}

/// Reads `len` bytes from `source` block by block, encodes each and hands it to `sink` (in
/// order). Returns the chunk hash. `cancel` is asked between blocks with the bytes done so far.
#[allow(clippy::too_many_arguments)]
pub fn encode_stream(source: &mut dyn Read, len: u64, block_size: u32, compressor: Option<&Compressor>, key: Option<&AesKey>, algorithm: HashAlgorithm, sink: &mut dyn FnMut(EncodedBlock) -> Result<()>, cancel: &mut dyn FnMut(u64) -> bool) -> Result<[u8; 20]> {
    let mut hasher = ChunkHasher::new(algorithm);
    let mut buf = vec![0u8; block_size as usize];
    let mut done = 0u64;
    while done < len {
        let n = (len - done).min(block_size as u64) as usize;
        source.read_exact(&mut buf[..n])?;
        hasher.update(&buf[..n]);
        sink(encode_block(&buf[..n], compressor, key)?)?;
        done += n as u64;
        if cancel(done) {
            return Err(Error::Cancelled);
        }
    }
    Ok(hasher.finish())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compression::{Method, decompress};

    #[test]
    fn padding_repeats_the_block_start() {
        let mut b = vec![1, 2, 3];
        pad_block(&mut b);
        assert_eq!(b.len(), 16);
        assert_eq!(&b[3..9], &[1, 2, 3, 1, 2, 3]);
        let mut full = vec![7; 32];
        pad_block(&mut full);
        assert_eq!(full.len(), 32);
    }

    #[test]
    fn blocks_round_trip_through_the_reader() {
        let data: Vec<u8> = (0..65536u32).map(|i| (i % 251) as u8 ^ (i / 1000) as u8).collect();
        for c in [Compressor::Zlib(6), Compressor::Gzip(6), Compressor::Lz4] {
            let b = encode_block(&data, Some(&c), None).unwrap();
            assert!(b.compressed && b.disk.len().is_multiple_of(16));
            let mut out = vec![0u8; data.len()];
            decompress(&Method::from_name(c.toc_name()), &b.disk[..b.compressed_size as usize], &mut out).unwrap();
            assert_eq!(out, data);
        }
        // Incompressible data is stored.
        let mut x = 0x2545_F491_4F6C_DD1Du64;
        let noise: Vec<u8> = (0..4096)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                (x >> 32) as u8
            })
            .collect();
        let b = encode_block(&noise, Some(&Compressor::Zlib(9)), None).unwrap();
        assert!(!b.compressed);
        assert_eq!(&b.disk[..noise.len()], &noise[..]);
        // Encrypted blocks decrypt back.
        let key = AesKey::new([5; 32]);
        let mut b = encode_block(&data[..100], None, Some(&key)).unwrap();
        assert_eq!(b.compressed_size, 100);
        key.decrypt_ecb(&mut b.disk);
        assert_eq!(&b.disk[..100], &data[..100]);
    }
}
