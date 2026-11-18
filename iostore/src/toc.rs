//! `.utoc` parsing (`FIoStoreTocResource`), bounds-checked: a damaged or foreign file is an
//! error, never a panic or a huge allocation.

use crate::error::{Error, Result, corrupt};
use crate::profile::GameProfile;
use crate::types::{ChunkId, ContainerFlags, ContainerId, Guid, TocVersion};

pub const TOC_MAGIC: &[u8; 16] = b"-==--==--==--==-";
pub const TOC_HEADER_SIZE: u32 = 0x90;
const BLOCK_ENTRY_SIZE: u32 = 12;
/// Far above anything real (consoles use a handful).
const MAX_PARTITIONS: u32 = 4096;

/// `FIoStoreTocHeader`, all fields as stored.
#[derive(Debug, Clone)]
pub struct TocHeader {
    pub magic: [u8; 16],
    pub version: TocVersion,
    pub header_size: u32,
    pub entry_count: u32,
    pub block_count: u32,
    pub block_entry_size: u32,
    pub compression_method_count: u32,
    pub compression_method_name_length: u32,
    pub block_size: u32,
    pub directory_index_size: u32,
    /// As stored (0 before `PartitionSize`).
    pub partition_count: u32,
    pub container_id: ContainerId,
    pub key_guid: Guid,
    pub flags: ContainerFlags,
    pub perfect_hash_seed_count: u32,
    /// As stored (0 before `PartitionSize`).
    pub partition_size: u64,
    pub chunks_without_perfect_hash_count: u32,
}

impl TocHeader {
    /// Partitions in use: at least 1.
    pub fn effective_partition_count(&self) -> u32 {
        if self.version < TocVersion::PARTITION_SIZE { 1 } else { self.partition_count.max(1) }
    }
    /// Bytes per partition file; `u64::MAX` when the container isn't split.
    pub fn effective_partition_size(&self) -> u64 {
        if self.version < TocVersion::PARTITION_SIZE || self.partition_size == 0 { u64::MAX } else { self.partition_size }
    }
}

/// `FIoOffsetAndLength`: position in the container's uncompressed address space.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OffsetLength {
    pub offset: u64,
    pub length: u64,
}

/// `FIoStoreTocCompressedBlockEntry`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlockEntry {
    /// Offset over all partitions (partition = offset / partition size).
    pub offset: u64,
    pub compressed_size: u32,
    pub uncompressed_size: u32,
    /// 0 = stored, else 1-based index into the compression method names.
    pub method: u8,
}

/// `FIoStoreTocEntryMeta`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChunkMeta {
    /// Hash of the uncompressed chunk. Only the first 20 bytes are meaningful.
    pub hash: [u8; 20],
    pub flags: u8,
}

impl ChunkMeta {
    pub const COMPRESSED: u8 = 1 << 0;
    pub const MEMORY_MAPPED: u8 = 1 << 1;
}

/// Signature section of signed containers (not verified: needs the game's public key).
#[derive(Debug, Clone)]
pub struct Signatures {
    pub hash_size: u32,
    pub toc_signature: Vec<u8>,
    pub block_signature: Vec<u8>,
    pub block_hashes: Vec<[u8; 20]>,
}

/// A parsed `.utoc`. The directory index is kept as stored (possibly encrypted).
#[derive(Debug, Clone)]
pub struct Toc {
    pub header: TocHeader,
    pub chunk_ids: Vec<ChunkId>,
    pub offsets: Vec<OffsetLength>,
    pub perfect_hash_seeds: Vec<i32>,
    pub chunks_without_perfect_hash: Vec<i32>,
    pub blocks: Vec<BlockEntry>,
    pub compression_methods: Vec<String>,
    pub signatures: Option<Signatures>,
    pub directory_index: Vec<u8>,
    pub metas: Vec<ChunkMeta>,
}

struct Cursor<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn take(&mut self, n: usize, what: &str) -> Result<&'a [u8]> {
        let end = self
            .pos
            .checked_add(n)
            .filter(|&e| e <= self.data.len())
            .ok_or_else(|| corrupt(format!("file ends inside the {what} ({} bytes needed at offset {}, file has {})", n, self.pos, self.data.len())))?;
        let s = &self.data[self.pos..end];
        self.pos = end;
        Ok(s)
    }
    /// `count` records of `size` bytes, checked against the remaining length first.
    fn table(&mut self, count: u32, size: usize, what: &str) -> Result<&'a [u8]> {
        let n = (count as usize).checked_mul(size).ok_or_else(|| corrupt(format!("{what}: count {count} too large")))?;
        self.take(n, what)
    }
}

fn u32_at(d: &[u8], o: usize) -> u32 {
    u32::from_le_bytes(d[o..o + 4].try_into().unwrap())
}
fn u64_at(d: &[u8], o: usize) -> u64 {
    u64::from_le_bytes(d[o..o + 8].try_into().unwrap())
}
fn be40(b: &[u8]) -> u64 {
    b.iter().fold(0u64, |a, &x| (a << 8) | x as u64)
}
fn le_n(b: &[u8]) -> u64 {
    b.iter().rev().fold(0u64, |a, &x| (a << 8) | x as u64)
}

impl TocHeader {
    pub fn parse(data: &[u8], profile: &dyn GameProfile) -> Result<Self> {
        if data.len() < 16 || !profile.is_toc_magic(&data[..16]) {
            return Err(Error::UnknownMagic);
        }
        if data.len() < TOC_HEADER_SIZE as usize {
            return Err(corrupt("file is shorter than the TOC header"));
        }
        let version = TocVersion(data[16]);
        if version.0 == 0 {
            return Err(corrupt("TOC version 0 (invalid)"));
        }
        if version > TocVersion::LATEST_SUPPORTED {
            return Err(Error::UnsupportedVersion(version.0));
        }
        let h = TocHeader {
            magic: data[..16].try_into().unwrap(),
            version,
            header_size: u32_at(data, 20),
            entry_count: u32_at(data, 24),
            block_count: u32_at(data, 28),
            block_entry_size: u32_at(data, 32),
            compression_method_count: u32_at(data, 36),
            compression_method_name_length: u32_at(data, 40),
            block_size: u32_at(data, 44),
            directory_index_size: u32_at(data, 48),
            partition_count: u32_at(data, 52),
            container_id: ContainerId(u64_at(data, 56)),
            key_guid: Guid(data[64..80].try_into().unwrap()),
            flags: ContainerFlags(data[80]),
            perfect_hash_seed_count: u32_at(data, 84),
            partition_size: u64_at(data, 88),
            chunks_without_perfect_hash_count: u32_at(data, 96),
        };
        if h.header_size != TOC_HEADER_SIZE {
            return Err(corrupt(format!("TOC header size {:#x}, expected {:#x}", h.header_size, TOC_HEADER_SIZE)));
        }
        if h.block_entry_size != BLOCK_ENTRY_SIZE {
            return Err(corrupt(format!("block entry size {}, expected {BLOCK_ENTRY_SIZE}", h.block_entry_size)));
        }
        if h.block_size == 0 && h.entry_count > 0 {
            return Err(corrupt("compression block size is 0"));
        }
        if h.version >= TocVersion::PARTITION_SIZE && h.partition_count > MAX_PARTITIONS {
            return Err(corrupt(format!("{} partitions", h.partition_count)));
        }
        if h.compression_method_count > 0 && !(1..=256).contains(&h.compression_method_name_length) {
            return Err(corrupt(format!("compression method name length {}", h.compression_method_name_length)));
        }
        Ok(h)
    }
}

impl Toc {
    /// Parses a whole `.utoc` file.
    pub fn parse(data: &[u8], profile: &dyn GameProfile) -> Result<Self> {
        let header = TocHeader::parse(data, profile)?;
        let v = header.version;
        let mut c = Cursor { data, pos: TOC_HEADER_SIZE as usize };

        let ids = c.table(header.entry_count, 12, "chunk id table")?;
        let chunk_ids = ids.chunks_exact(12).map(|b| ChunkId(b.try_into().unwrap())).collect();

        let offs = c.table(header.entry_count, 10, "chunk offset table")?;
        let offsets = offs.chunks_exact(10).map(|b| OffsetLength { offset: be40(&b[0..5]), length: be40(&b[5..10]) }).collect();

        let seed_count = if v >= TocVersion::PERFECT_HASH { header.perfect_hash_seed_count } else { 0 };
        let overflow_count = if v >= TocVersion::PERFECT_HASH_WITH_OVERFLOW { header.chunks_without_perfect_hash_count } else { 0 };
        let i32s = |b: &[u8]| b.chunks_exact(4).map(|x| i32::from_le_bytes(x.try_into().unwrap())).collect::<Vec<_>>();
        let perfect_hash_seeds = i32s(c.table(seed_count, 4, "perfect hash seeds")?);
        let chunks_without_perfect_hash = i32s(c.table(overflow_count, 4, "chunks without perfect hash")?);

        let blk = c.table(header.block_count, 12, "compression block table")?;
        let blocks: Vec<BlockEntry> = blk
            .chunks_exact(12)
            .map(|b| BlockEntry {
                offset: le_n(&b[0..5]),
                compressed_size: le_n(&b[5..8]) as u32,
                uncompressed_size: le_n(&b[8..11]) as u32,
                method: b[11],
            })
            .collect();

        let name_len = header.compression_method_name_length as usize;
        let names = c.table(header.compression_method_count, name_len, "compression method names")?;
        let compression_methods: Vec<String> = names
            .chunks_exact(name_len.max(1))
            .map(|n| {
                let end = n.iter().position(|&b| b == 0).unwrap_or(n.len());
                String::from_utf8_lossy(&n[..end]).into_owned()
            })
            .collect();

        let signatures = if header.flags.signed() {
            let hash_size = u32::from_le_bytes(c.take(4, "signature size")?.try_into().unwrap());
            if hash_size > 4096 {
                return Err(corrupt(format!("signature size {hash_size}")));
            }
            let toc_signature = c.take(hash_size as usize, "TOC signature")?.to_vec();
            let block_signature = c.take(hash_size as usize, "block signature")?.to_vec();
            let hashes = c.table(header.block_count, 20, "block signature hashes")?;
            Some(Signatures {
                hash_size,
                toc_signature,
                block_signature,
                block_hashes: hashes.chunks_exact(20).map(|h| h.try_into().unwrap()).collect(),
            })
        } else {
            None
        };

        let directory_index = if v >= TocVersion::DIRECTORY_INDEX { c.take(header.directory_index_size as usize, "directory index")?.to_vec() } else { Vec::new() };

        let meta_size = if v >= TocVersion::REPLACE_IO_CHUNK_HASH_WITH_IO_HASH { 24 } else { 33 };
        let meta = c.table(header.entry_count, meta_size, "chunk meta table")?;
        let metas = meta
            .chunks_exact(meta_size)
            .map(|m| ChunkMeta {
                hash: m[0..20].try_into().unwrap(),
                flags: if meta_size == 24 { m[20] } else { m[32] },
            })
            .collect();

        let toc = Toc {
            header,
            chunk_ids,
            offsets,
            perfect_hash_seeds,
            chunks_without_perfect_hash,
            blocks,
            compression_methods,
            signatures,
            directory_index,
            metas,
        };
        toc.validate()?;
        Ok(toc)
    }

    fn validate(&self) -> Result<()> {
        let bs = self.header.block_size as u64;
        for (i, ol) in self.offsets.iter().enumerate() {
            if ol.length == 0 {
                continue;
            }
            let last = (ol.offset + ol.length - 1) / bs;
            if last >= self.blocks.len() as u64 {
                return Err(corrupt(format!("chunk {i} ends in block {last}, but there are {} blocks", self.blocks.len())));
            }
        }
        for (i, b) in self.blocks.iter().enumerate() {
            if b.method as usize > self.compression_methods.len() {
                return Err(corrupt(format!("block {i} uses compression method {} of {}", b.method, self.compression_methods.len())));
            }
            let part = b.offset / self.header.effective_partition_size();
            if part >= self.header.effective_partition_count() as u64 {
                return Err(corrupt(format!("block {i} lies in partition {part} of {}", self.header.effective_partition_count())));
            }
            if b.uncompressed_size > self.header.block_size {
                return Err(corrupt(format!("block {i} unpacks to {} bytes, block size is {}", b.uncompressed_size, self.header.block_size)));
            }
        }
        Ok(())
    }

    /// Blocks covering chunk `index` (empty for a zero-length chunk).
    pub fn chunk_blocks(&self, index: u32) -> std::ops::Range<u32> {
        let ol = self.offsets[index as usize];
        if ol.length == 0 {
            return 0..0;
        }
        let bs = self.header.block_size as u64;
        let first = ol.offset / bs;
        let last = (ol.offset + ol.length - 1) / bs;
        first as u32..last as u32 + 1
    }
}

pub(crate) fn align16(n: u64) -> u64 {
    (n + 15) & !15
}
