//! An opened container: `.utoc` + its `.ucas` partitions, with streaming chunk reads.

use std::collections::HashMap;
use std::fs::File;
use std::ops::Range;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use sha1::Digest as _;

use crate::compression::{self, DecodeError, Method};
use crate::container_header::ContainerHeaderSummary;
use crate::crypto::AesKey;
use crate::dirindex::DirectoryIndex;
use crate::error::{Error, Result, corrupt};
use crate::profile::{CryptTarget, GameProfile};
use crate::toc::{ChunkMeta, Toc, TocHeader, align16};
use crate::types::{ChunkId, ChunkKind, HashAlgorithm, TocVersion};

/// One `.ucas` file of the container.
#[derive(Debug)]
pub struct Partition {
    pub path: PathBuf,
    file: Option<File>,
    /// File size, `None` if the file is missing.
    pub size: Option<u64>,
}

/// What [`Container`] knows about one TOC entry, without reading its data.
#[derive(Debug, Clone)]
pub struct ChunkInfo {
    pub index: u32,
    pub id: ChunkId,
    pub kind: ChunkKind,
    /// Uncompressed length.
    pub size: u64,
    /// Sum of the compressed sizes of its blocks.
    pub packed_size: u64,
    pub blocks: Range<u32>,
    pub meta: ChunkMeta,
}

impl ChunkInfo {
    pub fn compressed(&self) -> bool {
        self.meta.flags & ChunkMeta::COMPRESSED != 0
    }
    pub fn memory_mapped(&self) -> bool {
        self.meta.flags & ChunkMeta::MEMORY_MAPPED != 0
    }
    pub fn has_hash(&self) -> bool {
        self.meta.hash != [0; 20]
    }
}

/// Result of comparing a fully read chunk with the hash in the TOC.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HashCheck {
    Match,
    Mismatch {
        expected: [u8; 20],
        actual: [u8; 20],
    },
    /// The TOC stores no hash for this chunk (all zero).
    NotStored,
    /// The reader hasn't reached the end of the chunk.
    Incomplete,
}

#[derive(Debug)]
pub struct Container {
    utoc_path: PathBuf,
    toc: Toc,
    profile: Arc<dyn GameProfile>,
    partitions: Vec<Partition>,
    methods: Vec<Method>,
    key: Option<AesKey>,
    directory: Option<DirectoryIndex>,
    lookup: HashMap<ChunkId, u32>,
}

/// `name.ucas`, `name_s1.ucas`, `name_s2.ucas`, ...
pub fn partition_paths(utoc: &Path, count: u32) -> Vec<PathBuf> {
    let stem = utoc.file_stem().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default();
    let dir = utoc.parent().unwrap_or(Path::new(""));
    (0..count.max(1)).map(|i| if i == 0 { dir.join(format!("{stem}.ucas")) } else { dir.join(format!("{stem}_s{i}.ucas")) }).collect()
}

impl Container {
    /// Reads and checks the `.utoc` and opens the `.ucas` partitions that exist. Missing
    /// partitions are reported by [`Container::missing_partitions`] and fail only when read.
    /// The directory index isn't decoded yet (it may need a key).
    pub fn open(utoc: impl AsRef<Path>, profile: Arc<dyn GameProfile>) -> Result<Self> {
        let utoc_path = utoc.as_ref().to_path_buf();
        let mut data = std::fs::read(&utoc_path)?;
        profile.prepare_toc(&mut data)?;
        let toc = Toc::parse(&data, profile.as_ref())?;
        drop(data);

        let partitions = partition_paths(&utoc_path, toc.header.effective_partition_count())
            .into_iter()
            .map(|path| {
                let file = File::open(&path).ok();
                let size = file.as_ref().and_then(|f| f.metadata().ok()).map(|m| m.len());
                Partition { path, file, size }
            })
            .collect();
        let methods = toc.compression_methods.iter().map(|n| profile.compression_method(n)).collect();
        let lookup = toc.chunk_ids.iter().enumerate().map(|(i, id)| (*id, i as u32)).collect();
        Ok(Self {
            utoc_path,
            toc,
            profile,
            partitions,
            methods,
            key: None,
            directory: None,
            lookup,
        })
    }

    pub fn utoc_path(&self) -> &Path {
        &self.utoc_path
    }
    pub fn toc(&self) -> &Toc {
        &self.toc
    }
    pub fn header(&self) -> &TocHeader {
        &self.toc.header
    }
    pub fn version(&self) -> TocVersion {
        self.toc.header.version
    }
    pub fn profile(&self) -> &dyn GameProfile {
        self.profile.as_ref()
    }
    pub fn partitions(&self) -> &[Partition] {
        &self.partitions
    }
    pub fn missing_partitions(&self) -> Vec<&Path> {
        self.partitions.iter().filter(|p| p.file.is_none()).map(|p| p.path.as_path()).collect()
    }
    pub fn compression_methods(&self) -> &[Method] {
        &self.methods
    }
    pub fn chunk_count(&self) -> u32 {
        self.toc.chunk_ids.len() as u32
    }

    /// Container flag `Encrypted`: chunk data and the directory index need a key.
    pub fn is_encrypted(&self) -> bool {
        self.toc.header.flags.encrypted()
    }
    /// The directory index can't be read without a key.
    pub fn index_needs_key(&self) -> bool {
        self.is_encrypted() && !self.toc.directory_index.is_empty()
    }
    pub fn has_key(&self) -> bool {
        self.key.is_some()
    }

    /// Sets the AES key. If the directory index is encrypted, the key is checked by
    /// decrypting and parsing it; a key that doesn't fit gives [`Error::WrongKey`] and is
    /// not kept. Otherwise the key can only be checked by reading data.
    pub fn set_key(&mut self, key: AesKey) -> Result<()> {
        if self.index_needs_key() {
            let idx = self.decode_index(Some(&key)).map_err(|e| match e {
                Error::BadDirectoryIndex(_) => Error::WrongKey,
                e => e,
            })?;
            self.directory = Some(idx);
        }
        self.key = Some(key);
        Ok(())
    }

    fn decode_index(&self, key: Option<&AesKey>) -> Result<DirectoryIndex> {
        let raw = &self.toc.directory_index;
        if raw.is_empty() {
            return Ok(DirectoryIndex::default());
        }
        if self.is_encrypted() {
            let key = key.ok_or(Error::KeyRequired(self.toc.header.key_guid))?;
            if !raw.len().is_multiple_of(16) {
                return Err(corrupt(format!("encrypted directory index size {} isn't a multiple of 16", raw.len())));
            }
            let mut buf = raw.clone();
            self.profile.decrypt(key, &mut buf, CryptTarget::DirectoryIndex);
            DirectoryIndex::parse(&buf)
        } else {
            DirectoryIndex::parse(raw)
        }
    }

    /// The decoded directory index (decoded on first use).
    pub fn directory_index(&mut self) -> Result<&DirectoryIndex> {
        if self.directory.is_none() {
            let idx = self.decode_index(self.key.as_ref())?;
            self.directory = Some(idx);
        }
        Ok(self.directory.as_ref().unwrap())
    }

    /// The directory index if already decoded.
    pub fn loaded_directory_index(&self) -> Option<&DirectoryIndex> {
        self.directory.as_ref()
    }

    pub fn find(&self, id: &ChunkId) -> Option<u32> {
        self.lookup.get(id).copied()
    }

    pub fn chunk(&self, index: u32) -> Result<ChunkInfo> {
        let i = index as usize;
        let id = *self.toc.chunk_ids.get(i).ok_or(Error::NoSuchChunk(index))?;
        let ol = self.toc.offsets[i];
        let blocks = self.toc.chunk_blocks(index);
        let packed_size = self.toc.blocks[blocks.start as usize..blocks.end as usize].iter().map(|b| b.compressed_size as u64).sum();
        Ok(ChunkInfo {
            index,
            id,
            kind: id.kind(self.version()),
            size: ol.length,
            packed_size,
            blocks,
            meta: self.toc.metas[i],
        })
    }

    pub fn chunks(&self) -> impl Iterator<Item = ChunkInfo> + '_ {
        (0..self.chunk_count()).map(|i| self.chunk(i).unwrap())
    }

    /// Distinct compression method names used by a chunk's blocks ("None" for stored ones).
    pub fn chunk_methods(&self, info: &ChunkInfo) -> Vec<&str> {
        let mut out: Vec<&str> = Vec::new();
        for b in &self.toc.blocks[info.blocks.start as usize..info.blocks.end as usize] {
            let name = if b.method == 0 { "None" } else { self.toc.compression_methods[b.method as usize - 1].as_str() };
            if !out.contains(&name) {
                out.push(name);
            }
        }
        out
    }

    /// A streaming reader over chunk `index`: one block in memory at a time.
    pub fn open_chunk(&self, index: u32) -> Result<ChunkReader<'_>> {
        let info = self.chunk(index)?;
        if self.toc.header.flags.on_demand() {
            return Err(Error::OnDemand(index));
        }
        if self.is_encrypted() && self.key.is_none() && info.size > 0 {
            return Err(Error::KeyRequired(self.toc.header.key_guid));
        }
        let skip = if info.size == 0 { 0 } else { (self.toc.offsets[index as usize].offset % self.toc.header.block_size as u64) as usize };
        let hasher = match self.version().hash_algorithm() {
            HashAlgorithm::Sha1 => Hasher::Sha1(sha1::Sha1::new()),
            HashAlgorithm::Blake3 => Hasher::Blake3(Box::new(blake3::Hasher::new())),
        };
        Ok(ChunkReader {
            container: self,
            next_block: info.blocks.start,
            end_block: info.blocks.end,
            remaining: info.size,
            info,
            skip,
            raw: Vec::new(),
            out: Vec::new(),
            out_start: 0,
            out_end: 0,
            hasher: Some(hasher),
            digest: None,
        })
    }

    /// Reads a whole chunk into memory (for small chunks: headers, metadata).
    pub fn read_chunk(&self, index: u32) -> Result<Vec<u8>> {
        let mut r = self.open_chunk(index)?;
        let mut v = Vec::with_capacity(r.info().size.min(1 << 24) as usize);
        while let Some(piece) = r.next_piece()? {
            v.extend_from_slice(piece);
        }
        Ok(v)
    }

    /// Parses the container header chunk, if the container has one.
    pub fn container_header(&self) -> Option<Result<ContainerHeaderSummary>> {
        let idx = self.chunks().find(|c| c.kind == ChunkKind::ContainerHeader)?.index;
        Some(self.read_chunk(idx).and_then(|d| ContainerHeaderSummary::parse(&d)))
    }

    /// Has the chunks a global container must have: `ScriptObjects` (UE5) or
    /// `LoaderInitialLoadMeta` + `LoaderGlobalNames` (UE4; checked on 4.27 globals).
    pub fn has_script_objects(&self) -> bool {
        let kinds: Vec<ChunkKind> = self.chunks().map(|c| c.kind).collect();
        kinds.contains(&ChunkKind::ScriptObjects) || (kinds.contains(&ChunkKind::LoaderInitialLoadMeta) && kinds.contains(&ChunkKind::LoaderGlobalNames))
    }

    /// A block's bytes as stored in the `.ucas` (padded to 16, still encrypted if the container
    /// is): what a rebuild copies without recompressing.
    pub fn read_raw_block(&self, block: u32) -> Result<Vec<u8>> {
        let e = *self.toc.blocks.get(block as usize).ok_or_else(|| corrupt(format!("block {block} out of range")))?;
        let psize = self.toc.header.effective_partition_size();
        let (part, poff) = if psize == u64::MAX { (0, e.offset) } else { ((e.offset / psize) as usize, e.offset % psize) };
        let p = self.partitions.get(part).ok_or_else(|| corrupt(format!("block {block} is in partition {part}, but there are {}", self.partitions.len())))?;
        let file = p.file.as_ref().ok_or_else(|| Error::MissingPartition(p.path.clone()))?;
        let mut raw = vec![0u8; align16(e.compressed_size as u64) as usize];
        read_exact_at(file, &mut raw, poff)?;
        Ok(raw)
    }

    /// The key set with [`Container::set_key`].
    pub fn key(&self) -> Option<&AesKey> {
        self.key.as_ref()
    }

    fn decode_block(&self, chunk: u32, block: u32, raw: &mut Vec<u8>, out: &mut Vec<u8>) -> Result<()> {
        let e = self.toc.blocks[block as usize];
        let psize = self.toc.header.effective_partition_size();
        let (part, poff) = if psize == u64::MAX { (0, e.offset) } else { ((e.offset / psize) as usize, e.offset % psize) };
        let p = self.partitions.get(part).ok_or_else(|| corrupt(format!("block {block} is in partition {part}, but there are {}", self.partitions.len())))?;
        let file = p.file.as_ref().ok_or_else(|| Error::MissingPartition(p.path.clone()))?;
        let enc = self.is_encrypted();
        let cs = e.compressed_size as usize;
        let us = e.uncompressed_size as usize;
        let read_len = if enc { align16(cs as u64) as usize } else { cs };
        raw.resize(read_len, 0);
        read_exact_at(file, raw, poff).map_err(|err| {
            if err.kind() == std::io::ErrorKind::UnexpectedEof {
                Error::DecodeFailed {
                    chunk,
                    block,
                    reason: format!("{} ends before the block ({} bytes at {})", p.path.display(), read_len, poff),
                }
            } else {
                Error::Io(err)
            }
        })?;
        if enc {
            let key = self.key.as_ref().ok_or(Error::KeyRequired(self.toc.header.key_guid))?;
            self.profile.decrypt(key, raw, CryptTarget::Block(block));
        }
        out.resize(us, 0);
        if e.method == 0 {
            if cs < us {
                return Err(Error::DecodeFailed {
                    chunk,
                    block,
                    reason: format!("stored block is {cs} bytes, expected {us}"),
                });
            }
            out.copy_from_slice(&raw[..us]);
            return Ok(());
        }
        let method = &self.methods[e.method as usize - 1];
        compression::decompress(method, &raw[..cs], out).map_err(|err| match err {
            DecodeError::OodleUnavailable(m) => Error::OodleUnavailable(m),
            DecodeError::Unknown(n) => Error::UnknownCompression(n),
            DecodeError::Data(m) => {
                let hint = if enc && !self.index_needs_key() { "; the AES key may not match" } else { "" };
                Error::DecodeFailed { chunk, block, reason: format!("{m}{hint}") }
            }
        })
    }
}

enum Hasher {
    Sha1(sha1::Sha1),
    Blake3(Box<blake3::Hasher>),
}

impl Hasher {
    fn update(&mut self, d: &[u8]) {
        match self {
            Hasher::Sha1(h) => h.update(d),
            Hasher::Blake3(h) => {
                h.update(d);
            }
        }
    }
    fn finish(self) -> [u8; 20] {
        match self {
            Hasher::Sha1(h) => h.finalize().into(),
            Hasher::Blake3(h) => h.finalize().as_bytes()[..20].try_into().unwrap(),
        }
    }
}

/// Streams one chunk block by block. Use [`ChunkReader::next_piece`] (typed errors, one
/// decoded block per call) or the [`std::io::Read`] impl.
pub struct ChunkReader<'a> {
    container: &'a Container,
    info: ChunkInfo,
    next_block: u32,
    end_block: u32,
    remaining: u64,
    skip: usize,
    raw: Vec<u8>,
    out: Vec<u8>,
    out_start: usize,
    out_end: usize,
    hasher: Option<Hasher>,
    digest: Option<[u8; 20]>,
}

impl ChunkReader<'_> {
    pub fn info(&self) -> &ChunkInfo {
        &self.info
    }
    /// Bytes not yet returned.
    pub fn remaining(&self) -> u64 {
        self.remaining + (self.out_end - self.out_start) as u64
    }

    /// The next decoded piece (normally one block), or `None` at the end.
    pub fn next_piece(&mut self) -> Result<Option<&[u8]>> {
        if self.out_start == self.out_end && !self.fill()? {
            return Ok(None);
        }
        let (s, e) = (self.out_start, self.out_end);
        self.out_start = e;
        Ok(Some(&self.out[s..e]))
    }

    /// Decodes the next block into `out`; false at the end.
    fn fill(&mut self) -> Result<bool> {
        if self.remaining == 0 {
            if let Some(h) = self.hasher.take() {
                self.digest = Some(h.finish());
            }
            return Ok(false);
        }
        if self.next_block >= self.end_block {
            return Err(corrupt(format!("chunk {} needs more blocks than its range", self.info.index)));
        }
        let b = self.next_block;
        self.container.decode_block(self.info.index, b, &mut self.raw, &mut self.out)?;
        self.next_block += 1;
        let start = std::mem::take(&mut self.skip).min(self.out.len());
        let take = ((self.out.len() - start) as u64).min(self.remaining) as usize;
        if take == 0 {
            return Err(corrupt(format!("block {b} of chunk {} adds no data", self.info.index)));
        }
        self.out_start = start;
        self.out_end = start + take;
        self.remaining -= take as u64;
        if let Some(h) = self.hasher.as_mut() {
            h.update(&self.out[self.out_start..self.out_end]);
        }
        if self.remaining == 0
            && let Some(h) = self.hasher.take()
        {
            self.digest = Some(h.finish());
        }
        Ok(true)
    }

    /// Compares the data read so far with the TOC hash. Meaningful after the last piece.
    pub fn hash_check(&self) -> HashCheck {
        if !self.info.has_hash() {
            return HashCheck::NotStored;
        }
        match self.digest {
            None => HashCheck::Incomplete,
            Some(d) if d == self.info.meta.hash => HashCheck::Match,
            Some(d) => HashCheck::Mismatch { expected: self.info.meta.hash, actual: d },
        }
    }
}

impl std::io::Read for ChunkReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.out_start == self.out_end && !self.fill().map_err(std::io::Error::other)? {
            return Ok(0);
        }
        let n = buf.len().min(self.out_end - self.out_start);
        buf[..n].copy_from_slice(&self.out[self.out_start..self.out_start + n]);
        self.out_start += n;
        Ok(n)
    }
}

#[cfg(unix)]
fn read_exact_at(f: &File, buf: &mut [u8], off: u64) -> std::io::Result<()> {
    std::os::unix::fs::FileExt::read_exact_at(f, buf, off)
}

#[cfg(windows)]
fn read_exact_at(f: &File, mut buf: &mut [u8], mut off: u64) -> std::io::Result<()> {
    use std::os::windows::fs::FileExt;
    while !buf.is_empty() {
        match f.seek_read(buf, off) {
            Ok(0) => return Err(std::io::ErrorKind::UnexpectedEof.into()),
            Ok(n) => {
                buf = &mut buf[n..];
                off += n as u64;
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
}
