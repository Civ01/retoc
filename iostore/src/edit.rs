//! Changing a container in place, or writing a new one.
//!
//! New chunk data is appended to the last partition (a new `_sN` partition when the partition size
//! would be exceeded); the `.utoc` is rewritten last, through a temporary file and a rename. Until
//! then the old `.utoc` stays valid (it never points at the appended bytes), so an interrupted edit
//! leaves a working container plus unused bytes, which [`ContainerEdit::rollback`] or an undo
//! record ([`UndoRecord`]) removes.
//!
//! When chunks are only replaced, chunk order, perfect hash, directory index and container header
//! stay as they are. When chunks are added or removed, the perfect hash (TOC 4+) and the directory
//! index are rebuilt the way `FIoStoreWriter` builds them.

use crate::crypto::AesKey;
use crate::dirindex::{DirectoryIndex, DirectoryIndexWriter, encrypt_directory_index};
use crate::error::{Error, Result};
use crate::perfect_hash;
use crate::profile::{CryptTarget, GameProfile};
use crate::toc::{BlockEntry, ChunkMeta, OffsetLength, TOC_HEADER_SIZE, Toc, TocHeader};
use crate::types::{ChunkId, ContainerFlags, ContainerId, Guid, TocVersion};
use crate::write::{Compressor, EncodedBlock, encode_stream};
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

/// UE's default `MemoryMappingAlignment` (memory-mapped chunks start on it).
pub const MEMORY_MAPPING_ALIGNMENT: u64 = 16 * 1024;
/// `FIoStoreTocResource::CompressionMethodNameLen`.
pub const COMPRESSION_METHOD_NAME_LEN: u32 = 32;

#[derive(Debug, Clone)]
struct Entry {
    id: ChunkId,
    offset: OffsetLength,
    meta: ChunkMeta,
    /// Path relative to the mount point, if the chunk is in the directory index.
    path: Option<String>,
    removed: bool,
}

/// Settings of a container written from scratch.
#[derive(Debug, Clone)]
pub struct NewContainer {
    pub version: TocVersion,
    pub block_size: u32,
    pub container_id: ContainerId,
    /// E.g. `../../../`; files are added with paths relative to it.
    pub mount_point: String,
    /// `None`: one partition.
    pub partition_size: Option<u64>,
    /// Encrypts blocks and the directory index (key GUID stored in the header).
    pub key: Option<(AesKey, Guid)>,
}

/// An open edit. Dropping it without [`finish`](Self::finish) leaves the container as it was
/// apart from appended bytes; call [`rollback`](Self::rollback) to remove those.
pub struct ContainerEdit {
    utoc: PathBuf,
    toc: Toc,
    key: Option<AesKey>,
    entries: Vec<Entry>,
    mount_point: Option<String>,
    chunk_set_changed: bool,
    /// Lengths of the partition files before the edit (`None`: didn't exist).
    original_lengths: Vec<Option<u64>>,
    partition: usize,
    offset: u64,
    file: Option<File>,
    new_container: bool,
    dirty: bool,
}

/// UE's partition file name: `name.ucas`, `name_s1.ucas`, …
pub fn partition_path(utoc: &Path, index: usize) -> PathBuf {
    crate::container::partition_paths(utoc, index as u32 + 1).pop().expect("one path per partition")
}

impl ContainerEdit {
    /// Starts editing an existing container. `key` is needed for encrypted ones (new blocks and
    /// the directory index are encrypted with it).
    pub fn open(utoc: impl AsRef<Path>, profile: &dyn GameProfile, key: Option<AesKey>) -> Result<Self> {
        let utoc = utoc.as_ref().to_path_buf();
        let data = std::fs::read(&utoc)?;
        let toc = Toc::parse(&data, profile)?;
        let encrypted = toc.header.flags.encrypted();
        if encrypted && key.is_none() {
            return Err(Error::KeyRequired(toc.header.key_guid));
        }
        // A key is only used for encrypted containers (blocks of others stay plain).
        let key = if encrypted { key } else { None };
        let mut paths: Vec<Option<String>> = vec![None; toc.chunk_ids.len()];
        let mut mount_point = None;
        if !toc.directory_index.is_empty() {
            let mut raw = toc.directory_index.clone();
            if encrypted {
                profile.decrypt(key.as_ref().unwrap(), &mut raw, CryptTarget::DirectoryIndex);
            }
            let idx = DirectoryIndex::parse(&raw).map_err(|e| if encrypted { Error::WrongKey } else { e })?;
            for f in idx.files {
                if let Some(p) = paths.get_mut(f.toc_index as usize) {
                    *p = Some(f.path);
                }
            }
            mount_point = Some(idx.mount_point);
        }
        let entries = toc.chunk_ids.iter().zip(&toc.offsets).zip(&toc.metas).zip(paths).map(|(((&id, &offset), &meta), path)| Entry { id, offset, meta, path, removed: false }).collect();
        let count = toc.header.effective_partition_count() as usize;
        let original_lengths = (0..count).map(|i| std::fs::metadata(partition_path(&utoc, i)).ok().map(|m| m.len())).collect::<Vec<_>>();
        let partition = count - 1;
        let offset = original_lengths[partition].unwrap_or(0);
        Ok(Self {
            utoc,
            toc,
            key,
            entries,
            mount_point,
            chunk_set_changed: false,
            original_lengths,
            partition,
            offset,
            file: None,
            new_container: false,
            dirty: false,
        })
    }

    /// Starts a new container at `utoc` (its `.ucas` is created on the first chunk; an existing
    /// pair is replaced only on [`finish`](Self::finish)… so write new containers to a fresh path).
    pub fn create(utoc: impl AsRef<Path>, settings: &NewContainer) -> Result<Self> {
        let utoc = utoc.as_ref().to_path_buf();
        let mut raw = [0u8; TOC_HEADER_SIZE as usize];
        raw[..16].copy_from_slice(crate::toc::TOC_MAGIC);
        let mut flags = ContainerFlags::INDEXED;
        let (key, guid) = match &settings.key {
            Some((k, g)) => {
                flags |= ContainerFlags::ENCRYPTED;
                (Some(k.clone()), *g)
            }
            None => (None, Guid([0; 16])),
        };
        let header = TocHeader {
            magic: *crate::toc::TOC_MAGIC,
            version: settings.version,
            header_size: TOC_HEADER_SIZE,
            entry_count: 0,
            block_count: 0,
            block_entry_size: 12,
            compression_method_count: 0,
            compression_method_name_length: COMPRESSION_METHOD_NAME_LEN,
            block_size: settings.block_size,
            directory_index_size: 0,
            partition_count: if settings.version >= TocVersion::PARTITION_SIZE { 1 } else { 0 },
            container_id: settings.container_id,
            key_guid: guid,
            flags: ContainerFlags(flags),
            perfect_hash_seed_count: 0,
            partition_size: if settings.version >= TocVersion::PARTITION_SIZE { settings.partition_size.unwrap_or(u64::MAX) } else { 0 },
            chunks_without_perfect_hash_count: 0,
            raw,
        };
        let toc = Toc {
            header,
            chunk_ids: Vec::new(),
            offsets: Vec::new(),
            perfect_hash_seeds: Vec::new(),
            chunks_without_perfect_hash: Vec::new(),
            blocks: Vec::new(),
            compression_methods: Vec::new(),
            signatures: None,
            directory_index: Vec::new(),
            metas: Vec::new(),
        };
        Ok(Self {
            utoc,
            toc,
            key,
            entries: Vec::new(),
            mount_point: Some(settings.mount_point.clone()),
            chunk_set_changed: true,
            original_lengths: vec![None],
            partition: 0,
            offset: 0,
            file: None,
            new_container: true,
            dirty: true,
        })
    }

    pub fn toc(&self) -> &Toc {
        &self.toc
    }
    pub fn mount_point(&self) -> Option<&str> {
        self.mount_point.as_deref()
    }
    pub fn is_signed(&self) -> bool {
        self.toc.header.flags.signed()
    }
    pub fn is_encrypted(&self) -> bool {
        self.toc.header.flags.encrypted()
    }

    /// Live chunks: (TOC index as opened, chunk id, path).
    pub fn chunks(&self) -> impl Iterator<Item = (usize, ChunkId, Option<&str>)> {
        self.entries.iter().enumerate().filter(|(_, e)| !e.removed).map(|(i, e)| (i, e.id, e.path.as_deref()))
    }

    pub fn find(&self, id: &ChunkId) -> Option<usize> {
        self.entries.iter().position(|e| !e.removed && e.id == *id)
    }

    /// Bytes appended so far (for free-space checks and progress).
    pub fn appended_bytes(&self) -> u64 {
        let mut n = 0;
        for (i, len) in self.original_lengths.iter().enumerate() {
            let now = if i == self.partition { self.offset } else { std::fs::metadata(partition_path(&self.utoc, i)).map(|m| m.len()).unwrap_or(0) };
            n += now.saturating_sub(len.unwrap_or(0));
        }
        n
    }

    fn method_index(&mut self, name: &str) -> Result<u8> {
        if let Some(i) = self.toc.compression_methods.iter().position(|m| m.eq_ignore_ascii_case(name)) {
            return Ok(i as u8 + 1);
        }
        if self.toc.compression_methods.len() >= 255 {
            return Err(Error::Write("too many compression methods".into()));
        }
        if self.toc.header.compression_method_name_length == 0 {
            self.toc.header.compression_method_name_length = COMPRESSION_METHOD_NAME_LEN;
        }
        self.toc.compression_methods.push(name.to_string());
        self.toc.header.flags = ContainerFlags(self.toc.header.flags.0 | ContainerFlags::COMPRESSED);
        Ok(self.toc.compression_methods.len() as u8)
    }

    fn partition_limit(&self) -> u64 {
        self.toc.header.effective_partition_size()
    }

    /// Opens the append position, starting a new partition if `disk_size` doesn't fit.
    fn reserve(&mut self, disk_size: u64, alignment: u64) -> Result<u64> {
        let limit = self.partition_limit();
        let align = |o: u64| if alignment > 1 { o.next_multiple_of(alignment) } else { o.next_multiple_of(16) };
        let mut start = align(self.offset);
        if limit != u64::MAX && start + disk_size > limit {
            if disk_size > limit {
                return Err(Error::Write(format!("a chunk of {disk_size} bytes doesn't fit a partition of {limit} bytes")));
            }
            self.file = None;
            self.partition += 1;
            if self.partition >= self.original_lengths.len() {
                self.original_lengths.push(None);
            }
            self.offset = 0;
            start = 0;
            self.toc.header.partition_count = (self.partition + 1) as u32;
        }
        if self.file.is_none() {
            let path = partition_path(&self.utoc, self.partition);
            let f = OpenOptions::new().create(true).write(true).truncate(false).open(&path)?;
            self.file = Some(f);
        }
        let f = self.file.as_mut().unwrap();
        if start > self.offset {
            f.seek(SeekFrom::Start(self.offset))?;
            f.write_all(&vec![0u8; (start - self.offset) as usize])?;
        }
        f.seek(SeekFrom::Start(start))?;
        self.offset = start;
        Ok(start)
    }

    /// Encodes `len` bytes from `source` and appends them; returns (offset/length, meta) for the
    /// chunk. Blocks are added to the block table.
    fn append(&mut self, source: &mut dyn Read, len: u64, compressor: Option<&Compressor>, memory_mapped: bool, cancel: &mut dyn FnMut(u64) -> bool) -> Result<(OffsetLength, ChunkMeta)> {
        self.dirty = true;
        let block_size = self.toc.header.block_size;
        let first_block = self.toc.blocks.len() as u64;
        // Memory-mapped chunks are stored uncompressed and aligned (UE: bIsMemoryMapped).
        let compressor = if memory_mapped { None } else { compressor.copied() };
        let method = match &compressor {
            Some(c) => self.method_index(c.toc_name())?,
            None => 0,
        };
        let key = self.key.clone();
        let algorithm = self.toc.header.version.hash_algorithm();
        let alignment = if memory_mapped { MEMORY_MAPPING_ALIGNMENT } else { 16 };
        // UE never splits a chunk over partitions: with a partition limit the chunk is encoded in
        // full first and placed where it fits; without one it is streamed.
        let limited = self.partition_limit() != u64::MAX;
        let mut any_compressed = false;
        let mut first = true;
        let mut buffered: Vec<EncodedBlock> = Vec::new();
        let hash = {
            let this = &mut *self;
            let mut sink = |b: EncodedBlock| -> Result<()> {
                any_compressed |= b.compressed;
                if limited {
                    buffered.push(b);
                    return Ok(());
                }
                if first {
                    this.reserve(b.disk.len() as u64, alignment)?;
                    first = false;
                }
                this.write_block(&b, method)
            };
            encode_stream(source, len, block_size, compressor.as_ref(), key.as_ref(), algorithm, &mut sink, cancel)?
        };
        if limited && !buffered.is_empty() {
            let total = buffered.iter().map(|b| b.disk.len() as u64).sum();
            self.reserve(total, alignment)?;
            for b in &buffered {
                self.write_block(b, method)?;
            }
        }
        let mut flags = 0;
        if any_compressed {
            flags |= ChunkMeta::COMPRESSED;
        }
        if memory_mapped {
            flags |= ChunkMeta::MEMORY_MAPPED;
        }
        let offset = OffsetLength { offset: first_block * block_size as u64, length: len };
        Ok((offset, ChunkMeta { hash, flags, rest: [0; 12] }))
    }

    fn write_block(&mut self, b: &EncodedBlock, method: u8) -> Result<()> {
        let global = self.global_offset();
        self.file.as_mut().expect("reserve opened the partition").write_all(&b.disk)?;
        self.offset += b.disk.len() as u64;
        self.toc.blocks.push(BlockEntry {
            offset: global,
            compressed_size: b.compressed_size,
            uncompressed_size: b.uncompressed_size,
            method: if b.compressed { method } else { 0 },
        });
        Ok(())
    }

    fn global_offset(&self) -> u64 {
        let limit = self.partition_limit();
        if limit == u64::MAX { self.offset } else { self.partition as u64 * limit + self.offset }
    }

    /// Replaces the data of chunk `index` (as opened). Its id, path and memory-mapped flag stay.
    pub fn replace(&mut self, index: usize, source: &mut dyn Read, len: u64, compressor: Option<&Compressor>, cancel: &mut dyn FnMut(u64) -> bool) -> Result<()> {
        let e = self.entries.get(index).filter(|e| !e.removed).ok_or(Error::NoSuchChunk(index as u32))?;
        let mm = e.meta.flags & ChunkMeta::MEMORY_MAPPED != 0;
        let (offset, meta) = self.append(source, len, compressor, mm, cancel)?;
        let e = &mut self.entries[index];
        e.offset = offset;
        e.meta = meta;
        Ok(())
    }

    /// Adds a chunk (path relative to the mount point, or `None` for unnamed chunks). Returns its
    /// index in the edit's numbering (final TOC order is decided by [`finish`](Self::finish)).
    #[allow(clippy::too_many_arguments)]
    pub fn add(&mut self, id: ChunkId, path: Option<String>, source: &mut dyn Read, len: u64, compressor: Option<&Compressor>, memory_mapped: bool, cancel: &mut dyn FnMut(u64) -> bool) -> Result<usize> {
        if self.find(&id).is_some() {
            return Err(Error::Write(format!("chunk {} is already in the container", id.hex())));
        }
        if path.is_some() && self.mount_point.is_none() {
            return Err(Error::Write("the container has no directory index; it can't take named files".into()));
        }
        let (offset, meta) = self.append(source, len, compressor, memory_mapped, cancel)?;
        self.entries.push(Entry { id, offset, meta, path, removed: false });
        self.chunk_set_changed = true;
        Ok(self.entries.len() - 1)
    }

    /// Adds a chunk by copying raw blocks (as stored, already padded/encrypted with this edit's
    /// key) — used for rebuilds. `blocks` gives each block's bytes and its TOC entry.
    pub fn add_raw(&mut self, id: ChunkId, path: Option<String>, len: u64, meta: ChunkMeta, blocks: &mut dyn Iterator<Item = Result<(Vec<u8>, BlockEntry, Option<String>)>>) -> Result<usize> {
        self.dirty = true;
        let block_size = self.toc.header.block_size;
        let first_block = self.toc.blocks.len() as u64;
        let mm = meta.flags & ChunkMeta::MEMORY_MAPPED != 0;
        let mut first = true;
        for b in blocks {
            let (disk, entry, method_name) = b?;
            if first {
                self.reserve(disk.len() as u64, if mm { MEMORY_MAPPING_ALIGNMENT } else { 16 })?;
                first = false;
            }
            let method = match method_name {
                Some(n) => self.method_index(&n)?,
                None => 0,
            };
            let global = self.global_offset();
            self.file.as_mut().unwrap().write_all(&disk)?;
            self.offset += disk.len() as u64;
            self.toc.blocks.push(BlockEntry { offset: global, method, ..entry });
        }
        self.entries.push(Entry {
            id,
            offset: OffsetLength { offset: first_block * block_size as u64, length: len },
            meta,
            path,
            removed: false,
        });
        self.chunk_set_changed = true;
        Ok(self.entries.len() - 1)
    }

    /// Removes chunk `index` (as opened) from the TOC and the directory index. Its bytes stay in
    /// the `.ucas` until a rebuild.
    pub fn remove(&mut self, index: usize) -> Result<()> {
        let e = self.entries.get_mut(index).filter(|e| !e.removed).ok_or(Error::NoSuchChunk(index as u32))?;
        e.removed = true;
        self.chunk_set_changed = true;
        self.dirty = true;
        Ok(())
    }

    /// Changes the mount point; every named chunk's path is re-expressed relative to it (each must
    /// lie under it). Rebuilds the directory index on finish.
    pub fn set_mount_point(&mut self, mount: &str) -> Result<()> {
        let old = self.mount_point.clone().ok_or_else(|| Error::Write("the container has no directory index".into()))?;
        if old == mount {
            return Ok(());
        }
        let mut new_paths = Vec::with_capacity(self.entries.len());
        for e in &self.entries {
            new_paths.push(match &e.path {
                Some(p) => {
                    let full = format!("{old}{p}");
                    let rel = strip_prefix_ignore_case(&full, mount).ok_or_else(|| Error::Write(format!("{full} is not under the mount point {mount}")))?;
                    Some(rel.to_string())
                }
                None => None,
            });
        }
        for (e, p) in self.entries.iter_mut().zip(new_paths) {
            e.path = p;
        }
        self.mount_point = Some(mount.to_string());
        self.chunk_set_changed = true;
        self.dirty = true;
        Ok(())
    }

    /// The new `.utoc` bytes (nothing is written).
    pub fn build_toc(&self) -> Result<Vec<u8>> {
        let mut toc = self.toc.clone();
        // Any change invalidates a signature: written unsigned (the caller asked the user).
        if toc.header.flags.signed() {
            toc.header.flags = ContainerFlags(toc.header.flags.0 & !ContainerFlags::SIGNED);
            toc.signatures = None;
        }
        let live: Vec<&Entry> = self.entries.iter().filter(|e| !e.removed).collect();
        let order: Vec<usize> = if self.chunk_set_changed && toc.header.version >= TocVersion::PERFECT_HASH {
            let ids: Vec<ChunkId> = live.iter().map(|e| e.id).collect();
            let ph = perfect_hash::generate(&ids);
            if toc.header.version < TocVersion::PERFECT_HASH_WITH_OVERFLOW && !ph.overflow.is_empty() {
                return Err(Error::Write("no perfect hash found and TOC version 4 has no overflow list".into()));
            }
            toc.perfect_hash_seeds = ph.seeds;
            toc.chunks_without_perfect_hash = ph.overflow;
            ph.order.iter().map(|&i| i as usize).collect()
        } else {
            (0..live.len()).collect()
        };
        toc.chunk_ids = order.iter().map(|&i| live[i].id).collect();
        toc.offsets = order.iter().map(|&i| live[i].offset).collect();
        toc.metas = order.iter().map(|&i| live[i].meta).collect();
        if self.chunk_set_changed
            && let Some(mount) = &self.mount_point
        {
            let mut w = DirectoryIndexWriter::new(mount.clone());
            for (slot, &i) in order.iter().enumerate() {
                if let Some(p) = &live[i].path {
                    w.add_file(p, slot as u32);
                }
            }
            let mut data = w.serialize();
            if let Some(key) = &self.key
                && toc.header.flags.encrypted()
            {
                data = encrypt_directory_index(data, key);
            }
            toc.directory_index = data;
        }
        if toc.header.version >= TocVersion::PARTITION_SIZE {
            toc.header.partition_count = toc.header.partition_count.max(self.partition as u32 + 1);
        }
        Ok(toc.serialize())
    }

    /// Writes the new `.utoc` (temporary file, then rename). Partitions are flushed first.
    pub fn finish(mut self) -> Result<PathBuf> {
        let data = self.build_toc()?;
        if let Some(f) = self.file.take() {
            f.sync_all()?;
        }
        if self.new_container && self.toc.blocks.is_empty() {
            // No chunk: still create the (empty) partition so the pair exists.
            File::create(partition_path(&self.utoc, 0))?;
        }
        let tmp = self.utoc.with_extension("utoc.uetoc-tmp");
        {
            let mut f = File::create(&tmp)?;
            f.write_all(&data)?;
            f.sync_all()?;
        }
        std::fs::rename(&tmp, &self.utoc)?;
        Ok(self.utoc.clone())
    }

    /// Removes everything appended (truncates partitions to their old length, deletes new ones).
    pub fn rollback(mut self) -> Result<()> {
        self.file = None;
        truncate_partitions(&self.utoc, &self.original_lengths)
    }

    /// Record to restore the container if this edit is interrupted (save it before writing).
    pub fn undo_record(&self) -> Result<UndoRecord> {
        let utoc = if self.new_container { None } else { Some(std::fs::read(&self.utoc)?) };
        Ok(UndoRecord { utoc, partition_lengths: self.original_lengths.clone() })
    }
}

fn truncate_partitions(utoc: &Path, lengths: &[Option<u64>]) -> Result<()> {
    for (i, len) in lengths.iter().enumerate() {
        let p = partition_path(utoc, i);
        match len {
            Some(l) => {
                if std::fs::metadata(&p).is_ok_and(|m| m.len() > *l) {
                    OpenOptions::new().write(true).open(&p)?.set_len(*l)?;
                }
            }
            None => {
                let _ = std::fs::remove_file(&p);
            }
        }
    }
    // Partitions created beyond the record (none expected) are left alone.
    Ok(())
}

/// Old `.utoc` (or none, for a new container) and old partition lengths.
#[derive(Debug, Clone, PartialEq)]
pub struct UndoRecord {
    pub utoc: Option<Vec<u8>>,
    pub partition_lengths: Vec<Option<u64>>,
}

const UNDO_MAGIC: &[u8; 10] = b"UETOCUNDO1";

impl UndoRecord {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = UNDO_MAGIC.to_vec();
        match &self.utoc {
            Some(u) => {
                out.push(1);
                out.extend((u.len() as u64).to_le_bytes());
                out.extend(u);
            }
            None => out.push(0),
        }
        out.extend((self.partition_lengths.len() as u32).to_le_bytes());
        for l in &self.partition_lengths {
            out.extend(l.map_or(u64::MAX, |l| l).to_le_bytes());
        }
        out
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        let bad = || Error::Write("damaged undo file".into());
        let rest = data.strip_prefix(UNDO_MAGIC.as_slice()).ok_or_else(bad)?;
        let (&has, mut rest) = rest.split_first().ok_or_else(bad)?;
        let take = |r: &mut &[u8], n: usize| -> Result<Vec<u8>> {
            if r.len() < n {
                return Err(Error::Write("damaged undo file".into()));
            }
            let (a, b) = r.split_at(n);
            *r = b;
            Ok(a.to_vec())
        };
        let utoc = if has == 1 {
            let n = u64::from_le_bytes(take(&mut rest, 8)?.try_into().unwrap()) as usize;
            Some(take(&mut rest, n)?)
        } else {
            None
        };
        let count = u32::from_le_bytes(take(&mut rest, 4)?.try_into().unwrap()) as usize;
        if count > 4096 {
            return Err(bad());
        }
        let mut partition_lengths = Vec::with_capacity(count);
        for _ in 0..count {
            let v = u64::from_le_bytes(take(&mut rest, 8)?.try_into().unwrap());
            partition_lengths.push((v != u64::MAX).then_some(v));
        }
        Ok(Self { utoc, partition_lengths })
    }

    /// Puts the container back: old `.utoc` (or removes it for a new container) and old
    /// partition lengths.
    pub fn restore(&self, utoc: &Path) -> Result<()> {
        truncate_partitions(utoc, &self.partition_lengths)?;
        match &self.utoc {
            Some(bytes) => {
                let tmp = utoc.with_extension("utoc.uetoc-tmp");
                std::fs::write(&tmp, bytes)?;
                std::fs::rename(&tmp, utoc)?;
            }
            None => {
                let _ = std::fs::remove_file(utoc);
            }
        }
        Ok(())
    }
}

/// `s` without `prefix` (ASCII case-insensitive, as UE compares paths).
pub fn strip_prefix_ignore_case<'a>(s: &'a str, prefix: &str) -> Option<&'a str> {
    (s.len() >= prefix.len() && s.is_char_boundary(prefix.len()) && s[..prefix.len()].eq_ignore_ascii_case(prefix)).then(|| &s[prefix.len()..])
}
