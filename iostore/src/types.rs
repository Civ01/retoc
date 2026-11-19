//! Small value types of the IoStore format.

use std::fmt;

/// `EIoStoreTocVersion`. Kept as a number so unknown values never panic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TocVersion(pub u8);

impl TocVersion {
    pub const INITIAL: Self = Self(1);
    pub const DIRECTORY_INDEX: Self = Self(2);
    pub const PARTITION_SIZE: Self = Self(3);
    pub const PERFECT_HASH: Self = Self(4);
    pub const PERFECT_HASH_WITH_OVERFLOW: Self = Self(5);
    pub const ON_DEMAND_META_DATA: Self = Self(6);
    pub const REMOVED_ON_DEMAND_META_DATA: Self = Self(7);
    pub const REPLACE_IO_CHUNK_HASH_WITH_IO_HASH: Self = Self(8);
    /// Newest version this crate reads (UE 5.5 – 5.8).
    pub const LATEST_SUPPORTED: Self = Self(8);

    pub fn name(self) -> &'static str {
        match self.0 {
            0 => "Invalid",
            1 => "Initial",
            2 => "DirectoryIndex",
            3 => "PartitionSize",
            4 => "PerfectHash",
            5 => "PerfectHashWithOverflow",
            6 => "OnDemandMetaData",
            7 => "RemovedOnDemandMetaData",
            8 => "ReplaceIoChunkHashWithIoHash",
            9 => "AddedSourceHashes",
            10 => "ContainerEncryptionMethod",
            _ => "Unknown",
        }
    }

    /// Engine versions known to write this TOC version.
    pub fn engines(self) -> &'static str {
        match self.0 {
            1 => "4.25",
            2 => "4.25 – 4.26",
            3 => "4.27",
            4 => "5.0 previews",
            5 => "5.0 – 5.3",
            6 => "5.4",
            7 => "unreleased",
            8 => "5.5 – 5.8",
            _ => "unknown",
        }
    }

    /// UE5 renumbered `EIoChunkType`; containers from TOC version 5 on use the new numbers.
    pub fn uses_ue5_chunk_types(self) -> bool {
        self.0 >= 5
    }

    /// Chunk hash algorithm: SHA-1 in UE4 containers, BLAKE3 (first 20 bytes) in UE5.
    pub fn hash_algorithm(self) -> HashAlgorithm {
        if self.0 <= 3 { HashAlgorithm::Sha1 } else { HashAlgorithm::Blake3 }
    }
}

impl fmt::Display for TocVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({})", self.0, self.name())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashAlgorithm {
    Sha1,
    Blake3,
}

impl HashAlgorithm {
    pub fn name(self) -> &'static str {
        match self {
            Self::Sha1 => "SHA-1",
            Self::Blake3 => "BLAKE3-160",
        }
    }
}

/// `EIoContainerFlags`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ContainerFlags(pub u8);

impl ContainerFlags {
    pub const COMPRESSED: u8 = 1 << 0;
    pub const ENCRYPTED: u8 = 1 << 1;
    pub const SIGNED: u8 = 1 << 2;
    pub const INDEXED: u8 = 1 << 3;
    pub const ON_DEMAND: u8 = 1 << 4;

    pub fn compressed(self) -> bool {
        self.0 & Self::COMPRESSED != 0
    }
    pub fn encrypted(self) -> bool {
        self.0 & Self::ENCRYPTED != 0
    }
    pub fn signed(self) -> bool {
        self.0 & Self::SIGNED != 0
    }
    pub fn indexed(self) -> bool {
        self.0 & Self::INDEXED != 0
    }
    pub fn on_demand(self) -> bool {
        self.0 & Self::ON_DEMAND != 0
    }
}

impl fmt::Display for ContainerFlags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let names = [(Self::COMPRESSED, "Compressed"), (Self::ENCRYPTED, "Encrypted"), (Self::SIGNED, "Signed"), (Self::INDEXED, "Indexed"), (Self::ON_DEMAND, "OnDemand")];
        let mut first = true;
        for (bit, name) in names {
            if self.0 & bit != 0 {
                if !first {
                    f.write_str(", ")?;
                }
                f.write_str(name)?;
                first = false;
            }
        }
        let unknown = self.0 & !0x1f;
        if unknown != 0 {
            if !first {
                f.write_str(", ")?;
            }
            write!(f, "unknown {unknown:#04x}")?;
            first = false;
        }
        if first {
            f.write_str("none")?;
        }
        Ok(())
    }
}

/// `FIoContainerId`: CityHash64 of the lower-case container name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct ContainerId(pub u64);

impl fmt::Display for ContainerId {
    /// Unsigned decimal, the form used for the plugin's info-file name.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// `FGuid`: four little-endian u32 (A, B, C, D).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Guid(pub [u8; 16]);

impl Guid {
    pub fn is_zero(&self) -> bool {
        self.0 == [0; 16]
    }
    pub fn parts(&self) -> [u32; 4] {
        let p = |i: usize| u32::from_le_bytes(self.0[i * 4..i * 4 + 4].try_into().unwrap());
        [p(0), p(1), p(2), p(3)]
    }
}

impl fmt::Display for Guid {
    /// 32 upper-case hex digits of the 16 bytes in file order (the form tcl-uepak uses in
    /// its keys file, so records look alike in both plugins).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for b in self.0 {
            write!(f, "{b:02X}")?;
        }
        Ok(())
    }
}

/// `FIoChunkId`: 12 bytes, the last byte is the chunk type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ChunkId(pub [u8; 12]);

impl ChunkId {
    pub fn type_code(&self) -> u8 {
        self.0[11]
    }
    pub fn kind(&self, version: TocVersion) -> ChunkKind {
        ChunkKind::from_code(self.type_code(), version)
    }
    /// The 8-byte id (package id for package chunks).
    pub fn id64(&self) -> u64 {
        u64::from_le_bytes(self.0[0..8].try_into().unwrap())
    }
    pub fn hex(&self) -> String {
        self.0.iter().map(|b| format!("{b:02x}")).collect()
    }
    /// `FIoChunkId` from its 24-digit hex form.
    pub fn from_hex(s: &str) -> Option<Self> {
        if s.len() != 24 || !s.is_ascii() {
            return None;
        }
        let mut b = [0u8; 12];
        for (i, x) in b.iter_mut().enumerate() {
            *x = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok()?;
        }
        Some(Self(b))
    }
    /// `CreateIoChunkId(id, index, type)`: 8-byte id, 2-byte index (big endian), 1 byte padding, type.
    pub fn create(id: u64, index: u16, kind: ChunkKind, version: TocVersion) -> Option<Self> {
        let mut b = [0u8; 12];
        b[..8].copy_from_slice(&id.to_le_bytes());
        b[8..10].copy_from_slice(&index.to_be_bytes());
        b[11] = kind.code(version)?;
        Some(Self(b))
    }
}

/// `EIoChunkType` (both numberings).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ChunkKind {
    Invalid,
    ExportBundleData,
    BulkData,
    OptionalBulkData,
    MemoryMappedBulkData,
    ScriptObjects,
    ContainerHeader,
    ExternalFile,
    ShaderCodeLibrary,
    ShaderCode,
    PackageStoreEntry,
    DerivedData,
    EditorDerivedData,
    PackageResource,
    InstallManifest,
    LoaderGlobalMeta,
    LoaderInitialLoadMeta,
    LoaderGlobalNames,
    LoaderGlobalNameHashes,
    Unknown(u8),
}

impl ChunkKind {
    pub fn from_code(code: u8, version: TocVersion) -> Self {
        use ChunkKind::*;
        if version.uses_ue5_chunk_types() {
            match code {
                0 => Invalid,
                1 => ExportBundleData,
                2 => BulkData,
                3 => OptionalBulkData,
                4 => MemoryMappedBulkData,
                5 => ScriptObjects,
                6 => ContainerHeader,
                7 => ExternalFile,
                8 => ShaderCodeLibrary,
                9 => ShaderCode,
                10 => PackageStoreEntry,
                11 => DerivedData,
                12 => EditorDerivedData,
                13 => PackageResource,
                c => Unknown(c),
            }
        } else {
            match code {
                0 => Invalid,
                1 => InstallManifest,
                2 => ExportBundleData,
                3 => BulkData,
                4 => OptionalBulkData,
                5 => MemoryMappedBulkData,
                6 => LoaderGlobalMeta,
                7 => LoaderInitialLoadMeta,
                8 => LoaderGlobalNames,
                9 => LoaderGlobalNameHashes,
                10 => ContainerHeader,
                11 => ShaderCodeLibrary,
                12 => ShaderCode,
                c => Unknown(c),
            }
        }
    }

    /// The type byte for this kind in a container of `version` (`None` if that numbering has no such type).
    pub fn code(self, version: TocVersion) -> Option<u8> {
        (0..=255u8).find(|&c| Self::from_code(c, version) == self && !matches!(self, ChunkKind::Unknown(_)))
    }

    /// Name used in listings, e.g. `<chunkid>.ContainerHeader`.
    pub fn name(&self) -> String {
        match self {
            ChunkKind::Unknown(c) => format!("Type{c}"),
            other => format!("{other:?}"),
        }
    }
}

#[cfg(test)]
mod chunk_id_tests {
    use super::*;

    #[test]
    fn create_and_codes() {
        let v5 = TocVersion(8);
        let v3 = TocVersion(3);
        assert_eq!(ChunkKind::ContainerHeader.code(v5), Some(6));
        assert_eq!(ChunkKind::ContainerHeader.code(v3), Some(10));
        assert_eq!(ChunkKind::ScriptObjects.code(v3), None);
        let id = ChunkId::create(0x1122_3344_5566_7788, 0, ChunkKind::ContainerHeader, v5).unwrap();
        assert_eq!(id.hex(), "887766554433221100000006");
        assert_eq!(ChunkId::from_hex(&id.hex()), Some(id));
        assert_eq!(ChunkId::from_hex("zz"), None);
    }
}
