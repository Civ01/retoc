//! Reader for Unreal Engine IoStore containers (`.utoc` + `.ucas`).
//!
//! - TOC versions 1–8 (UE 4.25 – 5.8), bounds-checked parsing, no panics on bad input
//! - partitioned containers (`name_s1.ucas`, ...)
//! - streaming chunk reads, one compression block in memory at a time
//! - AES-256 (directory index + blocks), Zlib/Gzip/LZ4/Zstd/Oodle (Oodle via `oodle_loader`)
//! - chunk hash checks (SHA-1 for UE4 containers, BLAKE3-160 for UE5)
//! - game-specific behaviour behind [`GameProfile`] ([`Vanilla`] by default)
//!
//! ```no_run
//! use std::sync::Arc;
//! let mut c = iostore::Container::open("pakchunk0-Windows.utoc", Arc::new(iostore::Vanilla))?;
//! for f in c.directory_index()?.files.clone() {
//!     let mut r = c.open_chunk(f.toc_index)?;
//!     while let Some(piece) = r.next_piece()? { /* write piece */ let _ = piece; }
//!     assert_eq!(r.hash_check(), iostore::HashCheck::Match);
//! }
//! # Ok::<(), iostore::Error>(())
//! ```

pub mod compression;
pub mod container;
pub mod container_header;
pub mod crypto;
pub mod dirindex;
pub mod error;
pub mod profile;
pub mod toc;
pub mod types;

pub use compression::Method;
pub use container::{ChunkInfo, ChunkReader, Container, HashCheck, Partition, partition_paths};
pub use container_header::{ContainerHeaderSummary, container_header_version_name};
pub use crypto::AesKey;
pub use dirindex::{DirectoryIndex, IndexedFile};
pub use error::{Error, Result};
pub use profile::{CryptTarget, GameProfile, Vanilla};
pub use toc::{BlockEntry, ChunkMeta, OffsetLength, Signatures, Toc, TocHeader};
pub use types::{ChunkId, ChunkKind, ContainerFlags, ContainerId, Guid, HashAlgorithm, TocVersion};

/// Sets where the Oodle library is looked for (directories or files), as `oodle_loader`.
pub fn set_oodle_search_paths<I, P>(paths: I)
where
    I: IntoIterator<Item = P>,
    P: Into<std::path::PathBuf>,
{
    oodle_loader::set_search_paths(paths)
}

/// Path of the loaded Oodle library, loading it if needed.
pub fn oodle_status() -> std::result::Result<std::path::PathBuf, String> {
    oodle_loader::oodle().map(|o| o.path().to_path_buf()).map_err(|e| e.to_string())
}
