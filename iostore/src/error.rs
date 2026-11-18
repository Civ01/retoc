use std::path::PathBuf;

use crate::types::Guid;

/// Errors from reading IoStore containers. Each variant carries enough detail for a
/// caller to decide what to do next (ask for a key, offer another game profile, warn
/// about Oodle, ...).
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("not an IoStore .utoc file (unknown magic)")]
    UnknownMagic,

    #[error("TOC version {0} is newer than this plugin supports")]
    UnsupportedVersion(u8),

    #[error("damaged .utoc: {0}")]
    Corrupt(String),

    #[error("container data file not found: {}", .0.display())]
    MissingPartition(PathBuf),

    #[error("the container is encrypted and needs an AES key (key GUID {0})")]
    KeyRequired(Guid),

    #[error("the AES key doesn't decrypt this container")]
    WrongKey,

    #[error("damaged directory index: {0}")]
    BadDirectoryIndex(String),

    #[error("unknown compression method \"{0}\"")]
    UnknownCompression(String),

    #[error("Oodle library not available: {0}")]
    OodleUnavailable(String),

    #[error("chunk {chunk}: block {block} can't be decoded ({reason})")]
    DecodeFailed { chunk: u32, block: u32, reason: String },

    #[error("chunk {0} is stored on demand (outside this container); reading it isn't supported")]
    OnDemand(u32),

    #[error("chunk index {0} out of range")]
    NoSuchChunk(u32),
}

pub type Result<T, E = Error> = std::result::Result<T, E>;

pub(crate) fn corrupt(msg: impl Into<String>) -> Error {
    Error::Corrupt(msg.into())
}
