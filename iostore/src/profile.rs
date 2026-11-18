//! Game profiles: every game-specific deviation from vanilla Unreal goes through here, so
//! support for custom games (ported from CUE4Parse later) has one place to plug in.

use crate::compression::Method;
use crate::crypto::AesKey;
use crate::error::Result;
use crate::toc::TOC_MAGIC;

/// What a decryption call is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptTarget {
    DirectoryIndex,
    /// A compression block (index into the block table).
    Block(u32),
}

pub trait GameProfile: Send + Sync + std::fmt::Debug {
    /// Stable identifier (stored in settings later).
    fn id(&self) -> &'static str;

    /// Is this the start of a `.utoc` this profile reads?
    fn is_toc_magic(&self, magic: &[u8]) -> bool {
        magic == TOC_MAGIC
    }

    /// Called with the whole `.utoc` before parsing (e.g. to undo a custom TOC encryption).
    fn prepare_toc(&self, _toc: &mut Vec<u8>) -> Result<()> {
        Ok(())
    }

    /// Decrypts `data` (a multiple of 16 bytes) in place.
    fn decrypt(&self, key: &AesKey, data: &mut [u8], _target: CryptTarget) {
        key.decrypt_ecb(data);
    }

    /// Maps a compression method name from the `.utoc`.
    fn compression_method(&self, name: &str) -> Method {
        Method::from_name(name)
    }
}

/// Unmodified Unreal Engine.
#[derive(Debug, Default, Clone, Copy)]
pub struct Vanilla;

impl GameProfile for Vanilla {
    fn id(&self) -> &'static str {
        "vanilla"
    }
}
