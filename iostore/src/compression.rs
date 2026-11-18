//! Block decompression. Method names come from the `.utoc` (case-insensitive).

use std::io::Read;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Method {
    Zlib,
    Gzip,
    Lz4,
    Zstd,
    Oodle,
    Unknown(String),
}

impl Method {
    pub fn from_name(name: &str) -> Self {
        match name.to_ascii_lowercase().as_str() {
            "zlib" => Self::Zlib,
            "gzip" => Self::Gzip,
            "lz4" => Self::Lz4,
            "zstd" => Self::Zstd,
            "oodle" => Self::Oodle,
            _ => Self::Unknown(name.to_string()),
        }
    }
}

/// Why a block didn't decode.
#[derive(Debug)]
pub enum DecodeError {
    /// The data is bad (or the AES key is wrong).
    Data(String),
    /// Oodle couldn't be loaded.
    OodleUnavailable(String),
    Unknown(String),
}

/// Decompresses `input` into exactly `out.len()` bytes.
pub fn decompress(method: &Method, input: &[u8], out: &mut [u8]) -> Result<(), DecodeError> {
    let data = |e: &dyn std::fmt::Display| DecodeError::Data(e.to_string());
    match method {
        Method::Zlib => flate2::read::ZlibDecoder::new(input).read_exact(out).map_err(|e| data(&e)),
        Method::Gzip => flate2::read::GzDecoder::new(input).read_exact(out).map_err(|e| data(&e)),
        Method::Lz4 => match lz4_flex::block::decompress_into(input, out) {
            Ok(n) if n == out.len() => Ok(()),
            Ok(n) => Err(DecodeError::Data(format!("LZ4 gave {n} bytes, expected {}", out.len()))),
            Err(e) => Err(data(&e)),
        },
        Method::Zstd => match zstd::bulk::decompress_to_buffer(input, out) {
            Ok(n) if n == out.len() => Ok(()),
            Ok(n) => Err(DecodeError::Data(format!("Zstd gave {n} bytes, expected {}", out.len()))),
            Err(e) => Err(data(&e)),
        },
        Method::Oodle => {
            let oodle = oodle_loader::oodle().map_err(|e| DecodeError::OodleUnavailable(e.to_string()))?;
            let n = oodle.decompress(input, out);
            if n < 0 || n as usize != out.len() { Err(DecodeError::Data(format!("Oodle gave {n} bytes, expected {}", out.len()))) } else { Ok(()) }
        }
        Method::Unknown(name) => Err(DecodeError::Unknown(name.clone())),
    }
}
