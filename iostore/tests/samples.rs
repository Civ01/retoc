//! Real containers, kept outside the repo. Skipped unless `IOSTORE_SAMPLES` is set.
//!
//! - `IOSTORE_SAMPLES`: folder searched recursively for `*.utoc`
//! - `IOSTORE_OODLE`: folder or file of the Oodle library (`liboo2corelinux64.so.9` /
//!   `oo2core_9_win64.dll`)
//! - AES key: `key.txt` in the container's folder (hex or base64 anywhere in the text), else
//!   `IOSTORE_KEY`
//! - trimmed containers (`tools/ucas_trim.py` in tcl-iostore): only the chunks listed in
//!   `<name>.trim.json` are read
//!
//! Every chunk must decode and match its TOC hash.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use iostore::{AesKey, ChunkKind, Container, HashCheck, Vanilla};

fn utocs(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(rd) = std::fs::read_dir(dir) else { return };
    let mut entries: Vec<_> = rd.flatten().map(|e| e.path()).collect();
    entries.sort();
    for p in entries {
        if p.is_dir() {
            utocs(&p, out);
        } else if p.extension().is_some_and(|e| e.eq_ignore_ascii_case("utoc")) {
            out.push(p);
        }
    }
}

fn b64(s: &str) -> Option<Vec<u8>> {
    let val = |c: u8| match c {
        b'A'..=b'Z' => Some(c - b'A'),
        b'a'..=b'z' => Some(c - b'a' + 26),
        b'0'..=b'9' => Some(c - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    };
    let mut out = Vec::new();
    let (mut acc, mut bits) = (0u32, 0);
    for c in s.trim_end_matches('=').bytes() {
        acc = acc << 6 | val(c)? as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    Some(out)
}

fn find_key(text: &str) -> Option<[u8; 32]> {
    for word in text.split(|c: char| c.is_whitespace() || c == '"' || c == ',' || c == ':') {
        let w = word.strip_prefix("0x").or_else(|| word.strip_prefix("0X")).unwrap_or(word);
        if w.len() == 64 && w.chars().all(|c| c.is_ascii_hexdigit()) {
            let mut k = [0u8; 32];
            for (i, b) in k.iter_mut().enumerate() {
                *b = u8::from_str_radix(&w[i * 2..i * 2 + 2], 16).ok()?;
            }
            return Some(k);
        }
        if w.len() == 44
            && let Some(Ok(k)) = b64(w).map(<[u8; 32]>::try_from)
        {
            return Some(k);
        }
    }
    None
}

fn kept(utoc: &Path) -> Option<Vec<u32>> {
    let text = std::fs::read_to_string(utoc.with_extension("trim.json")).ok()?;
    Some(text.split("\"index\":").skip(1).filter_map(|s| s.trim_start().split(|c: char| !c.is_ascii_digit()).next()?.parse().ok()).collect())
}

#[test]
fn every_chunk_of_every_sample() {
    let Some(root) = std::env::var_os("IOSTORE_SAMPLES") else {
        eprintln!("IOSTORE_SAMPLES not set: skipped");
        return;
    };
    if let Some(o) = std::env::var_os("IOSTORE_OODLE") {
        iostore::set_oodle_search_paths([PathBuf::from(o)]);
    }
    let mut list = Vec::new();
    utocs(Path::new(&root), &mut list);
    assert!(!list.is_empty(), "no .utoc files under {}", Path::new(&root).display());
    let mut failures = Vec::new();
    for utoc in &list {
        let mut c = Container::open(utoc, Arc::new(Vanilla)).unwrap_or_else(|e| panic!("{}: {e}", utoc.display()));
        let key = std::fs::read_to_string(utoc.with_file_name("key.txt")).ok().and_then(|t| find_key(&t)).or_else(|| std::env::var("IOSTORE_KEY").ok().and_then(|t| find_key(&t)));
        if c.is_encrypted() {
            let k = key.unwrap_or_else(|| panic!("{}: encrypted, no key.txt / IOSTORE_KEY", utoc.display()));
            c.set_key(AesKey::new(k)).unwrap_or_else(|e| panic!("{}: {e}", utoc.display()));
        }
        let files = c.directory_index().unwrap_or_else(|e| panic!("{}: {e}", utoc.display())).files.len();
        let indexes: Vec<u32> = kept(utoc).unwrap_or_else(|| (0..c.chunk_count()).collect());
        let (mut ok, mut no_hash) = (0, 0);
        for &i in &indexes {
            let r = (|| -> iostore::Result<HashCheck> {
                let mut r = c.open_chunk(i)?;
                while r.next_piece()?.is_some() {}
                Ok(r.hash_check())
            })();
            match r {
                Ok(HashCheck::Match) => ok += 1,
                Ok(HashCheck::NotStored) => no_hash += 1,
                other => failures.push(format!("{} chunk {i}: {other:?}", utoc.display())),
            }
        }
        let name = utoc.file_name().unwrap().to_string_lossy();
        if name.eq_ignore_ascii_case("global.utoc") {
            assert!(c.has_script_objects(), "{}: global without script objects", utoc.display());
        }
        let ch = c.container_header().map(|r| r.map(|h| (h.version, h.package_count)).map_err(|e| e.to_string()));
        eprintln!(
            "{:<70} v{} {:>6} files, {:>6}/{:<6} chunks ok, {} without hash, header {:?}",
            utoc.strip_prefix(&root).unwrap_or(utoc).display(),
            c.version().0,
            files,
            ok,
            indexes.len(),
            no_hash,
            ch
        );
        let kinds: std::collections::HashSet<ChunkKind> = c.chunks().map(|c| c.kind).collect();
        assert!(!kinds.iter().any(|k| matches!(k, ChunkKind::Unknown(_))), "{}: unknown chunk types {kinds:?}", utoc.display());
    }
    assert!(failures.is_empty(), "{} failures:\n{}", failures.len(), failures.join("\n"));
}
