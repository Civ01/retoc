//! Container edits on copies of the sample containers (`IOSTORE_SAMPLES`, optional `IOSTORE_OODLE`).
//! Skipped without samples; containers over `IOSTORE_EDIT_MAX_MB` (default 64) are left out.

use iostore::edit::{ContainerEdit, NewContainer, UndoRecord, partition_path};
use iostore::write::{Compressor, OodleCompressor, OodleLevel};
use iostore::{AesKey, Container, ContainerId, HashCheck, TocVersion, Vanilla};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

fn utocs(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(rd) = std::fs::read_dir(dir) else { return };
    let mut v: Vec<_> = rd.flatten().map(|e| e.path()).collect();
    v.sort();
    for p in v {
        if p.is_dir() {
            utocs(&p, out);
        } else if p.extension().is_some_and(|e| e.eq_ignore_ascii_case("utoc")) {
            out.push(p);
        }
    }
}

fn hex_key(text: &str) -> Option<[u8; 32]> {
    // Same rules as samples.rs: 64 hex digits or 44 base64 characters.
    for w in text.split(|c: char| c.is_whitespace() || c == '"' || c == ',' || c == ':') {
        let w = w.strip_prefix("0x").unwrap_or(w);
        if w.len() == 64 && w.chars().all(|c| c.is_ascii_hexdigit()) {
            let mut k = [0u8; 32];
            for (i, b) in k.iter_mut().enumerate() {
                *b = u8::from_str_radix(&w[i * 2..i * 2 + 2], 16).ok()?;
            }
            return Some(k);
        }
        if w.len() == 44 {
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
            for c in w.trim_end_matches('=').bytes() {
                acc = acc << 6 | val(c)? as u32;
                bits += 6;
                if bits >= 8 {
                    bits -= 8;
                    out.push((acc >> bits) as u8);
                }
            }
            if let Ok(k) = <[u8; 32]>::try_from(out) {
                return Some(k);
            }
        }
    }
    None
}

fn key_for(utoc: &Path) -> Option<AesKey> {
    std::fs::read_to_string(utoc.with_file_name("key.txt")).ok().and_then(|t| hex_key(&t)).map(AesKey::new)
}

/// Copies the container's files into `dir`.
fn copy_container(utoc: &Path, dir: &Path) -> PathBuf {
    std::fs::create_dir_all(dir).unwrap();
    let c = Container::open(utoc, Arc::new(Vanilla)).unwrap();
    for p in c.partitions() {
        std::fs::copy(&p.path, dir.join(p.path.file_name().unwrap())).unwrap();
    }
    let out = dir.join(utoc.file_name().unwrap());
    std::fs::copy(utoc, &out).unwrap();
    out
}

fn container_size(utoc: &Path) -> u64 {
    let c = Container::open(utoc, Arc::new(Vanilla)).unwrap();
    c.partitions().iter().filter_map(|p| p.size).sum::<u64>() + std::fs::metadata(utoc).unwrap().len()
}

type Snapshot = (BTreeMap<[u8; 12], Vec<u8>>, Vec<(String, [u8; 12])>);

/// Every chunk's data, keyed by chunk id, plus the directory listing.
fn snapshot(utoc: &Path, key: Option<&AesKey>) -> Snapshot {
    let mut c = Container::open(utoc, Arc::new(Vanilla)).unwrap();
    if let Some(k) = key {
        c.set_key(k.clone()).unwrap();
    }
    let mut data = BTreeMap::new();
    for i in 0..c.chunk_count() {
        let mut r = c.open_chunk(i).unwrap();
        let mut buf = Vec::new();
        while let Some(p) = r.next_piece().unwrap() {
            buf.extend_from_slice(p);
        }
        assert!(matches!(r.hash_check(), HashCheck::Match | HashCheck::NotStored), "{}: chunk {i} hash {:?}", utoc.display(), r.hash_check());
        data.insert(c.toc().chunk_ids[i as usize].0, buf);
    }
    let ids = c.toc().chunk_ids.clone();
    let mut files: Vec<(String, [u8; 12])> = c.directory_index().unwrap().files.iter().map(|f| (f.path.clone(), ids[f.toc_index as usize].0)).collect();
    files.sort();
    (data, files)
}

fn compressor_like(c: &Container) -> Option<Compressor> {
    let name = c.toc().compression_methods.first()?.to_ascii_lowercase();
    Some(match name.as_str() {
        "zlib" => Compressor::Zlib(6),
        "gzip" => Compressor::Gzip(6),
        "lz4" => Compressor::Lz4,
        "oodle" => Compressor::Oodle(OodleCompressor::Kraken, OodleLevel::Fast),
        _ => return None,
    })
}

fn samples() -> Option<Vec<PathBuf>> {
    let root = std::env::var_os("IOSTORE_SAMPLES")?;
    if let Some(o) = std::env::var_os("IOSTORE_OODLE") {
        iostore::set_oodle_search_paths([PathBuf::from(o)]);
    }
    let max = std::env::var("IOSTORE_EDIT_MAX_MB").ok().and_then(|v| v.parse().ok()).unwrap_or(64u64) << 20;
    let mut list = Vec::new();
    utocs(Path::new(&root), &mut list);
    let oodle = iostore::oodle_status().is_ok();
    Some(
        list.into_iter()
            .filter(|u| container_size(u) <= max)
            // Trimmed copies (tools/ucas_trim.py) have zeroed chunks.
            .filter(|u| !u.with_extension("trim.json").exists())
            .filter(|u| oodle || !Container::open(u, Arc::new(Vanilla)).unwrap().toc().compression_methods.iter().any(|m| m.eq_ignore_ascii_case("oodle")))
            .collect(),
    )
}

#[test]
fn replace_every_chunk_reads_back() {
    let Some(list) = samples() else { return eprintln!("IOSTORE_SAMPLES not set: skipped") };
    let tmp = std::env::temp_dir().join("iostore-edit-replace");
    let _ = std::fs::remove_dir_all(&tmp);
    for (n, utoc) in list.iter().enumerate() {
        let key = key_for(utoc);
        let src = Container::open(utoc, Arc::new(Vanilla)).unwrap();
        if src.is_encrypted() && key.is_none() {
            continue;
        }
        let comp = compressor_like(&src);
        let copy = copy_container(utoc, &tmp.join(n.to_string()));
        let (before, files_before) = snapshot(&copy, key.as_ref());
        let original_toc = std::fs::read(&copy).unwrap();

        let mut edit = ContainerEdit::open(&copy, &Vanilla, key.clone()).unwrap();
        let ids: Vec<_> = edit.chunks().map(|(i, id, _)| (i, id)).collect();
        for (i, id) in ids {
            let data = &before[&id.0];
            edit.replace(i, &mut data.as_slice(), data.len() as u64, comp.as_ref(), &mut |_| false).unwrap();
        }
        let undo = edit.undo_record().unwrap();
        edit.finish().unwrap();

        let (after, files_after) = snapshot(&copy, key.as_ref());
        assert_eq!(before, after, "{}", utoc.display());
        assert_eq!(files_before, files_after, "{}", utoc.display());
        let new_toc = iostore::Toc::parse(&std::fs::read(&copy).unwrap(), &Vanilla).unwrap();
        let old_toc = iostore::Toc::parse(&original_toc, &Vanilla).unwrap();
        // Replace only: same chunk order, perfect hash and directory index.
        assert_eq!(new_toc.chunk_ids, old_toc.chunk_ids);
        assert_eq!(new_toc.perfect_hash_seeds, old_toc.perfect_hash_seeds);
        assert_eq!(new_toc.directory_index, old_toc.directory_index);

        // Undo puts the original bytes back.
        let restored = UndoRecord::from_bytes(&undo.to_bytes()).unwrap();
        restored.restore(&copy).unwrap();
        assert_eq!(std::fs::read(&copy).unwrap(), original_toc);
        let src_len = std::fs::metadata(partition_path(utoc, 0)).unwrap().len();
        assert_eq!(std::fs::metadata(partition_path(&copy, 0)).unwrap().len(), src_len);
        eprintln!("replace: {} ({} chunks{})", utoc.display(), before.len(), if key.is_some() { ", encrypted" } else { "" });
    }
}

#[test]
fn remove_and_add_rebuilds_lookup_and_index() {
    let Some(list) = samples() else { return eprintln!("IOSTORE_SAMPLES not set: skipped") };
    let tmp = std::env::temp_dir().join("iostore-edit-add");
    let _ = std::fs::remove_dir_all(&tmp);
    for (n, utoc) in list.iter().enumerate() {
        let key = key_for(utoc);
        let src = Container::open(utoc, Arc::new(Vanilla)).unwrap();
        if (src.is_encrypted() && key.is_none()) || src.chunk_count() < 2 {
            continue;
        }
        let copy = copy_container(utoc, &tmp.join(n.to_string()));
        let (before, files_before) = snapshot(&copy, key.as_ref());
        let mut edit = ContainerEdit::open(&copy, &Vanilla, key.clone()).unwrap();
        // Remove the first named chunk (or the first chunk) and add it back as new.
        let (i, id, path) = edit.chunks().find(|(_, _, p)| p.is_some()).or_else(|| edit.chunks().next()).map(|(i, id, p)| (i, id, p.map(String::from))).unwrap();
        edit.remove(i).unwrap();
        let data = &before[&id.0];
        edit.add(id, path, &mut data.as_slice(), data.len() as u64, None, false, &mut |_| false).unwrap();
        edit.finish().unwrap();
        let (after, files_after) = snapshot(&copy, key.as_ref());
        assert_eq!(before, after, "{}", utoc.display());
        assert_eq!(files_before, files_after, "{}", utoc.display());
        let toc = iostore::Toc::parse(&std::fs::read(&copy).unwrap(), &Vanilla).unwrap();
        if toc.header.version >= TocVersion::PERFECT_HASH {
            for (slot, cid) in toc.chunk_ids.iter().enumerate() {
                assert_eq!(iostore::perfect_hash::lookup(&toc.chunk_ids, &toc.perfect_hash_seeds, &toc.chunks_without_perfect_hash, cid), Some(slot as u32));
            }
        }
        eprintln!("remove+add: {} ({} chunks)", utoc.display(), before.len());
    }
}

#[test]
fn new_container_with_partitions() {
    let tmp = std::env::temp_dir().join("iostore-edit-new");
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp).unwrap();
    for (version, key) in [(TocVersion(3), None), (TocVersion(8), None), (TocVersion(8), Some(AesKey::new([9; 32])))] {
        let utoc = tmp.join(format!("new{}{}.utoc", version.0, if key.is_some() { "e" } else { "" }));
        let settings = NewContainer {
            version,
            block_size: 65536,
            container_id: ContainerId(0x1234),
            mount_point: "../../../".into(),
            partition_size: Some(300_000),
            key: key.clone().map(|k| (k, iostore::Guid([1; 16]))),
        };
        let mut edit = ContainerEdit::create(&utoc, &settings).unwrap();
        let mut expected = BTreeMap::new();
        for i in 0..6u8 {
            let mut id = [0u8; 12];
            id[0] = i + 1;
            id[11] = 2;
            let data: Vec<u8> = (0..150_000u32).map(|x| (x as u8).wrapping_mul(i + 3)).collect();
            edit.add(iostore::ChunkId(id), Some(format!("Game/Content/f{i}.uasset")), &mut data.as_slice(), data.len() as u64, None, false, &mut |_| false).unwrap();
            expected.insert(id, data);
        }
        edit.finish().unwrap();
        let (data, files) = snapshot(&utoc, key.as_ref());
        assert_eq!(data, expected);
        assert_eq!(files.len(), 6);
        assert_eq!(files[0].0, "Game/Content/f0.uasset");
        let c = Container::open(&utoc, Arc::new(Vanilla)).unwrap();
        if version >= TocVersion::PARTITION_SIZE {
            assert!(c.partitions().len() > 1, "expected several partitions");
        }
    }
}
