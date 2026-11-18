#![allow(clippy::manual_checked_ops)]
//! Containers built in the test: every compression method, encryption, partitions,
//! damaged input. A tiny writer lives here; the real writer comes with packing.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use iostore::{AesKey, Container, Error, HashCheck, Vanilla};
use sha1::Digest;

const BS: usize = 0x1000;

#[derive(Clone, Copy, PartialEq)]
enum Comp {
    None,
    Zlib,
    Lz4,
    Zstd,
}

struct Spec {
    version: u8,
    comp: Comp,
    key: Option<[u8; 32]>,
    /// bytes per partition (0 = single file)
    partition_size: u64,
    files: Vec<(&'static str, Vec<u8>)>,
}

fn fstr(s: &str, out: &mut Vec<u8>) {
    out.extend(((s.len() + 1) as u32).to_le_bytes());
    out.extend(s.as_bytes());
    out.push(0);
}

/// Flat directory index: all files in the root directory.
fn dir_index(names: &[&str]) -> Vec<u8> {
    let mut d = Vec::new();
    fstr("../../../Game/", &mut d);
    d.extend(1u32.to_le_bytes());
    for v in [u32::MAX, u32::MAX, u32::MAX, if names.is_empty() { u32::MAX } else { 0 }] {
        d.extend(v.to_le_bytes());
    }
    d.extend((names.len() as u32).to_le_bytes());
    for i in 0..names.len() as u32 {
        let next = if (i as usize) + 1 < names.len() { i + 1 } else { u32::MAX };
        for v in [i, next, i] {
            d.extend(v.to_le_bytes());
        }
    }
    d.extend((names.len() as u32).to_le_bytes());
    for n in names {
        fstr(n, &mut d);
    }
    d
}

fn hash(version: u8, data: &[u8]) -> [u8; 20] {
    if version <= 3 { sha1::Sha1::digest(data).into() } else { blake3::hash(data).as_bytes()[..20].try_into().unwrap() }
}

fn compress(c: Comp, d: &[u8]) -> Vec<u8> {
    use std::io::Write;
    match c {
        Comp::None => d.to_vec(),
        Comp::Zlib => {
            let mut e = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
            e.write_all(d).unwrap();
            e.finish().unwrap()
        }
        Comp::Lz4 => lz4_flex::block::compress(d),
        Comp::Zstd => zstd::bulk::compress(d, 3).unwrap(),
    }
}

fn build(dir: &Path, name: &str, spec: &Spec) -> PathBuf {
    let utoc = dir.join(format!("{name}.utoc"));
    let mut ucas: Vec<Vec<u8>> = vec![Vec::new()];
    let mut ids = Vec::new();
    let mut offs = Vec::new();
    let mut blocks: Vec<[u8; 12]> = Vec::new();
    let mut metas = Vec::new();
    let key = spec.key.map(AesKey::new);
    let mut uncompressed_pos = 0u64;
    let mut global_pos = 0u64;
    for (i, (_, data)) in spec.files.iter().enumerate() {
        let mut id = [0u8; 12];
        id[0] = i as u8 + 1;
        id[11] = if spec.version >= 5 { 1 } else { 2 }; // ExportBundleData
        ids.push(id);
        let mut ol = [0u8; 10];
        ol[..5].copy_from_slice(&uncompressed_pos.to_be_bytes()[3..]);
        ol[5..].copy_from_slice(&(data.len() as u64).to_be_bytes()[3..]);
        offs.push(ol);
        for piece in data.chunks(BS) {
            let mut stored = compress(spec.comp, piece);
            let method = if spec.comp == Comp::None || stored.len() >= piece.len() {
                stored = piece.to_vec();
                0u8
            } else {
                1
            };
            let csize = stored.len();
            // pad to 16 like UE
            let padded = (csize + 15) & !15;
            for j in csize..padded {
                stored.push(stored[(j - csize) % csize]);
            }
            if let Some(k) = &key {
                k.encrypt_ecb(&mut stored);
            }
            if spec.partition_size > 0 {
                let part = (global_pos / spec.partition_size) as usize;
                let end_part = ((global_pos + stored.len() as u64 - 1) / spec.partition_size) as usize;
                if end_part != part {
                    global_pos = end_part as u64 * spec.partition_size;
                }
            }
            let part = if spec.partition_size > 0 { (global_pos / spec.partition_size) as usize } else { 0 };
            while ucas.len() <= part {
                ucas.push(Vec::new());
            }
            let local = if spec.partition_size > 0 { global_pos % spec.partition_size } else { global_pos };
            ucas[part].resize(local as usize, 0);
            ucas[part].extend_from_slice(&stored);
            let mut b = [0u8; 12];
            b[..5].copy_from_slice(&global_pos.to_le_bytes()[..5]);
            b[5..8].copy_from_slice(&(csize as u32).to_le_bytes()[..3]);
            b[8..11].copy_from_slice(&(piece.len() as u32).to_le_bytes()[..3]);
            b[11] = method;
            blocks.push(b);
            global_pos += stored.len() as u64;
        }
        uncompressed_pos += (data.len() as u64).div_ceil(BS as u64).max(1) * BS as u64;
        if data.is_empty() {
            uncompressed_pos -= BS as u64;
        }
        metas.push((hash(spec.version, data), 1u8));
    }
    let names: Vec<&str> = spec.files.iter().map(|f| f.0).collect();
    let mut di = dir_index(&names);
    if let Some(k) = &key {
        di.resize((di.len() + 15) & !15, 0);
        k.encrypt_ecb(&mut di);
    }
    let mut flags = 8u8; // Indexed
    if spec.comp != Comp::None {
        flags |= 1;
    }
    if key.is_some() {
        flags |= 2;
    }
    let method_names: Vec<&str> = match spec.comp {
        Comp::None => vec![],
        Comp::Zlib => vec!["Zlib"],
        Comp::Lz4 => vec!["LZ4"],
        Comp::Zstd => vec!["Zstd"],
    };
    let mut t = Vec::new();
    t.extend(b"-==--==--==--==-");
    t.push(spec.version);
    t.extend([0, 0, 0]);
    let n = spec.files.len() as u32;
    for v in [0x90u32, n, blocks.len() as u32, 12, method_names.len() as u32, 32, BS as u32, di.len() as u32, ucas.len() as u32] {
        t.extend(v.to_le_bytes());
    }
    t.extend(0x1122334455667788u64.to_le_bytes());
    t.extend([0u8; 16]);
    t.push(flags);
    t.extend([0, 0, 0]);
    t.extend(0u32.to_le_bytes()); // seeds
    t.extend(if spec.partition_size > 0 { spec.partition_size } else { u64::MAX }.to_le_bytes());
    t.extend(0u32.to_le_bytes()); // without perfect hash
    t.resize(0x90, 0);
    for id in &ids {
        t.extend(id);
    }
    for o in &offs {
        t.extend(o);
    }
    for b in &blocks {
        t.extend(b);
    }
    for m in &method_names {
        let mut name = m.as_bytes().to_vec();
        name.resize(32, 0);
        t.extend(name);
    }
    t.extend(&di);
    for (h, f) in &metas {
        if spec.version >= 8 {
            t.extend(h);
            t.push(*f);
            t.extend([0, 0, 0]);
        } else {
            t.extend(h);
            t.extend([0u8; 12]);
            t.push(*f);
        }
    }
    std::fs::write(&utoc, t).unwrap();
    for (i, data) in ucas.iter().enumerate() {
        let p = if i == 0 { dir.join(format!("{name}.ucas")) } else { dir.join(format!("{name}_s{i}.ucas")) };
        std::fs::write(p, data).unwrap();
    }
    utoc
}

fn data(n: usize, seed: u32) -> Vec<u8> {
    // compressible but not trivial
    let mut x = seed.wrapping_mul(2654435761) | 1;
    (0..n)
        .map(|i| {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            if i % 7 < 4 { (i / 97) as u8 } else { x as u8 }
        })
        .collect()
}

fn files() -> Vec<(&'static str, Vec<u8>)> {
    vec![("small.uasset", data(100, 1)), ("exact.ubulk", data(BS, 2)), ("multi.uexp", data(BS * 5 + 123, 3)), ("empty.bin", vec![])]
}

fn tmp(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("iostore-test-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn check_all(c: &mut Container, expected: &[(&str, Vec<u8>)]) {
    let idx = c.directory_index().unwrap().clone();
    assert_eq!(idx.mount_point, "../../../Game/");
    assert_eq!(idx.files.len(), expected.len());
    for f in &idx.files {
        let want = &expected.iter().find(|e| e.0 == f.path).unwrap().1;
        let mut r = c.open_chunk(f.toc_index).unwrap();
        let mut got = Vec::new();
        while let Some(p) = r.next_piece().unwrap() {
            got.extend_from_slice(p);
        }
        assert_eq!(&got, want, "{}", f.path);
        assert_eq!(r.hash_check(), HashCheck::Match);
        // Read impl gives the same bytes
        let mut via_read = Vec::new();
        c.open_chunk(f.toc_index).unwrap().read_to_end(&mut via_read).unwrap();
        assert_eq!(&via_read, want);
    }
}

#[test]
fn every_method_and_version() {
    let dir = tmp("methods");
    for version in [3u8, 5, 6, 8] {
        for comp in [Comp::None, Comp::Zlib, Comp::Lz4, Comp::Zstd] {
            let spec = Spec {
                version,
                comp,
                key: None,
                partition_size: 0,
                files: files(),
            };
            let utoc = build(&dir, &format!("v{version}_{}", comp as u8), &spec);
            let mut c = Container::open(&utoc, Arc::new(Vanilla)).unwrap();
            assert!(c.missing_partitions().is_empty());
            check_all(&mut c, &spec.files);
        }
    }
}

#[test]
fn encrypted_needs_and_checks_key() {
    let dir = tmp("enc");
    let key = [7u8; 32];
    let spec = Spec {
        version: 8,
        comp: Comp::Zlib,
        key: Some(key),
        partition_size: 0,
        files: files(),
    };
    let utoc = build(&dir, "enc", &spec);
    let mut c = Container::open(&utoc, Arc::new(Vanilla)).unwrap();
    assert!(c.index_needs_key());
    assert!(matches!(c.directory_index(), Err(Error::KeyRequired(_))));
    assert!(matches!(c.set_key(AesKey::new([8u8; 32])), Err(Error::WrongKey)));
    assert!(!c.has_key());
    c.set_key(AesKey::new(key)).unwrap();
    check_all(&mut c, &spec.files);
}

#[test]
fn partitions() {
    let dir = tmp("parts");
    let spec = Spec {
        version: 8,
        comp: Comp::None,
        key: None,
        partition_size: 3 * BS as u64,
        files: files(),
    };
    let utoc = build(&dir, "parts", &spec);
    let mut c = Container::open(&utoc, Arc::new(Vanilla)).unwrap();
    assert!(c.partitions().len() > 1, "test should span partitions");
    check_all(&mut c, &spec.files);
    // a missing partition only fails when read
    std::fs::remove_file(dir.join("parts_s1.ucas")).unwrap();
    let mut c = Container::open(&utoc, Arc::new(Vanilla)).unwrap();
    assert_eq!(c.missing_partitions().len(), 1);
    let multi = c.directory_index().unwrap().files.iter().find(|f| f.path == "multi.uexp").unwrap().toc_index;
    assert!(matches!(c.read_chunk(multi), Err(Error::MissingPartition(_))));
}

#[test]
fn damaged_input_is_an_error_not_a_panic() {
    let dir = tmp("damage");
    let spec = Spec {
        version: 8,
        comp: Comp::Zstd,
        key: None,
        partition_size: 0,
        files: files(),
    };
    let utoc = build(&dir, "ok", &spec);
    let good = std::fs::read(&utoc).unwrap();
    let bad = dir.join("bad.utoc");
    // every truncation and many single-byte corruptions
    for len in (0..good.len()).step_by(7) {
        std::fs::write(&bad, &good[..len]).unwrap();
        let _ = Container::open(&bad, Arc::new(Vanilla)).map(|mut c| c.directory_index().map(|_| ()));
    }
    std::fs::copy(dir.join("ok.ucas"), dir.join("bad.ucas")).unwrap();
    for pos in (16..good.len()).step_by(3) {
        let mut d = good.clone();
        d[pos] ^= 0xa5;
        std::fs::write(&bad, &d).unwrap();
        if let Ok(mut c) = Container::open(&bad, Arc::new(Vanilla)) {
            let _ = c.directory_index();
            for i in 0..c.chunk_count() {
                let _ = c.read_chunk(i);
            }
        }
    }
    // newer version
    let mut d = good.clone();
    d[16] = 9;
    std::fs::write(&bad, &d).unwrap();
    assert!(matches!(Container::open(&bad, Arc::new(Vanilla)), Err(Error::UnsupportedVersion(9))));
    // corrupted data: hash mismatch or decode error
    let mut ucas = std::fs::read(dir.join("ok.ucas")).unwrap();
    let n = ucas.len();
    ucas[n - 40] ^= 0xff;
    std::fs::write(dir.join("bad.ucas"), &ucas).unwrap();
    std::fs::write(&bad, &good).unwrap();
    let mut c = Container::open(&bad, Arc::new(Vanilla)).unwrap();
    let multi = c.directory_index().unwrap().files.iter().find(|f| f.path == "multi.uexp").unwrap().toc_index;
    let mut r = c.open_chunk(multi).unwrap();
    let outcome = loop {
        match r.next_piece() {
            Ok(Some(_)) => continue,
            Ok(None) => break r.hash_check(),
            Err(_) => break HashCheck::Incomplete,
        }
    };
    assert_ne!(outcome, HashCheck::Match);
}
