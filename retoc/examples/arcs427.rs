//! UE 4.27 to-zen experiment: convert each legacy package of `<legacy dir>` alone and resolve its
//! external arcs against the game's own Zen packages; compare with the game's chunk.
//! Usage: arcs427 <game dir with global.utoc> <legacy dir (to-legacy output)> [--no-game]
use retoc::container_header::EIoContainerHeaderVersion;
use retoc::legacy_asset::FSerializedAssetBundle;
use retoc::zen::FZenPackageHeader;
use retoc::zen_asset_conversion::{build_zen_asset, LegacyExportBundles};
use retoc::*;
use std::collections::HashMap;
use std::io::Cursor;
use std::sync::Arc;

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let use_game = !args.iter().any(|a| a == "--no-game");
    let store = iostore::open(&args[1], Arc::new(Config::default()))?;
    let toc = store.container_file_version().unwrap();
    let hv = store.container_header_version().unwrap();
    let log = logging::Log::no_log();
    let lookup_cache: std::sync::Mutex<HashMap<FPackageId, Option<LegacyExportBundles>>> = Default::default();
    let external = |pkg: FPackageId, idx, cmd, name: Option<&str>| -> Option<i32> {
        if !use_game {
            return None;
        }
        let mut c = lookup_cache.lock().unwrap();
        if !c.contains_key(&pkg) {
            let id = FIoChunkId::from_package_id(pkg, 0, EIoChunkType::ExportBundleData);
            let m = store.read(id).ok().and_then(|d| FZenPackageHeader::deserialize(&mut Cursor::new(d), store.package_store_entry(pkg), toc, hv, None).ok()).map(|h| LegacyExportBundles::from_header(&h));
            c.insert(pkg, m);
        }
        c[&pkg].as_ref()?.resolve(idx, cmd, name)
    };
    let (mut same, mut diff, mut unresolved_total) = (0, 0, 0);
    let (mut arcs_same, mut arcs_diff) = (0, 0);
    for e in walkdir(&args[2]) {
        if !e.ends_with(".uasset") && !e.ends_with(".umap") {
            continue;
        }
        let rel = e.strip_prefix(&args[2]).unwrap().trim_start_matches('/').to_string();
        let p = std::path::Path::new(&e);
        let bundle = FSerializedAssetBundle {
            asset_file_buffer: std::fs::read(p)?,
            exports_file_buffer: std::fs::read(p.with_extension("uexp"))?,
            bulk_data_buffer: std::fs::read(p.with_extension("ubulk")).ok(),
            optional_bulk_data_buffer: None,
            memory_mapped_bulk_data_buffer: None,
        };
        let path = UEPathBuf::from(format!("../../../{rel}"));
        let mut conv = match build_zen_asset(bundle, &HashMap::new(), &path, Some(version::EngineVersion::UE4_27.package_file_version()), hv, hv <= EIoContainerHeaderVersion::Initial, None, None, &log) {
            Ok(c) => c,
            Err(err) => {
                println!("{rel}: convert failed: {err:#}");
                continue;
            }
        };
        let unresolved = conv.fixup_legacy_external_arcs_with(&HashMap::new(), &external, &log)?;
        unresolved_total += unresolved.len();
        for u in &unresolved { println!("  unresolved {rel}: {u}"); }
        let id = FIoChunkId::from_package_id(conv.package_id, 0, EIoChunkType::ExportBundleData);
        let game = store.read(id)?;
        let arcs = |d: &[u8]| -> Vec<(u64, i32, i32)> {
            let h = FZenPackageHeader::deserialize(&mut Cursor::new(d.to_vec()), Some(conv.store_entry().clone()), toc, hv, None).unwrap();
            let mut v: Vec<(u64, i32, i32)> = h.external_package_dependencies.iter().flat_map(|e| e.legacy_dependency_arcs.iter().map(move |a| (e.from_package_id.0, a.from_export_bundle_index, a.to_export_bundle_index))).collect();
            v.sort();
            v
        };
        let game_entry = store.package_store_entry(conv.package_id);
        let ga = { let h = FZenPackageHeader::deserialize(&mut Cursor::new(game.clone()), game_entry, toc, hv, None).unwrap(); let mut v: Vec<(u64, i32, i32)> = h.external_package_dependencies.iter().flat_map(|e| e.legacy_dependency_arcs.iter().map(move |a| (e.from_package_id.0, a.from_export_bundle_index, a.to_export_bundle_index))).collect(); v.sort(); v };
        let ca = arcs(conv.package_data());
        // from-bundle indices only (to-bundle indices depend on this package's own bundle layout)
        let from = |v: &[(u64, i32, i32)]| { let mut f: Vec<(u64, i32)> = v.iter().map(|x| (x.0, x.1)).collect(); f.sort(); f.dedup(); f };
        if from(&ga) == from(&ca) { arcs_same += 1 } else { arcs_diff += 1; println!("  arcs {rel}: game {:?}\n       conv {:?}", from(&ga), from(&ca)); }
        if game == conv.package_data() {
            same += 1;
        } else {
            diff += 1;
            let n = game.iter().zip(conv.package_data()).filter(|(a, b)| a != b).count();
            println!("{rel}: differs ({} vs {} bytes, {n} differing), unresolved arcs {}", conv.package_data().len(), game.len(), unresolved.len());
        }
    }
    println!("same={same} diff={diff} unresolved arcs={unresolved_total} external arcs (from bundles) same={arcs_same} diff={arcs_diff}");
    Ok(())
}

fn walkdir(d: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut stack = vec![std::path::PathBuf::from(d)];
    while let Some(p) = stack.pop() {
        for e in std::fs::read_dir(&p).unwrap().flatten() {
            let q = e.path();
            if q.is_dir() { stack.push(q) } else { out.push(q.to_string_lossy().into_owned()) }
        }
    }
    out
}
