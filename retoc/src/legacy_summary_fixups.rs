//! Legacy header fields that Zen drops but that can be recomputed exactly from what it keeps
//! (checked against UE 5.8.4 source and the engine's own cook of the same package):
//! - `PackageSource`: `FCrc::StrCrc_DEPRECATED` of the upper-cased file base name (SavePackage2.cpp).
//! - `SavedHash`: BLAKE3-160 over the header with the field zeroed plus the export data without the
//!   trailing package tag (SavePackage2.cpp, versions with `PackageSavedHash`).
//! - `ScriptSerializationStart/EndOffset`: the range of an export's tagged properties, which
//!   `FLinkerLoad::MarkScriptSerializationStart/End` `checkf` on load (tagged-property packages only).

use crate::legacy_asset::{FMinimalName, FPackageNameMap};
use crate::zen::EUnrealEngineObjectUE5Version;

/// `FCrc::StrCrc_DEPRECATED` (MSB-first CRC-32, poly 0x04C11DB7, each UTF-16 unit as low byte then high byte).
pub fn str_crc_deprecated(s: &str) -> u32 {
    let table = &crate::crc::CRC_TABLE_DEPRECATED;
    let mut crc = 0xFFFF_FFFFu32;
    for unit in s.encode_utf16() {
        for byte in [unit as u8, (unit >> 8) as u8] {
            crc = (crc << 8) ^ table[((crc >> 24) ^ byte as u32) as usize];
        }
    }
    !crc
}

/// `PackageSource` as SavePackage2 writes it: CRC of `FPaths::GetBaseFilename(Filename).ToUpper()`.
pub fn package_source(package_name: &str) -> u32 {
    let base = package_name.rsplit('/').next().unwrap_or(package_name);
    // FString::ToUpper maps one TCHAR to one TCHAR; keep characters whose upper case is longer.
    let upper: String = base
        .chars()
        .map(|c| {
            let mut up = c.to_uppercase();
            match (up.next(), up.next()) {
                (Some(u), None) => u,
                _ => c,
            }
        })
        .collect();
    str_crc_deprecated(&upper)
}

/// Offset of `SavedHash` in a legacy header: tag, legacy file version, UE3, UE4, UE5, licensee.
pub const SAVED_HASH_OFFSET: usize = 24;

/// SavePackage2's saved hash: zero the field, hash header + exports up to the package tag.
pub fn saved_hash(header: &[u8], exports: &[u8]) -> [u8; 20] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(&header[..SAVED_HASH_OFFSET]);
    hasher.update(&[0u8; 20]);
    hasher.update(&header[SAVED_HASH_OFFSET + 20..]);
    hasher.update(&exports[..exports.len().saturating_sub(4)]);
    let mut out = [0u8; 20];
    out.copy_from_slice(&hasher.finalize().as_bytes()[..20]);
    out
}

struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}
impl Reader<'_> {
    fn bytes(&mut self, n: usize) -> Option<&[u8]> {
        let end = self.pos.checked_add(n)?;
        let out = self.data.get(self.pos..end)?;
        self.pos = end;
        Some(out)
    }
    fn u8(&mut self) -> Option<u8> {
        self.bytes(1).map(|b| b[0])
    }
    fn i32(&mut self) -> Option<i32> {
        self.bytes(4).map(|b| i32::from_le_bytes(b.try_into().unwrap()))
    }
    fn skip(&mut self, n: usize) -> Option<()> {
        self.bytes(n).map(|_| ())
    }
}

/// Bare name (no number) of an FName in export data, if the index is valid.
fn name<'a>(r: &mut Reader, names: &'a FPackageNameMap) -> Option<(String, i32)> {
    let index = r.i32()?;
    let number = r.i32()?;
    if index < 0 || number < 0 {
        return None;
    }
    let bare = names.get(FMinimalName { index, number: 0 }).ok()?;
    Some((bare.into_owned(), number))
}

fn skip_extensions(r: &mut Reader) -> Option<()> {
    let extensions = r.u8()?;
    if extensions & 0x02 != 0 {
        // OverriddenPropertyOperation (uint8) + bExperimentalOverridableLogic (bool, 4 bytes)
        r.skip(5)?;
    }
    if extensions & 0x04 != 0 {
        // bExperimentalExternalObjects (bool, 4 bytes)
        r.skip(4)?;
    }
    if extensions & !0x06 != 0 { None } else { Some(()) }
}

/// End of the tagged properties at the start of an export's data (relative to the export), or
/// `None` if the data doesn't parse as a tag stream ending in `None` within the export.
/// `file_version_ue5` must be at least `ScriptSerializationOffset` (the offsets don't exist before).
pub fn tagged_properties_end(export: &[u8], names: &FPackageNameMap, file_version_ue5: i32) -> Option<usize> {
    let has_extensions = file_version_ue5 >= EUnrealEngineObjectUE5Version::PropertyTagExtensionAndOverridableSerialization as i32;
    let complete_type_name = file_version_ue5 >= EUnrealEngineObjectUE5Version::PropertyTagCompleteTypeName as i32;
    let mut r = Reader { data: export, pos: 0 };

    // UStruct::SerializeVersionedTaggedProperties on a UClass: serialization control extensions.
    if has_extensions {
        let control = r.u8()?;
        if control & 0x02 != 0 {
            r.skip(1)?; // EOverriddenPropertyOperation
        }
        if control & !0x02 != 0 {
            return None;
        }
    }
    loop {
        let (tag_name, _) = name(&mut r, names)?;
        if tag_name == "None" {
            return Some(r.pos);
        }
        let size;
        if complete_type_name {
            // FPropertyTypeName: nodes of (FName, int32 InnerCount), depth first.
            let mut remaining: i64 = 1;
            let mut nodes = 0;
            while remaining > 0 {
                name(&mut r, names)?;
                let inner = r.i32()?;
                if inner < 0 {
                    return None;
                }
                remaining += inner as i64 - 1;
                nodes += 1;
                if nodes > 256 {
                    return None;
                }
            }
            size = r.i32()?;
            let flags = r.u8()?;
            if flags & !0x3F != 0 {
                return None;
            }
            if flags & 0x01 != 0 {
                r.skip(4)?; // ArrayIndex
            }
            if flags & 0x02 != 0 {
                r.skip(16)?; // PropertyGuid
            }
            if flags & 0x04 != 0 {
                skip_extensions(&mut r)?;
            }
        } else {
            // LoadPropertyTagNoFullType (UE 5.2/5.3 layout of versions 1010-1011).
            let (type_name, type_number) = name(&mut r, names)?;
            size = r.i32()?;
            r.skip(4)?; // ArrayIndex
            if type_number == 0 {
                match type_name.as_str() {
                    "StructProperty" => {
                        name(&mut r, names)?;
                        r.skip(16)?;
                    }
                    "BoolProperty" => r.skip(1)?,
                    "ByteProperty" | "EnumProperty" | "ArrayProperty" | "OptionalProperty" | "SetProperty" => {
                        name(&mut r, names)?;
                    }
                    "MapProperty" => {
                        name(&mut r, names)?;
                        name(&mut r, names)?;
                    }
                    _ => {}
                }
            }
            if r.u8()? != 0 {
                r.skip(16)?; // PropertyGuid
            }
            if has_extensions {
                skip_extensions(&mut r)?;
            }
        }
        if size < 0 {
            return None;
        }
        r.skip(size as usize)?;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn package_source_matches_the_engine() {
        // Engine's 5.8 cook of /Game/Mods/SML/BP_SML (versioned and unversioned).
        assert_eq!(package_source("/Game/Mods/SML/BP_SML"), 0x9F193E2C);
    }

    #[test]
    fn tag_stream_end() {
        let names = FPackageNameMap::create_from_names(vec!["None".into(), "IntProperty".into(), "Value".into()]);
        let fname = |i: i32| [i.to_le_bytes(), 0i32.to_le_bytes()].concat();
        // 5.8: control byte, one IntProperty tag (type node with 0 inner, size 4, no flags), value, None.
        let mut data = vec![0u8];
        data.extend(fname(2));
        data.extend(fname(1));
        data.extend(0i32.to_le_bytes());
        data.extend(4i32.to_le_bytes());
        data.push(0);
        data.extend(7i32.to_le_bytes());
        data.extend(fname(0));
        let end = data.len();
        data.extend([0xAA; 12]); // native data after the properties
        assert_eq!(tagged_properties_end(&data, &names, 1018), Some(end));
        // Only "None": 1 control byte + 8.
        let mut none = vec![0u8];
        none.extend(fname(0));
        assert_eq!(tagged_properties_end(&none, &names, 1018), Some(9));
        // Garbage: no answer.
        assert_eq!(tagged_properties_end(&[0, 0xFF, 0xFF, 0xFF, 0x7F, 0, 0, 0, 0], &names, 1018), None);
        assert_eq!(tagged_properties_end(&[], &names, 1018), None);
    }
}
