//! Just enough of `FIoContainerHeader` for display: version, container id, package counts.

use crate::error::{Result, corrupt};

const MAGIC: u32 = 0x496f_436e;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContainerHeaderSummary {
    /// `EIoContainerHeaderVersion` (-1 PreInitial ... 5 SoftPackageReferencesOffset).
    pub version: i32,
    pub container_id: u64,
    pub package_count: u32,
    /// Optional-segment packages (version 2+).
    pub optional_segment_package_count: Option<u32>,
}

pub fn container_header_version_name(v: i32) -> &'static str {
    match v {
        -1 => "PreInitial",
        0 => "Initial",
        1 => "LocalizedPackages",
        2 => "OptionalSegmentPackages",
        3 => "NoExportInfo",
        4 => "SoftPackageReferences",
        5 => "SoftPackageReferencesOffset",
        _ => "Unknown",
    }
}

struct R<'a>(&'a [u8], usize);
impl R<'_> {
    fn u32(&mut self) -> Result<u32> {
        let b = self.0.get(self.1..self.1 + 4).ok_or_else(|| corrupt("container header ends early"))?;
        self.1 += 4;
        Ok(u32::from_le_bytes(b.try_into().unwrap()))
    }
    fn skip(&mut self, n: usize) -> Result<()> {
        if self.1 + n > self.0.len() {
            return Err(corrupt("container header ends early"));
        }
        self.1 += n;
        Ok(())
    }
    fn u64(&mut self) -> Result<u64> {
        Ok(self.u32()? as u64 | (self.u32()? as u64) << 32)
    }
}

impl ContainerHeaderSummary {
    pub fn parse(d: &[u8]) -> Result<Self> {
        let mut r = R(d, 0);
        let first = r.u32()?;
        let (version, container_id) = if first == MAGIC {
            let v = r.u32()? as i32;
            if !(1..=16).contains(&v) {
                return Err(corrupt(format!("container header version {v}")));
            }
            (v, r.u64()?)
        } else {
            (0, first as u64 | (r.u32()? as u64) << 32)
        };
        let mut explicit_count = None;
        if version < 2 {
            explicit_count = Some(r.u32()?);
        }
        if version == 0 {
            // names + name hashes buffers
            for _ in 0..2 {
                let n = r.u32()? as usize;
                r.skip(n)?;
            }
        }
        let ids = r.u32()?;
        r.skip(ids as usize * 8)?;
        let mut optional = None;
        if version >= 2 {
            let store = r.u32()? as usize;
            r.skip(store)?;
            optional = Some(r.u32()?);
        }
        Ok(Self {
            version,
            container_id,
            package_count: explicit_count.unwrap_or(ids),
            optional_segment_package_count: optional,
        })
    }
}
