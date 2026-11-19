//! `FIoDirectoryIndexResource`: mount point + directory tree + string table.
//!
//! Parsing is strict (every index in range, no cycles, sane strings), because for
//! encrypted containers a clean parse is the only sign that the AES key was right.

use crate::error::{Error, Result};

#[derive(Debug, Clone, Default)]
pub struct DirectoryIndex {
    /// As stored, e.g. `../../../TheIsle/Content/`.
    pub mount_point: String,
    /// Files in tree order: path relative to the mount point (`/`-separated) and TOC entry index.
    pub files: Vec<IndexedFile>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexedFile {
    pub path: String,
    pub toc_index: u32,
}

const NONE: u32 = u32::MAX;
const MAX_STRING: i32 = 1 << 16;

fn bad(msg: impl Into<String>) -> Error {
    Error::BadDirectoryIndex(msg.into())
}

struct R<'a> {
    d: &'a [u8],
    p: usize,
}

impl R<'_> {
    fn u32(&mut self) -> Result<u32> {
        let b = self.d.get(self.p..self.p + 4).ok_or_else(|| bad("ends early"))?;
        self.p += 4;
        Ok(u32::from_le_bytes(b.try_into().unwrap()))
    }
    fn fstring(&mut self) -> Result<String> {
        let len = self.u32()? as i32;
        if len == 0 {
            return Ok(String::new());
        }
        if len.unsigned_abs() > MAX_STRING as u32 {
            return Err(bad(format!("string length {len}")));
        }
        let (bytes, wide) = if len > 0 { (len as usize, false) } else { ((-len) as usize * 2, true) };
        let b = self.d.get(self.p..self.p + bytes).ok_or_else(|| bad("string runs past the end"))?;
        self.p += bytes;
        let s = if wide {
            let units: Vec<u16> = b.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
            if units.last() != Some(&0) {
                return Err(bad("wide string without terminator"));
            }
            String::from_utf16(&units[..units.len() - 1]).map_err(|_| bad("invalid UTF-16 string"))?
        } else {
            if b.last() != Some(&0) {
                return Err(bad("string without terminator"));
            }
            // FString's ANSI form is Latin-1.
            b[..b.len() - 1].iter().map(|&c| c as char).collect::<String>()
        };
        // Paths never contain control characters; a wrong AES key gives noise that does.
        if s.chars().any(|c| (c as u32) < 0x20) {
            return Err(bad("control characters in string"));
        }
        Ok(s)
    }
    fn count(&mut self, record: usize) -> Result<usize> {
        let n = self.u32()? as usize;
        if n.checked_mul(record).is_none_or(|bytes| bytes > self.d.len() - self.p.min(self.d.len())) {
            return Err(bad(format!("array of {n} entries doesn't fit")));
        }
        Ok(n)
    }
}

#[derive(Debug, Clone)]
struct Dir {
    name: u32,
    first_child: u32,
    next_sibling: u32,
    first_file: u32,
}

#[derive(Debug, Clone)]
struct File {
    name: u32,
    next: u32,
    user_data: u32,
}

impl DirectoryIndex {
    /// Parses a decrypted directory index. An empty buffer is an empty index.
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.is_empty() {
            return Ok(Self::default());
        }
        let mut r = R { d: data, p: 0 };
        let mount_point = r.fstring()?;
        let n = r.count(16)?;
        let mut dirs = Vec::with_capacity(n);
        for _ in 0..n {
            dirs.push(Dir {
                name: r.u32()?,
                first_child: r.u32()?,
                next_sibling: r.u32()?,
                first_file: r.u32()?,
            });
        }
        let n = r.count(12)?;
        let mut files = Vec::with_capacity(n);
        for _ in 0..n {
            files.push(File { name: r.u32()?, next: r.u32()?, user_data: r.u32()? });
        }
        let n = r.count(4)?;
        let mut strings = Vec::with_capacity(n);
        for _ in 0..n {
            strings.push(r.fstring()?);
        }
        // Encrypted buffers are padded to 16 bytes; anything beyond that is suspicious.
        if data.len() - r.p >= 16 {
            return Err(bad(format!("{} unused bytes at the end", data.len() - r.p)));
        }

        let name = |i: u32| -> Result<&str> { strings.get(i as usize).map(String::as_str).ok_or_else(|| bad(format!("name index {i} out of range"))) };

        let mut out = Vec::with_capacity(files.len());
        if !dirs.is_empty() {
            let mut seen_dirs = vec![false; dirs.len()];
            let mut seen_files = vec![false; files.len()];
            // (directory, length of the path prefix before it)
            let mut stack: Vec<(u32, usize)> = vec![(0, 0)];
            let mut path = String::new();
            while let Some((d, prefix)) = stack.pop() {
                let dir = dirs.get(d as usize).ok_or_else(|| bad(format!("directory index {d} out of range")))?;
                if std::mem::replace(&mut seen_dirs[d as usize], true) {
                    return Err(bad("directory tree has a cycle"));
                }
                path.truncate(prefix);
                if dir.name != NONE {
                    let n = name(dir.name)?;
                    if n.is_empty() {
                        return Err(bad("empty directory name"));
                    }
                    path.push_str(n);
                    path.push('/');
                }
                let mut f = dir.first_file;
                while f != NONE {
                    let file = files.get(f as usize).ok_or_else(|| bad(format!("file index {f} out of range")))?;
                    if std::mem::replace(&mut seen_files[f as usize], true) {
                        return Err(bad("file list has a cycle"));
                    }
                    let n = name(file.name)?;
                    if n.is_empty() {
                        return Err(bad("empty file name"));
                    }
                    out.push(IndexedFile { path: format!("{path}{n}"), toc_index: file.user_data });
                    f = file.next;
                }
                // Children are pushed in reverse so they come out in stored order.
                let here = path.len();
                let mut children = Vec::new();
                let mut c = dir.first_child;
                while c != NONE {
                    let child = dirs.get(c as usize).ok_or_else(|| bad(format!("directory index {c} out of range")))?;
                    if children.len() > dirs.len() {
                        return Err(bad("sibling list has a cycle"));
                    }
                    children.push(c);
                    c = child.next_sibling;
                }
                for c in children.into_iter().rev() {
                    stack.push((c, here));
                }
            }
        }
        Ok(Self { mount_point, files: out })
    }
}

/// `FIoDirectoryIndexWriter`: same entry order as UE, so feeding files in TOC entry order (as
/// `FIoStoreWriter` does) gives UE's bytes.
#[derive(Debug, Clone)]
pub struct DirectoryIndexWriter {
    mount_point: String,
    dirs: Vec<Dir>,
    files: Vec<File>,
    strings: Vec<String>,
    string_index: std::collections::HashMap<String, u32>,
}

impl DirectoryIndexWriter {
    pub fn new(mount_point: impl Into<String>) -> Self {
        Self {
            mount_point: mount_point.into(),
            dirs: vec![Dir {
                name: NONE,
                first_child: NONE,
                next_sibling: NONE,
                first_file: NONE,
            }],
            files: Vec::new(),
            strings: Vec::new(),
            string_index: std::collections::HashMap::new(),
        }
    }

    fn name_index(&mut self, s: &str) -> u32 {
        if let Some(&i) = self.string_index.get(s) {
            return i;
        }
        let i = self.strings.len() as u32;
        self.strings.push(s.to_string());
        self.string_index.insert(s.to_string(), i);
        i
    }

    fn directory(&mut self, name: &str, parent: u32) -> u32 {
        let name = self.name_index(name);
        let mut d = self.dirs[parent as usize].first_child;
        while d != NONE {
            if self.dirs[d as usize].name == name {
                return d;
            }
            d = self.dirs[d as usize].next_sibling;
        }
        let new = self.dirs.len() as u32;
        let sibling = self.dirs[parent as usize].first_child;
        self.dirs.push(Dir {
            name,
            first_child: NONE,
            next_sibling: sibling,
            first_file: NONE,
        });
        self.dirs[parent as usize].first_child = new;
        new
    }

    /// Adds `path` (relative to the mount point, `/`-separated) pointing at TOC entry `toc_index`.
    pub fn add_file(&mut self, path: &str, toc_index: u32) {
        let (dir_path, file_name) = match path.rfind('/') {
            Some(i) => (&path[..i], &path[i + 1..]),
            None => ("", path),
        };
        let mut dir = 0;
        for part in dir_path.split('/').filter(|p| !p.is_empty()) {
            dir = self.directory(part, dir);
        }
        let name = self.name_index(file_name);
        let new = self.files.len() as u32;
        let next = self.dirs[dir as usize].first_file;
        self.files.push(File { name, next, user_data: toc_index });
        self.dirs[dir as usize].first_file = new;
    }

    /// The index as stored, unencrypted (see [`encrypt_directory_index`]).
    pub fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::new();
        write_fstring(&mut out, &self.mount_point);
        out.extend((self.dirs.len() as u32).to_le_bytes());
        for d in &self.dirs {
            for v in [d.name, d.first_child, d.next_sibling, d.first_file] {
                out.extend(v.to_le_bytes());
            }
        }
        out.extend((self.files.len() as u32).to_le_bytes());
        for f in &self.files {
            for v in [f.name, f.next, f.user_data] {
                out.extend(v.to_le_bytes());
            }
        }
        out.extend((self.strings.len() as u32).to_le_bytes());
        for s in &self.strings {
            write_fstring(&mut out, s);
        }
        out
    }
}

/// `FString` serialization: ANSI when every character is ASCII, else UTF-16 (negative length).
fn write_fstring(out: &mut Vec<u8>, s: &str) {
    if s.is_empty() {
        out.extend(0i32.to_le_bytes());
    } else if s.is_ascii() {
        out.extend(((s.len() + 1) as i32).to_le_bytes());
        out.extend(s.as_bytes());
        out.push(0);
    } else {
        let units: Vec<u16> = s.encode_utf16().collect();
        out.extend((-((units.len() + 1) as i32)).to_le_bytes());
        for u in units {
            out.extend(u.to_le_bytes());
        }
        out.extend([0, 0]);
    }
}

/// `FIoDirectoryIndexWriter::Flush` for encrypted containers: pad to 16 bytes by repeating the
/// start of the buffer, then AES-ECB.
pub fn encrypt_directory_index(mut data: Vec<u8>, key: &crate::crypto::AesKey) -> Vec<u8> {
    let len = data.len();
    if !len.is_multiple_of(16) {
        for i in len..len.next_multiple_of(16) {
            data.push(data[(i - len) % len]);
        }
    }
    key.encrypt_ecb(&mut data);
    data
}

/// `IoDirectoryIndexUtils::GetCommonRootPath`: longest common directory of `paths`, with a
/// trailing `/` (UE's mount point for a new container).
pub fn common_root_path<'a>(paths: impl IntoIterator<Item = &'a str>) -> String {
    let mut root: Option<&str> = None;
    for p in paths {
        let dir = match p.rfind('/') {
            Some(i) => &p[..=i],
            None => "",
        };
        root = Some(match root {
            None => dir,
            Some(r) => {
                // Case-insensitive, as UE's Strnicmp.
                let common = r.char_indices().zip(dir.chars()).take_while(|((_, a), b)| a.eq_ignore_ascii_case(b)).last().map(|((i, c), _)| i + c.len_utf8()).unwrap_or(0);
                // Back to the last whole directory.
                match r[..common].rfind('/') {
                    Some(i) => &r[..=i],
                    None => "",
                }
            }
        });
    }
    root.unwrap_or("").to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fstr(s: &str, out: &mut Vec<u8>) {
        out.extend(((s.len() + 1) as u32).to_le_bytes());
        out.extend(s.as_bytes());
        out.push(0);
    }

    /// root -> "Game" -> files a.uasset (0), b.ubulk (1); root file c.bin (2)
    fn sample() -> Vec<u8> {
        let mut d = Vec::new();
        fstr("../../../", &mut d);
        d.extend(2u32.to_le_bytes());
        for v in [NONE, 1, NONE, 2] {
            d.extend(v.to_le_bytes());
        }
        for v in [0u32, NONE, NONE, 0] {
            d.extend(v.to_le_bytes());
        }
        d.extend(3u32.to_le_bytes());
        for v in [1u32, 1, 0, 2, NONE, 1, 3, NONE, 2] {
            d.extend(v.to_le_bytes());
        }
        d.extend(4u32.to_le_bytes());
        for s in ["Game", "a.uasset", "b.ubulk", "c.bin"] {
            fstr(s, &mut d);
        }
        d
    }

    #[test]
    fn parses_tree() {
        let idx = DirectoryIndex::parse(&sample()).unwrap();
        assert_eq!(idx.mount_point, "../../../");
        let got: Vec<_> = idx.files.iter().map(|f| (f.path.as_str(), f.toc_index)).collect();
        assert_eq!(got, [("c.bin", 2), ("Game/a.uasset", 0), ("Game/b.ubulk", 1)]);
    }

    #[test]
    fn rejects_noise_and_cycles() {
        let mut noise = sample();
        for (i, b) in noise.iter_mut().enumerate() {
            *b ^= (i * 37 + 11) as u8;
        }
        assert!(DirectoryIndex::parse(&noise).is_err());
        let mut cyc = sample();
        // file 1 -> next = 0 (file 0 -> next = 1)
        let files_at = 4 + 10 + 4 + 32 + 4;
        cyc[files_at + 12 + 4..files_at + 12 + 8].copy_from_slice(&0u32.to_le_bytes());
        assert!(DirectoryIndex::parse(&cyc).is_err());
        assert!(DirectoryIndex::parse(&sample()[..20]).is_err());
    }
}
