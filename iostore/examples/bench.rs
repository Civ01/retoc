//! cargo run --release -p iostore --example bench -- <utoc> [key-hex]
use std::sync::Arc;
use std::time::Instant;
fn main() {
    let a: Vec<String> = std::env::args().collect();
    if let Ok(o) = std::env::var("IOSTORE_OODLE") {
        iostore::set_oodle_search_paths([o]);
    }
    let t = Instant::now();
    let mut c = iostore::Container::open(&a[1], Arc::new(iostore::Vanilla)).unwrap();
    if let Some(k) = a.get(2) {
        let mut b = [0u8; 32];
        for i in 0..32 {
            b[i] = u8::from_str_radix(&k[i * 2..i * 2 + 2], 16).unwrap();
        }
        c.set_key(iostore::AesKey::new(b)).unwrap();
    }
    let n = c.directory_index().unwrap().files.len();
    println!("open + index: {:?} ({n} files)", t.elapsed());
    let t = Instant::now();
    let mut bytes = 0u64;
    for i in 0..c.chunk_count() {
        let mut r = c.open_chunk(i).unwrap();
        while let Some(p) = r.next_piece().unwrap() {
            bytes += p.len() as u64;
        }
        assert_eq!(r.hash_check(), iostore::HashCheck::Match);
    }
    let s = t.elapsed().as_secs_f64();
    println!("read+hash: {s:.2} s, {:.0} MB/s", bytes as f64 / 1048576.0 / s);
}
