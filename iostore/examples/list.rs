//! cargo run -p iostore --example list -- <utoc>   (prints index, size, path; largest last)
use std::sync::Arc;
fn main() {
    let a: Vec<String> = std::env::args().collect();
    let mut c = iostore::Container::open(&a[1], Arc::new(iostore::Vanilla)).unwrap();
    let files = c.directory_index().unwrap().files.clone();
    let mut v: Vec<_> = files.iter().map(|f| (c.chunk(f.toc_index).unwrap().size, f.toc_index, f.path.clone())).collect();
    v.sort();
    for (size, i, p) in v.iter().rev().take(5).rev() {
        println!("{i}\t{size}\t{p}");
    }
}
