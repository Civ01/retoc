//! The TOC's perfect hash table (TOC version 4+): UE's `FIoStoreWriterImpl::GeneratePerfectHashes`
//! and the runtime lookup it serves (`FFileIoStoreContainer` in FileIoDispatcherBackend.cpp).
//!
//! UE sorts buckets with an unstable sort, so the seeds it picks for equally sized buckets aren't
//! reproducible; any table the runtime lookup resolves is equally valid. Ours sorts stably.

use crate::types::ChunkId;

/// `FIoStoreTocResource::HashChunkIdWithSeed`.
pub fn hash_chunk_id(seed: i32, id: &ChunkId) -> u64 {
    let mut hash: u64 = if seed != 0 { seed as i64 as u64 } else { 0xcbf2_9ce4_8422_2325 };
    for &b in &id.0 {
        hash = hash.wrapping_mul(0x0000_0100_0000_01B3) ^ b as u64;
    }
    hash
}

/// A generated table: the chunk table must be reordered so that slot `i` holds `order[i]`.
#[derive(Debug, Clone)]
pub struct PerfectHash {
    /// For each slot, the index of the chunk (in the input order) placed there.
    pub order: Vec<u32>,
    pub seeds: Vec<i32>,
    /// Slots of chunks without a perfect hash (TOC 5+ only; must be empty for TOC 4).
    pub overflow: Vec<i32>,
}

const PRIMES: [u32; 1000] = primes();

const fn primes() -> [u32; 1000] {
    let mut out = [0u32; 1000];
    let mut n = 2u32;
    let mut count = 0;
    while count < 1000 {
        let mut d = 2;
        let mut prime = true;
        while d * d <= n {
            if n.is_multiple_of(d) {
                prime = false;
                break;
            }
            d += 1;
        }
        if prime {
            out[count] = n;
            count += 1;
        }
        n += 1;
    }
    out
}

/// Builds the table as UE does (same primes, same bucket rules, overflow when a bucket finds no seed).
pub fn generate(ids: &[ChunkId]) -> PerfectHash {
    let chunk_count = ids.len() as u32;
    let seed_count = ((chunk_count as f64 / 2.0).round() as u32).max(1);
    let mut slots: Vec<Option<u32>> = vec![None; chunk_count as usize];
    let mut seeds = vec![0i32; seed_count as usize];
    let mut overflow_chunks: Vec<u32> = Vec::new();

    let mut buckets: Vec<Vec<u32>> = vec![Vec::new(); seed_count as usize];
    for (i, id) in ids.iter().enumerate() {
        buckets[(hash_chunk_id(0, id) % seed_count as u64) as usize].push(i as u32);
    }
    buckets.sort_by_key(|b| std::cmp::Reverse(b.len()));

    for bucket in buckets.iter().take_while(|b| b.len() > 1) {
        let bucket_hash = hash_chunk_id(0, &ids[bucket[0] as usize]);
        let mut prime_index = 0;
        let mut used = vec![false; chunk_count as usize];
        let mut index_in_bucket = 0;
        let mut found = true;
        while index_in_bucket < bucket.len() {
            let seed = PRIMES[prime_index];
            let slot = (hash_chunk_id(seed as i32, &ids[bucket[index_in_bucket] as usize]) % chunk_count as u64) as usize;
            if slots[slot].is_some() || used[slot] {
                prime_index += 1;
                if prime_index == PRIMES.len() {
                    found = false;
                    seeds[(bucket_hash % seed_count as u64) as usize] = -(overflow_chunks.len() as i32) - chunk_count as i32 - 1;
                    overflow_chunks.extend_from_slice(bucket);
                    break;
                }
                index_in_bucket = 0;
                used.iter_mut().for_each(|u| *u = false);
            } else {
                used[slot] = true;
                index_in_bucket += 1;
            }
        }
        if found {
            let seed = PRIMES[prime_index];
            seeds[(bucket_hash % seed_count as u64) as usize] = seed as i32;
            for &chunk in bucket {
                let slot = (hash_chunk_id(seed as i32, &ids[chunk as usize]) % chunk_count as u64) as usize;
                slots[slot] = Some(chunk);
            }
        }
    }

    let mut free = (0..chunk_count as usize).filter(|&s| slots[s].is_none()).collect::<Vec<_>>().into_iter();
    for bucket in buckets.iter().filter(|b| b.len() == 1) {
        let slot = free.next().expect("a free slot per single-chunk bucket");
        let chunk = bucket[0];
        seeds[(hash_chunk_id(0, &ids[chunk as usize]) % seed_count as u64) as usize] = -(slot as i32) - 1;
        slots[slot] = Some(chunk);
    }
    let mut overflow = Vec::with_capacity(overflow_chunks.len());
    for chunk in overflow_chunks {
        let slot = free.next().expect("a free slot per overflow chunk");
        slots[slot] = Some(chunk);
        overflow.push(slot as i32);
    }
    PerfectHash {
        order: slots.into_iter().map(|s| s.expect("every slot filled")).collect(),
        seeds,
        overflow,
    }
}

/// The runtime lookup: slot of `id` in a chunk table ordered for `seeds`, or `None`.
pub fn lookup(ids: &[ChunkId], seeds: &[i32], overflow: &[i32], id: &ChunkId) -> Option<u32> {
    let chunk_count = ids.len() as u32;
    if chunk_count == 0 || seeds.is_empty() {
        return None;
    }
    let seed = seeds[(hash_chunk_id(0, id) % seeds.len() as u64) as usize];
    if seed == 0 {
        return None;
    }
    let slot = if seed < 0 {
        let index = (-(seed as i64) - 1) as u64;
        if index < chunk_count as u64 {
            index as u32
        } else {
            return overflow.iter().map(|&s| s as u32).find(|&s| ids.get(s as usize) == Some(id));
        }
    } else {
        (hash_chunk_id(seed, id) % chunk_count as u64) as u32
    };
    (ids.get(slot as usize) == Some(id)).then_some(slot)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn primes_match_ue() {
        assert_eq!(&PRIMES[..5], &[2, 3, 5, 7, 11]);
        assert_eq!(PRIMES[999], 7919);
    }

    #[test]
    fn generated_tables_resolve_every_chunk() {
        for n in [1u32, 2, 3, 10, 1000, 20000] {
            let ids: Vec<ChunkId> = (0..n)
                .map(|i| {
                    let mut b = [0u8; 12];
                    b[..4].copy_from_slice(&i.wrapping_mul(2_654_435_761).to_le_bytes());
                    b[11] = (i % 7) as u8;
                    ChunkId(b)
                })
                .collect();
            let ph = generate(&ids);
            let table: Vec<ChunkId> = ph.order.iter().map(|&i| ids[i as usize]).collect();
            for (i, id) in ids.iter().enumerate() {
                let slot = lookup(&table, &ph.seeds, &ph.overflow, id).unwrap_or_else(|| panic!("n={n}: chunk {i} not found"));
                assert_eq!(ph.order[slot as usize], i as u32);
            }
        }
    }
}
