//! Resource budgets, as hard assertions.
//!
//! Allocation counts and peak heap are exact and do not depend on how busy the
//! machine is, so unlike timings they can fail a build. Each test pins a
//! property the design promises: a decision allocates nothing, opening costs
//! the same whatever the filters weigh, and building holds no copies.
//! `cargo bench --bench burton` reports the same figures alongside timings.

#![allow(clippy::unwrap_used)]

mod support {
    pub(crate) mod alloc;
}

use std::path::Path;

use burton::{Artifact, Filter, KeySets, Lookup, Record, Tier, write_bundle};
use support::alloc::{Counting, measure};

#[global_allocator]
static ALLOC: Counting = Counting;

const SCHEME: &str = "budget/v1";

fn digest(i: u32, tier: u8) -> [u8; 32] {
    let mut d = [0u8; 32];
    d[..4].copy_from_slice(&i.to_le_bytes());
    d[8..12].copy_from_slice(&i.wrapping_mul(0x9e37_79b9).to_le_bytes());
    d[16] = tier;
    d
}

/// A long, realistic coordinate: storing these whole is what the budgets catch.
fn purl(i: u32) -> String {
    format!("pkg:npm/@some-organization/a-reasonably-long-package-name-{i}@1.2.{i}")
}

/// A bundle with `n` good keys of each kind and a tenth as many bad ones.
fn publish(dir: &Path, n: u32) {
    let mut sets = KeySets::new();
    for i in 0..n {
        sets.insert(
            Tier::Good,
            Record {
                purl: Some(purl(i)),
                sha256: Some(digest(i, 1)),
            },
        );
    }
    for i in 0..n / 10 {
        sets.insert(Tier::Bad, Record::sha256(digest(i, 2)));
    }
    write_bundle(dir, &sets.into_filters(1e-9), "2026-10-29", SCHEME).unwrap();
}

/// Filters a decision opens: one per tier, for each key it is given.
const FILTERS_PER_KEY: u64 = Tier::ALL.len() as u64;

#[test]
fn a_decision_does_not_allocate() {
    let dir = tempfile::tempdir().unwrap();
    publish(dir.path(), 1_000);
    let lk = Lookup::open(dir.path(), SCHEME).unwrap();

    let (good, bad, miss) = (digest(3, 1), digest(3, 2), digest(3, 9));
    let blessed = purl(3);
    let cases = [
        (Artifact::sha256(&good), 1),
        (Artifact::sha256(&bad), 1),
        (Artifact::sha256(&miss), 1),
        (Artifact::purl(&blessed), 1),
        (Artifact::purl(&blessed).and_sha256(&good), 2),
        (Artifact::purl("pkg:npm/absent@1").and_sha256(&miss), 2),
    ];
    for (artifact, keys) in cases {
        let (decision, usage) = measure(|| lk.decide(&artifact));
        // Unix opens a short path from the stack; Windows widens it to UTF-16
        // on the heap, once per filter opened.
        let allowed = if cfg!(unix) {
            0
        } else {
            keys * FILTERS_PER_KEY
        };
        assert!(
            usage.allocs <= allowed,
            "{artifact:?} -> {decision:?} allocated: {usage:?}"
        );
    }
}

#[test]
fn opening_costs_the_same_however_large_the_filters() {
    let (small, large) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    publish(small.path(), 10);
    publish(large.path(), 100_000);

    let (_, s) = measure(|| Lookup::open(small.path(), SCHEME).unwrap());
    let (_, l) = measure(|| Lookup::open(large.path(), SCHEME).unwrap());
    // Only the manifest's key counts differ, by a few digits each.
    assert_eq!(l.allocs, s.allocs, "small {s:?}, large {l:?}");
    assert!(l.peak <= s.peak + 256, "small {s:?}, large {l:?}");
    assert!(l.peak < 64 * 1024, "{l:?}");
}

#[test]
fn loading_a_filter_does_not_copy_it() {
    let dir = tempfile::tempdir().unwrap();
    publish(dir.path(), 10_000);
    let image = std::fs::read(dir.path().join("sha256-good.adbl")).unwrap();

    let (filter, usage) = measure(|| Filter::load(image).unwrap());
    assert_eq!(usage.allocs, 0, "{usage:?}");
    assert_eq!(filter.len(), 10_000);
}

#[test]
fn key_sets_hold_digests_not_keys() {
    const N: u32 = 50_000;
    // Each purl is made inside the measurement and dropped by `insert`, so
    // only what the sets keep accumulates.
    let (sets, usage) = measure(|| {
        let mut sets = KeySets::new();
        for i in 0..N {
            sets.insert(Tier::Good, Record::purl(purl(i)));
        }
        sets
    });
    assert_eq!(sets.counts(Tier::Good), (N as usize, 0));
    // A 32-byte digest and a control byte per bucket, peaking while the table
    // doubles: about 65 bytes a key at this size. Keeping the purls as well
    // would add about 80 more here, and grow with their length.
    let per_key = usage.peak / u64::from(N);
    assert!(per_key <= 80, "{per_key} bytes/key, {usage:?}");
}

#[test]
fn building_filters_holds_nothing_but_the_filters() {
    let mut sets = KeySets::new();
    for i in 0..50_000 {
        sets.insert(Tier::Good, Record::sha256(digest(i, 1)));
        sets.insert(Tier::SightedSuspicious, Record::sha256(digest(i, 5)));
        sets.insert(Tier::Good, Record::sha256(digest(i, 5)));
    }

    let (filters, usage) = measure(|| sets.into_filters(1e-9));
    let images: u64 = filters.iter().map(|f| f.as_bytes().len() as u64).sum();
    // The images themselves and the Vec holding them. Subtracting the claims
    // from `good` must not build a set of its own.
    let slack = (filters.capacity() * size_of::<Filter>()) as u64;
    assert!(
        usage.peak <= images + slack,
        "{images} B of filters, {usage:?}"
    );
}

#[test]
fn writing_costs_the_same_however_large_the_filters() {
    let cost = |n: u32| {
        let mut sets = KeySets::new();
        for i in 0..n {
            sets.insert(Tier::Good, Record::sha256(digest(i, 1)));
        }
        let filters = sets.into_filters(1e-9);
        let dir = tempfile::tempdir().unwrap();
        measure(|| write_bundle(dir.path(), &filters, "2026-10-29", SCHEME).unwrap()).1
    };
    let (s, l) = (cost(10), cost(100_000));
    assert!(l.peak <= s.peak + 256, "small {s:?}, large {l:?}");
    assert!(l.peak < 64 * 1024, "{l:?}");
}
