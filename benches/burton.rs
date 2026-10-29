//! Time and memory for the operations callers pay for.
//!
//! ```text
//! cargo bench                          # everything
//! cargo bench -- decide                # cases whose name contains "decide"
//! cargo bench -- --save main           # record a baseline
//! cargo bench -- --baseline main       # compare against it; exit 1 on regression
//! ```
//!
//! Time is the minimum over many rounds: load on the machine only ever adds
//! time, so the minimum is what stays put while the median shows the noise.
//! Allocations and peak heap are counted exactly and do not vary with load at
//! all, so any increase over a baseline is a regression.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::cast_precision_loss)]

#[path = "../tests/support/alloc.rs"]
mod alloc;

use std::collections::BTreeMap;
use std::fmt::Write;
use std::hint::black_box;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};

use burton::{Artifact, Filter, KeySets, Lookup, Record, Tier, parse_sha256_hex, write_bundle};

#[global_allocator]
static ALLOC: alloc::Counting = alloc::Counting;

/// Rounds per case. Odd, so the median is a sample.
const ROUNDS: usize = 31;
/// Shortest round worth timing; fast cases loop until they reach it.
const ROUND: Duration = Duration::from_millis(5);
/// A minimum this much above the baseline's is a regression. Allocation and
/// peak are exact, so any increase in those is one.
const TIME_TOLERANCE: f64 = 0.15;

const SCHEME: &str = "bench/v1";
/// Keys in the good tiers of the benchmark bundle; adverse tiers hold fewer.
const GOOD_KEYS: u32 = 100_000;

struct Row {
    name: String,
    min_ns: f64,
    median_ns: f64,
    allocs: f64,
    bytes: f64,
    peak: u64,
}

struct Bench {
    filter: Option<String>,
    rows: Vec<Row>,
}

impl Bench {
    /// Time `run` on inputs from `setup`, which is not timed, and count what
    /// one call allocates. `ops` is how many operations one call performs, so
    /// every figure is per operation.
    fn case<S, R>(
        &mut self,
        name: &str,
        ops: u64,
        mut setup: impl FnMut() -> S,
        mut run: impl FnMut(S) -> R,
    ) {
        if self
            .filter
            .as_ref()
            .is_some_and(|f| !name.contains(f.as_str()))
        {
            return;
        }

        // Calibrate: enough calls per round to make timer resolution noise.
        let mut iters = 1usize;
        loop {
            let inputs: Vec<S> = (0..iters).map(|_| setup()).collect();
            let start = Instant::now();
            for input in inputs {
                black_box(run(black_box(input)));
            }
            if start.elapsed() >= ROUND || iters >= 1 << 20 {
                break;
            }
            iters *= 2;
        }

        let mut samples: Vec<f64> = (0..ROUNDS)
            .map(|_| {
                let inputs: Vec<S> = (0..iters).map(|_| setup()).collect();
                let start = Instant::now();
                for input in inputs {
                    black_box(run(black_box(input)));
                }
                start.elapsed().as_nanos() as f64 / (iters as f64 * ops as f64)
            })
            .collect();
        samples.sort_by(f64::total_cmp);

        let input = setup();
        let (out, usage) = alloc::measure(|| run(input));
        drop(black_box(out));

        let row = Row {
            name: name.to_owned(),
            min_ns: samples[0],
            median_ns: samples[ROUNDS / 2],
            allocs: usage.allocs as f64 / ops as f64,
            bytes: usage.bytes as f64 / ops as f64,
            peak: usage.peak,
        };
        println!("{}", format_row(&row));
        self.rows.push(row);
    }
}

fn main() {
    let mut args = std::env::args().skip(1).filter(|a| a != "--bench");
    let (mut save, mut baseline, mut filter) = (None, None, None);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--save" => save = args.next(),
            "--baseline" => baseline = args.next(),
            _ => filter = Some(arg),
        }
    }

    let dir = tempfile::tempdir().unwrap();
    let fixture = Fixture::publish(dir.path());
    let mut b = Bench {
        filter,
        rows: Vec::new(),
    };
    println!(
        "{:<40} {:>10} {:>10} {:>7} {:>10} {:>11} {:>10}",
        "case", "min", "median", "spread", "allocs/op", "bytes/op", "peak"
    );
    fixture.consumer(&mut b);
    Fixture::producer(&mut b);

    let mut failed = false;
    if let Some(name) = &baseline {
        failed = compare(&b.rows, &baseline_path(name));
    }
    if let Some(name) = &save {
        let path = baseline_path(name);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let mut text = String::new();
        for r in &b.rows {
            writeln!(text, "{}\t{}\t{}\t{}", r.name, r.min_ns, r.allocs, r.peak).unwrap();
        }
        std::fs::write(&path, text).unwrap();
        println!("saved {}", path.display());
    }
    if failed {
        std::process::exit(1);
    }
}

/// A bundle shaped like a real one, and the keys to ask it about.
struct Fixture {
    dir: PathBuf,
    good: [u8; 32],
    bad: [u8; 32],
    miss: [u8; 32],
    good_purl: String,
    bad_purl: String,
    miss_purl: String,
}

/// A real SHA-256, so keys are as uniform as artifact digests are. A
/// patterned stand-in can alias in the bits the probes read and turn a miss
/// into a full-length hit.
fn digest(i: u32, tier: &str) -> [u8; 32] {
    Sha256::digest(format!("{tier}/{i}")).into()
}

fn purl(i: u32, tier: &str) -> String {
    format!(
        "pkg:npm/@bench-scope/{tier}-package-{i}@1.{}.{}",
        i % 97,
        i % 13
    )
}

fn records(n: u32, tier: &str) -> impl Iterator<Item = Record> {
    (0..n).map(move |i| Record {
        purl: Some(purl(i, tier)),
        sha256: Some(digest(i, tier)),
    })
}

fn sets_for(n: u32) -> KeySets {
    let mut sets = KeySets::new();
    for (tier, count) in [
        (Tier::Good, n),
        (Tier::Bad, n / 10),
        (Tier::SightedHostile, n / 100),
        (Tier::SightedSuspicious, n / 100),
    ] {
        for r in records(count, tier.as_str()) {
            sets.insert(tier, r);
        }
    }
    sets
}

impl Fixture {
    fn publish(dir: &Path) -> Self {
        write_bundle(
            dir,
            &sets_for(GOOD_KEYS).into_filters(1e-9),
            "2026-10-29",
            SCHEME,
        )
        .unwrap();
        Self {
            dir: dir.to_owned(),
            good: digest(7, Tier::Good.as_str()),
            bad: digest(7, Tier::Bad.as_str()),
            miss: digest(7, "absent"),
            good_purl: purl(7, Tier::Good.as_str()),
            bad_purl: purl(7, Tier::Bad.as_str()),
            miss_purl: purl(7, "absent"),
        }
    }

    fn consumer(&self, b: &mut Bench) {
        let dir = &self.dir;
        b.case("open", 1, || (), |()| Lookup::open(dir, SCHEME).unwrap());

        let lk = Lookup::open(dir, SCHEME).unwrap();
        let cases: [(&str, Artifact<'_>); 7] = [
            ("decide sha256 miss", Artifact::sha256(&self.miss)),
            ("decide sha256 skip", Artifact::sha256(&self.good)),
            ("decide sha256 known-bad", Artifact::sha256(&self.bad)),
            ("decide purl miss", Artifact::purl(&self.miss_purl)),
            ("decide purl known-bad", Artifact::purl(&self.bad_purl)),
            (
                "decide purl+sha256 miss",
                Artifact::purl(&self.miss_purl).and_sha256(&self.miss),
            ),
            (
                "decide purl+sha256 skip",
                Artifact::purl(&self.good_purl).and_sha256(&self.good),
            ),
        ];
        for (name, artifact) in cases {
            b.case(name, 1, || (), |()| lk.decide(&artifact));
        }

        b.case(
            "open + decide (one-shot process)",
            1,
            || (),
            |()| {
                Lookup::open(dir, SCHEME)
                    .unwrap()
                    .decide(&Artifact::sha256(&self.good))
            },
        );

        let hex = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f";
        b.case("parse_sha256_hex", 1, || (), |()| parse_sha256_hex(hex));

        let image = std::fs::read(dir.join("sha256-good.adbl")).unwrap();
        b.case(
            "Filter::load sha256-good",
            1,
            || image.clone(),
            |bytes| Filter::load(bytes).unwrap(),
        );
    }

    fn producer(b: &mut Bench) {
        let n = u64::from(GOOD_KEYS);
        let recs: Vec<Record> = records(GOOD_KEYS, "good").collect();
        b.case(
            "KeySets::insert, per record",
            n,
            || recs.clone(),
            |recs| {
                let mut sets = KeySets::new();
                for r in recs {
                    sets.insert(Tier::Good, r);
                }
                sets
            },
        );
        b.case(
            "KeySets::into_filters, per good key",
            n,
            || sets_for(GOOD_KEYS),
            |sets| sets.into_filters(1e-9),
        );
        let filters = sets_for(GOOD_KEYS).into_filters(1e-9);
        let out = tempfile::tempdir().unwrap();
        b.case(
            "write_bundle",
            1,
            || (),
            |()| write_bundle(out.path(), &filters, "2026-10-29", SCHEME).unwrap(),
        );
    }
}

fn format_row(r: &Row) -> String {
    format!(
        "{:<40} {:>10} {:>10} {:>6.0}% {:>10.1} {:>11} {:>10}",
        r.name,
        duration(r.min_ns),
        duration(r.median_ns),
        (r.median_ns / r.min_ns - 1.0) * 100.0,
        r.allocs,
        size(r.bytes),
        size(r.peak as f64),
    )
}

fn duration(ns: f64) -> String {
    match ns {
        n if n < 1e3 => format!("{n:.0} ns"),
        n if n < 1e6 => format!("{:.2} µs", n / 1e3),
        n if n < 1e9 => format!("{:.2} ms", n / 1e6),
        n => format!("{:.2} s", n / 1e9),
    }
}

fn size(bytes: f64) -> String {
    match bytes {
        b if b < 1024.0 => format!("{b:.0} B"),
        b if b < 1024.0 * 1024.0 => format!("{:.1} KiB", b / 1024.0),
        b => format!("{:.1} MiB", b / (1024.0 * 1024.0)),
    }
}

fn baseline_path(name: &str) -> PathBuf {
    let target =
        std::env::var_os("CARGO_TARGET_DIR").map_or_else(|| "target".into(), PathBuf::from);
    target.join("burton-bench").join(format!("{name}.tsv"))
}

/// Print each case against the baseline; true if any regressed.
fn compare(rows: &[Row], path: &Path) -> bool {
    let Ok(text) = std::fs::read_to_string(path) else {
        eprintln!("no baseline at {}", path.display());
        return true;
    };
    let base: BTreeMap<&str, (f64, f64, u64)> = text
        .lines()
        .filter_map(|line| {
            let mut f = line.split('\t');
            let name = f.next()?;
            let min = f.next()?.parse().ok()?;
            let allocs = f.next()?.parse().ok()?;
            let peak = f.next()?.parse().ok()?;
            Some((name, (min, allocs, peak)))
        })
        .collect();

    println!("\nagainst {}:", path.display());
    let mut regressed = false;
    for r in rows {
        let Some(&(min, allocs, peak)) = base.get(r.name.as_str()) else {
            continue;
        };
        let change = r.min_ns / min - 1.0;
        let mut why = Vec::new();
        if change > TIME_TOLERANCE {
            why.push("time");
        }
        if r.allocs > allocs {
            why.push("allocs");
        }
        if r.peak > peak {
            why.push("peak");
        }
        println!(
            "{:<40} {:>+6.1}%  allocs {} -> {}  peak {} -> {}{}",
            r.name,
            change * 100.0,
            allocs,
            r.allocs,
            size(peak as f64),
            size(r.peak as f64),
            if why.is_empty() {
                String::new()
            } else {
                format!("  REGRESSED: {}", why.join(", "))
            },
        );
        regressed |= !why.is_empty();
    }
    regressed
}
