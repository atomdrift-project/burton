//! Producing a bundle: set algebra, serialization, and the pre-publish checks.
//!
//! Which records earn which tier is policy and belongs to whoever owns the
//! corpus. A build is always a full rebuild, because bloom filters cannot
//! delete.

use std::collections::{BTreeMap, HashSet};
use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use crate::filter::{Builder, Filter, Kind, Tier, digest_of, stem};
use crate::manifest::{Entry, MANIFEST_FILE, MANIFEST_SCHEMA, Manifest};

/// One artifact from the pool. Either field may be absent; a record with
/// neither contributes nothing.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Record {
    /// The package coordinate, **already canonical**. Whatever produced it must
    /// be what the consumer uses; name it in [`write_bundle`]'s `key_scheme` so
    /// a mismatch is caught at open.
    pub purl: Option<String>,
    /// The 32-byte artifact digest.
    pub sha256: Option<[u8; 32]>,
}

impl Record {
    /// A record known by its package coordinate alone.
    #[must_use]
    pub fn purl(purl: impl Into<String>) -> Self {
        Self {
            purl: Some(purl.into()),
            sha256: None,
        }
    }

    /// A record known by its content digest alone.
    #[must_use]
    pub const fn sha256(digest: [u8; 32]) -> Self {
        Self {
            purl: None,
            sha256: Some(digest),
        }
    }
}

/// Deduplicated keys, one set per (kind, tier), accumulated as records stream
/// in. Keys are held as their 32-byte filter digests, so peak memory is 32
/// bytes per distinct key and does not grow with row count.
#[derive(Debug, Default)]
pub struct KeySets {
    /// `sets[kind][tier]`, as in [`crate::Lookup`].
    sets: [[HashSet<[u8; 32]>; Tier::ALL.len()]; Kind::ALL.len()],
}

// `subtract_claims_from_good` splits each row into good and the rest.
const _: () = assert!(Tier::Good.index() == 0, "Good must lead every slot row");

impl KeySets {
    /// An empty accumulator.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert one record under `tier`. Each key present joins its set;
    /// duplicates collapse.
    pub fn insert(&mut self, tier: Tier, record: Record) {
        if let Some(purl) = record.purl {
            self.sets[Kind::Purl.index()][tier.index()].insert(digest_of(purl.as_bytes()));
        }
        if let Some(sha) = record.sha256 {
            self.sets[Kind::Sha256.index()][tier.index()].insert(sha);
        }
    }

    /// Distinct keys of `kind` held for `tier`, before claims are subtracted
    /// from `good`.
    #[must_use]
    pub fn count(&self, kind: Kind, tier: Tier) -> usize {
        self.sets[kind.index()][tier.index()].len()
    }

    /// Build one filter per (kind, tier): the complete set [`write_bundle`]
    /// requires.
    ///
    /// `good` is first reduced by every other tier: worst pool wins, and the
    /// weakest claim is enough. A lone unadjudicated citation cannot convict —
    /// hence its own tier rather than `bad` — but is ample reason to scan.
    ///
    /// [`crate::Lookup`] applies the same ordering at query time. Both exist
    /// because they fail differently: subtraction cannot help when the files on
    /// disk were built at different times, and the query-time rule cannot shrink
    /// a filter that already carries a key it should not.
    ///
    /// `target_fp` above `1e-3` is clamped to it, since a looser filter would
    /// fail [`Filter::load`]'s false-positive bound; one that is not a positive
    /// number builds at `1e-9`.
    #[must_use]
    pub fn into_filters(mut self, target_fp: f64) -> Vec<Filter> {
        self.subtract_claims_from_good();
        let mut out = Vec::with_capacity(Kind::ALL.len() * Tier::ALL.len());
        for tier in Tier::ALL {
            for kind in Kind::ALL {
                let keys = &self.sets[kind.index()][tier.index()];
                let mut b = Builder::new(kind, tier, keys.len() as u64, target_fp);
                for digest in keys {
                    b.insert_digest(digest);
                }
                out.push(b.build());
            }
        }
        out
    }

    fn subtract_claims_from_good(&mut self) {
        for row in &mut self.sets {
            let [good, claims @ ..] = row;
            good.retain(|k| !claims.iter().any(|c| c.contains(k)));
        }
    }
}

/// Write every filter to `<dir>/<stem>.adbl`, then the manifest naming them.
///
/// `filters` must hold exactly one filter for every (kind, tier), as
/// [`KeySets::into_filters`] returns: a bundle missing one would be refused
/// by every reader, so it is refused here before anything is written.
///
/// Each file is written to a fresh temporary name, synced, and renamed into
/// place, so no reader ever sees a partly written file. The filters' renames
/// are made durable before the manifest is replaced, so after a crash the
/// manifest never names filters that were lost. Files are still replaced one
/// at a time: to swap a live bundle as a whole, write into a fresh directory
/// and rename that. Write a directory from one process at a time.
///
/// `key_scheme` is recorded so a consumer using a different one fails at open
/// instead of matching nothing. Run [`verify`] first: nothing here does.
///
/// # Errors
/// [`WriteError::FilterCount`] unless every (kind, tier) has exactly one
/// filter; otherwise any file that cannot be written, or a manifest that
/// cannot be serialized.
pub fn write_bundle(
    dir: impl AsRef<Path>,
    filters: &[Filter],
    built: &str,
    key_scheme: &str,
) -> Result<Manifest, WriteError> {
    let dir = dir.as_ref();
    let mut counts = [[0usize; Tier::ALL.len()]; Kind::ALL.len()];
    for f in filters {
        counts[f.kind().index()][f.tier().index()] += 1;
    }
    for kind in Kind::ALL {
        for tier in Tier::ALL {
            let count = counts[kind.index()][tier.index()];
            if count != 1 {
                return Err(WriteError::FilterCount {
                    stem: stem(kind, tier).to_owned(),
                    count,
                });
            }
        }
    }

    let mut entries = BTreeMap::new();
    for filter in filters {
        let stem = filter.stem();
        let file = format!("{stem}.adbl");
        write_atomic(dir, &file, filter.as_bytes())?;
        entries.insert(
            stem.to_owned(),
            Entry {
                sha256: crate::hex(&digest_of(filter.as_bytes())),
                n: filter.len(),
                file,
            },
        );
    }
    sync_dir(dir)?;
    let manifest = Manifest {
        schema: MANIFEST_SCHEMA,
        built: built.to_owned(),
        key_scheme: key_scheme.to_owned(),
        provenance: toml::Table::new(),
        filter: entries,
    };
    let text = toml::to_string(&manifest).map_err(|source| WriteError::Serialize { source })?;
    write_atomic(dir, MANIFEST_FILE, text.as_bytes())?;
    sync_dir(dir)?;
    Ok(manifest)
}

/// Write `bytes` to `dir/file`: to a temporary file beside it, synced, then
/// renamed over it.
///
/// The temporary file is hidden and named for this process. No live process
/// can own that name, so anything already there was left by a crash under a
/// reused process id, or planted: it is unlinked, which never follows a
/// symlink, and the file is created only if nothing has taken the name since.
fn write_atomic(dir: &Path, file: &str, bytes: &[u8]) -> Result<(), WriteError> {
    let path = dir.join(file);
    let tmp = dir.join(format!(".{file}.{}.tmp", std::process::id()));
    let io_err = |source| WriteError::Io {
        path: path.clone(),
        source,
    };

    if let Err(e) = std::fs::remove_file(&tmp)
        && e.kind() != io::ErrorKind::NotFound
    {
        return Err(io_err(e));
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&tmp)
        .map_err(io_err)?;
    let synced = file.write_all(bytes).and_then(|()| file.sync_all());
    drop(file);
    synced
        .and_then(|()| std::fs::rename(&tmp, &path))
        .map_err(|source| {
            // Best effort: the error being reported is the write's, not this.
            let _ = std::fs::remove_file(&tmp);
            io_err(source)
        })
}

/// Make the renames into `dir` durable. Unix syncs a directory like a file;
/// std offers no way to on Windows, where a rename is only atomic.
fn sync_dir(dir: &Path) -> Result<(), WriteError> {
    if cfg!(unix) {
        File::open(dir)
            .and_then(|d| d.sync_all())
            .map_err(|source| WriteError::Io {
                path: dir.to_owned(),
                source,
            })?;
    }
    Ok(())
}

/// Why a bundle could not be written.
#[derive(Debug)]
pub enum WriteError {
    /// A file could not be written.
    Io {
        /// The file being written.
        path: PathBuf,
        /// What went wrong.
        source: io::Error,
    },
    /// The manifest could not be serialized.
    Serialize {
        /// What went wrong.
        source: toml::ser::Error,
    },
    /// A (kind, tier) has no filter, or more than one. Nothing was written.
    FilterCount {
        /// The slot's stem.
        stem: String,
        /// How many filters were given for it.
        count: usize,
    },
}

impl fmt::Display for WriteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { path, source } => write!(f, "writing {}: {source}", path.display()),
            Self::Serialize { source } => write!(f, "serializing the manifest: {source}"),
            Self::FilterCount { stem, count } => {
                write!(f, "bundle needs exactly one {stem} filter, got {count}")
            }
        }
    }
}

impl std::error::Error for WriteError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            Self::Serialize { source } => Some(source),
            Self::FilterCount { .. } => None,
        }
    }
}

// --- Checks that run before anything is published ---------------------------
//
// A bundle is published unattended and cannot be edited after the fact. These
// run on the freshly built filters, before anything is written, so a violation
// leaves the last good build in place.

/// A digest that must never land in a given tier.
struct Canary {
    sha256: [u8; 32],
    forbidden: Tier,
}

/// Checked on every build. A handful catch the catastrophic mislabel that a
/// silent rebuild would otherwise carry all the way to a skip.
const CANARIES: &[Canary] = &[
    // EICAR is benign by construction, but every scanner is expected to treat
    // it as hostile. It must never be blessed. SHA-256
    // 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f.
    Canary {
        sha256: [
            0x27, 0x5a, 0x02, 0x1b, 0xbf, 0xb6, 0x48, 0x9e, 0x54, 0xd4, 0x71, 0x89, 0x9f, 0x7d,
            0xb9, 0xd1, 0x66, 0x3f, 0xc6, 0x95, 0xec, 0x2f, 0xe2, 0xa2, 0xc4, 0x53, 0x8a, 0xab,
            0xf6, 0x51, 0xfd, 0x0f,
        ],
        forbidden: Tier::Good,
    },
];

/// Below this, ratio bounds mean nothing; only the collapse guard applies.
const RATIO_FLOOR: u64 = 1_000;
/// Fail if a filter falls below this fraction of its previous size…
const MAX_SHRINK: f64 = 0.5;
/// …or grows past this multiple. Together they catch a corrupt export without
/// anyone maintaining expected counts by hand.
const MAX_GROWTH: f64 = 3.0;

/// Whether [`verify`] enforces the key-count ratio bounds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ratio {
    /// A breach is fatal. The default, and right for unattended builds.
    Enforce,
    /// A breach is returned rather than fatal, for an operator deliberately
    /// changing a tier's rule, where the large step *is* the change.
    Waive,
}

/// Why a freshly built bundle must not be published.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyError {
    /// A canary digest landed in a tier it must never be in.
    Canary {
        /// The digest, in hex.
        sha256: String,
        /// The stem it was found in.
        stem: String,
    },
    /// A digest the caller vouched for is in an adverse tier.
    Vouched {
        /// The caller's label for it, such as a path.
        label: String,
        /// The stem it was found in.
        stem: String,
    },
    /// A filter that had keys now has none.
    Collapsed {
        /// The filter's stem.
        stem: String,
        /// How many keys it held last build.
        was: u64,
    },
    /// A filter's key count moved further than the bounds allow.
    Ratio(RatioBreach),
}

/// A filter whose key count moved further than the ratio bounds allow: fatal
/// under [`Ratio::Enforce`], returned by [`verify`] under [`Ratio::Waive`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RatioBreach {
    /// The filter's stem.
    pub stem: String,
    /// How many keys it held last build.
    pub was: u64,
    /// How many it holds now.
    pub now: u64,
}

impl fmt::Display for RatioBreach {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self { stem, was, now } = self;
        if now < was {
            write!(
                f,
                "{stem} shrank to {now} keys from {was} ({:.0}% of previous, floor {:.0}%)",
                ratio(*now, *was) * 100.0,
                MAX_SHRINK * 100.0
            )
        } else {
            write!(
                f,
                "{stem} grew to {now} keys from {was} ({:.1}x previous, ceiling {MAX_GROWTH:.1}x)",
                ratio(*now, *was)
            )
        }
    }
}

impl fmt::Display for VerifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Canary { sha256, stem } => {
                write!(f, "canary {sha256} is in {stem} and must never be")
            }
            Self::Vouched { label, stem } => write!(f, "known-good {label} is in {stem}"),
            Self::Collapsed { stem, was } => {
                write!(f, "{stem} collapsed to 0 keys (was {was})")
            }
            Self::Ratio(breach) => breach.fmt(f),
        }
    }
}

impl std::error::Error for VerifyError {}

/// Refuse to publish a bundle that looks poisoned or truncated.
///
/// 1. No canary digest (EICAR, for one) is in its forbidden tier.
/// 2. No digest in `vouched` — `(label, digest)` pairs for artifacts the
///    caller asserts are ubiquitously benign, such as the build host's
///    `/bin/ls` — is in any adverse tier, since any of them denies a skip.
/// 3. No filter that had keys is missing or collapsed to zero, and none moved
///    past the ratio bounds.
///
/// [`Ratio::Waive`] downgrades **only** the ratio bounds. Canaries, vouched
/// digests, and the collapse guard stay fatal. The breaches it waives are
/// returned, not swallowed; under [`Ratio::Enforce`] there are none.
///
/// # Errors
/// The first violation found.
pub fn verify(
    filters: &[Filter],
    prev: Option<&Manifest>,
    vouched: &[(String, [u8; 32])],
    policy: Ratio,
) -> Result<Vec<RatioBreach>, VerifyError> {
    let digests = |tier: Tier| {
        filters
            .iter()
            .filter(move |f| f.kind() == Kind::Sha256 && f.tier() == tier)
    };

    for c in CANARIES {
        if let Some(f) = digests(c.forbidden).find(|f| f.may_contain(&c.sha256)) {
            return Err(VerifyError::Canary {
                sha256: crate::hex(&c.sha256),
                stem: f.stem().to_owned(),
            });
        }
    }

    for tier in Tier::ALL.into_iter().filter(|t| *t != Tier::Good) {
        for f in digests(tier) {
            if let Some((label, _)) = vouched.iter().find(|(_, d)| f.may_contain(d)) {
                return Err(VerifyError::Vouched {
                    label: label.clone(),
                    stem: f.stem().to_owned(),
                });
            }
        }
    }

    let mut waived = Vec::new();
    let Some(prev) = prev else {
        return Ok(waived);
    };
    // A filter gone from the build entirely is the most complete collapse.
    if let Some((stem, entry)) = prev
        .filter
        .iter()
        .find(|(stem, entry)| entry.n > 0 && !filters.iter().any(|f| f.stem() == *stem))
    {
        return Err(VerifyError::Collapsed {
            stem: stem.clone(),
            was: entry.n,
        });
    }
    for f in filters {
        let stem = f.stem();
        let Some(was) = prev.filter.get(stem).map(|e| e.n) else {
            continue;
        };
        let now = f.len();
        if was > 0 && now == 0 {
            return Err(VerifyError::Collapsed {
                stem: stem.to_owned(),
                was,
            });
        }
        if was < RATIO_FLOOR {
            continue;
        }
        if (MAX_SHRINK..=MAX_GROWTH).contains(&ratio(now, was)) {
            continue;
        }
        let breach = RatioBreach {
            stem: stem.to_owned(),
            was,
            now,
        };
        match policy {
            Ratio::Waive => waived.push(breach),
            Ratio::Enforce => return Err(VerifyError::Ratio(breach)),
        }
    }
    Ok(waived)
}

/// `now` as a fraction of `was`.
#[expect(clippy::cast_precision_loss, reason = "key counts are far below 2^53")]
fn ratio(now: u64, was: u64) -> f64 {
    now as f64 / was as f64
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    fn digest(tag: u8) -> [u8; 32] {
        let mut d = [0u8; 32];
        d[0] = tag;
        d
    }

    fn sets(rows: &[(Tier, Record)]) -> KeySets {
        let mut s = KeySets::new();
        for (tier, r) in rows {
            s.insert(*tier, r.clone());
        }
        s
    }

    fn rec(d: [u8; 32]) -> Record {
        Record::sha256(d)
    }

    fn find<'a>(filters: &'a [Filter], stem: &str) -> &'a Filter {
        filters.iter().find(|f| f.stem() == stem).unwrap()
    }

    #[test]
    fn a_bundle_holds_every_kind_and_tier() {
        let filters = KeySets::new().into_filters(1e-9);
        assert_eq!(filters.len(), Kind::ALL.len() * Tier::ALL.len());
        for kind in Kind::ALL {
            for tier in Tier::ALL {
                let stem = format!("{}-{}", kind.as_str(), tier.as_str());
                assert!(filters.iter().any(|f| f.stem() == stem), "missing {stem}");
            }
        }
    }

    #[test]
    fn every_claim_subtracts_from_good() {
        // Each of these is also blessed. Good must lose every time.
        let claimed = [Tier::Bad, Tier::SightedHostile, Tier::SightedSuspicious];
        let mut rows = vec![(Tier::Good, rec(digest(9)))];
        for (i, tier) in claimed.iter().enumerate() {
            let d = digest(u8::try_from(i).unwrap());
            rows.push((Tier::Good, rec(d)));
            rows.push((*tier, rec(d)));
        }
        let filters = sets(&rows).into_filters(1e-9);
        let good = find(&filters, "sha256-good");
        assert_eq!(good.len(), 1, "only the unclaimed key should be blessed");
        assert!(good.may_contain(&digest(9)));
        for (i, tier) in claimed.iter().enumerate() {
            let d = digest(u8::try_from(i).unwrap());
            assert!(!good.may_contain(&d), "{tier:?} key survived in good");
        }
    }

    #[test]
    fn claims_subtract_purls_from_good_too() {
        let filters = sets(&[
            (Tier::Good, Record::purl("pkg:npm/a@1")),
            (Tier::Good, Record::purl("pkg:npm/b@1")),
            (Tier::SightedSuspicious, Record::purl("pkg:npm/b@1")),
        ])
        .into_filters(1e-9);
        let good = find(&filters, "purl-good");
        assert_eq!(good.len(), 1);
        assert!(good.may_contain(&digest_of(b"pkg:npm/a@1")));
        assert!(!good.may_contain(&digest_of(b"pkg:npm/b@1")));
    }

    #[test]
    fn write_and_reopen_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let filters =
            sets(&[(Tier::Good, rec(digest(4))), (Tier::Bad, rec(digest(5)))]).into_filters(1e-9);
        let m = write_bundle(dir.path(), &filters, "2026-08-31", "test/v1").unwrap();

        assert_eq!(m.schema, MANIFEST_SCHEMA);
        assert_eq!(m.key_scheme, "test/v1");
        assert_eq!(m.filter.len(), filters.len());
        assert_eq!(crate::read_manifest(dir.path()).unwrap().as_ref(), Some(&m));

        let lk = crate::Lookup::open(dir.path(), "test/v1").unwrap();
        assert!(lk.may_skip(&crate::Artifact::sha256(&digest(4))));
        assert_eq!(
            lk.decide(&crate::Artifact::sha256(&digest(5))),
            crate::Decision::KnownBad
        );
    }

    #[test]
    fn writing_leaves_no_temporary_files() {
        let dir = tempfile::tempdir().unwrap();
        let filters = KeySets::new().into_filters(1e-9);
        write_bundle(dir.path(), &filters, "2026-08-31", "test/v1").unwrap();
        write_bundle(dir.path(), &filters, "2026-09-01", "test/v1").unwrap();
        let mut names: Vec<String> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        names.sort();
        let mut want: Vec<String> = filters
            .iter()
            .map(|f| format!("{}.adbl", f.stem()))
            .chain([MANIFEST_FILE.to_owned()])
            .collect();
        want.sort();
        assert_eq!(names, want);
    }

    /// A symlink planted at the temporary name, to make the writer clobber a
    /// file outside the bundle, is not followed.
    #[cfg(unix)]
    #[test]
    fn a_planted_temporary_file_is_not_followed() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("precious");
        std::fs::write(&target, "untouched").unwrap();
        let planted = dir
            .path()
            .join(format!(".purl-good.adbl.{}.tmp", std::process::id()));
        std::os::unix::fs::symlink(&target, &planted).unwrap();

        let filters = KeySets::new().into_filters(1e-9);
        write_bundle(dir.path(), &filters, "2026-08-31", "test/v1").unwrap();
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "untouched");
        assert!(crate::Lookup::open(dir.path(), "test/v1").is_ok());
    }

    /// A crash leaves its temporary file behind. Under a reused process id —
    /// every run, in a container — the next write must not fail on it.
    #[test]
    fn a_stale_temporary_file_does_not_block_the_next_write() {
        let dir = tempfile::tempdir().unwrap();
        let stale = dir
            .path()
            .join(format!(".{MANIFEST_FILE}.{}.tmp", std::process::id()));
        std::fs::write(&stale, "half a manifest").unwrap();

        let filters = KeySets::new().into_filters(1e-9);
        write_bundle(dir.path(), &filters, "2026-08-31", "test/v1").unwrap();
        assert!(!stale.exists());
        assert!(crate::Lookup::open(dir.path(), "test/v1").is_ok());
    }

    #[test]
    fn a_failed_write_names_the_file() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("no-such-dir");
        let filters = KeySets::new().into_filters(1e-9);
        let err = write_bundle(&missing, &filters, "2026-08-31", "test/v1").unwrap_err();
        assert!(err.to_string().contains("no-such-dir"), "{err}");
        assert!(std::error::Error::source(&err).is_some());
    }

    /// Every reader refuses a bundle that is missing a slot or names one
    /// twice, so the writer refuses it first and writes nothing.
    #[test]
    fn a_bundle_needs_exactly_one_filter_per_slot() {
        let dir = tempfile::tempdir().unwrap();
        let mut filters = KeySets::new().into_filters(1e-9);
        let at = filters
            .iter()
            .position(|f| f.stem() == "sha256-sighted-suspicious")
            .unwrap();
        let dropped = filters.remove(at);

        let err = write_bundle(dir.path(), &filters, "2026-08-31", "test/v1").unwrap_err();
        assert!(
            matches!(&err, WriteError::FilterCount { stem, count: 0 }
                if stem == "sha256-sighted-suspicious"),
            "{err:?}"
        );

        filters.push(dropped);
        filters.push(KeySets::new().into_filters(1e-9).swap_remove(0));
        let err = write_bundle(dir.path(), &filters, "2026-08-31", "test/v1").unwrap_err();
        assert!(
            matches!(err, WriteError::FilterCount { count: 2, .. }),
            "{err:?}"
        );
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
    }

    #[test]
    fn manifest_sha256_matches_the_bytes_written() {
        let dir = tempfile::tempdir().unwrap();
        let filters = sets(&[(Tier::Good, rec(digest(6)))]).into_filters(1e-9);
        let m = write_bundle(dir.path(), &filters, "2026-08-31", "test/v1").unwrap();
        for entry in m.filter.values() {
            let bytes = std::fs::read(dir.path().join(&entry.file)).unwrap();
            assert_eq!(
                crate::hex(&digest_of(&bytes)),
                entry.sha256,
                "{}",
                entry.file
            );
        }
    }

    #[test]
    fn the_canary_is_eicar() {
        let eicar = CANARIES.first().unwrap();
        assert_eq!(
            crate::hex(&eicar.sha256),
            "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
        );
    }

    #[test]
    fn a_blessed_canary_is_refused() {
        let eicar = CANARIES.first().unwrap().sha256;
        let filters = sets(&[(Tier::Good, rec(eicar))]).into_filters(1e-9);
        assert!(matches!(
            verify(&filters, None, &[], Ratio::Enforce),
            Err(VerifyError::Canary { .. })
        ));
    }

    #[test]
    fn a_vouched_digest_in_any_adverse_tier_is_refused() {
        for tier in [Tier::Bad, Tier::SightedHostile, Tier::SightedSuspicious] {
            let filters = sets(&[(tier, rec(digest(7)))]).into_filters(1e-9);
            let vouched = [("/bin/ls".to_owned(), digest(7))];
            let err = verify(&filters, None, &vouched, Ratio::Enforce).unwrap_err();
            assert_eq!(
                err,
                VerifyError::Vouched {
                    label: "/bin/ls".to_owned(),
                    stem: format!("sha256-{}", tier.as_str()),
                },
            );
            assert!(err.to_string().contains("/bin/ls"), "{err}");
        }
    }

    /// A manifest describing `n` keys per stem, for the ratio checks.
    fn baseline(counts: &[(&str, u64)]) -> Manifest {
        Manifest {
            schema: MANIFEST_SCHEMA,
            built: "2026-08-30".to_owned(),
            key_scheme: "test/v1".to_owned(),
            provenance: toml::Table::new(),
            filter: counts
                .iter()
                .map(|(stem, n)| {
                    (
                        (*stem).to_owned(),
                        Entry {
                            file: format!("{stem}.adbl"),
                            sha256: String::new(),
                            n: *n,
                        },
                    )
                })
                .collect(),
        }
    }

    #[test]
    fn duplicate_records_collapse() {
        let mut sets = KeySets::new();
        for _ in 0..10 {
            sets.insert(
                Tier::Good,
                Record {
                    purl: Some("pkg:npm/x@1".to_owned()),
                    sha256: Some(digest(1)),
                },
            );
        }
        assert_eq!(sets.count(Kind::Purl, Tier::Good), 1);
        assert_eq!(sets.count(Kind::Sha256, Tier::Good), 1);
        let filters = sets.into_filters(1e-9);
        assert_eq!(find(&filters, "sha256-good").len(), 1);
        assert_eq!(find(&filters, "purl-good").len(), 1);
    }

    #[test]
    fn a_record_keys_only_the_fields_it_has() {
        let mut sets = KeySets::new();
        sets.insert(Tier::Good, Record::purl("pkg:npm/x@1"));
        sets.insert(Tier::Good, rec(digest(2)));
        sets.insert(Tier::Good, Record::default());
        assert_eq!(sets.count(Kind::Purl, Tier::Good), 1);
        assert_eq!(sets.count(Kind::Sha256, Tier::Good), 1);
    }

    #[test]
    fn verify_passes_a_clean_build() {
        let filters =
            sets(&[(Tier::Good, rec(digest(1))), (Tier::Bad, rec(digest(2)))]).into_filters(1e-9);
        assert_eq!(verify(&filters, None, &[], Ratio::Enforce), Ok(vec![]));
    }

    /// Both ends of the ratio band, and the middle that must pass.
    #[test]
    fn the_ratio_band_catches_both_directions() {
        let rows: Vec<(Tier, Record)> = (0..=255u8).map(|i| (Tier::Bad, rec(digest(i)))).collect();
        let filters = sets(&rows).into_filters(1e-9); // 256 keys

        let prev = baseline(&[("sha256-bad", 1_000)]);
        let err = verify(&filters, Some(&prev), &[], Ratio::Enforce).unwrap_err();
        assert!(err.to_string().contains("shrank to 256"), "{err}");

        // 80 is under RATIO_FLOOR, so the ratios do not apply at all.
        let prev = baseline(&[("sha256-bad", 80)]);
        assert_eq!(
            verify(&filters, Some(&prev), &[], Ratio::Enforce),
            Ok(vec![])
        );

        // A growth breach needs a previous count at or above the floor.
        let many: Vec<(Tier, Record)> = (0..8_000u32)
            .map(|i| {
                let mut d = [0u8; 32];
                d[0..4].copy_from_slice(&i.to_le_bytes());
                (Tier::Bad, rec(d))
            })
            .collect();
        let prev = baseline(&[("sha256-bad", 2_000)]);
        let grown = sets(&many).into_filters(1e-9); // 8000/2000 = 4x
        let err = verify(&grown, Some(&prev), &[], Ratio::Enforce).unwrap_err();
        let VerifyError::Ratio(RatioBreach {
            was: 2_000,
            now: 8_000,
            ..
        }) = &err
        else {
            panic!("expected a ratio breach, got {err:?}");
        };
        assert!(err.to_string().contains("grew to 8000"), "{err}");

        // In band: 3000 from 2000 is 1.5x.
        let mid: Vec<(Tier, Record)> = many.into_iter().take(3_000).collect();
        assert_eq!(
            verify(
                &sets(&mid).into_filters(1e-9),
                Some(&prev),
                &[],
                Ratio::Enforce
            ),
            Ok(vec![])
        );
    }

    #[test]
    fn a_collapse_is_fatal_even_with_the_override() {
        let filters = KeySets::new().into_filters(1e-9);
        let prev = baseline(&[("sha256-good", 10_000)]);
        for ratio in [Ratio::Enforce, Ratio::Waive] {
            let err = verify(&filters, Some(&prev), &[], ratio).unwrap_err();
            assert_eq!(
                err,
                VerifyError::Collapsed {
                    stem: "sha256-good".to_owned(),
                    was: 10_000
                }
            );
        }
    }

    /// A filter missing from the build has collapsed as surely as an empty
    /// one, whether or not the override is set.
    #[test]
    fn a_vanished_filter_is_a_collapse() {
        let filters: Vec<Filter> = KeySets::new()
            .into_filters(1e-9)
            .into_iter()
            .filter(|f| f.stem() != "purl-bad")
            .collect();
        let prev = baseline(&[("purl-bad", 5)]);
        for ratio in [Ratio::Enforce, Ratio::Waive] {
            assert_eq!(
                verify(&filters, Some(&prev), &[], ratio),
                Err(VerifyError::Collapsed {
                    stem: "purl-bad".to_owned(),
                    was: 5
                })
            );
        }
        // One that held nothing before has lost nothing.
        let prev = baseline(&[("purl-bad", 0)]);
        assert_eq!(
            verify(&filters, Some(&prev), &[], Ratio::Enforce),
            Ok(vec![])
        );
    }

    #[test]
    fn the_override_waives_a_ratio_breach_but_reports_it() {
        let rows: Vec<(Tier, Record)> = (0..2_000)
            .map(|i| (Tier::Good, rec(digest(u8::try_from(i % 256).unwrap()))))
            .collect();
        let filters = sets(&rows).into_filters(1e-9);
        let prev = baseline(&[("sha256-good", 100_000)]);

        // 2,000 rows, 256 distinct digests.
        let breach = RatioBreach {
            stem: "sha256-good".to_owned(),
            was: 100_000,
            now: 256,
        };
        assert_eq!(
            verify(&filters, Some(&prev), &[], Ratio::Enforce),
            Err(VerifyError::Ratio(breach.clone()))
        );
        assert_eq!(
            verify(&filters, Some(&prev), &[], Ratio::Waive),
            Ok(vec![breach])
        );
    }

    #[test]
    fn small_filters_swing_freely() {
        let filters = sets(&[(Tier::Bad, rec(digest(8)))]).into_filters(1e-9);
        let prev = baseline(&[("sha256-bad", 900)]);
        assert_eq!(
            verify(&filters, Some(&prev), &[], Ratio::Enforce),
            Ok(vec![])
        );
    }
}
