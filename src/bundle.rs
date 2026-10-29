//! Producing a bundle: set algebra, serialization, and the pre-publish checks.
//!
//! Which records earn which tier is policy and belongs to whoever owns the
//! corpus. A build is always a full rebuild, because bloom filters cannot
//! delete.

use std::collections::{BTreeMap, HashSet};
use std::fmt;
use std::fs::{File, Metadata};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::filter::{
    Builder, Filter, Kind, SUPPORTED_VERSIONS, Tier, UnsupportedVersion, digest_of,
};
use crate::lookup::OpenError;

/// The file naming a bundle's contents. Read by [`crate::Lookup::open`].
pub const MANIFEST_FILE: &str = "bloom.toml";

/// Manifest layout version. Bump on an incompatible manifest change.
pub const MANIFEST_SCHEMA: u32 = 1;

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

    /// Deduplicated `(purl, sha256)` key counts for one tier, before subtraction.
    #[must_use]
    pub fn counts(&self, tier: Tier) -> (usize, usize) {
        (
            self.sets[Kind::Purl.index()][tier.index()].len(),
            self.sets[Kind::Sha256.index()][tier.index()].len(),
        )
    }

    /// Build one filter per (kind, tier), at this build's format version.
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

    /// Build a bundle for an older format version, folding tiers it cannot
    /// carry.
    ///
    /// v1 has no `sighted` vocabulary, so `sighted-hostile` merges into `bad` —
    /// v1's own semantics, where a corroborated citation *was* a bad key.
    /// `sighted-suspicious` is dropped: a v1 client cannot tell a lone
    /// prediction from a measured verdict, so folding it in would read as bad.
    ///
    /// # Errors
    /// [`UnsupportedVersion`] for a version outside [`SUPPORTED_VERSIONS`].
    pub fn into_filters_for(
        mut self,
        version: u16,
        target_fp: f64,
    ) -> Result<Vec<Filter>, UnsupportedVersion> {
        if !SUPPORTED_VERSIONS.contains(&version) {
            return Err(UnsupportedVersion(version));
        }
        if version < Tier::SightedHostile.min_format_version() {
            for row in &mut self.sets {
                let hostile = std::mem::take(&mut row[Tier::SightedHostile.index()]);
                row[Tier::Bad.index()].extend(hostile);
                row[Tier::SightedSuspicious.index()].clear();
            }
        }
        Ok(self
            .into_filters(target_fp)
            .into_iter()
            .filter_map(|f| f.stamped_as(version))
            .collect())
    }

    fn subtract_claims_from_good(&mut self) {
        for row in &mut self.sets {
            let [good, claims @ ..] = row;
            good.retain(|k| !claims.iter().any(|c| c.contains(k)));
        }
    }
}

/// One filter's entry in the manifest.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Entry {
    /// File name within the bundle directory, e.g. `purl-good.adbl`. A bare
    /// name: [`crate::Lookup::open`] refuses anything with a path in it.
    pub file: String,
    /// Lowercase hex SHA-256 of the file, for an installer to verify a
    /// download against.
    pub sha256: String,
    /// The layout version this file was written with.
    pub format_version: u16,
    /// Keys inserted. Informational.
    pub n: u64,
}

/// The contract between producing a bundle and opening one.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Manifest {
    /// Manifest layout version ([`MANIFEST_SCHEMA`]).
    pub schema: u32,
    /// Build date, `YYYY-MM-DD`.
    pub built: String,
    /// The key canonicalization that produced this bundle's keys. `None` in
    /// bundles predating the field, which [`crate::Lookup::open`] accepts: a
    /// bundle stating nothing cannot contradict the caller.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_scheme: Option<String>,
    /// One entry per filter, keyed by stem (`purl-good`, …).
    pub filter: BTreeMap<String, Entry>,
}

/// Write every filter to `<dir>/<stem>.adbl`, then the manifest naming them.
///
/// Each file is written to a temporary name, synced, and renamed into place,
/// so no reader ever sees a partly written file and the manifest is replaced
/// last. Files are still replaced one at a time: to swap a live bundle as a
/// whole, write into a fresh directory and rename that.
///
/// `key_scheme` is recorded so a consumer using a different one fails at open
/// instead of matching nothing. Run [`verify`] first: nothing here does.
///
/// # Errors
/// Any file that cannot be written, or a manifest that cannot be serialized.
pub fn write_bundle(
    dir: &Path,
    filters: &[Filter],
    built: &str,
    key_scheme: &str,
) -> Result<Manifest, WriteError> {
    let mut entries = BTreeMap::new();
    for filter in filters {
        let stem = filter.stem();
        let file = format!("{stem}.adbl");
        write_atomic(&dir.join(&file), filter.as_bytes())?;
        entries.insert(
            stem,
            Entry {
                sha256: crate::hex(&digest_of(filter.as_bytes())),
                // The filter's own version, not this build's: a bundle
                // projected down for older clients writes older headers.
                format_version: filter.version(),
                n: filter.len(),
                file,
            },
        );
    }
    let manifest = Manifest {
        schema: MANIFEST_SCHEMA,
        built: built.to_owned(),
        key_scheme: Some(key_scheme.to_owned()),
        filter: entries,
    };
    let text = toml::to_string(&manifest).map_err(|source| WriteError::Serialize { source })?;
    write_atomic(&dir.join(MANIFEST_FILE), text.as_bytes())?;
    Ok(manifest)
}

/// Write `bytes` beside `path`, sync, and rename over it.
fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), WriteError> {
    let tmp = path.with_extension("tmp");
    let written = File::create(&tmp)
        .and_then(|mut f| {
            f.write_all(bytes)?;
            f.sync_all()
        })
        .and_then(|()| std::fs::rename(&tmp, path));
    written.map_err(|source| {
        // Best effort: the error being reported is the write's, not this.
        let _ = std::fs::remove_file(&tmp);
        WriteError::Io {
            path: path.to_owned(),
            source,
        }
    })
}

/// Read the manifest in `dir`, typically a previous build to size a new one
/// against.
///
/// `Ok(None)` only when there is no manifest. One that exists but cannot be
/// read or parsed is an error: treating it as "no baseline" would silently
/// switch off [`verify`]'s collapse and ratio checks.
///
/// # Errors
/// [`OpenError::Io`], [`OpenError::Parse`], or [`OpenError::Schema`].
pub fn read_manifest(dir: &Path) -> Result<Option<Manifest>, OpenError> {
    match load_manifest(dir) {
        Err(OpenError::Io { source, .. }) if source.kind() == io::ErrorKind::NotFound => Ok(None),
        other => other.map(|(manifest, _)| Some(manifest)),
    }
}

/// Read, parse, and schema-check the manifest in `dir`, with the metadata of
/// the very file read.
pub(crate) fn load_manifest(dir: &Path) -> Result<(Manifest, Metadata), OpenError> {
    let path = dir.join(MANIFEST_FILE);
    let read = File::open(&path).and_then(|mut f| {
        let meta = f.metadata()?;
        let mut text = String::with_capacity(usize::try_from(meta.len()).unwrap_or(0));
        f.read_to_string(&mut text)?;
        Ok((text, meta))
    });
    let (text, meta) = match read {
        Ok(read) => read,
        Err(source) => return Err(OpenError::Io { path, source }),
    };
    let manifest: Manifest = match toml::from_str(&text) {
        Ok(m) => m,
        Err(source) => {
            return Err(OpenError::Parse {
                path,
                source: Box::new(source),
            });
        }
    };
    if manifest.schema != MANIFEST_SCHEMA {
        return Err(OpenError::Schema {
            path,
            found: manifest.schema,
        });
    }
    Ok((manifest, meta))
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
}

impl fmt::Display for WriteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { path, source } => write!(f, "writing {}: {source}", path.display()),
            Self::Serialize { source } => write!(f, "serializing the manifest: {source}"),
        }
    }
}

impl std::error::Error for WriteError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            Self::Serialize { source } => Some(source),
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
    Ratio {
        /// The filter's stem.
        stem: String,
        /// How many keys it held last build.
        was: u64,
        /// How many it holds now.
        now: u64,
    },
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
            Self::Ratio { stem, was, now } if now < was => write!(
                f,
                "{stem} shrank to {now} keys from {was} ({:.0}% of previous, floor {:.0}%)",
                ratio(*now, *was) * 100.0,
                MAX_SHRINK * 100.0
            ),
            Self::Ratio { stem, was, now } => write!(
                f,
                "{stem} grew to {now} keys from {was} ({:.1}x previous, ceiling {MAX_GROWTH:.1}x)",
                ratio(*now, *was)
            ),
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
/// 3. No filter collapsed to zero keys or moved past the ratio bounds.
///
/// [`Ratio::Waive`] downgrades **only** the ratio bounds. Canaries, vouched
/// digests, and the collapse guard stay fatal. Waived breaches are returned,
/// not swallowed.
///
/// # Errors
/// The first violation found.
pub fn verify(
    filters: &[Filter],
    prev: Option<&Manifest>,
    vouched: &[(String, [u8; 32])],
    policy: Ratio,
) -> Result<Vec<VerifyError>, VerifyError> {
    let digests = |tier: Tier| {
        filters
            .iter()
            .filter(move |f| f.kind() == Kind::Sha256 && f.tier() == tier)
    };

    for c in CANARIES {
        if let Some(f) = digests(c.forbidden).find(|f| f.may_contain(&c.sha256)) {
            return Err(VerifyError::Canary {
                sha256: crate::hex(&c.sha256),
                stem: f.stem(),
            });
        }
    }

    for tier in Tier::ALL.into_iter().filter(|t| *t != Tier::Good) {
        for f in digests(tier) {
            if let Some((label, _)) = vouched.iter().find(|(_, d)| f.may_contain(d)) {
                return Err(VerifyError::Vouched {
                    label: label.clone(),
                    stem: f.stem(),
                });
            }
        }
    }

    let mut waived = Vec::new();
    let Some(prev) = prev else {
        return Ok(waived);
    };
    for f in filters {
        let stem = f.stem();
        let Some(was) = prev.filter.get(&stem).map(|e| e.n) else {
            continue;
        };
        let now = f.len();
        if was > 0 && now == 0 {
            return Err(VerifyError::Collapsed { stem, was });
        }
        if was < RATIO_FLOOR {
            continue;
        }
        if (MAX_SHRINK..=MAX_GROWTH).contains(&ratio(now, was)) {
            continue;
        }
        let breach = VerifyError::Ratio { stem, was, now };
        match policy {
            Ratio::Waive => waived.push(breach),
            Ratio::Enforce => return Err(breach),
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
    fn v1_folds_hostile_sightings_and_drops_the_rest() {
        let filters = sets(&[
            (Tier::Bad, rec(digest(1))),
            (Tier::SightedHostile, rec(digest(2))),
            (Tier::SightedSuspicious, rec(digest(3))),
        ])
        .into_filters_for(1, 1e-9)
        .unwrap();

        assert!(filters.iter().all(|f| f.version() == 1));
        assert!(filters.iter().all(|f| f.tier().min_format_version() <= 1));
        let bad = find(&filters, "sha256-bad");
        assert!(bad.may_contain(&digest(1)));
        assert!(
            bad.may_contain(&digest(2)),
            "hostile sighting should fold in"
        );
        assert!(
            !bad.may_contain(&digest(3)),
            "weak sighting must be dropped"
        );
    }

    #[test]
    fn an_unsupported_format_version_is_an_error_not_an_empty_bundle() {
        assert_eq!(
            KeySets::new().into_filters_for(99, 1e-9).err(),
            Some(UnsupportedVersion(99))
        );
        assert_eq!(
            KeySets::new().into_filters_for(0, 1e-9).err(),
            Some(UnsupportedVersion(0))
        );
    }

    #[test]
    fn write_and_reopen_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let filters =
            sets(&[(Tier::Good, rec(digest(4))), (Tier::Bad, rec(digest(5)))]).into_filters(1e-9);
        let m = write_bundle(dir.path(), &filters, "2026-08-31", "test/v1").unwrap();

        assert_eq!(m.schema, MANIFEST_SCHEMA);
        assert_eq!(m.key_scheme.as_deref(), Some("test/v1"));
        assert_eq!(m.filter.len(), filters.len());
        assert_eq!(read_manifest(dir.path()).unwrap().as_ref(), Some(&m));

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

    #[test]
    fn a_failed_write_names_the_file() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("no-such-dir");
        let filters = KeySets::new().into_filters(1e-9);
        let err = write_bundle(&missing, &filters, "2026-08-31", "test/v1").unwrap_err();
        assert!(err.to_string().contains("no-such-dir"), "{err}");
        assert!(std::error::Error::source(&err).is_some());
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
    fn read_manifest_tells_absent_from_broken() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(read_manifest(dir.path()).unwrap(), None);

        std::fs::write(dir.path().join(MANIFEST_FILE), "garbage {{").unwrap();
        assert!(matches!(
            read_manifest(dir.path()),
            Err(OpenError::Parse { .. })
        ));

        let mut m = baseline(&[("sha256-good", 1)]);
        m.schema = MANIFEST_SCHEMA + 1;
        std::fs::write(dir.path().join(MANIFEST_FILE), toml::to_string(&m).unwrap()).unwrap();
        assert!(matches!(
            read_manifest(dir.path()),
            Err(OpenError::Schema { found, .. }) if found == MANIFEST_SCHEMA + 1
        ));
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
            key_scheme: Some("test/v1".to_owned()),
            filter: counts
                .iter()
                .map(|(stem, n)| {
                    (
                        (*stem).to_owned(),
                        Entry {
                            file: format!("{stem}.adbl"),
                            sha256: String::new(),
                            format_version: 2,
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
        assert_eq!(sets.counts(Tier::Good), (1, 1));
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
        assert_eq!(sets.counts(Tier::Good), (1, 1));
    }

    #[test]
    fn the_manifest_round_trips_with_and_without_a_key_scheme() {
        let mut m = baseline(&[("sha256-good", 42)]);
        for scheme in [Some("test/v1".to_owned()), None] {
            m.key_scheme = scheme.clone();
            let text = toml::to_string(&m).unwrap();
            assert_eq!(text.contains("key_scheme"), scheme.is_some());
            let back: Manifest = toml::from_str(&text).unwrap();
            assert_eq!(back, m);
        }
    }

    /// An older manifest has no `key_scheme` field at all; it must still parse.
    #[test]
    fn a_manifest_predating_the_key_scheme_field_parses() {
        let text = r#"
schema = 1
built = "2026-01-01"
[filter.sha256-good]
file = "sha256-good.adbl"
sha256 = "00"
format_version = 2
n = 7
"#;
        let m: Manifest = toml::from_str(text).unwrap();
        assert_eq!(m.key_scheme, None);
        assert_eq!(m.filter.len(), 1);
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
        let VerifyError::Ratio {
            was: 2_000,
            now: 8_000,
            ..
        } = &err
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

    #[test]
    fn the_override_waives_a_ratio_breach_but_reports_it() {
        let rows: Vec<(Tier, Record)> = (0..2_000)
            .map(|i| (Tier::Good, rec(digest(u8::try_from(i % 256).unwrap()))))
            .collect();
        let filters = sets(&rows).into_filters(1e-9);
        let prev = baseline(&[("sha256-good", 100_000)]);

        assert!(matches!(
            verify(&filters, Some(&prev), &[], Ratio::Enforce),
            Err(VerifyError::Ratio { .. })
        ));
        let waived = verify(&filters, Some(&prev), &[], Ratio::Waive).unwrap();
        assert_eq!(waived.len(), 1);
        assert!(matches!(waived.first(), Some(VerifyError::Ratio { .. })));
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
