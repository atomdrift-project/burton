//! Producing a bundle: set algebra, serialization, and the pre-publish checks.
//!
//! Which records earn which tier is policy and belongs to whoever owns the
//! corpus. A build is always a full rebuild, because bloom filters cannot
//! delete.

use std::collections::{BTreeMap, HashSet};
use std::path::Path;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::filter::{Builder, Filter, Kind, Tier};

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

/// Deduplicated keys, one set per (kind, tier), accumulated as records stream
/// in. Nothing is buffered, so peak memory is the distinct keys and does not
/// grow with row count.
#[derive(Debug)]
pub struct KeySets {
    purl: [HashSet<String>; Tier::ALL.len()],
    sha256: [HashSet<[u8; 32]>; Tier::ALL.len()],
}

impl Default for KeySets {
    fn default() -> Self {
        Self::new()
    }
}

impl KeySets {
    /// An empty accumulator.
    #[must_use]
    pub fn new() -> Self {
        Self {
            purl: std::array::from_fn(|_| HashSet::new()),
            sha256: std::array::from_fn(|_| HashSet::new()),
        }
    }

    /// Insert one record under `tier`. Each key present joins its set;
    /// duplicates collapse.
    pub fn insert(&mut self, tier: Tier, record: Record) {
        if let Some(purl) = record.purl
            && let Some(set) = self.purl.get_mut(tier.index())
        {
            set.insert(purl);
        }
        if let Some(sha) = record.sha256
            && let Some(set) = self.sha256.get_mut(tier.index())
        {
            set.insert(sha);
        }
    }

    /// Deduplicated `(purl, sha256)` key counts for one tier, before subtraction.
    #[must_use]
    pub fn counts(&self, tier: Tier) -> (usize, usize) {
        (
            self.purl.get(tier.index()).map_or(0, HashSet::len),
            self.sha256.get(tier.index()).map_or(0, HashSet::len),
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
    #[must_use]
    pub fn into_filters(mut self, target_fp: f64) -> Vec<Filter> {
        self.subtract_claims_from_good();
        let mut out = Vec::with_capacity(Kind::ALL.len() * Tier::ALL.len());
        for tier in Tier::ALL {
            out.push(build_keys(
                Kind::Purl,
                tier,
                self.purl.get(tier.index()),
                target_fp,
            ));
            out.push(build_digests(
                Kind::Sha256,
                tier,
                self.sha256.get(tier.index()),
                target_fp,
            ));
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
    #[must_use]
    pub fn into_filters_for(mut self, version: u16, target_fp: f64) -> Vec<Filter> {
        if version < Tier::SightedHostile.min_format_version() {
            self.fold(Tier::SightedHostile, Tier::Bad);
            self.clear(Tier::SightedSuspicious);
        }
        self.into_filters(target_fp)
            .into_iter()
            .filter_map(|f| f.stamped_as(version))
            .collect()
    }

    fn subtract_claims_from_good(&mut self) {
        let claimed_purls: HashSet<String> = Tier::ALL
            .iter()
            .filter(|t| **t != Tier::Good)
            .filter_map(|t| self.purl.get(t.index()))
            .flatten()
            .cloned()
            .collect();
        let claimed_shas: HashSet<[u8; 32]> = Tier::ALL
            .iter()
            .filter(|t| **t != Tier::Good)
            .filter_map(|t| self.sha256.get(t.index()))
            .flatten()
            .copied()
            .collect();
        if let Some(good) = self.purl.get_mut(Tier::Good.index()) {
            good.retain(|k| !claimed_purls.contains(k));
        }
        if let Some(good) = self.sha256.get_mut(Tier::Good.index()) {
            good.retain(|k| !claimed_shas.contains(k));
        }
    }

    fn fold(&mut self, from: Tier, into: Tier) {
        if let Some(taken) = self.purl.get_mut(from.index()).map(std::mem::take)
            && let Some(dst) = self.purl.get_mut(into.index())
        {
            dst.extend(taken);
        }
        if let Some(taken) = self.sha256.get_mut(from.index()).map(std::mem::take)
            && let Some(dst) = self.sha256.get_mut(into.index())
        {
            dst.extend(taken);
        }
    }

    fn clear(&mut self, tier: Tier) {
        if let Some(s) = self.purl.get_mut(tier.index()) {
            s.clear();
        }
        if let Some(s) = self.sha256.get_mut(tier.index()) {
            s.clear();
        }
    }
}

fn build_keys(kind: Kind, tier: Tier, keys: Option<&HashSet<String>>, fp: f64) -> Filter {
    let mut b = Builder::new(kind, tier, keys.map_or(0, HashSet::len) as u64, fp);
    for k in keys.into_iter().flatten() {
        b.insert_key(k.as_bytes());
    }
    b.build()
}

fn build_digests(kind: Kind, tier: Tier, keys: Option<&HashSet<[u8; 32]>>, fp: f64) -> Filter {
    let mut b = Builder::new(kind, tier, keys.map_or(0, HashSet::len) as u64, fp);
    for k in keys.into_iter().flatten() {
        b.insert_digest(k);
    }
    b.build()
}

/// One filter's entry in the manifest.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Entry {
    /// File name relative to the bundle directory, e.g. `purl-good.adbl`.
    pub file: String,
    /// Lowercase hex SHA-256 of the file, for verifying a download.
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

/// Write every filter to `<dir>/<stem>.adbl`, plus the manifest naming them.
///
/// `key_scheme` is recorded so a consumer using a different one fails at open
/// instead of matching nothing.
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
        std::fs::write(dir.join(&file), filter.as_bytes())
            .map_err(|e| WriteError::File(file.clone(), e))?;
        entries.insert(
            stem,
            Entry {
                sha256: crate::hex(&sha256_of(filter.as_bytes())),
                // The filter's own version, not this build's: a bundle
                // projected down for older clients writes older headers, and a
                // publisher derives the upload path from this field.
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
    let text = toml::to_string(&manifest).map_err(WriteError::Manifest)?;
    std::fs::write(dir.join(MANIFEST_FILE), text)
        .map_err(|e| WriteError::File(MANIFEST_FILE.to_owned(), e))?;
    Ok(manifest)
}

/// Read a previously built manifest, to size a new build against. Absent or
/// unparseable means no baseline.
#[must_use]
pub fn read_manifest(dir: &Path) -> Option<Manifest> {
    let text = std::fs::read_to_string(dir.join(MANIFEST_FILE)).ok()?;
    toml::from_str(&text).ok()
}

fn sha256_of(bytes: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(&Sha256::digest(bytes));
    out
}

/// Why a bundle could not be written.
#[derive(Debug)]
pub enum WriteError {
    /// A file could not be written.
    File(String, std::io::Error),
    /// The manifest could not be serialized.
    Manifest(toml::ser::Error),
}

impl std::fmt::Display for WriteError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::File(name, e) => write!(f, "writing {name}: {e}"),
            Self::Manifest(e) => write!(f, "serializing the manifest: {e}"),
        }
    }
}

impl std::error::Error for WriteError {}

// --- Checks that run before anything is published ---------------------------
//
// A bundle is published unattended and cannot be edited after the fact. These
// run on the freshly built filters, before anything is written, so a violation
// leaves the last good build in place.

/// A digest that must never land in a given tier.
struct Canary {
    sha256: &'static str,
    forbidden: Tier,
}

/// Checked on every build. A handful catch the catastrophic mislabel that a
/// silent rebuild would otherwise carry all the way to a skip.
const CANARIES: &[Canary] = &[
    // EICAR is benign by construction, but every scanner is expected to treat
    // it as hostile. It must never be blessed.
    Canary {
        sha256: "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
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
    /// A digest the caller vouched for is catalogued bad.
    Vouched(String),
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
        /// What happened, in words.
        detail: String,
    },
}

impl std::fmt::Display for VerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Canary { sha256, stem } => {
                write!(f, "canary {sha256} is in {stem} and must never be")
            }
            Self::Vouched(what) => write!(f, "known-good {what} is in sha256-bad"),
            Self::Collapsed { stem, was } => {
                write!(f, "{stem} collapsed to 0 keys (was {was})")
            }
            Self::Ratio { stem, detail } => write!(f, "{stem} {detail}"),
        }
    }
}

impl std::error::Error for VerifyError {}

/// Refuse to publish a bundle that looks poisoned or truncated.
///
/// 1. No [`CANARIES`] digest is in its forbidden tier.
/// 2. No digest in `vouched` — artifacts the caller asserts are ubiquitously
///    benign, such as the build host's `/bin/ls` — is catalogued bad.
/// 3. No filter collapsed to zero keys or moved past the ratio bounds.
///
/// `accept_unusual` downgrades **only** the ratio bounds, for the one case they
/// cannot distinguish from a corrupt export: an operator changing a tier's rule,
/// where the large step *is* the change. Canaries, vouched digests, and the
/// collapse guard stay fatal. Waived breaches are returned, not swallowed.
///
/// # Errors
/// The first violation found.
pub fn verify(
    filters: &[Filter],
    prev: Option<&Manifest>,
    vouched: &[(String, [u8; 32])],
    accept_unusual: bool,
) -> Result<Vec<VerifyError>, VerifyError> {
    let find = |stem: &str| filters.iter().find(|f| f.stem() == stem);
    let mut waived = Vec::new();

    for c in CANARIES {
        let Some(digest) = crate::parse_sha256_hex(c.sha256) else {
            continue; // A malformed constant is a bug, not a bundle defect.
        };
        let stem = format!("sha256-{}", c.forbidden.as_str());
        if find(&stem).is_some_and(|f| f.may_contain(&digest)) {
            return Err(VerifyError::Canary {
                sha256: c.sha256.to_owned(),
                stem,
            });
        }
    }

    if let Some(bad) = find("sha256-bad") {
        for (label, digest) in vouched {
            if bad.may_contain(digest) {
                return Err(VerifyError::Vouched(label.clone()));
            }
        }
    }

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
        #[allow(clippy::cast_precision_loss)]
        let ratio = now as f64 / was as f64;
        let detail = if ratio < MAX_SHRINK {
            format!(
                "shrank to {now} keys from {was} ({:.0}% of previous, floor {:.0}%)",
                ratio * 100.0,
                MAX_SHRINK * 100.0
            )
        } else if ratio > MAX_GROWTH {
            format!(
                "grew to {now} keys from {was} ({ratio:.1}x previous, ceiling {MAX_GROWTH:.1}x)"
            )
        } else {
            continue;
        };
        let breach = VerifyError::Ratio { stem, detail };
        if accept_unusual {
            waived.push(breach);
        } else {
            return Err(breach);
        }
    }
    Ok(waived)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]
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
        Record {
            purl: None,
            sha256: Some(d),
        }
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
    fn v1_folds_hostile_sightings_and_drops_the_rest() {
        let filters = sets(&[
            (Tier::Bad, rec(digest(1))),
            (Tier::SightedHostile, rec(digest(2))),
            (Tier::SightedSuspicious, rec(digest(3))),
        ])
        .into_filters_for(1, 1e-9);

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
    fn write_and_reopen_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let filters =
            sets(&[(Tier::Good, rec(digest(4))), (Tier::Bad, rec(digest(5)))]).into_filters(1e-9);
        let m = write_bundle(dir.path(), &filters, "2026-08-31", "test/v1").unwrap();

        assert_eq!(m.schema, MANIFEST_SCHEMA);
        assert_eq!(m.key_scheme.as_deref(), Some("test/v1"));
        assert_eq!(m.filter.len(), filters.len());
        assert_eq!(read_manifest(dir.path()).as_ref(), Some(&m));

        let lk = crate::Lookup::open(dir.path(), "test/v1").unwrap();
        assert!(lk.may_skip(&crate::Artifact::sha256(&digest(4))));
        assert_eq!(
            lk.decide(&crate::Artifact::sha256(&digest(5))),
            crate::Decision::KnownBad
        );
    }

    #[test]
    fn manifest_sha256_matches_the_bytes_written() {
        let dir = tempfile::tempdir().unwrap();
        let filters = sets(&[(Tier::Good, rec(digest(6)))]).into_filters(1e-9);
        let m = write_bundle(dir.path(), &filters, "2026-08-31", "test/v1").unwrap();
        for entry in m.filter.values() {
            let bytes = std::fs::read(dir.path().join(&entry.file)).unwrap();
            assert_eq!(
                crate::hex(&sha256_of(&bytes)),
                entry.sha256,
                "{}",
                entry.file
            );
        }
    }

    #[test]
    fn a_blessed_canary_is_refused() {
        let eicar = crate::parse_sha256_hex(CANARIES.first().unwrap().sha256).unwrap();
        let filters = sets(&[(Tier::Good, rec(eicar))]).into_filters(1e-9);
        assert!(matches!(
            verify(&filters, None, &[], false),
            Err(VerifyError::Canary { .. })
        ));
    }

    #[test]
    fn a_vouched_digest_in_bad_is_refused() {
        let filters = sets(&[(Tier::Bad, rec(digest(7)))]).into_filters(1e-9);
        let vouched = [("/bin/ls".to_owned(), digest(7))];
        assert_eq!(
            verify(&filters, None, &vouched, false),
            Err(VerifyError::Vouched("/bin/ls".to_owned()))
        );
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
        sets.insert(
            Tier::Good,
            Record {
                purl: Some("pkg:npm/x@1".to_owned()),
                sha256: None,
            },
        );
        sets.insert(
            Tier::Good,
            Record {
                purl: None,
                sha256: Some(digest(2)),
            },
        );
        sets.insert(Tier::Good, Record::default());
        assert_eq!(sets.counts(Tier::Good), (1, 1));
    }

    #[test]
    fn an_unreadable_format_version_produces_no_bundle() {
        // The CLI relies on this to refuse to publish rather than write nothing.
        let filters = KeySets::new().into_filters_for(99, 1e-9);
        assert!(filters.is_empty());
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
        assert_eq!(verify(&filters, None, &[], false), Ok(vec![]));
    }

    /// Both ends of the ratio band, and the middle that must pass.
    #[test]
    fn the_ratio_band_catches_both_directions() {
        let rows: Vec<(Tier, Record)> = (0..=255u8).map(|i| (Tier::Bad, rec(digest(i)))).collect();
        let filters = sets(&rows).into_filters(1e-9); // 256 keys

        let prev = baseline(&[("sha256-bad", 1_000)]);
        assert!(matches!(
            verify(&filters, Some(&prev), &[], false),
            Err(VerifyError::Ratio { .. })
        ));

        // 80 is under RATIO_FLOOR, so the ratios do not apply at all.
        let prev = baseline(&[("sha256-bad", 80)]);
        assert_eq!(verify(&filters, Some(&prev), &[], false), Ok(vec![]));

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
        let err = verify(&grown, Some(&prev), &[], false).unwrap_err();
        let VerifyError::Ratio { detail, .. } = &err else {
            panic!("expected a ratio breach, got {err:?}");
        };
        assert!(detail.contains("grew to"), "{detail}");

        // In band: 3000 from 2000 is 1.5x.
        let mid: Vec<(Tier, Record)> = many.into_iter().take(3_000).collect();
        assert_eq!(
            verify(&sets(&mid).into_filters(1e-9), Some(&prev), &[], false),
            Ok(vec![])
        );
    }

    #[test]
    fn default_matches_new() {
        assert_eq!(
            KeySets::default().counts(Tier::Good),
            KeySets::new().counts(Tier::Good)
        );
    }

    /// Error text is what an operator sees at 3am. Every variant must render.
    #[test]
    fn every_error_renders() {
        let errors = [
            VerifyError::Canary {
                sha256: "ab".to_owned(),
                stem: "sha256-good".to_owned(),
            },
            VerifyError::Vouched("/bin/ls".to_owned()),
            VerifyError::Collapsed {
                stem: "sha256-bad".to_owned(),
                was: 9,
            },
            VerifyError::Ratio {
                stem: "purl-good".to_owned(),
                detail: "shrank".to_owned(),
            },
        ];
        for e in &errors {
            assert!(!e.to_string().is_empty(), "{e:?}");
        }
        let io = WriteError::File("x.adbl".to_owned(), std::io::Error::other("disk on fire"));
        assert!(io.to_string().contains("x.adbl"));
        assert!(io.to_string().contains("disk on fire"));
    }

    #[test]
    fn a_collapse_is_fatal_even_with_the_override() {
        let filters = KeySets::new().into_filters(1e-9);
        let prev = baseline(&[("sha256-good", 10_000)]);
        for accept in [false, true] {
            assert!(matches!(
                verify(&filters, Some(&prev), &[], accept),
                Err(VerifyError::Collapsed { .. })
            ));
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
            verify(&filters, Some(&prev), &[], false),
            Err(VerifyError::Ratio { .. })
        ));
        let waived = verify(&filters, Some(&prev), &[], true).unwrap();
        assert_eq!(waived.len(), 1);
        assert!(matches!(waived.first(), Some(VerifyError::Ratio { .. })));
    }

    #[test]
    fn small_filters_swing_freely() {
        let filters = sets(&[(Tier::Bad, rec(digest(8)))]).into_filters(1e-9);
        let prev = baseline(&[("sha256-bad", 900)]);
        assert_eq!(verify(&filters, Some(&prev), &[], false), Ok(vec![]));
    }
}
