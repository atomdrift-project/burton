//! Consuming a bundle: the decision rule, and the one type that applies it.

use std::fmt;
use std::path::{Path, PathBuf};

use crate::build::{MANIFEST_FILE, Manifest};
use crate::filter::{Filter, Kind, LoadError, Tier, digest_of};

/// What to do with an artifact before spending real work on it.
///
/// Branch on [`Decision::may_skip`], not on `== Skip`: when a tier is added,
/// `may_skip` is the one place that has to be right.
///
/// Deliberately not `#[non_exhaustive]`. A downstream `match` that stops
/// compiling when a tier appears is what we want; a wildcard arm silently
/// grading a new adverse tier as benign is not.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[must_use]
pub enum Decision {
    /// The producer's own analysis found this hostile. Scan it, and say so.
    KnownBad,
    /// Corroborated outside claims. Nothing of the producer's measured it.
    SightedHostile,
    /// A lone, unadjudicated outside claim. A flag, not a verdict.
    SightedSuspicious,
    /// Blessed *and* claimed — the bundle contradicts itself, or two keys for
    /// one artifact disagree. Trust neither; scan.
    Conflicted,
    /// Blessed, claimed by nothing, and revocable. The only skippable value.
    Skip,
    /// Nothing is known, or a skip was withheld for safety. Scan.
    Unknown,
}

impl Decision {
    /// Whether this decision permits skipping the work. The only question a
    /// fast path should ask.
    #[must_use]
    pub const fn may_skip(self) -> bool {
        matches!(self, Self::Skip)
    }

    /// Whether anything, of any provenance, claims this artifact. True for
    /// [`Self::Conflicted`]: a bless beside a conviction is no less alarming.
    #[must_use]
    pub const fn is_adverse(self) -> bool {
        self.severity().is_some()
    }

    /// Wire form: lowercase and hyphenated.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::KnownBad => "known-bad",
            Self::SightedHostile => "sighted-hostile",
            Self::SightedSuspicious => "sighted-suspicious",
            Self::Conflicted => "conflicted",
            Self::Skip => "skip",
            Self::Unknown => "unknown",
        }
    }

    /// How bad this is, for "worst wins". Higher is worse; `None` makes no
    /// adverse claim.
    const fn severity(self) -> Option<u8> {
        match self {
            Self::KnownBad | Self::Conflicted => Some(3),
            Self::SightedHostile => Some(2),
            Self::SightedSuspicious => Some(1),
            Self::Skip | Self::Unknown => None,
        }
    }

    const fn is_blessed(self) -> bool {
        matches!(self, Self::Skip | Self::Conflicted)
    }
}

/// What several keys naming the *same* artifact say together.
///
/// Claims are disjunctive: any key's claim is a claim against the artifact, and
/// the worst wins. Blessings are conjunctive: a skip needs every key supplied to
/// be blessed. A blessing beside a claim is [`Decision::Conflicted`].
///
/// The asymmetry is the grinding defence. A digest is cheap to grind into a good
/// filter's false-positive set; a package coordinate is not. A caller who knows
/// one key is unaffected — there is nothing to conjoin.
///
/// A fold, not a pairwise combinator: the pairwise version is not associative
/// (`Skip, Unknown, KnownBad` lands differently by order), so a third key kind
/// would make the answer depend on which key was asked first.
fn combine(decisions: impl Iterator<Item = Decision>) -> Decision {
    let mut worst: Option<(u8, Decision)> = None;
    let mut any_blessed = false;
    let mut all_blessed = true;
    let mut seen = false;

    for d in decisions {
        seen = true;
        if let Some(severity) = d.severity()
            && worst.is_none_or(|(w, _)| severity > w)
        {
            worst = Some((severity, d));
        }
        if d.is_blessed() {
            any_blessed = true;
        } else {
            all_blessed = false;
        }
    }

    match (worst, any_blessed) {
        // Something claims this artifact and something blesses it. Trust
        // neither. Never resolves back to a skip.
        (Some(_), true) => Decision::Conflicted,
        (Some((_, worst)), false) => worst,
        (None, _) if seen && all_blessed => Decision::Skip,
        (None, _) => Decision::Unknown,
    }
}

/// The adverse tiers, worst first; the first that hits decides. Adding a tier
/// means adding a row here, and nothing else in this module knows the list.
const ADVERSE: [(Tier, Decision); 3] = [
    (Tier::Bad, Decision::KnownBad),
    (Tier::SightedHostile, Decision::SightedHostile),
    (Tier::SightedSuspicious, Decision::SightedSuspicious),
];

// A tier missing from ADVERSE would load, be consulted by nothing, and silently
// fail to deny a skip.
const _: () = assert!(
    ADVERSE.len() + 1 == Tier::ALL.len(),
    "every tier but Good must appear in ADVERSE"
);

/// What you know about one artifact.
///
/// Supply every key you have: [`Lookup`] requires all of them to agree before
/// it blesses anything.
#[derive(Debug, Clone, Copy, Default)]
pub struct Artifact<'a> {
    purl: Option<&'a str>,
    sha256: Option<&'a [u8; 32]>,
}

impl<'a> Artifact<'a> {
    /// An artifact known by its package coordinate, already in the bundle's
    /// key scheme (see [`Lookup::open`]). Any other form simply will not match.
    #[must_use]
    pub const fn purl(purl: &'a str) -> Self {
        Self {
            purl: Some(purl),
            sha256: None,
        }
    }

    /// An artifact known only by its content digest.
    #[must_use]
    pub const fn sha256(digest: &'a [u8; 32]) -> Self {
        Self {
            purl: None,
            sha256: Some(digest),
        }
    }

    /// Add a package coordinate.
    #[must_use]
    pub const fn and_purl(mut self, purl: &'a str) -> Self {
        self.purl = Some(purl);
        self
    }

    /// Add a content digest.
    #[must_use]
    pub const fn and_sha256(mut self, digest: &'a [u8; 32]) -> Self {
        self.sha256 = Some(digest);
        self
    }
}

/// A loaded bundle. Open it once and share it; filters live in memory, so a
/// bundle costs what its files cost on disk.
#[derive(Debug)]
pub struct Lookup {
    /// `slots[kind][tier]`, so no tier can be reached except by index.
    slots: [[Option<Filter>; Tier::ALL.len()]; Kind::ALL.len()],
    scheme: Option<String>,
}

impl Lookup {
    /// A bundle holding nothing: [`Decision::Unknown`] to everything, and no
    /// skips. What a caller falls back to when [`Lookup::open`] fails.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            slots: std::array::from_fn(|_| std::array::from_fn(|_| None)),
            scheme: None,
        }
    }

    /// Open the bundle in `dir`, requiring the key scheme `scheme`.
    ///
    /// The manifest is the authority. Every filter it names must load, be
    /// valid, and identify itself as the file it is named as. **Any failure
    /// fails the whole open**: a partly readable bundle is exactly the case
    /// where a stale bless cannot be vetoed.
    ///
    /// A bundle recording a different `scheme` is refused — producer and
    /// consumer that disagree would otherwise match nothing, silently and
    /// forever. A bundle recording none predates the field and is accepted.
    ///
    /// Manifest digests are not re-verified here. They authenticate a download;
    /// re-hashing the whole bundle on every open costs more than it catches.
    ///
    /// # Errors
    /// [`OpenError`] for a missing or unparseable manifest, a scheme mismatch,
    /// or any named filter that will not load.
    pub fn open(dir: impl AsRef<Path>, scheme: &str) -> Result<Self, OpenError> {
        let dir = dir.as_ref();
        let path = dir.join(MANIFEST_FILE);
        let text =
            std::fs::read_to_string(&path).map_err(|e| OpenError::Manifest(path.clone(), e))?;
        let manifest: Manifest =
            toml::from_str(&text).map_err(|e| OpenError::Schema(path, e.to_string()))?;

        if let Some(found) = manifest.key_scheme.as_deref()
            && found != scheme
        {
            return Err(OpenError::KeyScheme(KeySchemeError {
                expected: scheme.to_owned(),
                found: found.to_owned(),
            }));
        }

        let mut me = Self::empty();
        for (stem, entry) in &manifest.filter {
            let bytes = std::fs::read(dir.join(&entry.file))
                .map_err(|e| OpenError::Missing(entry.file.clone(), e))?;
            let filter =
                Filter::load(bytes).map_err(|e| OpenError::Invalid(entry.file.clone(), e))?;
            if &filter.stem() != stem {
                return Err(OpenError::Mislabelled {
                    file: entry.file.clone(),
                    claims: filter.stem(),
                });
            }
            if let Some(slot) = me.slot_mut(filter.kind(), filter.tier()) {
                *slot = Some(filter);
            }
        }
        me.scheme = manifest.key_scheme;
        Ok(me)
    }

    /// The verdict for one artifact: every tier consulted for every key, worst
    /// claim wins, a blessing needs unanimity.
    pub fn decide(&self, artifact: &Artifact<'_>) -> Decision {
        let purl = artifact
            .purl
            .map(|p| self.decide_key(Kind::Purl, &digest_of(p.as_bytes())));
        let sha256 = artifact.sha256.map(|d| self.decide_key(Kind::Sha256, d));
        combine(purl.into_iter().chain(sha256))
    }

    /// Whether this artifact may be skipped.
    #[must_use]
    pub fn may_skip(&self, artifact: &Artifact<'_>) -> bool {
        self.decide(artifact).may_skip()
    }

    /// True when at least one filter is loaded.
    #[must_use]
    pub fn is_active(&self) -> bool {
        self.filters().next().is_some()
    }

    /// Total keys across every loaded filter.
    #[must_use]
    pub fn keys(&self) -> u64 {
        self.filters().map(Filter::len).sum()
    }

    /// The key scheme this bundle recorded, if it recorded one.
    #[must_use]
    pub fn key_scheme(&self) -> Option<&str> {
        self.scheme.as_deref()
    }

    /// The rule for one key: worst pool wins.
    ///
    /// A blessing needs the `bad` filter loaded to be honored; that is the
    /// revocation channel. A missing *sighted* filter is not the same failure —
    /// that is a bundle predating those tiers, and [`Lookup::open`] has already
    /// ruled out anything missing by accident.
    fn decide_key(&self, kind: Kind, digest: &[u8; 32]) -> Decision {
        let hit = |tier: Tier| self.slot(kind, tier).is_some_and(|f| f.may_contain(digest));
        let adverse = ADVERSE
            .iter()
            .find(|(tier, _)| hit(*tier))
            .map(|(_, verdict)| *verdict);

        match (adverse, hit(Tier::Good)) {
            (Some(_), true) => Decision::Conflicted,
            (Some(worst), false) => worst,
            (None, true) if self.slot(kind, Tier::Bad).is_some() => Decision::Skip,
            (None, _) => Decision::Unknown,
        }
    }

    fn slot(&self, kind: Kind, tier: Tier) -> Option<&Filter> {
        self.slots
            .get(kind.index())
            .and_then(|row| row.get(tier.index()))
            .and_then(Option::as_ref)
    }

    fn slot_mut(&mut self, kind: Kind, tier: Tier) -> Option<&mut Option<Filter>> {
        self.slots
            .get_mut(kind.index())
            .and_then(|row| row.get_mut(tier.index()))
    }

    fn filters(&self) -> impl Iterator<Item = &Filter> {
        self.slots.iter().flatten().filter_map(Option::as_ref)
    }
}

/// A bundle built with a different key canonicalization than the caller uses.
///
/// Not corruption: producer and consumer would simply agree on nothing, and
/// every artifact would look unknown. Failing at open makes that visible.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeySchemeError {
    /// What the caller asked for.
    pub expected: String,
    /// What the bundle records.
    pub found: String,
}

/// Why a bundle could not be opened. Every variant means the same to a caller:
/// no usable bundle, so nothing may be skipped.
#[derive(Debug)]
pub enum OpenError {
    /// The manifest is absent or unreadable.
    Manifest(PathBuf, std::io::Error),
    /// The manifest is not valid TOML.
    Schema(PathBuf, String),
    /// The bundle's key scheme is not the caller's.
    KeyScheme(KeySchemeError),
    /// A filter the manifest names could not be read.
    Missing(String, std::io::Error),
    /// A filter the manifest names is not a valid filter.
    Invalid(String, LoadError),
    /// A filter's header disagrees with the name the manifest gave it.
    Mislabelled {
        /// The file name as the manifest gives it.
        file: String,
        /// The stem the file's own header claims.
        claims: String,
    },
}

impl fmt::Display for OpenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Manifest(p, e) => write!(f, "reading {}: {e}", p.display()),
            Self::Schema(p, e) => write!(f, "parsing {}: {e}", p.display()),
            Self::KeyScheme(k) => write!(
                f,
                "bundle uses key scheme {:?}, this build uses {:?}",
                k.found, k.expected
            ),
            Self::Missing(file, e) => write!(f, "reading {file}: {e}"),
            Self::Invalid(file, e) => write!(f, "{file}: {e}"),
            Self::Mislabelled { file, claims } => {
                write!(f, "{file} identifies itself as {claims}")
            }
        }
    }
}

impl std::error::Error for OpenError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Manifest(_, e) | Self::Missing(_, e) => Some(e),
            Self::Invalid(_, e) => Some(e),
            Self::Schema(..) | Self::KeyScheme(_) | Self::Mislabelled { .. } => None,
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use Decision::{Conflicted, KnownBad, SightedHostile, SightedSuspicious, Skip, Unknown};

    const ALL: [Decision; 6] = [
        KnownBad,
        SightedHostile,
        SightedSuspicious,
        Conflicted,
        Skip,
        Unknown,
    ];

    #[test]
    fn only_skip_may_skip() {
        for d in ALL {
            assert_eq!(d.may_skip(), d == Skip, "{d:?}");
        }
    }

    fn of(ds: &[Decision]) -> Decision {
        combine(ds.iter().copied())
    }

    #[test]
    fn order_never_changes_the_answer() {
        for a in ALL {
            for b in ALL {
                assert_eq!(of(&[a, b]), of(&[b, a]), "{a:?} vs {b:?}");
                for c in ALL {
                    assert_eq!(of(&[a, b, c]), of(&[c, b, a]), "{a:?}{b:?}{c:?}");
                }
            }
        }
    }

    #[test]
    fn one_key_stands_on_its_own() {
        for d in ALL {
            assert_eq!(of(&[d]), d, "{d:?}");
        }
        assert_eq!(of(&[]), Unknown, "no keys means nothing is known");
    }

    #[test]
    fn a_blessing_needs_every_key_to_agree() {
        assert_eq!(of(&[Skip, Skip]), Skip);
        // The whole point: one blessed key is not enough when another key is
        // supplied and says nothing about the artifact.
        assert_eq!(of(&[Skip, Unknown]), Unknown);
        assert_eq!(of(&[Unknown, Unknown]), Unknown);
    }

    #[test]
    fn a_claim_against_any_key_wins() {
        assert_eq!(of(&[KnownBad, Unknown]), KnownBad);
        assert_eq!(of(&[SightedSuspicious, SightedHostile]), SightedHostile);
        assert_eq!(of(&[SightedHostile, KnownBad]), KnownBad);
        assert_eq!(
            of(&[Unknown, SightedSuspicious, Unknown]),
            SightedSuspicious
        );
    }

    #[test]
    fn disagreement_is_a_conflict_and_never_a_skip() {
        for adverse in [KnownBad, SightedHostile, SightedSuspicious] {
            assert_eq!(of(&[Skip, adverse]), Conflicted, "{adverse:?}");
            assert!(!of(&[Skip, adverse]).may_skip());
        }
        // Order-independence is what the pairwise version got wrong.
        assert_eq!(of(&[Skip, Unknown, KnownBad]), Conflicted);
        for d in ALL {
            assert_eq!(of(&[Conflicted, d]), Conflicted, "{d:?}");
        }
    }

    #[test]
    fn nothing_combines_into_a_skip_that_was_not_already_blessed() {
        for a in ALL {
            for b in ALL {
                if of(&[a, b]).may_skip() {
                    assert!(a.may_skip() && b.may_skip(), "{a:?} + {b:?} became a skip");
                }
            }
        }
    }

    #[test]
    fn every_adverse_decision_reports_itself_adverse() {
        for d in ALL {
            assert_eq!(
                d.is_adverse(),
                matches!(
                    d,
                    KnownBad | SightedHostile | SightedSuspicious | Conflicted
                ),
                "{d:?}"
            );
        }
    }

    #[test]
    fn an_artifact_with_no_keys_is_unknown() {
        let lk = Lookup::empty();
        assert_eq!(lk.decide(&Artifact::default()), Unknown);
        assert!(!lk.may_skip(&Artifact::default()));
    }

    #[test]
    fn a_lookup_is_shareable_across_threads() {
        const fn assert_shareable<T: Send + Sync>() {}
        assert_shareable::<Lookup>();
        assert_shareable::<Decision>();
    }

    #[test]
    fn every_decision_has_a_distinct_wire_name() {
        let mut seen = std::collections::HashSet::new();
        for d in ALL {
            assert!(seen.insert(d.as_str()), "duplicate wire name for {d:?}");
            assert!(!d.as_str().is_empty());
        }
    }

    /// Nothing outranks a claim except a worse claim.
    #[test]
    fn severity_orders_the_adverse_tiers() {
        assert_eq!(of(&[KnownBad, SightedHostile, SightedSuspicious]), KnownBad);
        assert_eq!(of(&[SightedHostile, SightedSuspicious]), SightedHostile);
        assert_eq!(of(&[SightedSuspicious, Unknown]), SightedSuspicious);
    }

    /// Adding a tier to `Tier` without grading it in `ADVERSE` must not
    /// compile; this checks the table stays in the intended order meanwhile.
    #[test]
    fn adverse_is_ordered_worst_first() {
        let severities: Vec<Option<u8>> = ADVERSE.iter().map(|(_, d)| d.severity()).collect();
        assert!(
            severities.windows(2).all(|w| w[0] > w[1]),
            "ADVERSE must be strictly worst-first: {severities:?}"
        );
        assert!(!ADVERSE.iter().any(|(t, _)| *t == Tier::Good));
    }

    #[test]
    fn an_empty_lookup_knows_nothing_and_skips_nothing() {
        let lk = Lookup::empty();
        assert!(!lk.is_active());
        assert_eq!(lk.keys(), 0);
        assert_eq!(lk.decide(&Artifact::sha256(&[1u8; 32])), Unknown);
        assert!(!lk.may_skip(&Artifact::purl("pkg:npm/x@1")));
    }
}
