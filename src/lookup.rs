//! Consuming a bundle: the decision rule, and the one type that applies it.

use std::ffi::OsStr;
use std::fmt;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{PoisonError, RwLock, RwLockReadGuard};

use crate::bundle::{MANIFEST_FILE, MANIFEST_SCHEMA, load_manifest};
use crate::filter::{Header, Kind, LoadError, OnDisk, OnDiskError, Tier, digest_of};

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
    /// Nothing is known, or a blessing had no revocation channel. Scan.
    Unknown,
    /// No filter that could be read claims this artifact, but one could not
    /// be read when consulted, so nothing may be blessed. Scan, and look at
    /// the bundle.
    Unavailable,
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
            Self::Unavailable => "unavailable",
        }
    }

    /// How bad this is, for "worst wins". Higher is worse; `None` makes no
    /// adverse claim.
    const fn severity(self) -> Option<u8> {
        match self {
            Self::KnownBad | Self::Conflicted => Some(3),
            Self::SightedHostile => Some(2),
            Self::SightedSuspicious => Some(1),
            Self::Skip | Self::Unknown | Self::Unavailable => None,
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
/// be blessed. A blessing beside a claim is [`Decision::Conflicted`]. With no
/// claim, a key whose filters could not be read makes the whole
/// [`Decision::Unavailable`].
///
/// The asymmetry is the grinding defence. A digest is cheap to grind into a good
/// filter's false-positive set; a package coordinate is not. A caller who knows
/// one key is unaffected — there is nothing to conjoin.
///
/// A fold, not a pairwise combinator: the pairwise version is not associative
/// (`Skip, Unknown, KnownBad` lands differently by order), so a third key kind
/// would make the answer depend on which key was asked first.
fn combine(decisions: impl IntoIterator<Item = Decision>) -> Decision {
    let mut worst: Option<(u8, Decision)> = None;
    let mut any_blessed = false;
    let mut all_blessed = true;
    let mut unavailable = false;
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
        unavailable |= d == Decision::Unavailable;
    }

    match (worst, any_blessed) {
        // Something claims this artifact and something blesses it. Trust
        // neither. Never resolves back to a skip.
        (Some(_), true) => Decision::Conflicted,
        (Some((_, worst)), false) => worst,
        (None, _) if unavailable => Decision::Unavailable,
        (None, _) if seen && all_blessed => Decision::Skip,
        (None, _) => Decision::Unknown,
    }
}

/// The adverse tiers, worst first. Adding a tier means adding a row here, and
/// nothing else in this module knows the list.
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

/// An opened bundle. Open it once and share it.
///
/// Filters stay on disk. Opening reads only the manifest and each filter's
/// header, so it is cheap enough for short-lived processes, and a decision
/// reads only the few bytes its probes touch, so a bundle costs no memory for
/// its bits.
///
/// An open bundle follows its directory. On Unix the filter files are held
/// open, and each decision checks the manifest's identity — a single `stat` —
/// and reopens the whole bundle when it has been replaced, as [`write_bundle`]
/// and a directory swap both do. Decisions therefore always read one build. A
/// replacement that will not open yields [`Decision::Unavailable`] until one
/// does. Elsewhere no handle is held between decisions, so an updater can
/// rename the directory out from under an open bundle; each decision reopens
/// the filters it consults instead.
///
/// [`write_bundle`]: crate::write_bundle
#[derive(Debug)]
pub struct Lookup {
    /// Where the bundle lives; `None` for [`Lookup::empty`].
    source: Option<Source>,
    current: RwLock<Generation>,
    /// The key scheme the bundle recorded when first opened.
    scheme: Option<String>,
}

/// What a [`Lookup`] needs to reopen its bundle.
#[derive(Debug)]
struct Source {
    dir: PathBuf,
    manifest: PathBuf,
    scheme: String,
}

/// One opened build of a bundle.
#[derive(Debug)]
struct Generation {
    /// `slots[kind][tier]`, so no tier can be reached except by index.
    slots: [[Option<Slot>; Tier::ALL.len()]; Kind::ALL.len()],
    /// The manifest this generation was opened from; `None` for an empty one.
    manifest: Option<FileId>,
}

/// One filter of an opened bundle, held open for the generation's life.
#[cfg(unix)]
#[derive(Debug)]
struct Slot(OnDisk);

#[cfg(unix)]
impl Slot {
    fn new(_path: PathBuf, filter: OnDisk) -> Self {
        Self(filter)
    }

    fn header(&self) -> &Header {
        self.0.header()
    }

    /// Possible membership; `None` when the filter cannot be read, or was
    /// rewritten in place since it was opened.
    fn may_contain(&self, digest: &[u8; 32]) -> Option<bool> {
        if !self.0.is_unchanged() {
            return None;
        }
        self.0.may_contain(digest).ok()
    }
}

/// One filter of an opened bundle: where it is, and what it was at open.
#[cfg(not(unix))]
#[derive(Debug)]
struct Slot {
    path: PathBuf,
    header: Header,
}

#[cfg(not(unix))]
impl Slot {
    fn new(path: PathBuf, filter: OnDisk) -> Self {
        Self {
            path,
            header: *filter.header(),
        }
    }

    fn header(&self) -> &Header {
        &self.header
    }

    /// Possible membership, reopening the file. `None` when it cannot be read
    /// now, or is no longer the filter this slot was opened as.
    ///
    /// The file may belong to a newer build than the one opened, and one
    /// decision may read filters from both. That never yields a skip neither
    /// build would give: a claim from either build denies it, and a blessing
    /// must come from a good filter.
    fn may_contain(&self, digest: &[u8; 32]) -> Option<bool> {
        let filter = OnDisk::open(&self.path).ok()?;
        let now = filter.header();
        if (now.kind, now.tier) != (self.header.kind, self.header.tier) {
            return None;
        }
        filter.may_contain(digest).ok()
    }
}

/// What tells one manifest file from its replacement.
#[cfg(unix)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FileId {
    dev: u64,
    ino: u64,
    len: u64,
    mtime: (i64, i64),
}

#[cfg(unix)]
impl FileId {
    fn of(meta: &std::fs::Metadata) -> Self {
        use std::os::unix::fs::MetadataExt;
        Self {
            dev: meta.dev(),
            ino: meta.ino(),
            len: meta.size(),
            mtime: (meta.mtime(), meta.mtime_nsec()),
        }
    }

    fn now(path: &Path) -> Option<Self> {
        std::fs::metadata(path).ok().map(|m| Self::of(&m))
    }
}

/// Elsewhere the manifest is not watched: slots reopen their files instead.
#[cfg(not(unix))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FileId;

#[cfg(not(unix))]
impl FileId {
    const fn of(_: &std::fs::Metadata) -> Self {
        Self
    }

    #[expect(clippy::unnecessary_wraps, reason = "mirrors the Unix version")]
    const fn now(_: &Path) -> Option<Self> {
        Some(Self)
    }
}

impl Generation {
    fn empty() -> Self {
        Self {
            slots: Default::default(),
            manifest: None,
        }
    }

    /// Open the bundle in `dir`: the rules of [`Lookup::open`].
    fn open(dir: &Path, scheme: &str) -> Result<(Self, Option<String>), OpenError> {
        let (manifest, meta) = load_manifest(dir)?;

        if let Some(found) = manifest.key_scheme.as_deref()
            && found != scheme
        {
            return Err(OpenError::KeyScheme {
                expected: scheme.to_owned(),
                found: found.to_owned(),
            });
        }

        let mut generation = Self {
            slots: Default::default(),
            manifest: Some(FileId::of(&meta)),
        };
        for (stem, entry) in &manifest.filter {
            let file = &entry.file;
            if Path::new(file).file_name() != Some(OsStr::new(file)) {
                return Err(OpenError::UnsafePath { file: file.clone() });
            }
            let path = dir.join(file);
            let filter = match OnDisk::open(&path) {
                Ok(filter) => filter,
                Err(OnDiskError::Io(source)) => return Err(OpenError::Io { path, source }),
                Err(OnDiskError::Invalid(source)) => {
                    return Err(OpenError::Invalid {
                        file: file.clone(),
                        source,
                    });
                }
            };
            let header = *filter.header();
            if header.stem() != *stem {
                return Err(OpenError::Mislabelled {
                    file: file.clone(),
                    claims: header.stem(),
                });
            }
            if header.version != entry.format_version {
                return Err(OpenError::VersionMismatch {
                    file: file.clone(),
                    manifest: entry.format_version,
                    header: header.version,
                });
            }
            generation.slots[header.kind.index()][header.tier.index()] =
                Some(Slot::new(path, filter));
        }
        Ok((generation, manifest.key_scheme))
    }

    fn decide(&self, artifact: &Artifact<'_>) -> Decision {
        let purl = artifact
            .purl
            .map(|p| self.decide_key(Kind::Purl, &digest_of(p.as_bytes())));
        let sha256 = artifact.sha256.map(|d| self.decide_key(Kind::Sha256, d));
        combine(purl.into_iter().chain(sha256))
    }

    /// The rule for one key: every filter is read, and the worst pool wins.
    ///
    /// Reading on past the first claim costs a few probes on a rare path and
    /// keeps the rule free of ordering: what the key's filters say together
    /// is the answer, whichever was read first.
    ///
    /// A blessing needs the `bad` filter loaded to be honored; that is the
    /// revocation channel. A missing *sighted* filter is not the same failure —
    /// that is a bundle predating those tiers, and [`Lookup::open`] has already
    /// ruled out anything missing by accident.
    fn decide_key(&self, kind: Kind, digest: &[u8; 32]) -> Decision {
        let hit = |tier: Tier| {
            self.slot(kind, tier)
                .map_or(Some(false), |slot| slot.may_contain(digest))
        };
        let mut worst = None;
        let mut unreadable = false;
        for (tier, verdict) in ADVERSE {
            match hit(tier) {
                // ADVERSE is worst first, so the first claim is the worst.
                Some(true) => worst = worst.or(Some(verdict)),
                Some(false) => {}
                None => unreadable = true,
            }
        }
        let good = hit(Tier::Good);

        match (worst, good) {
            (Some(_), Some(true)) => Decision::Conflicted,
            (Some(worst), _) => worst,
            (None, None) => Decision::Unavailable,
            (None, Some(_)) if unreadable => Decision::Unavailable,
            (None, Some(true)) if self.slot(kind, Tier::Bad).is_some() => Decision::Skip,
            (None, Some(_)) => Decision::Unknown,
        }
    }

    const fn slot(&self, kind: Kind, tier: Tier) -> Option<&Slot> {
        self.slots[kind.index()][tier.index()].as_ref()
    }

    fn filters(&self) -> impl Iterator<Item = &Slot> {
        self.slots.iter().flatten().flatten()
    }
}

impl Lookup {
    /// A bundle holding nothing: [`Decision::Unknown`] to everything, and no
    /// skips. What a caller falls back to when [`Lookup::open`] fails.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            source: None,
            current: RwLock::new(Generation::empty()),
            scheme: None,
        }
    }

    /// Open the bundle in `dir`, requiring the key scheme `scheme`.
    ///
    /// The manifest is the authority. It must be at [`MANIFEST_SCHEMA`], and
    /// every filter it names must be a bare file name in `dir`, have a valid
    /// header of the stated version, and identify itself as the filter it is
    /// named as. **Any failure fails the whole open**: a partly readable
    /// bundle is exactly the case where a stale bless cannot be vetoed.
    ///
    /// A bundle recording a different `scheme` is refused — producer and
    /// consumer that disagree would otherwise match nothing, silently and
    /// forever. A bundle recording none predates the field and is accepted.
    ///
    /// Only headers are read: manifest digests are not re-verified and the
    /// bit arrays are not scanned. Both belong to whoever installs a bundle —
    /// check each download against its manifest digest and run
    /// [`crate::Filter::load`] on it — so that opening stays cheap.
    ///
    /// # Errors
    /// [`OpenError`] for a missing, unparseable, or unsupported manifest, a
    /// scheme mismatch, or any named filter that will not open.
    pub fn open(dir: impl AsRef<Path>, scheme: &str) -> Result<Self, OpenError> {
        let dir = dir.as_ref();
        let (generation, recorded) = Generation::open(dir, scheme)?;
        Ok(Self {
            source: Some(Source {
                dir: dir.to_owned(),
                manifest: dir.join(MANIFEST_FILE),
                scheme: scheme.to_owned(),
            }),
            current: RwLock::new(generation),
            scheme: recorded,
        })
    }

    /// The verdict for one artifact: every filter consulted for every key,
    /// the worst claim wins, a blessing needs unanimity. A filter that cannot
    /// be read when consulted cannot erase another's claim, but nothing is
    /// blessed without it, and a bundle that cannot be read at all is
    /// [`Decision::Unavailable`].
    pub fn decide(&self, artifact: &Artifact<'_>) -> Decision {
        self.current()
            .map_or(Decision::Unavailable, |g| g.decide(artifact))
    }

    /// Whether this artifact may be skipped.
    #[must_use]
    pub fn may_skip(&self, artifact: &Artifact<'_>) -> bool {
        self.decide(artifact).may_skip()
    }

    /// True when at least one filter is loaded.
    #[must_use]
    pub fn is_active(&self) -> bool {
        self.read().filters().next().is_some()
    }

    /// Total keys across every loaded filter, as their headers record them.
    #[must_use]
    pub fn key_count(&self) -> u64 {
        self.read().filters().map(|slot| slot.header().n).sum()
    }

    /// The key scheme this bundle recorded when it was opened, if any.
    #[must_use]
    pub fn key_scheme(&self) -> Option<&str> {
        self.scheme.as_deref()
    }

    /// The generation to decide with: the one open, if its manifest is still
    /// the one in place, or else a fresh one. `None` when the bundle in place
    /// cannot be opened; the next call tries again.
    fn current(&self) -> Option<RwLockReadGuard<'_, Generation>> {
        let held = self.read();
        let Some(source) = &self.source else {
            return Some(held);
        };
        if Some(FileId::now(&source.manifest)?) == held.manifest {
            return Some(held);
        }
        drop(held);
        let (fresh, _) = Generation::open(&source.dir, &source.scheme).ok()?;
        *self.current.write().unwrap_or_else(PoisonError::into_inner) = fresh;
        Some(self.read())
    }

    fn read(&self) -> RwLockReadGuard<'_, Generation> {
        // Nothing panics while holding the lock, and a generation is replaced
        // whole, so a poisoned one is still consistent.
        self.current.read().unwrap_or_else(PoisonError::into_inner)
    }
}

/// Why a bundle could not be opened. Every variant means the same to a caller:
/// no usable bundle, so nothing may be skipped.
#[derive(Debug)]
pub enum OpenError {
    /// A file could not be read: the manifest, or a filter it names.
    Io {
        /// The file being read.
        path: PathBuf,
        /// What went wrong.
        source: io::Error,
    },
    /// The manifest is not valid TOML, or not shaped like a manifest.
    Parse {
        /// The manifest's path.
        path: PathBuf,
        /// What went wrong.
        source: Box<toml::de::Error>,
    },
    /// The manifest's layout version is not [`MANIFEST_SCHEMA`].
    Schema {
        /// The manifest's path.
        path: PathBuf,
        /// The version it declares.
        found: u32,
    },
    /// The bundle's key scheme is not the caller's. Not corruption: producer
    /// and consumer would simply agree on nothing.
    KeyScheme {
        /// What the caller asked for.
        expected: String,
        /// What the bundle records.
        found: String,
    },
    /// A manifest entry's file is not a bare file name in the bundle directory.
    UnsafePath {
        /// The file name as the manifest gives it.
        file: String,
    },
    /// A filter the manifest names is not a valid filter.
    Invalid {
        /// The file name as the manifest gives it.
        file: String,
        /// What is wrong with it.
        source: LoadError,
    },
    /// A filter's header disagrees with the stem the manifest gave it.
    Mislabelled {
        /// The file name as the manifest gives it.
        file: String,
        /// The stem the file's own header claims.
        claims: String,
    },
    /// A filter's header version disagrees with its manifest entry.
    VersionMismatch {
        /// The file name as the manifest gives it.
        file: String,
        /// The version the manifest records.
        manifest: u16,
        /// The version the file's header carries.
        header: u16,
    },
}

impl fmt::Display for OpenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { path, source } => write!(f, "reading {}: {source}", path.display()),
            Self::Parse { path, source } => write!(f, "parsing {}: {source}", path.display()),
            Self::Schema { path, found } => write!(
                f,
                "{}: manifest schema {found}, this build reads {MANIFEST_SCHEMA}",
                path.display()
            ),
            Self::KeyScheme { expected, found } => write!(
                f,
                "bundle uses key scheme {found:?}, this build uses {expected:?}"
            ),
            Self::UnsafePath { file } => write!(f, "{file:?} is not a bare file name"),
            Self::Invalid { file, source } => write!(f, "{file}: {source}"),
            Self::Mislabelled { file, claims } => {
                write!(f, "{file} identifies itself as {claims}")
            }
            Self::VersionMismatch {
                file,
                manifest,
                header,
            } => write!(
                f,
                "{file} is format v{header}, the manifest says v{manifest}"
            ),
        }
    }
}

impl std::error::Error for OpenError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            Self::Parse { source, .. } => Some(source),
            Self::Invalid { source, .. } => Some(source),
            Self::Schema { .. }
            | Self::KeyScheme { .. }
            | Self::UnsafePath { .. }
            | Self::Mislabelled { .. }
            | Self::VersionMismatch { .. } => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use Decision::{
        Conflicted, KnownBad, SightedHostile, SightedSuspicious, Skip, Unavailable, Unknown,
    };

    const ALL: [Decision; 7] = [
        KnownBad,
        SightedHostile,
        SightedSuspicious,
        Conflicted,
        Skip,
        Unknown,
        Unavailable,
    ];

    fn of(ds: &[Decision]) -> Decision {
        combine(ds.iter().copied())
    }

    #[test]
    fn only_skip_may_skip() {
        for d in ALL {
            assert_eq!(d.may_skip(), d == Skip, "{d:?}");
        }
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
        assert_eq!(of(&[KnownBad, KnownBad, SightedSuspicious]), KnownBad);
    }

    #[test]
    fn an_unreadable_key_blocks_a_blessing_but_not_a_claim() {
        assert_eq!(of(&[Skip, Unavailable]), Unavailable);
        assert_eq!(of(&[Unknown, Unavailable]), Unavailable);
        assert_eq!(of(&[KnownBad, Unavailable]), KnownBad);
        assert_eq!(of(&[SightedSuspicious, Unavailable]), SightedSuspicious);
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
        }
    }

    /// The table must stay in the intended order: `decide_key` keeps the first
    /// claim it reads as the worst.
    #[test]
    fn adverse_is_ordered_worst_first() {
        let severities: Vec<Option<u8>> = ADVERSE.iter().map(|(_, d)| d.severity()).collect();
        assert!(
            severities.is_sorted_by(|a, b| a > b),
            "ADVERSE must be strictly worst-first: {severities:?}"
        );
        assert!(!ADVERSE.iter().any(|(t, _)| *t == Tier::Good));
    }

    #[test]
    fn an_empty_lookup_knows_nothing_and_skips_nothing() {
        let lk = Lookup::empty();
        assert!(!lk.is_active());
        assert_eq!(lk.key_count(), 0);
        assert_eq!(lk.decide(&Artifact::sha256(&[1u8; 32])), Unknown);
        assert!(!lk.may_skip(&Artifact::purl("pkg:npm/x@1")));
    }
}
