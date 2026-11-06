//! Consuming a bundle: the decision rule, and the one type that applies it.

use std::ffi::OsStr;
use std::fmt;
use std::fs::Metadata;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{PoisonError, RwLock, RwLockReadGuard, RwLockWriteGuard};
use std::time::{Duration, Instant, SystemTime};

use crate::filter::{Header, Kind, LoadError, OnDisk, OnDiskError, Tier, digest_of, stem};
use crate::manifest::{MANIFEST_FILE, ManifestError, load_manifest};

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
    /// Nothing claims this artifact, and not every key supplied is blessed.
    /// Scan.
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

impl fmt::Display for Decision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
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
/// reads one page of each filter it consults, so a bundle costs no memory for
/// its bits.
///
/// An open bundle follows its directory. Each decision checks the manifest's
/// identity — a single `stat` — and reopens the whole bundle when it has been
/// replaced, as [`write_bundle`] and a directory swap both do. A replacement
/// that will not open yields [`Decision::Unavailable`] until one does: it is
/// tried again when its manifest changes, or once a second has passed, and
/// never by more than one thread at a time. [`Lookup::refresh`] tries at once
/// and says what is wrong. On Unix
/// the filter files are held open, so decisions always read one build.
/// Elsewhere no handle is held between decisions, so an updater can rename the
/// directory out from under an open bundle; each decision reopens the filters
/// it consults instead.
///
/// Replace bundle files by renaming over them, as [`write_bundle`] does,
/// never by rewriting them in place. A held handle keeps the file it opened
/// through a rename, but an in-place rewrite changes the bytes beneath it,
/// mid-write included, and nothing re-reads a header to notice: that would
/// cost every decision a read per filter.
///
/// [`write_bundle`]: crate::write_bundle
#[derive(Debug)]
pub struct Lookup {
    /// `None` for [`Lookup::empty`].
    bundle: Option<Bundle>,
}

/// An opened bundle, and what it takes to reopen it.
#[derive(Debug)]
struct Bundle {
    dir: PathBuf,
    manifest: PathBuf,
    /// The key scheme required at open, and so of every generation since.
    scheme: String,
    current: RwLock<State>,
}

/// How long a manifest that failed to open is left alone before a decision
/// tries it again. A replacement normally fixes itself by being replaced,
/// which is retried at once; this bounds the cost of one that never is.
const RETRY_AFTER: Duration = Duration::from_secs(1);

/// The generation decisions read, and how the last reopen went.
#[derive(Debug)]
struct State {
    generation: Generation,
    /// Set while the manifest in place is one that failed to open.
    failed: Option<Failure>,
}

/// A reopen that failed: of which manifest, and when.
#[derive(Debug, Clone, Copy)]
struct Failure {
    manifest: FileId,
    at: Instant,
}

impl State {
    fn is_for(&self, manifest: FileId) -> bool {
        self.generation.manifest == manifest
    }

    /// Whether `manifest` failed to open too recently to try again.
    fn deferring(&self, manifest: FileId) -> bool {
        self.failed
            .is_some_and(|f| f.manifest == manifest && f.at.elapsed() < RETRY_AFTER)
    }
}

/// One opened build of a bundle.
#[derive(Debug)]
struct Generation {
    /// One slot per (kind, tier), kind-major in [`Kind::ALL`] and
    /// [`Tier::ALL`] order. Never partial: [`Generation::open`] refuses a
    /// bundle missing any.
    slots: Vec<Slot>,
    /// The manifest this generation was opened from.
    manifest: FileId,
}

/// One filter of an opened bundle, held open for the generation's life.
#[cfg(unix)]
#[derive(Debug)]
struct Slot(OnDisk);

#[cfg(unix)]
impl Slot {
    /// The path is not kept: the held handle follows its file wherever it is
    /// renamed, so decisions read the build that was opened.
    fn new(_path: PathBuf, filter: OnDisk) -> Self {
        Self(filter)
    }

    fn header(&self) -> &Header {
        self.0.header()
    }

    /// Possible membership; `None` when the filter cannot be read.
    fn may_contain(&self, digest: &[u8; 32]) -> Option<bool> {
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
    /// Only the header is kept. The file is closed: here a held handle would
    /// stop an updater renaming the bundle's directory.
    fn new(path: PathBuf, filter: OnDisk) -> Self {
        let header = *filter.header();
        drop(filter);
        Self { path, header }
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

/// What tells one manifest file from its replacement. A rename gives the path
/// a new inode; an in-place rewrite a new length or modification time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FileId {
    len: u64,
    modified: Option<SystemTime>,
    #[cfg(unix)]
    inode: (u64, u64),
}

impl FileId {
    fn of(meta: &Metadata) -> Self {
        Self {
            len: meta.len(),
            modified: meta.modified().ok(),
            #[cfg(unix)]
            inode: {
                use std::os::unix::fs::MetadataExt;
                (meta.dev(), meta.ino())
            },
        }
    }

    fn now(path: &Path) -> io::Result<Self> {
        std::fs::metadata(path).map(|m| Self::of(&m))
    }
}

impl Generation {
    /// Open the bundle in `dir`: the rules of [`Lookup::open`].
    fn open(dir: &Path, scheme: &str) -> Result<Self, OpenError> {
        let (mut manifest, meta) = load_manifest(dir)?;
        if manifest.key_scheme != scheme {
            return Err(OpenError::KeyScheme {
                expected: scheme.to_owned(),
                found: manifest.key_scheme,
            });
        }

        let mut slots = Vec::with_capacity(Kind::ALL.len() * Tier::ALL.len());
        for kind in Kind::ALL {
            for tier in Tier::ALL {
                let name = stem(kind, tier);
                let Some(entry) = manifest.filter.remove(name) else {
                    return Err(OpenError::Missing {
                        stem: name.to_owned(),
                    });
                };
                let file = entry.file;
                if Path::new(&file).file_name() != Some(OsStr::new(&file)) {
                    return Err(OpenError::UnsafePath { file });
                }
                let path = dir.join(&file);
                let filter = match OnDisk::open(&path) {
                    Ok(filter) => filter,
                    Err(OnDiskError::Io(source)) => return Err(OpenError::Io { path, source }),
                    Err(OnDiskError::Invalid(source)) => {
                        return Err(OpenError::Invalid { file, source });
                    }
                };
                let header = filter.header();
                if (header.kind, header.tier) != (kind, tier) {
                    return Err(OpenError::Mislabelled {
                        file,
                        claims: stem(header.kind, header.tier).to_owned(),
                    });
                }
                slots.push(Slot::new(path, filter));
            }
        }
        // Whatever is left names no slot this build has.
        if let Some(stem) = manifest.filter.into_keys().next() {
            return Err(OpenError::UnknownFilter { stem });
        }
        Ok(Self {
            slots,
            manifest: FileId::of(&meta),
        })
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
    /// Every slot is filled, so the `bad` filter that revokes a blessing is
    /// always consulted. One that cannot be read now (`None`) blesses
    /// nothing.
    fn decide_key(&self, kind: Kind, digest: &[u8; 32]) -> Decision {
        let hit = |tier: Tier| self.slot(kind, tier).may_contain(digest);
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
            (None, Some(true)) => Decision::Skip,
            (None, Some(false)) => Decision::Unknown,
        }
    }

    fn slot(&self, kind: Kind, tier: Tier) -> &Slot {
        &self.slots[kind.index() * Tier::ALL.len() + tier.index()]
    }
}

impl Lookup {
    /// A bundle holding nothing: [`Decision::Unknown`] to everything, and no
    /// skips. What a caller falls back to when [`Lookup::open`] fails.
    #[must_use]
    pub const fn empty() -> Self {
        Self { bundle: None }
    }

    /// Open the bundle in `dir`, requiring the key scheme `scheme`.
    ///
    /// The manifest is the authority. It must be at [`crate::MANIFEST_SCHEMA`] and
    /// name exactly one filter for every (kind, tier), and each filter must be
    /// a bare file name in `dir`, have a valid header, and identify itself as
    /// the filter it is named as. **Any failure fails the whole open**: a
    /// partly readable bundle is exactly the case where a stale bless cannot
    /// be vetoed.
    ///
    /// A bundle recording a different `scheme` is refused — producer and
    /// consumer that disagree would otherwise match nothing, silently and
    /// forever.
    ///
    /// Only headers are read: manifest digests are not re-verified and the
    /// bit arrays are not scanned. Both belong to whoever installs a bundle —
    /// check each download against its manifest digest and run
    /// [`crate::Filter::load`] on it — so that opening stays cheap.
    ///
    /// # Errors
    /// [`OpenError`] for a missing, oversized, unparseable, or unsupported
    /// manifest, a scheme mismatch, a missing or unknown filter entry, or any
    /// named filter that will not open.
    pub fn open(dir: impl AsRef<Path>, scheme: &str) -> Result<Self, OpenError> {
        let dir = dir.as_ref();
        let generation = Generation::open(dir, scheme)?;
        Ok(Self {
            bundle: Some(Bundle {
                dir: dir.to_owned(),
                manifest: dir.join(MANIFEST_FILE),
                scheme: scheme.to_owned(),
                current: RwLock::new(State {
                    generation,
                    failed: None,
                }),
            }),
        })
    }

    /// The verdict for one artifact: every filter consulted for every key,
    /// the worst claim wins, a blessing needs unanimity. A filter that cannot
    /// be read when consulted cannot erase another's claim, but nothing is
    /// blessed without it, and a bundle that cannot be read at all is
    /// [`Decision::Unavailable`]. [`Lookup::empty`] knows nothing:
    /// [`Decision::Unknown`].
    pub fn decide(&self, artifact: &Artifact<'_>) -> Decision {
        let Some(bundle) = &self.bundle else {
            return Decision::Unknown;
        };
        bundle
            .current()
            .map_or(Decision::Unavailable, |s| s.generation.decide(artifact))
    }

    /// Bring the bundle up to date now, and say why it cannot be.
    ///
    /// [`Lookup::decide`] does this itself, quietly: a replacement that will
    /// not open makes decisions [`Decision::Unavailable`], and is retried only
    /// when its manifest changes or a second has passed. Call this to retry at
    /// once and learn why — to log it after an `Unavailable`, say. `Ok` for
    /// [`Lookup::empty`], which has nothing to refresh.
    ///
    /// # Errors
    /// What [`Lookup::open`] would return for the bundle in place, including
    /// [`OpenError::Manifest`] when its manifest is gone.
    pub fn refresh(&self) -> Result<(), OpenError> {
        self.bundle.as_ref().map_or(Ok(()), Bundle::refresh)
    }

    /// Whether this artifact may be skipped.
    #[must_use]
    pub fn may_skip(&self, artifact: &Artifact<'_>) -> bool {
        self.decide(artifact).may_skip()
    }

    /// True when a bundle is open: this is not [`Lookup::empty`].
    #[must_use]
    pub const fn is_active(&self) -> bool {
        self.bundle.is_some()
    }

    /// Total keys across the filters a decision would read now, as their
    /// headers record them; 0 when the bundle in place will not open.
    #[must_use]
    pub fn key_count(&self) -> u64 {
        let Some(bundle) = &self.bundle else {
            return 0;
        };
        bundle.current().map_or(0, |s| {
            s.generation.slots.iter().map(|slot| slot.header().n).sum()
        })
    }

    /// The key scheme this bundle was opened with, which every bundle it
    /// reopens must share; `None` for [`Lookup::empty`].
    #[must_use]
    pub fn key_scheme(&self) -> Option<&str> {
        self.bundle.as_ref().map(|b| b.scheme.as_str())
    }
}

impl Bundle {
    /// The state to decide with: the generation open, if its manifest is
    /// still the one in place, or else a fresh one. `None` when the bundle in
    /// place cannot be opened, or failed to too recently to try again.
    fn current(&self) -> Option<RwLockReadGuard<'_, State>> {
        let manifest = FileId::now(&self.manifest).ok()?;
        let held = self.read();
        if held.is_for(manifest) {
            return Some(held);
        }
        if held.deferring(manifest) {
            return None;
        }
        drop(held);

        let mut state = self.write();
        // Another thread may have reopened it, or failed to, while this one
        // waited for the lock. Either way, once is enough.
        if !state.is_for(manifest) {
            if state.deferring(manifest) {
                return None;
            }
            self.reopen(&mut state, manifest).ok()?;
        }
        drop(state);
        Some(self.read())
    }

    /// [`Lookup::refresh`]: [`Self::current`], without the deferral, and
    /// with the reason.
    fn refresh(&self) -> Result<(), OpenError> {
        let manifest = FileId::now(&self.manifest).map_err(|source| ManifestError::Io {
            path: self.manifest.clone(),
            source,
        })?;
        let mut state = self.write();
        if state.is_for(manifest) {
            return Ok(());
        }
        self.reopen(&mut state, manifest)
    }

    /// Replace the generation with the bundle in place, whose manifest is
    /// `manifest`, or record that it would not open.
    fn reopen(&self, state: &mut State, manifest: FileId) -> Result<(), OpenError> {
        match Generation::open(&self.dir, &self.scheme) {
            Ok(fresh) => {
                state.generation = fresh;
                state.failed = None;
                Ok(())
            }
            Err(err) => {
                state.failed = Some(Failure {
                    manifest,
                    at: Instant::now(),
                });
                Err(err)
            }
        }
    }

    /// Nothing panics while holding the lock, and a generation is replaced
    /// whole, so a poisoned state is still consistent. So too for
    /// [`Self::write`].
    fn read(&self) -> RwLockReadGuard<'_, State> {
        self.current.read().unwrap_or_else(PoisonError::into_inner)
    }

    fn write(&self) -> RwLockWriteGuard<'_, State> {
        self.current.write().unwrap_or_else(PoisonError::into_inner)
    }
}

/// [`Lookup::empty`].
impl Default for Lookup {
    fn default() -> Self {
        Self::empty()
    }
}

/// Why a bundle could not be opened. Every variant means the same to a caller:
/// no usable bundle, so nothing may be skipped.
#[derive(Debug)]
pub enum OpenError {
    /// The manifest is missing, unreadable, or not one this build reads.
    Manifest(ManifestError),
    /// A filter the manifest names could not be read.
    Io {
        /// The filter's path.
        path: PathBuf,
        /// What went wrong.
        source: io::Error,
    },
    /// The bundle's key scheme is not the caller's. Not corruption: producer
    /// and consumer would simply agree on nothing.
    KeyScheme {
        /// What the caller asked for.
        expected: String,
        /// What the bundle records.
        found: String,
    },
    /// The manifest names no filter for this (kind, tier). Every one is
    /// required: a bundle without its `bad` filter cannot revoke a blessing,
    /// and one without a `sighted` filter silently drops those claims.
    Missing {
        /// The stem with no entry.
        stem: String,
    },
    /// The manifest names a filter for a slot this build does not have.
    UnknownFilter {
        /// The stem as the manifest gives it.
        stem: String,
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
}

impl fmt::Display for OpenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Manifest(err) => err.fmt(f),
            Self::Io { path, source } => write!(f, "reading {}: {source}", path.display()),
            Self::KeyScheme { expected, found } => write!(
                f,
                "bundle uses key scheme {found:?}, this build uses {expected:?}"
            ),
            Self::Missing { stem } => write!(f, "manifest names no {stem} filter"),
            Self::UnknownFilter { stem } => write!(f, "manifest names unknown filter {stem:?}"),
            Self::UnsafePath { file } => write!(f, "{file:?} is not a bare file name"),
            Self::Invalid { file, source } => write!(f, "{file}: {source}"),
            Self::Mislabelled { file, claims } => {
                write!(f, "{file} identifies itself as {claims}")
            }
        }
    }
}

impl std::error::Error for OpenError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            // Transparent, as its Display is.
            Self::Manifest(err) => err.source(),
            Self::Io { source, .. } => Some(source),
            Self::Invalid { source, .. } => Some(source),
            Self::KeyScheme { .. }
            | Self::Missing { .. }
            | Self::UnknownFilter { .. }
            | Self::UnsafePath { .. }
            | Self::Mislabelled { .. } => None,
        }
    }
}

impl From<ManifestError> for OpenError {
    fn from(err: ManifestError) -> Self {
        Self::Manifest(err)
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
