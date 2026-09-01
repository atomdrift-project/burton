//! The on-disk filter: a self-describing header followed by a bit array.
//!
//! # Layout
//!
//! All integers are little-endian. The header is 36 bytes:
//!
//! ```text
//! offset  size  field
//!      0     4  magic, always "ADBL"
//!      4     2  format version
//!      6     1  key kind      (see Kind)
//!      7     1  trust tier    (see Tier)
//!      8     4  k, hash functions per key
//!     12     8  m, bits in the array; always a power of two
//!     20     8  n, keys inserted at build time (informational)
//!     28     8  seed, reserved; producers write zero
//! ```
//!
//! The bit array follows, exactly `m / 8` bytes of it.
//!
//! # Hashing
//!
//! A key is reduced to a 32-byte SHA-256 digest, from which `k` indices are
//! derived by double hashing: `i_j = (h1 + j*h2) mod m`, `h1` and `h2` being the
//! digest's first two 64-bit lanes with `h2` forced odd so it is coprime with
//! the modulus. A [`Kind::Sha256`] key is already uniform and is used directly.
//!
//! SHA-256 is identical everywhere, so a producer in another language agrees bit
//! for bit if it canonicalizes keys the same way. Nothing here checks that; the
//! bundle's key scheme does (see [`crate::Lookup::open`]).
//!
//! # Reading is strict
//!
//! [`Filter::load`] rejects rather than interprets: wrong magic, an unknown
//! version, a tier that version cannot carry, `k` or `m` out of bounds, a bit
//! array whose length disagrees with the header. The one guess that matters —
//! is this key blessed? — is the one that must not be wrong.

use std::fmt;

use sha2::{Digest, Sha256};

/// Layout version this build writes. Bump on any header or bit-derivation
/// change. v2 added the `sighted-*` tiers and is otherwise byte-identical to
/// v1, which is what lets one build read both.
pub const FORMAT_VERSION: u16 = 2;

/// Layout versions this build can read, newest first. A v1 filter is a v2
/// filter using none of the newer tiers, so reading one is not reinterpretation.
/// Anything outside this list is [`LoadError::UnsupportedVersion`].
pub const SUPPORTED_VERSIONS: &[u16] = &[2, 1];

const MAGIC: [u8; 4] = *b"ADBL";

/// Fixed header length in bytes.
pub(crate) const HEADER_LEN: usize = 36;

/// Upper bound on hash functions per key. Bounds the probe loop and keeps a
/// corrupt header from producing an absurd amount of work.
const MAX_K: u32 = 64;

/// Smallest bit array a filter may declare. Below this, `m / 8` rounds to a
/// byte count that cannot hold the array the header describes.
const MIN_BITS: u64 = 64;

/// The category of key a filter holds. Stored in the header so a filter in the
/// wrong slot is rejected rather than consulted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Kind {
    /// Canonical package URLs, e.g. `pkg:npm/left-pad@1.3.0`. The canonical
    /// form is the producer's to define; see [`crate::Lookup::open`].
    Purl,
    /// 32-byte SHA-256 artifact digests, used directly with no rehash.
    Sha256,
}

impl Kind {
    /// Every kind, in slot order.
    pub const ALL: [Self; 2] = [Self::Purl, Self::Sha256];

    /// Wire value. Permanent: it is the header's `kind` byte.
    const fn to_u8(self) -> u8 {
        match self {
            Self::Purl => 1,
            Self::Sha256 => 3,
        }
    }

    const fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(Self::Purl),
            // 2 was `url`, never published. The value stays retired.
            3 => Some(Self::Sha256),
            _ => None,
        }
    }

    /// Dense index, for slot arrays.
    pub(crate) const fn index(self) -> usize {
        match self {
            Self::Purl => 0,
            Self::Sha256 => 1,
        }
    }

    /// Lowercase slug used in artifact file names.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Purl => "purl",
            Self::Sha256 => "sha256",
        }
    }
}

/// The trust tier a filter encodes.
///
/// `Bad` and the `Sighted` tiers differ by provenance, not strength: bad means
/// the producer measured it hostile, sighted means somebody else says so.
/// Keeping them apart lets a consumer report "cited by threat intelligence"
/// without claiming to have found anything itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Tier {
    /// Affirmatively blessed. A hit here, and nowhere else, permits a skip.
    Good,
    /// Catalogued bad by the producer's own analysis.
    Bad,
    /// Corroborated outside claims: two or more independent operators, or one
    /// whose report a person adjudicated.
    SightedHostile,
    /// A lone, unadjudicated outside claim. A flag, not a verdict — but still
    /// enough to deny a skip.
    SightedSuspicious,
}

impl Tier {
    /// Every tier, in slot order.
    pub const ALL: [Self; 4] = [
        Self::Good,
        Self::Bad,
        Self::SightedHostile,
        Self::SightedSuspicious,
    ];

    /// Wire value. Permanent: it is the header's `tier` byte, and a build that
    /// reassigned one would load an old filter into the wrong slot. Append only.
    const fn to_u8(self) -> u8 {
        match self {
            Self::Good => 1,
            Self::Bad => 2,
            // 3 was `unknown-clean`, never published. The value stays retired.
            Self::SightedHostile => 4,
            Self::SightedSuspicious => 5,
        }
    }

    const fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(Self::Good),
            2 => Some(Self::Bad),
            4 => Some(Self::SightedHostile),
            5 => Some(Self::SightedSuspicious),
            _ => None,
        }
    }

    /// Dense index, for slot arrays.
    pub(crate) const fn index(self) -> usize {
        match self {
            Self::Good => 0,
            Self::Bad => 1,
            Self::SightedHostile => 2,
            Self::SightedSuspicious => 3,
        }
    }

    /// Lowercase slug used in artifact file names.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Good => "good",
            Self::Bad => "bad",
            Self::SightedHostile => "sighted-hostile",
            Self::SightedSuspicious => "sighted-suspicious",
        }
    }

    /// The lowest format version that can carry this tier. A bundle published
    /// at an older version must omit the tiers above its own.
    #[must_use]
    pub const fn min_format_version(self) -> u16 {
        match self {
            Self::Good | Self::Bad => 1,
            Self::SightedHostile | Self::SightedSuspicious => 2,
        }
    }
}

/// Why a serialized filter could not be loaded. Every variant means the same:
/// the file is unusable, and [`crate::Lookup::open`] refuses the whole bundle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LoadError {
    /// Shorter than a complete header, or than the bit array it declares.
    Truncated,
    /// Leading bytes are not `"ADBL"`.
    BadMagic,
    /// A layout version outside [`SUPPORTED_VERSIONS`].
    UnsupportedVersion(u16),
    /// A header field is structurally invalid. The string names the field.
    Corrupt(&'static str),
}

impl fmt::Display for LoadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated => f.write_str("truncated"),
            Self::BadMagic => f.write_str("bad magic (not an ADBL filter)"),
            Self::UnsupportedVersion(v) => {
                write!(f, "format v{v}, this build reads {SUPPORTED_VERSIONS:?}")
            }
            Self::Corrupt(field) => write!(f, "corrupt header field: {field}"),
        }
    }
}

impl std::error::Error for LoadError {}

/// An immutable, queryable filter.
///
/// One buffer holds the whole file image: loading does not copy the bit array
/// out of it and writing hands it straight back, so a 32 MiB filter costs
/// 32 MiB once. Membership testing is deliberately not public.
#[derive(Clone)]
pub struct Filter {
    /// The whole on-disk image: [`HEADER_LEN`] bytes of header, then the bits.
    bytes: Vec<u8>,
    kind: Kind,
    tier: Tier,
    version: u16,
    k: u32,
    m_bits: u64,
    n: u64,
    seed: u64,
}

impl fmt::Debug for Filter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Filter")
            .field("stem", &self.stem())
            .field("version", &self.version)
            .field("k", &self.k)
            .field("m_bits", &self.m_bits)
            .field("n", &self.n)
            .finish()
    }
}

impl Filter {
    /// The key category this filter holds.
    #[must_use]
    pub const fn kind(&self) -> Kind {
        self.kind
    }

    /// The trust tier this filter encodes.
    #[must_use]
    pub const fn tier(&self) -> Tier {
        self.tier
    }

    /// The layout version this filter carries.
    #[must_use]
    pub const fn version(&self) -> u16 {
        self.version
    }

    /// Keys inserted at build time.
    #[must_use]
    pub const fn len(&self) -> u64 {
        self.n
    }

    /// True when no keys were inserted.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.n == 0
    }

    /// Canonical artifact stem, e.g. `purl-good`. The one place file names
    /// are spelled.
    #[must_use]
    pub fn stem(&self) -> String {
        format!("{}-{}", self.kind.as_str(), self.tier.as_str())
    }

    /// The on-disk image, ready to write. No allocation, no copy.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Re-stamp for an older bundle, or `None` when this tier did not exist at
    /// that version.
    ///
    /// `None` rather than a silent downgrade: a `sighted-*` filter has no v1
    /// meaning, and writing one into a v1 bundle hands a client a file it must
    /// reject, failing its whole update. The caller folds or drops.
    #[must_use]
    pub fn stamped_as(mut self, version: u16) -> Option<Self> {
        if version < self.tier.min_format_version() || !SUPPORTED_VERSIONS.contains(&version) {
            return None;
        }
        self.version = version;
        let slot = self.bytes.get_mut(4..6)?;
        slot.copy_from_slice(&version.to_le_bytes());
        Some(self)
    }

    /// Test a key for possible membership. `false` is authoritative; `true` is
    /// probabilistic.
    ///
    /// Crate-private, and staying that way: anyone who can ask one filter this
    /// can act on a `good` hit without consulting the adverse tiers.
    pub(crate) fn may_contain(&self, digest: &[u8; 32]) -> bool {
        // `all` short-circuits, so a miss costs about two probes rather than k.
        // Most queries are misses; this is the hot path.
        self.probes(digest).all(|i| self.bit(i))
    }

    fn probes(&self, digest: &[u8; 32]) -> Probes {
        Probes::new(self.k, self.m_bits, self.seed, digest)
    }

    #[inline]
    fn bit(&self, idx: usize) -> bool {
        // idx < m_bits by construction, so the byte is in range; ask anyway.
        self.bytes
            .get(HEADER_LEN + (idx >> 3))
            .is_some_and(|b| b & (1u8 << (idx & 7)) != 0)
    }

    /// Parse a filter from its on-disk image, taking ownership of the buffer.
    ///
    /// # Errors
    /// [`LoadError`] if the buffer is truncated, the magic or version does not
    /// match, or a header field is invalid.
    pub fn load(bytes: Vec<u8>) -> Result<Self, LoadError> {
        let head = bytes.get(..HEADER_LEN).ok_or(LoadError::Truncated)?;
        let u16_at = |o: usize| -> u16 {
            head.get(o..o + 2)
                .and_then(|s| s.try_into().ok())
                .map_or(0, u16::from_le_bytes)
        };
        let u32_at = |o: usize| -> u32 {
            head.get(o..o + 4)
                .and_then(|s| s.try_into().ok())
                .map_or(0, u32::from_le_bytes)
        };
        let u64_at = |o: usize| -> u64 {
            head.get(o..o + 8)
                .and_then(|s| s.try_into().ok())
                .map_or(0, u64::from_le_bytes)
        };

        if head.get(..4) != Some(&MAGIC) {
            return Err(LoadError::BadMagic);
        }
        let version = u16_at(4);
        if !SUPPORTED_VERSIONS.contains(&version) {
            return Err(LoadError::UnsupportedVersion(version));
        }
        let kind = head
            .get(6)
            .copied()
            .and_then(Kind::from_u8)
            .ok_or(LoadError::Corrupt("kind"))?;
        let tier = head
            .get(7)
            .copied()
            .and_then(Tier::from_u8)
            .ok_or(LoadError::Corrupt("tier"))?;
        // A tier the declared version cannot carry means the file is
        // mislabelled, not merely new. Reject rather than pick a field to
        // believe: this catches a v2 filter republished under a v1 name, which
        // would otherwise reach a v1 reader as a plausible-looking `bad`.
        if tier.min_format_version() > version {
            return Err(LoadError::Corrupt("tier newer than declared version"));
        }

        let k = u32_at(8);
        if k == 0 || k > MAX_K {
            return Err(LoadError::Corrupt("k out of range"));
        }
        let m_bits = u64_at(12);
        if m_bits < MIN_BITS || !m_bits.is_power_of_two() {
            return Err(LoadError::Corrupt("m_bits not a power of two >= 64"));
        }
        // The image is the header plus exactly m/8 bytes, no more.
        if (bytes.len() as u64).checked_sub(HEADER_LEN as u64) != Some(m_bits / 8) {
            return Err(LoadError::Truncated);
        }

        Ok(Self {
            kind,
            tier,
            version,
            k,
            m_bits,
            n: u64_at(20),
            seed: u64_at(28),
            bytes,
        })
    }
}

/// Accumulates keys and produces a [`Filter`]. Bloom filters cannot delete, so
/// revoking a key means rebuilding without it.
#[derive(Debug)]
pub(crate) struct Builder {
    bytes: Vec<u8>,
    kind: Kind,
    tier: Tier,
    k: u32,
    m_bits: u64,
    n: u64,
}

impl Builder {
    /// Size a builder for `expected` keys at `target_fp` false-positive rate.
    ///
    /// `target_fp` outside `(0, 1)` falls back to `1e-9`; `expected` is floored
    /// at 1 so the filter is never zero-bit.
    ///
    /// `m = -n·ln(p) / (ln 2)²`, rounded up to a power of two so indexing is a
    /// mask. `k` is `log2(1/p)`, the probe count that reaches `p` at the ideal
    /// `m`; rounding only made `m` larger, so it reaches `p` here too. The
    /// textbook `(m/n)·ln 2` would spend up to twice the probes buying accuracy
    /// nobody asked for — we cap by it only because it is smaller when rounding
    /// leaves the filter tight.
    #[must_use]
    #[allow(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        clippy::cast_precision_loss
    )]
    // Inputs are small positive counts and probabilities, and the result is
    // bounded by next_power_of_two and clamped, so these conversions are exact
    // in the range that reaches them.
    pub(crate) fn new(kind: Kind, tier: Tier, expected: u64, target_fp: f64) -> Self {
        const LN2: f64 = std::f64::consts::LN_2;
        let n = expected.max(1);
        let p = if target_fp.is_finite() && target_fp > 0.0 && target_fp < 1.0 {
            target_fp
        } else {
            1e-9
        };
        let raw_bits = -(n as f64) * p.ln() / (LN2 * LN2);
        let m_bits = (raw_bits.ceil() as u64).max(MIN_BITS).next_power_of_two();
        let needed = -p.log2();
        let optimal = (m_bits as f64 / n as f64) * LN2;
        let k = (needed.min(optimal).ceil() as u32).clamp(1, MAX_K);

        let mut bytes = Vec::with_capacity(HEADER_LEN + (m_bits / 8) as usize);
        bytes.extend_from_slice(&MAGIC);
        bytes.extend_from_slice(&FORMAT_VERSION.to_le_bytes());
        bytes.push(kind.to_u8());
        bytes.push(tier.to_u8());
        bytes.extend_from_slice(&k.to_le_bytes());
        bytes.extend_from_slice(&m_bits.to_le_bytes());
        bytes.extend_from_slice(&0u64.to_le_bytes()); // n, patched by build()
        bytes.extend_from_slice(&0u64.to_le_bytes()); // seed, reserved
        bytes.resize(HEADER_LEN + (m_bits / 8) as usize, 0);

        Self {
            bytes,
            kind,
            tier,
            k,
            m_bits,
            n: 0,
        }
    }

    /// Insert a variable-length key.
    pub(crate) fn insert_key(&mut self, key: &[u8]) {
        self.insert_digest(&digest_of(key));
    }

    /// Insert a 32-byte SHA-256 digest directly.
    pub(crate) fn insert_digest(&mut self, digest: &[u8; 32]) {
        for idx in Probes::new(self.k, self.m_bits, 0, digest) {
            if let Some(byte) = self.bytes.get_mut(HEADER_LEN + (idx >> 3)) {
                *byte |= 1u8 << (idx & 7);
            }
        }
        self.n += 1;
    }

    /// Finalize into an immutable [`Filter`].
    #[must_use]
    pub(crate) fn build(mut self) -> Filter {
        if let Some(slot) = self.bytes.get_mut(20..28) {
            slot.copy_from_slice(&self.n.to_le_bytes());
        }
        Filter {
            bytes: self.bytes,
            kind: self.kind,
            tier: self.tier,
            version: FORMAT_VERSION,
            k: self.k,
            m_bits: self.m_bits,
            n: self.n,
            seed: 0,
        }
    }
}

/// The `k` bit indices for one digest. One derivation shared by insert and
/// query, so they cannot drift; an iterator, so a query stops at the first
/// clear bit.
struct Probes {
    h: u64,
    step: u64,
    mask: u64,
    left: u32,
}

impl Probes {
    fn new(k: u32, m_bits: u64, seed: u64, digest: &[u8; 32]) -> Self {
        Self {
            h: lane(digest, 0) ^ seed,
            // Odd, so it is coprime with the power-of-two modulus and the
            // indices walk every residue instead of a short cycle.
            step: lane(digest, 1) | 1,
            mask: m_bits - 1,
            left: k,
        }
    }
}

impl Iterator for Probes {
    type Item = usize;

    #[inline]
    #[allow(clippy::cast_possible_truncation)]
    // idx < m_bits, which load() bounds to a usize on every target we build for.
    fn next(&mut self) -> Option<usize> {
        self.left = self.left.checked_sub(1)?;
        let idx = (self.h & self.mask) as usize;
        self.h = self.h.wrapping_add(self.step);
        Some(idx)
    }
}

/// Read 64-bit lane `i` of a digest, little-endian. Lanes 2 and 3 go unused;
/// 128 bits is ample for double hashing.
fn lane(d: &[u8; 32], i: usize) -> u64 {
    d.get(i * 8..i * 8 + 8)
        .and_then(|s| s.try_into().ok())
        .map_or(0, u64::from_le_bytes)
}

/// SHA-256 of a variable-length key.
pub(crate) fn digest_of(key: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(&Sha256::digest(key));
    out
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    fn build(keys: &[&str], fp: f64) -> Filter {
        let mut b = Builder::new(Kind::Purl, Tier::Good, keys.len() as u64, fp);
        for k in keys {
            b.insert_key(k.as_bytes());
        }
        b.build()
    }

    #[test]
    fn never_misses_a_key_it_holds() {
        let keys: Vec<String> = (0..5_000).map(|i| format!("pkg:npm/p{i}@1.0.0")).collect();
        let refs: Vec<&str> = keys.iter().map(String::as_str).collect();
        let f = build(&refs, 1e-9);
        for k in &refs {
            assert!(f.may_contain(&digest_of(k.as_bytes())), "lost {k}");
        }
    }

    #[test]
    fn false_positive_rate_meets_the_target() {
        let keys: Vec<String> = (0..20_000).map(|i| format!("in{i}")).collect();
        let refs: Vec<&str> = keys.iter().map(String::as_str).collect();
        let f = build(&refs, 1e-3);
        let fp = (0..50_000)
            .filter(|i| f.may_contain(&digest_of(format!("out{i}").as_bytes())))
            .count();
        // Budget is 50 at p=1e-3; a wide margin keeps this from flaking.
        assert!(fp < 150, "{fp} false positives in 50000");
    }

    #[test]
    fn k_is_sized_for_the_target_not_for_the_rounded_up_m() {
        // 1e-9 needs 30 probes. The textbook k for the rounded-up m would be
        // far larger and buy accuracy nobody asked for.
        let f = build(&["a"], 1e-9);
        assert_eq!(f.k, 30);
    }

    #[test]
    fn a_nonsense_target_falls_back_to_a_safe_default() {
        for fp in [0.0, 1.0, -1.0, f64::NAN, f64::INFINITY] {
            let f = build(&["a"], fp);
            assert_eq!(f.k, 30, "fp={fp} should fall back to 1e-9");
        }
    }

    #[test]
    fn debug_and_display_render() {
        let f = build(&["a"], 1e-9);
        let shown = format!("{f:?}");
        assert!(shown.contains("purl-good"), "{shown}");
        assert!(
            !shown.contains("bytes"),
            "the bit array must not be printed"
        );

        for e in [
            LoadError::Truncated,
            LoadError::BadMagic,
            LoadError::UnsupportedVersion(7),
            LoadError::Corrupt("kind"),
        ] {
            assert!(!e.to_string().is_empty(), "{e:?}");
        }
    }

    #[test]
    fn round_trips_through_bytes() {
        let f = build(&["pkg:npm/left-pad@1.3.0"], 1e-9);
        let back = Filter::load(f.as_bytes().to_vec()).unwrap();
        assert_eq!(back.kind(), Kind::Purl);
        assert_eq!(back.tier(), Tier::Good);
        assert_eq!(back.len(), 1);
        assert_eq!(back.stem(), "purl-good");
        assert!(back.may_contain(&digest_of(b"pkg:npm/left-pad@1.3.0")));
    }

    #[test]
    fn rejects_what_it_does_not_understand() {
        let good = build(&["x"], 1e-9).as_bytes().to_vec();

        assert_eq!(Filter::load(vec![0; 4]).err(), Some(LoadError::Truncated));

        let mut bad_magic = good.clone();
        bad_magic.get_mut(0..4).unwrap().copy_from_slice(b"XXXX");
        assert_eq!(Filter::load(bad_magic).err(), Some(LoadError::BadMagic));

        let mut bad_ver = good.clone();
        bad_ver
            .get_mut(4..6)
            .unwrap()
            .copy_from_slice(&99u16.to_le_bytes());
        assert_eq!(
            Filter::load(bad_ver).err(),
            Some(LoadError::UnsupportedVersion(99))
        );

        let mut retired_kind = good.clone();
        *retired_kind.get_mut(6).unwrap() = 2; // the withdrawn `url` kind
        assert_eq!(
            Filter::load(retired_kind).err(),
            Some(LoadError::Corrupt("kind"))
        );

        let mut retired_tier = good.clone();
        *retired_tier.get_mut(7).unwrap() = 3; // the withdrawn `unknown-clean`
        assert_eq!(
            Filter::load(retired_tier).err(),
            Some(LoadError::Corrupt("tier"))
        );

        let mut short = good.clone();
        short.truncate(HEADER_LEN + 1);
        assert_eq!(Filter::load(short).err(), Some(LoadError::Truncated));

        let mut zero_k = good.clone();
        zero_k
            .get_mut(8..12)
            .unwrap()
            .copy_from_slice(&0u32.to_le_bytes());
        assert_eq!(
            Filter::load(zero_k).err(),
            Some(LoadError::Corrupt("k out of range"))
        );

        let mut tiny_m = good;
        tiny_m
            .get_mut(12..20)
            .unwrap()
            .copy_from_slice(&8u64.to_le_bytes());
        assert!(matches!(
            Filter::load(tiny_m).err(),
            Some(LoadError::Corrupt(_))
        ));
    }

    #[test]
    fn a_v2_tier_cannot_masquerade_as_v1() {
        let mut b = Builder::new(Kind::Sha256, Tier::SightedHostile, 1, 1e-9);
        b.insert_digest(&[7u8; 32]);
        let mut bytes = b.build().as_bytes().to_vec();
        bytes
            .get_mut(4..6)
            .unwrap()
            .copy_from_slice(&1u16.to_le_bytes());
        assert_eq!(
            Filter::load(bytes).err(),
            Some(LoadError::Corrupt("tier newer than declared version"))
        );
    }

    /// `ALL` is hand-written but the slot arrays are sized by it. A variant
    /// added to the enum and not to `ALL` would get a filter nobody consults.
    #[test]
    fn all_lists_every_variant() {
        let tiers = (0u8..=255).filter_map(Tier::from_u8).count();
        assert_eq!(Tier::ALL.len(), tiers, "Tier::ALL is missing a variant");
        let kinds = (0u8..=255).filter_map(Kind::from_u8).count();
        assert_eq!(Kind::ALL.len(), kinds, "Kind::ALL is missing a variant");
    }

    #[test]
    fn wire_values_round_trip_and_are_distinct() {
        for t in Tier::ALL {
            assert_eq!(Tier::from_u8(t.to_u8()), Some(t), "{t:?}");
        }
        for k in Kind::ALL {
            assert_eq!(Kind::from_u8(k.to_u8()), Some(k), "{k:?}");
        }
        let indices: Vec<usize> = Tier::ALL.iter().map(|t| t.index()).collect();
        assert_eq!(indices, (0..Tier::ALL.len()).collect::<Vec<_>>());
        let indices: Vec<usize> = Kind::ALL.iter().map(|k| k.index()).collect();
        assert_eq!(indices, (0..Kind::ALL.len()).collect::<Vec<_>>());
    }

    #[test]
    fn stems_are_unique() {
        let mut seen = std::collections::HashSet::new();
        for kind in Kind::ALL {
            for tier in Tier::ALL {
                let stem = format!("{}-{}", kind.as_str(), tier.as_str());
                assert!(seen.insert(stem.clone()), "duplicate stem {stem}");
            }
        }
    }

    #[test]
    fn an_empty_filter_holds_nothing() {
        let f = Builder::new(Kind::Sha256, Tier::Good, 0, 1e-9).build();
        assert!(f.is_empty());
        assert_eq!(f.len(), 0);
        for tag in 0..64u8 {
            assert!(!f.may_contain(&[tag; 32]));
        }
    }

    /// The sizing rule has to hold across the range, not just at one point.
    #[test]
    fn sizing_meets_the_target_across_the_range() {
        for (n, p) in [(100u64, 1e-2), (1_000, 1e-3), (10_000, 1e-4), (5_000, 1e-6)] {
            let mut b = Builder::new(Kind::Sha256, Tier::Good, n, p);
            for i in 0..n {
                b.insert_digest(&digest_of(format!("in-{n}-{i}").as_bytes()));
            }
            let f = b.build();

            let trials = 200_000u32;
            let hits = (0..trials)
                .filter(|i| f.may_contain(&digest_of(format!("out-{n}-{i}").as_bytes())))
                .count();
            let observed = f64::from(u32::try_from(hits).unwrap_or(u32::MAX)) / f64::from(trials);
            // Generous headroom: this is a sanity bound, not a distribution test.
            assert!(observed <= p * 10.0, "n={n} p={p}: observed {observed}");
        }
    }

    /// A parser fed damaged bytes must return an error, never panic. Every byte
    /// of a valid filter is flipped in turn, plus every truncation.
    #[test]
    fn load_never_panics_on_damaged_input() {
        let good = build(&["a", "b", "c"], 1e-3).as_bytes().to_vec();

        for i in 0..good.len() {
            for mask in [0x01u8, 0x80, 0xff] {
                let mut bytes = good.clone();
                if let Some(b) = bytes.get_mut(i) {
                    *b ^= mask;
                }
                // Must not panic. Either outcome is acceptable.
                if let Ok(f) = Filter::load(bytes) {
                    let _ = f.may_contain(&[0u8; 32]);
                }
            }
        }
        for len in 0..good.len().min(256) {
            let mut bytes = good.clone();
            bytes.truncate(len);
            assert!(Filter::load(bytes).is_err(), "truncation to {len} loaded");
        }
        for extra in 1..8 {
            let mut bytes = good.clone();
            bytes.resize(good.len() + extra, 0);
            assert!(
                Filter::load(bytes).is_err(),
                "{extra} trailing bytes loaded"
            );
        }
    }

    /// A header may declare an enormous `m` without the bytes to back it.
    #[test]
    fn an_absurd_m_is_rejected_not_allocated() {
        let mut bytes = build(&["x"], 1e-9).as_bytes().to_vec();
        if let Some(slot) = bytes.get_mut(12..20) {
            slot.copy_from_slice(&(1u64 << 62).to_le_bytes());
        }
        assert_eq!(Filter::load(bytes).err(), Some(LoadError::Truncated));
    }

    #[test]
    fn stamping_down_drops_tiers_the_version_cannot_carry() {
        let v2_only = Builder::new(Kind::Sha256, Tier::SightedHostile, 1, 1e-9).build();
        assert!(v2_only.stamped_as(1).is_none());

        let both = Builder::new(Kind::Sha256, Tier::Bad, 1, 1e-9).build();
        let v1 = both.stamped_as(1).unwrap();
        assert_eq!(v1.version(), 1);
        // The stamp must reach the bytes, not just the struct.
        assert_eq!(Filter::load(v1.as_bytes().to_vec()).unwrap().version(), 1);
    }
}
