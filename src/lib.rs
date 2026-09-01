//! Bloom-filter allow/deny bundles, for skipping work you have already done.
//!
//! A bundle holds one filter per key kind (`purl`, `sha256`) and trust tier
//! (`good`, `bad`, `sighted-hostile`, `sighted-suspicious`). [`Lookup::decide`]
//! consults every tier and returns a [`Decision`]. Only [`Decision::may_skip`]
//! permits skipping work.
//!
//! ```
//! use burton::{Artifact, Lookup};
//!
//! # let bundle_dir = std::path::Path::new("/var/lib/burton");
//! # let digest = [0u8; 32];
//! # let purl = "pkg:npm/left-pad@1.3.0";
//! // Once at startup: open the installed bundle, or run without one.
//! let lookup = Lookup::open(bundle_dir, "purl-identity/v1")
//!     .unwrap_or_else(|_| Lookup::empty());
//!
//! // Per artifact, before the expensive work, with every key you have.
//! if !lookup.may_skip(&Artifact::sha256(&digest).and_purl(purl)) {
//!     // analyze it
//! }
//! ```
//!
//! # Worst pool wins
//!
//! An artifact is skippable only when it is blessed and nothing claims it. The
//! weakest adverse tier is enough to deny a skip: a bless means "do not look at
//! this at all", so the bar is "nothing anywhere has anything to say".
//!
//! # Failure is always safe
//!
//! A bloom miss is authoritative; a hit is probabilistic. A false positive on an
//! adverse filter costs a needless scan. On the good filter it costs an artifact
//! nobody ever looks at. So:
//!
//! - [`Lookup::open`] treats the manifest as authority and fails whole. A bundle
//!   that will not open completely grants nothing.
//! - A bless is withheld unless the matching `bad` filter is loaded. That filter
//!   is the revocation channel.
//! - Single-filter membership is not public. Asking "is this blessed?" without
//!   consulting the adverse tiers is the mistake this crate exists to prevent.
//!
//! # Grinding
//!
//! Bundles are public, so a good filter's false-positive set is public too. An
//! attacker who controls an artifact's bytes can grind its digest into that set
//! and never be scanned. Filter size raises the cost but cannot remove it.
//! Supply every key you have: blessings are conjunctive, and owning a blessed
//! package coordinate is not cheap.
//!
//! # Not included
//!
//! Fetching, authenticating, and installing bundles. Key canonicalization, which
//! belongs to whoever owns the corpus — a bundle records the scheme that
//! produced its keys and [`Lookup::open`] refuses one it does not expect.

#![forbid(unsafe_code)]

pub mod build;
mod filter;
mod lookup;

pub use build::{KeySets, Manifest, Record};
pub use filter::{FORMAT_VERSION, Filter, Kind, LoadError, SUPPORTED_VERSIONS, Tier};
pub use lookup::{Artifact, Decision, KeySchemeError, Lookup, OpenError};

/// Key scheme for bundles whose keys are raw byte strings.
///
/// Name your own scheme — a stable string such as `"purl-identity/v1"` — so a
/// producer and consumer that disagree fail at [`Lookup::open`] rather than
/// quietly matching nothing. Use this only when keys really are raw, as
/// digest-only bundles are.
pub const KEY_SCHEME_OPAQUE: &str = "opaque";

/// Parse a 64-character hex SHA-256 into its 32 bytes.
///
/// `None` for any wrong length or non-hex character, so a malformed row is
/// skipped rather than silently hashed as text.
#[must_use]
pub fn parse_sha256_hex(s: &str) -> Option<[u8; 32]> {
    let s = s.trim().as_bytes();
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, slot) in out.iter_mut().enumerate() {
        let (hi, lo) = (s.get(i * 2)?, s.get(i * 2 + 1)?);
        *slot = (hex_nibble(*hi)? << 4) | hex_nibble(*lo)?;
    }
    Some(out)
}

const fn hex_nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// Lowercase hex of a SHA-256 digest.
#[must_use]
pub fn hex(digest: &[u8; 32]) -> String {
    const fn nibble(n: u8) -> char {
        (if n < 10 { b'0' + n } else { b'a' + n - 10 }) as char
    }
    let mut out = String::with_capacity(64);
    for b in digest {
        out.push(nibble(b >> 4));
        out.push(nibble(b & 0x0f));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_round_trips() {
        let d = [0xabu8; 32];
        assert_eq!(parse_sha256_hex(&hex(&d)), Some(d));
    }

    #[test]
    fn bad_hex_is_rejected_not_hashed() {
        assert_eq!(parse_sha256_hex("nope"), None);
        assert_eq!(parse_sha256_hex(&"z".repeat(64)), None);
        assert_eq!(parse_sha256_hex(&"a".repeat(63)), None);
    }
}
