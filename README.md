# burton

Bloom-filter allow/deny bundles, for skipping work you have already done.

```rust
use burton::{Artifact, Lookup};

// Once at startup: open the installed bundle, or run without one.
let lookup = Lookup::open(bundle_dir, "purl-identity/v1")
    .unwrap_or_else(|_| Lookup::empty());

// Per artifact, before the expensive work, with every key you have.
if !lookup.may_skip(&Artifact::sha256(&digest).and_purl(purl)) {
    analyze(path)?;
}
```

Opening reads only the manifest and each filter's header; decisions read the
few bytes their probes touch. That keeps it cheap for short-lived processes
that open a bundle, decide a handful of artifacts, and exit.

## The rule

A bundle holds one filter per key kind (`purl`, `sha256`) and trust tier:

| Tier                 | Meaning                                                    |
|----------------------|------------------------------------------------------------|
| `good`               | Blessed. A hit here, and nowhere else, permits a skip.     |
| `bad`                | The producer's own analysis found it hostile.              |
| `sighted-hostile`    | Corroborated outside claims. Nothing of the producer's ran.|
| `sighted-suspicious` | A lone, unadjudicated outside claim.                       |

**Worst pool wins.** Every key is checked against every filter, and the worst
claim found is the answer. An artifact is skippable only when it is blessed and
nothing claims it: a bless means "do not look at this at all", so the bar is
"nothing anywhere has anything to say".

There is no way to ask a single filter whether a key is in it. That question,
answered alone, is how an adverse tier gets skipped.

## Bloom filters answer only one way

A miss is authoritative. A hit is probabilistic.

A false positive on an adverse filter costs a needless scan. On the *good*
filter it costs an artifact nobody ever looks at — which is why the loosest
target a build accepts is `1e-3`, and why a bundle that will not open in full
grants no skips at all.

## Failure is always safe

Every error path ends in "no skip".

`Lookup::open` treats the manifest as the authority: every filter it names must
be a bare file name in the bundle directory, have a valid header of the version
the manifest states, and identify itself as the filter it is named as. Any
failure fails the whole open, because a partly readable bundle is exactly the
case where a stale bless cannot be vetoed. Callers fall back to
`Lookup::empty()`.

A filter that cannot be read when a decision consults it blesses nothing, and
erases no other filter's claim: the decision is `Unavailable` unless something
readable claims the artifact.

A bless is also withheld unless the matching `bad` filter is loaded. That filter
is the revocation channel.

## Key canonicalization is yours

This crate does not normalize package URLs; that belongs to whoever owns the
corpus. It records the scheme name in the bundle and refuses to open one whose
scheme is not what the caller asked for — otherwise a producer and consumer that
disagree match nothing at all, silently and forever.

## Threat model

Bundles are public, so the good filter's false-positive set is public. An
attacker who controls an artifact's bytes can grind its digest into that set and
never be scanned. Filter size raises the cost; it cannot remove it.

Two defences, neither automatic:

1. **Supply every key you have.** Blessings are conjunctive: `decide` skips only
   if *all* the keys given are blessed. Grinding a digest is cheap. Also owning
   a blessed package coordinate is not.
2. **Re-examine recently written files** whatever the verdict says. A bless
   describes bytes, not the circumstances in which they appeared.

See [SECURITY.md](SECURITY.md) to report a vulnerability.

## Not included

- **Fetching and installing bundles.** A library that downloads a list of
  files it will then decline to scan is a library that ships an attack surface.
  An installer should check each download against its manifest digest, run
  `Filter::load` on it (which refuses an implausibly full or permissive bit
  array), and swap the bundle directory into place whole. `Lookup::open` does
  none of this, so that opening stays cheap.
- **Signing.** A bundle is only as trustworthy as the channel it arrived on. The
  manifest's digests detect a damaged download, not a hostile one.
- **Deleting keys.** Bloom filters cannot. Revocation is a full rebuild.

## Building a bundle

`KeySets` accumulates deduplicated keys as records stream in, held as 32-byte
digests, so peak memory is 32 bytes per distinct key and does not grow with row
count. `good` is reduced by every other tier before the filters are built.

Call `verify` on the built filters before `write_bundle`: canary digests that
must never be blessed, caller-vouched digests that must never be in an adverse
tier, and key counts bounded against the previous build's manifest. A bundle
published unattended cannot be recalled, so these are fatal unless the caller
waives the count bounds explicitly.

`write_bundle` replaces each file atomically, manifest last. To replace a live
bundle as a whole, write into a fresh directory and rename it into place.

## On-disk format

A 36-byte header — `"ADBL"`, format version, kind, tier, `k`, `m`, `n`, and a
reserved field that must be zero — followed by exactly `m / 8` bytes of bits.
`m` is a power of two, so indexing is a mask. Keys are reduced to a SHA-256
digest and `k` indices derived by double hashing; a `sha256` key is already
uniform and is used directly. A producer in another language agrees bit for bit
if it canonicalizes keys the same way.

`bloom.toml` names every file with its digest, format version, key count, and
the key scheme that produced it.

## License

Apache-2.0
