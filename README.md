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

## The rule

A bundle holds one filter per key kind (`purl`, `sha256`) and trust tier:

| Tier                 | Meaning                                                    |
|----------------------|------------------------------------------------------------|
| `good`               | Blessed. A hit here, and nowhere else, permits a skip.      |
| `bad`                | The producer's own analysis found it hostile.               |
| `sighted-hostile`    | Corroborated outside claims. Nothing of the producer's ran. |
| `sighted-suspicious` | A lone, unadjudicated outside claim.                        |

**Worst pool wins.** An artifact is skippable only when it is blessed and
nothing claims it. The weakest adverse tier denies a skip: a bless means "do not
look at this at all", so the bar is "nothing anywhere has anything to say".

There is no way to ask a single filter whether a key is in it. That question,
answered alone, is how an adverse tier gets skipped.

## Bloom filters answer only one way

A miss is authoritative. A hit is probabilistic.

A false positive on an adverse filter costs a needless scan. On the *good*
filter it costs an artifact nobody ever looks at — which is why good filters are
sized well below their nominal rate, and why a bundle that will not open in full
grants no skips at all.

## Failure is always safe

Every error path ends in "no skip".

`Lookup::open` treats the manifest as the authority: every filter it names must
be present, valid, and identify itself as the file it is named as. Any failure
fails the whole open, because a partly readable bundle is exactly the case where
a stale bless cannot be vetoed. Callers fall back to `Lookup::empty()`.

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

## Not included

- **Fetching bundles.** A library that downloads a list of files it will then
  decline to scan is a library that ships an attack surface.
- **Signing.** A bundle is only as trustworthy as the channel it arrived on. The
  manifest's digests detect a damaged download, not a hostile one.
- **Deleting keys.** Bloom filters cannot. Revocation is a full rebuild.

## Building a bundle

`KeySets` accumulates deduplicated keys as records stream in, so peak memory is
the distinct keys and does not grow with row count. `good` is reduced by every
other tier before the filters are built.

`build::verify` runs before anything is written: canary digests that must never
be blessed, caller-vouched digests that must never be catalogued bad, and key
counts bounded against the previous build. A bundle published unattended cannot
be recalled, so these are fatal by default.

## On-disk format

A 36-byte header — `"ADBL"`, format version, kind, tier, `k`, `m`, `n`, a
reserved seed — followed by exactly `m / 8` bytes of bits. `m` is a power of two,
so indexing is a mask. Keys are reduced to a SHA-256 digest and `k` indices
derived by double hashing; a `sha256` key is already uniform and is used
directly. A producer in another language agrees bit for bit if it canonicalizes
keys the same way.

`bloom.toml` names every file with its digest, format version, key count, and
the key scheme that produced it.

## License

Apache-2.0
