# Bundle format

A bundle is a directory holding a manifest, `bloom.toml`, and the eight
filter files it names: one for every key kind (`purl`, `sha256`) and trust
tier (`good`, `bad`, `sighted-hostile`, `sighted-suspicious`). This document
is enough to produce or read one in another language. Where it and the code
disagree, the code is wrong.

## Versions

Two numbers version a bundle, and a reader accepts exactly one value of each:

| Number | Where | Current |
|---|---|---|
| Filter format | bytes 4–5 of every filter header | 3 |
| Manifest schema | `schema` in `bloom.toml` | 2 |

Bump the filter format on any change to the header, the tiers or kinds, how
bits are derived, or the bundle around the filters. Bump the manifest schema
on any change to what a manifest says. An older reader then refuses the new
bundle rather than misreading it, and a publisher can serve each filter
format from its own prefix (`bloom/v3/`) beside the ones older readers still
fetch. Never reuse a number: pre-release builds read and published filter
formats 1 and 2 and manifest schema 1, and wire values retired below stay
retired.

## Filter files

All integers are little-endian. A filter is a 36-byte header, zero padding to
offset 4096, and then the bit array: `m / 32768` blocks of 4096 bytes each.
Every block is page-aligned, and every key lives in exactly one block, so
looking a key up reads one page.

```text
offset  size  field
     0     4  magic, "ADBL"
     4     2  format version, 3
     6     1  key kind: 1 purl, 3 sha256            (2 is retired)
     7     1  trust tier: 1 good, 2 bad,
              4 sighted-hostile, 5 sighted-suspicious (3 is retired)
     8     4  k, probes per key, 1 to 64
    12     8  m, bits in the array: a positive multiple of 32768
    20     8  n, keys inserted (informational)
    28     8  reserved, 0
    36  4060  padding, 0
  4096        the blocks
```

Bit `i` of block `b` is bit `i & 7` (least significant first) of byte
`4096 + 4096 * b + (i >> 3)`.

### Probing

Every key is reduced to a 32-byte digest. A `sha256` key is its digest; a
`purl` key is the SHA-256 of its UTF-8 bytes, which must already be in the
bundle's key scheme (below). Read the digest as four little-endian `u64`
lanes, `l0` from bytes 0–7 through `l3` from bytes 24–31. With `blocks =
m / 32768`, all arithmetic modulo 2^64, and `rotl` a left rotation:

```text
block = (l3 * blocks) >> 64                       (the high half of the 128-bit product)
seed  = l0 ^ rotl(l1, 21) ^ rotl(l2, 42)

for w = 1, 2, ...:
    z = splitmix64(seed + w * 0x9e3779b97f4a7c15)
    probes, in order: (z >> 0) mod 32768, (z >> 16) mod 32768,
                      (z >> 32) mod 32768, (z >> 48) mod 32768
    ...until k probes

splitmix64(z):
    z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9
    z = (z ^ (z >> 27)) * 0x94d049bb133111eb
    return z ^ (z >> 31)
```

A key is present when all `k` probed bits of its block are set. The block
comes from a lane the probes never use, by multiply-shift, which spreads keys
evenly over any number of blocks. The probes are independent positions, not
double hashing: within a 32768-bit block, double hashing fixes a key's probe
set by about 29 bits, and the overlaps between keys put a floor near `1e-5`
under the false-positive rate whatever the filter's size.

### Sizing

Informative; a reader does not check it. For `n` keys at target
false-positive rate `p`, this crate builds

```text
k      = clamp(ceil(-log2 p), 1, 64)
blocks = max(1, ceil(-n ln p / (ln 2)^2 * (1 + k / 1000) / 32768))
```

with `n` floored at 1 and `p` clamped to at most `1e-3` (`1e-9` if it is not
positive), so that every filter it builds passes the load checks below. The
`k / 1000` margin pays for blocking: keys fall unevenly across blocks, and a
fuller block answers falsely more often. It is 3% at `k = 30` and suffices up
to `k = 64`.

### Reading

A reader refuses a filter, and with it the whole bundle, when any of these
hold:

- the magic is not `ADBL`, or the version is not 3;
- the kind or tier is not a value listed above;
- `k` or `m` is out of range, or the reserved field is not zero;
- the file is not a regular file of exactly `4096 + m / 8` bytes.

An installer also loads every bit (`Filter::load`) and refuses a filter
that no correct build could produce, since a forged one could bless any key:

- the padding is not all zero,
- more than 75% of the array's bits are set, or
- `fill^k`, the chance an arbitrary key passes every probe, exceeds 0.05.

## Manifest

`bloom.toml` is TOML, at most 64 KiB:

```toml
schema = 2
built = "2026-11-06"
key_scheme = "purl-identity/v1"

[provenance]                    # optional; never read by burton
release = "2026.09.1"

[filter.purl-bad]
file = "purl-bad.adbl"
sha256 = "<64 lowercase hex digits>"
n = 1204

# …one [filter.<stem>] table for each of the eight stems
```

| Field | Meaning |
|---|---|
| `schema` | Manifest schema, 2. |
| `built` | Build date, `YYYY-MM-DD`. Informational. |
| `key_scheme` | The canonicalization that produced the keys. A reader names the scheme it expects and refuses any other. |
| `provenance` | Optional table of anything a publisher wants to record about where the keys came from. Carried, never interpreted: nothing in it may affect a decision. |
| `filter.<stem>.file` | The filter's file name: a bare name in the bundle directory. |
| `filter.<stem>.sha256` | SHA-256 of that file, for an installer to verify downloads against. |
| `filter.<stem>.n` | Keys inserted. Informational. |

A stem is `<kind>-<tier>`: `purl-good`, `purl-bad`, `purl-sighted-hostile`,
`purl-sighted-suspicious`, and the same four for `sha256`.

A reader refuses the bundle when the manifest is larger than 64 KiB, when its
`schema` is not 2 (reported as such however the rest is shaped, since another
schema need not have these fields), when it has a field not listed above or
lacks one (anything goes inside `provenance`), when its
`key_scheme` is not the expected one, when any of the eight stems is missing
or any other is present, when a `file` is not a bare name, or when a filter's
header names a different kind or tier than its stem.

## Writing and installing

A writer replaces each file by writing a temporary file in the same
directory, syncing it, and renaming it over the old one. It renames every
filter before the manifest, and on Unix syncs the directory after the filters
and again after the manifest, so that after a crash the manifest never names
filters that were lost. One writer per directory at a time. Never rewrite a
published file in place: a reader holding it open reads whatever bytes are
there, mid-write included.

To replace a live bundle as a whole, write it to a fresh directory and rename
that into place. An installer that fetches a bundle should check every file
against its manifest digest, run `Filter::load` on every filter, and only then
rename the directory into place.

A reader that has a bundle open notices a replaced manifest and reopens the
bundle whole. If the replacement will not open, nothing is skipped until one
does.
