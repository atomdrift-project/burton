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
| Filter format | bytes 4–5 of every filter header | 2 |
| Manifest schema | `schema` in `bloom.toml` | 2 |

Bump the filter format on any change to the header, the tiers or kinds, or
how bits are derived. Bump the manifest schema on any change to what a
manifest says. An older reader then refuses the new bundle rather than
misreading it. Never reuse a number: version 1 of each was an unpublished
draft, and wire values retired below stay retired.

## Filter files

All integers are little-endian. A filter is a 36-byte header followed by a
bit array of exactly `m / 8` bytes, and nothing else.

```text
offset  size  field
     0     4  magic, "ADBL"
     4     2  format version, 2
     6     1  key kind: 1 purl, 3 sha256            (2 is retired)
     7     1  trust tier: 1 good, 2 bad,
              4 sighted-hostile, 5 sighted-suspicious (3 is retired)
     8     4  k, probes per key, 1 to 64
    12     8  m, bits in the array: a power of two, at least 64
    20     8  n, keys inserted (informational)
    28     8  reserved, 0
```

Bit `i` of the array is bit `i & 7` (least significant first) of byte
`i >> 3`.

### Probing

Every key is reduced to a 32-byte digest. A `sha256` key is its digest; a
`purl` key is the SHA-256 of its UTF-8 bytes, which must already be in the
bundle's key scheme (below). With `h1` the little-endian `u64` in digest bytes
0–7 and `h2` the one in bytes 8–15 with its low bit set, the key's probes are

```text
i_j = (h1 + j * h2) mod 2^64 mod m,    j = 0 .. k-1
```

A key is present when all `k` probed bits are set. `h2` is odd, so it is
coprime with `m` and the probes never cycle early.

### Sizing

Informative; a reader does not check it. For `n` keys at target
false-positive rate `p`, this crate builds

```text
m = next_power_of_two(max(64, ceil(-n ln p / (ln 2)^2)))
k = clamp(ceil(min(-log2 p, (m / n) ln 2)), 1, 64)
```

with `n` floored at 1 and `p` clamped to at most `1e-3` (`1e-9` if it is not
positive), so that every filter it builds passes the load checks below.

### Reading

A reader refuses a filter, and with it the whole bundle, when any of these
hold:

- the magic is not `ADBL`, or the version is not 2;
- the kind or tier is not a value listed above;
- `k` or `m` is out of range, or the reserved field is not zero;
- the file is not a regular file of exactly `36 + m / 8` bytes.

An installer also loads every bit (`Filter::load`) and refuses a filter
that no correct build could produce, since a forged one could bless any key:

- more than 75% of its bits are set, or
- `fill^k`, the chance an arbitrary key passes every probe, exceeds 0.05.

## Manifest

`bloom.toml` is TOML, at most 64 KiB:

```toml
schema = 2
built = "2026-11-06"
key_scheme = "purl-identity/v1"

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
| `filter.<stem>.file` | The filter's file name: a bare name in the bundle directory. |
| `filter.<stem>.sha256` | SHA-256 of that file, for an installer to verify downloads against. |
| `filter.<stem>.n` | Keys inserted. Informational. |

A stem is `<kind>-<tier>`: `purl-good`, `purl-bad`, `purl-sighted-hostile`,
`purl-sighted-suspicious`, and the same four for `sha256`.

A reader refuses the bundle when the manifest is larger than 64 KiB, when its
`schema` is not 2 (reported as such however the rest is shaped, since another
schema need not have these fields), when it has a field not listed above or
lacks one, when its
`key_scheme` is not the expected one, when any of the eight stems is missing
or any other is present, when a `file` is not a bare name, or when a filter's
header names a different kind or tier than its stem.

## Writing and installing

A writer replaces each file by writing a temporary file in the same
directory, syncing it, and renaming it over the old one. It renames every
filter before the manifest, and on Unix syncs the directory after the filters
and again after the manifest, so that after a crash the manifest never names
filters that were lost. One writer per directory at a time.

To replace a live bundle as a whole, write it to a fresh directory and rename
that into place. An installer that fetches a bundle should check every file
against its manifest digest, run `Filter::load` on every filter, and only then
rename the directory into place.

A reader that has a bundle open notices a replaced manifest and reopens the
bundle whole. If the replacement will not open, nothing is skipped until one
does.
