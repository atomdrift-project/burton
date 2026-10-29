# Changelog

All notable changes to this crate are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the crate follows
[Semantic Versioning](https://semver.org/).

## [Unreleased]

First public release.

### Wire format

- Filter format v2, readable alongside v1. The reserved header field must be
  zero; a filter with anything else there is refused.
- Manifest schema 1. `Lookup::open` refuses any other schema, a filter `file`
  that is not a bare file name, and a filter whose header version disagrees
  with its manifest entry.

### Behaviour

- Every filter is consulted for every key and the worst claim wins. A filter
  that cannot be read blesses nothing but no longer erases another filter's
  claim; with no claim, the result is the new `Decision::Unavailable`.
- `write_bundle` writes each file to a temporary name, syncs, and renames it
  into place, with the manifest last.
- `verify` refuses a vouched digest found in any adverse tier, not only `bad`.
- A `target_fp` looser than `1e-3` is clamped to `1e-3` rather than replaced
  by `1e-9`.
- Purl keys are held as their 32-byte digests while building, so memory no
  longer grows with purl length.

### API

- One flat namespace: the `build` module is gone, and everything it held is
  exported from the crate root.
- `read_manifest` returns `Result<Option<Manifest>, OpenError>`: only an absent
  manifest is `None`.
- `KeySets::into_filters_for` returns `Result<_, UnsupportedVersion>`.
- `verify` takes `Ratio::{Enforce, Waive}` instead of a `bool`.
- `OpenError`, `WriteError`, and `VerifyError` use struct variants and expose
  their underlying errors through `source()`. `KeySchemeError` is folded into
  `OpenError::KeyScheme`.
- `Lookup::keys` is renamed `Lookup::key_count`.
- `Record::purl` and `Record::sha256` constructors.
- `hex` is no longer public. `Filter` is no longer `Clone`.
