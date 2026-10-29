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
- An open `Lookup` checks the manifest's identity once per decision and
  reopens the bundle whole when it has been replaced. On Unix it holds its
  filters open, so a decision costs a `stat` and positional reads instead of
  opening every filter, and always reads a single build. Other platforms still
  reopen the filters per decision, so no handle blocks an updater.
- `write_bundle` writes each file to a temporary name, syncs, and renames it
  into place, with the manifest last.
- `verify` refuses a vouched digest found in any adverse tier, not only `bad`.
- A `target_fp` looser than `1e-3` is clamped to `1e-3` rather than replaced
  by `1e-9`.
- Purl keys are held as their 32-byte digests while building, so memory no
  longer grows with purl length.

### Tooling

- `make bench` / `bench-save` / `bench-check`: timings, exact allocation
  counts, and peak heap per operation, with baseline comparison.
- `tests/budget.rs` asserts allocation and memory budgets on every test run.

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
- `Display` for `Kind`, `Tier`, and `Decision`; `Default` for `Lookup`.
- `VerifyError::Ratio` carries the key counts (`was`, `now`) rather than a
  preformatted message; its `Display` text is unchanged.
- `hex` is no longer public. `Filter` is no longer `Clone`.
