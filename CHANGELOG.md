# Changelog

All notable changes to this crate are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the crate follows
[Semantic Versioning](https://semver.org/).

## [Unreleased]

Initial release, as 0.1.0.

### Formats

- Filter format 3 and manifest schema 2, specified in `FORMAT.md`. A reader
  accepts exactly these versions, and a bundle carries exactly one filter for
  each key kind (`purl`, `sha256`) and trust tier (`good`, `bad`,
  `sighted-hostile`, `sighted-suspicious`). Pre-release builds published
  formats 1 and 2 and schema 1; this release reads none of them.
- An optional manifest `[provenance]` table carries a publisher's own
  metadata, which burton never interprets.

### Consuming

- `Lookup::open` opens a bundle whole or not at all, and refuses one built
  under another key scheme.
- `Lookup::decide` consults every filter for every key: the worst claim wins,
  and a skip needs every key supplied to be blessed. `Decision::may_skip` is
  the one question a fast path should ask.
- Filters stay on disk, and a decision reads one page of each filter it
  consults: every key's probes fall in one page-aligned 4 KiB block. On Unix
  it reads through filters held open, without allocating.
- Filters are sized to whole blocks, not powers of two, so they are as large
  as their keys need and no larger.
- An open `Lookup` follows its bundle as it is replaced, and `Lookup::refresh`
  reports why a replacement will not open.

### Producing

- `KeySets` accumulates records as 32-byte digests and builds the eight
  filters, removing from `good` anything any other tier claims.
- `verify` refuses a build that blesses a canary, convicts a vouched digest,
  drops or empties a filter, or moves a filter's key count outside its ratio
  bounds (waivable with `Ratio::Waive`).
- `write_bundle` writes each file atomically and durably, the manifest last.
- `Filter::load` runs the full check, bit fill included, that an installer
  should apply to every downloaded filter.

### Tooling

- `make bench`, `bench-save`, and `bench-check` report timings, exact
  allocation counts, and peak heap per operation, against a saved baseline.
- `tests/budget.rs` asserts allocation and memory budgets on every test run.
