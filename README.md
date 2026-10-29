# burton

Burton answers one question: may this artifact be skipped? It consults a
bundle of Bloom filters, one per key kind (purl, sha256) and trust tier
(good, bad, sighted-hostile, sighted-suspicious).

```rust
let lookup = Lookup::open(dir, "purl-identity/v1")
    .unwrap_or_else(|_| Lookup::empty());
if !lookup.may_skip(&Artifact::sha256(&digest).and_purl(purl)) {
    analyze(path)?;
}
```

The rule is simple. Every key is checked against every filter, and the worst
answer wins. An artifact may be skipped only when all its keys are blessed,
nothing claims it, and the bad filter that would revoke the blessing is
present. When in doubt, burton says scan.

Failure is safe. A bundle that does not open completely grants nothing. A
filter that cannot be read blesses nothing and hides no claim. On Unix, an
open bundle notices a replaced manifest and reopens itself. A bundle records
its key scheme, and Lookup::open refuses one that does not match.

Bloom filters are public, and so is their false-positive set. An attacker can
grind a digest into the good filter. Supply every key you have: a blessing
needs all of them, and a package name is harder to forge. Rescan recently
written files regardless of what burton says.

Burton does not fetch, sign, or install bundles, nor does it canonicalize
package URLs. An installer should check each file against its manifest
digest, run Filter::load on it, and rename the directory into place.

To build a bundle, feed records to KeySets, run verify, then write_bundle.
The file format is described in src/filter.rs. `make test` enforces memory
budgets; `make bench-check` fails on a regression against a saved baseline.
Report security problems as described in SECURITY.md.

License: Apache-2.0.
