# Security policy

burton decides what a scanner may skip, so a bug that lets an artifact be
skipped when it should not be is a security bug. That includes:

- any input — bundle files, manifest, or keys — that yields `Decision::Skip`
  for an artifact some loaded filter claims;
- a manifest or filter that makes `Lookup::open` read outside its directory;
- a panic, unbounded allocation, or unbounded work on malformed input.

Grinding a digest into a public good filter's false-positive set is a known,
documented limit (see the README's threat model), not a vulnerability.

## Reporting

Please report privately through GitHub's
[private vulnerability reporting](https://github.com/atomdrift-project/burton/security/advisories/new)
rather than a public issue. Include a bundle or test that reproduces the
problem if you can. Expect an acknowledgement within a few days.

Fixes land on the latest release only.
