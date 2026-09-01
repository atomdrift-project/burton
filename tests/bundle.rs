//! End-to-end tests of the guarantees a caller relies on.
//!
//! Every one of these is a way a bundle can be wrong. In all of them the
//! required outcome is the same: nothing is skipped.

#![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]

use std::path::Path;

use burton::{Artifact, Decision, KeySets, Lookup, Record, Tier, build};

const SCHEME: &str = "test/v1";

fn digest(tag: u8) -> [u8; 32] {
    let mut d = [0u8; 32];
    d[0] = tag;
    d
}

/// A bundle where `blessed` is good and `catalogued` is bad, both by digest and
/// by coordinate.
fn publish(dir: &Path) {
    let mut sets = KeySets::new();
    sets.insert(
        Tier::Good,
        Record {
            purl: Some("pkg:npm/left-pad@1.3.0".to_owned()),
            sha256: Some(digest(1)),
        },
    );
    sets.insert(
        Tier::Bad,
        Record {
            purl: Some("pkg:npm/evil@6.6.6".to_owned()),
            sha256: Some(digest(2)),
        },
    );
    sets.insert(
        Tier::SightedSuspicious,
        Record {
            purl: None,
            sha256: Some(digest(3)),
        },
    );
    build::write_bundle(dir, &sets.into_filters(1e-9), "2026-08-31", SCHEME).unwrap();
}

fn open(dir: &Path) -> Lookup {
    Lookup::open(dir, SCHEME).unwrap()
}

#[test]
fn a_complete_bundle_blesses_what_it_should() {
    let dir = tempfile::tempdir().unwrap();
    publish(dir.path());
    let lk = open(dir.path());

    assert!(lk.is_active());
    assert!(lk.may_skip(&Artifact::sha256(&digest(1))));
    assert!(lk.may_skip(&Artifact::purl("pkg:npm/left-pad@1.3.0")));
    // Both keys agree, which is the strongest form of the question.
    assert!(lk.may_skip(&Artifact::purl("pkg:npm/left-pad@1.3.0").and_sha256(&digest(1))));

    assert_eq!(lk.decide(&Artifact::sha256(&digest(2))), Decision::KnownBad);
    assert_eq!(
        lk.decide(&Artifact::sha256(&digest(3))),
        Decision::SightedSuspicious
    );
    assert_eq!(lk.decide(&Artifact::sha256(&digest(9))), Decision::Unknown);
}

#[test]
fn a_blessed_digest_alone_does_not_carry_an_unknown_coordinate() {
    let dir = tempfile::tempdir().unwrap();
    publish(dir.path());
    let lk = open(dir.path());

    // This is the grinding defence. The digest is blessed, but the caller also
    // knows a coordinate, and that coordinate was never blessed. An attacker
    // who ground a digest into the good filter's false-positive set still has
    // to own a blessed package name.
    let blessed = digest(1);
    let ground = Artifact::sha256(&blessed).and_purl("pkg:npm/attacker-owned@1.0.0");
    assert!(!lk.may_skip(&ground));
    assert_eq!(lk.decide(&ground), Decision::Unknown);
}

#[test]
fn keys_that_disagree_are_a_conflict() {
    let dir = tempfile::tempdir().unwrap();
    publish(dir.path());
    let lk = open(dir.path());

    let catalogued = digest(2);
    let mixed = Artifact::purl("pkg:npm/left-pad@1.3.0").and_sha256(&catalogued);
    assert_eq!(lk.decide(&mixed), Decision::Conflicted);
    assert!(!lk.may_skip(&mixed));
}

#[test]
fn a_missing_filter_fails_the_whole_open() {
    for victim in [
        "sha256-bad.adbl",
        "sha256-sighted-suspicious.adbl",
        "purl-good.adbl",
    ] {
        let dir = tempfile::tempdir().unwrap();
        publish(dir.path());
        std::fs::remove_file(dir.path().join(victim)).unwrap();

        let err = Lookup::open(dir.path(), SCHEME).unwrap_err();
        assert!(
            matches!(err, burton::OpenError::Missing(ref f, _) if f == victim),
            "{victim}: {err:?}"
        );
        // And the fallback a caller is told to use skips nothing.
        assert!(!Lookup::empty().may_skip(&Artifact::sha256(&digest(1))));
    }
}

#[test]
fn a_corrupt_filter_fails_the_whole_open() {
    let dir = tempfile::tempdir().unwrap();
    publish(dir.path());
    let victim = dir.path().join("sha256-sighted-hostile.adbl");
    let mut bytes = std::fs::read(&victim).unwrap();
    bytes.truncate(bytes.len() - 1);
    std::fs::write(&victim, bytes).unwrap();

    assert!(matches!(
        Lookup::open(dir.path(), SCHEME),
        Err(burton::OpenError::Invalid(_, burton::LoadError::Truncated))
    ));
}

#[test]
fn a_filter_under_the_wrong_name_fails_the_whole_open() {
    let dir = tempfile::tempdir().unwrap();
    publish(dir.path());
    // Swap the bad filter's contents into the good filter's file. Nothing about
    // the bytes is invalid; only the name is a lie.
    let bad = std::fs::read(dir.path().join("sha256-bad.adbl")).unwrap();
    std::fs::write(dir.path().join("sha256-good.adbl"), bad).unwrap();

    assert!(matches!(
        Lookup::open(dir.path(), SCHEME),
        Err(burton::OpenError::Mislabelled { .. })
    ));
}

#[test]
fn a_bundle_from_a_different_key_scheme_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    publish(dir.path());

    let err = Lookup::open(dir.path(), "some-other-scheme/v9").unwrap_err();
    let burton::OpenError::KeyScheme(k) = err else {
        panic!("expected a key scheme error, got {err:?}");
    };
    assert_eq!(k.found, SCHEME);
    assert_eq!(k.expected, "some-other-scheme/v9");
}

#[test]
fn a_bundle_that_names_no_scheme_is_accepted() {
    let dir = tempfile::tempdir().unwrap();
    publish(dir.path());
    let path = dir.path().join("bloom.toml");
    let text = std::fs::read_to_string(&path).unwrap();
    let stripped: String = text
        .lines()
        .filter(|l| !l.starts_with("key_scheme"))
        .collect::<Vec<_>>()
        .join("\n");
    std::fs::write(&path, stripped).unwrap();

    // Nothing to disagree with, so it opens. It just cannot vouch for itself.
    let lk = Lookup::open(dir.path(), "anything-at-all").unwrap();
    assert_eq!(lk.key_scheme(), None);
    assert!(lk.may_skip(&Artifact::sha256(&digest(1))));
}

#[test]
fn a_missing_manifest_is_not_a_bundle() {
    let dir = tempfile::tempdir().unwrap();
    assert!(matches!(
        Lookup::open(dir.path(), SCHEME),
        Err(burton::OpenError::Manifest(..))
    ));
}

#[test]
fn without_the_revocation_channel_nothing_is_blessed() {
    let dir = tempfile::tempdir().unwrap();
    publish(dir.path());

    // A bundle that never carried a `bad` filter: the manifest does not name
    // one, so the open succeeds. A blessing with no way to revoke it is still
    // not honored.
    let path = dir.path().join("bloom.toml");
    let mut manifest = build::read_manifest(dir.path()).unwrap();
    manifest.filter.remove("sha256-bad");
    std::fs::remove_file(dir.path().join("sha256-bad.adbl")).unwrap();
    std::fs::write(&path, toml::to_string(&manifest).unwrap()).unwrap();

    let lk = Lookup::open(dir.path(), SCHEME).unwrap();
    assert!(lk.is_active());
    assert_eq!(lk.decide(&Artifact::sha256(&digest(1))), Decision::Unknown);
    assert!(!lk.may_skip(&Artifact::sha256(&digest(1))));
    // The purl side still has its own bad channel, so it is unaffected.
    assert!(lk.may_skip(&Artifact::purl("pkg:npm/left-pad@1.3.0")));
}

#[test]
fn a_bundle_never_loses_a_key_it_holds() {
    let dir = tempfile::tempdir().unwrap();
    let mut sets = KeySets::new();
    let purls: Vec<String> = (0..2_000).map(|i| format!("pkg:npm/p{i}@1.0.0")).collect();
    for (i, purl) in purls.iter().enumerate() {
        sets.insert(
            Tier::Good,
            Record {
                purl: Some(purl.clone()),
                sha256: Some(digest(u8::try_from(i % 251).unwrap())),
            },
        );
    }
    build::write_bundle(dir.path(), &sets.into_filters(1e-9), "2026-08-31", SCHEME).unwrap();

    let lk = open(dir.path());
    for purl in &purls {
        assert!(lk.may_skip(&Artifact::purl(purl)), "lost {purl}");
    }
}

#[test]
fn an_unparseable_manifest_is_not_a_bundle() {
    let dir = tempfile::tempdir().unwrap();
    publish(dir.path());
    std::fs::write(dir.path().join("bloom.toml"), "this is not toml {{{").unwrap();
    assert!(matches!(
        Lookup::open(dir.path(), SCHEME),
        Err(burton::OpenError::Schema(..))
    ));
}

#[test]
fn an_empty_bundle_opens_and_skips_nothing() {
    let dir = tempfile::tempdir().unwrap();
    build::write_bundle(
        dir.path(),
        &KeySets::new().into_filters(1e-9),
        "2026-08-31",
        SCHEME,
    )
    .unwrap();

    let lk = open(dir.path());
    assert!(lk.is_active(), "the filters exist, they are just empty");
    assert_eq!(lk.keys(), 0);
    assert!(!lk.may_skip(&Artifact::sha256(&digest(1))));
    assert!(!lk.may_skip(&Artifact::purl("pkg:npm/anything@1")));
}

#[test]
fn a_v1_bundle_opens_and_folds_sightings_into_bad() {
    let dir = tempfile::tempdir().unwrap();
    let mut sets = KeySets::new();
    sets.insert(
        Tier::Good,
        Record {
            purl: None,
            sha256: Some(digest(1)),
        },
    );
    sets.insert(
        Tier::Bad,
        Record {
            purl: None,
            sha256: Some(digest(2)),
        },
    );
    sets.insert(
        Tier::SightedHostile,
        Record {
            purl: None,
            sha256: Some(digest(3)),
        },
    );
    sets.insert(
        Tier::SightedSuspicious,
        Record {
            purl: None,
            sha256: Some(digest(4)),
        },
    );
    build::write_bundle(
        dir.path(),
        &sets.into_filters_for(1, 1e-9),
        "2026-08-31",
        SCHEME,
    )
    .unwrap();

    let lk = open(dir.path());
    assert!(lk.may_skip(&Artifact::sha256(&digest(1))));
    assert_eq!(lk.decide(&Artifact::sha256(&digest(2))), Decision::KnownBad);
    // A v1 client cannot express "sighted", so a corroborated one reads as bad.
    assert_eq!(lk.decide(&Artifact::sha256(&digest(3))), Decision::KnownBad);
    // ...and a lone claim is dropped rather than overstated.
    assert_eq!(lk.decide(&Artifact::sha256(&digest(4))), Decision::Unknown);
}

#[test]
fn many_threads_agree_with_one() {
    let dir = tempfile::tempdir().unwrap();
    publish(dir.path());
    let lk = open(dir.path());

    let blessed = digest(1);
    let catalogued = digest(2);
    std::thread::scope(|scope| {
        for _ in 0..8 {
            scope.spawn(|| {
                for _ in 0..2_000 {
                    assert!(lk.may_skip(&Artifact::sha256(&blessed)));
                    assert_eq!(
                        lk.decide(&Artifact::sha256(&catalogued)),
                        Decision::KnownBad
                    );
                    assert!(!lk.may_skip(&Artifact::sha256(&digest(200))));
                }
            });
        }
    });
}

/// A bundle that contradicts itself: the same digest blessed *and* catalogued.
///
/// Build-time subtraction makes this impossible within one build, so reaching
/// it means the files on disk came from different ones. The rule still has to
/// hold, and it must never resolve to a skip.
#[test]
fn a_self_contradictory_bundle_conflicts_rather_than_blesses() {
    let both = digest(1);

    // Two bundles built separately, each blessing or catalguing the same key.
    let blessed = tempfile::tempdir().unwrap();
    let mut sets = KeySets::new();
    sets.insert(
        Tier::Good,
        Record {
            purl: None,
            sha256: Some(both),
        },
    );
    build::write_bundle(
        blessed.path(),
        &sets.into_filters(1e-9),
        "2026-08-31",
        SCHEME,
    )
    .unwrap();

    let catalogued = tempfile::tempdir().unwrap();
    let mut sets = KeySets::new();
    sets.insert(
        Tier::Bad,
        Record {
            purl: None,
            sha256: Some(both),
        },
    );
    build::write_bundle(
        catalogued.path(),
        &sets.into_filters(1e-9),
        "2026-08-31",
        SCHEME,
    )
    .unwrap();

    // Splice the second bundle's bad filter over the first's, as filters built
    // at different times and shipped together would be.
    std::fs::copy(
        catalogued.path().join("sha256-bad.adbl"),
        blessed.path().join("sha256-bad.adbl"),
    )
    .unwrap();

    let lk = open(blessed.path());
    assert_eq!(lk.decide(&Artifact::sha256(&both)), Decision::Conflicted);
    assert!(!lk.may_skip(&Artifact::sha256(&both)));
}

/// Error text is what an operator sees when a bundle will not open.
#[test]
fn every_open_error_renders() {
    let dir = tempfile::tempdir().unwrap();
    assert!(
        !Lookup::open(dir.path(), SCHEME)
            .unwrap_err()
            .to_string()
            .is_empty()
    );

    publish(dir.path());
    assert!(
        Lookup::open(dir.path(), "other/v1")
            .unwrap_err()
            .to_string()
            .contains("other/v1")
    );

    std::fs::remove_file(dir.path().join("purl-bad.adbl")).unwrap();
    let err = Lookup::open(dir.path(), SCHEME).unwrap_err();
    assert!(err.to_string().contains("purl-bad.adbl"));
    assert!(std::error::Error::source(&err).is_some());

    let dir = tempfile::tempdir().unwrap();
    publish(dir.path());
    let victim = dir.path().join("sha256-good.adbl");
    let mut bytes = std::fs::read(&victim).unwrap();
    bytes.truncate(40);
    std::fs::write(&victim, bytes).unwrap();
    let err = Lookup::open(dir.path(), SCHEME).unwrap_err();
    assert!(err.to_string().contains("sha256-good.adbl"), "{err}");
    assert!(std::error::Error::source(&err).is_some());

    let dir = tempfile::tempdir().unwrap();
    publish(dir.path());
    let bad = std::fs::read(dir.path().join("sha256-bad.adbl")).unwrap();
    std::fs::write(dir.path().join("sha256-good.adbl"), bad).unwrap();
    let err = Lookup::open(dir.path(), SCHEME).unwrap_err();
    assert!(err.to_string().contains("sha256-bad"), "{err}");

    let dir = tempfile::tempdir().unwrap();
    publish(dir.path());
    std::fs::write(dir.path().join("bloom.toml"), "{{{").unwrap();
    assert!(
        !Lookup::open(dir.path(), SCHEME)
            .unwrap_err()
            .to_string()
            .is_empty()
    );
}
