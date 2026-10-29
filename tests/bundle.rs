//! End-to-end tests of the guarantees a caller relies on.
//!
//! Every one of these is a way a bundle can be wrong. In all of them the
//! required outcome is the same: nothing is skipped.

#![allow(clippy::unwrap_used, clippy::panic)]

use std::path::Path;

use burton::{
    Artifact, Decision, KeySets, LoadError, Lookup, MANIFEST_FILE, OpenError, Record, Tier,
    read_manifest, write_bundle,
};

const SCHEME: &str = "test/v1";

const BLESSED: &str = "pkg:npm/left-pad@1.3.0";
const CATALOGUED: &str = "pkg:npm/evil@6.6.6";

fn digest(tag: u8) -> [u8; 32] {
    let mut d = [0u8; 32];
    d[0] = tag;
    d
}

/// A bundle where digest 1 and `BLESSED` are good, digest 2 and `CATALOGUED`
/// are bad, and digest 3 is a lone sighting.
fn publish(dir: &Path) {
    let mut sets = KeySets::new();
    sets.insert(
        Tier::Good,
        Record {
            purl: Some(BLESSED.to_owned()),
            sha256: Some(digest(1)),
        },
    );
    sets.insert(
        Tier::Bad,
        Record {
            purl: Some(CATALOGUED.to_owned()),
            sha256: Some(digest(2)),
        },
    );
    sets.insert(Tier::SightedSuspicious, Record::sha256(digest(3)));
    write_bundle(dir, &sets.into_filters(1e-9), "2026-08-31", SCHEME).unwrap();
}

fn publish_one(dir: &Path, tier: Tier, record: Record) {
    let mut sets = KeySets::new();
    sets.insert(tier, record);
    write_bundle(dir, &sets.into_filters(1e-9), "2026-08-31", SCHEME).unwrap();
}

fn open(dir: &Path) -> Lookup {
    Lookup::open(dir, SCHEME).unwrap()
}

/// Rewrite the manifest in `dir` through `edit`.
fn edit_manifest(dir: &Path, edit: impl FnOnce(&mut burton::Manifest)) {
    let mut manifest = read_manifest(dir).unwrap().unwrap();
    edit(&mut manifest);
    std::fs::write(dir.join(MANIFEST_FILE), toml::to_string(&manifest).unwrap()).unwrap();
}

#[test]
fn a_complete_bundle_blesses_what_it_should() {
    let dir = tempfile::tempdir().unwrap();
    publish(dir.path());
    let lk = open(dir.path());

    assert!(lk.is_active());
    assert!(lk.may_skip(&Artifact::sha256(&digest(1))));
    assert!(lk.may_skip(&Artifact::purl(BLESSED)));
    // Both keys agree, which is the strongest form of the question.
    assert!(lk.may_skip(&Artifact::purl(BLESSED).and_sha256(&digest(1))));

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
    let mixed = Artifact::purl(BLESSED).and_sha256(&catalogued);
    assert_eq!(lk.decide(&mixed), Decision::Conflicted);
    assert!(!lk.may_skip(&mixed));
}

/// Every filter is read, so a claim in any tier is found even when another
/// tier also claims the artifact, and the worst one is reported.
#[test]
fn every_tier_is_consulted_and_the_worst_claim_wins() {
    let dir = tempfile::tempdir().unwrap();
    let mut sets = KeySets::new();
    for tier in [Tier::Bad, Tier::SightedHostile, Tier::SightedSuspicious] {
        sets.insert(tier, Record::sha256(digest(1)));
    }
    sets.insert(Tier::SightedHostile, Record::sha256(digest(2)));
    sets.insert(Tier::SightedSuspicious, Record::sha256(digest(2)));
    write_bundle(dir.path(), &sets.into_filters(1e-9), "2026-08-31", SCHEME).unwrap();
    let lk = open(dir.path());

    assert_eq!(lk.decide(&Artifact::sha256(&digest(1))), Decision::KnownBad);
    assert_eq!(
        lk.decide(&Artifact::sha256(&digest(2))),
        Decision::SightedHostile
    );
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
            matches!(&err, OpenError::Io { path, source }
                if path.ends_with(victim) && source.kind() == std::io::ErrorKind::NotFound),
            "{victim}: {err:?}"
        );
        assert!(err.to_string().contains(victim), "{err}");
        assert!(std::error::Error::source(&err).is_some());
    }
    // And the fallback a caller is told to use skips nothing.
    assert!(!Lookup::empty().may_skip(&Artifact::sha256(&digest(1))));
}

#[test]
fn a_corrupt_filter_fails_the_whole_open() {
    let dir = tempfile::tempdir().unwrap();
    publish(dir.path());
    let victim = dir.path().join("sha256-sighted-hostile.adbl");
    let mut bytes = std::fs::read(&victim).unwrap();
    bytes.truncate(bytes.len() - 1);
    std::fs::write(&victim, bytes).unwrap();

    let err = Lookup::open(dir.path(), SCHEME).unwrap_err();
    assert!(
        matches!(&err, OpenError::Invalid { file, source: LoadError::Truncated }
            if file == "sha256-sighted-hostile.adbl"),
        "{err:?}"
    );
    assert!(
        err.to_string().contains("sha256-sighted-hostile.adbl"),
        "{err}"
    );
}

#[test]
fn a_filter_under_the_wrong_name_fails_the_whole_open() {
    let dir = tempfile::tempdir().unwrap();
    publish(dir.path());
    // Swap the bad filter's contents into the good filter's file. Nothing about
    // the bytes is invalid; only the name is a lie.
    let bad = std::fs::read(dir.path().join("sha256-bad.adbl")).unwrap();
    std::fs::write(dir.path().join("sha256-good.adbl"), bad).unwrap();

    let err = Lookup::open(dir.path(), SCHEME).unwrap_err();
    assert!(
        matches!(&err, OpenError::Mislabelled { file, claims }
            if file == "sha256-good.adbl" && claims == "sha256-bad"),
        "{err:?}"
    );
}

/// A manifest is untrusted input: its file names must not reach outside the
/// bundle directory, however valid the file they point at.
#[test]
fn a_manifest_cannot_point_outside_its_directory() {
    let root = tempfile::tempdir().unwrap();
    let (bundle, other) = (root.path().join("bundle"), root.path().join("other"));
    std::fs::create_dir(&bundle).unwrap();
    std::fs::create_dir(&other).unwrap();
    publish(&bundle);
    publish(&other);

    let absolute = other.join("sha256-good.adbl").to_str().unwrap().to_owned();
    for file in ["../other/sha256-good.adbl", absolute.as_str(), "..", ""] {
        edit_manifest(&bundle, |m| {
            m.filter.get_mut("sha256-good").unwrap().file = file.to_owned();
        });
        let err = Lookup::open(&bundle, SCHEME).unwrap_err();
        assert!(
            matches!(&err, OpenError::UnsafePath { file: f } if f == file),
            "{file}: {err:?}"
        );
    }
}

/// A content-addressed file name is still a bare name, and opens.
#[test]
fn a_manifest_may_name_files_however_it_likes_within_its_directory() {
    let dir = tempfile::tempdir().unwrap();
    publish(dir.path());
    std::fs::rename(
        dir.path().join("sha256-good.adbl"),
        dir.path().join("sha256-good-0123abcd.adbl"),
    )
    .unwrap();
    edit_manifest(dir.path(), |m| {
        m.filter.get_mut("sha256-good").unwrap().file = "sha256-good-0123abcd.adbl".to_owned();
    });
    assert!(open(dir.path()).may_skip(&Artifact::sha256(&digest(1))));
}

#[test]
fn a_manifest_of_another_schema_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    publish(dir.path());
    edit_manifest(dir.path(), |m| m.schema = 99);
    let err = Lookup::open(dir.path(), SCHEME).unwrap_err();
    assert!(
        matches!(err, OpenError::Schema { found: 99, .. }),
        "{err:?}"
    );
}

#[test]
fn a_filter_whose_version_disagrees_with_the_manifest_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    publish(dir.path());
    edit_manifest(dir.path(), |m| {
        m.filter.get_mut("purl-bad").unwrap().format_version = 1;
    });
    let err = Lookup::open(dir.path(), SCHEME).unwrap_err();
    assert!(
        matches!(&err, OpenError::VersionMismatch { file, manifest: 1, header: 2 }
            if file == "purl-bad.adbl"),
        "{err:?}"
    );
}

#[test]
fn a_bundle_from_a_different_key_scheme_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    publish(dir.path());

    let err = Lookup::open(dir.path(), "some-other-scheme/v9").unwrap_err();
    assert!(err.to_string().contains("some-other-scheme/v9"), "{err}");
    let OpenError::KeyScheme { expected, found } = err else {
        panic!("expected a key scheme error, got {err:?}");
    };
    assert_eq!(found, SCHEME);
    assert_eq!(expected, "some-other-scheme/v9");
}

#[test]
fn a_bundle_that_names_no_scheme_is_accepted() {
    let dir = tempfile::tempdir().unwrap();
    publish(dir.path());
    edit_manifest(dir.path(), |m| m.key_scheme = None);

    // Nothing to disagree with, so it opens. It just cannot vouch for itself.
    let lk = Lookup::open(dir.path(), "anything-at-all").unwrap();
    assert_eq!(lk.key_scheme(), None);
    assert!(lk.may_skip(&Artifact::sha256(&digest(1))));
}

#[test]
fn a_missing_manifest_is_not_a_bundle() {
    let dir = tempfile::tempdir().unwrap();
    let err = Lookup::open(dir.path(), SCHEME).unwrap_err();
    assert!(
        matches!(&err, OpenError::Io { path, .. } if path.ends_with(MANIFEST_FILE)),
        "{err:?}"
    );
}

#[test]
fn an_unparseable_manifest_is_not_a_bundle() {
    let dir = tempfile::tempdir().unwrap();
    publish(dir.path());
    std::fs::write(dir.path().join(MANIFEST_FILE), "this is not toml {{{").unwrap();
    let err = Lookup::open(dir.path(), SCHEME).unwrap_err();
    assert!(matches!(err, OpenError::Parse { .. }), "{err:?}");
    assert!(std::error::Error::source(&err).is_some());
}

#[test]
fn without_the_revocation_channel_nothing_is_blessed() {
    let dir = tempfile::tempdir().unwrap();
    publish(dir.path());

    // A bundle that never carried a `bad` filter: the manifest does not name
    // one, so the open succeeds. A blessing with no way to revoke it is still
    // not honored.
    edit_manifest(dir.path(), |m| {
        m.filter.remove("sha256-bad");
    });
    std::fs::remove_file(dir.path().join("sha256-bad.adbl")).unwrap();

    let lk = open(dir.path());
    assert!(lk.is_active());
    assert_eq!(lk.decide(&Artifact::sha256(&digest(1))), Decision::Unknown);
    assert!(!lk.may_skip(&Artifact::sha256(&digest(1))));
    // The purl side still has its own bad channel, so it is unaffected.
    assert!(lk.may_skip(&Artifact::purl(BLESSED)));
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
    write_bundle(dir.path(), &sets.into_filters(1e-9), "2026-08-31", SCHEME).unwrap();

    let lk = open(dir.path());
    for purl in &purls {
        assert!(lk.may_skip(&Artifact::purl(purl)), "lost {purl}");
    }
}

#[test]
fn an_empty_bundle_opens_and_skips_nothing() {
    let dir = tempfile::tempdir().unwrap();
    write_bundle(
        dir.path(),
        &KeySets::new().into_filters(1e-9),
        "2026-08-31",
        SCHEME,
    )
    .unwrap();

    let lk = open(dir.path());
    assert!(lk.is_active(), "the filters exist, they are just empty");
    assert_eq!(lk.key_count(), 0);
    assert!(!lk.may_skip(&Artifact::sha256(&digest(1))));
    assert!(!lk.may_skip(&Artifact::purl("pkg:npm/anything@1")));
}

#[test]
fn a_v1_bundle_opens_and_folds_sightings_into_bad() {
    let dir = tempfile::tempdir().unwrap();
    let mut sets = KeySets::new();
    sets.insert(Tier::Good, Record::sha256(digest(1)));
    sets.insert(Tier::Bad, Record::sha256(digest(2)));
    sets.insert(Tier::SightedHostile, Record::sha256(digest(3)));
    sets.insert(Tier::SightedSuspicious, Record::sha256(digest(4)));
    let filters = sets.into_filters_for(1, 1e-9).unwrap();
    write_bundle(dir.path(), &filters, "2026-08-31", SCHEME).unwrap();

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

    // Two bundles built separately, one blessing and one cataloguing the same key.
    let blessed = tempfile::tempdir().unwrap();
    publish_one(blessed.path(), Tier::Good, Record::sha256(both));
    let catalogued = tempfile::tempdir().unwrap();
    publish_one(catalogued.path(), Tier::Bad, Record::sha256(both));

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

/// An open bundle holds no file, so an updater can swap the directory out from
/// under it on every platform. Once it is gone, nothing is blessed or convicted.
#[test]
fn a_bundle_moved_away_while_open_decides_nothing() {
    let root = tempfile::tempdir().unwrap();
    let dir = root.path().join("bundle");
    std::fs::create_dir(&dir).unwrap();
    publish(&dir);
    let lk = open(&dir);
    assert!(lk.may_skip(&Artifact::sha256(&digest(1))));

    std::fs::rename(&dir, root.path().join("old")).unwrap();
    for tag in [1, 2] {
        assert_eq!(
            lk.decide(&Artifact::sha256(&digest(tag))),
            Decision::Unavailable
        );
    }
}

/// A filter that cannot be read blesses nothing, but cannot erase what the
/// filters that can be read say — for its own key or for another.
#[test]
fn an_unreadable_filter_does_not_erase_a_claim() {
    let dir = tempfile::tempdir().unwrap();
    publish(dir.path());
    let lk = open(dir.path());
    std::fs::remove_file(dir.path().join("purl-good.adbl")).unwrap();
    std::fs::remove_file(dir.path().join("sha256-sighted-hostile.adbl")).unwrap();

    // The purl's own good filter is gone, and its bad filter still convicts.
    assert_eq!(lk.decide(&Artifact::purl(CATALOGUED)), Decision::KnownBad);
    // A digest blessed by a readable filter is not blessed with one missing.
    assert_eq!(
        lk.decide(&Artifact::sha256(&digest(1))),
        Decision::Unavailable
    );
    assert_eq!(
        lk.decide(&Artifact::sha256(&digest(9))),
        Decision::Unavailable
    );
    // One key's broken filters do not hide the other key's claim.
    assert_eq!(
        lk.decide(&Artifact::purl(BLESSED).and_sha256(&digest(2))),
        Decision::KnownBad
    );
    assert_eq!(
        lk.decide(&Artifact::purl(CATALOGUED).and_sha256(&digest(9))),
        Decision::KnownBad
    );
}

/// A bundle replaced while open is read as the replacement: a revocation it
/// carries takes effect without reopening.
#[test]
fn a_revocation_installed_while_open_is_honored() {
    let dir = tempfile::tempdir().unwrap();
    publish(dir.path());
    let lk = open(dir.path());
    assert!(lk.may_skip(&Artifact::sha256(&digest(1))));

    publish_one(dir.path(), Tier::Bad, Record::sha256(digest(1)));
    assert!(!lk.may_skip(&Artifact::sha256(&digest(1))));
    assert!(lk.decide(&Artifact::sha256(&digest(1))).is_adverse());
}

/// A file that changes tier after open is no longer the filter its slot names,
/// so it decides nothing rather than blessing from the wrong pool.
#[test]
fn a_filter_relabelled_while_open_decides_nothing() {
    let dir = tempfile::tempdir().unwrap();
    publish(dir.path());
    let lk = open(dir.path());

    let bad = std::fs::read(dir.path().join("sha256-bad.adbl")).unwrap();
    std::fs::write(dir.path().join("sha256-good.adbl"), bad).unwrap();
    assert_eq!(
        lk.decide(&Artifact::sha256(&digest(1))),
        Decision::Unavailable
    );
}
