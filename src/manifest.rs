//! The manifest: what a bundle holds, and the contract between producing a
//! bundle and opening one. Its format is specified in `FORMAT.md`.

use std::collections::BTreeMap;
use std::fmt;
use std::fs::{File, Metadata};
use std::io::{self, Read};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// The file naming a bundle's contents. Read by [`crate::Lookup::open`].
pub const MANIFEST_FILE: &str = "bloom.toml";

/// The one manifest layout version this build reads and writes.
///
/// Bump it on any change to what a manifest says: an older build then
/// refuses the new bundle instead of misreading it. Never reuse a number;
/// 1 was an unpublished draft.
pub const MANIFEST_SCHEMA: u32 = 2;

/// Largest manifest this build will read. A real one is about a kilobyte;
/// the cap keeps a hostile one from costing unbounded memory.
const MAX_MANIFEST_LEN: u64 = 64 * 1024;

/// One filter's entry in the manifest.
///
/// Unknown fields are refused, as unknown header fields are: a manifest this
/// build does not fully understand is not one it may act on.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Entry {
    /// File name within the bundle directory, e.g. `purl-good.adbl`. A bare
    /// name: [`crate::Lookup::open`] refuses anything with a path in it.
    pub file: String,
    /// Lowercase hex SHA-256 of the file, for an installer to verify a
    /// download against.
    pub sha256: String,
    /// Keys inserted. Informational.
    pub n: u64,
}

/// The contract between producing a bundle and opening one.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    /// Manifest layout version ([`MANIFEST_SCHEMA`]).
    pub schema: u32,
    /// Build date, `YYYY-MM-DD`.
    pub built: String,
    /// The key canonicalization that produced this bundle's keys.
    /// [`crate::Lookup::open`] refuses a bundle whose scheme is not the
    /// caller's.
    pub key_scheme: String,
    /// One entry per filter, keyed by stem (`purl-good`, …). A bundle has
    /// exactly one filter for every (kind, tier).
    pub filter: BTreeMap<String, Entry>,
}

/// Read the manifest in `dir`, typically a previous build to size a new one
/// against.
///
/// `Ok(None)` only when there is no manifest. One that exists but cannot be
/// read or parsed is an error: treating it as "no baseline" would silently
/// switch off [`crate::verify`]'s collapse and ratio checks.
///
/// # Errors
/// [`ManifestError`] for a manifest that exists but cannot be read, is too
/// large, does not parse, or is of another schema.
pub fn read_manifest(dir: impl AsRef<Path>) -> Result<Option<Manifest>, ManifestError> {
    match load_manifest(dir.as_ref()) {
        Err(ManifestError::Io { source, .. }) if source.kind() == io::ErrorKind::NotFound => {
            Ok(None)
        }
        other => other.map(|(manifest, _)| Some(manifest)),
    }
}

/// Read, parse, and schema-check the manifest in `dir`, with the metadata of
/// the very file read.
pub(crate) fn load_manifest(dir: &Path) -> Result<(Manifest, Metadata), ManifestError> {
    let path = dir.join(MANIFEST_FILE);
    let read = File::open(&path).and_then(|f| {
        let meta = f.metadata()?;
        let capacity = usize::try_from(meta.len().min(MAX_MANIFEST_LEN)).unwrap_or(0);
        let mut text = String::with_capacity(capacity);
        // One byte past the cap tells a manifest at the limit from one over
        // it, even when the file grows after the metadata was read.
        f.take(MAX_MANIFEST_LEN + 1).read_to_string(&mut text)?;
        Ok((text, meta))
    });
    let (text, meta) = match read {
        Ok(read) => read,
        Err(source) => return Err(ManifestError::Io { path, source }),
    };
    if text.len() as u64 > MAX_MANIFEST_LEN {
        return Err(ManifestError::TooLarge { path });
    }
    let manifest: Manifest = match toml::from_str(&text) {
        Ok(m) => m,
        Err(source) => {
            // A manifest of another schema need not parse as this one. Say
            // which schema it is, rather than which field this one lacks.
            #[derive(Deserialize)]
            struct Versioned {
                schema: u32,
            }
            if let Ok(Versioned { schema }) = toml::from_str(&text)
                && schema != MANIFEST_SCHEMA
            {
                return Err(ManifestError::Schema {
                    path,
                    found: schema,
                });
            }
            return Err(ManifestError::Parse {
                path,
                source: Box::new(source),
            });
        }
    };
    if manifest.schema != MANIFEST_SCHEMA {
        return Err(ManifestError::Schema {
            path,
            found: manifest.schema,
        });
    }
    Ok((manifest, meta))
}

/// Why a manifest could not be read.
#[derive(Debug)]
pub enum ManifestError {
    /// The manifest could not be read.
    Io {
        /// The manifest's path.
        path: PathBuf,
        /// What went wrong.
        source: io::Error,
    },
    /// The manifest is larger than any real one, and was not read.
    TooLarge {
        /// The manifest's path.
        path: PathBuf,
    },
    /// The manifest is not valid TOML, or not shaped like a manifest.
    Parse {
        /// The manifest's path.
        path: PathBuf,
        /// What went wrong.
        source: Box<toml::de::Error>,
    },
    /// The manifest's layout version is not [`MANIFEST_SCHEMA`].
    Schema {
        /// The manifest's path.
        path: PathBuf,
        /// The version it declares.
        found: u32,
    },
}

impl fmt::Display for ManifestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { path, source } => write!(f, "reading {}: {source}", path.display()),
            Self::TooLarge { path } => write!(
                f,
                "{}: manifest is larger than {MAX_MANIFEST_LEN} bytes",
                path.display()
            ),
            Self::Parse { path, source } => write!(f, "parsing {}: {source}", path.display()),
            Self::Schema { path, found } => write!(
                f,
                "{}: manifest schema {found}, this build reads {MANIFEST_SCHEMA}",
                path.display()
            ),
        }
    }
}

impl std::error::Error for ManifestError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            Self::Parse { source, .. } => Some(source),
            Self::TooLarge { .. } | Self::Schema { .. } => None,
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn sample() -> Manifest {
        Manifest {
            schema: MANIFEST_SCHEMA,
            built: "2026-08-30".to_owned(),
            key_scheme: "test/v1".to_owned(),
            filter: BTreeMap::from([(
                "sha256-good".to_owned(),
                Entry {
                    file: "sha256-good.adbl".to_owned(),
                    sha256: String::new(),
                    n: 1,
                },
            )]),
        }
    }

    #[test]
    fn read_manifest_tells_absent_from_broken() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(read_manifest(dir.path()).unwrap(), None);

        std::fs::write(dir.path().join(MANIFEST_FILE), "garbage {{").unwrap();
        assert!(matches!(
            read_manifest(dir.path()),
            Err(ManifestError::Parse { .. })
        ));

        let mut m = sample();
        m.schema = MANIFEST_SCHEMA + 1;
        std::fs::write(dir.path().join(MANIFEST_FILE), toml::to_string(&m).unwrap()).unwrap();
        assert!(matches!(
            read_manifest(dir.path()),
            Err(ManifestError::Schema { found, .. }) if found == MANIFEST_SCHEMA + 1
        ));
    }

    /// A manifest from another schema is reported as one, however different
    /// its shape — not as this schema's missing or unknown fields.
    #[test]
    fn another_schema_is_named_whatever_its_shape() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(MANIFEST_FILE);
        for text in [
            "schema = 1",
            "schema = 3\nfilters = []",
            "schema = 1\nbuilt = 7",
        ] {
            std::fs::write(&path, text).unwrap();
            assert!(
                matches!(read_manifest(dir.path()), Err(ManifestError::Schema { .. })),
                "{text}"
            );
        }
        // Our own schema, malformed, is a parse error that says what is wrong.
        std::fs::write(&path, "schema = 2").unwrap();
        let err = read_manifest(dir.path()).unwrap_err();
        assert!(err.to_string().contains("built"), "{err}");
    }

    #[test]
    fn an_oversized_manifest_is_refused_unread() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(MANIFEST_FILE);
        let limit = usize::try_from(MAX_MANIFEST_LEN).unwrap();

        // At the limit it is read (and fails only as TOML); one byte more is not.
        std::fs::write(&path, "#".repeat(limit)).unwrap();
        assert!(matches!(
            read_manifest(dir.path()),
            Err(ManifestError::Parse { .. })
        ));
        std::fs::write(&path, "#".repeat(limit + 1)).unwrap();
        assert!(matches!(
            read_manifest(dir.path()),
            Err(ManifestError::TooLarge { .. })
        ));
    }

    #[test]
    fn the_manifest_round_trips() {
        let m = sample();
        let back: Manifest = toml::from_str(&toml::to_string(&m).unwrap()).unwrap();
        assert_eq!(back, m);
    }

    /// A manifest that does not name its key scheme could be opened under
    /// any scheme at all, so it does not parse.
    #[test]
    fn a_manifest_without_a_key_scheme_is_refused() {
        let text = r#"
schema = 2
built = "2026-01-01"
[filter.sha256-good]
file = "sha256-good.adbl"
sha256 = "00"
n = 7
"#;
        let err = toml::from_str::<Manifest>(text).unwrap_err();
        assert!(err.to_string().contains("key_scheme"), "{err}");
    }

    /// A field this build does not know may change what the manifest means,
    /// at the top level or in an entry.
    #[test]
    fn a_manifest_with_unknown_fields_is_refused() {
        let text = toml::to_string(&sample()).unwrap();
        let top = text.replacen("schema", "mystery = 1\nschema", 1);
        assert!(toml::from_str::<Manifest>(&top).is_err(), "{top}");
        let entry = text.replacen("n = 1", "n = 1\nformat_version = 2", 1);
        assert!(toml::from_str::<Manifest>(&entry).is_err(), "{entry}");
    }
}
