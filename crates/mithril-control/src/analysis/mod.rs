use std::fs::{self, DirBuilder, File, OpenOptions};
use std::os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};

use duckdb::{params, Config, Connection};
use snafu::ResultExt as _;
use uuid::Uuid;

use crate::error::{AnalysisDatabaseSnafu, AnalysisStateSnafu, IoSnafu};
use crate::Result;

pub const ANALYSIS_DUCKDB_BINDING_VERSION: &str = "1.4.4";
pub const ANALYSIS_SQLPARSER_VERSION: &str = "0.63.0";
const ANALYSIS_SCHEMA_VERSION: i64 = 1;

pub struct AnalysisStore {
    root: PathBuf,
    _lease: File,
    writer: Mutex<Connection>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AnalysisStoreMetaV1 {
    pub store_uuid: Uuid,
    pub schema_version: u32,
    pub recovery_epoch: u64,
    pub commit_revision: u64,
}

impl AnalysisStore {
    pub fn open(root: impl AsRef<Path>) -> Result<Self> {
        let root = root.as_ref().to_path_buf();
        if !root.is_absolute() {
            return AnalysisStateSnafu {
                path: root,
                reason: "the analysis path is not absolute".to_owned(),
            }
            .fail();
        }
        match DirBuilder::new().mode(0o700).create(&root) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(source) => return Err(source).context(IoSnafu { path: &root }),
        }
        let metadata = fs::symlink_metadata(&root).context(IoSnafu { path: &root })?;
        if !metadata.is_dir() || metadata.permissions().mode() & 0o077 != 0 {
            return AnalysisStateSnafu {
                path: root,
                reason: "the analysis directory is not private".to_owned(),
            }
            .fail();
        }
        let filesystem = rustix::fs::statfs(&root)
            .map_err(std::io::Error::from)
            .context(IoSnafu { path: &root })?;
        if !matches!(filesystem.f_type, 0xef53 | 0x0102_1994) {
            return AnalysisStateSnafu {
                path: root,
                reason: "the analysis filesystem is not qualified".to_owned(),
            }
            .fail();
        }

        let lease_path = root.join("analysis.lock");
        let lease = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .mode(0o600)
            .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
            .open(&lease_path)
            .context(IoSnafu { path: &lease_path })?;
        let lease_metadata = lease.metadata().context(IoSnafu { path: &lease_path })?;
        if !lease_metadata.is_file() || lease_metadata.permissions().mode() & 0o077 != 0 {
            return AnalysisStateSnafu {
                path: lease_path,
                reason: "the analysis lease file is not private".to_owned(),
            }
            .fail();
        }
        lease.try_lock().map_err(|error| {
            AnalysisStateSnafu {
                path: root.clone(),
                reason: format!("the analysis writer is already owned: {error}"),
            }
            .build()
        })?;

        let path = root.join("analysis.duckdb");
        let existing = match fs::symlink_metadata(&path) {
            Ok(metadata) => {
                if !metadata.is_file() || metadata.permissions().mode() & 0o077 != 0 {
                    return AnalysisStateSnafu {
                        path,
                        reason: "the analysis database file is not private".to_owned(),
                    }
                    .fail();
                }
                true
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
            Err(source) => return Err(source).context(IoSnafu { path: &path }),
        };

        let config = Config::default()
            .enable_autoload_extension(false)
            .context(AnalysisDatabaseSnafu {
                operation: "disable extension loading",
            })?
            .enable_external_access(false)
            .context(AnalysisDatabaseSnafu {
                operation: "disable external access",
            })?;
        let mut writer = Connection::open_with_flags(&path, config)
            .context(AnalysisDatabaseSnafu { operation: "open" })?;
        let metadata = fs::symlink_metadata(&path).context(IoSnafu { path: &path })?;
        if !metadata.is_file() {
            return AnalysisStateSnafu {
                path,
                reason: "the analysis database path is not a file".to_owned(),
            }
            .fail();
        }
        if !existing {
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
                .context(IoSnafu { path: &path })?;
        }
        let transaction = writer.transaction().context(AnalysisDatabaseSnafu {
            operation: "begin schema",
        })?;
        transaction
            .execute_batch(
                "CREATE TABLE IF NOT EXISTS store_meta (
                    singleton BOOLEAN PRIMARY KEY CHECK (singleton),
                    store_uuid VARCHAR NOT NULL,
                    schema_version INTEGER NOT NULL,
                    recovery_epoch UBIGINT NOT NULL,
                    commit_revision UBIGINT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS relation_revisions (
                    relation_name VARCHAR PRIMARY KEY,
                    last_changed_revision UBIGINT NOT NULL
                );",
            )
            .context(AnalysisDatabaseSnafu {
                operation: "create schema",
            })?;
        let initial_uuid = Uuid::new_v4().hyphenated().to_string();
        transaction
            .execute(
                "INSERT INTO store_meta
                 SELECT true, ?, ?, 1, 0 WHERE NOT EXISTS (SELECT 1 FROM store_meta)",
                params![initial_uuid, ANALYSIS_SCHEMA_VERSION],
            )
            .context(AnalysisDatabaseSnafu {
                operation: "initialize store identity",
            })?;
        let meta = Self::read_meta_from(&transaction, &path)?;
        if meta.schema_version != ANALYSIS_SCHEMA_VERSION as u32 {
            return AnalysisStateSnafu {
                path,
                reason: "the analysis schema version is unsupported".to_owned(),
            }
            .fail();
        }
        transaction.commit().context(AnalysisDatabaseSnafu {
            operation: "commit schema",
        })?;
        Ok(Self {
            root,
            _lease: lease,
            writer: Mutex::new(writer),
        })
    }

    pub fn meta(&self) -> Result<AnalysisStoreMetaV1> {
        let writer = self.writer()?;
        Self::read_meta_from(&writer, &self.root.join("analysis.duckdb"))
    }

    fn writer(&self) -> Result<MutexGuard<'_, Connection>> {
        self.writer.lock().map_err(|_| {
            AnalysisStateSnafu {
                path: self.root.clone(),
                reason: "the analysis writer lock is poisoned".to_owned(),
            }
            .build()
        })
    }

    fn read_meta_from(connection: &Connection, path: &Path) -> Result<AnalysisStoreMetaV1> {
        let (uuid, schema_version, recovery_epoch, commit_revision): (String, i64, u64, u64) =
            connection
                .query_row(
                    "SELECT store_uuid, schema_version, recovery_epoch, commit_revision
                     FROM store_meta WHERE singleton = true",
                    [],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
                )
                .context(AnalysisDatabaseSnafu {
                    operation: "read store identity",
                })?;
        let store_uuid = Uuid::parse_str(&uuid).map_err(|error| {
            AnalysisStateSnafu {
                path: path.to_path_buf(),
                reason: format!("the store UUID is invalid: {error}"),
            }
            .build()
        })?;
        let schema_version = u32::try_from(schema_version).map_err(|error| {
            AnalysisStateSnafu {
                path: path.to_path_buf(),
                reason: format!("the schema version is invalid: {error}"),
            }
            .build()
        })?;
        Ok(AnalysisStoreMetaV1 {
            store_uuid,
            schema_version,
            recovery_epoch,
            commit_revision,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn analysis_store_identity_and_rollback_survive_reopen(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let root = directory.path().join("analysis");
        let store = AnalysisStore::open(&root)?;
        let initial = store.meta()?;
        assert_eq!(initial.schema_version, 1);
        assert_eq!(initial.commit_revision, 0);
        assert!(AnalysisStore::open(&root).is_err());
        {
            let mut writer = store.writer()?;
            let transaction = writer.transaction().context(AnalysisDatabaseSnafu {
                operation: "begin rollback proof",
            })?;
            transaction
                .execute("UPDATE store_meta SET commit_revision = 1", [])
                .context(AnalysisDatabaseSnafu {
                    operation: "write rollback proof",
                })?;
        }
        assert_eq!(store.meta()?, initial);
        drop(store);
        let reopened = AnalysisStore::open(&root)?;
        assert_eq!(reopened.meta()?, initial);
        let writer = reopened.writer()?;
        let version: String = writer
            .query_row("SELECT version()", [], |row| row.get(0))
            .context(AnalysisDatabaseSnafu {
                operation: "read engine version",
            })?;
        assert!(version.contains(ANALYSIS_DUCKDB_BINDING_VERSION));
        assert!(writer
            .execute_batch("COPY (SELECT 1) TO '/tmp/araphor-analysis-forbidden.csv'")
            .is_err());
        Ok(())
    }

    #[test]
    fn analysis_store_rejects_newer_schema_and_nonprivate_directory(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let root = directory.path().join("analysis");
        let store = AnalysisStore::open(&root)?;
        {
            let writer = store.writer()?;
            writer.execute("UPDATE store_meta SET schema_version = 2", [])?;
        }
        drop(store);
        assert!(AnalysisStore::open(&root).is_err());
        fs::set_permissions(&root, fs::Permissions::from_mode(0o755))?;
        assert!(AnalysisStore::open(&root).is_err());
        assert!(AnalysisStore::open("relative-analysis").is_err());
        Ok(())
    }
}
