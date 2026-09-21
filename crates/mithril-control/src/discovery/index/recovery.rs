use std::io::{Read as _, Write as _};

use super::*;

impl DiscoveryIndex {
    pub(super) fn sidecar(path: &Path, suffix: &str) -> PathBuf {
        let mut name = path.as_os_str().to_os_string();
        name.push(suffix);
        name.into()
    }

    fn sync_root(root: &Path) -> Result<()> {
        File::open(root)
            .and_then(|file| file.sync_all())
            .context(IoSnafu { path: root })
    }

    fn file_digest(path: &Path) -> Result<[u8; 32]> {
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
            .open(path)
            .context(IoSnafu { path })?;
        let metadata = file.metadata().context(IoSnafu { path })?;
        DiscoveryInputManifestV1::require(
            metadata.is_file() && metadata.len() <= MAX_INDEX_DISK_BYTES / 2,
            "INDEX_REPLACEMENT_FILE",
        )?;
        let mut digest = Sha256::new();
        let mut buffer = [0; 64 * 1024];
        loop {
            let count = file.read(&mut buffer).context(IoSnafu { path })?;
            if count == 0 {
                return Ok(digest.finalize().into());
            }
            digest.update(&buffer[..count]);
        }
    }

    fn remove_owned(path: &Path) -> Result<()> {
        match fs::symlink_metadata(path) {
            Ok(metadata) => {
                DiscoveryInputManifestV1::require(metadata.is_file(), "INDEX_FILE_TYPE")?;
                fs::remove_file(path).context(IoSnafu { path })
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(source) => Err(source).context(IoSnafu { path }),
        }
    }

    pub(super) fn finish_install(root: &Path) -> Result<()> {
        let marker = root.join("discovery-index.install");
        let metadata = match fs::symlink_metadata(&marker) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(source) => return Err(source).context(IoSnafu { path: &marker }),
        };
        DiscoveryInputManifestV1::require(
            metadata.is_file() && metadata.len() == 32,
            "INDEX_INSTALL_MARKER",
        )?;
        let expected = fs::read(&marker).context(IoSnafu { path: &marker })?;
        let candidate = root.join("discovery-index.rebuild.sqlite");
        let current = root.join("discovery-index.sqlite");
        let previous = root.join("discovery-index.previous.sqlite");
        if candidate
            .try_exists()
            .context(IoSnafu { path: &candidate })?
        {
            DiscoveryInputManifestV1::require(
                Self::file_digest(&candidate)?.as_slice() == expected,
                "INDEX_INSTALL_DIGEST",
            )?;
            for suffix in ["", "-wal", "-shm"] {
                let from = Self::sidecar(&current, suffix);
                let to = Self::sidecar(&previous, suffix);
                if from.try_exists().context(IoSnafu { path: &from })? {
                    DiscoveryInputManifestV1::require(
                        !to.try_exists().context(IoSnafu { path: &to })?,
                        "INDEX_INSTALL_CONFLICT",
                    )?;
                    fs::rename(&from, &to).context(IoSnafu { path: &from })?;
                    Self::sync_root(root)?;
                    install_boundary(suffix);
                }
            }
            fs::rename(&candidate, &current).context(IoSnafu { path: &candidate })?;
            Self::sync_root(root)?;
            install_boundary("installed");
        }
        DiscoveryInputManifestV1::require(
            Self::file_digest(&current)?.as_slice() == expected,
            "INDEX_INSTALL_DIGEST",
        )?;
        for suffix in ["", "-wal", "-shm"] {
            Self::remove_owned(&Self::sidecar(&previous, suffix))?;
        }
        Self::sync_root(root)?;
        Self::remove_owned(&marker)?;
        Self::sync_root(root)
    }

    fn validate_and_checkpoint(&self) -> Result<()> {
        let writer = self.writer.lock().map_err(|_| {
            DiscoverySnafu {
                code: "INDEX_OWNER",
                reason: "the writer lock is poisoned",
            }
            .build()
        })?;
        let check: String = writer
            .query_row("PRAGMA integrity_check", [], |row| row.get(0))
            .context(DiscoveryDatabaseSnafu {
                operation: "validate replacement",
            })?;
        DiscoveryInputManifestV1::require(check == "ok", "INDEX_INTEGRITY")?;
        let violations: u64 = writer
            .query_row("SELECT count(*) FROM pragma_foreign_key_check", [], |row| {
                row.get(0)
            })
            .context(DiscoveryDatabaseSnafu {
                operation: "validate replacement references",
            })?;
        DiscoveryInputManifestV1::require(violations == 0, "INDEX_INTEGRITY")?;
        let busy: u64 = writer
            .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |row| row.get(0))
            .context(DiscoveryDatabaseSnafu {
                operation: "checkpoint replacement",
            })?;
        DiscoveryInputManifestV1::require(busy == 0, "INDEX_CHECKPOINT_BUSY")?;
        self.check_disk(0)
    }
}

impl DiscoveryOwner {
    /// Rebuild the derived index while the Discovery owner is closed.
    pub fn rebuild_index(store: ControlStore) -> Result<Self> {
        let lease = DiscoveryIndex::lease(&store)?;
        let root = store.root();
        DiscoveryIndex::finish_install(&root)?;
        let current = root.join("discovery-index.sqlite");
        if current.try_exists().context(IoSnafu { path: &current })? {
            // A newer index is not corruption. Do not replace it with an older schema.
            let result = Connection::open_with_flags(
                &current,
                rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY
                    | rusqlite::OpenFlags::SQLITE_OPEN_NOFOLLOW,
            )
            .and_then(|db| db.pragma_query_value::<i64, _>(None, "user_version", |row| row.get(0)));
            match result {
                Ok(version) => DiscoveryInputManifestV1::require(
                    version <= INDEX_SCHEMA_VERSION,
                    "INDEX_SCHEMA",
                )?,
                Err(rusqlite::Error::SqliteFailure(error, _))
                    if matches!(
                        error.code,
                        rusqlite::ErrorCode::DatabaseCorrupt | rusqlite::ErrorCode::NotADatabase
                    ) => {}
                Err(source) => {
                    return Err(source).context(DiscoveryDatabaseSnafu {
                        operation: "inspect replacement source",
                    })
                }
            }
        }
        let candidate = root.join("discovery-index.rebuild.sqlite");
        for suffix in ["", "-wal", "-shm"] {
            DiscoveryIndex::remove_owned(&DiscoveryIndex::sidecar(&candidate, suffix))?;
        }
        let (_, heads) = store.discovery_catalog()?;
        let index = DiscoveryIndex::open_at(store.clone(), candidate.clone(), lease.clone())?;
        let owner = Self {
            live: super::super::live::DiscoveryLive {
                store: store.clone(),
                index,
                operation: Mutex::new(()),
            },
        };
        while !owner.project_revisions()? {}
        for head in &heads {
            match feed::RevisionPayload::read(&owner, head)? {
                feed::RevisionPayload::Export(_) => {
                    owner.live.index.replay_interval(head)?;
                }
                feed::RevisionPayload::Profile(profile) => {
                    let mut cursor = None;
                    let mut atoms = 0_u64;
                    let mut observations = 0_u64;
                    loop {
                        let page = owner.read_snapshot(head, cursor.as_ref())?;
                        atoms += page.atoms.len() as u64;
                        observations = page
                            .atoms
                            .iter()
                            .fold(observations, |sum, atom| sum.saturating_add(atom.count));
                        cursor = page.next;
                        if cursor.is_none() {
                            break;
                        }
                    }
                    DiscoveryInputManifestV1::require(
                        atoms == profile.atom_count && observations == profile.included_records,
                        "INDEX_REBUILD_COUNTS",
                    )?;
                }
                feed::RevisionPayload::Context(_) | feed::RevisionPayload::Checkpoint(_) => {}
            }
        }
        DiscoveryInputManifestV1::require(
            store.discovery_catalog()?.1 == heads,
            "INDEX_REBUILD_CHANGED",
        )?;
        owner.live.index.validate_and_checkpoint()?;
        drop(owner);
        File::open(&candidate)
            .and_then(|file| file.sync_all())
            .context(IoSnafu { path: &candidate })?;
        let digest = DiscoveryIndex::file_digest(&candidate)?;
        let pending = root.join("discovery-index.install.tmp");
        DiscoveryIndex::remove_owned(&pending)?;
        let mut marker = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&pending)
            .context(IoSnafu { path: &pending })?;
        marker
            .write_all(&digest)
            .and_then(|()| marker.sync_all())
            .context(IoSnafu { path: &pending })?;
        fs::rename(&pending, root.join("discovery-index.install"))
            .context(IoSnafu { path: &pending })?;
        DiscoveryIndex::sync_root(&root)?;
        install_boundary("marker");
        DiscoveryIndex::finish_install(&root)?;
        let index = DiscoveryIndex::open_at(store.clone(), current, lease)?;
        Ok(Self {
            live: super::super::live::DiscoveryLive {
                store,
                index,
                operation: Mutex::new(()),
            },
        })
    }
}

fn install_boundary(_boundary: &str) {
    #[cfg(test)]
    if std::env::var("ARAPHOR_TEST_INDEX_INSTALL_KILL").as_deref() == Ok(_boundary) {
        std::process::exit(73);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore = "subprocess worker for the replacement crash test"]
    fn discovery_index_install_worker() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let root = std::env::var("ARAPHOR_TEST_INDEX_INSTALL_ROOT")?;
        DiscoveryOwner::rebuild_index(ControlStore::open(root)?)?;
        Err("the requested crash boundary was not reached".into())
    }

    #[test]
    fn discovery_index_replacement_recovers_process_exit_and_keeps_positions(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        for boundary in ["marker", "", "installed"] {
            let directory = tempfile::tempdir()?;
            let store = ControlStore::open(directory.path())?;
            let index = DiscoveryIndex::open(store.clone())?;
            let page = super::super::tests::resolved_page()?;
            let artifact = store.put_discovery_artifact(&page.artifact()?)?;
            let head = store.commit_discovery_head(
                crate::DiscoveryHeadKeyV1 {
                    tenant_id: page.stream.tenant_id,
                    id: DiscoveryDigestV1::of(&"replacement")?,
                },
                None,
                artifact,
            )?;
            let progress = index.apply_export(&head)?;
            let atoms = index.atoms(&head, None)?;
            drop(index);
            drop(store);
            let status = std::process::Command::new(std::env::current_exe()?)
                .args([
                    "discovery::index::recovery::tests::discovery_index_install_worker",
                    "--exact",
                    "--ignored",
                    "--nocapture",
                ])
                .env("ARAPHOR_TEST_INDEX_INSTALL_ROOT", directory.path())
                .env("ARAPHOR_TEST_INDEX_INSTALL_KILL", boundary)
                .status()?;
            assert_eq!(status.code(), Some(73));
            let store = ControlStore::open(directory.path())?;
            let owner = DiscoveryOwner::open(store.clone())?;
            assert_eq!(
                owner
                    .live
                    .index
                    .progress(head.key.tenant_id, &head.key.id)?,
                Some(progress)
            );
            assert_eq!(owner.live.index.atoms(&head, None)?, atoms);
            let revisions = owner.read_revisions(head.key.tenant_id.into(), None)?;
            assert_eq!(revisions.events.len(), 3);
            assert!(revisions
                .events
                .iter()
                .all(|event| event.position.commit_index == head.commit_index));
            assert_eq!(store.evidence_cursor(&page.stream)?, 0);
            assert!(!directory.path().join("discovery-index.install").exists());
            assert!(!directory
                .path()
                .join("discovery-index.previous.sqlite")
                .exists());
        }
        Ok(())
    }

    #[test]
    fn discovery_index_replacement_keeps_prior_index_on_invalid_authority(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let store = ControlStore::open(directory.path())?;
        let index = DiscoveryIndex::open(store.clone())?;
        drop(index);
        let current = directory.path().join("discovery-index.sqlite");
        let digest = DiscoveryIndex::file_digest(&current)?;
        store.commit_discovery_head(
            crate::DiscoveryHeadKeyV1 {
                tenant_id: [3; 16],
                id: DiscoveryDigestV1::of(&"unsupported")?,
            },
            None,
            store.put_discovery_artifact(&DiscoveryArtifactV1 {
                schema_version: 1,
                tenant_id: [3; 16],
                dependencies: vec![],
                payload: vec![0],
            })?,
        )?;
        assert!(DiscoveryOwner::rebuild_index(store.clone()).is_err());
        assert_eq!(DiscoveryIndex::file_digest(&current)?, digest);
        drop(DiscoveryIndex::open(store.clone())?);
        let db = Connection::open(&current)?;
        db.pragma_update(None, "user_version", INDEX_SCHEMA_VERSION + 1)?;
        drop(db);
        let digest = DiscoveryIndex::file_digest(&current)?;
        assert!(DiscoveryOwner::rebuild_index(store).is_err());
        assert_eq!(DiscoveryIndex::file_digest(&current)?, digest);
        Ok(())
    }

    #[test]
    fn discovery_index_replacement_repairs_corrupt_sql_and_bounds_reserved_disk(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let store = ControlStore::open(directory.path())?;
        let index = DiscoveryIndex::open(store.clone())?;
        let page = super::super::tests::resolved_page()?;
        let head = store.commit_discovery_head(
            crate::DiscoveryHeadKeyV1 {
                tenant_id: page.stream.tenant_id,
                id: DiscoveryDigestV1::of(&"corrupt-index")?,
            },
            None,
            store.put_discovery_artifact(&page.artifact()?)?,
        )?;
        let progress = index.apply_export(&head)?;
        drop(index);
        drop(store);
        fs::write(
            directory.path().join("discovery-index.sqlite"),
            b"not a SQLite database",
        )?;
        let store = ControlStore::open(directory.path())?;
        let owner = DiscoveryOwner::open(store)?;
        let index = &owner.live.index;
        assert_eq!(
            index.progress(head.key.tenant_id, &head.key.id)?,
            Some(progress)
        );
        let candidate = directory.path().join("discovery-index.rebuild.sqlite");
        let file = File::create(&candidate)?;
        let active = ["", "-wal", "-shm"]
            .into_iter()
            .try_fold(0_u64, |sum, suffix| {
                match fs::metadata(DiscoveryIndex::sidecar(&index.path, suffix)) {
                    Ok(metadata) => Ok(sum + metadata.len()),
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(sum),
                    Err(error) => Err(error),
                }
            })?;
        file.set_len(MAX_INDEX_DISK_BYTES - active)?;
        index.check_disk(0)?;
        file.set_len(MAX_INDEX_DISK_BYTES - active + 1)?;
        assert!(index.check_disk(0).is_err());
        assert!(index.progress(head.key.tenant_id, &head.key.id)?.is_some());
        Ok(())
    }
}
