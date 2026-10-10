use std::fs;
use std::sync::Arc;

use super::*;
use crate::graph::tests::native_storage::CommitFixture;
use crate::{
    AnalysisContextVersionV1, AnalysisResultCommitV1, NotificationAuthorization,
    NotificationErrorCodeV1, NotificationGrantV1, NotificationObligationV1, NotificationRouter,
};

type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;

mod recovery;

mod fixtures;
use fixtures::MigrationFixture;

#[test]
fn native_migration_empty_store() -> TestResult {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("analysis");
    let store = AnalysisStore::open(&root)?;
    let original = store.meta()?;
    store.legacy_graph_fixture()?;
    drop(store);
    let store = AnalysisStore::open(root)?;
    let current = store.meta()?;
    assert_eq!(current.schema_version, ANALYSIS_SCHEMA_VERSION as u32);
    assert_eq!(current.store_uuid, original.store_uuid);
    assert_eq!(current.commit_revision, original.commit_revision);
    assert_eq!(current.recovery_epoch, original.recovery_epoch);
    AnalysisStore::validate_usage(store.writer()?.get()?, &store.root)?;
    Ok(())
}

#[test]
fn native_migration_generic_results() -> TestResult {
    let fixture = CommitFixture::new()?;
    fixture.store.commit_graph(&fixture.request, true)?;
    fixture.store.legacy_graph_fixture()?;
    {
        let writer = fixture.store.writer()?;
        writer.get()?.execute(
            "UPDATE analysis_results SET body = ?, stream_key = NULL, method_version = NULL,
            interval_id = NULL, profile_revision = NULL, facts_revision = NULL,
            coverage_revision = NULL, first_cursor = NULL WHERE result_id = ?",
            params![
                b"legacy generic result".as_slice(),
                fixture.request.result_id
            ],
        )?;
        writer.get()?.execute_batch(&format!(
            "DELETE FROM tenant_usage; INSERT INTO tenant_usage {}",
            AnalysisStore::usage_projection(false)
        ))?;
    }
    let root = fixture.directory.path().join("analysis");
    let tenant = fixture.request.scope.identity.tenant_id;
    drop(fixture.owner);
    drop(fixture.store);
    let store = AnalysisStore::open(root)?;
    assert_eq!(
        store.read_result(tenant, &fixture.request.result_id)?,
        Some(b"legacy generic result".to_vec())
    );
    assert_eq!(
        store
            .processor_result(&fixture.request.scope)?
            .ok_or("generic result")?
            .body,
        b"legacy generic result"
    );
    let encoding: Option<Vec<u8>> = store.writer()?.get()?.query_row(
        "SELECT graph_encoding FROM analysis_results WHERE result_id = ?",
        params![fixture.request.result_id],
        |row| row.get(0),
    )?;
    assert!(encoding.is_none());
    Ok(())
}

#[test]
fn native_migration_retains_history() -> TestResult {
    let fixture = MigrationFixture::new()?;
    let meta = fixture.store.meta()?;
    let progress = fixture.store.processor_health(&fixture.first.scope)?;
    let root = fixture.directory.path().join("analysis");
    fixture.store.legacy_graph_fixture()?;
    drop(fixture.store);
    let store = AnalysisStore::open(&root)?;
    let restored = store.meta()?;
    assert_eq!(restored.schema_version, ANALYSIS_SCHEMA_VERSION as u32);
    assert_eq!(restored.store_uuid, meta.store_uuid);
    assert_eq!(restored.recovery_epoch, meta.recovery_epoch);
    assert_eq!(restored.commit_revision, meta.commit_revision);
    assert_eq!(store.processor_health(&fixture.first.scope)?, progress);
    let fixture = MigrationFixture {
        store: Arc::new(store),
        ..fixture
    };
    fixture.check(&fixture.store)?;
    let reader = fixture.store.writer()?;
    let results: u64 = reader.get()?.query_row(
        "SELECT COUNT(*) FROM analysis_results WHERE processor_id = 'graph-findings'",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(results, 2);
    for result in [&fixture.first, &fixture.second] {
        let header = GraphRows::read_header(
            reader.get()?,
            result.scope.identity.tenant_id,
            &result.result_id,
        )?
        .ok_or("native graph header")?;
        assert!(header.snapshot.graph.subjects.is_empty());
        assert!(header.snapshot.graph.edges.is_empty());
        assert!(header.snapshot.findings.is_empty());
    }
    drop(reader);
    fixture.store.recover()?;
    fixture.check(&fixture.store)?;
    Ok(())
}

#[test]
fn native_migration_json_layout() -> TestResult {
    let mut fixture = MigrationFixture::new()?;
    let root = fixture.directory.path().join("analysis");
    fixture.store.legacy_graph_fixture()?;
    let snapshot = GraphSnapshotV1::try_from(fixture.first.body.as_slice())?;
    let value = serde_json::to_value(snapshot)?;
    fixture.first.body = serde_json::to_string_pretty(&value)?
        .replace("\"node_id\": \"node\"", "\"node_id\": \"\\u006eode\"")
        .replace("\"scope\":", "\"\\u0073cope\":")
        .into_bytes();
    {
        let writer = fixture.store.writer()?;
        writer.get()?.execute(
            "UPDATE analysis_results SET body = ? WHERE result_id = ?",
            params![fixture.first.body, fixture.first.result_id],
        )?;
        writer.get()?.execute_batch(&format!(
            "DELETE FROM tenant_usage; INSERT INTO tenant_usage {}",
            AnalysisStore::usage_projection(false)
        ))?;
    }
    drop(fixture.store);
    let store = AnalysisStore::open(&root)?;
    let fixture = MigrationFixture {
        store: Arc::new(store),
        ..fixture
    };
    fixture.check(&fixture.store)?;
    assert!(fixture.first.body.windows(6).any(|part| part == b"\\u0073"));
    let encoding: u64 = fixture.store.writer()?.get()?.query_row(
        "SELECT octet_length(graph_encoding) FROM analysis_results WHERE result_id = ?",
        params![fixture.first.result_id],
        |row| row.get(0),
    )?;
    assert!(encoding > 0);
    let backup = root.join("backups/layout");
    fixture.store.backup(&backup)?;
    fixture.check(&AnalysisStore::restore(
        &backup,
        &fixture.directory.path().join("layout-restored"),
    )?)?;
    Ok(())
}

#[test]
fn native_migration_preserves_failures() -> TestResult {
    for fault in ["malformed", "index", "quota"] {
        let fixture = MigrationFixture::new()?;
        let root = fixture.directory.path().join("analysis");
        fixture.store.legacy_graph_fixture()?;
        let database = root.join("analysis.duckdb");
        drop(fixture.store);
        {
            let writer = Connection::open(&database)?;
            match fault {
                "malformed" => {
                    writer.execute(
                        "UPDATE analysis_results SET body = ? WHERE result_id = ?",
                        params![b"{invalid graph".as_slice(), fixture.first.result_id],
                    )?;
                    writer.execute_batch(&format!(
                        "DELETE FROM tenant_usage; INSERT INTO tenant_usage {}",
                        AnalysisStore::usage_projection(false)
                    ))?;
                }
                "index" => {
                    writer.execute(
                        "UPDATE analysis_results SET first_cursor = 99 WHERE result_id = ?",
                        params![fixture.second.result_id],
                    )?;
                }
                "quota" => {}
                _ => unreachable!(),
            }
        }
        let before = fs::read(&database)?;
        let segments = fs::read_dir(root.join("segments"))?
            .map(|entry| {
                let path = entry?.path();
                Ok((path.clone(), fs::read(path)?))
            })
            .collect::<std::io::Result<Vec<_>>>()?;
        let limits = if fault == "quota" {
            StorageLimitsV1 {
                tenant_max_bytes: 1,
                ..Default::default()
            }
        } else {
            StorageLimitsV1::default()
        };
        let reopened = AnalysisStore::open_with_limits(&root, Default::default(), limits);
        if fault == "quota" {
            assert!(matches!(
                reopened,
                Err(crate::Error::StorageCapacity {
                    resource: "tenant logical bytes",
                    ..
                })
            ));
        } else {
            assert!(reopened.is_err(), "accepted {fault}");
        }
        assert_eq!(fs::read(&database)?, before, "changed {fault}");
        for (path, bytes) in segments {
            assert_eq!(fs::read(path)?, bytes);
        }
        let writer = Connection::open(&database)?;
        assert_eq!(
            AnalysisStore::read_meta_from(&writer, &database)?.schema_version,
            17
        );
        assert!(writer.prepare("SELECT * FROM graph_subjects").is_err());
        assert!(writer
            .prepare("SELECT graph_encoding FROM analysis_results")
            .is_err());
        let retained: Vec<u8> = writer.query_row(
            "SELECT body FROM analysis_results WHERE result_id = ?",
            params![fixture.second.result_id],
            |row| row.get(0),
        )?;
        assert_eq!(retained, fixture.second.body);
    }
    Ok(())
}

#[test]
fn native_migration_checks_space() -> TestResult {
    let fixture = MigrationFixture::new()?;
    let root = fixture.directory.path().join("analysis");
    fixture.store.legacy_graph_fixture()?;
    let database = root.join("analysis.duckdb");
    drop(fixture.store);
    let before = fs::read(&database)?;
    let limits = StorageLimitsV1 {
        disk_max_bytes: 1024 * 1024 * 1024,
        ..Default::default()
    };
    let usage = AnalysisStore::storage_at(&root, 0, 0)?;
    let padding = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(root.join("migration-space"))?;
    padding.set_len(limits.disk_max_bytes - usage.file_bytes - SPILL_RESERVE + 1)?;
    assert!(matches!(
        AnalysisStore::open_with_limits(&root, Default::default(), limits),
        Err(crate::Error::StorageCapacity {
            resource: "data files",
            ..
        })
    ));
    assert_eq!(fs::read(&database)?, before);
    let writer = Connection::open(database)?;
    assert_eq!(
        AnalysisStore::read_meta_from(&writer, &root)?.schema_version,
        17
    );
    assert!(writer.prepare("SELECT * FROM graph_subjects").is_err());
    assert!(writer
        .prepare("SELECT graph_encoding FROM analysis_results")
        .is_err());
    Ok(())
}
