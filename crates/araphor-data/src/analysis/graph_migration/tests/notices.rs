use super::*;
use crate::analysis::{GRAPH_LEGACY_VERSION, GRAPH_NOTICE_LEGACY_VERSION};

#[test]
fn notice_migration_keeps_refs() -> TestResult {
    for legacy in [GRAPH_NOTICE_LEGACY_VERSION, GRAPH_LEGACY_VERSION] {
        let mut fixture = CommitFixture::new()?;
        let refs = if legacy == GRAPH_NOTICE_LEGACY_VERSION {
            fixture.add_packages()?
        } else {
            Vec::new()
        };
        let notice = fixture.request.context_revision + 100;
        fixture.snapshot.context_notice_revision = notice;
        fixture.request.body = serde_json::to_vec(&fixture.snapshot)?;
        let receipt = fixture.store.commit_graph(&fixture.request, true)?;
        let meta = fixture.store.meta()?;
        let health = fixture.store.processor_health(&fixture.request.scope)?;
        let packages = fixture
            .store
            .package_revisions(fixture.request.scope.identity.tenant_id)?;
        fixture.store.legacy_notice_fixture()?;
        if legacy == GRAPH_LEGACY_VERSION {
            fixture.store.legacy_graph_fixture()?;
        }
        let stored: u64 = fixture.store.writer()?.get()?.query_row(
            "SELECT facts_revision FROM analysis_results WHERE result_id = ?",
            params![fixture.request.result_id],
            |row| row.get(0),
        )?;
        assert_eq!(stored, fixture.request.context_revision);
        assert_ne!(stored, notice);
        let root = fixture.directory.path().join("analysis");
        let backup = root.join("backups/notices");
        let manifest = fixture.store.backup(&backup)?;
        assert_eq!(manifest.schema_version, legacy);
        let CommitFixture {
            directory,
            owner,
            store,
            request,
            snapshot,
        } = fixture;
        drop(owner);
        drop(store);
        let reopened = AnalysisStore::open(&root)?;
        let restored = AnalysisStore::restore(&backup, &directory.path().join("restored"))?;
        let mut restored_meta = meta.clone();
        restored_meta.recovery_epoch = meta.recovery_epoch.checked_add(1).ok_or("restore epoch")?;
        for (store, expected) in [(&reopened, &meta), (&restored, &restored_meta)] {
            assert_eq!(store.meta()?, *expected);
            assert_eq!(store.processor_health(&request.scope)?, health);
            assert_eq!(
                store.package_revisions(request.scope.identity.tenant_id)?,
                packages
            );
            assert_eq!(store.commit_graph(&request, true)?, receipt);
            assert_eq!(
                store.read_result(request.scope.identity.tenant_id, &request.result_id)?,
                Some(request.body.clone())
            );
            assert_eq!(
                store.graph_result(request.scope.identity.tenant_id, &request.result_id)?,
                Some(snapshot.clone())
            );
            assert_eq!(
                store.graph_notice(&request.scope, &request.result_id, receipt.commit_revision)?,
                Some((notice, 1))
            );
            let key = crate::GraphAndFindingOwner::package_key(
                &request.scope.identity,
                &request.result_id,
            );
            let context = store.context_version(&key)?;
            if refs.is_empty() {
                assert!(context.is_none());
            } else {
                let context = context.ok_or("package context")?;
                assert_eq!(
                    crate::InstalledRefV1::context_refs(&context)?,
                    Some(refs.clone())
                );
            }
            let mut changed = request.clone();
            changed.created_utc_ns += 1;
            assert!(matches!(
                store.commit_graph(&changed, true),
                Err(crate::Error::AnalysisConflict { .. })
            ));
            AnalysisStore::validate_usage(store.writer()?.get()?, &store.root)?;
        }
    }
    Ok(())
}

#[test]
fn native_notice_migration_empty() -> TestResult {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("analysis");
    let store = AnalysisStore::open(&root)?;
    let meta = store.meta()?;
    store.legacy_notice_fixture()?;
    drop(store);
    let store = AnalysisStore::open(&root)?;
    assert_eq!(store.meta()?, meta);
    AnalysisStore::validate_usage(store.writer()?.get()?, &root)?;
    Ok(())
}

#[test]
fn notice_migration_keeps_history() -> TestResult {
    let fixture = MigrationFixture::new()?;
    let meta = fixture.store.meta()?;
    let health = fixture.store.processor_health(&fixture.first.scope)?;
    fixture.store.legacy_notice_fixture()?;
    let root = fixture.directory.path().join("analysis");
    let backup = root.join("backups/notices");
    assert_eq!(
        fixture.store.backup(&backup)?.schema_version,
        GRAPH_NOTICE_LEGACY_VERSION
    );
    drop(fixture.store);
    let reopened = AnalysisStore::open(&root)?;
    let restored = AnalysisStore::restore(&backup, &fixture.directory.path().join("restored"))?;
    let fixture = MigrationFixture {
        store: Arc::new(reopened),
        ..fixture
    };
    let mut restored_meta = meta.clone();
    restored_meta.recovery_epoch = meta.recovery_epoch.checked_add(1).ok_or("restore epoch")?;
    for (store, expected) in [(fixture.store.as_ref(), &meta), (&restored, &restored_meta)] {
        fixture.check(store)?;
        assert_eq!(store.meta()?, *expected);
        assert_eq!(store.processor_health(&fixture.first.scope)?, health);
        for request in [&fixture.first, &fixture.second] {
            let snapshot = GraphSnapshotV1::try_from(request.body.as_slice())?;
            let notice: u64 = store.writer()?.get()?.query_row(
                "SELECT facts_revision FROM analysis_results WHERE result_id = ?",
                params![request.result_id],
                |row| row.get(0),
            )?;
            assert_eq!(notice, snapshot.context_notice_revision);
        }
    }
    Ok(())
}

#[test]
fn notice_migration_rejects_header() -> TestResult {
    let fixture = MigrationFixture::new()?;
    fixture.store.legacy_notice_fixture()?;
    let root = fixture.directory.path().join("analysis");
    let database = root.join("analysis.duckdb");
    {
        let writer = fixture.store.writer()?;
        writer.get()?.execute(
            "UPDATE analysis_results SET body = 'invalid'::BLOB WHERE result_id = ?",
            params![fixture.second.result_id],
        )?;
        writer.get()?.execute_batch(&format!(
            "DELETE FROM tenant_usage; INSERT INTO tenant_usage {}",
            AnalysisStore::usage_projection(true)
        ))?;
    }
    drop(fixture.store);
    let bytes = fs::read(&database)?;
    assert!(AnalysisStore::open(&root).is_err());
    assert_eq!(fs::read(&database)?, bytes);
    let writer = Connection::open(database)?;
    assert_eq!(
        AnalysisStore::read_meta_from(&writer, &root)?.schema_version,
        GRAPH_NOTICE_LEGACY_VERSION
    );
    Ok(())
}
