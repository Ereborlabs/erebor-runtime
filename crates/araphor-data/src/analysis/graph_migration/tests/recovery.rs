use super::*;

#[test]
fn native_backup_retains_references() -> TestResult {
    for legacy in [false, true] {
        let fixture = MigrationFixture::new()?;
        let root = fixture.directory.path().join("analysis");
        let backup = root.join("backups/history");
        let manifest = fixture.store.backup(&backup)?;
        if legacy {
            let lease = crate::analysis::connection::AnalysisLease::acquire(&backup)?;
            let store = AnalysisStore::open_leased(
                backup.clone(),
                Default::default(),
                Default::default(),
                lease,
            )?;
            store.legacy_graph_fixture()?;
            drop(store);
            fs::remove_file(backup.join("analysis.lock"))?;
            let mut legacy_manifest = manifest.clone();
            legacy_manifest.schema_version = 17;
            legacy_manifest.database_bytes = fs::metadata(backup.join("analysis.duckdb"))?.len();
            fs::write(
                backup.join("manifest.json"),
                serde_json::to_vec(&legacy_manifest)?,
            )?;
        }
        let target = fixture.directory.path().join(if legacy {
            "legacy-restored"
        } else {
            "restored"
        });
        let restored = AnalysisStore::restore(&backup, &target)?;
        assert_eq!(
            restored.meta()?.schema_version,
            ANALYSIS_SCHEMA_VERSION as u32
        );
        assert_eq!(
            restored.meta()?.store_uuid,
            fixture.store.meta()?.store_uuid
        );
        assert_eq!(restored.meta()?.commit_revision, manifest.commit_revision);
        assert_eq!(restored.meta()?.recovery_epoch, manifest.recovery_epoch + 1);
        fixture.check(&restored)?;
        drop(restored);
        fixture.check(&AnalysisStore::open(&target)?)?;
    }
    Ok(())
}

#[test]
fn native_recovery_rejects_corruption() -> TestResult {
    for fault in [
        "DELETE FROM graph_findings",
        "UPDATE graph_subjects SET ordinal = ordinal + 10",
        "UPDATE graph_findings SET result_id = 'orphan'",
        "UPDATE graph_findings SET tenant_id = 'foreign'::BLOB",
        "DROP TABLE graph_relationships",
        "UPDATE analysis_results SET graph_encoding = NULL",
        "ALTER TABLE analysis_results DROP COLUMN graph_encoding",
        "ALTER TABLE analysis_results ALTER COLUMN graph_encoding SET NOT NULL",
    ] {
        let fixture = MigrationFixture::new()?;
        let root = fixture.directory.path().join("analysis");
        drop(fixture.store);
        {
            Connection::open(root.join("analysis.duckdb"))?.execute_batch(fault)?;
        }
        assert!(AnalysisStore::open(root).is_err(), "accepted {fault}");
    }
    Ok(())
}
