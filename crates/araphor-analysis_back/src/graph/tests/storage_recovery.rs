use std::sync::Arc;

use super::native_storage::CommitFixture;
use crate::NotificationRouter;
use araphor_data::analysis::{AnalysisStore, ANALYSIS_SCHEMA_VERSION};
use araphor_data::{
    AnalysisContextVersionV1, AnalysisResultCommitV1, NotificationAuthorization,
    NotificationErrorCodeV1, NotificationGrantV1, NotificationObligationV1,
};
use duckdb::Connection;

type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;

struct NoAuthority;

impl NotificationAuthorization for NoAuthority {
    fn check(&self, _grant: &NotificationGrantV1, _now: u64) -> araphor_data::Result<()> {
        araphor_data::NotificationSnafu {
            code: NotificationErrorCodeV1::Denied,
            field: "fixture grant",
        }
        .fail()
    }
}

struct RecoveryFixture {
    directory: tempfile::TempDir,
    store: Arc<AnalysisStore>,
    first: AnalysisResultCommitV1,
    second: AnalysisResultCommitV1,
    notification: AnalysisContextVersionV1,
}

impl RecoveryFixture {
    fn new() -> std::result::Result<Self, Box<dyn std::error::Error>> {
        let CommitFixture {
            directory,
            owner,
            store,
            mut snapshot,
            request,
        } = CommitFixture::new()?;
        store.commit_graph(&request, true)?;
        let router = NotificationRouter::new(store.clone(), Arc::new(NoAuthority))?;
        assert_eq!(router.route(&owner, 11)?, 1);
        let notification = store
            .notification_states(
                request.scope.identity.tenant_id,
                araphor_data::analysis::NotificationLookup::Finding(
                    &snapshot.findings[0].finding_id,
                    snapshot.findings[0].required_action.as_deref(),
                ),
            )?
            .remove(0);
        let state: NotificationObligationV1 = serde_json::from_slice(&notification.body)?;
        state.validate()?;
        assert_eq!(
            state
                .finding
                .as_ref()
                .ok_or("notification finding")?
                .result_id,
            request.result_id
        );
        let mut second = request.clone();
        second.result_id = "graph:native-storage-replacement".into();
        second.expected_cursor = 1;
        second.created_utc_ns = 12;
        snapshot.findings.clear();
        second.body = serde_json::to_vec(&snapshot)?;
        store.commit_graph(&second, false)?;
        assert!(owner
            .current_findings(request.scope.identity.tenant_id)?
            .is_empty());
        drop(router);
        drop(owner);
        Ok(Self {
            directory,
            store,
            first: request,
            second,
            notification,
        })
    }

    fn check(&self, store: &AnalysisStore) -> TestResult {
        let tenant = self.first.scope.identity.tenant_id;
        assert_eq!(
            store.read_result(tenant, &self.first.result_id)?,
            Some(self.first.body.clone())
        );
        assert_eq!(
            store.read_result(tenant, &self.second.result_id)?,
            Some(self.second.body.clone())
        );
        assert_eq!(
            store.context_version(&self.notification.key)?,
            Some(self.notification.clone())
        );
        let state: NotificationObligationV1 = serde_json::from_slice(&self.notification.body)?;
        let reference = state.finding.ok_or("notification finding")?;
        let historical = store
            .graph_result(tenant, &reference.result_id)?
            .ok_or("historical graph")?;
        assert!(historical
            .findings
            .iter()
            .any(|finding| finding.finding_id == reference.finding_id));
        let progress = store
            .processor_result(&self.first.scope)?
            .ok_or("processor result")?;
        assert_eq!(progress.result_id, self.first.result_id);
        assert_eq!(progress.body, self.first.body);
        store.verify_state()?;
        Ok(())
    }
}

#[test]
fn native_backup_retains_references() -> TestResult {
    let fixture = RecoveryFixture::new()?;
    let root = fixture.directory.path().join("analysis");
    let backup = root.join("backups/history");
    let manifest = fixture.store.backup(&backup)?;
    let target = fixture.directory.path().join("restored");
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
        "UPDATE analysis_results SET body = 'invalid'::BLOB WHERE processor_id = 'graph-findings'",
        "UPDATE analysis_results SET method_version = 99 WHERE processor_id = 'graph-findings'",
        "UPDATE analysis_results SET first_cursor = 99 WHERE processor_id = 'graph-findings'",
    ] {
        let fixture = RecoveryFixture::new()?;
        let root = fixture.directory.path().join("analysis");
        drop(fixture.store);
        Connection::open(root.join("analysis.duckdb"))?.execute_batch(fault)?;
        assert!(AnalysisStore::open(&root).is_err(), "accepted {fault}");
    }
    Ok(())
}
