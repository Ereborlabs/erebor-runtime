use std::sync::Arc;

use super::native_storage::CommitFixture;
use araphor_data::*;

type TestResult<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
type FrozenResult = (Vec<u8>, Vec<u8>, u64);

struct NoFacts;

impl crate::GraphContextProvider for NoFacts {
    fn facts(
        &self,
        _record: &crate::DiscoveryRecordV1,
    ) -> araphor_data::Result<Vec<crate::AnalysisContextVersionV1>> {
        Ok(Vec::new())
    }
}

fn frozen(store: &AnalysisStore, result_id: &str) -> TestResult<FrozenResult> {
    Ok(store.frozen_result(result_id)?)
}

fn usage(store: &AnalysisStore, tenant: [u8; 16]) -> TestResult<(u64, u64, u64, u64)> {
    Ok(store.retained_usage(tenant)?)
}

#[test]
fn graph_notice_keeps_result() -> TestResult {
    let mut fixture = CommitFixture::new()?;
    let references = fixture.add_packages()?;
    let notice = fixture.request.context_revision + 100;
    fixture.snapshot.context_notice_revision = notice;
    fixture.request.body = serde_json::to_vec(&fixture.snapshot)?;
    let receipt = fixture.store.commit_graph(&fixture.request, true)?;
    let scope = &fixture.request.scope;
    let id = &fixture.request.result_id;
    let tenant = scope.identity.tenant_id;
    let bytes = frozen(&fixture.store, id)?;
    let quota = usage(&fixture.store, tenant)?;
    let meta = fixture.store.meta()?;
    let health = fixture.store.processor_health(scope)?;
    let head = fixture.store.processor_result(scope)?;
    assert_eq!(
        fixture
            .store
            .graph_notice(scope, id, receipt.commit_revision)?,
        Some((notice, 1))
    );
    fixture
        .store
        .mark_graph_notice(scope, id, receipt.commit_revision, notice + 1, 1)?;
    assert_eq!(
        fixture
            .store
            .graph_notice(scope, id, receipt.commit_revision)?,
        Some((notice + 1, 1))
    );
    assert!(matches!(
        fixture
            .store
            .mark_graph_notice(scope, id, receipt.commit_revision + 1, notice + 2, 1),
        Err(araphor_data::Error::AnalysisConflict { .. })
    ));
    let mut foreign = scope.clone();
    foreign.identity.tenant_id = [99; 16];
    assert!(fixture
        .store
        .mark_graph_notice(&foreign, id, receipt.commit_revision, notice + 2, 1)
        .is_err());
    assert_eq!(
        fixture
            .store
            .graph_notice(&foreign, id, receipt.commit_revision)?,
        None
    );
    assert_eq!(frozen(&fixture.store, id)?, bytes);
    assert_eq!(usage(&fixture.store, tenant)?, quota);
    assert_eq!(fixture.store.meta()?, meta);
    assert_eq!(fixture.store.processor_health(scope)?, health);
    assert_eq!(fixture.store.processor_result(scope)?, head);
    assert_eq!(fixture.store.commit_graph(&fixture.request, true)?, receipt);
    let mut changed = fixture.request.clone();
    changed.created_utc_ns += 1;
    assert!(matches!(
        fixture.store.commit_graph(&changed, true),
        Err(araphor_data::Error::AnalysisConflict { .. })
    ));
    assert_eq!(
        fixture.owner.installed_refs(tenant, id)?,
        Some(references.clone())
    );
    let CommitFixture {
        directory,
        owner,
        store,
        request,
        snapshot,
    } = fixture;
    drop(owner);
    drop(store);
    let store = Arc::new(AnalysisStore::open(directory.path().join("analysis"))?);
    assert_eq!(frozen(&store, &request.result_id)?, bytes);
    assert_eq!(usage(&store, tenant)?, quota);
    assert_eq!(store.meta()?, meta);
    assert_eq!(store.processor_health(&request.scope)?, health);
    assert_eq!(store.processor_result(&request.scope)?, head);
    assert_eq!(store.commit_graph(&request, true)?, receipt);
    assert_eq!(
        store.graph_notice(&request.scope, &request.result_id, receipt.commit_revision)?,
        Some((notice + 1, 1))
    );
    let owner = crate::GraphAndFindingOwner::new(
        store.clone(),
        Arc::new(NoFacts),
        crate::InstalledAnalysis::testing(Some(store.clone()), tenant)?,
    )?;
    assert_eq!(
        owner.snapshot_result(tenant, &request.result_id)?,
        Some(snapshot)
    );
    assert_eq!(
        owner.installed_refs(tenant, &request.result_id)?,
        Some(references)
    );
    Ok(())
}

#[test]
fn graph_notice_rejects_replacement() -> TestResult {
    let fixture = CommitFixture::new()?;
    let first = fixture.store.commit_graph(&fixture.request, true)?;
    let mut replacement = fixture.request.clone();
    replacement.result_id = "graph:notice-replacement".into();
    replacement.expected_cursor = 1;
    replacement.created_utc_ns += 1;
    let second = fixture.store.commit_graph(&replacement, false)?;
    assert!(second.commit_revision > first.commit_revision);
    assert_eq!(
        fixture.store.graph_notice(
            &fixture.request.scope,
            &fixture.request.result_id,
            first.commit_revision
        )?,
        None
    );
    assert!(matches!(
        fixture.store.mark_graph_notice(
            &fixture.request.scope,
            &fixture.request.result_id,
            first.commit_revision,
            1,
            1
        ),
        Err(araphor_data::Error::AnalysisConflict { .. })
    ));
    assert_eq!(
        fixture.store.graph_notice(
            &replacement.scope,
            &replacement.result_id,
            second.commit_revision
        )?,
        Some((fixture.snapshot.context_notice_revision, 1))
    );
    assert_eq!(fixture.store.commit_graph(&fixture.request, true)?, first);
    Ok(())
}

#[test]
fn graph_notice_separates_windows() -> TestResult {
    let fixture = CommitFixture::new()?;
    let first = fixture.store.commit_graph(&fixture.request, true)?;
    let (_, mut window) = fixture.next_window()?;
    let second = fixture.store.commit_graph(&window, true)?;
    fixture.store.mark_graph_notice(
        &fixture.request.scope,
        &fixture.request.result_id,
        first.commit_revision,
        1,
        2,
    )?;
    assert_eq!(
        fixture.store.graph_notice(
            &fixture.request.scope,
            &fixture.request.result_id,
            first.commit_revision
        )?,
        Some((1, 2))
    );
    assert_eq!(
        fixture
            .store
            .graph_notice(&window.scope, &window.result_id, second.commit_revision)?,
        Some((0, 2))
    );
    let old_id = window.result_id.clone();
    window.result_id = "graph:notice-second-window-replacement".into();
    window.expected_cursor = 2;
    window.created_utc_ns += 1;
    let replacement = fixture.store.commit_graph(&window, false)?;
    assert!(replacement.commit_revision > second.commit_revision);
    assert!(matches!(
        fixture
            .store
            .mark_graph_notice(&window.scope, &old_id, second.commit_revision, 1, 2),
        Err(araphor_data::Error::AnalysisConflict { .. })
    ));
    fixture.store.mark_graph_notice(
        &fixture.request.scope,
        &fixture.request.result_id,
        first.commit_revision,
        2,
        2,
    )?;
    assert_eq!(
        fixture.store.graph_notice(
            &fixture.request.scope,
            &fixture.request.result_id,
            first.commit_revision
        )?,
        Some((2, 2))
    );
    assert_eq!(
        fixture
            .store
            .read_result(window.scope.identity.tenant_id, &fixture.request.result_id)?,
        Some(fixture.request.body.clone())
    );
    Ok(())
}
