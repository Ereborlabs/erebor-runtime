use super::*;
use crate::{EvidenceRecord, ProcessorScopeV1, ValidatedEvidenceBatchV1};

type TestResult<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

fn identity(tenant: u8, node: &str, source: u8) -> EvidenceIntakeIdentityV1 {
    EvidenceIntakeIdentityV1 {
        tenant_id: [tenant; 16],
        node_id: node.into(),
        node_boot_id: [tenant; 16],
        source_id: [source; 16],
        ..crate::analysis::tests::identity()
    }
}

fn accept(store: &AnalysisStore, source: &EvidenceIntakeIdentityV1, cursor: u64) -> TestResult {
    let frame = Vec::<u8>::try_from(&EvidenceRecord {
        observed_boottime_ns: cursor,
        ..Default::default()
    })?;
    store.accept_validated_batch(
        source.clone(),
        ValidatedEvidenceBatchV1 {
            cpu_id: 0,
            first_cursor: cursor,
            last_cursor: cursor,
            intake_utc_ns: cursor,
            frame_ends: vec![frame.len()],
            framed_records: frame.into(),
        },
    )?;
    Ok(())
}

fn registered(store: &AnalysisStore, source: &EvidenceIntakeIdentityV1) -> TestResult<bool> {
    Ok(store
        .processor_health(&ProcessorScopeV1 {
            processor_id: crate::GRAPH_PROCESSOR.into(),
            method_version: u64::from(crate::GRAPH_SCHEMA_VERSION),
            identity: source.clone(),
        })?
        .is_some())
}

#[test]
fn interest_limits_future_registration() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = Arc::new(AnalysisStore::open(directory.path().join("data"))?);
    let first = identity(1, "node-a", 1);
    let second = identity(2, "node-b", 2);
    let mut all_node = AnalysisSelectionV1::tenant(first.tenant_id);
    all_node.nodes = vec![first.node_id.clone()];
    let exact = AnalysisSelectionV1::new(second.tenant_id, vec![second.clone()]);
    let _lease = store.lease_graph(vec![all_node, exact])?;
    for source in [&first, &second] {
        accept(&store, source, 1)?;
        assert!(registered(&store, source)?);
    }
    for source in [
        identity(1, "node-b", 3),
        identity(2, "node-b", 4),
        identity(3, "node-a", 5),
    ] {
        accept(&store, &source, 1)?;
        assert!(!registered(&store, &source)?);
        assert_eq!(
            store
                .source_receipt(&source)?
                .ok_or("source receipt")?
                .contiguous_cursor,
            1
        );
    }
    assert!(store.graph_enabled());
    Ok(())
}

#[test]
fn interest_has_one_owner() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = Arc::new(AnalysisStore::open(directory.path().join("data"))?);
    let first = identity(1, "node-a", 1);
    let second = identity(2, "node-b", 2);
    let scope = AnalysisSelectionV1::new(first.tenant_id, vec![first.clone()]);
    let lease = store.lease_graph(vec![scope.clone()])?;
    let before = store.meta()?;
    assert!(store.lease_graph(vec![scope]).is_err());
    assert_eq!(store.meta()?, before);
    accept(&store, &first, 1)?;
    assert!(registered(&store, &first)?);
    let before = store.meta()?;
    store.register_graph(&first)?;
    assert_eq!(store.meta()?, before);
    drop(lease);
    assert!(!store.graph_enabled());
    assert!(registered(&store, &first)?);
    let _replacement = store.lease_graph(vec![AnalysisSelectionV1::new(
        second.tenant_id,
        vec![second.clone()],
    )])?;
    accept(&store, &second, 1)?;
    assert!(registered(&store, &second)?);
    let unrelated = identity(1, "node-a", 3);
    accept(&store, &unrelated, 1)?;
    assert!(!registered(&store, &unrelated)?);
    assert!(registered(&store, &first)?);
    Ok(())
}

#[test]
fn registration_checks_final_guard() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = Arc::new(AnalysisStore::open_with_limits(
        directory.path().join("data"),
        crate::RetentionLimitsV1 {
            raw_max_age_ns: Some(10),
            raw_max_bytes: None,
        },
        Default::default(),
    )?);
    let source = identity(1, "node-a", 1);
    accept(&store, &source, 1)?;
    let before = store.meta()?;
    let denied = || Err(crate::PackageErrorCodeV1::Denied.error("Graph registration"));
    assert!(store
        .register_graph_guarded(&source, before.commit_revision, denied)
        .is_err());
    assert_eq!(store.meta()?, before);
    assert!(!registered(&store, &source)?);
    assert_eq!(
        crate::EvidenceRetentionOwner::new(&store)
            .retain(&source, 100)?
            .removed_records,
        1
    );
    let floor = store
        .source_receipt(&source)?
        .ok_or("source floor")?
        .retained_floor;
    store.register_graph_guarded(&source, store.meta()?.commit_revision, || Ok(()))?;
    let scope = ProcessorScopeV1 {
        processor_id: crate::GRAPH_PROCESSOR.into(),
        method_version: u64::from(crate::GRAPH_SCHEMA_VERSION),
        identity: source.clone(),
    };
    assert_eq!(
        store
            .processor_health(&scope)?
            .ok_or("registered source")?
            .consumed_cursor,
        floor
    );
    let before = store.meta()?;
    assert!(store
        .register_graph_guarded(&source, before.commit_revision, denied)
        .is_err());
    assert_eq!(store.meta()?, before);
    assert!(registered(&store, &source)?);
    let captured = before.commit_revision;
    store.retire_required(&crate::ProcessorRetirementV1 {
        scope,
        change_id: "graph-registration-race".into(),
        reason: "Stop this required processor.".into(),
        expected_cursor: floor,
        cutoff_cursor: floor,
    })?;
    let retired = store.meta()?;
    assert!(!store.register_graph_guarded(&source, captured, || Ok(()))?);
    assert!(store
        .register_graph_guarded(&source, captured, denied)
        .is_err());
    assert!(store
        .register_graph_guarded(&source, retired.commit_revision, || Ok(()))
        .is_err());
    assert!(store.register_graph(&source).is_err());
    assert_eq!(store.meta()?, retired);
    let wrong = identity(1, "node-a", 2);
    accept(&store, &wrong, 1)?;
    let captured = store.meta()?.commit_revision;
    store.register_processor(
        &ProcessorScopeV1 {
            processor_id: crate::GRAPH_PROCESSOR.into(),
            method_version: u64::from(crate::GRAPH_SCHEMA_VERSION),
            identity: wrong.clone(),
        },
        crate::ProcessorClassV1::Optional,
        1,
    )?;
    let before = store.meta()?;
    assert!(store
        .register_graph_guarded(&wrong, captured, || Ok(()))
        .is_err());
    assert!(store
        .register_graph_guarded(&source, retired.commit_revision, || Ok(()))
        .is_err());
    assert_eq!(store.meta()?, before);
    Ok(())
}

#[test]
fn interest_rejects_bad_scope() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = Arc::new(AnalysisStore::open(directory.path().join("data"))?);
    let before = store.meta()?;
    assert!(store.lease_graph(Vec::new()).is_err());
    assert!(store
        .lease_graph(vec![AnalysisSelectionV1::new(
            [1; 16],
            vec![identity(2, "node-a", 1)],
        )])
        .is_err());
    assert_eq!(store.meta()?, before);
    assert!(!store.graph_enabled());
    Ok(())
}

#[test]
fn scope_removal_keeps_others() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = Arc::new(AnalysisStore::open(directory.path().join("data"))?);
    let first = identity(1, "node-a", 1);
    let second = identity(2, "node-b", 2);
    let first_scope = AnalysisSelectionV1::tenant(first.tenant_id);
    let second_scope = AnalysisSelectionV1::tenant(second.tenant_id);
    let lease = store.lease_graph(vec![first_scope.clone(), second_scope.clone()])?;
    for source in [&first, &second] {
        accept(&store, source, 1)?;
        assert!(registered(&store, source)?);
    }
    let before = store.meta()?;
    lease.remove(&first_scope)?;
    lease.remove(&first_scope)?;
    assert_eq!(store.meta()?, before);
    assert!(store.graph_enabled());
    let excluded = identity(1, "node-a", 3);
    let included = identity(2, "node-b", 4);
    accept(&store, &excluded, 1)?;
    accept(&store, &included, 1)?;
    assert!(!registered(&store, &excluded)?);
    assert!(registered(&store, &included)?);
    lease.remove(&second_scope)?;
    assert!(!store.graph_enabled());
    assert!(store.lease_graph(vec![first_scope.clone()]).is_err());
    for source in [&first, &second, &included] {
        assert!(registered(&store, source)?);
    }
    drop(lease);
    let _replacement = store.lease_graph(vec![first_scope])?;
    let resumed = identity(1, "node-a", 5);
    accept(&store, &resumed, 1)?;
    assert!(registered(&store, &resumed)?);
    assert!(!registered(&store, &excluded)?);
    Ok(())
}

#[test]
fn required_rows_survive_restart() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("data");
    let store = Arc::new(AnalysisStore::open_with_limits(
        &path,
        crate::RetentionLimitsV1 {
            raw_max_age_ns: Some(10),
            raw_max_bytes: None,
        },
        Default::default(),
    )?);
    let source = identity(1, "node-a", 1);
    let lease = store.lease_graph(vec![AnalysisSelectionV1::tenant(source.tenant_id)])?;
    accept(&store, &source, 1)?;
    drop(lease);
    assert!(registered(&store, &source)?);
    assert_eq!(
        crate::EvidenceRetentionOwner::new(&store)
            .retain(&source, 100)?
            .removed_records,
        0
    );
    drop(store);
    let store = Arc::new(AnalysisStore::open_with_limits(
        &path,
        crate::RetentionLimitsV1 {
            raw_max_age_ns: Some(10),
            raw_max_bytes: None,
        },
        Default::default(),
    )?);
    assert!(!store.graph_enabled());
    assert!(registered(&store, &source)?);
    assert_eq!(
        crate::EvidenceRetentionOwner::new(&store)
            .retain(&source, 100)?
            .removed_records,
        0
    );
    let new_source = identity(1, "node-a", 2);
    accept(&store, &new_source, 1)?;
    assert!(!registered(&store, &new_source)?);
    let _lease = store.lease_graph(vec![AnalysisSelectionV1::tenant(source.tenant_id)])?;
    let next_source = identity(1, "node-a", 3);
    accept(&store, &next_source, 1)?;
    assert!(registered(&store, &next_source)?);
    Ok(())
}
