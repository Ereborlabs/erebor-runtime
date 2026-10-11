use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

use super::*;

#[derive(Default)]
pub(super) struct NoticeInputs {
    facts: Inputs,
    pub(super) revision: AtomicU64,
    pub(super) calls: AtomicUsize,
    advance: AtomicBool,
}

impl GraphContextProvider for NoticeInputs {
    fn facts(&self, record: &DiscoveryRecordV1) -> Result<Vec<AnalysisContextVersionV1>> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if self.advance.swap(false, Ordering::SeqCst) {
            self.revision.fetch_add(1, Ordering::SeqCst);
        }
        self.facts.facts(record)
    }

    fn revision(&self, _source: &EvidenceIntakeIdentityV1) -> Result<u64> {
        Ok(self.revision.load(Ordering::SeqCst))
    }
}

#[test]
fn graph_notice_stays_pending() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = Arc::new(AnalysisStore::open(directory.path().join("analysis"))?);
    let provider = Arc::new(NoticeInputs::default());
    let owner = GraphAndFindingOwner::new(
        store.clone(),
        provider.clone(),
        InstalledAnalysis::testing(Some(store.clone()), source().tenant_id)?,
    )?;
    let observation = record(1, &wire(1, DeniedBeforeEffect, 2, 2, [20; 16]))?;
    accept(&store, &[observation])?;
    coverage(&store, 1, 1, "HEALTHY")?;
    assert_eq!(owner.process(10)?, 1);
    let head = store
        .processor_result(&GraphAndFindingOwner::scope(&source()))?
        .ok_or("head")?;
    let frozen = store.read_result(source().tenant_id, &head.result_id)?;
    let meta = store.meta()?;
    provider.revision.store(1, Ordering::SeqCst);
    provider.advance.store(true, Ordering::SeqCst);
    assert!(!owner.refresh(&source(), 11)?);
    assert_eq!(provider.revision.load(Ordering::SeqCst), 2);
    assert_eq!(provider.calls.load(Ordering::SeqCst), 2);
    assert_eq!(
        store.graph_notice(
            &GraphAndFindingOwner::scope(&source()),
            &head.result_id,
            head.commit_revision
        )?,
        Some((1, 1))
    );
    assert_eq!(owner.process(12)?, 0);
    assert_eq!(owner.process(12)?, 0);
    assert_eq!(provider.calls.load(Ordering::SeqCst), 3);
    assert_eq!(owner.process(13)?, 0);
    assert_eq!(owner.process(13)?, 0);
    assert_eq!(provider.calls.load(Ordering::SeqCst), 3);
    assert_eq!(
        store.read_result(source().tenant_id, &head.result_id)?,
        frozen
    );
    assert_eq!(store.meta()?, meta);
    Ok(())
}

#[test]
fn graph_notice_checks_once() -> TestResult {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("analysis");
    let store = Arc::new(AnalysisStore::open(&root)?);
    let provider = Arc::new(NoticeInputs::default());
    let owner = GraphAndFindingOwner::new(
        store.clone(),
        provider.clone(),
        InstalledAnalysis::testing(Some(store.clone()), source().tenant_id)?,
    )?;
    let observation = record(1, &wire(1, DeniedBeforeEffect, 2, 2, [20; 16]))?;
    accept(&store, std::slice::from_ref(&observation))?;
    coverage(&store, 1, 1, "HEALTHY")?;
    assert_eq!(owner.process(10)?, 1);
    assert_eq!(provider.calls.load(Ordering::SeqCst), 1);
    let original = owner.current_findings(source().tenant_id)?;
    let id = &original[0].0;
    let snapshot = owner
        .snapshot_result(source().tenant_id, id)?
        .ok_or("graph snapshot")?;
    let bytes = store
        .read_result(source().tenant_id, id)?
        .ok_or("graph body")?;
    let references = owner
        .installed_refs(source().tenant_id, id)?
        .ok_or("installed refs")?;
    assert_eq!(references.len(), 3);
    assert_eq!(
        references
            .iter()
            .map(|reference| reference.package_id.as_str())
            .collect::<std::collections::BTreeSet<_>>(),
        std::collections::BTreeSet::from(["HF-PROC-001", "HF-DW-001", "HF-XNODE-001"])
    );
    let meta = store.meta()?;
    let health = store.processor_health(&snapshot.scope)?;
    provider.revision.store(1, Ordering::SeqCst);
    assert_eq!(owner.process(11)?, 0);
    assert_eq!(owner.process(11)?, 0);
    assert_eq!(provider.calls.load(Ordering::SeqCst), 2);
    assert_eq!(owner.process(12)?, 0);
    assert_eq!(owner.process(12)?, 0);
    assert_eq!(provider.calls.load(Ordering::SeqCst), 2);
    assert_eq!(owner.current_findings(source().tenant_id)?, original);
    assert_eq!(
        store.read_result(source().tenant_id, id)?,
        Some(bytes.clone())
    );
    assert_eq!(store.meta()?, meta);
    assert_eq!(store.processor_health(&snapshot.scope)?, health);
    drop(owner);
    drop(store);
    let store = Arc::new(AnalysisStore::open(&root)?);
    let owner = GraphAndFindingOwner::new(
        store.clone(),
        provider.clone(),
        InstalledAnalysis::testing(Some(store.clone()), source().tenant_id)?,
    )?;
    assert_eq!(owner.process(20)?, 0);
    assert_eq!(provider.calls.load(Ordering::SeqCst), 2);
    assert_eq!(
        owner.snapshot_result(source().tenant_id, id)?,
        Some(snapshot.clone())
    );
    assert_eq!(
        owner.installed_refs(source().tenant_id, id)?,
        Some(references)
    );
    assert!(!owner.refresh(&source(), 21)?);
    assert_eq!(provider.calls.load(Ordering::SeqCst), 3);
    provider
        .facts
        .0
        .lock()
        .map_err(|_| "fixture facts")?
        .extend([policy(&observation, 1)?, activation(&observation)?]);
    provider.revision.store(2, Ordering::SeqCst);
    assert_eq!(owner.process(22)?, 0);
    assert_eq!(owner.process(22)?, 1);
    assert_eq!(provider.calls.load(Ordering::SeqCst), 4);
    let current = owner.current_findings(source().tenant_id)?;
    assert_ne!(current[0].0, *id);
    let replacement = owner
        .snapshot_result(source().tenant_id, &current[0].0)?
        .ok_or("replacement")?;
    assert_eq!(replacement.previous_result_id.as_ref(), Some(id));
    assert_eq!(
        replacement.witness_deadline_utc_ns,
        snapshot.witness_deadline_utc_ns
    );
    assert_eq!(store.read_result(source().tenant_id, id)?, Some(bytes));
    let expiry = snapshot.witness_deadline_utc_ns + 1;
    assert_eq!(owner.process(expiry)?, 0);
    assert_eq!(owner.process(expiry)?, 1);
    assert_eq!(provider.calls.load(Ordering::SeqCst), 4);
    assert!(owner
        .current_findings(source().tenant_id)?
        .iter()
        .all(|(_, finding)| {
            finding.state == FindingStateV1::CoverageInsufficient
                && finding
                    .limits
                    .iter()
                    .any(|limit| limit == "RETAINED_INPUT_EXPIRED")
        }));
    Ok(())
}
