use super::*;
use crate::{
    BehaviorSnapshotV1, DiscoveryProofKindV1, EvidenceIntakeIdentityV1, ProcessorClassV1,
    ProcessorScopeV1, ValidatedEvidenceBatchV1, DISCOVERY_PROCESSOR, DISCOVERY_SCHEMA_VERSION,
};

type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;

mod contexts;
mod gaps;
mod native;
mod state;

fn profile() -> DiscoveryProfileV1 {
    DiscoveryProfileV1 {
        schema_version: DISCOVERY_SCHEMA_VERSION,
        scope: ProcessorScopeV1 {
            processor_id: DISCOVERY_PROCESSOR.into(),
            method_version: DISCOVERY_SCHEMA_VERSION.into(),
            identity: EvidenceIntakeIdentityV1 {
                tenant_id: [1; 16],
                node_id: "node-a".into(),
                node_boot_id: [2; 16],
                label_epoch: 1,
                source_id: [3; 16],
                source_epoch: 1,
            },
        },
        profile_id: "profile-a".into(),
        interval_id: "interval-a".into(),
        revision: 1,
        facts_revision: 0,
        coverage_revision: 0,
        created_utc_ns: 10,
        updated_utc_ns: 10,
        sealed: false,
        input_bytes: 0,
        incomplete: false,
        gaps: Vec::new(),
        snapshot: BehaviorSnapshotV1 {
            schema_version: DISCOVERY_SCHEMA_VERSION,
            tenant_id: [1; 16],
            source_revision: "live-v1".into(),
            proof_kind: DiscoveryProofKindV1::ObservedRuntime,
            accepted_records: 0,
            included_records: 0,
            unresolved_records: 0,
            excluded_records: 0,
            coverage: Vec::new(),
            atoms: Vec::new(),
            unresolved: Vec::new(),
            excluded: Vec::new(),
            lifecycle: crate::DiscoveryLifecycleCaseV1::ALL
                .into_iter()
                .map(|case| crate::DiscoveryLifecycleEntryV1 {
                    case,
                    state: crate::DiscoveryLifecycleStateV1::Missing,
                })
                .collect(),
        },
        context_refs: Vec::new(),
    }
}

fn commit(profile: &DiscoveryProfileV1) -> AnalysisResultCommitV1 {
    AnalysisResultCommitV1 {
        scope: profile.scope.clone(),
        expected_cursor: 0,
        consumed_cursor: 0,
        coverage_revision: profile.coverage_revision,
        context_revision: 0,
        result_id: profile.profile_id.clone(),
        body: Vec::new(),
        created_utc_ns: profile.updated_utc_ns,
        witnesses: Vec::new(),
        context_refs: profile.context_refs.clone(),
    }
}

#[test]
fn profile_guard_rolls_back() -> TestResult {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("data");
    let store = AnalysisStore::open(&root)?;
    let mut profile = profile();
    store.accept_validated_batch(
        profile.scope.identity.clone(),
        ValidatedEvidenceBatchV1 {
            cpu_id: 0,
            first_cursor: 1,
            last_cursor: 1,
            intake_utc_ns: 1,
            framed_records: b"frame".to_vec().into(),
            frame_ends: vec![5],
        },
    )?;
    store.register_processor(&profile.scope, ProcessorClassV1::Optional, 1)?;
    let mut selected = crate::AnalysisSelectionV1::new(
        profile.scope.identity.tenant_id,
        vec![profile.scope.identity.clone()],
    );
    selected.select_profiles(crate::Selection::All)?;
    let mut previous = None;
    let mut notices = store.subscribe_revision();
    for revision in 1..=2 {
        profile.revision = revision;
        profile.updated_utc_ns = 10 + revision;
        let before = store.meta()?;
        let head = store.processor_result(&profile.scope)?;
        let control = std::sync::Arc::new(crate::AnalysisReadControl::default());
        control.check()?;
        let cancelled = std::sync::Arc::clone(&control);
        store.set_commit_hook(crate::AnalysisCommitStage::BeforeResultCommit, move || {
            cancelled.cancel()
        })?;
        assert!(matches!(
            store.commit_working_profile_guarded(
                commit(&profile),
                PreparedProfile::new(profile.clone())?,
                previous,
                || control.check()
            ),
            Err(crate::Error::AnalysisReadCancelled { .. })
        ));
        assert_eq!(store.meta()?, before);
        assert_eq!(store.processor_result(&profile.scope)?, head);
        assert!(!notices.has_changed()?);
        let receipt = store.commit_working_profile_guarded(
            commit(&profile),
            PreparedProfile::new(profile.clone())?,
            previous,
            || Ok(()),
        )?;
        assert_eq!(
            store.dependency_revision(&selected, &crate::AnalysisReadControl::default())?,
            (store.meta()?, receipt.commit_revision)
        );
        previous = Some(receipt.commit_revision);
        notices.borrow_and_update();
        let committed = store.meta()?;
        assert!(matches!(
            store.commit_working_profile_guarded(
                commit(&profile),
                PreparedProfile::new(profile.clone())?,
                previous,
                || control.check()
            ),
            Err(crate::Error::AnalysisReadCancelled { .. })
        ));
        assert_eq!(store.meta()?, committed);
        assert!(!notices.has_changed()?);
    }
    let head = store.processor_result(&profile.scope)?;
    drop(store);
    assert_eq!(
        AnalysisStore::open(root)?.processor_result(&profile.scope)?,
        head
    );
    Ok(())
}

#[test]
fn profile_handoff_matches_bytes() -> TestResult {
    let directory = tempfile::tempdir()?;
    let mut results = Vec::new();
    for typed in [false, true] {
        let root = directory.path().join(if typed { "typed" } else { "bytes" });
        let store = AnalysisStore::open(&root)?;
        let mut profile = profile();
        store.accept_validated_batch(
            profile.scope.identity.clone(),
            ValidatedEvidenceBatchV1 {
                cpu_id: 0,
                first_cursor: 1,
                last_cursor: 1,
                intake_utc_ns: 1,
                framed_records: b"frame".to_vec().into(),
                frame_ends: vec![5],
            },
        )?;
        store.register_processor(&profile.scope, ProcessorClassV1::Optional, 1)?;
        let mut previous = None;
        let mut receipts = Vec::new();
        for step in 0..3 {
            profile.revision = step + 1;
            profile.updated_utc_ns = 10 + step;
            profile.sealed = step == 2;
            if profile.sealed {
                profile.profile_id = "profile-history".into();
            }
            let mut input = commit(&profile);
            let bytes = serde_json::to_vec(&profile)?;
            let receipt = if typed {
                let prepared = PreparedProfile::new(profile.clone())?;
                assert_eq!(prepared.body, bytes);
                if profile.sealed {
                    store.commit_sealed_profile(input.clone(), prepared)?
                } else {
                    store.commit_working_profile(input.clone(), prepared, previous)?
                }
            } else {
                input.body = bytes.clone();
                if profile.sealed {
                    store.commit_profile(&input)?
                } else {
                    store.commit_working(&input, previous)?
                }
            };
            let revision = store.meta()?.commit_revision;
            if profile.sealed {
                let retry = if typed {
                    store.commit_sealed_profile(
                        input.clone(),
                        PreparedProfile::new(profile.clone())?,
                    )?
                } else {
                    store.commit_profile(&input)?
                };
                assert_eq!(retry, receipt);
                assert_eq!(store.meta()?.commit_revision, revision);
            } else {
                previous = Some(receipt.commit_revision);
            }
            let (request, body): (Vec<u8>, Vec<u8>) = store.reader()?.get()?.query_row(
                "SELECT request_meta, body FROM analysis_results WHERE result_id = ?",
                duckdb::params![profile.profile_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )?;
            assert_eq!(request, input.request_meta()?);
            assert_eq!(body, bytes);
            receipts.push(receipt);
        }
        let head = store.processor_result(&profile.scope)?;
        assert_eq!(
            head.as_ref().map(|head| head.result_id.as_str()),
            Some("profile-a")
        );
        let revision = store.meta()?.commit_revision;
        drop(store);
        let reopened = AnalysisStore::open(&root)?;
        assert_eq!(reopened.processor_result(&profile.scope)?, head);
        assert_eq!(reopened.meta()?.commit_revision, revision);
        assert_eq!(
            reopened.read_result(profile.scope.identity.tenant_id, &profile.profile_id)?,
            Some(serde_json::to_vec(&profile)?)
        );
        results.push((receipts, head, revision));
    }
    assert_eq!(results[0], results[1]);
    Ok(())
}

#[test]
fn profile_handoff_rejects_mismatches() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = AnalysisStore::open(directory.path().join("data"))?;
    let mut profile = profile();
    let original = commit(&profile);
    let revision = store.meta()?.commit_revision;
    for field in 0..5 {
        let mut input = original.clone();
        match field {
            0 => input.scope.identity.tenant_id = [9; 16],
            1 => input.result_id.push('x'),
            2 => input.coverage_revision += 1,
            3 => input.body = b"independent".to_vec(),
            _ => input.scope.processor_id = "different".into(),
        }
        assert!(store
            .commit_working_profile(input, PreparedProfile::new(profile.clone())?, None)
            .is_err());
        assert_eq!(store.meta()?.commit_revision, revision);
    }
    assert!(store
        .commit_sealed_profile(original.clone(), PreparedProfile::new(profile.clone())?)
        .is_err());
    profile.sealed = true;
    let mut advancing = original;
    advancing.consumed_cursor = 1;
    assert!(store
        .commit_sealed_profile(advancing, PreparedProfile::new(profile.clone())?)
        .is_err());
    profile.snapshot.tenant_id = [9; 16];
    assert!(PreparedProfile::new(profile).is_err());
    assert_eq!(store.meta()?.commit_revision, revision);
    Ok(())
}
