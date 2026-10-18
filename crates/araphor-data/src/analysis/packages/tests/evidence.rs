use super::*;
use crate::{
    AnalysisContextKeyV1, AnalysisContextRefV1, AnalysisContextVersionV1, AnalysisResultCommitV1,
    AnalysisWitnessV1, ContextSensitivityV1, EvidenceIntakeIdentityV1, EvidenceRetentionOwner,
    ProcessorClassV1, ProcessorScopeV1, RetentionLimitsV1, ValidatedEvidenceBatchV1,
};

#[test]
fn packages_preserve_native_references() -> TestResult {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("store");
    let retention = RetentionLimitsV1 {
        raw_max_age_ns: Some(1),
        raw_max_bytes: Some(1024 * 1024),
    };
    let store = AnalysisStore::open_with_limits(&root, retention, Default::default())?;
    let identity = EvidenceIntakeIdentityV1 {
        tenant_id: [1; 16],
        node_id: "node".into(),
        node_boot_id: [2; 16],
        label_epoch: 1,
        source_id: [3; 16],
        source_epoch: 1,
    };
    store.accept_validated_batch(
        identity.clone(),
        ValidatedEvidenceBatchV1 {
            cpu_id: 0,
            first_cursor: 1,
            last_cursor: 1,
            intake_utc_ns: 1,
            framed_records: b"record".to_vec().into(),
            frame_ends: vec![6],
        },
    )?;
    let context = AnalysisContextVersionV1 {
        key: AnalysisContextKeyV1 {
            tenant_id: [1; 16],
            owner_id: "context".into(),
            entity_key: b"entity".to_vec(),
            lifetime_key: b"lifetime".to_vec(),
            owner_revision: 1,
        },
        valid_from_utc_ns: Some(1),
        valid_until_utc_ns: None,
        sensitivity: ContextSensitivityV1::Tenant,
        body: b"context".to_vec(),
    };
    let context_revision = store.commit_context(&context)?;
    let scope = ProcessorScopeV1 {
        processor_id: "source".into(),
        method_version: 1,
        identity: identity.clone(),
    };
    store.register_processor(&scope, ProcessorClassV1::Optional, 1)?;
    let witness = AnalysisWitnessV1 {
        identity: identity.clone().into(),
        cursor: 1,
        expires_utc_ns: 100,
    };
    let context_ref = AnalysisContextRefV1 {
        key: context.key.clone(),
        commit_revision: context_revision,
    };
    let native = store.commit_result(&AnalysisResultCommitV1 {
        scope,
        expected_cursor: 0,
        consumed_cursor: 1,
        coverage_revision: 0,
        context_revision,
        result_id: "native".into(),
        body: b"result".to_vec(),
        created_utc_ns: 1,
        witnesses: vec![witness.clone()],
        context_refs: vec![context_ref.clone()],
    })?;
    let ids = vec!["native".to_owned()];
    let references = store.package_result_refs([1; 16], &ids)?;
    assert_eq!(references[0].commit_revision, native.commit_revision);
    assert!(store.package_result_refs([9; 16], &ids).is_err());
    assert_eq!(
        store.package_contexts([1; 16], &[context.key])?,
        vec![context_ref.clone()]
    );
    let evidence = store.package_evidence([1; 16], &ids)?;
    assert_eq!(evidence, (vec![witness], vec![context_ref]));
    let active = start(&store, "first")?;
    let mut input = commit(active, "derived");
    input.dependencies = references;
    input.witnesses = evidence.0;
    input.context_refs = evidence.1;
    input.created_utc_ns = 2;
    store.commit_package(&input, || Ok(()))?;
    assert_eq!(
        EvidenceRetentionOwner::new(&store)
            .retain(&identity, 3)?
            .removed_records,
        0
    );
    drop(store);
    let store = AnalysisStore::open_with_limits(&root, retention, Default::default())?;
    assert_eq!(
        store.package_evidence([1; 16], &["derived".into()])?,
        (input.witnesses.clone(), input.context_refs.clone())
    );
    assert_eq!(
        EvidenceRetentionOwner::new(&store)
            .retain(&identity, 101)?
            .removed_records,
        1
    );
    assert_eq!(
        store.package_evidence([1; 16], &["derived".into(), "native".into()])?,
        (input.witnesses.clone(), input.context_refs.clone())
    );
    drop(store);
    let store = AnalysisStore::open_with_limits(&root, retention, Default::default())?;
    assert_eq!(
        store.package_evidence([1; 16], &["derived".into()])?,
        (input.witnesses, input.context_refs)
    );
    Ok(())
}
