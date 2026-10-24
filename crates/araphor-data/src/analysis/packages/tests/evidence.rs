use super::*;
use crate::{
    AnalysisContextKeyV1, AnalysisContextVersionV1, AnalysisResultCommitV1, AnalysisWitnessV1,
    ContextSensitivityV1, EvidenceIntakeIdentityV1, EvidenceRetentionOwner, ProcessorClassV1,
    ProcessorScopeV1, RetentionLimitsV1, ValidatedEvidenceBatchV1,
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
    for first in (1..=8193_u64).step_by(crate::EVIDENCE_BATCH_RECORDS) {
        let last = (first + crate::EVIDENCE_BATCH_RECORDS as u64 - 1).min(8193);
        let count = (last - first + 1) as usize;
        store.accept_validated_batch(
            identity.clone(),
            ValidatedEvidenceBatchV1 {
                cpu_id: 0,
                first_cursor: first,
                last_cursor: last,
                intake_utc_ns: 1,
                framed_records: b"record".repeat(count).into(),
                frame_ends: (1..=count).map(|count| count * 6).collect(),
            },
        )?;
    }
    let contexts = (0..257_u32)
        .map(|index| AnalysisContextVersionV1 {
            key: AnalysisContextKeyV1 {
                tenant_id: [1; 16],
                owner_id: "context".into(),
                entity_key: index.to_be_bytes().to_vec(),
                lifetime_key: b"lifetime".to_vec(),
                owner_revision: 1,
            },
            valid_from_utc_ns: Some(1),
            valid_until_utc_ns: None,
            sensitivity: ContextSensitivityV1::Tenant,
            body: b"context".to_vec(),
        })
        .collect::<Vec<_>>();
    let context_refs = store.commit_contexts(&contexts)?;
    let context_revision = context_refs.first().ok_or("context")?.commit_revision;
    let scope = ProcessorScopeV1 {
        processor_id: "source".into(),
        method_version: 1,
        identity: identity.clone(),
    };
    store.register_processor(&scope, ProcessorClassV1::Optional, 1)?;
    let witnesses = (1..=8193)
        .map(|cursor| AnalysisWitnessV1 {
            identity: identity.clone().into(),
            cursor,
            expires_utc_ns: 100,
        })
        .collect::<Vec<_>>();
    let native = store.commit_result(&AnalysisResultCommitV1 {
        scope,
        expected_cursor: 0,
        consumed_cursor: 8193,
        coverage_revision: 0,
        context_revision,
        result_id: "native".into(),
        body: b"result".to_vec(),
        created_utc_ns: 1,
        witnesses: witnesses.clone(),
        context_refs: context_refs.clone(),
    })?;
    let ids = vec!["native".to_owned()];
    let references = store.package_result_refs([1; 16], &ids)?;
    assert_eq!(references[0].commit_revision, native.commit_revision);
    assert!(store.package_result_refs([9; 16], &ids).is_err());
    assert_eq!(
        store.package_contexts(
            [1; 16],
            &contexts
                .iter()
                .map(|context| context.key.clone())
                .collect::<Vec<_>>()
        )?,
        context_refs
    );
    let evidence = store.package_evidence([1; 16], &ids)?;
    assert_eq!(evidence, (witnesses, context_refs));
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
        8193
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
