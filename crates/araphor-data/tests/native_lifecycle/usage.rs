use super::*;
use araphor_data::{
    AnalysisContextKeyV1, AnalysisContextRefV1, AnalysisContextVersionV1, ContextSensitivityV1,
};

fn context(tenant: u8, revision: u64) -> AnalysisContextVersionV1 {
    AnalysisContextVersionV1 {
        key: AnalysisContextKeyV1 {
            tenant_id: [tenant; 16],
            owner_id: "p".into(),
            entity_key: vec![1],
            lifetime_key: vec![1],
            owner_revision: revision,
        },
        valid_from_utc_ns: Some(1),
        valid_until_utc_ns: None,
        sensitivity: ContextSensitivityV1::Tenant,
        body: vec![1],
    }
}

#[test]
fn analysis_store_witness_usage() -> TestResult {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("analysis");
    let limits = RetentionLimitsV1 {
        raw_max_age_ns: Some(1),
        raw_max_bytes: None,
    };
    let store = AnalysisStore::open_with_retention(&root, limits)?;
    let identity = EvidenceIntakeIdentityV1 {
        node_id: "n".repeat(128),
        ..identity()
    };
    store.accept_validated_batch(
        identity.clone(),
        ValidatedEvidenceBatchV1 {
            cpu_id: 0,
            first_cursor: 1,
            last_cursor: 1,
            intake_utc_ns: 1,
            framed_records: b"frame".to_vec().into(),
            frame_ends: vec![5],
        },
    )?;
    let segments =
        std::fs::read_dir(root.join("segments"))?.collect::<std::io::Result<Vec<_>>>()?;
    assert_eq!(segments.len(), 1);
    let file_bytes = segments[0].metadata()?.len();
    let scope = ProcessorScopeV1 {
        processor_id: "p".into(),
        method_version: 1,
        identity: identity.clone(),
    };
    store.register_processor(&scope, ProcessorClassV1::Required, 1)?;
    let context = context(1, 1);
    let context_bytes = (context.body.len()
        + context.key.owner_id.len()
        + context.key.entity_key.len()
        + context.key.lifetime_key.len()) as u64;
    let context_revision = store.commit_context(&context)?;
    let input = AnalysisResultCommitV1 {
        context_revision,
        body: vec![1],
        created_utc_ns: 2,
        witnesses: vec![AnalysisWitnessV1 {
            identity: identity.into(),
            cursor: 1,
            expires_utc_ns: 100,
        }],
        context_refs: vec![AnalysisContextRefV1 {
            commit_revision: context_revision,
            key: context.key,
        }],
        result_id: "r".into(),
        ..result(&scope, 0, 1)
    };
    let witness_bytes = file_bytes + context_bytes;
    let receipt = store.commit_result(&input)?;
    assert_eq!(store.commit_result(&input)?, receipt);
    let mut second = input;
    second.expected_cursor = 1;
    second.result_id = "s".into();
    store.commit_result(&second)?;
    assert_eq!(store.read_result([1; 16], "s")?, Some(vec![1]));
    for (tenant, now, expected) in [
        (1_u8, 2_u64, witness_bytes),
        (1, 100, context_bytes),
        (2, 2, 0),
    ] {
        let usage = store.witness_usage([tenant; 16], now)?;
        assert_eq!(usage.charged_bytes, expected);
        assert_eq!(
            usage.context_bytes,
            if tenant == 1 { context_bytes } else { 0 }
        );
        assert_eq!(
            usage.referenced_bytes,
            if tenant == 1 && now < 100 { 5 } else { 0 }
        );
        assert_eq!(
            usage.segment_bytes + usage.context_bytes,
            usage.charged_bytes
        );
        assert_eq!(
            usage.referenced_bytes + usage.extra_segment_bytes,
            usage.segment_bytes
        );
    }
    let retention = araphor_data::EvidenceRetentionOwner::new(&store);
    assert_eq!(
        retention.retain(&second.scope.identity, 3)?.removed_records,
        0
    );
    assert_eq!(
        retention
            .retain(&second.scope.identity, 101)?
            .removed_records,
        1
    );
    assert_eq!(store.read_result([1; 16], "s")?, Some(vec![1]));
    let meta = store.meta()?;
    store.checkpoint()?;
    assert_eq!(store.meta()?, meta);
    drop(store);
    let store = AnalysisStore::open_with_retention(&root, limits)?;
    assert_eq!(store.read_result([1; 16], "s")?, Some(vec![1]));
    assert_eq!(store.meta()?, meta);
    assert_eq!(
        store.witness_usage([1; 16], 101)?.context_bytes,
        context_bytes
    );
    Ok(())
}

#[test]
fn analysis_witness_segment_cost() -> TestResult {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("analysis");
    let limits = RetentionLimitsV1 {
        raw_max_age_ns: Some(1),
        raw_max_bytes: Some(32 * 1024 * 1024),
    };
    let store = AnalysisStore::open_with_retention(&root, limits)?;
    let identity = EvidenceIntakeIdentityV1 {
        node_id: "n".into(),
        ..identity()
    };
    for group in 0..4 {
        store.accept_validated_batch(
            identity.clone(),
            ValidatedEvidenceBatchV1 {
                cpu_id: 0,
                first_cursor: group * 1024 + 1,
                last_cursor: (group + 1) * 1024,
                intake_utc_ns: 1,
                framed_records: vec![7; 4 * 1024 * 1024].into(),
                frame_ends: (1..=1024).map(|index| index * 4096 - index % 2).collect(),
            },
        )?;
    }
    let scope = ProcessorScopeV1 {
        processor_id: "p".into(),
        method_version: 1,
        identity: identity.clone(),
    };
    store.register_processor(&scope, ProcessorClassV1::Optional, 1)?;
    let mut input = AnalysisResultCommitV1 {
        consumed_cursor: 4096,
        body: vec![1],
        created_utc_ns: 2,
        witnesses: [1, 2, 3073, 4096]
            .into_iter()
            .map(|cursor| AnalysisWitnessV1 {
                identity: identity.clone().into(),
                cursor,
                expires_utc_ns: 100,
            })
            .collect(),
        result_id: "first".into(),
        ..result(&scope, 0, 4096)
    };
    store.commit_result(&input)?;
    let segment_bytes = std::fs::read_dir(root.join("segments"))?
        .try_fold(0_u64, |bytes, entry| {
            Ok::<_, std::io::Error>(bytes + entry?.metadata()?.len())
        })?;
    assert!(segment_bytes > 16 * 1024 * 1024);
    let before = store.meta()?;
    let usage = store.witness_usage(identity.tenant_id, 3)?;
    assert_eq!(usage.read_revision, before.commit_revision);
    assert_eq!(usage.referenced_bytes, 16 * 1024);
    assert_eq!(usage.segment_bytes, segment_bytes);
    assert_eq!(usage.extra_segment_bytes, segment_bytes - 16 * 1024);
    assert_eq!(usage.charged_bytes, segment_bytes);
    assert_eq!(usage.context_bytes, 0);
    assert_eq!(store.meta()?, before);
    assert_eq!(store.witness_usage([9; 16], 3)?.charged_bytes, 0);
    assert!(store.witness_usage([0; 16], 3).is_err());
    assert!(store.witness_usage(identity.tenant_id, 0).is_err());
    input.result_id = "second".into();
    input.expected_cursor = 4096;
    input
        .witnesses
        .retain(|witness| matches!(witness.cursor, 1 | 4096));
    for witness in &mut input.witnesses {
        witness.expires_utc_ns = 200;
    }
    store.commit_result(&input)?;
    let duplicate = store.witness_usage(identity.tenant_id, 3)?;
    assert_eq!(duplicate.referenced_bytes, usage.referenced_bytes);
    assert_eq!(duplicate.charged_bytes, usage.charged_bytes);
    let expired = store.witness_usage(identity.tenant_id, 100)?;
    assert_eq!(expired.referenced_bytes, 8192);
    assert_eq!(expired.segment_bytes, segment_bytes);
    drop(store);
    let store = AnalysisStore::open_with_retention(&root, limits)?;
    assert_eq!(store.witness_usage(identity.tenant_id, 100)?, expired);
    let owner = araphor_data::EvidenceRetentionOwner::new(&store);
    assert_eq!(owner.retain(&identity, 100)?.removed_records, 0);
    let cleared = owner.retain(&identity, 201)?;
    assert_eq!(cleared.removed_records, 4096);
    assert_eq!(cleared.retained_bytes, 0);
    assert_eq!(cleared.retained_floor, 4096);
    assert_eq!(owner.retain(&identity, 201)?.removed_records, 0);
    assert_eq!(
        store.witness_usage(identity.tenant_id, 201)?.charged_bytes,
        0
    );
    let meta = store.meta()?;
    store.checkpoint()?;
    assert_eq!(store.meta()?, meta);
    drop(store);
    let store = AnalysisStore::open_with_retention(&root, limits)?;
    assert_eq!(store.meta()?, meta);
    assert_eq!(
        store.witness_usage(identity.tenant_id, 201)?.charged_bytes,
        0
    );
    assert_eq!(store.read_result([1; 16], "first")?, Some(vec![1]));
    assert_eq!(store.read_result([1; 16], "second")?, Some(vec![1]));
    Ok(())
}
