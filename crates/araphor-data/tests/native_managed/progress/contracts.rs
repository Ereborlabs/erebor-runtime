use super::*;
use araphor_data::{
    analysis::AnalysisStore, AnalysisContextKeyV1, AnalysisContextRefV1, AnalysisContextVersionV1,
    AnalysisProcessorResultV1, AnalysisWitnessV1, ContextSensitivityV1, EvidenceIntakeIdentityV1,
    EvidenceStoreOutcomeV1, ValidatedEvidenceBatchV1,
};

pub(super) fn result(scope: ProcessorScopeV1, result_id: String) -> AnalysisResultCommitV1 {
    AnalysisResultCommitV1 {
        scope,
        expected_cursor: 0,
        consumed_cursor: 1,
        coverage_revision: 0,
        context_revision: 0,
        result_id,
        body: b"finding".to_vec(),
        created_utc_ns: 100,
        witnesses: Vec::new(),
        context_refs: Vec::new(),
    }
}

fn identity(tenant: u8) -> EvidenceIntakeIdentityV1 {
    EvidenceIntakeIdentityV1 {
        tenant_id: [tenant; 16],
        ..super::scope().identity
    }
}

#[test]
fn registration_guard_rolls_back() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("analysis");
    let store = AnalysisStore::open(&root)?;
    let scope = ProcessorScopeV1 {
        processor_id: "guarded-processor".into(),
        method_version: 1,
        identity: identity(1),
    };
    let before = store.meta()?;
    let mut notices = store.subscribe_revision();
    let control = std::sync::Arc::new(araphor_data::AnalysisReadControl::default());
    control.check()?;
    let cancelled = std::sync::Arc::clone(&control);
    store.set_commit_hook(
        araphor_data::AnalysisCommitStage::BeforeResultCommit,
        move || cancelled.cancel(),
    )?;
    assert!(matches!(
        store.register_processor_guarded(&scope, ProcessorClassV1::Required, 1, || {
            control.check()
        }),
        Err(araphor_data::Error::AnalysisReadCancelled { .. })
    ));
    assert_eq!(store.meta()?, before);
    assert!(store.processor_health(&scope)?.is_none());
    assert!(!notices.has_changed()?);
    let revision =
        store.register_processor_guarded(&scope, ProcessorClassV1::Optional, 1, || Ok(()))?;
    assert!(revision > before.commit_revision);
    notices.borrow_and_update();
    let committed = store.meta()?;
    assert!(matches!(
        store.register_processor_guarded(&scope, ProcessorClassV1::Optional, 1, || {
            control.check()
        }),
        Err(araphor_data::Error::AnalysisReadCancelled { .. })
    ));
    assert_eq!(store.meta()?, committed);
    assert!(!notices.has_changed()?);
    let health = store.processor_health(&scope)?;
    drop(store);
    let reopened = AnalysisStore::open(root)?;
    assert_eq!(reopened.processor_health(&scope)?, health);
    assert_eq!(
        reopened.register_processor(&scope, ProcessorClassV1::Optional, 1)?,
        revision
    );
    assert_eq!(reopened.meta()?, committed);
    Ok(())
}

#[test]
fn optional_registration_preserves_state() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("analysis");
    let store = AnalysisStore::open(&root)?;
    let scope = ProcessorScopeV1 {
        processor_id: "existing-required".into(),
        method_version: 1,
        identity: identity(1),
    };
    store.accept_validated_batch(
        scope.identity.clone(),
        ValidatedEvidenceBatchV1 {
            cpu_id: 0,
            first_cursor: 1,
            last_cursor: 1,
            intake_utc_ns: 1,
            framed_records: b"frame".to_vec().into(),
            frame_ends: vec![5],
        },
    )?;
    let revision = store.register_processor(&scope, ProcessorClassV1::Required, 2)?;
    let health = store.processor_health(&scope)?;
    let before = store.meta()?;
    let mut notices = store.subscribe_revision();
    assert_eq!(
        store.ensure_optional_processor_guarded(&scope, || Ok(()))?,
        revision
    );
    assert_eq!(store.processor_health(&scope)?, health);
    assert_eq!(store.meta()?, before);
    assert!(!notices.has_changed()?);
    assert_eq!(
        store.register_processor(&scope, ProcessorClassV1::Required, 2)?,
        revision
    );
    assert!(matches!(
        store.register_processor(&scope, ProcessorClassV1::Optional, 1),
        Err(araphor_data::Error::AnalysisConflict { .. })
    ));
    let control = araphor_data::AnalysisReadControl::default();
    control.cancel()?;
    assert!(matches!(
        store.ensure_optional_processor_guarded(&scope, || control.check()),
        Err(araphor_data::Error::AnalysisReadCancelled { .. })
    ));
    assert_eq!(store.processor_health(&scope)?, health);
    assert_eq!(store.meta()?, before);
    assert!(!notices.has_changed()?);
    let missing = ProcessorScopeV1 {
        processor_id: "missing-optional".into(),
        ..scope.clone()
    };
    assert!(matches!(
        store.ensure_optional_processor_guarded(&missing, || control.check()),
        Err(araphor_data::Error::AnalysisReadCancelled { .. })
    ));
    assert!(store.processor_health(&missing)?.is_none());
    assert_eq!(store.meta()?, before);
    assert!(!notices.has_changed()?);
    let registered = store.ensure_optional_processor_guarded(&missing, || Ok(()))?;
    assert!(registered > revision);
    assert_eq!(
        store
            .processor_health(&missing)?
            .ok_or("optional registration absent")?
            .class,
        ProcessorClassV1::Optional
    );
    let committed = store.meta()?;
    notices.borrow_and_update();
    assert_eq!(
        store.ensure_optional_processor_guarded(&missing, || Ok(()))?,
        registered
    );
    assert_eq!(
        store.register_processor(&missing, ProcessorClassV1::Optional, 1)?,
        registered
    );
    assert_eq!(store.meta()?, committed);
    assert!(!notices.has_changed()?);
    store.retire_required(&araphor_data::ProcessorRetirementV1 {
        scope: scope.clone(),
        change_id: "retire-existing".into(),
        reason: "Stop this required processor.".into(),
        expected_cursor: 1,
        cutoff_cursor: 1,
    })?;
    let retired = store.meta()?;
    let retirement = store.processor_retirement(&scope)?;
    notices.borrow_and_update();
    assert!(matches!(
        store.ensure_optional_processor_guarded(&scope, || Ok(())),
        Err(araphor_data::Error::AnalysisConflict { .. })
    ));
    assert_eq!(store.meta()?, retired);
    assert_eq!(store.processor_retirement(&scope)?, retirement);
    assert!(!notices.has_changed()?);
    drop(store);
    let reopened = AnalysisStore::open(root)?;
    assert_eq!(reopened.processor_retirement(&scope)?, retirement);
    assert!(matches!(
        reopened.ensure_optional_processor_guarded(&scope, || Ok(())),
        Err(araphor_data::Error::AnalysisConflict { .. })
    ));
    Ok(())
}

#[test]
fn resume_guard_rolls_back() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("analysis");
    let limits = araphor_data::RetentionLimitsV1 {
        raw_max_age_ns: Some(1),
        raw_max_bytes: None,
    };
    let store = AnalysisStore::open_with_retention(&root, limits)?;
    let scope = ProcessorScopeV1 {
        processor_id: "guarded-processor".into(),
        method_version: 1,
        identity: identity(1),
    };
    store.accept_validated_batch(
        scope.identity.clone(),
        ValidatedEvidenceBatchV1 {
            cpu_id: 0,
            first_cursor: 1,
            last_cursor: 1,
            intake_utc_ns: 1,
            framed_records: b"frame".to_vec().into(),
            frame_ends: vec![5],
        },
    )?;
    store.register_processor(&scope, ProcessorClassV1::Optional, 1)?;
    assert_eq!(
        araphor_data::EvidenceRetentionOwner::new(&store)
            .step(100)?
            .removed_records,
        1
    );
    let before = store.meta()?;
    let health = store.processor_health(&scope)?;
    let mut notices = store.subscribe_revision();
    let control = std::sync::Arc::new(araphor_data::AnalysisReadControl::default());
    control.check()?;
    let cancelled = std::sync::Arc::clone(&control);
    store.set_commit_hook(
        araphor_data::AnalysisCommitStage::BeforeResultCommit,
        move || cancelled.cancel(),
    )?;
    assert!(matches!(
        store.resume_optional_guarded(&scope, || control.check()),
        Err(araphor_data::Error::AnalysisReadCancelled { .. })
    ));
    assert_eq!(store.meta()?, before);
    assert_eq!(store.processor_health(&scope)?, health);
    assert!(store.processor_gaps(&scope, 0)?.is_empty());
    assert!(!notices.has_changed()?);
    let gap = store
        .resume_optional_guarded(&scope, || Ok(()))?
        .ok_or("resume gap absent")?;
    assert_eq!((gap.first_cursor, gap.last_cursor), (1, 1));
    assert_eq!(store.processor_gaps(&scope, 0)?, [gap]);
    notices.borrow_and_update();
    let committed = store.meta()?;
    assert!(matches!(
        store.resume_optional_guarded(&scope, || control.check()),
        Err(araphor_data::Error::AnalysisReadCancelled { .. })
    ));
    assert_eq!(store.meta()?, committed);
    assert!(!notices.has_changed()?);
    drop(store);
    let reopened = AnalysisStore::open_with_retention(root, limits)?;
    assert_eq!(reopened.processor_gaps(&scope, 0)?, [gap]);
    assert_eq!(reopened.resume_optional(&scope)?, None);
    assert_eq!(reopened.meta()?, committed);
    Ok(())
}

#[test]
fn analysis_store_result_progress() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let store = AnalysisStore::open(directory.path().join("analysis"))?;
    let source = identity(1);
    let scope = ProcessorScopeV1 {
        processor_id: "security-file".into(),
        method_version: 1,
        identity: source.clone(),
    };
    assert_eq!(
        store.register_processor(&scope, ProcessorClassV1::Required, 1)?,
        1
    );
    assert_eq!(
        store.register_processor(&scope, ProcessorClassV1::Required, 1)?,
        1
    );
    assert!(matches!(
        store.register_processor(&scope, ProcessorClassV1::Optional, 1),
        Err(araphor_data::Error::AnalysisConflict { .. })
    ));
    assert_eq!(
        store.accept_validated_batch(
            source.clone(),
            ValidatedEvidenceBatchV1 {
                cpu_id: 0,
                first_cursor: 1,
                last_cursor: 1,
                intake_utc_ns: 1_000_000_000,
                framed_records: b"frame".to_vec().into(),
                frame_ends: vec![5],
            },
        )?,
        EvidenceStoreOutcomeV1::Accepted
    );
    let context = AnalysisContextVersionV1 {
        key: AnalysisContextKeyV1 {
            tenant_id: source.tenant_id,
            owner_id: "policy".into(),
            entity_key: b"workload".to_vec(),
            lifetime_key: b"pod".to_vec(),
            owner_revision: 1,
        },
        valid_from_utc_ns: Some(1),
        valid_until_utc_ns: None,
        sensitivity: ContextSensitivityV1::Tenant,
        body: b"verified-context".to_vec(),
    };
    let context_revision = store.commit_context(&context)?;
    let mut input = AnalysisResultCommitV1 {
        context_revision,
        body: b"result".to_vec(),
        created_utc_ns: 1_000_000_000,
        witnesses: vec![AnalysisWitnessV1 {
            identity: source.into(),
            cursor: 1,
            expires_utc_ns: 1_000_000_001,
        }],
        context_refs: vec![AnalysisContextRefV1 {
            key: context.key.clone(),
            commit_revision: context_revision,
        }],
        ..result(scope, "finding-1".into())
    };
    let mut invalid = input.clone();
    assert!(store.processor_result(&input.scope)?.is_none());
    invalid.body.clear();
    assert!(store.commit_result(&invalid).is_err());
    invalid = input.clone();
    invalid.context_refs[0].commit_revision = 0;
    let before = store.meta()?;
    assert!(matches!(
        store.commit_result(&invalid),
        Err(araphor_data::Error::AnalysisState { .. })
    ));
    assert_eq!(store.meta()?, before);
    let receipt = store.commit_result(&input)?;
    assert_eq!(receipt.commit_revision, 4);
    assert_eq!(receipt.consumed_cursor, 1);
    let head = AnalysisProcessorResultV1 {
        result_id: input.result_id.clone(),
        body: input.body.clone(),
        commit_revision: receipt.commit_revision,
    };
    assert_eq!(store.processor_result(&input.scope)?, Some(head.clone()));
    let mut foreign = input.scope.clone();
    foreign.identity.tenant_id = [4; 16];
    assert!(store.processor_result(&foreign)?.is_none());
    assert_eq!(
        store.read_result([1; 16], "finding-1")?,
        Some(b"result".to_vec())
    );
    assert_eq!(store.read_result([4; 16], "finding-1")?, None);
    assert_eq!(store.read_result([1; 16], "missing")?, None);
    assert_eq!(store.commit_result(&input)?, receipt);
    assert_eq!(store.meta()?.commit_revision, 4);
    let body_key = {
        #[derive(serde::Deserialize)]
        struct Saved {
            revision: u64,
            request: AnalysisResultCommitV1,
            producer: Option<araphor_data::analysis::PackageResultRefV1>,
            body_bytes: u64,
        }
        let view = store.view()?;
        let mut rows = view.snapshot().prefix(b"\0data/@progress/result/");
        let (key, bytes) = rows.next().ok_or("saved result")??;
        assert!(rows.next().is_none());
        assert_eq!(bytes.first(), Some(&0));
        assert_eq!(key.len(), b"\0data/@progress/result/".len() + 8);
        let saved: Saved = rmp_serde::from_slice(&bytes[1..])?;
        let mut expected = input.clone();
        expected.body.clear();
        assert_eq!(saved.request, expected);
        assert_eq!(saved.revision, receipt.commit_revision);
        assert!(saved.producer.is_none());
        assert_eq!(saved.body_bytes, input.body.len() as u64);
        let body_key = [b"\0data/@progress/body/".as_slice(), &key[key.len() - 8..]].concat();
        let bytes = view.snapshot().get(&body_key)?.ok_or("saved body")?;
        assert_eq!(bytes.first(), Some(&0));
        assert_eq!(&bytes[1..], input.body);
        body_key
    };
    for change in 0..16 {
        let mut changed = input.clone();
        match change {
            0 => changed.scope.processor_id.push('x'),
            1 => changed.scope.method_version += 1,
            2 => changed.scope.identity.node_id.push('x'),
            3 => changed.expected_cursor += 1,
            4 => changed.consumed_cursor += 1,
            5 => changed.coverage_revision += 1,
            6 => changed.context_revision += 1,
            7 => changed.body.push(0),
            8 => changed.created_utc_ns += 1,
            9 => changed.witnesses[0].expires_utc_ns += 1,
            10 => changed.witnesses[0].cursor += 1,
            11 => changed.witnesses.clear(),
            12 => changed.context_refs[0].commit_revision += 1,
            13 => changed.context_refs[0].key.owner_revision += 1,
            14 => changed.context_refs.clear(),
            _ => {
                changed.scope.identity.tenant_id = [4; 16];
                changed.witnesses.clear();
                changed.context_refs.clear();
            }
        }
        assert!(
            matches!(
                store.commit_result(&changed),
                Err(araphor_data::Error::AnalysisConflict { .. })
            ),
            "changed request component {change}"
        );
        assert_eq!(store.meta()?.commit_revision, 4);
    }
    let path = directory.path().join("analysis");
    drop(store);
    let store = AnalysisStore::open(path)?;
    assert_eq!(store.processor_result(&input.scope)?, Some(head));
    assert_eq!(store.commit_result(&input)?, receipt);
    input.result_id = "finding-2".into();
    assert!(matches!(
        store.commit_result(&input),
        Err(araphor_data::Error::AnalysisConflict { .. })
    ));
    assert_eq!(store.meta()?.commit_revision, 4);
    input.expected_cursor = 1;
    input.context_refs[0].commit_revision += 1;
    assert!(store.commit_result(&input).is_err());
    input.context_refs[0].commit_revision -= 1;
    input.witnesses[0].identity = identity(4).into();
    assert!(store.commit_result(&input).is_err());
    assert_eq!(store.meta()?.commit_revision, 4);
    let mut tx = store.write()?;
    tx.native().insert(body_key, [0]);
    tx.commit([])?;
    assert!(matches!(
        store.read_result([1; 16], "finding-1"),
        Err(araphor_data::Error::Package {
            code: Code::Invalid,
            field: "processor result body length",
            ..
        })
    ));
    Ok(())
}

#[test]
fn observability_recovery_mixed_witnesses() -> std::result::Result<(), Box<dyn std::error::Error>> {
    use araphor_data::{
        AnalysisReadControl, EvidenceRetentionOwner, RetentionLimitsV1, TraceBatchV1,
        TraceBindingV1, TraceCleanupV1, TraceFrameKindV1, TraceFrameV1, TraceIdentityV1,
        TraceIntentV1, TraceSourceV1, TraceTerminalReasonV1, TraceTerminalV1,
    };

    let directory = tempfile::tempdir()?;
    let root = directory.path().join("analysis");
    let limits = RetentionLimitsV1 {
        raw_max_age_ns: Some(100),
        raw_max_bytes: Some(64 * 1024 * 1024),
    };
    let store = AnalysisStore::open_with_retention(&root, limits)?;
    let evidence = identity(1);
    store.accept_validated_batch(
        evidence.clone(),
        ValidatedEvidenceBatchV1 {
            cpu_id: 0,
            first_cursor: 1,
            last_cursor: 1,
            intake_utc_ns: 100,
            framed_records: b"event".to_vec().into(),
            frame_ends: vec![5],
        },
    )?;
    let scope = ProcessorScopeV1 {
        processor_id: "mixed-witness".into(),
        method_version: 1,
        identity: evidence.clone(),
    };
    store.register_processor(&scope, ProcessorClassV1::Optional, 1)?;
    let source = TraceSourceV1::new(b"BEGIN { @x = count(); }".to_vec())?;
    let diagnostic = TraceIdentityV1 {
        tenant_id: [1; 16],
        node_id: "node-a".into(),
        node_boot_id: [2; 16],
        request_id: [7; 16],
        execution_id: [8; 16],
        source_sha256: source.sha256,
    };
    store.accept_trace(&TraceIntentV1 {
        tenant_id: [1; 16],
        request_id: diagnostic.request_id,
        source,
        bindings: vec![TraceBindingV1 {
            binding_id: [9; 16],
            identity: diagnostic.clone(),
            namespace_uid: "namespace-a".into(),
        }],
        authority: b"Control-owned inputs".to_vec(),
        accepted_unix_ns: 100,
        deadline_unix_ns: 1_000_000_000,
        host_sensitive: true,
    })?;
    let frame = TraceFrameV1 {
        execution_id: diagnostic.execution_id,
        sequence: 1,
        kind: TraceFrameKindV1::Data,
        bytes: b"raw\n".to_vec(),
    };
    let terminal = TraceTerminalV1 {
        execution_id: diagnostic.execution_id,
        reason: TraceTerminalReasonV1::Completed,
        last_sequence: 1,
        output_bytes: 4,
        output_incomplete: false,
        kernel_lost_events: None,
        ready_at_unix_ns: None,
        exit_code: Some(0),
        forced_kill: false,
        cleanup: TraceCleanupV1::Unknown,
    };
    store.append_trace(
        &diagnostic,
        &TraceBatchV1 {
            execution_id: diagnostic.execution_id,
            frames: vec![frame.clone()],
            terminal: Some(terminal.clone()),
        },
        100,
    )?;
    let input = AnalysisResultCommitV1 {
        body: b"result".to_vec(),
        created_utc_ns: 101,
        witnesses: vec![
            AnalysisWitnessV1 {
                identity: evidence.into(),
                cursor: 1,
                expires_utc_ns: 300,
            },
            AnalysisWitnessV1 {
                identity: diagnostic.clone().into(),
                cursor: 2,
                expires_utc_ns: 300,
            },
        ],
        ..result(scope, "mixed-result".into())
    };
    let mut invalid = input.clone();
    invalid.witnesses[1].cursor = 3;
    assert!(store.commit_result(&invalid).is_err());
    invalid.witnesses[1].cursor = 2;
    invalid.witnesses[1].identity = TraceIdentityV1 {
        source_sha256: [9; 32],
        ..diagnostic.clone()
    }
    .into();
    assert!(store.commit_result(&invalid).is_err());
    invalid.witnesses[1].identity = TraceIdentityV1 {
        tenant_id: [9; 16],
        ..diagnostic.clone()
    }
    .into();
    assert!(store.commit_result(&invalid).is_err());
    assert!(store.read_result([1; 16], "mixed-result")?.is_none());
    let receipt = store.commit_result(&input)?;
    let retained = EvidenceRetentionOwner::new(&store).retain_trace(&diagnostic, 201)?;
    assert_eq!(retained.removed_records, 0);
    assert_eq!(retained.retained_floor, 0);
    drop(store);

    let store = AnalysisStore::open_with_retention(&root, limits)?;
    assert_eq!(store.commit_result(&input)?, receipt);
    assert_eq!(
        store.read_result([1; 16], "mixed-result")?,
        Some(b"result".to_vec())
    );
    let output = store.read_trace(&diagnostic, 1, &AnalysisReadControl::default())?;
    assert_eq!(output.frames, vec![frame]);
    assert_eq!(output.terminal, Some(terminal));
    let expired = EvidenceRetentionOwner::new(&store).retain_trace(&diagnostic, 301)?;
    assert_eq!(expired.removed_records, 2);
    assert_eq!(expired.retained_floor, 2);
    assert!(matches!(
        store.read_trace(&diagnostic, 1, &AnalysisReadControl::default()),
        Err(araphor_data::Error::RetainedRangeExpired { .. })
    ));
    assert_eq!(store.commit_result(&input)?, receipt);
    Ok(())
}
