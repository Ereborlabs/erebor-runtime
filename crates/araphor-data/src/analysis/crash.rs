use super::*;

impl AnalysisStore {
    pub(super) fn crash_at(&self, point: &str) {
        if std::env::var("ARAPHOR_CRASH_POINT").as_deref() == Ok(point)
            && std::env::var_os("ARAPHOR_CRASH_ROOT")
                .is_some_and(|root| Path::new(&root) == self.root)
        {
            std::process::exit(73);
        }
    }
}

#[test]
fn analysis_store_commit_crashes() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let source = EvidenceIntakeIdentityV1 {
        tenant_id: [1; 16],
        node_id: "node-a".into(),
        node_boot_id: [2; 16],
        label_epoch: 1,
        source_id: [3; 16],
        source_epoch: 1,
    };
    let context = AnalysisContextVersionV1 {
        key: AnalysisContextKeyV1 {
            tenant_id: source.tenant_id,
            owner_id: "policy".into(),
            entity_key: b"workload".to_vec(),
            lifetime_key: b"pod".to_vec(),
            owner_revision: 1,
        },
        valid_from_utc_ns: None,
        valid_until_utc_ns: None,
        sensitivity: ContextSensitivityV1::Tenant,
        body: b"context".to_vec(),
    };
    let input = AnalysisResultCommitV1 {
        scope: ProcessorScopeV1 {
            processor_id: "required".into(),
            method_version: 1,
            identity: source.clone(),
        },
        expected_cursor: 0,
        consumed_cursor: 3,
        coverage_revision: 0,
        context_revision: 3,
        result_id: "finding".into(),
        body: b"result".to_vec(),
        created_utc_ns: 150,
        witnesses: vec![AnalysisWitnessV1 {
            identity: source.clone(),
            cursor: 3,
            expires_utc_ns: 1_000,
        }],
        context_refs: vec![AnalysisContextRefV1 {
            key: context.key.clone(),
            content_sha256: context.content_digest()?,
        }],
    };
    let limits = RetentionLimitsV1 {
        raw_max_age_ns: 50,
        raw_max_bytes: 1024,
    };
    if let Some(root) = std::env::var_os("ARAPHOR_CRASH_ROOT") {
        let store = AnalysisStore::open(PathBuf::from(root))?;
        let point = std::env::var("ARAPHOR_CRASH_POINT")?;
        if point.starts_with("result.") {
            store.commit_result(&input)?;
        } else {
            EvidenceRetentionOwner::new(&store, limits)?.retain(&source, 200)?;
        }
        return Err("the requested commit crash did not occur".into());
    }

    for point in [
        "result.before",
        "result.after",
        "retention.before",
        "retention.after",
    ] {
        let directory = tempfile::tempdir()?;
        let root = directory.path().join("analysis");
        let store = AnalysisStore::open(&root)?;
        store.register_processor(&input.scope, ProcessorClassV1::Required, 1)?;
        store.accept_validated_batch(
            source.clone(),
            ValidatedEvidenceBatchV1 {
                cpu_id: 0,
                first_cursor: 1,
                last_cursor: 3,
                intake_utc_ns: 100,
                framed_records: b"abc".to_vec().into(),
                frame_ends: vec![1, 2, 3],
            },
        )?;
        assert_eq!(store.commit_context(&context)?, 3);
        if point.starts_with("retention.") {
            assert_eq!(store.commit_result(&input)?.commit_revision, 4);
        }
        let before = store.meta()?;
        drop(store);
        let status = std::process::Command::new(std::env::current_exe()?)
            .args(["--exact", "analysis::crash::analysis_store_commit_crashes"])
            .env("ARAPHOR_CRASH_ROOT", &root)
            .env("ARAPHOR_CRASH_POINT", point)
            .status()?;
        assert_eq!(status.code(), Some(73), "{point}");
        let store = AnalysisStore::open(&root)?;
        let after = point.ends_with(".after");
        let meta = store.meta()?;
        assert_eq!(meta.store_uuid, before.store_uuid, "{point}");
        assert_eq!(meta.recovery_epoch, before.recovery_epoch, "{point}");
        assert_eq!(
            meta.commit_revision,
            before.commit_revision + u64::from(after),
            "{point}"
        );
        assert_eq!(
            *store.subscribe_revision().borrow(),
            meta.commit_revision,
            "{point}"
        );
        let committed = point != "result.before";
        assert_eq!(
            store.read_result(source.tenant_id, "finding")?,
            committed.then(|| input.body.clone()),
            "{point}"
        );
        assert_eq!(store.read_result([9; 16], "finding")?, None);
        let health = store
            .processor_health(&input.scope)?
            .ok_or("processor is absent")?;
        assert_eq!(
            health.consumed_cursor,
            if committed { 3 } else { 0 },
            "{point}"
        );
        let counts: (u64, u64) = store.reader()?.get()?.query_row(
            "SELECT (SELECT COUNT(*) FROM evidence_refs), (SELECT COUNT(*) FROM context_refs)",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        assert_eq!(
            counts,
            (u64::from(committed), u64::from(committed)),
            "{point}"
        );
        let expired = point == "retention.after";
        let retained = store.source_status(&source)?.ok_or("source is absent")?;
        assert_eq!(retained.receipt.contiguous_cursor, 3, "{point}");
        assert_eq!(
            retained.receipt.retained_floor,
            if expired { 2 } else { 0 },
            "{point}"
        );
        assert_eq!(
            retained.retained_event_count,
            if expired { 1 } else { 3 },
            "{point}"
        );
        if expired {
            assert!(matches!(
                store.read_page(&source, 1),
                Err(crate::Error::RetainedRangeExpired { .. })
            ));
        } else {
            assert_eq!(store.read_page(&source, 1)?.records.len(), 3, "{point}");
        }
        assert_eq!(
            store.read_page(&source, 3)?.records[0].framed_record,
            b"c",
            "{point}"
        );
        let receipt = store.commit_result(&input)?;
        assert_eq!(receipt.commit_revision, 4, "{point}");
        let revision = store.meta()?.commit_revision;
        assert_eq!(store.commit_result(&input)?, receipt, "{point}");
        assert_eq!(store.meta()?.commit_revision, revision, "{point}");
        let result = EvidenceRetentionOwner::new(&store, limits)?.retain(&source, 200)?;
        assert_eq!(
            result.removed_records,
            if expired { 0 } else { 2 },
            "{point}"
        );
        assert_eq!(result.retained_floor, 2, "{point}");
        assert_eq!(store.meta()?.commit_revision, 5, "{point}");
        drop(store);
        let store = AnalysisStore::open(root)?;
        assert_eq!(store.meta()?.commit_revision, 5, "{point}");
        assert_eq!(
            store.read_page(&source, 3)?.records[0].framed_record,
            b"c",
            "{point}"
        );
    }
    Ok(())
}
