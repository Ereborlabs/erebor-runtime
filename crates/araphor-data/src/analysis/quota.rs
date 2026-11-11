pub(super) const TRACE_RESERVE: u64 = 16 * 1024;
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize)]
pub struct WitnessUsageV1 {
    pub read_revision: u64,
    pub referenced_bytes: u64,
    pub segment_bytes: u64,
    pub extra_segment_bytes: u64,
    pub context_bytes: u64,
    pub charged_bytes: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis::AnalysisStore;
    use crate::AnalysisReadControl;
    use crate::{
        AnalysisContextKeyV1, AnalysisContextRefV1, AnalysisContextVersionV1,
        AnalysisResultCommitV1, AnalysisWitnessV1, ContextSensitivityV1, EvidenceIntakeIdentityV1,
        ProcessorClassV1, ProcessorScopeV1, TraceBatchV1, TraceFrameKindV1, TraceFrameV1,
        ValidatedEvidenceBatchV1,
    };

    type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;

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
        let limits = super::super::RetentionLimitsV1 {
            raw_max_age_ns: Some(1),
            raw_max_bytes: None,
        };
        let mut store = AnalysisStore::open_with_retention(&root, limits)?;
        let identity = EvidenceIntakeIdentityV1 {
            node_id: "n".repeat(128),
            ..crate::analysis::tests::identity()
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
        let file_bytes =
            std::fs::metadata(super::super::segments::SegmentRange::path(&root, 1))?.len();
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
            ..crate::analysis::tests::result(scope, "r".into())
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
        let retention = crate::EvidenceRetentionOwner::new(&store);
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
        AnalysisStore::validate_state(store.writer()?.get()?, &store.root)?;
        drop(store);
        let store = AnalysisStore::open_with_retention(&root, limits)?;
        assert_eq!(store.read_result([1; 16], "s")?, Some(vec![1]));
        AnalysisStore::validate_state(store.writer()?.get()?, &root)?;
        Ok(())
    }

    #[test]
    fn analysis_witness_segment_cost() -> TestResult {
        let directory = tempfile::tempdir()?;
        let root = directory.path().join("analysis");
        let limits = crate::RetentionLimitsV1 {
            raw_max_age_ns: Some(1),
            raw_max_bytes: Some(32 * 1024 * 1024),
        };
        let store = AnalysisStore::open_with_retention(&root, limits)?;
        let identity = EvidenceIntakeIdentityV1 {
            node_id: "n".into(),
            ..crate::analysis::tests::identity()
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
            ..crate::analysis::tests::result(scope, "first".into())
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
        let owner = crate::EvidenceRetentionOwner::new(&store);
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
        assert!(store.maintenance.try_write().is_ok());
        AnalysisStore::validate_state(store.writer()?.get()?, &store.root)?;
        Ok(())
    }

    #[test]
    fn raw_projection_keeps_terminal_reserves() -> TestResult {
        use super::super::raw::tests::{trace_intent, trace_terminal};
        let directory = tempfile::tempdir()?;
        let root = directory.path().join("analysis");
        let store = AnalysisStore::open(&root)?;
        let intent = trace_intent()?;
        let identity = &intent.bindings[0].identity;
        store.accept_trace(&intent)?;
        let frame = |sequence, byte| TraceFrameV1 {
            execution_id: identity.execution_id,
            sequence,
            kind: TraceFrameKindV1::Data,
            bytes: vec![byte],
        };
        store.append_trace(
            identity,
            &TraceBatchV1 {
                execution_id: identity.execution_id,
                frames: vec![frame(1, 7)],
                terminal: None,
            },
            101,
        )?;
        {
            let raw = store.raw.lock().map_err(|_| "raw poisoned")?;
            assert_eq!(
                (raw.budget.trace_reserve, raw.budget.trace_slots),
                (TRACE_RESERVE, 1)
            );
        }
        let terminal = trace_terminal(2, 2);
        let receipt = store.append_trace(
            identity,
            &TraceBatchV1 {
                execution_id: identity.execution_id,
                frames: vec![frame(2, 8)],
                terminal: Some(terminal.clone()),
            },
            102,
        )?;
        {
            let raw = store.raw.lock().map_err(|_| "raw poisoned")?;
            assert_eq!((raw.budget.trace_reserve, raw.budget.trace_slots), (0, 0));
        }
        assert_eq!((receipt.last_sequence, receipt.output_bytes), (2, 2));
        let page = store.read_trace(identity, 1, &AnalysisReadControl::default())?;
        assert_eq!(page.frames, vec![frame(1, 7), frame(2, 8)]);
        assert_eq!(page.terminal, Some(terminal));
        drop(store);
        let store = AnalysisStore::open(&root)?;
        assert_eq!(store.trace_receipt(identity)?, Some(receipt));
        assert_eq!(
            store
                .read_trace(identity, 1, &AnalysisReadControl::default())?
                .frames,
            vec![frame(1, 7), frame(2, 8)]
        );
        Ok(())
    }

    #[test]
    fn usage_tracks_transactions() -> TestResult {
        let directory = tempfile::tempdir()?;
        let root = directory.path().join("analysis");
        let store = AnalysisStore::open(&root)?;
        store.commit_context(&context(1, 1))?;
        let mut writer = store.writer()?;
        let before = AnalysisStore::revision_usage(writer.get()?, [1; 16])?;
        assert_eq!(before, (1, 1));
        let transaction = writer.get_mut()?.transaction()?;
        transaction.execute(
            "INSERT INTO context_versions SELECT ?, owner_id, entity_key, lifetime_key,
                owner_revision, valid_from_utc_ns, valid_until_utc_ns, sensitivity, body,
                commit_revision, ('tenant2:' || HEX(version_key))::BLOB FROM context_versions",
            params![[2u8; 16].as_slice()],
        )?;
        assert_eq!(
            AnalysisStore::revision_usage(&transaction, [2; 16])?,
            (2, 1)
        );
        transaction.execute(
            "DELETE FROM context_versions WHERE tenant_id = ?",
            params![[1u8; 16].as_slice()],
        )?;
        assert_eq!(
            AnalysisStore::revision_usage(&transaction, [1; 16])?,
            (1, 0)
        );
        transaction.rollback()?;
        assert_eq!(
            AnalysisStore::revision_usage(writer.get()?, [1; 16])?,
            before
        );
        AnalysisStore::validate_state(writer.get()?, &root)?;
        drop(writer);
        drop(store);
        let store = AnalysisStore::open(&root)?;
        assert_eq!(
            AnalysisStore::revision_usage(store.writer()?.get()?, [1; 16])?,
            before
        );
        Ok(())
    }
}
