use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;

use araphor_data::{
    AnalysisContextKeyV1, AnalysisContextVersionV1, CompiledPolicyContextV1, ContainerKindV1,
    ContextSensitivityV1, KubernetesWorkloadIdentityV1, TargetContextV1, WorkloadTargetFactV1,
};
use araphor_discovery_effects::ObservedEffects;
use datafusion::common::ScalarValue;
use futures_util::StreamExt as _;
use prost::Message as _;

use super::{
    next, values, AnalysisReadControl, AnalysisSelectionV1, Duration, EvidenceIntakeIdentityV1,
    Fixture, Limits, Operation, Subscription, TestClock,
};

const COUNTS: &str = "SELECT event_count, first_cursor, last_cursor, binding_id, source_id
    FROM discovery.observed_effects((SELECT * FROM events)) ORDER BY source_id";

fn recorded_sql(events: &str) -> String {
    format!(
        "WITH input_events AS ({events}),
        identified AS (
            SELECT input_events.*, named_struct('stream', named_struct(
                'tenant_id', tenant_id, 'node_id', node_id, 'node_boot_id', node_boot_id,
                'label_epoch', label_epoch, 'source_id', source_id, 'source_epoch', source_epoch),
                'cpu_id', cpu_id, 'durable_cursor', source_cursor) AS record_id
            FROM input_events
        ),
        empty_contexts AS (
            SELECT record_id, '' AS subject_revision, '' AS image_digest,
                '' AS configuration_digest, process_instance_id, entry_instance_id,
                binding_id, role_id, state_id, entry_rule_id,
                CAST(0 AS BIGINT UNSIGNED) AS catalog_revision,
                named_struct('workload_selector_id', '', 'protected_scope_id', '',
                    'execution_set_id', '', 'entry_kind', '', 'role_id', '',
                    'process_state_id', '', 'effect_family', effect_family,
                    'operation_id', '', 'operation', operation,
                    'operation_argument', COALESCE(operation_argument, 0),
                    'argument_wildcard', FALSE, 'object_selector', '',
                    'binding_lifecycle', '') AS static_key,
                named_struct('profile_id', '', 'profile_version', CAST(0 AS BIGINT UNSIGNED),
                    'source_revision_id', '', 'signed_profile_digest', '') AS policy_revision
            FROM identified WHERE FALSE
        ),
        snapshot AS (
            SELECT * FROM discovery.recorded_snapshot(
                (SELECT * FROM input_events), (SELECT * FROM empty_contexts),
                (SELECT * FROM discovery.coverage_ranges(
                    (SELECT * FROM input_events), (SELECT * FROM coverage))),
                (SELECT record_id, CAST(NULL AS VARCHAR) AS reason FROM identified WHERE FALSE),
                (SELECT CAST(NULL AS VARCHAR) AS \"case\", CAST(NULL AS VARCHAR) AS state,
                    [record_id] AS records, CAST(NULL AS VARCHAR) AS reason
                    FROM identified WHERE FALSE),
                (SELECT decode('01010101010101010101010101010101', 'hex') AS tenant_id,
                    'retained-cut' AS source_revision, 'OBSERVED_RUNTIME' AS proof_kind))
        )
        SELECT accepted_records, included_records, unresolved_records, excluded_records,
            duplicate_deliveries, array_length(atoms), array_length(coverage),
            array_length(unresolved), array_length(excluded), array_length(lifecycle),
            unresolved[1]['record_id']['durable_cursor'] AS first_cursor,
            unresolved[CAST(array_length(unresolved) AS BIGINT)]['record_id']['durable_cursor'] AS last_cursor,
            unresolved[1]['reason'] AS reason,
            unresolved[1]['record_id']['stream']['source_id'] AS source_id
        FROM snapshot"
    )
}

fn assert_recorded(update: &super::Update, count: u64, first: Option<u64>, last: Option<u64>) {
    for (column, expected) in [count, 0, count, 0, 0, 0, u64::from(count > 0), count, 0, 9]
        .into_iter()
        .enumerate()
    {
        assert_eq!(
            values(update, column),
            [ScalarValue::UInt64(Some(expected))]
        );
    }
    assert_eq!(values(update, 10), [ScalarValue::UInt64(first)]);
    assert_eq!(values(update, 11), [ScalarValue::UInt64(last)]);
    assert_eq!(
        values(update, 12),
        [ScalarValue::Utf8(
            (count > 0).then(|| "MISSING_RECORDED_CONTEXT".into())
        )]
    );
    assert_eq!(
        values(update, 13),
        [ScalarValue::Binary((count > 0).then(|| vec![3; 16]))]
    );
}

fn fixture(limits: Limits) -> Fixture {
    let mut fixture = Fixture::new(limits);
    Arc::get_mut(&mut fixture.engine)
        .unwrap()
        .register_relation_planner(Arc::new(ObservedEffects))
        .unwrap();
    fixture
}

async fn subscribe(
    fixture: &Fixture,
    sql: &str,
    clock: Arc<TestClock>,
) -> (Subscription, Arc<AnalysisReadControl>) {
    let control = Arc::new(AnalysisReadControl::with_timeout(Duration::from_secs(20)).unwrap());
    let subscription = fixture
        .engine
        .subscribe(
            sql,
            vec![],
            fixture.selection(),
            Arc::clone(&control),
            b"discovery package",
            None,
            clock,
            true,
        )
        .await
        .unwrap();
    (subscription, control)
}

fn assert_released(fixture: &Fixture) {
    drop(
        fixture
            .engine
            .reserve_evaluation(fixture.source.tenant_id)
            .unwrap(),
    );
    drop(
        fixture
            .engine
            .reserve_stream(fixture.source.tenant_id)
            .unwrap(),
    );
    drop(
        fixture
            .engine
            .memory()
            .reserve_input(fixture.engine.limits().input_capacity)
            .unwrap(),
    );
    drop(
        fixture
            .engine
            .memory()
            .reserve_output(fixture.engine.limits().output_capacity)
            .unwrap(),
    );
}

fn target_context(
    fixture: &Fixture,
    snapshot: &str,
    policy: &str,
    signature: &str,
) -> AnalysisContextVersionV1 {
    let target = TargetContextV1 {
        workload_digest_valid: true,
        workload: WorkloadTargetFactV1 {
            node_id: fixture.source.node_id.clone(),
            workload_binding_generation_digest: "f".repeat(64),
            execution_set_id: uuid::Uuid::from_bytes([4; 16]).to_string(),
            cluster_uid: "cluster".into(),
            namespace_uid: "namespace".into(),
            controller_uid: "controller".into(),
            service_account_uid: "account".into(),
            pod_uid: "pod".into(),
            container_id: "containerd://worker".into(),
            container_name: "worker".into(),
            container_kind: ContainerKindV1::Application,
            image_digest: "sha256:image".into(),
            pod_labels: std::collections::BTreeMap::from([("app".into(), "worker".into())]),
            kubernetes: Some(KubernetesWorkloadIdentityV1 {
                namespace_name: "default".into(),
                pod_name: "worker-pod".into(),
                profile_id: "profile".into(),
                policy_source_revision_id: "workload-policy".into(),
                binding_id: uuid::Uuid::from_bytes([10; 16]).to_string(),
                protected_scope_id: "scope".into(),
                workload_selector_id: "selector".into(),
                kubernetes_node_name: "node".into(),
                kubernetes_node_uid: "node-uid".into(),
                node_boot_id: uuid::Uuid::from_bytes(fixture.source.node_boot_id).to_string(),
                label_epoch: fixture.source.label_epoch,
            }),
        },
        policy_source_revision_id: policy.into(),
        target_snapshot_digest: snapshot.into(),
        signed_profile_digest: signature.into(),
    };
    AnalysisContextVersionV1 {
        key: AnalysisContextKeyV1 {
            tenant_id: fixture.source.tenant_id,
            owner_id: "mithril-control/target".into(),
            entity_key: vec![10; 16],
            lifetime_key: snapshot.as_bytes().to_vec(),
            owner_revision: 1,
        },
        valid_from_utc_ns: None,
        valid_until_utc_ns: None,
        sensitivity: ContextSensitivityV1::Tenant,
        body: serde_json::to_vec(&target).unwrap(),
    }
}

#[tokio::test]
async fn targets_keep_snapshot_metadata() {
    let fixture = Fixture::new(Limits {
        tenant_streams: 1,
        ..Default::default()
    });
    let first_context = target_context(
        &fixture,
        &"a".repeat(64),
        "snapshot-policy-1",
        &"c".repeat(64),
    );
    let second_context = target_context(
        &fixture,
        &"b".repeat(64),
        "snapshot-policy-2",
        &"d".repeat(64),
    );
    let mut foreign = target_context(&fixture, &"e".repeat(64), "foreign-policy", &"f".repeat(64));
    foreign.key.tenant_id = [9; 16];
    let first_target: TargetContextV1 = serde_json::from_slice(&first_context.body).unwrap();
    let second_target: TargetContextV1 = serde_json::from_slice(&second_context.body).unwrap();
    assert_eq!(first_target.workload, second_target.workload);
    assert_ne!(
        first_context.key.lifetime_key,
        second_context.key.lifetime_key
    );
    let published = fixture
        .store
        .commit_contexts(&[first_context.clone(), foreign])
        .unwrap();
    let sql = "SELECT entity_key, lifetime_key, source_revision_id, policy_source_revision_id,
            target_snapshot_digest, signed_profile_digest, binding_id, node_id,
            workload_binding_generation_digest, image_digest
        FROM targets WHERE source_revision_id <> policy_source_revision_id
        ORDER BY lifetime_key";
    let (_, sources) = fixture.engine.prepare(sql, vec![]).await.unwrap();
    assert_eq!(
        sources.keys().map(String::as_str).collect::<Vec<_>>(),
        ["targets"]
    );
    let mut subscription = fixture
        .engine
        .subscribe(
            sql,
            vec![],
            AnalysisSelectionV1::tenant(fixture.source.tenant_id),
            Arc::new(AnalysisReadControl::with_timeout(Duration::from_secs(20)).unwrap()),
            b"target snapshots",
            None,
            TestClock::new(2_000_000_000),
            true,
        )
        .await
        .unwrap();
    for name in [
        "source_revision_id",
        "target_snapshot_digest",
        "signed_profile_digest",
    ] {
        assert!(!subscription
            .schema()
            .field_with_name(name)
            .unwrap()
            .is_nullable());
    }
    let first = next(&mut subscription).await;
    assert_eq!(first.operation, Operation::Replace);
    assert_eq!(
        first.snapshot.contexts().cloned().collect::<Vec<_>>(),
        vec![published[0].clone()]
    );
    assert_eq!(first.cursor.read_revision(), published[0].commit_revision);
    let committed = fixture
        .store
        .commit_contexts(std::slice::from_ref(&second_context))
        .unwrap();
    let second = next(&mut subscription).await;
    assert_eq!(second.operation, Operation::Replace);
    assert_eq!(second.cursor.read_revision(), committed[0].commit_revision);
    assert!(second.cursor.read_revision() > first.cursor.read_revision());
    assert_eq!(
        second.snapshot.contexts().cloned().collect::<Vec<_>>(),
        vec![published[0].clone(), committed[0].clone()]
    );
    for (update, targets) in [
        (&first, vec![&first_target]),
        (&second, vec![&first_target, &second_target]),
    ] {
        let count = targets.len();
        assert_eq!(
            values(update, 0),
            vec![ScalarValue::Binary(Some(vec![10; 16])); count]
        );
        assert_eq!(
            values(update, 1),
            targets
                .iter()
                .map(|target| ScalarValue::Binary(Some(
                    target.target_snapshot_digest.as_bytes().to_vec()
                )))
                .collect::<Vec<_>>()
        );
        assert_eq!(
            values(update, 2),
            targets
                .iter()
                .map(|target| ScalarValue::Utf8(Some(target.policy_source_revision_id.clone())))
                .collect::<Vec<_>>()
        );
        assert_eq!(
            values(update, 3),
            vec![ScalarValue::Utf8(Some("workload-policy".into())); count]
        );
        assert_eq!(
            values(update, 4),
            targets
                .iter()
                .map(|target| ScalarValue::Utf8(Some(target.target_snapshot_digest.clone())))
                .collect::<Vec<_>>()
        );
        assert_eq!(
            values(update, 5),
            targets
                .iter()
                .map(|target| ScalarValue::Utf8(Some(target.signed_profile_digest.clone())))
                .collect::<Vec<_>>()
        );
        assert_eq!(
            values(update, 6),
            vec![ScalarValue::Binary(Some(vec![10; 16])); count]
        );
        assert_eq!(
            values(update, 7),
            vec![ScalarValue::Utf8(Some(fixture.source.node_id.clone())); count]
        );
        assert_eq!(
            values(update, 8),
            vec![ScalarValue::Utf8(Some("f".repeat(64))); count]
        );
        assert_eq!(
            values(update, 9),
            vec![ScalarValue::Utf8(Some("sha256:image".into())); count]
        );
        assert!(update
            .snapshot
            .contexts()
            .all(|reference| reference.key.tenant_id == fixture.source.tenant_id));
        assert!(update.snapshot.witnesses.is_empty());
    }
    assert_eq!(
        first.snapshot.contexts().cloned().collect::<Vec<_>>(),
        vec![published[0].clone()]
    );
    assert_eq!(
        fixture.store.context_version(&first_context.key).unwrap(),
        Some(first_context)
    );
    {
        let waiting = subscription.next();
        tokio::pin!(waiting);
        assert!(futures_util::poll!(waiting.as_mut()).is_pending());
    }
    subscription.cancel().unwrap();
    assert!(subscription.next().await.is_none());
    drop((subscription, first, second));
    assert_released(&fixture);
}

#[tokio::test]
async fn compiled_policies_follow_sources() {
    for mixed in [false, true] {
        let fixture = Fixture::new(Limits {
            tenant_streams: 1,
            ..Default::default()
        });
        let contexts = |snapshot: &str, signature: &str| {
            let proof = CompiledPolicyContextV1 {
                source_revision_id: "snapshot-policy".into(),
                signed_profile_digest: signature.into(),
                profile_id: "profile".into(),
                profile_version: 1,
                policy_document_digest: "policy-document".into(),
                execution_set_ids: vec![uuid::Uuid::from_bytes([4; 16]).to_string()],
                compiled_keys: Vec::new(),
            };
            let mut rows = vec![AnalysisContextVersionV1 {
                key: AnalysisContextKeyV1 {
                    tenant_id: fixture.source.tenant_id,
                    owner_id: "mithril-control/compiled-policy".into(),
                    entity_key: proof.source_revision_id.as_bytes().to_vec(),
                    lifetime_key: signature.as_bytes().to_vec(),
                    owner_revision: 1,
                },
                valid_from_utc_ns: None,
                valid_until_utc_ns: None,
                sensitivity: ContextSensitivityV1::Tenant,
                body: proof.encode().unwrap(),
            }];
            if mixed {
                rows.push(target_context(
                    &fixture,
                    snapshot,
                    &proof.source_revision_id,
                    signature,
                ));
            }
            rows
        };
        let initial = contexts(&"a".repeat(64), &"c".repeat(64));
        let mut retained = initial.clone();
        retained.extend(initial.iter().cloned().map(|mut context| {
            context.key.tenant_id = [9; 16];
            context
        }));
        let published = fixture.store.commit_contexts(&retained).unwrap();
        let sql = format!(
            "SELECT p.source_revision_id, p.signed_profile_digest, p.commit_revision,
                array_length(p.execution_set_ids), array_length(p.compiled_keys)
            FROM compiled_policies p {} ORDER BY p.signed_profile_digest",
            if mixed {
                "JOIN targets t ON t.source_revision_id = p.source_revision_id
                AND t.signed_profile_digest = p.signed_profile_digest"
            } else {
                ""
            }
        );
        let (_, sources) = fixture.engine.prepare(&sql, vec![]).await.unwrap();
        assert_eq!(
            sources.keys().map(String::as_str).collect::<Vec<_>>(),
            if mixed {
                vec!["compiled_policies", "targets"]
            } else {
                vec!["compiled_policies"]
            }
        );
        let clock = TestClock::new(2_000_000_000);
        let control = Arc::new(AnalysisReadControl::with_timeout(Duration::from_secs(20)).unwrap());
        let mut subscription = fixture
            .engine
            .subscribe(
                &sql,
                vec![],
                AnalysisSelectionV1::tenant(fixture.source.tenant_id),
                Arc::clone(&control),
                b"compiled policy proofs",
                None,
                clock.clone(),
                true,
            )
            .await
            .unwrap();
        let first = next(&mut subscription).await;
        let mut expected = published[..initial.len()].to_vec();
        expected.sort_by(|left, right| left.key.cmp(&right.key));
        assert_eq!(
            first.snapshot.contexts().cloned().collect::<Vec<_>>(),
            expected
        );
        let refreshed = fixture
            .store
            .commit_contexts(&contexts(&"b".repeat(64), &"d".repeat(64)))
            .unwrap();
        let second = next(&mut subscription).await;
        expected.extend(refreshed.iter().cloned());
        expected.sort_by(|left, right| left.key.cmp(&right.key));
        assert_eq!(
            second.snapshot.contexts().cloned().collect::<Vec<_>>(),
            expected
        );
        for (update, signatures, revisions) in [
            (
                &first,
                vec!["c".repeat(64)],
                vec![published[0].commit_revision],
            ),
            (
                &second,
                vec!["c".repeat(64), "d".repeat(64)],
                vec![published[0].commit_revision, refreshed[0].commit_revision],
            ),
        ] {
            assert_eq!(update.operation, Operation::Replace);
            assert_eq!(
                values(update, 0),
                vec![ScalarValue::Utf8(Some("snapshot-policy".into())); signatures.len()]
            );
            assert_eq!(
                values(update, 1),
                signatures
                    .into_iter()
                    .map(|value| ScalarValue::Utf8(Some(value)))
                    .collect::<Vec<_>>()
            );
            assert_eq!(
                values(update, 2),
                revisions
                    .into_iter()
                    .map(|value| ScalarValue::UInt64(Some(value)))
                    .collect::<Vec<_>>()
            );
            let count = values(update, 0).len();
            assert_eq!(values(update, 3), vec![ScalarValue::UInt64(Some(1)); count]);
            assert_eq!(values(update, 4), vec![ScalarValue::UInt64(Some(0)); count]);
            assert!(update.snapshot.witnesses.is_empty());
        }
        assert_eq!(first.cursor.read_revision(), published[0].commit_revision);
        assert_eq!(second.cursor.read_revision(), refreshed[0].commit_revision);
        assert!(second.cursor.read_revision() > first.cursor.read_revision());
        assert_eq!(
            first.snapshot.contexts().cloned().collect::<Vec<_>>(),
            published[..initial.len()]
        );
        assert_eq!(
            fixture.store.context_version(&initial[0].key).unwrap(),
            Some(initial[0].clone())
        );
        {
            let waiting = subscription.next();
            tokio::pin!(waiting);
            assert!(futures_util::poll!(waiting.as_mut()).is_pending());
            let reads = clock.reads.load(Ordering::SeqCst);
            clock.now.store(1_000_000_000_000, Ordering::SeqCst);
            assert!(
                tokio::time::timeout(Duration::from_millis(40), waiting.as_mut())
                    .await
                    .is_err()
            );
            assert_eq!(clock.reads.load(Ordering::SeqCst), reads);
            control.cancel().unwrap();
            let error = tokio::time::timeout(Duration::from_secs(8), waiting)
                .await
                .unwrap()
                .unwrap()
                .unwrap_err();
            assert_eq!(crate::Failure::from(&error), crate::Failure::Cancelled);
        }
        assert!(subscription.next().await.is_none());
        drop((subscription, first, second));
        assert_released(&fixture);
    }
}

#[tokio::test]
async fn updates_keep_source_scope() {
    let fixture = fixture(Limits::default());
    fixture.commit(&fixture.source, 1, 2, 1_000_000_000);
    let other = EvidenceIntakeIdentityV1 {
        source_id: [8; 16],
        ..fixture.source.clone()
    };
    fixture.commit(&other, 1, 3, 1_100_000_000);
    let foreign = EvidenceIntakeIdentityV1 {
        tenant_id: [9; 16],
        ..fixture.source.clone()
    };
    fixture.commit(&foreign, 1, 5, 1_200_000_000);
    let (_, sources) = fixture.engine.prepare(COUNTS, vec![]).await.unwrap();
    assert_eq!(
        sources.keys().map(String::as_str).collect::<Vec<_>>(),
        ["events"]
    );
    let (mut subscription, _) = subscribe(&fixture, COUNTS, TestClock::new(2_000_000_000)).await;
    let first = next(&mut subscription).await;
    assert_eq!(first.operation, Operation::Replace);
    assert_eq!(values(&first, 0), [ScalarValue::Int64(Some(2))]);
    assert_eq!(values(&first, 1), [ScalarValue::UInt64(Some(1))]);
    assert_eq!(values(&first, 2), [ScalarValue::UInt64(Some(2))]);
    assert_eq!(values(&first, 3), [ScalarValue::Binary(None)]);
    assert_eq!(
        values(&first, 4),
        [ScalarValue::Binary(Some(fixture.source.source_id.to_vec()))]
    );
    assert_eq!(first.snapshot.witnesses.len(), 2);
    fixture.commit(&fixture.source, 3, 1, 1_500_000_000);
    let second = next(&mut subscription).await;
    assert_eq!(values(&second, 0), [ScalarValue::Int64(Some(3))]);
    assert_eq!(values(&second, 1), [ScalarValue::UInt64(Some(1))]);
    assert_eq!(values(&second, 2), [ScalarValue::UInt64(Some(3))]);
    assert!(second.cursor.read_revision() > first.cursor.read_revision());
    assert_eq!(second.snapshot.witnesses.len(), 3);
    assert!(second.snapshot.witnesses.iter().all(|witness| {
        matches!(&witness.identity, araphor_data::AnalysisStreamIdentityV1::Evidence(identity) if identity == &fixture.source)
    }));
    assert_eq!(values(&first, 0), [ScalarValue::Int64(Some(2))]);
    assert_eq!(first.snapshot.witnesses.len(), 2);
    subscription.cancel().unwrap();
}

#[tokio::test]
async fn tenant_sources_stay_separate() {
    let fixture = fixture(Limits::default());
    fixture.commit(&fixture.source, 1, 2, 1_000_000_000);
    let other = EvidenceIntakeIdentityV1 {
        source_id: [8; 16],
        ..fixture.source.clone()
    };
    fixture.commit(&other, 1, 3, 1_100_000_000);
    let foreign = EvidenceIntakeIdentityV1 {
        tenant_id: [9; 16],
        ..fixture.source.clone()
    };
    fixture.commit(&foreign, 1, 5, 1_200_000_000);
    let mut subscription = fixture
        .engine
        .subscribe(
            COUNTS,
            vec![],
            AnalysisSelectionV1::tenant(fixture.source.tenant_id),
            Arc::new(AnalysisReadControl::with_timeout(Duration::from_secs(20)).unwrap()),
            b"tenant discovery",
            None,
            TestClock::new(2_000_000_000),
            false,
        )
        .await
        .unwrap();
    let result = next(&mut subscription).await;
    assert_eq!(
        values(&result, 0),
        [ScalarValue::Int64(Some(2)), ScalarValue::Int64(Some(3))]
    );
    assert_eq!(
        values(&result, 4),
        [
            ScalarValue::Binary(Some(fixture.source.source_id.to_vec())),
            ScalarValue::Binary(Some(other.source_id.to_vec())),
        ]
    );
    assert_eq!(
        values(&result, 3),
        [ScalarValue::Binary(None), ScalarValue::Binary(None)]
    );
    assert_eq!(result.snapshot.witnesses.len(), 5);
    assert!(subscription.next().await.is_none());
}

#[tokio::test]
async fn coverage_notices_update_ranges() {
    let fixture = fixture(Limits::default());
    fixture.commit(&fixture.source, 1, 2, 1_000_000_000);
    let sql = "SELECT first_cursor, last_cursor, expected_records, coverage_revision,
            coverage_interval_id, state, gap_reasons
        FROM discovery.coverage_ranges(
            (SELECT * FROM events), (SELECT * FROM coverage))";
    let (_, sources) = fixture.engine.prepare(sql, vec![]).await.unwrap();
    assert_eq!(
        sources.keys().map(String::as_str).collect::<Vec<_>>(),
        ["coverage", "events"]
    );
    let (mut subscription, _) = subscribe(&fixture, sql, TestClock::new(2_000_000_000)).await;
    let first = next(&mut subscription).await;
    assert_eq!(first.operation, Operation::Replace);
    assert_eq!(values(&first, 0), [ScalarValue::UInt64(Some(1))]);
    assert_eq!(values(&first, 1), [ScalarValue::UInt64(Some(2))]);
    assert_eq!(values(&first, 2), [ScalarValue::UInt64(Some(2))]);
    assert_eq!(values(&first, 3), [ScalarValue::UInt64(Some(0))]);
    assert_eq!(
        values(&first, 4),
        [ScalarValue::Binary(Some(fixture.source.source_id.to_vec()))]
    );
    assert_eq!(
        values(&first, 5),
        [ScalarValue::Utf8(Some("UNKNOWN".into()))]
    );
    for (revision, state, expected) in [(1, "GAPPED", "GAPPED"), (2, "HEALTHY", "UNKNOWN")] {
        fixture
            .store
            .accept_validated_coverage(araphor_data::ValidatedCoverageV1 {
                identity: fixture.source.clone(),
                cpu_id: 0,
                revision,
                encoded_report: araphor_data::CoverageReport {
                    source_id: fixture.source.source_id.to_vec(),
                    source_epoch: fixture.source.source_epoch,
                    cpu_id: 0,
                    revision,
                    intervals: vec![araphor_data::CoverageInterval {
                        interval_id: fixture.source.source_id.to_vec(),
                        source_epoch: fixture.source.source_epoch,
                        revision,
                        state: state.into(),
                        ..Default::default()
                    }],
                }
                .encode_to_vec(),
            })
            .unwrap();
        let update = next(&mut subscription).await;
        assert_eq!(update.operation, Operation::Replace);
        assert_eq!(values(&update, 0), values(&first, 0));
        assert_eq!(values(&update, 1), values(&first, 1));
        assert_eq!(values(&update, 2), values(&first, 2));
        assert_eq!(values(&update, 3), [ScalarValue::UInt64(Some(revision))]);
        assert_eq!(
            values(&update, 5),
            [ScalarValue::Utf8(Some(expected.into()))]
        );
        assert_eq!(update.snapshot.witnesses.len(), 2);
        assert!(update.cursor.read_revision() > first.cursor.read_revision());
        assert!(update
            .snapshot
            .page
            .extraction
            .sources
            .iter()
            .all(|source| {
                source.receipt.coverage_revision == revision
                    && source.receipt.contiguous_cursor == 2
            }));
    }
    assert_eq!(values(&first, 3), [ScalarValue::UInt64(Some(0))]);
    assert_eq!(
        values(&first, 5),
        [ScalarValue::Utf8(Some("UNKNOWN".into()))]
    );
    subscription.cancel().unwrap();
}

#[tokio::test]
async fn coverage_window_uses_deadlines() {
    let fixture = fixture(Limits::default());
    fixture.commit(&fixture.source, 1, 1, 1_000_000_123);
    fixture.commit(&fixture.source, 2, 1, 3_000_000_000);
    let clock = TestClock::new(4_000_000_000);
    let sql = "SELECT first_cursor, last_cursor, expected_records
        FROM discovery.coverage_ranges(
            (SELECT * FROM events
                WHERE received_at >= CURRENT_TIMESTAMP - INTERVAL '3 seconds'),
            (SELECT * FROM coverage))";
    let (mut subscription, _) = subscribe(&fixture, sql, Arc::clone(&clock)).await;
    assert_eq!(subscription.moving_resolution_ns(), Some(1_000));
    let revision = fixture.store.meta().unwrap().commit_revision;
    for (now, count, first) in [
        (4_000_000_000, 2, 1),
        (4_000_001_000, 1, 2),
        (6_000_001_000, 0, 0),
    ] {
        clock.set(now);
        let update = next(&mut subscription).await;
        if count == 0 {
            assert!(values(&update, 0).is_empty());
            assert!(values(&update, 1).is_empty());
            assert!(values(&update, 2).is_empty());
        } else {
            assert_eq!(values(&update, 0), [ScalarValue::UInt64(Some(first))]);
            assert_eq!(values(&update, 1), [ScalarValue::UInt64(Some(2))]);
            assert_eq!(values(&update, 2), [ScalarValue::UInt64(Some(count))]);
        }
        if now > 4_000_000_000 {
            assert!(update.clock_changed);
        }
        assert_eq!(update.snapshot.witnesses.len(), count as usize);
        assert_eq!(
            update.snapshot.page.extraction.meta.commit_revision,
            revision
        );
    }
    subscription.cancel().unwrap();
}

#[tokio::test]
async fn window_expires_without_intake() {
    let fixture = fixture(Limits::default());
    fixture.commit(&fixture.source, 1, 1, 1_000_000_123);
    fixture.commit(&fixture.source, 2, 1, 3_000_000_000);
    let clock = TestClock::new(4_000_000_000);
    let sql = "SELECT event_count, first_cursor, last_cursor,
            first_received_at, last_received_at
        FROM discovery.observed_effects((SELECT * FROM events
            WHERE received_at >= CURRENT_TIMESTAMP - INTERVAL '3 seconds'))";
    let (mut subscription, _) = subscribe(&fixture, sql, Arc::clone(&clock)).await;
    assert_eq!(subscription.moving_resolution_ns(), Some(1_000));
    let first = next(&mut subscription).await;
    assert_eq!(values(&first, 0), [ScalarValue::Int64(Some(2))]);
    assert_eq!(
        values(&first, 3),
        [ScalarValue::TimestampMicrosecond(Some(1_000_000), None)]
    );
    assert_eq!(
        values(&first, 4),
        [ScalarValue::TimestampMicrosecond(Some(3_000_000), None)]
    );
    let revision = first.snapshot.page.extraction.meta.commit_revision;
    clock.set(4_000_001_000);
    let second = next(&mut subscription).await;
    assert!(second.clock_changed);
    assert_eq!(values(&second, 0), [ScalarValue::Int64(Some(1))]);
    assert_eq!(values(&second, 1), [ScalarValue::UInt64(Some(2))]);
    assert_eq!(values(&second, 2), [ScalarValue::UInt64(Some(2))]);
    assert_eq!(second.snapshot.witnesses.len(), 1);
    assert_eq!(
        second.snapshot.page.extraction.meta.commit_revision,
        revision
    );
    clock.set(6_000_001_000);
    let empty = next(&mut subscription).await;
    assert!(empty.clock_changed);
    assert!(values(&empty, 0).is_empty());
    assert!(empty.snapshot.witnesses.is_empty());
    assert_eq!(
        empty.snapshot.page.extraction.meta.commit_revision,
        revision
    );
    subscription.cancel().unwrap();
}

#[tokio::test]
async fn idle_waits_for_events() {
    let fixture = fixture(Limits {
        tenant_streams: 1,
        ..Default::default()
    });
    fixture.commit(&fixture.source, 1, 1, 1_000_000_000);
    let clock = TestClock::new(2_000_000_000);
    let (mut subscription, control) = subscribe(&fixture, COUNTS, Arc::clone(&clock)).await;
    drop(next(&mut subscription).await);
    let reads = Arc::new(AtomicUsize::new(0));
    let observed = Arc::clone(&reads);
    control
        .on_read_step(move || {
            observed.fetch_add(1, Ordering::SeqCst);
            Ok(())
        })
        .unwrap();
    {
        let waiting = subscription.next();
        tokio::pin!(waiting);
        assert!(futures_util::poll!(waiting.as_mut()).is_pending());
        let clock_reads = clock.reads.load(Ordering::SeqCst);
        clock.now.store(1_000_000_000_000, Ordering::SeqCst);
        assert!(
            tokio::time::timeout(Duration::from_millis(40), waiting.as_mut())
                .await
                .is_err()
        );
        assert_eq!(clock.reads.load(Ordering::SeqCst), clock_reads);
        assert_eq!(reads.load(Ordering::SeqCst), 0);
        control.cancel().unwrap();
        let error = tokio::time::timeout(Duration::from_secs(8), waiting)
            .await
            .unwrap()
            .unwrap()
            .unwrap_err();
        assert_eq!(crate::Failure::from(&error), crate::Failure::Cancelled);
    }
    assert!(subscription.next().await.is_none());
    drop(subscription);
    assert_released(&fixture);
}

#[tokio::test]
async fn cancel_joins_source_read() {
    let fixture = fixture(Limits {
        tenant_streams: 1,
        ..Default::default()
    });
    fixture.commit(&fixture.source, 1, 1, 1_000_000_000);
    let (mut subscription, control) =
        subscribe(&fixture, COUNTS, TestClock::new(2_000_000_000)).await;
    let entered = Arc::new(tokio::sync::Notify::new());
    let joined = Arc::new(AtomicBool::new(false));
    let started = Arc::clone(&entered);
    let finished = Arc::clone(&joined);
    let (release, released) = std::sync::mpsc::channel();
    control
        .on_read_step(move || {
            started.notify_one();
            released.recv().unwrap();
            finished.store(true, Ordering::SeqCst);
            Ok(())
        })
        .unwrap();
    let worker = tokio::spawn(async move {
        let result = subscription.next().await;
        (subscription, result)
    });
    tokio::time::timeout(Duration::from_secs(8), entered.notified())
        .await
        .unwrap();
    control.cancel().unwrap();
    tokio::task::yield_now().await;
    assert!(!worker.is_finished());
    assert!(!joined.load(Ordering::SeqCst));
    release.send(()).unwrap();
    let (mut subscription, result) = tokio::time::timeout(Duration::from_secs(8), worker)
        .await
        .unwrap()
        .unwrap();
    let error = result.unwrap().unwrap_err();
    assert_eq!(crate::Failure::from(&error), crate::Failure::Cancelled);
    assert!(joined.load(Ordering::SeqCst));
    assert!(subscription.next().await.is_none());
    drop(subscription);
    assert_released(&fixture);
}

#[tokio::test]
async fn recorded_updates_and_expires() {
    let fixture = fixture(Limits {
        tenant_streams: 1,
        ..Default::default()
    });
    fixture.commit(&fixture.source, 1, 2, 1_000_000_123);
    for source in [
        EvidenceIntakeIdentityV1 {
            source_id: [8; 16],
            ..fixture.source.clone()
        },
        EvidenceIntakeIdentityV1 {
            tenant_id: [9; 16],
            ..fixture.source.clone()
        },
    ] {
        fixture.commit(&source, 1, 5, 1_500_000_000);
    }
    let clock = TestClock::new(3_500_000_000);
    let sql = recorded_sql(
        "SELECT * FROM events
        WHERE received_at >= CURRENT_TIMESTAMP - INTERVAL '3 seconds'",
    );
    let (_, sources) = fixture.engine.prepare(&sql, vec![]).await.unwrap();
    assert_eq!(
        sources.keys().map(String::as_str).collect::<Vec<_>>(),
        ["coverage", "events"]
    );
    let (mut subscription, control) = subscribe(&fixture, &sql, Arc::clone(&clock)).await;
    assert_eq!(subscription.moving_resolution_ns(), Some(1_000));
    let first = next(&mut subscription).await;
    assert_eq!(first.operation, Operation::Replace);
    assert_recorded(&first, 2, Some(1), Some(2));
    assert_eq!(first.snapshot.witnesses.len(), 2);
    assert_eq!(first.snapshot.page.extraction.sources.len(), 1);
    assert_eq!(
        first.snapshot.page.extraction.sources[0].receipt.identity,
        fixture.source
    );

    fixture.commit(&fixture.source, 3, 1, 3_000_000_000);
    let second = next(&mut subscription).await;
    assert_recorded(&second, 3, Some(1), Some(3));
    assert_eq!(second.snapshot.witnesses.len(), 3);
    assert!(second.cursor.read_revision() > first.cursor.read_revision());
    let revision = second.cursor.read_revision();
    let reads = Arc::new(AtomicUsize::new(0));
    let observed = Arc::clone(&reads);
    control
        .on_read_step(move || {
            observed.fetch_add(1, Ordering::SeqCst);
            Ok(())
        })
        .unwrap();
    {
        let waiting = subscription.next();
        tokio::pin!(waiting);
        assert!(futures_util::poll!(waiting.as_mut()).is_pending());
        let clock_reads = clock.reads.load(Ordering::SeqCst);
        assert!(tokio::time::timeout(Duration::from_millis(40), waiting)
            .await
            .is_err());
        assert_eq!(reads.load(Ordering::SeqCst), 0);
        assert_eq!(clock.reads.load(Ordering::SeqCst), clock_reads);
    }

    clock.set(4_000_001_000);
    let expired = next(&mut subscription).await;
    assert!(expired.clock_changed);
    assert_recorded(&expired, 1, Some(3), Some(3));
    assert_eq!(expired.snapshot.witnesses.len(), 1);
    assert_eq!(expired.cursor.read_revision(), revision);
    clock.set(6_000_001_000);
    let empty = next(&mut subscription).await;
    assert!(empty.clock_changed);
    assert_recorded(&empty, 0, None, None);
    assert!(empty.snapshot.witnesses.is_empty());
    assert_eq!(empty.cursor.read_revision(), revision);
    assert_recorded(&first, 2, Some(1), Some(2));
    assert_eq!(first.snapshot.witnesses.len(), 2);
    subscription.cancel().unwrap();
    drop((subscription, first, second, expired, empty));
    assert_released(&fixture);
}
