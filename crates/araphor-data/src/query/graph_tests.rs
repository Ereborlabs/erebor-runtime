use std::sync::Arc;
use std::time::Duration;

use duckdb::types::Value;
use erebor_interceptor_abi::EffectPhysicalResultV1;
use futures_util::StreamExt as _;
use tokio::sync::watch;

use super::tests::QueryFixture;
use super::*;
use crate::*;

type TestResult<T = ()> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

struct Authority {
    tenant: [u8; 16],
    changes: watch::Sender<u64>,
}

impl Authority {
    fn new(tenant: [u8; 16]) -> Self {
        Self {
            tenant,
            changes: watch::channel(1).0,
        }
    }
}

impl QueryAuthorization for Authority {
    fn check(&self, grant: &QueryGrant) -> Result<()> {
        if grant.selection.tenant_id != self.tenant || grant.revision != *self.changes.borrow() {
            return crate::QueryDeniedSnafu.fail();
        }
        Ok(())
    }
    fn changes(&self) -> watch::Receiver<u64> {
        self.changes.subscribe()
    }
    fn expires_ns(&self) -> Option<u64> {
        None
    }
}

struct Context(Vec<AnalysisContextVersionV1>);
impl GraphContextProvider for Context {
    fn facts(&self, record: &DiscoveryRecordV1) -> Result<Vec<AnalysisContextVersionV1>> {
        Ok(self
            .0
            .iter()
            .filter(|context| {
                GraphFactV1::try_from(*context).is_ok_and(|fact| fact.record_id == record.id)
            })
            .cloned()
            .collect())
    }
}

struct Clock;
impl QueryClock for Clock {
    fn now_ns(&self) -> Result<u64> {
        Ok(500)
    }
}

fn limits() -> QueryLimits {
    QueryLimits {
        extract_timeout: Duration::from_secs(30),
        evaluate_timeout: Duration::from_secs(30),
        ..Default::default()
    }
}

fn plan(selection: AnalysisSelectionV1, sql: &str, follow: bool) -> Result<QueryPlan> {
    QueryPlan::client(
        QueryGrant {
            principal: "query-graph".into(),
            revision: 1,
            selection,
        },
        QuerySql::admit(sql, vec![], follow)?,
    )
}

async fn query(
    fixture: &QueryFixture,
    selection: AnalysisSelectionV1,
    sql: &str,
) -> Result<QueryResult> {
    let tenant = selection.tenant_id;
    Arc::new(fixture.owner(limits())?)
        .query_client(
            plan(selection, sql, false)?,
            Arc::new(Authority::new(tenant)),
            201,
            Arc::new(AnalysisReadControl::default()),
        )
        .await
}

fn scope(fixture: &QueryFixture) -> AnalysisSelectionV1 {
    AnalysisSelectionV1::new(fixture.source.tenant_id, vec![fixture.source.clone()])
}

fn effect(cursor: u64, denied: bool, binding: u8) -> EvidenceRecord {
    EvidenceRecord {
        observed_boottime_ns: cursor * 1_000,
        ingested_utc_ns: cursor as i64,
        coverage_interval_id: vec![4; 16].into(),
        profile_generation_ref_id: Some(1),
        task_cookie: 9,
        process_lineage_id: vec![5; 16].into(),
        authority_domain_id: vec![6; 16].into(),
        execution_set_id: vec![7; 16].into(),
        exact_object_id: vec![8; 16].into(),
        reason: 9,
        decision: if denied {
            EffectPhysicalResultV1::DeniedBeforeEffect as u32
        } else {
            EffectPhysicalResultV1::UnknownAfterPreEffect as u32
        },
        effect_family: 2,
        operation: 4,
        configured_errno: -13,
        kernel_result: if denied { -13 } else { 0 },
        temporal_coverage: EvidenceTemporalCoverage::Complete as i32,
        decision_context: Some(EvidenceDecisionContext {
            schema_version: 1,
            original_kernel_sequence: cursor,
            process_instance_id: vec![8; 16],
            entry_instance_id: vec![9; 16],
            binding_id: vec![binding; 16],
            profile_generation_ref_id: 1,
            role_id: 1,
            state_id: 1,
            entry_rule_id: 1,
            ..Default::default()
        }),
        ..Default::default()
    }
}

fn process(graph: &GraphAndFindingOwner) -> Result<()> {
    for _ in 0..8 {
        graph.process(500)?;
    }
    Ok(())
}

async fn replacement(stream: &mut QueryStream) -> TestResult<QueryResult> {
    loop {
        let frame = tokio::time::timeout(Duration::from_secs(5), stream.next())
            .await?
            .ok_or("follow closed")??;
        match frame.payload {
            QueryPayload::Replace { result, .. } => return Ok(result),
            QueryPayload::Error { .. } | QueryPayload::Terminal { .. } => {
                return Err("follow failed".into())
            }
            _ => {}
        }
    }
}

#[tokio::test]
async fn control_graph_query_disabled_owner_is_explicit() -> TestResult {
    let fixture = QueryFixture::new()?;
    for relation in super::graph::RELATIONS {
        assert!(matches!(
            query(
                &fixture,
                scope(&fixture),
                &format!("SELECT COUNT(*) FROM {relation}")
            )
            .await,
            Err(crate::Error::QueryUnsupported { .. })
        ));
    }
    let catalog = query(
        &fixture,
        scope(&fixture),
        "SELECT DISTINCT relation, readiness FROM catalog WHERE relation = 'findings'",
    )
    .await?;
    assert_eq!(
        catalog.rows,
        vec![vec![
            Value::Text("findings".into()),
            Value::Text("disabled".into())
        ]]
    );
    assert!(matches!(
        query(
            &fixture,
            scope(&fixture),
            "SELECT COUNT(*) FROM notifications"
        )
        .await,
        Err(crate::Error::QueryUnsupported { .. })
    ));
    Ok(())
}

#[tokio::test]
async fn control_graph_query_scope_precedes_projection() -> TestResult {
    let fixture = QueryFixture::new()?;
    let graph = GraphAndFindingOwner::new(fixture.store.clone(), Arc::new(Context(vec![])))?;
    fixture.commit(1, 100, effect(1, true, 10))?;
    let mut other = fixture.source.clone();
    other.node_id = "other-node".into();
    other.source_id = [20; 16];
    fixture.commit_as(&other, 0, 1, 100, effect(1, true, 11))?;
    let mut foreign = other.clone();
    foreign.tenant_id = [2; 16];
    foreign.source_id = [21; 16];
    fixture.commit_as(&foreign, 0, 1, 100, effect(1, true, 12))?;
    process(&graph)?;
    for relation in super::graph::RELATIONS {
        let result = query(
            &fixture,
            scope(&fixture),
            &format!("SELECT COUNT(*) FROM {relation}"),
        )
        .await?;
        assert!(
            matches!(result.rows[0][0], Value::BigInt(value) if value > 0),
            "{relation}: {:?}",
            result.rows
        );
    }
    let rows = query(
        &fixture,
        scope(&fixture),
        "SELECT source_key, finding_revision, sensitivity, graph_sensitivity, effects FROM findings",
    )
    .await?;
    assert_eq!(rows.rows.len(), 1);
    let Value::Blob(source) = &rows.rows[0][0] else {
        return Err("source key absent".into());
    };
    assert_eq!(
        serde_json::from_slice::<EvidenceIntakeIdentityV1>(source)?,
        fixture.source
    );
    let Value::Blob(revision) = &rows.rows[0][1] else {
        return Err("revision absent".into());
    };
    let revision: GraphRevisionV1 = serde_json::from_slice(revision)?;
    assert_eq!(revision.evidence.len(), 1);
    assert_eq!(revision.evidence[0].stream, fixture.source);
    assert_eq!(rows.rows[0][2], Value::Text("tenant".into()));
    assert_eq!(rows.rows[0][3], Value::Text("tenant".into()));
    let Value::Blob(effects) = &rows.rows[0][4] else {
        return Err("effects absent".into());
    };
    let effects: Vec<GraphEffectV1> = serde_json::from_slice(effects)?;
    assert_eq!(effects.len(), 1);
    assert_eq!(effects[0].source_decision, 1);
    assert_eq!(effects[0].physical_result, GraphPhysicalResultV1::Prevented);
    assert_eq!(effects[0].kernel_result, -13);
    let mut selected = AnalysisSelectionV1::tenant(fixture.source.tenant_id);
    selected.nodes.push(fixture.source.node_id.clone());
    assert_eq!(
        query(&fixture, selected, "SELECT COUNT(*) FROM findings")
            .await?
            .rows,
        vec![vec![Value::BigInt(1)]]
    );
    let mut selected = AnalysisSelectionV1::tenant(fixture.source.tenant_id);
    selected.binding_ids.push([10; 16]);
    assert_eq!(
        query(&fixture, selected, "SELECT COUNT(*) FROM findings")
            .await?
            .rows,
        vec![vec![Value::BigInt(1)]]
    );
    let mut selected = scope(&fixture);
    selected.binding_ids.push([11; 16]);
    assert_eq!(
        query(&fixture, selected, "SELECT COUNT(*) FROM findings")
            .await?
            .rows,
        vec![vec![Value::BigInt(0)]]
    );
    let mut selected = scope(&fixture);
    selected
        .sources
        .exact_mut()
        .ok_or("sources absent")?
        .push(foreign);
    assert!(matches!(
        plan(selected, "SELECT COUNT(*) FROM findings", false),
        Err(crate::Error::QueryDenied { .. })
    ));
    Ok(())
}

#[tokio::test]
async fn control_graph_query_context_keeps_authority_and_sensitivity() -> TestResult {
    let fixture = QueryFixture::new()?;
    let subject = GraphSubjectKeyV1 {
        tenant_id: fixture.source.tenant_id,
        authority: GraphSubjectAuthorityV1::Provider {
            authority_id: "qualified-provider".into(),
        },
        kind: GraphSubjectKindV1::ProviderObject,
        identity: b"object-lifetime".to_vec(),
    };
    let fact = GraphFactV1 {
        record_id: DiscoveryRecordIdV1 {
            stream: fixture.source.clone(),
            cpu_id: 0,
            durable_cursor: 1,
        },
        value: GraphFactValueV1::Context {
            subject: subject.clone(),
            action_id: "provider-action".into(),
            classification: GraphContextActionV1::OutsideAuthority,
            proof_quality: ProofQualityV1::kernel_decision(TemporalCoverageV1::Unknown),
        },
    };
    let context = AnalysisContextVersionV1 {
        key: AnalysisContextKeyV1 {
            tenant_id: fixture.source.tenant_id,
            owner_id: "qualified-query-fact".into(),
            entity_key: b"provider-action".to_vec(),
            lifetime_key: b"action-lifetime".to_vec(),
            owner_revision: 1,
        },
        valid_from_utc_ns: None,
        valid_until_utc_ns: None,
        sensitivity: ContextSensitivityV1::HostRestricted,
        body: serde_json::to_vec(&fact)?,
    };
    let graph = GraphAndFindingOwner::new(
        fixture.store.clone(),
        Arc::new(Context(vec![context.clone()])),
    )?;
    fixture.commit(1, 100, effect(1, true, 10))?;
    process(&graph)?;
    let rows = query(&fixture, scope(&fixture),
        "SELECT subject_id, authority, graph_sensitivity FROM graph_subjects WHERE subject_kind = 'PROVIDER_OBJECT'").await?;
    assert_eq!(rows.rows.len(), 1);
    assert_eq!(rows.rows[0][0], Value::Blob(serde_json::to_vec(&subject)?));
    assert_eq!(
        rows.rows[0][1],
        Value::Blob(serde_json::to_vec(&subject.authority)?)
    );
    assert_eq!(rows.rows[0][2], Value::Text("host_restricted".into()));
    let rows = query(
        &fixture,
        scope(&fixture),
        "SELECT DISTINCT sensitivity, graph_sensitivity FROM findings",
    )
    .await?;
    assert_eq!(
        rows.rows,
        vec![vec![
            Value::Text("host_restricted".into()),
            Value::Text("host_restricted".into())
        ]]
    );
    let stored = fixture
        .store
        .context_version(&context.key)?
        .ok_or("context absent")?;
    assert_eq!(stored, context);
    Ok(())
}

#[tokio::test]
async fn control_graph_query_overlap_keeps_latest_finding_revision() -> TestResult {
    let fixture = QueryFixture::new()?;
    let graph = GraphAndFindingOwner::new(fixture.store.clone(), Arc::new(Context(vec![])))?;
    let mut frames = Vec::new();
    let mut ends = Vec::new();
    for cursor in 1..=257 {
        frames.extend(Vec::<u8>::try_from(&effect(cursor, cursor == 129, 10))?);
        ends.push(frames.len());
    }
    fixture.store.accept_validated_batch(
        fixture.source.clone(),
        ValidatedEvidenceBatchV1 {
            cpu_id: 0,
            first_cursor: 1,
            last_cursor: 257,
            intake_utc_ns: 100,
            framed_records: frames.into(),
            frame_ends: ends,
        },
    )?;
    process(&graph)?;
    let mut snapshots = Vec::new();
    let mut after = None;
    loop {
        let page = fixture.store.graph_snapshots(
            fixture.source.tenant_id,
            Some(&fixture.source),
            after.as_deref(),
            true,
        )?;
        if page.is_empty() {
            break;
        }
        after = page.last().map(|snapshot| snapshot.0.clone());
        snapshots.extend(page);
    }
    assert_eq!(snapshots.len(), 2);
    let expected = snapshots
        .iter()
        .max_by_key(|snapshot| snapshot.2)
        .ok_or("snapshot absent")?;
    assert_eq!(expected.1.first_cursor, 129);
    let finding = expected.1.findings.first().ok_or("finding absent")?;
    assert_eq!(
        snapshots
            .iter()
            .flat_map(|snapshot| &snapshot.1.findings)
            .filter(|candidate| candidate.finding_id == finding.finding_id)
            .count(),
        2
    );
    let retained = snapshots
        .iter()
        .map(|snapshot| {
            fixture
                .store
                .read_result(fixture.source.tenant_id, &snapshot.0)
                .map(|body| (snapshot.0.clone(), body))
        })
        .collect::<Result<Vec<_>>>()?;
    let result = query(
        &fixture,
        scope(&fixture),
        "SELECT finding_id, finding_revision, graph_result_id, commit_revision FROM findings",
    )
    .await?;
    assert_eq!(
        result.rows,
        vec![vec![
            Value::Text(finding.finding_id.clone()),
            Value::Blob(serde_json::to_vec(&finding.revision)?),
            Value::Text(expected.0.clone()),
            Value::UBigInt(expected.2)
        ]]
    );
    graph.refresh(&fixture.source, 600)?;
    for (id, body) in retained {
        assert_eq!(
            fixture.store.read_result(fixture.source.tenant_id, &id)?,
            body
        );
    }
    Ok(())
}

#[tokio::test]
async fn control_graph_query_mixed_binding_window_keeps_manifest_private() -> TestResult {
    let fixture = QueryFixture::new()?;
    let graph = GraphAndFindingOwner::new(fixture.store.clone(), Arc::new(Context(vec![])))?;
    fixture.commit(1, 100, effect(1, true, 10))?;
    fixture.commit(2, 100, effect(2, true, 11))?;
    process(&graph)?;
    assert_eq!(
        query(&fixture, scope(&fixture), "SELECT COUNT(*) FROM findings")
            .await?
            .rows,
        vec![vec![Value::BigInt(2)]]
    );
    let mut selected = scope(&fixture);
    selected.binding_ids.push([10; 16]);
    for relation in super::graph::RELATIONS {
        assert_eq!(
            query(
                &fixture,
                selected.clone(),
                &format!("SELECT COUNT(*) FROM {relation}")
            )
            .await?
            .rows,
            vec![vec![Value::BigInt(0)]],
            "{relation}"
        );
    }
    Ok(())
}

#[tokio::test]
async fn control_graph_query_limits_and_cancel_remain_explicit() -> TestResult {
    let fixture = QueryFixture::new()?;
    let graph = GraphAndFindingOwner::new(fixture.store.clone(), Arc::new(Context(vec![])))?;
    for cursor in 1..=3 {
        fixture.commit(cursor, 100, effect(cursor, true, 10))?;
    }
    process(&graph)?;
    let authority = Arc::new(Authority::new(fixture.source.tenant_id));
    let narrow = Arc::new(fixture.owner(QueryLimits {
        scan_bytes: 1,
        ..limits()
    })?);
    let result = narrow
        .query_client(
            plan(scope(&fixture), "SELECT COUNT(*) FROM findings", false)?,
            authority.clone(),
            500,
            Arc::new(AnalysisReadControl::default()),
        )
        .await;
    assert!(
        matches!(result, Err(crate::Error::AnalysisInputTooLarge { .. })),
        "{result:?}"
    );
    let narrow = Arc::new(fixture.owner(QueryLimits {
        input_bytes: 1_024,
        ..limits()
    })?);
    assert!(matches!(
        narrow
            .query_client(
                plan(scope(&fixture), "SELECT COUNT(*) FROM findings", false)?,
                authority.clone(),
                500,
                Arc::new(AnalysisReadControl::default())
            )
            .await,
        Err(crate::Error::AnalysisInputTooLarge { .. })
    ));
    let narrow = Arc::new(fixture.owner(QueryLimits {
        output_rows: 1,
        ..limits()
    })?);
    let result = narrow
        .query_client(
            plan(
                scope(&fixture),
                "SELECT finding_id FROM findings ORDER BY finding_id",
                false,
            )?,
            authority.clone(),
            500,
            Arc::new(AnalysisReadControl::default()),
        )
        .await?;
    assert!(result.limited);
    assert_eq!(result.rows.len(), 1);
    drop(result);
    assert!(matches!(
        narrow
            .query_client(
                plan(
                    scope(&fixture),
                    "SELECT finding_id FROM findings ORDER BY finding_id",
                    true
                )?,
                authority.clone(),
                500,
                Arc::new(AnalysisReadControl::default())
            )
            .await,
        Err(crate::Error::QueryLimit { .. })
    ));
    let complete = query(
        &fixture,
        scope(&fixture),
        "SELECT finding_revision FROM findings ORDER BY finding_id",
    )
    .await?;
    assert_eq!(complete.rows.len(), 3);
    let output_bytes = complete.output_bytes - 1;
    drop(complete);
    let byte_bound = Arc::new(fixture.owner(QueryLimits {
        output_bytes,
        ..limits()
    })?);
    assert!(matches!(
        byte_bound
            .query_client(
                plan(
                    scope(&fixture),
                    "SELECT finding_revision FROM findings ORDER BY finding_id",
                    true
                )?,
                authority.clone(),
                500,
                Arc::new(AnalysisReadControl::default())
            )
            .await,
        Err(crate::Error::QueryLimit { .. })
    ));
    let cancelled = Arc::new(AnalysisReadControl::default());
    cancelled.cancel()?;
    assert!(matches!(
        narrow
            .query_client(
                plan(scope(&fixture), "SELECT COUNT(*) FROM findings", false)?,
                authority,
                500,
                cancelled
            )
            .await,
        Err(crate::Error::AnalysisReadCancelled { .. })
    ));
    Ok(())
}

#[tokio::test]
async fn control_graph_query_follow_uses_committed_results() -> TestResult {
    let fixture = QueryFixture::new()?;
    let graph = GraphAndFindingOwner::new(fixture.store.clone(), Arc::new(Context(vec![])))?;
    fixture.commit(1, 100, effect(1, true, 10))?;
    process(&graph)?;
    let owner = Arc::new(fixture.owner(limits())?);
    let plan = plan(
        scope(&fixture),
        "SELECT finding_id, commit_revision FROM findings ORDER BY finding_id",
        true,
    )?;
    assert_eq!(plan.operation(), QueryOperation::Replace);
    let dependencies = plan.dependencies(500)?;
    let before = fixture
        .store
        .dependency_revision(&dependencies, &AnalysisReadControl::default())?
        .1;
    let unrelated = AnalysisContextVersionV1 {
        key: AnalysisContextKeyV1 {
            tenant_id: fixture.source.tenant_id,
            owner_id: "unrelated-owner".into(),
            entity_key: vec![1],
            lifetime_key: vec![2],
            owner_revision: 1,
        },
        valid_from_utc_ns: None,
        valid_until_utc_ns: None,
        sensitivity: ContextSensitivityV1::Tenant,
        body: vec![1],
    };
    fixture.store.commit_context(&unrelated)?;
    assert_eq!(
        fixture
            .store
            .dependency_revision(&dependencies, &AnalysisReadControl::default())?
            .1,
        before
    );
    let mut stream = owner.stream_client_clock(
        plan,
        None,
        Arc::new(Authority::new(fixture.source.tenant_id)),
        Arc::new(Clock),
    )?;
    let initial = replacement(&mut stream).await?;
    assert_eq!(initial.rows.len(), 1);
    drop(initial);
    fixture.commit(2, 101, effect(2, true, 10))?;
    process(&graph)?;
    let updated = replacement(&mut stream).await?;
    assert_eq!(updated.rows.len(), 2);
    assert!(
        fixture
            .store
            .dependency_revision(&dependencies, &AnalysisReadControl::default())?
            .1
            > before
    );
    stream.cancel()?;
    Ok(())
}

struct NotificationAuthority;
impl NotificationAuthorization for NotificationAuthority {
    fn check(&self, grant: &NotificationGrantV1, now: u64) -> Result<()> {
        grant.validate()?;
        if now >= grant.expires_utc_ns {
            return crate::QueryDeniedSnafu.fail();
        }
        Ok(())
    }
}
struct Sink;
impl NotificationSink for Sink {
    fn deliver(&self, _delivery: &NotificationDeliveryV1) -> NotificationSinkResultV1 {
        NotificationSinkResultV1::Failed {
            reason: NotificationFailureV1::SinkUnavailable,
        }
    }
}

#[tokio::test]
async fn control_graph_query_notifications_use_current_exact_refs() -> TestResult {
    let fixture = QueryFixture::new()?;
    let graph = GraphAndFindingOwner::new(fixture.store.clone(), Arc::new(Context(vec![])))?;
    fixture.commit(1, 100, effect(1, true, 10))?;
    process(&graph)?;
    let router = NotificationRouter::new(fixture.store.clone(), Arc::new(NotificationAuthority))?;
    let grant = NotificationGrantV1 {
        tenant_id: fixture.source.tenant_id,
        principal_id: [9; 16],
        principal: NotificationPrincipalV1::Human,
        authorization_revision: 1,
        routes: vec!["escalation".into(), "primary".into()],
        operations: vec![
            NotificationOperationV1::Configure,
            NotificationOperationV1::Read,
        ],
        max_sensitivity: ContextSensitivityV1::Tenant,
        expires_utc_ns: 10_000,
    };
    for route in ["escalation", "primary"] {
        router.configure(
            &grant,
            NotificationPolicyV1 {
                tenant_id: fixture.source.tenant_id,
                route_id: route.into(),
                revision: 1,
                package_ids: vec![if route == "primary" {
                    "HF-PROC-001".into()
                } else {
                    "HF-XNODE-001".into()
                }],
                minimum_priority: NotificationPriorityV1::High,
                acknowledgement_ns: 100,
                retry_limit: 4,
                retry_delay_ns: 1,
                escalation_route_id: "escalation".into(),
                max_sensitivity: ContextSensitivityV1::Tenant,
                allow_concerns: false,
            },
            10,
        )?;
    }
    assert_eq!(router.route(&graph, 100)?, 1);
    let current = graph.current_findings(fixture.source.tenant_id)?.remove(0);
    let owner = Arc::new(fixture.owner(limits())?);
    let plan = plan(scope(&fixture), "SELECT notification_id, notification_revision, deadline_utc_ns, finding_revision, finding_result_id FROM notifications", true)?;
    let dependencies = plan.dependencies(500)?;
    let before = fixture
        .store
        .dependency_revision(&dependencies, &AnalysisReadControl::default())?
        .1;
    let mut stream = owner.stream_client_clock(
        plan,
        None,
        Arc::new(Authority::new(fixture.source.tenant_id)),
        Arc::new(Clock),
    )?;
    let first = replacement(&mut stream).await?;
    assert_eq!(first.rows.len(), 1);
    let key = first.rows[0][0].clone();
    let initial = first.rows[0][1].clone();
    assert_eq!(first.rows[0][2], Value::UBigInt(200));
    assert_eq!(
        first.rows[0][3],
        Value::Blob(serde_json::to_vec(&current.1.revision)?)
    );
    assert_eq!(first.rows[0][4], Value::Text(current.0));
    drop(first);
    assert!(router.deliver(&graph, &Sink, 101)? > 0);
    let updated = replacement(&mut stream).await?;
    assert_eq!(updated.rows.len(), 1);
    assert_eq!(updated.rows[0][0], key);
    assert_ne!(updated.rows[0][1], initial);
    assert_eq!(updated.rows[0][2], Value::UBigInt(200));
    assert!(
        fixture
            .store
            .dependency_revision(&dependencies, &AnalysisReadControl::default())?
            .1
            > before
    );
    stream.cancel()?;
    drop(updated);
    drop(stream);
    let result = query(
        &fixture,
        scope(&fixture),
        "SELECT overdue, deadline_utc_ns, finding_available FROM notifications",
    )
    .await?;
    assert_eq!(
        result.rows,
        vec![vec![
            Value::Boolean(true),
            Value::UBigInt(200),
            Value::Boolean(true)
        ]]
    );
    let mut wrong = scope(&fixture);
    wrong.binding_ids.push([11; 16]);
    assert_eq!(
        query(&fixture, wrong, "SELECT COUNT(*) FROM notifications")
            .await?
            .rows,
        vec![vec![Value::BigInt(0)]]
    );
    let mut permitted = scope(&fixture);
    permitted.binding_ids.push([10; 16]);
    assert_eq!(
        query(
            &fixture,
            permitted.clone(),
            "SELECT COUNT(*) FROM notifications"
        )
        .await?
        .rows,
        vec![vec![Value::BigInt(1)]]
    );
    fixture.commit(2, 102, effect(2, true, 11))?;
    process(&graph)?;
    assert!(router.route(&graph, 102)? > 0);
    assert_eq!(
        query(&fixture, permitted, "SELECT COUNT(*) FROM notifications")
            .await?
            .rows,
        vec![vec![Value::BigInt(0)]]
    );
    let mut other = fixture.source.clone();
    other.node_id = "other-notification-node".into();
    other.source_id = [20; 16];
    fixture.commit_as(&other, 0, 1, 103, effect(1, true, 12))?;
    process(&graph)?;
    router.route(&graph, 103)?;
    assert_eq!(
        query(
            &fixture,
            scope(&fixture),
            "SELECT COUNT(*) FROM notifications"
        )
        .await?
        .rows,
        vec![vec![Value::BigInt(2)]]
    );
    assert_eq!(
        query(
            &fixture,
            AnalysisSelectionV1::new(fixture.source.tenant_id, vec![other]),
            "SELECT COUNT(*) FROM notifications"
        )
        .await?
        .rows,
        vec![vec![Value::BigInt(1)]]
    );
    Ok(())
}
