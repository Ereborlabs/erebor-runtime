use std::collections::{BTreeMap, BTreeSet};

use sdk::arrow_array::{
    Array, BinaryArray, BooleanArray, Int32Array, Int64Array, RecordBatch, StringArray,
    TimestampMicrosecondArray, UInt32Array, UInt64Array,
};

use super::*;
use crate::analysis::graph_rows::tests::fixture::CommitFixture;
use crate::*;

type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;

fn read(
    store: &AnalysisStore,
    selection: &AnalysisSelectionV1,
    names: &[&str],
    now: u64,
) -> crate::Result<AnalysisPositionPageV1> {
    let relations = names
        .iter()
        .map(|name| (*name).to_owned())
        .collect::<BTreeSet<_>>();
    let columns = names
        .iter()
        .map(|name| {
            let schema = &AnalysisStore::table_schemas()[*name];
            ((*name).to_owned(), (0..schema.fields().len()).collect())
        })
        .collect::<BTreeMap<_, BTreeSet<_>>>();
    let page = store.read_tables(
        selection,
        AnalysisTableRead {
            relations: &relations,
            columns: &columns,
            event_ranges: None,
            inputs: None,
            mode: AnalysisReadModeV1::Complete,
            now,
        },
        AnalysisExtractLimits::default(),
        &AnalysisReadControl::default(),
    )?;
    for name in names {
        if let Some(batches) = page.tables.get(*name) {
            for batch in batches {
                assert_eq!(batch.schema(), AnalysisStore::table_schemas()[*name]);
                for (field, array) in batch.schema_ref().fields().iter().zip(batch.columns()) {
                    assert_eq!(array.data_type(), field.data_type());
                    if !field.is_nullable() {
                        assert_eq!(array.null_count(), 0);
                    }
                }
            }
        }
    }
    Ok(page)
}

fn column<'a, A: Array + 'static>(
    batch: &'a RecordBatch,
    field: &str,
) -> std::result::Result<&'a A, Box<dyn std::error::Error>> {
    batch
        .column_by_name(field)
        .ok_or_else(|| format!("native column is absent: {field}"))?
        .as_any()
        .downcast_ref::<A>()
        .ok_or_else(|| format!("native column type differs: {field}").into())
}

fn row(
    page: &AnalysisPositionPageV1,
    table: &str,
    mut ordinal: usize,
) -> std::result::Result<RecordBatch, Box<dyn std::error::Error>> {
    let batches = page
        .tables
        .get(table)
        .ok_or_else(|| format!("native table is absent: {table}"))?;
    for batch in batches {
        if ordinal < batch.num_rows() {
            return Ok(batch.slice(ordinal, 1));
        }
        ordinal -= batch.num_rows();
    }
    Err(format!("native table row is absent: {table}").into())
}

#[test]
fn graph_event_coverage_fields() -> TestResult {
    let fixture = CommitFixture::new()?;
    let receipt = fixture.store.commit_graph(&fixture.request, true)?;
    let graph = &fixture.snapshot;
    let mut selection = AnalysisSelectionV1::new(
        graph.scope.identity.tenant_id,
        vec![graph.scope.identity.clone()],
    );
    selection.select_graphs(
        Selection::Exact(vec![fixture.request.result_id.clone()]),
        None,
    )?;
    let names = [
        "events",
        "coverage",
        "findings",
        "relationships",
        "graph_subjects",
        "graph_branches",
        "correlation_packages",
        "policy_observations",
        "graph_manifest",
    ];
    let page = read(&fixture.store, &selection, &names, 100)?;
    for (name, expected) in [
        ("events", 1),
        ("coverage", 2),
        ("findings", graph.findings.len()),
        ("relationships", graph.graph.edges.len()),
        ("graph_subjects", graph.graph.subjects.len()),
        ("graph_branches", graph.graph.branches.len()),
        ("correlation_packages", graph.packages.len()),
        (
            "policy_observations",
            graph
                .findings
                .iter()
                .map(|finding| finding.policy_provenance.len())
                .sum(),
        ),
        ("graph_manifest", 1),
    ] {
        assert!(expected > 0, "{name}");
        assert_eq!(
            page.tables[name]
                .iter()
                .map(RecordBatch::num_rows)
                .sum::<usize>(),
            expected,
            "{name}"
        );
    }
    let event = &page.tables["events"][0];
    assert_eq!(column::<UInt64Array>(event, "source_cursor")?.value(0), 1);
    assert_eq!(column::<UInt32Array>(event, "operation")?.value(0), 2);
    assert_eq!(
        column::<Int32Array>(event, "configured_errno")?.value(0),
        -13
    );
    assert_eq!(column::<UInt64Array>(event, "task_cookie")?.value(0), 9);
    assert_eq!(
        column::<BinaryArray>(event, "process_instance_id")?.value(0),
        [8; 16]
    );
    assert_eq!(
        column::<TimestampMicrosecondArray>(event, "received_at")?.value(0),
        0
    );
    let coverage = row(&page, "coverage", 0)?;
    let interval = row(&page, "coverage", 1)?;
    assert_eq!(
        column::<StringArray>(&coverage, "kind")?.value(0),
        "receipt"
    );
    assert_eq!(
        column::<StringArray>(&interval, "kind")?.value(0),
        "interval"
    );
    assert_eq!(
        column::<StringArray>(&interval, "state")?.value(0),
        "HEALTHY"
    );
    assert_eq!(
        column::<UInt64Array>(&interval, "closing_attempted")?.value(0),
        1
    );
    assert_eq!(
        column::<UInt64Array>(&interval, "opening_attempted")?.value(0),
        0
    );
    assert!(column::<UInt64Array>(&coverage, "interval_revision")?.is_null(0));
    assert_eq!(
        column::<UInt64Array>(&interval, "interval_revision")?.value(0),
        1
    );
    for name in &names[2..] {
        let batch = &page.tables[*name][0];
        assert_eq!(
            column::<BinaryArray>(batch, "tenant_id")?.value(0),
            graph.scope.identity.tenant_id
        );
        assert_eq!(
            column::<BinaryArray>(batch, "source_key")?.value(0),
            graph.scope.identity.key()
        );
        assert_eq!(
            column::<StringArray>(batch, "graph_result_id")?.value(0),
            fixture.request.result_id
        );
        assert_eq!(
            column::<UInt64Array>(batch, "commit_revision")?.value(0),
            receipt.commit_revision
        );
        assert_eq!(
            column::<BinaryArray>(batch, "graph_revision")?.value(0),
            serde_json::to_vec(&graph.input_manifest)?
        );
    }
    let finding = &page.tables["findings"][0];
    assert_eq!(
        column::<StringArray>(finding, "finding_id")?.value(0),
        graph.findings[0].finding_id
    );
    assert_eq!(
        column::<BinaryArray>(finding, "effects")?.value(0),
        serde_json::to_vec(&graph.findings[0].effects)?
    );
    assert_eq!(
        column::<Int64Array>(finding, "window_start_utc_ns")?.value(0),
        graph.findings[0].window_start_utc_ns
    );
    let edges = &page.tables["relationships"][0];
    assert_eq!(
        column::<BinaryArray>(edges, "relationship_key")?.value(0),
        serde_json::to_vec(&graph.graph.edges[0].key)?
    );
    let subjects = &page.tables["graph_subjects"][0];
    assert_eq!(
        column::<BinaryArray>(subjects, "subject_id")?.value(0),
        serde_json::to_vec(&graph.graph.subjects[0])?
    );
    assert!(column::<UInt32Array>(subjects, "traversal_depth")?.is_null(0));
    let branches = &page.tables["graph_branches"][0];
    assert_eq!(
        column::<StringArray>(branches, "package_id")?.value(0),
        graph.graph.branches[0].package_id
    );
    let packages = &page.tables["correlation_packages"][0];
    assert_eq!(
        column::<BinaryArray>(packages, "required_inputs")?.value(0),
        serde_json::to_vec(&graph.packages[0].required_inputs)?
    );
    let observations = &page.tables["policy_observations"][0];
    assert_eq!(
        column::<BinaryArray>(observations, "observations")?.value(0),
        serde_json::to_vec(&graph.findings[0].policy_provenance[0].observations)?
    );
    let manifest = &page.tables["graph_manifest"][0];
    assert_eq!(
        column::<UInt64Array>(manifest, "subject_count")?.value(0),
        graph.graph.subjects.len() as u64
    );
    assert_eq!(
        column::<UInt64Array>(manifest, "relationship_count")?.value(0),
        graph.graph.edges.len() as u64
    );
    assert_eq!(
        page.extraction.sources[0].receipt.identity,
        graph.scope.identity
    );
    assert!(page
        .extraction
        .witnesses
        .iter()
        .any(|witness| witness.identity == graph.scope.identity && witness.cursor == 1));
    assert!(page.extraction.references.iter().any(|reference| reference
        .result()
        .is_some_and(|result| result.result_id == fixture.request.result_id)));
    let foreign = read(
        &fixture.store,
        &AnalysisSelectionV1::tenant([9; 16]),
        &names,
        100,
    )?;
    assert!(foreign
        .tables
        .values()
        .flatten()
        .all(|batch| batch.num_rows() == 0));
    assert!(foreign.extraction.witnesses.is_empty());
    Ok(())
}

#[test]
fn context_notification_fields() -> TestResult {
    let fixture = CommitFixture::new()?;
    fixture.store.commit_graph(&fixture.request, true)?;
    fixture.store.enable_notification_owner()?;
    let tenant = fixture.snapshot.scope.identity.tenant_id;
    let document = DiscoveryContextRevisionV1 {
        imported_utc_ns: 20,
        document: DiscoveryContextDocumentV1 {
            schema_version: DISCOVERY_SCHEMA_VERSION,
            tenant_id: tenant,
            id: "native-runbook".into(),
            revision: 1,
            kind: DiscoveryContextKindV1::Runbook,
            subject: AnalysisContextKeyV1 {
                tenant_id: tenant,
                owner_id: "inventory".into(),
                entity_key: vec![1],
                lifetime_key: vec![2],
                owner_revision: 1,
            },
            method: DiscoveryMethodV1 {
                id: "native-method".into(),
                revision: 2,
            },
            origin: "retained operator input".into(),
            valid_from_utc_ns: 10,
            valid_until_utc_ns: Some(1000),
            sensitivity: ContextSensitivityV1::Tenant,
            approver: Some("reviewer".into()),
            text: "Read the retained source facts.".into(),
        },
    };
    let context = AnalysisContextVersionV1::try_from(&document)?;
    let context_revision = fixture.store.commit_context(&context)?;
    let target = WorkloadTargetFactV1 {
        node_id: fixture.snapshot.scope.identity.node_id.clone(),
        workload_binding_generation_digest: "generation".into(),
        execution_set_id: "execution".into(),
        cluster_uid: "cluster".into(),
        namespace_uid: "namespace".into(),
        controller_uid: "controller".into(),
        service_account_uid: "account".into(),
        pod_uid: "pod".into(),
        container_id: "container".into(),
        container_name: "worker".into(),
        container_kind: ContainerKindV1::Application,
        image_digest: "sha256:image".into(),
        pod_labels: BTreeMap::from([("app".into(), "worker".into())]),
        kubernetes: Some(KubernetesWorkloadIdentityV1 {
            namespace_name: "default".into(),
            pod_name: "worker-pod".into(),
            profile_id: "profile".into(),
            policy_source_revision_id: "policy".into(),
            binding_id: uuid::Uuid::from_bytes([10; 16]).to_string(),
            protected_scope_id: "scope".into(),
            workload_selector_id: "selector".into(),
            kubernetes_node_name: "node".into(),
            kubernetes_node_uid: "node-uid".into(),
            node_boot_id: uuid::Uuid::from_bytes([2; 16]).to_string(),
            label_epoch: 1,
        }),
    };
    let target_context = AnalysisContextVersionV1 {
        key: AnalysisContextKeyV1 {
            tenant_id: tenant,
            owner_id: "mithril-control/target".into(),
            entity_key: vec![3],
            lifetime_key: vec![4],
            owner_revision: 1,
        },
        valid_from_utc_ns: Some(10),
        valid_until_utc_ns: None,
        sensitivity: ContextSensitivityV1::Tenant,
        body: serde_json::to_vec(&target)?,
    };
    fixture.store.commit_context(&target_context)?;
    let obligation = NotificationObligationV1 {
        schema_version: 1,
        key: NotificationKeyV1 {
            tenant_id: tenant,
            notification_id: [7; 16],
        },
        revision: 1,
        finding: Some(NotificationFindingRefV1 {
            finding_id: fixture.snapshot.findings[0].finding_id.clone(),
            result_id: fixture.request.result_id.clone(),
        }),
        unconfirmed_concern: None,
        finding_revision: 1,
        package_id: fixture.snapshot.findings[0].package_id.clone(),
        required_action: Some("inspect".into()),
        sensitivity: ContextSensitivityV1::Tenant,
        source_priority: NotificationPriorityV1::Warning,
        minimum_priority: NotificationPriorityV1::Info,
        route: Some(NotificationRouteRefV1 {
            route_id: "operator".into(),
            revision: 2,
        }),
        escalation: None,
        first_seen_utc_ns: 1,
        deadline_utc_ns: Some(100),
        overdue_since_utc_ns: Some(100),
        attempt_sequence: 1,
        attempts: vec![NotificationAttemptV1 {
            number: 1,
            kind: NotificationDeliveryKindV1::Finding,
            finding_revision: 1,
            context_revision: 1,
            priority: NotificationPriorityV1::Warning,
            started_utc_ns: 2,
            completed_utc_ns: Some(3),
            result: Some(NotificationSinkResultV1::Accepted {
                receipt: "retained".into(),
            }),
        }],
        sink_health: NotificationSinkHealthV1::Unhealthy,
        failure: Some(NotificationFailureV1::TransportFailed),
        human_acknowledgement: Some(NotificationAcknowledgementV1 {
            request_id: [1; 16],
            principal_id: [2; 16],
            authorization_revision: 1,
            finding_revision: 1,
            acknowledged_utc_ns: 4,
        }),
        agent_receipt: Some(NotificationAgentReceiptV1 {
            request_id: [3; 16],
            principal_id: [4; 16],
            authorization_revision: 1,
            received_utc_ns: 4,
        }),
        advisory: Some(NotificationAdvisoryV1 {
            suggested_priority: NotificationPriorityV1::Critical,
            model_label: "native".into(),
        }),
    };
    let mut concern = obligation.clone();
    concern.key.notification_id = [8; 16];
    concern.finding = None;
    concern.unconfirmed_concern = Some(UnconfirmedNotificationConcernV1 {
        concern_id: [9; 16],
        model_label: "native".into(),
        summary: "Review retained evidence".into(),
        context: vec![context.key.clone()],
        sensitivity: ContextSensitivityV1::Tenant,
        suggested_priority: NotificationPriorityV1::Info,
    });
    concern.route = None;
    concern.required_action = None;
    concern.human_acknowledgement = None;
    concern.agent_receipt = None;
    concern.advisory = None;
    concern.failure = None;
    concern.attempts.clear();
    for value in [&obligation, &concern] {
        value.validate()?;
        fixture.store.commit_context(&AnalysisContextVersionV1 {
            key: AnalysisContextKeyV1 {
                tenant_id: tenant,
                owner_id: NOTIFICATION_STATE_OWNER.into(),
                entity_key: value.key.notification_id.to_vec(),
                lifetime_key: b"obligation".to_vec(),
                owner_revision: value.revision,
            },
            valid_from_utc_ns: None,
            valid_until_utc_ns: None,
            sensitivity: value.sensitivity,
            body: serde_json::to_vec(value)?,
        })?;
    }
    let mut selection = AnalysisSelectionV1::tenant(tenant);
    selection.contexts = Selection::Exact(vec![context.key.clone(), target_context.key.clone()]);
    selection.select_targets(true, false)?;
    selection.select_notifications(Selection::All)?;
    let names = ["context_versions", "context", "targets", "notifications"];
    let page = read(&fixture.store, &selection, &names, 150)?;
    assert_eq!(
        page.tables["context_versions"]
            .iter()
            .map(RecordBatch::num_rows)
            .sum::<usize>(),
        2
    );
    assert_eq!(
        page.tables["context"]
            .iter()
            .map(RecordBatch::num_rows)
            .sum::<usize>(),
        2
    );
    assert_eq!(page.tables["targets"][0].num_rows(), 1);
    assert_eq!(
        page.tables["notifications"]
            .iter()
            .map(RecordBatch::num_rows)
            .sum::<usize>(),
        2
    );
    let versions = &page.tables["context_versions"][0];
    assert_eq!(
        column::<BinaryArray>(versions, "body")?.value(0),
        context.body
    );
    let document_row = row(&page, "context", 0)?;
    let target_row = row(&page, "context", 1)?;
    let documents = &document_row;
    assert_eq!(
        column::<StringArray>(documents, "kind")?.value(0),
        "RUNBOOK"
    );
    assert_eq!(
        column::<StringArray>(documents, "trust")?.value(0),
        "REVIEWED"
    );
    assert_eq!(
        column::<StringArray>(documents, "text")?.value(0),
        document.document.text
    );
    assert_eq!(
        column::<UInt64Array>(documents, "imported_utc_ns")?.value(0),
        20
    );
    assert!(column::<StringArray>(&target_row, "kind")?.is_null(0));
    let targets = &page.tables["targets"][0];
    assert_eq!(
        column::<BinaryArray>(targets, "binding_id")?.value(0),
        [10; 16]
    );
    assert_eq!(
        column::<BinaryArray>(targets, "node_boot_id")?.value(0),
        [2; 16]
    );
    assert_eq!(
        column::<StringArray>(targets, "container_kind")?.value(0),
        "APPLICATION"
    );
    assert_eq!(
        column::<BinaryArray>(targets, "pod_labels")?.value(0),
        serde_json::to_vec(&target.pod_labels)?
    );
    let finding_row = row(&page, "notifications", 0)?;
    let concern_row = row(&page, "notifications", 1)?;
    let notifications = &finding_row;
    assert_eq!(
        column::<StringArray>(notifications, "kind")?.value(0),
        "finding"
    );
    assert_eq!(
        column::<StringArray>(&concern_row, "kind")?.value(0),
        "unconfirmed_concern"
    );
    assert!(column::<BooleanArray>(notifications, "finding_available")?.value(0));
    assert!(!column::<BooleanArray>(&concern_row, "finding_available")?.value(0));
    assert_eq!(
        column::<BinaryArray>(notifications, "finding_revision")?.value(0),
        serde_json::to_vec(&fixture.snapshot.findings[0].revision)?
    );
    assert_eq!(
        column::<StringArray>(notifications, "priority")?.value(0),
        "critical"
    );
    assert_eq!(
        column::<StringArray>(notifications, "failure")?.value(0),
        "transport_failed"
    );
    assert_eq!(
        column::<BinaryArray>(notifications, "delivery_attempts")?.value(0),
        serde_json::to_vec(&obligation.attempts)?
    );
    assert_eq!(
        column::<BinaryArray>(notifications, "human_acknowledgement")?.value(0),
        serde_json::to_vec(
            obligation
                .human_acknowledgement
                .as_ref()
                .ok_or("finding acknowledgement")?
        )?
    );
    assert_eq!(
        column::<BinaryArray>(&concern_row, "unconfirmed_concern")?.value(0),
        serde_json::to_vec(
            concern
                .unconfirmed_concern
                .as_ref()
                .ok_or("notification concern")?
        )?
    );
    assert!(!column::<BooleanArray>(notifications, "overdue")?.value(0));
    assert!(column::<BooleanArray>(&concern_row, "overdue")?.value(0));
    assert!(page.extraction.references.iter().any(|reference| reference
        .context()
        .is_some_and(|reference| reference.key == context.key
            && reference.commit_revision == context_revision)));
    assert!(page.extraction.references.iter().any(|reference| reference
        .result()
        .is_some_and(|reference| reference.result_id == fixture.request.result_id)));
    let foreign = read(
        &fixture.store,
        &AnalysisSelectionV1::tenant([9; 16]),
        &names,
        150,
    )?;
    assert!(foreign
        .tables
        .values()
        .flatten()
        .all(|batch| batch.num_rows() == 0));
    Ok(())
}

#[test]
fn trace_recipe_measurement_fields() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = AnalysisStore::open(directory.path().join("analysis"))?;
    let recipe = TraceRecipeV1::SyscallErrors;
    let manifest = recipe.manifest()?;
    let mut intent = crate::analysis::raw::tests::trace_intent()?;
    intent.source = manifest.source.clone();
    intent.bindings[0].identity.source_sha256 = intent.source.sha256;
    store.accept_trace(&intent)?;
    let identity = &intent.bindings[0].identity;
    let bytes =
        include_bytes!("../../../../../../mithril-e2e/fixtures/observability/k3s-syscall-map.json")
            .to_vec();
    let frames = vec![TraceFrameV1 {
        execution_id: identity.execution_id,
        sequence: 1,
        kind: TraceFrameKindV1::Data,
        bytes,
    }];
    let measurements = recipe
        .measurements(&frames[0])
        .ok_or("recipe measurements")?;
    let mut terminal = crate::analysis::raw::tests::trace_terminal(1, frames[0].bytes.len() as u64);
    terminal.kernel_lost_events = Some(3);
    terminal.ready_at_unix_ns = Some(101);
    terminal.cleanup = TraceCleanupV1::Verified;
    store.append_trace(
        identity,
        &TraceBatchV1 {
            execution_id: identity.execution_id,
            frames,
            terminal: Some(terminal),
        },
        102,
    )?;
    let mut selection = AnalysisSelectionV1::new(identity.tenant_id, Vec::new());
    selection.traces = Selection::Exact(vec![identity.clone()]);
    let names = [
        "traces",
        "trace_output",
        "trace_measurements",
        "trace_recipes",
    ];
    let page = read(&store, &selection, &names, 200)?;
    assert_eq!(page.tables["traces"][0].num_rows(), 1);
    assert_eq!(page.tables["trace_output"][0].num_rows(), 2);
    assert_eq!(
        page.tables["trace_measurements"]
            .iter()
            .map(RecordBatch::num_rows)
            .sum::<usize>(),
        measurements.len()
    );
    assert_eq!(page.tables["trace_recipes"][0].num_rows(), 2);
    let traces = &page.tables["traces"][0];
    assert_eq!(
        column::<BinaryArray>(traces, "source")?.value(0),
        manifest.source.bytes
    );
    assert_eq!(
        column::<StringArray>(traces, "terminal_reason")?.value(0),
        "completed"
    );
    assert_eq!(
        column::<StringArray>(traces, "cleanup")?.value(0),
        "verified"
    );
    assert_eq!(
        column::<UInt64Array>(traces, "kernel_lost_events")?.value(0),
        3
    );
    let output = &page.tables["trace_output"][0];
    assert_eq!(column::<StringArray>(output, "kind")?.value(0), "data");
    assert_eq!(column::<StringArray>(output, "kind")?.value(1), "terminal");
    let measured = &page.tables["trace_measurements"][0];
    for (row, expected) in measurements.iter().enumerate() {
        let ids = column::<UInt32Array>(measured, "syscall_id")?;
        if let Some(id) = expected.syscall_id {
            assert_eq!(ids.value(row), id);
        } else {
            assert!(ids.is_null(row));
        }
        assert_eq!(
            column::<Int64Array>(measured, "errno")?.value(row),
            expected.errno
        );
        assert_eq!(
            column::<UInt64Array>(measured, "count")?.value(row),
            expected.count
        );
        assert!(column::<BooleanArray>(measured, "cumulative")?.value(row));
        assert!(!column::<BooleanArray>(measured, "atomic_snapshot")?.value(row));
    }
    let recipes = &page.tables["trace_recipes"][0];
    for (row, recipe) in [TraceRecipeV1::SyscallErrors, TraceRecipeV1::FailedOpens]
        .into_iter()
        .enumerate()
    {
        let manifest = recipe.manifest()?;
        assert_eq!(
            column::<BinaryArray>(recipes, "source_sha256")?.value(row),
            manifest.source.sha256
        );
        assert_eq!(
            column::<BinaryArray>(recipes, "measurement_keys")?.value(row),
            serde_json::to_vec(&manifest.measurement_keys)?
        );
        assert_eq!(
            column::<UInt32Array>(recipes, "maximum_map_keys")?.value(row),
            manifest.maximum_map_keys
        );
    }
    assert_eq!(page.extraction.trace_reads(), &[identity.request_id]);
    assert!(page
        .extraction
        .witnesses
        .iter()
        .any(
            |witness| matches!(&witness.identity, AnalysisStreamIdentityV1::Diagnostic(saved) if saved == identity)
                && witness.cursor == 1
        ));
    let foreign = read(
        &store,
        &AnalysisSelectionV1::tenant([9; 16]),
        &["traces", "trace_output", "trace_measurements"],
        200,
    )?;
    assert!(foreign
        .tables
        .values()
        .flatten()
        .all(|batch| batch.num_rows() == 0));
    assert!(foreign.extraction.trace_reads().is_empty());
    Ok(())
}
