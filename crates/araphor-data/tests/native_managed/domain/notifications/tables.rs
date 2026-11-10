use super::*;
use araphor_data::{AnalysisPositionPageV1, Selection, UnconfirmedNotificationConcernV1};

#[derive(Debug, PartialEq, serde::Deserialize)]
struct Row {
    notification_revision: u64,
    finding_value_id: Option<u64>,
    finding_available: bool,
    current_finding_result_id: Option<String>,
    same_graph_revision: bool,
    retry_utc_ns: Option<u64>,
    delivery_ready: bool,
    overdue: bool,
}

fn page(
    store: &NativeStore,
    view: Option<&araphor_data::analysis::native::DataView>,
    selection: &AnalysisSelectionV1,
    now: u64,
) -> araphor_data::Result<AnalysisPositionPageV1> {
    let requests = [(
        "notifications".into(),
        Some(
            (0..araphor_data::AnalysisStore::table_schemas()["notifications"]
                .fields()
                .len())
                .collect(),
        ),
    )]
    .into();
    let read = AnalysisTableRead {
        requests: &requests,
        event_ranges: None,
        now,
        mode: AnalysisReadModeV1::Complete,
    };
    let control = AnalysisReadControl::default();
    match view {
        Some(view) => store.read_tables_at(
            view,
            selection,
            read,
            AnalysisExtractLimits::default(),
            &control,
            None,
        ),
        None => store.read_tables(selection, read, AnalysisExtractLimits::default(), &control),
    }
}

fn rows(page: &AnalysisPositionPageV1) -> Result<Vec<Row>, Box<dyn std::error::Error>> {
    let mut rows = Vec::new();
    for batch in page.tables.get("notifications").into_iter().flatten() {
        rows.extend(serde_arrow::from_record_batch::<Vec<Row>>(batch)?);
    }
    Ok(rows)
}

fn foreign_call(
    store: &NativeStore,
    model: &sdk::Model,
) -> Result<String, Box<dyn std::error::Error>> {
    use araphor_data::analysis::native::{ManagedCommit, ManagedReturn};
    let mut model = model.clone();
    model.graph = None;
    model.reasons.clear();
    let fixture = Fixture::with_model(store, [2; 16], "foreign-notice", model.clone())?;
    let admitted = fixture.admit(store)?;
    let instance =
        store.set_managed_running([2; 16], "foreign-notice", admitted.lifecycle, true, || {
            Ok(())
        })?;
    let page = super::super::super::attempts::capture(store, &instance, false)?;
    let attempt = store.register_managed_attempt(
        &page.state,
        &super::super::super::attempts::request("foreign", true),
        || Ok(()),
    )?;
    let evaluation = super::super::super::publication::evaluation(&attempt);
    let output = super::super::super::publication::output(&model)?;
    let returns = [ManagedReturn {
        call: 10,
        evaluation: &evaluation,
        output: &output,
        changes: None,
        graph: None,
        retained: None,
    }];
    let input = ManagedCommit {
        control: &AnalysisReadControl::default(),
        budget: &super::super::super::graph::Budget,
        attempt: &attempt,
        completed: true,
        now_utc_ns: 1000,
        returns: &returns,
        selected: &output.datasets[0],
        selected_schema: &instance.spec.manifest.selected_schema,
    };
    let receipt = store.commit_managed(store.prepare_managed(&input)?, || Ok(()))?;
    Ok(receipt
        .results
        .get(&10)
        .ok_or("foreign call")?
        .result_id
        .clone())
}

#[test]
fn native_notification_finding_cuts() -> TestResult {
    for source_bound in [false, true] {
        let directory = tempfile::tempdir()?;
        let root = directory.path().join("data");
        let store = NativeStore::open(&root)?;
        store.enable_notification_owner()?;
        let (_, model, source, observation) = fixture_source(&store, source_bound)?;
        if source_bound {
            store.register_processor(
                &araphor_data::ProcessorScopeV1 {
                    processor_id: araphor_data::GRAPH_PROCESSOR.into(),
                    method_version: u64::from(araphor_data::GRAPH_SCHEMA_VERSION),
                    identity: source,
                },
                araphor_data::ProcessorClassV1::Required,
                1,
            )?;
        }
        let expected = finding(
            &observation,
            &super::super::super::publication::output(&model)?.datasets[0].batches[0],
        )?
        .value;
        commit(&store, &model, &observation, 0)?;
        let first = reference_for(&store, 0, &expected.finding_id)?;
        let subject = state(first.clone());
        store.commit_contexts(&[context(&subject)?, route_context(&route(1))?])?;
        let selection = AnalysisSelectionV1::tenant([1; 16]);
        let view = store.view()?;
        let initial = page(&store, Some(&view), &selection, 50)?;
        let original = rows(&initial)?.remove(0);
        assert!(original.finding_available);
        assert!(original.finding_value_id.is_some());
        assert_eq!(
            original.current_finding_result_id.as_deref(),
            Some(first.result_id.as_str())
        );
        assert!(original.same_graph_revision);
        commit(&store, &model, &observation, 1)?;
        let second = reference_for(&store, 1, &expected.finding_id)?;
        let current = page(&store, None, &selection, 50)?;
        let row = rows(&current)?.remove(0);
        assert_eq!(row.finding_value_id, original.finding_value_id);
        assert_eq!(
            row.current_finding_result_id.as_deref(),
            Some(second.result_id.as_str())
        );
        assert!(!row.same_graph_revision);
        assert_eq!(
            rows(&page(&store, Some(&view), &selection, 50)?)?,
            vec![original]
        );
        let subject_key = context(&subject)?.key;
        assert!(current.extraction.references.iter().any(|reference| matches!(reference,
            araphor_data::AnalysisReferenceV1::Context { reference, .. } if reference.key == subject_key)));
        let mut next = subject.clone();
        next.revision = 2;
        next.finding_revision = 2;
        next.finding = Some(second.clone());
        store.commit_context_checked(&context(&next)?, 1)?;
        let current = rows(&page(&store, None, &selection, 50)?)?.remove(0);
        assert_eq!(current.notification_revision, 2);
        assert!(current.same_graph_revision);
        let mut historical = selection.clone();
        historical.select_notifications(Selection::Exact(vec![context(&subject)?.key]))?;
        let old = rows(&page(&store, None, &historical, 50)?)?;
        if source_bound {
            assert_eq!(old.len(), 1);
            assert_eq!(old[0].notification_revision, 1);
            assert!(!old[0].same_graph_revision);
            assert_eq!(old[0].finding_value_id, current.finding_value_id);
        } else {
            assert!(old.is_empty());
        }
        store.database().inner().flush_memtables()?;
        store.database().inner().major_compact()?;
        drop(view);
        drop(store);
        let store = NativeStore::open(&root)?;
        store.enable_notification_owner()?;
        assert_eq!(rows(&page(&store, None, &historical, 50)?)?, old);
        assert_eq!(rows(&page(&store, None, &selection, 50)?)?, vec![current]);
    }
    Ok(())
}

#[test]
fn native_notification_route_time() -> TestResult {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("data");
    let store = NativeStore::open(&root)?;
    store.enable_notification_owner()?;
    let mut subject = state(NotificationFindingRefV1 {
        finding_id: "absent".into(),
        result_id: "absent".into(),
    });
    let first = context(&subject)?;
    subject.revision = 2;
    pending(&mut subject, 1);
    let waiting = context(&subject)?;
    subject.revision = 3;
    subject.sink_health = NotificationSinkHealthV1::Unhealthy;
    subject.failure = Some(araphor_data::NotificationFailureV1::SinkUnavailable);
    subject.attempts[0].completed_utc_ns = Some(10);
    subject.attempts[0].result = Some(araphor_data::NotificationSinkResultV1::Failed {
        reason: araphor_data::NotificationFailureV1::SinkUnavailable,
    });
    let old = context(&subject)?;
    let mut revised = route(2);
    revised.policy.retry_delay_ns = 1000;
    store.commit_contexts_checked(
        &[
            (first, 0),
            (waiting, 1),
            (old.clone(), 2),
            (route_context(&route(1))?, 0),
            (route_context(&revised)?, 1),
        ],
        || Ok(()),
    )?;
    let view = store.view()?;
    let selection = AnalysisSelectionV1::tenant([1; 16]);
    let before = page(&store, Some(&view), &selection, 15)?;
    let row = rows(&before)?.remove(0);
    assert_eq!(row.retry_utc_ns, Some(20));
    assert!(!row.delivery_ready);
    assert_eq!(before.next_change, Some(20));
    let due = page(&store, Some(&view), &selection, 20)?;
    assert!(rows(&due)?[0].delivery_ready);
    assert_eq!(due.extraction.meta, before.extraction.meta);
    assert!(rows(&page(&store, Some(&view), &selection, 100)?)?[0].overdue);
    subject.revision = 4;
    subject.route.as_mut().ok_or("route")?.revision = 2;
    store.commit_context_checked(&context(&subject)?, 3)?;
    let latest = page(&store, None, &selection, 15)?;
    assert_eq!(rows(&latest)?[0].retry_utc_ns, Some(1010));
    assert_eq!(latest.next_change, Some(100));
    let mut exact = selection;
    exact.select_notifications(Selection::Exact(vec![old.key]))?;
    assert_eq!(
        rows(&page(&store, None, &exact, 15)?)?[0].retry_utc_ns,
        Some(20)
    );
    drop(view);
    drop(store);
    let store = NativeStore::open(&root)?;
    store.enable_notification_owner()?;
    assert_eq!(
        rows(&page(&store, None, &exact, 15)?)?[0].retry_utc_ns,
        Some(20)
    );
    Ok(())
}

#[test]
fn native_notification_scope_limits() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = NativeStore::open(&directory.path().join("data"))?;
    store.enable_notification_owner()?;
    let (_, model, source, observation) = fixture_source(&store, true)?;
    store.register_processor(
        &araphor_data::ProcessorScopeV1 {
            processor_id: araphor_data::GRAPH_PROCESSOR.into(),
            method_version: u64::from(araphor_data::GRAPH_SCHEMA_VERSION),
            identity: source.clone(),
        },
        araphor_data::ProcessorClassV1::Required,
        1,
    )?;
    commit(&store, &model, &observation, 0)?;
    let expected = finding(
        &observation,
        &super::super::super::publication::output(&model)?.datasets[0].batches[0],
    )?
    .value;
    let first = reference_for(&store, 0, &expected.finding_id)?;
    let confirmed = state(first.clone());
    let mut concern = confirmed.clone();
    concern.key.notification_id = [4; 16];
    concern.finding = None;
    concern.unconfirmed_concern = Some(UnconfirmedNotificationConcernV1 {
        concern_id: [5; 16],
        model_label: "test".into(),
        summary: "concern".into(),
        context: Vec::new(),
        sensitivity: ContextSensitivityV1::Tenant,
        suggested_priority: NotificationPriorityV1::Info,
    });
    let mut missing = confirmed.clone();
    missing.key.notification_id = [6; 16];
    missing.finding.as_mut().ok_or("finding")?.result_id = "absent".into();
    let mut empty = confirmed.clone();
    empty.key.notification_id = [7; 16];
    empty.finding.as_mut().ok_or("finding")?.finding_id = "absent".into();
    store.commit_contexts(&[
        context(&confirmed)?,
        context(&concern)?,
        context(&missing)?,
        context(&empty)?,
    ])?;
    let all = AnalysisSelectionV1::tenant([1; 16]);
    assert_eq!(rows(&page(&store, None, &all, 50)?)?.len(), 4);
    let attempt = store
        .managed_attempt(
            [1; 16],
            "domain",
            "domain-0",
            &AnalysisReadControl::default(),
        )?
        .ok_or("saved attempt")?;
    let call = attempt
        .receipt()
        .ok_or("receipt")?
        .results
        .get(&10)
        .ok_or("call")?
        .result_id
        .clone();
    let processor = araphor_data::ProcessorScopeV1 {
        processor_id: "native-notice-result".into(),
        method_version: 1,
        identity: source.clone(),
    };
    store.register_processor(&processor, araphor_data::ProcessorClassV1::Required, 1)?;
    store.commit_result(&araphor_data::AnalysisResultCommitV1 {
        scope: processor,
        expected_cursor: 0,
        consumed_cursor: 1,
        coverage_revision: 0,
        context_revision: 0,
        result_id: "opaque-result".into(),
        body: vec![1, 2, 3],
        created_utc_ns: 1000,
        witnesses: Vec::new(),
        context_refs: Vec::new(),
    })?;
    let foreign = foreign_call(&store, &model)?;
    for (id, result) in [(8, call), (9, "opaque-result".into()), (10, foreign)] {
        let mut other = confirmed.clone();
        other.key.notification_id = [id; 16];
        other.finding.as_mut().ok_or("finding")?.result_id = result;
        store.commit_context(&context(&other)?)?;
    }
    let unscoped = rows(&page(&store, None, &all, 50)?)?;
    assert_eq!(unscoped.len(), 7);
    assert_eq!(
        unscoped.iter().filter(|row| row.finding_available).count(),
        1
    );
    let narrow = AnalysisSelectionV1::new([1; 16], vec![source]);
    let scoped = rows(&page(&store, None, &narrow, 50)?)?;
    assert_eq!(scoped.len(), 2);
    assert_eq!(scoped.iter().filter(|row| row.finding_available).count(), 1);
    let hidden = AnalysisSelectionV1::new([1; 16], vec![]);
    assert!(rows(&page(&store, None, &hidden, 50)?)?.is_empty());
    let mut bindings = hidden.clone();
    bindings.binding_ids.push([99; 16]);
    assert!(rows(&page(&store, None, &bindings, 50)?)?.is_empty());
    let requests = [(
        "notifications".into(),
        Some(
            (0..araphor_data::AnalysisStore::table_schemas()["notifications"]
                .fields()
                .len())
                .collect(),
        ),
    )]
    .into();
    let read = AnalysisTableRead {
        requests: &requests,
        event_ranges: None,
        now: 50,
        mode: AnalysisReadModeV1::Complete,
    };
    let control = AnalysisReadControl::default();
    assert!(matches!(
        store.read_tables_filtered(
            &hidden,
            &all,
            read,
            AnalysisExtractLimits::default(),
            &control,
            None,
        ),
        Err(Error::Package {
            code: Code::Denied,
            field: "managed source selection",
            ..
        })
    ));
    for limits in [
        AnalysisExtractLimits {
            input_bytes: 1,
            ..Default::default()
        },
        AnalysisExtractLimits {
            keys: Some(2),
            ..Default::default()
        },
    ] {
        assert!(store.read_tables(&all, read, limits, &control).is_err());
    }
    let cancelled = AnalysisReadControl::default();
    cancelled.cancel()?;
    assert!(store
        .read_tables(&all, read, AnalysisExtractLimits::default(), &cancelled)
        .is_err());
    Ok(())
}

#[test]
fn source_binding_keeps_target() -> TestResult {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("data");
    let store = NativeStore::open(&root)?;
    store.enable_notification_owner()?;
    use araphor_analysis_builtins::graph::{FindingResolve as _, ReasonDetails};
    let package = "HF-PROC-001";
    let (_, model, source, observation) =
        super::super::fixture_package(&store, true, Some([6; 16]), package)?;
    store.register_processor(
        &araphor_data::ProcessorScopeV1 {
            processor_id: araphor_data::GRAPH_PROCESSOR.into(),
            method_version: u64::from(araphor_data::GRAPH_SCHEMA_VERSION),
            identity: source.clone(),
        },
        araphor_data::ProcessorClassV1::Required,
        1,
    )?;
    let target = super::super::finding_for(
        package,
        &observation,
        &super::super::super::publication::output(&model)?.datasets[0].batches[0],
    )?;
    assert_eq!(target.value.effects[0].binding_id, Some([6; 16]));
    let external = GraphSubjectKeyV1 {
        tenant_id: [1; 16],
        authority: araphor_data::GraphSubjectAuthorityV1::External {
            authority_id: "external-context".into(),
        },
        kind: GraphSubjectKindV1::External,
        identity: vec![9; 16],
    };
    let value = araphor_data::GraphFactValueV1::Context {
        subject: external.clone(),
        action_id: "outside".into(),
        classification: araphor_data::GraphContextActionV1::OutsideAuthority,
        proof_quality: observation.proof_quality,
    };
    let fact = algorithm::Fact {
        record: 0,
        key: super::super::super::attempts::context(1).key,
        sensitivity: ContextSensitivityV1::Tenant,
        value: value.clone(),
    };
    let finding = FindingV1::resolve(
        package,
        FindingReasonV1::OutsideAuthority,
        ReasonDetails {
            record: 0,
            context: Some(0),
            reason: "OUTSIDE_AUTHORITY".into(),
            confirmed: false,
            evidence: vec![0],
            limits: Vec::new(),
        },
        std::slice::from_ref(&observation),
        std::slice::from_ref(&fact),
    )?;
    assert!(finding.effects.is_empty());
    let anchor = algorithm::Anchor {
        record: observation.id.clone(),
        fact: Some(algorithm::FactAnchor {
            record: observation.id.clone(),
            key: fact.key.clone(),
            sensitivity: fact.sensitivity,
            value: value.clone(),
        }),
    };
    let other = FindingMember {
        anchor: anchor.clone(),
        value: finding,
    };
    let subject = algorithm::SubjectChange {
        anchor,
        key: external,
    };
    let commands = [
        (
            DomainRelations::SUBJECTS.into(),
            command(
                &model,
                DomainRelations::SUBJECTS,
                b"context",
                &[DomainRelations::key(&subject.key)?],
                None,
                algorithm::SubjectChange::encode(&[subject])?,
                false,
            )?,
        ),
        (
            DomainRelations::FINDINGS.into(),
            command(
                &model,
                DomainRelations::FINDINGS,
                b"other-finding",
                &[DomainRelations::key(&other.value.finding_id)?],
                None,
                FindingMember::encode(&[other])?,
                false,
            )?,
        ),
    ];
    super::super::commit_commands(
        &store,
        &model,
        &observation,
        0,
        None,
        "domain",
        None,
        &commands,
        Some(&value),
    )?;
    let reference = reference_for(&store, 0, &target.value.finding_id)?;
    let mut obligation = state(reference);
    obligation.package_id = package.into();
    let mut approved = route(1);
    approved.policy.package_ids = vec![package.into()];
    store.commit_contexts(&[context(&obligation)?, route_context(&approved)?])?;
    let mut selection = AnalysisSelectionV1::new([1; 16], vec![source]);
    selection.binding_ids.push([6; 16]);
    let selected = rows(&page(&store, None, &selection, 50)?)?;
    assert_eq!(selected.len(), 1);
    assert!(selected[0].finding_available);
    let mut foreign = selection.clone();
    foreign.binding_ids = vec![[99; 16]];
    assert!(rows(&page(&store, None, &foreign, 50)?)?.is_empty());
    store.database().inner().flush_memtables()?;
    store.database().inner().major_compact()?;
    drop(store);
    let store = NativeStore::open(&root)?;
    store.enable_notification_owner()?;
    assert_eq!(rows(&page(&store, None, &selection, 50)?)?, selected);
    Ok(())
}
