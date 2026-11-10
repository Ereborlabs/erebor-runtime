use super::findings::reference as reference_for;
use super::*;
use araphor_data::{
    AnalysisContextKeyV1, AnalysisContextVersionV1, ApprovedNotificationRouteV1, ManagedBudget,
    NotificationAttemptV1, NotificationDeliveryKindV1, NotificationErrorCodeV1 as Notice,
    NotificationFindingRefV1, NotificationGrantV1, NotificationKeyV1, NotificationObligationV1,
    NotificationOperationV1, NotificationPolicyV1, NotificationPrincipalV1, NotificationPriorityV1,
    NotificationRouteRefV1, NotificationSinkHealthV1, NOTIFICATION_ROUTE_OWNER,
    NOTIFICATION_STATE_OWNER,
};

#[path = "notifications/tables.rs"]
mod tables;

fn route(revision: u64) -> ApprovedNotificationRouteV1 {
    ApprovedNotificationRouteV1 {
        policy: NotificationPolicyV1 {
            tenant_id: [1; 16],
            route_id: "human".into(),
            revision,
            package_ids: vec!["managed-graph".into()],
            minimum_priority: NotificationPriorityV1::Info,
            acknowledgement_ns: 100,
            retry_limit: 3,
            retry_delay_ns: 10,
            escalation_route_id: "human".into(),
            max_sensitivity: ContextSensitivityV1::Tenant,
            allow_concerns: false,
        },
        grant: NotificationGrantV1 {
            tenant_id: [1; 16],
            principal_id: [2; 16],
            principal: NotificationPrincipalV1::Human,
            authorization_revision: 1,
            routes: vec!["human".into()],
            operations: vec![NotificationOperationV1::Configure],
            max_sensitivity: ContextSensitivityV1::HostRestricted,
            expires_utc_ns: u64::MAX,
        },
        approved_utc_ns: 1,
    }
}

fn route_context(
    route: &ApprovedNotificationRouteV1,
) -> araphor_data::Result<AnalysisContextVersionV1> {
    Ok(AnalysisContextVersionV1 {
        key: AnalysisContextKeyV1 {
            tenant_id: route.policy.tenant_id,
            owner_id: NOTIFICATION_ROUTE_OWNER.into(),
            entity_key: route.policy.route_id.as_bytes().to_vec(),
            lifetime_key: b"route".to_vec(),
            owner_revision: route.policy.revision,
        },
        valid_from_utc_ns: None,
        valid_until_utc_ns: None,
        sensitivity: ContextSensitivityV1::HostRestricted,
        body: route.encode()?,
    })
}

#[test]
fn prepared_routes_keep_limit() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = NativeStore::open_with_limits(directory.path().join("data"), Default::default(), araphor_data::StorageLimitsV1 {
        notification_routes: Some(0), ..Default::default()
    })?;
    store.commit_context(&route_context(&route(1))?)?;
    let control = AnalysisReadControl::default();
    let budget = super::super::graph::Budget;
    assert!(matches!(store.prepare_notifications([1; 16], &[], &[], &control, &budget),
        Err(araphor_data::Error::Notification { code: Notice::Limit, field: "route count", .. })));
    Ok(())
}

#[test]
fn prepared_related_keep_limit() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = NativeStore::open_with_limits(directory.path().join("data"), Default::default(), araphor_data::StorageLimitsV1 {
        notification_routes: Some(0), ..Default::default()
    })?;
    let (_, model, _, observation) = fixture(&store)?;
    let expected = finding(&observation, &super::super::publication::output(&model)?.datasets[0].batches[0])?.value;
    commit(&store, &model, &observation, 0)?;
    let reference = reference_for(&store, 0, &expected.finding_id)?;
    let mut first = state(reference.clone());
    let mut second = first.clone();
    first.key.notification_id = [5; 16];
    second.key.notification_id = [6; 16];
    store.commit_contexts(&[context(&first)?, context(&second)?])?;
    let control = AnalysisReadControl::default();
    let budget = super::super::graph::Budget;
    assert!(matches!(store.prepare_notifications([1; 16], &[reference], &[], &control, &budget),
        Err(araphor_data::Error::Notification { code: Notice::Limit, field: "related obligation count", .. })));
    Ok(())
}

fn state(reference: NotificationFindingRefV1) -> NotificationObligationV1 {
    NotificationObligationV1 {
        schema_version: 1,
        key: NotificationKeyV1 {
            tenant_id: [1; 16],
            notification_id: [3; 16],
        },
        revision: 1,
        finding: Some(reference),
        unconfirmed_concern: None,
        finding_revision: 1,
        package_id: "managed-graph".into(),
        required_action: None,
        sensitivity: ContextSensitivityV1::Tenant,
        source_priority: NotificationPriorityV1::Info,
        minimum_priority: NotificationPriorityV1::Info,
        route: Some(NotificationRouteRefV1 {
            route_id: "human".into(),
            revision: 1,
        }),
        escalation: None,
        first_seen_utc_ns: 1,
        deadline_utc_ns: Some(100),
        overdue_since_utc_ns: None,
        attempt_sequence: 0,
        attempts: Vec::new(),
        sink_health: NotificationSinkHealthV1::Unknown,
        failure: None,
        human_acknowledgement: None,
        agent_receipt: None,
        advisory: None,
    }
}

fn context(state: &NotificationObligationV1) -> araphor_data::Result<AnalysisContextVersionV1> {
    Ok(AnalysisContextVersionV1 {
        key: AnalysisContextKeyV1 {
            tenant_id: state.key.tenant_id,
            owner_id: NOTIFICATION_STATE_OWNER.into(),
            entity_key: state.key.notification_id.to_vec(),
            lifetime_key: b"obligation".to_vec(),
            owner_revision: state.revision,
        },
        valid_from_utc_ns: None,
        valid_until_utc_ns: None,
        sensitivity: state.sensitivity,
        body: state.encode()?,
    })
}

fn pending(state: &mut NotificationObligationV1, revision: u64) {
    state.attempt_sequence = 1;
    state.attempts.push(NotificationAttemptV1 {
        number: 1,
        kind: NotificationDeliveryKindV1::Finding,
        finding_revision: 1,
        context_revision: revision,
        priority: NotificationPriorityV1::Info,
        started_utc_ns: 5,
        completed_utc_ns: None,
        result: None,
    });
}

#[test]
fn prepared_notifications_keep_pending_subjects_routes_and_value_changes() -> TestResult {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("data");
    let store = NativeStore::open(&root)?;
    let (_, model, _, observation) = fixture(&store)?;
    let expected = finding(
        &observation,
        &super::super::publication::output(&model)?.datasets[0].batches[0],
    )?
    .value;
    commit(&store, &model, &observation, 0)?;
    let first = reference_for(&store, 0, &expected.finding_id)?;
    let subject = state(first.clone());
    store.commit_contexts(&[context(&subject)?, route_context(&route(1))?])?;
    commit(&store, &model, &observation, 1)?;
    let second = reference_for(&store, 1, &expected.finding_id)?;
    let mut head = subject.clone();
    head.revision = 2;
    head.finding_revision = 2;
    head.finding = Some(second.clone());
    head.route.as_mut().ok_or("route")?.revision = 2;
    let captured = context(&head)?;
    head.revision = 3;
    pending(&mut head, 1);
    store.commit_contexts_checked(
        &[
            (captured, 1),
            (context(&head)?, 2),
            (route_context(&route(2))?, 1),
        ],
        || Ok(()),
    )?;
    commit(&store, &model, &observation, 2)?;
    let third = reference_for(&store, 2, &expected.finding_id)?;
    let control = AnalysisReadControl::default();
    let budget = super::super::graph::Budget;
    let batch = store.prepare_notifications(
        [1; 16],
        &[third.clone(), third.clone()],
        &[head.key],
        &control,
        &budget,
    )?;
    assert_eq!(batch.heads()[&expected.finding_id], third.result_id);
    assert_eq!(batch.finding(&third)?, &expected);
    assert!(!batch.changed(&third, &second)?);
    assert_eq!(batch.subject(head.key, 1)?, &subject);
    assert_eq!(
        batch
            .states()
            .map(|(state, _)| state.clone())
            .collect::<Vec<_>>(),
        vec![head.clone()]
    );
    assert_eq!(batch.routes()?, &[route(2)]);
    assert_eq!(
        batch.route(&NotificationRouteRefV1 {
            route_id: "human".into(),
            revision: 1
        })?,
        Some(&route(1))
    );
    assert_eq!(batch.historical(&first)?.ok_or("historical")?.0, &expected);
    commit(&store, &model, &observation, 4)?;
    let fourth = reference_for(&store, 4, &expected.finding_id)?;
    assert_eq!(batch.finding(&third)?, &expected);
    drop(batch);
    store.database().inner().flush_memtables()?;
    store.database().inner().rotate_journal()?;
    store.database().inner().major_compact()?;
    drop(store);
    let store = NativeStore::open(&root)?;
    let batch =
        store.prepare_notifications([1; 16], &[fourth.clone()], &[head.key], &control, &budget)?;
    assert_eq!(batch.finding(&fourth)?.severity, FindingSeverityV1::Warning);
    assert!(batch.changed(&fourth, &second)?);
    assert_eq!(batch.subject(head.key, 1)?, &subject);
    assert_eq!(batch.historical(&first)?.ok_or("original")?.0, &expected);
    assert_eq!(
        batch.route(&subject.route.clone().ok_or("subject route")?)?,
        Some(&route(1))
    );
    assert!(matches!(
        batch.finding(&third),
        Err(Error::Notification {
            code: Notice::Conflict,
            ..
        })
    ));
    Ok(())
}

#[test]
fn source_notification_revisions() -> TestResult {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("data");
    let store = NativeStore::open(&root)?;
    let (_, model, source, observation) = fixture_source(&store, true)?;
    let scope = araphor_data::ProcessorScopeV1 {
        processor_id: araphor_data::GRAPH_PROCESSOR.into(),
        method_version: u64::from(araphor_data::GRAPH_SCHEMA_VERSION),
        identity: source,
    };
    store.register_processor(&scope, araphor_data::ProcessorClassV1::Required, 1)?;
    let expected = finding(
        &observation,
        &super::super::publication::output(&model)?.datasets[0].batches[0],
    )?
    .value;
    commit(&store, &model, &observation, 0)?;
    let first = reference_for(&store, 0, &expected.finding_id)?;
    let subject = state(first.clone());
    store.commit_contexts(&[context(&subject)?, route_context(&route(1))?])?;
    let mut head = subject.clone();
    head.revision = 2;
    pending(&mut head, subject.revision);
    store.commit_context_checked(&context(&head)?, subject.revision)?;
    commit(&store, &model, &observation, 1)?;
    let second = reference_for(&store, 1, &expected.finding_id)?;
    let control = AnalysisReadControl::default();
    let budget = super::super::graph::Budget;
    let batch = store.prepare_notifications(
        [1; 16],
        &[second.clone()],
        &[subject.key],
        &control,
        &budget,
    )?;
    assert!(!batch.changed(&second, &first)?);
    let (_, revision) = batch.historical(&first)?.ok_or("first source revision")?;
    assert_eq!(revision.evidence, vec![observation.id.clone()]);
    assert!(revision.context.iter().any(|key| key.owner_revision == 99));
    assert_eq!(
        batch
            .historical(&second)?
            .ok_or("second source revision")?
            .1,
        revision
    );
    drop(batch);
    commit(&store, &model, &observation, 2)?;
    commit(&store, &model, &observation, 4)?;
    let fourth = reference_for(&store, 4, &expected.finding_id)?;
    let batch = store.prepare_notifications(
        [1; 16],
        &[fourth.clone()],
        &[subject.key],
        &control,
        &budget,
    )?;
    assert!(batch.changed(&fourth, &first)?);
    assert_eq!(batch.subject(subject.key, subject.revision)?, &subject);
    let original = batch
        .historical(&first)?
        .ok_or("original source revision")?;
    let original = (original.0.clone(), original.1.clone());
    drop(batch);
    store.database().inner().flush_memtables()?;
    store.database().inner().major_compact()?;
    drop(store);
    let store = NativeStore::open(&root)?;
    let batch = store.prepare_notifications(
        [1; 16],
        &[fourth.clone()],
        &[subject.key],
        &control,
        &budget,
    )?;
    let historical = batch
        .historical(&first)?
        .ok_or("reopened source revision")?;
    assert_eq!(historical, (&original.0, &original.1));
    assert!(batch.changed(&fourth, &first)?);
    Ok(())
}

#[test]
fn source_instance_heads() -> TestResult {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("data");
    let store = NativeStore::open(&root)?;
    let (instance, model, source, observation) = fixture_source(&store, true)?;
    let scope = araphor_data::ProcessorScopeV1 {
        processor_id: araphor_data::GRAPH_PROCESSOR.into(),
        method_version: u64::from(araphor_data::GRAPH_SCHEMA_VERSION),
        identity: source,
    };
    store.register_processor(&scope, araphor_data::ProcessorClassV1::Required, 1)?;
    let value = finding(
        &observation,
        &super::super::publication::output(&model)?.datasets[0].batches[0],
    )?
    .value;
    commit(&store, &model, &observation, 0)?;
    let first = reference_for(&store, 0, &value.finding_id)?;
    let mut spec = instance.spec.clone();
    spec.id = "second-domain".into();
    let second = store.admit_managed(&spec, &instance.grant, || Ok(()))?;
    store.set_managed_running([1; 16], &spec.id, second.lifecycle, true, || Ok(()))?;
    commit_named(&store, &model, &observation, 0, &spec.id)?;
    let control = AnalysisReadControl::default();
    let budget = super::super::graph::Budget;
    let attempt = store
        .managed_attempt([1; 16], &spec.id, "domain-0", &control)?
        .ok_or("other attempt")?;
    let other = NotificationFindingRefV1 {
        finding_id: value.finding_id.clone(),
        result_id: attempt
            .receipt()
            .ok_or("other receipt")?
            .selected
            .result_id
            .clone(),
    };
    let batch = store.prepare_notifications([1; 16], &[other.clone()], &[], &control, &budget)?;
    assert_eq!(batch.heads()[&value.finding_id], other.result_id);
    drop(batch);
    commit_named(&store, &model, &observation, 7, "domain")?;
    let batch = store.prepare_notifications([1; 16], &[other.clone()], &[], &control, &budget)?;
    assert_eq!(batch.heads()[&value.finding_id], other.result_id);
    drop(batch);
    commit_named(&store, &model, &observation, 7, &spec.id)?;
    let batch = store.prepare_notifications([1; 16], &[other.clone()], &[], &control, &budget)?;
    assert!(!batch.heads().contains_key(&value.finding_id));
    drop(batch);
    let historical = store.graph_finding_batch([1; 16], &[first.clone()])?;
    assert_eq!(historical[&first.result_id].1[&value.finding_id], value);
    drop(attempt);
    store.database().inner().flush_memtables()?;
    store.database().inner().major_compact()?;
    drop(store);
    let store = NativeStore::open(&root)?;
    let batch = store.prepare_notifications([1; 16], &[other], &[], &control, &budget)?;
    assert!(!batch.heads().contains_key(&value.finding_id));
    assert_eq!(store.graph_finding_batch([1; 16], &[first])?, historical);
    Ok(())
}

#[test]
fn prepared_notifications_defer_basis_and_state_errors_separately() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = NativeStore::open(&directory.path().join("data"))?;
    let (_, model, _, observation) = fixture(&store)?;
    commit_expiry(&store, &model, &observation, 0, Some(u64::MAX))?;
    let finding = finding(
        &observation,
        &super::super::publication::output(&model)?.datasets[0].batches[0],
    )?
    .value;
    let current = reference_for(&store, 0, &finding.finding_id)?;
    let state = state(current.clone());
    store.commit_contexts(&[context(&state)?, route_context(&route(1))?])?;
    let view = store.view()?;
    let mut transaction = store.write()?;
    let mut removed = 0;
    for entry in view.snapshot().prefix(b"\0data/ref/raw/") {
        transaction.native().remove(entry?.0);
        removed += 1;
    }
    assert!(removed > 0);
    transaction.commit([])?;
    let control = AnalysisReadControl::default();
    let budget = super::super::graph::Budget;
    let mut foreign = state.key;
    foreign.tenant_id = [2; 16];
    foreign.notification_id = [4; 16];
    let batch = store.prepare_notifications(
        [1; 16],
        &[current.clone()],
        &[state.key, foreign],
        &control,
        &budget,
    )?;
    assert_eq!(batch.finding(&current)?, &finding);
    assert!(
        matches!(batch.historical(&current), Err(Error::PreparedNotification { source })
        if matches!(source.as_ref(), Error::Package { code: Code::Missing, .. }))
    );
    assert!(
        matches!(batch.check_state(foreign), Err(Error::PreparedNotification { source })
        if matches!(source.as_ref(), Error::Notification { code: Notice::Invalid, .. }))
    );
    batch.check_state(state.key)?;
    batch.check_related(&current)?;
    assert_eq!(batch.states().count(), 1);
    assert_eq!(batch.routes()?, &[route(1)]);
    Ok(())
}

#[test]
fn prepared_notifications_keep_missing_subject_errors_local() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = NativeStore::open(&directory.path().join("data"))?;
    let reference = NotificationFindingRefV1 {
        result_id: "absent".into(),
        finding_id: "finding".into(),
    };
    let mut state = state(reference.clone());
    state.revision = 2;
    pending(&mut state, 1);
    store.commit_contexts(&[context(&state)?, route_context(&route(1))?])?;
    let control = AnalysisReadControl::default();
    let budget = super::super::graph::Budget;
    let batch = store.prepare_notifications(
        [1; 16],
        &[reference.clone()],
        &[state.key],
        &control,
        &budget,
    )?;
    assert!(batch.historical(&reference)?.is_none());
    assert!(
        matches!(batch.subject(state.key, 1), Err(Error::PreparedNotification { source })
        if matches!(source.as_ref(), Error::Notification { code: Notice::Unavailable, .. }))
    );
    assert_eq!(batch.routes()?, &[route(1)]);
    assert_eq!(batch.states().count(), 1);
    Ok(())
}

type Hook = Box<dyn FnOnce() -> araphor_data::Result<()> + Send>;
struct Budget {
    limit: usize,
    hook: std::sync::Mutex<Option<Hook>>,
}
impl ManagedBudget for Budget {
    fn limit(&self) -> usize {
        self.limit
    }
    fn check(&self) -> araphor_data::Result<()> {
        Ok(())
    }
    fn reserve(&self, _: usize) -> araphor_data::Result<Box<dyn std::any::Any + Send + Sync>> {
        if let Some(hook) = self
            .hook
            .lock()
            .map_err(|_| Code::Denied.error("test hook"))?
            .take()
        {
            hook()?;
        }
        Ok(Box::new(()))
    }
}

#[test]
fn prepared_notifications_pin_one_view_and_abort_budget_or_cancellation() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = Arc::new(NativeStore::open(&directory.path().join("data"))?);
    store.commit_context(&route_context(&route(1))?)?;
    let next = route_context(&route(2))?;
    let writer = Arc::clone(&store);
    let budget = Budget {
        limit: usize::MAX,
        hook: std::sync::Mutex::new(Some(Box::new(move || {
            writer.commit_context_checked(&next, 1)?;
            Ok(())
        }))),
    };
    let control = AnalysisReadControl::default();
    let before = store.view()?.revision();
    let batch = store.prepare_notifications([1; 16], &[], &[], &control, &budget)?;
    assert!(store.view()?.revision() > before);
    assert_eq!(batch.routes()?, &[route(1)]);
    assert_eq!(
        store
            .context_head([1; 16], NOTIFICATION_ROUTE_OWNER, b"human", b"route")?
            .ok_or("new route")?
            .key
            .owner_revision,
        2
    );
    let limited = Budget {
        limit: 4096,
        hook: std::sync::Mutex::new(None),
    };
    assert!(matches!(
        store.prepare_notifications([1; 16], &[], &[], &control, &limited),
        Err(Error::Package {
            code: Code::Limit,
            ..
        })
    ));
    let cancelled = Arc::new(AnalysisReadControl::default());
    let cancel = Arc::clone(&cancelled);
    let cancelling = Budget {
        limit: usize::MAX,
        hook: std::sync::Mutex::new(Some(Box::new(move || cancel.cancel()))),
    };
    assert!(matches!(
        store.prepare_notifications([1; 16], &[], &[], &cancelled, &cancelling),
        Err(Error::AnalysisReadCancelled { .. })
    ));
    Ok(())
}

struct Meter(std::sync::atomic::AtomicUsize);
impl ManagedBudget for Meter {
    fn limit(&self) -> usize {
        usize::MAX
    }
    fn check(&self) -> araphor_data::Result<()> {
        Ok(())
    }
    fn reserve(&self, bytes: usize) -> araphor_data::Result<Box<dyn std::any::Any + Send + Sync>> {
        self.0
            .fetch_add(bytes, std::sync::atomic::Ordering::Relaxed);
        Ok(Box::new(()))
    }
}

#[test]
fn prepared_notifications_charge_retained_package_proofs() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = NativeStore::open(&directory.path().join("data"))?;
    let (_, model, _, observation) = fixture(&store)?;
    let artifact = PackageArtifactV1 {
        descriptor: sdk::Package::new(
            "proof-package",
            "1",
            vec![sdk::Model::new(
                "proof",
                Vec::new(),
                vec![sdk::Port::new(
                    "rows",
                    sdk::Schema::new(vec![sdk::Field::new("count", sdk::DataType::UInt64, false)]),
                )],
            )],
        ),
        implementations: vec![PackageImplementationV1::Sql {
            export: "proof".into(),
            program: SqlModelV1 {
                outputs: BTreeMap::from([(
                    "rows".into(),
                    format!("SELECT 1 AS count /*{}*/", "x".repeat(512 * 1024)),
                )]),
                ..Default::default()
            },
        }],
        fixtures: Vec::new(),
    };
    let image = PackageBundle::try_from(PackageBundleV1 {
        schema_version: 1,
        root: artifact.reference(),
        artifacts: vec![artifact],
    })?;
    store.install_package_image([1; 16], &image, || Ok(()))?;
    let proof = AnalysisContextVersionV1::from_package(
        &image,
        [1; 16],
        &image.bundle().root,
        "proof",
        "rows",
    )?;
    assert!(proof.body.len() < 1024);
    store.commit_context(&proof)?;
    commit(&store, &model, &observation, 5)?;
    let value = finding(
        &observation,
        &super::super::publication::output(&model)?.datasets[0].batches[0],
    )?
    .value;
    let reference = reference_for(&store, 5, &value.finding_id)?;
    let control = AnalysisReadControl::default();
    let unlimited = Meter(std::sync::atomic::AtomicUsize::new(0));
    let batch =
        store.prepare_notifications([1; 16], &[reference.clone()], &[], &control, &unlimited)?;
    assert_eq!(batch.finding(&reference)?, &value);
    assert!(batch
        .historical(&reference)?
        .ok_or("basis")?
        .1
        .context
        .contains(&proof.key));
    drop(batch);
    let retained = store
        .view()?
        .package_revision([1; 16], "proof-package", "1", &control)?
        .ok_or("retained proof")?;
    let baseline = {
        let store = NativeStore::open(&directory.path().join("baseline"))?;
        let (_, model, _, observation) = fixture(&store)?;
        store.install_package_image([1; 16], &image, || Ok(()))?;
        store.commit_context(&proof)?;
        commit(&store, &model, &observation, 6)?;
        let reference = reference_for(&store, 6, &value.finding_id)?;
        let meter = Meter(std::sync::atomic::AtomicUsize::new(0));
        let batch =
            store.prepare_notifications([1; 16], &[reference.clone()], &[], &control, &meter)?;
        assert_eq!(batch.finding(&reference)?, &value);
        assert!(!batch
            .historical(&reference)?
            .ok_or("baseline basis")?
            .1
            .context
            .contains(&proof.key));
        drop(batch);
        meter.0.load(std::sync::atomic::Ordering::Relaxed)
    };
    assert!(
        unlimited.0.load(std::sync::atomic::Ordering::Relaxed) > baseline + retained.artifact.len()
    );
    let limited = Budget {
        limit: baseline + retained.artifact.len() / 2,
        hook: std::sync::Mutex::new(None),
    };
    let prepared =
        store.prepare_notifications([1; 16], &[reference.clone()], &[], &control, &limited);
    match prepared {
        Err(Error::Package {
            code: Code::Limit, ..
        }) => {}
        Err(error) => {
            return Err(format!("expected fatal package proof limit, got {error:?}").into())
        }
        Ok(batch) => {
            return Err(format!(
                "expected fatal package proof limit, prepared basis error: {:?}",
                batch.historical(&reference).err()
            )
            .into())
        }
    }
    Ok(())
}
