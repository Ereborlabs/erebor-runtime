use super::*;
use crate::{
    EvidenceIntakeIdentityV1, PackageErrorCodeV1 as Code, ProcessorClassV1, ProcessorScopeV1,
    ProcessorStateV1, GRAPH_PROCESSOR, GRAPH_SCHEMA_VERSION,
};

impl Fixture {
    fn health_job(
        &self,
        store: &AnalysisStore,
        id: &str,
        destination: ManagedDestination,
    ) -> TestResult<ManagedInstance> {
        let mut spec = self.instance.spec.clone();
        spec.id = id.into();
        if let ManagedDestination::Graph { source, .. } = &destination {
            spec.tenant = source.tenant_id;
        }
        if matches!(
            destination,
            ManagedDestination::Notification
                | ManagedDestination::Graph {
                    operation: ManagedGraphOperation::Expire,
                    ..
                }
        ) {
            let sql = "SELECT 1::BIGINT UNSIGNED AS value";
            spec.definition = ResolvedDefinition::new(
                Definition {
                    name: "health-metadata".into(),
                    description: String::new(),
                    labels: BTreeMap::new(),
                    program: Program::Sql {
                        source: Source::Inline { inline: sql.into() },
                    },
                },
                sql.into(),
                Vec::new(),
            )?;
            spec.manifest.definition = spec.definition.digest()?;
            spec.manifest.calls.clear();
        }
        spec.destination = destination;
        let mut grant = self.instance.grant.clone();
        grant.selection = AnalysisSelectionV1::tenant(spec.tenant);
        store.admit_definition(spec.tenant, &spec.definition, || Ok(()))?;
        Ok(store.admit_managed(&spec, &grant, || Ok(()))?)
    }
}

fn graph(
    source: &EvidenceIntakeIdentityV1,
    operation: ManagedGraphOperation,
) -> ManagedDestination {
    ManagedDestination::Graph {
        source: source.clone(),
        events_sql: if operation == ManagedGraphOperation::Evaluate {
            "SELECT * FROM events".into()
        } else {
            String::new()
        },
        calls: if operation == ManagedGraphOperation::Evaluate {
            BTreeSet::from([10, 11])
        } else {
            BTreeSet::new()
        },
        operation,
    }
}

fn scope(source: &EvidenceIntakeIdentityV1) -> ProcessorScopeV1 {
    ProcessorScopeV1 {
        processor_id: GRAPH_PROCESSOR.into(),
        method_version: u64::from(GRAPH_SCHEMA_VERSION),
        identity: source.clone(),
    }
}

#[test]
fn graph_failures_survive_reopen() -> TestResult {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("store");
    let store = AnalysisStore::open(&root)?;
    let fixture = Fixture::admit(&store)?;
    let source = crate::analysis::tests::identity();
    let scope = scope(&source);
    store.register_processor(&scope, ProcessorClassV1::Required, 1)?;
    let evaluate = fixture.health_job(
        &store,
        "custom-detector",
        graph(&source, ManagedGraphOperation::Evaluate),
    )?;
    let expire = fixture.health_job(
        &store,
        "custom-expiry",
        graph(&source, ManagedGraphOperation::Expire),
    )?;
    let control = AnalysisReadControl::default();
    for job in [&expire, &evaluate] {
        assert!(!job.running);
        store.set_managed_running(
            job.spec.tenant,
            &job.spec.id,
            job.lifecycle,
            true,
            || Ok(()),
        )?;
        let resume = store.managed_resume(job.spec.tenant, &job.spec.id, &control)?;
        let failed = store.fail_managed(&resume, Code::Limit, || Ok(()))?;
        let stopped = store.set_managed_running(
            job.spec.tenant,
            &job.spec.id,
            failed.lifecycle,
            false,
            || Ok(()),
        )?;
        assert!(!stopped.running);
        let health = store.processor_health(&scope)?.ok_or("Graph health")?;
        assert_eq!(health.state, ProcessorStateV1::ProcessingFailed);
        assert!(health.incomplete);
    }
    drop(store);
    let store = AnalysisStore::open(&root)?;
    for (id, failed) in [("custom-expiry", true), ("custom-detector", false)] {
        let before = store
            .processor_health(&scope)?
            .ok_or("saved Graph health")?;
        assert_eq!(before.state, ProcessorStateV1::ProcessingFailed);
        assert!(before.incomplete);
        let current = store
            .managed_instance(source.tenant_id, id, &control)?
            .ok_or("saved job")?;
        assert!(!current.running);
        store.remove_managed(&current, || Ok(()))?;
        let health = store
            .processor_health(&scope)?
            .ok_or("Graph health after removal")?;
        assert_eq!(health.state == ProcessorStateV1::ProcessingFailed, failed);
        assert_eq!(health.incomplete, failed);
    }
    Ok(())
}

#[test]
fn graph_health_current_destination() -> TestResult {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("store");
    let store = AnalysisStore::open(&root)?;
    let fixture = Fixture::admit(&store)?;
    let source = crate::analysis::tests::identity();
    let other = EvidenceIntakeIdentityV1 {
        node_boot_id: [8; 16],
        ..source.clone()
    };
    let candidate_source = EvidenceIntakeIdentityV1 {
        source_epoch: 2,
        ..source.clone()
    };
    let foreign = EvidenceIntakeIdentityV1 {
        tenant_id: [9; 16],
        ..source.clone()
    };
    for identity in [&source, &other, &candidate_source, &foreign] {
        store.register_processor(&scope(identity), ProcessorClassV1::Required, 1)?;
    }
    let control = AnalysisReadControl::default();
    for (id, destination) in [
        (
            ManagedGraphOperation::Evaluate.instance_id(&source),
            ManagedDestination::Selected,
        ),
        (
            ManagedGraphOperation::Expire.instance_id(&source),
            ManagedDestination::Notification,
        ),
        (
            "other-boot".into(),
            graph(&other, ManagedGraphOperation::Evaluate),
        ),
        (
            "foreign".into(),
            graph(&foreign, ManagedGraphOperation::Expire),
        ),
    ] {
        let job = fixture.health_job(&store, &id, destination)?;
        store.set_managed_running(job.spec.tenant, &id, job.lifecycle, true, || Ok(()))?;
        let resume = store.managed_resume(job.spec.tenant, &id, &control)?;
        let failed = store.fail_managed(&resume, Code::Limit, || Ok(()))?;
        let stopped =
            store.set_managed_running(job.spec.tenant, &id, failed.lifecycle, false, || Ok(()))?;
        assert!(!stopped.running);
        let health = store
            .processor_health(&scope(&source))?
            .ok_or("unrelated Graph health")?;
        assert_ne!(health.state, ProcessorStateV1::ProcessingFailed);
        assert!(!health.incomplete);
    }
    let job = fixture.health_job(
        &store,
        "custom",
        graph(&source, ManagedGraphOperation::Evaluate),
    )?;
    store.set_managed_running(source.tenant_id, &job.spec.id, job.lifecycle, true, || {
        Ok(())
    })?;
    let resume = store.managed_resume(source.tenant_id, &job.spec.id, &control)?;
    let failed = store.fail_managed(&resume, Code::Limit, || Ok(()))?;
    let current = store.set_managed_running(
        source.tenant_id,
        &job.spec.id,
        failed.lifecycle,
        false,
        || Ok(()),
    )?;
    assert!(!current.running);
    let mut next = current.spec.clone();
    next.destination = graph(&candidate_source, ManagedGraphOperation::Evaluate);
    let candidate = store.prepare_managed_version(&current, &next, || Ok(()))?;
    assert_ne!(candidate.generation, current.generation);
    assert_eq!(
        store.managed_instance(source.tenant_id, &job.spec.id, &control)?,
        Some(current)
    );
    for (identity, failed) in [
        (&source, true),
        (&other, true),
        (&foreign, true),
        (&candidate_source, false),
    ] {
        let health = store
            .processor_health(&scope(identity))?
            .ok_or("destination Graph health")?;
        assert_eq!(health.state == ProcessorStateV1::ProcessingFailed, failed);
        assert_eq!(health.incomplete, failed);
    }
    drop(store);
    let store = AnalysisStore::open(&root)?;
    for (identity, failed) in [
        (&source, true),
        (&other, true),
        (&foreign, true),
        (&candidate_source, false),
    ] {
        let health = store
            .processor_health(&scope(identity))?
            .ok_or("reopened destination health")?;
        assert_eq!(health.state == ProcessorStateV1::ProcessingFailed, failed);
        assert_eq!(health.incomplete, failed);
    }
    Ok(())
}
