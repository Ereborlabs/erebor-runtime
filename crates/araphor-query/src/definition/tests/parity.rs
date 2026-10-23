use std::sync::mpsc;
use std::time::Duration;

use araphor_analysis_builtins::{discovery as builtin, Rows};
use araphor_data::{AnalysisReadControl, AnalysisSelectionV1};

use super::*;
use crate::definition::{CallResult, DefinitionOutput, Invocation};
use crate::execution::Session;

async fn prepared(
    fixture: &Fixture,
    tenant: u8,
    counts: [u64; 2],
    control: &AnalysisReadControl,
) -> TestResult<(Session, PreparedDefinition)> {
    let mut session =
        fixture
            .engine
            .session(AnalysisSelectionV1::tenant([tenant; 16]), control, 123)?;
    let package = builtin::Discovery::package();
    let model = &package.exports[2];
    for data in datasets(tenant, counts)? {
        let port = &model
            .inputs
            .iter()
            .find(|input| input.port.name == data.name)
            .ok_or("input port")?
            .port;
        session.register(
            &format!("parity_{}", data.name),
            Arc::new(port.schema.clone()),
            &data.batches,
        )?;
    }
    let prepared = session
        .prepare_definition(&Fixture::sql(
            r#"SELECT * FROM "discovery"."1".groups('groups',
            atoms => (SELECT * FROM parity_atoms),
            coverage => (SELECT * FROM parity_coverage))"#,
        ))
        .await?;
    Ok((session, prepared))
}

async fn entered(receiver: mpsc::Receiver<()>) -> TestResult {
    tokio::task::spawn_blocking(move || receiver.recv_timeout(Duration::from_secs(30))).await??;
    Ok(())
}

fn returned(output: &DefinitionOutput) -> TestResult<&CallResult> {
    assert_eq!(output.calls.len(), 1);
    Ok(output.calls.values().next().ok_or("call return")?)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn nonempty_tenant_guests_overlap() -> TestResult {
    let fixture = Fixture::limits(Limits {
        global_evaluations: Some(2),
        tenant_evaluations: Some(1),
        ..Default::default()
    })?;
    let descriptor = builtin::Discovery::package();
    let bundle = PackageBundleV1 {
        schema_version: 1,
        root: PackageRefV1 {
            package_id: descriptor.id.clone(),
            revision: descriptor.revision.clone(),
        },
        artifacts: vec![PackageArtifactV1 {
            implementations: vec![PackageImplementationV1::Wasm {
                exports: descriptor
                    .exports
                    .iter()
                    .map(|model| model.name.clone())
                    .collect(),
                artifact: araphor_analysis_builtins::components::DISCOVERY.to_vec(),
            }],
            descriptor,
            fixtures: Vec::new(),
        }],
    };
    fixture.install(&bundle)?;
    fixture
        .engine
        .store()
        .install_package_image([2; 16], &bundle, || Ok(()))?;
    let revision = fixture.engine.store().meta()?.commit_revision;
    let first_control = AnalysisReadControl::default();
    let second_control = AnalysisReadControl::default();
    let (first, first_plan) = prepared(&fixture, 1, [2, 3], &first_control).await?;
    let (second, second_plan) = prepared(&fixture, 2, [7, 11], &second_control).await?;
    assert!(Arc::ptr_eq(first.engine(), second.engine()));
    let (entry, observed) = mpsc::channel();
    let (first_release, waiting) = mpsc::channel();
    fixture.engine.guest_entry(entry, Some(waiting))?;
    let first = tokio::spawn(async move {
        first
            .execute_definition(
                &first_plan,
                Invocation {
                    id: "tenant-1".into(),
                    ..Default::default()
                },
            )
            .await
    });
    entered(observed).await?;
    let (entry, observed) = mpsc::channel();
    let (second_release, waiting) = mpsc::channel();
    fixture.engine.guest_entry(entry, Some(waiting))?;
    let second = tokio::spawn(async move {
        second
            .execute_definition(
                &second_plan,
                Invocation {
                    id: "tenant-2".into(),
                    ..Default::default()
                },
            )
            .await
    });
    entered(observed).await?;
    assert!(fixture.engine.reserve_evaluation([1; 16]).is_err());
    assert!(fixture.engine.reserve_evaluation([2; 16]).is_err());
    first_release.send(())?;
    let first = tokio::time::timeout(Duration::from_secs(30), first).await???;
    assert_group(returned(&first)?, 1, 5)?;
    assert!(!second.is_finished());
    drop(fixture.engine.reserve_evaluation([1; 16])?);
    assert!(fixture.engine.reserve_evaluation([2; 16]).is_err());
    second_control.check()?;
    second_release.send(())?;
    let second = tokio::time::timeout(Duration::from_secs(30), second).await???;
    assert_group(returned(&second)?, 2, 18)?;
    first_control.check()?;
    second_control.check()?;
    drop(fixture.engine.reserve_evaluation([1; 16])?);
    drop(fixture.engine.reserve_evaluation([2; 16])?);
    assert_eq!(fixture.engine.store().meta()?.commit_revision, revision);
    Ok(())
}

#[tokio::test]
async fn preparation_precedes_evaluation_deadline() -> TestResult {
    let fixture = Fixture::limits(Limits {
        input_capacity: Some(128 * 1024 * 1024),
        output_capacity: Some(16 * 1024 * 1024),
        evaluate_timeout: Some(Duration::from_nanos(1)),
        ..Default::default()
    })?;
    let bundle = super::execution::component("wasm", "evaluate")?;
    fixture.install(&bundle)?;
    let control = AnalysisReadControl::with_timeout(Duration::from_secs(30))?;
    let session = fixture
        .engine
        .session(AnalysisSelectionV1::tenant([1; 16]), &control, 123)?;
    let definition = session
        .prepare_definition(&Fixture::sql(
            r#"SELECT * FROM "runtime-fixture"."1".evaluate(mode => 'echo', amount => 42)"#,
        ))
        .await?;
    let retained = fixture.engine.memory().input_reserved();
    let bytes = araphor_analysis_builtins::components::RUNTIME;
    assert!(!fixture.engine.guest_cached(bytes)?);
    for id in ["cold", "cached"] {
        let error = session
            .execute_definition(
                &definition,
                Invocation {
                    id: id.into(),
                    seed: Some(7),
                    ..Default::default()
                },
            )
            .await
            .err()
            .ok_or("tiny evaluation deadline succeeded")?;
        assert_eq!(
            crate::Failure::from(&error),
            crate::Failure::DeadlineExceeded,
            "{error:?}"
        );
        assert!(fixture.engine.guest_cached(bytes)?);
        control.check()?;
        drop(fixture.engine.reserve_evaluation([1; 16])?);
        assert_eq!(fixture.engine.memory().input_reserved(), retained);
        let pressure = fixture.engine.memory().reserve_input(
            fixture
                .engine
                .limits()
                .input_capacity
                .ok_or("configured input capacity")?
                .saturating_sub(retained),
        )?;
        assert!(fixture.engine.memory().reserve_input(1).is_err());
        drop(pressure);
        drop(
            fixture.engine.memory().reserve_output(
                fixture
                    .engine
                    .limits()
                    .output_capacity
                    .ok_or("configured output capacity")?,
            )?,
        );
    }
    let (plan, _) = fixture
        .engine
        .prepare("SELECT 42 AS value", Vec::new())
        .await?;
    let error = session
        .physical(&plan, &session.state()?)
        .await
        .err()
        .ok_or("ordinary SQL planning deadline succeeded")?;
    assert_eq!(
        crate::Failure::from(&error),
        crate::Failure::DeadlineExceeded,
        "{error:?}"
    );
    control.check()?;
    drop(definition);
    drop(
        fixture.engine.memory().reserve_input(
            fixture
                .engine
                .limits()
                .input_capacity
                .ok_or("input capacity")?,
        )?,
    );
    Ok(())
}

#[tokio::test]
async fn views_prepare_hidden_guests() -> TestResult {
    use datafusion::datasource::{provider_as_source, view::ViewTable};
    use datafusion::logical_expr::TableScan;

    let fixture = Fixture::limits(Limits {
        evaluate_timeout: Some(Duration::from_nanos(1)),
        ..Default::default()
    })?;
    fixture.install(&super::execution::component("wasm", "evaluate")?)?;
    let control = AnalysisReadControl::with_timeout(Duration::from_secs(30))?;
    let session = fixture
        .engine
        .session(AnalysisSelectionV1::tenant([1; 16]), &control, 123)?;
    let definition = session
        .prepare_definition(&Fixture::sql(
            r#"SELECT * FROM "runtime-fixture"."1".evaluate(mode => 'echo', amount => 42)"#,
        ))
        .await?;
    let mut plan = definition.plan;
    for name in ["inner_guest", "outer_guest"] {
        plan = LogicalPlan::TableScan(TableScan::try_new(
            name,
            provider_as_source(Arc::new(ViewTable::new(plan, None))),
            None,
            Vec::new(),
            None,
        )?);
    }
    assert!(Fixture::calls(&plan)?.is_empty());
    assert!(PackageCall::contains(&plan)?);
    let bytes = araphor_analysis_builtins::components::RUNTIME;
    assert!(!fixture.engine.guest_cached(bytes)?);
    let mut state = session.state()?;
    state
        .config_mut()
        .set_extension(Arc::new(fixture.engine.reserve_evaluation([1; 16])?));
    let physical = session.physical(&plan, &state).await?;
    assert!(fixture.engine.guest_cached(bytes)?);
    drop(physical);
    drop(state);
    control.check()?;
    drop(fixture.engine.reserve_evaluation([1; 16])?);
    Ok(())
}

#[tokio::test]
async fn preparation_cancellation_keeps_leases() -> TestResult {
    use futures_util::FutureExt as _;

    for cancel in [true, false] {
        let fixture = Fixture::limits(Limits {
            tenant_evaluations: Some(1),
            input_capacity: Some(128 * 1024 * 1024),
            output_capacity: Some(16 * 1024 * 1024),
            ..Default::default()
        })?;
        fixture.install(&super::execution::component("wasm", "evaluate")?)?;
        let control = AnalysisReadControl::with_timeout(Duration::from_secs(30))?;
        let session =
            fixture
                .engine
                .session(AnalysisSelectionV1::tenant([1; 16]), &control, 123)?;
        let definition = session
            .prepare_definition(&Fixture::sql(
                r#"SELECT * FROM "runtime-fixture"."1".evaluate(mode => 'echo', amount => 42)"#,
            ))
            .await?;
        let (entry, observed) = mpsc::channel();
        let (release, waiting) = mpsc::channel();
        fixture.engine.preparation_entry(entry, waiting)?;
        let mut execution =
            Box::pin(session.execute_definition(&definition, Invocation::default()));
        tokio::select! {
            result = &mut execution => {
                return Err(format!("preparation ended before entry: {:?}", result.err()).into());
            }
            result = entered(observed) => result?,
        }
        assert!(fixture.engine.reserve_evaluation([1; 16]).is_err());
        if cancel {
            control.cancel()?;
            assert!(execution.as_mut().now_or_never().is_none());
            assert!(fixture.engine.reserve_evaluation([1; 16]).is_err());
            release.send(())?;
            let error = tokio::time::timeout(Duration::from_secs(30), execution)
                .await?
                .err()
                .ok_or("cancelled preparation succeeded")?;
            assert_eq!(
                crate::Failure::from(&error),
                crate::Failure::Cancelled,
                "{error:?}"
            );
        } else {
            drop(execution);
            assert!(fixture.engine.reserve_evaluation([1; 16]).is_err());
            release.send(())?;
            drop(
                tokio::time::timeout(
                    Duration::from_secs(30),
                    fixture.engine.acquire_evaluation([1; 16]),
                )
                .await??,
            );
            control.check()?;
        }
        drop(fixture.engine.reserve_evaluation([1; 16])?);
        drop(definition);
        drop(
            fixture.engine.memory().reserve_input(
                fixture
                    .engine
                    .limits()
                    .input_capacity
                    .ok_or("configured input capacity")?,
            )?,
        );
        drop(
            fixture.engine.memory().reserve_output(
                fixture
                    .engine
                    .limits()
                    .output_capacity
                    .ok_or("configured output capacity")?,
            )?,
        );
    }
    Ok(())
}

#[tokio::test]
async fn prepared_guest_keeps_identity() -> TestResult {
    use araphor_package_runtime::{Runtime, TaskTracker};

    let runtime = Runtime::new(Default::default())?;
    let foreign = Runtime::new(araphor_package_runtime::Limits {
        wasm: araphor_package_runtime::WasmLimits {
            fuel: Some(100_000_000),
            ..Default::default()
        },
        ..Default::default()
    })?;
    let bundle = Arc::new(super::execution::component("wasm", "evaluate")?);
    let model = &bundle.artifacts[0].descriptor.exports[0];
    let evaluation = sdk::Evaluation {
        export: model.name.clone(),
        inputs: Vec::new(),
        parameters: araphor_data::decode_parameters(
            &model.parameters,
            Some(&serde_json::json!({"mode": "echo", "amount": 42})),
        )?,
        checkpoint: None,
        context: sdk::EvaluationContext {
            id: "prepared".into(),
            time_utc_ns: 123,
            seed: Some(7),
        },
    };
    let control = AnalysisReadControl::with_timeout(Duration::from_secs(30))?;
    let prepared = runtime
        .prepare(
            Arc::clone(&bundle),
            bundle.root.clone(),
            model.name.clone(),
            &control,
        )?
        .ok_or("prepared Wasm absent")?;
    let workers = TaskTracker::new();
    for (owner, image) in [
        (foreign, Arc::clone(&bundle)),
        (Arc::clone(&runtime), Arc::new(bundle.as_ref().clone())),
    ] {
        let error = owner
            .evaluate_reserved(
                image,
                bundle.root.clone(),
                evaluation.clone(),
                control.within(None)?,
                &workers,
                None,
                Some(prepared.clone()),
                None,
                (),
            )
            .await
            .err()
            .ok_or("foreign prepared guest accepted")?;
        assert!(matches!(
            error,
            araphor_package_runtime::Error::Data {
                source: araphor_data::Error::Package {
                    code: araphor_data::PackageErrorCodeV1::Invalid,
                    field: "prepared package binding",
                    ..
                }
            }
        ));
    }
    let (_, output) = runtime
        .evaluate_reserved(
            Arc::clone(&bundle),
            bundle.root.clone(),
            evaluation,
            control.within(None)?,
            &workers,
            None,
            Some(prepared),
            None,
            (),
        )
        .await?;
    assert_eq!(
        output.datasets[0].batches[0]
            .column(0)
            .as_any()
            .downcast_ref::<sdk::arrow_array::UInt64Array>()
            .ok_or("UInt64 output")?
            .value(0),
        42
    );
    workers.close();
    workers.wait().await;
    control.check()?;
    Ok(())
}

fn datasets(tenant: u8, counts: [u64; 2]) -> sdk::Result<Vec<sdk::Dataset>> {
    let atoms: Vec<_> = counts
        .into_iter()
        .enumerate()
        .map(|(index, count)| {
            let key = atom_key(tenant, index);
            builtin::BehaviorAtomV1 {
                evidence_sample: vec![builtin::DiscoveryRecordIdV1 {
                    stream: key.stream.clone(),
                    cpu_id: u32::from(tenant),
                    durable_cursor: index as u64 + 1,
                }],
                key,
                count,
                first_cursor: index as u64 + 1,
                last_cursor: index as u64 + 1,
            }
        })
        .collect();
    let datasets = vec![
        Rows::encode(
            &builtin::Discovery::port::<builtin::BehaviorAtomV1>("atoms"),
            &atoms,
        )?,
        Rows::encode::<builtin::DiscoveryCoverageV1>(
            &builtin::Discovery::port::<builtin::DiscoveryCoverageV1>("coverage"),
            &[],
        )?,
    ];
    Ok(datasets)
}

fn assert_group(result: &CallResult, tenant: u8, count: u64) -> TestResult {
    assert_eq!(result.evaluation().context.id, format!("tenant-{tenant}"));
    assert_eq!(result.output().datasets.len(), 1);
    let groups: Vec<builtin::BehaviorDisplayGroupV1> = Rows::decode(
        &builtin::Discovery::port::<builtin::BehaviorDisplayGroupV1>("groups"),
        &result.output().datasets[0],
    )?;
    assert_eq!(groups.len(), 1);
    assert_eq!(
        groups[0].key,
        builtin::BehaviorDisplayKeyV1::from(&atom_key(tenant, 0))
    );
    assert_eq!(groups[0].count, count);
    assert_eq!(
        groups[0].members,
        [atom_key(tenant, 0), atom_key(tenant, 1)]
    );
    assert_eq!(
        groups[0].evidence_sample,
        [1, 2].map(|cursor| builtin::DiscoveryRecordIdV1 {
            stream: atom_key(tenant, 0).stream,
            cpu_id: u32::from(tenant),
            durable_cursor: cursor,
        })
    );
    assert!(groups[0].coverage.is_empty());
    assert!(result.output().checkpoint.is_none());
    assert!(result.output().evidence.is_empty());
    assert!(result.output().reasons.is_empty());
    Ok(())
}

fn atom_key(tenant: u8, index: usize) -> builtin::BehaviorAtomKeyV1 {
    use builtin::*;
    BehaviorAtomKeyV1 {
        stream: EvidenceIntakeIdentityV1 {
            tenant_id: [tenant; 16],
            node_id: format!("node-{tenant}"),
            node_boot_id: [2; 16],
            label_epoch: 1,
            source_id: [3; 16],
            source_epoch: 1,
        },
        cpu_id: u32::from(tenant),
        subject_revision: format!("tenant-{tenant}"),
        image_digest: "image".into(),
        configuration_digest: "config".into(),
        process_instance_id: [1; 16],
        entry_instance_id: [2; 16],
        binding_id: [3; 16],
        role_id: 1,
        state_id: 1,
        entry_rule_id: 1,
        catalog_revision: 1,
        static_key: DiscoveryPolicyKeyV1 {
            workload_selector_id: "workload".into(),
            protected_scope_id: "scope".into(),
            execution_set_id: "execution".into(),
            entry_kind: "entry".into(),
            role_id: "role".into(),
            process_state_id: "state".into(),
            effect_family: 1,
            operation_id: "operation".into(),
            operation: 1,
            operation_argument: 0,
            argument_wildcard: false,
            object_selector: "object".into(),
            binding_lifecycle: "lifecycle".into(),
        },
        policy_revision: DiscoveryPolicyRevisionV1 {
            profile_id: "profile".into(),
            profile_version: 1,
            source_revision_id: "source".into(),
            signed_profile_digest: "digest".into(),
        },
        generation: index as u64 + 1,
        coverage_interval_id: [4; 16],
        temporal_coverage: 1,
        effect: DiscoveryEffectKeyV1 {
            task_cookie: 7,
            target_task_cookie: None,
            process_lineage_id: Vec::new(),
            authority_domain_id: Vec::new(),
            execution_set_id: Vec::new(),
            exact_object_id: vec![7; 16],
            destination_id: 0,
            policy_rule_id: 1,
            reason: 0,
            decision: 1,
            effect_family: 1,
            operation: 1,
            operation_argument: Some(0),
            configured_errno: -13,
            kernel_result: -13,
            exact_file_object: None,
        },
        physical_result: DiscoveryPhysicalResultV1::Unknown,
        proof_kind: DiscoveryProofKindV1::RecordedInput,
    }
}
