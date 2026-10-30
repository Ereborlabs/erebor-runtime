use std::sync::Mutex;

use araphor_data::{ManagedDestination, ManagedExit};
use araphor_discovery_definition::{Definition, Program, Source};
use araphor_query::definition::{ExecutionReceipt, PackageCall};
use datafusion::catalog::{streaming::StreamingTable, TableProvider};
use datafusion::common::DataFusionError;
use datafusion::execution::TaskContext;
use datafusion::physical_plan::{
    stream::RecordBatchStreamAdapter, streaming::PartitionStream, SendableRecordBatchStream,
};
use erebor_runtime_error::{ErrorExt as _, StatusCode};
use tokio::sync::oneshot;

use super::*;

pub(super) fn assert_failed_profile(
    fixture: &Fixture,
    instance: &crate::Instance,
    id: &str,
    code: Code,
    progress: u64,
) -> TestResult {
    let control = AnalysisReadControl::default();
    let tenant = fixture.source.tenant_id;
    let instance = &instance.admitted().spec.id;
    let attempt = fixture
        .store
        .managed_attempt(tenant, instance, id, &control)?
        .ok_or("failed Profile attempt")?;
    assert_eq!(
        attempt.terminal().ok_or("failed Profile terminal")?.exit,
        ManagedExit::Failed(code)
    );
    assert!(attempt.receipt().is_none());
    assert!(fixture
        .store
        .managed_selected(tenant, instance, id, &control)?
        .is_none());
    assert_eq!(
        fixture
            .store
            .managed_instance(tenant, instance, &control)?
            .ok_or("retained Profile instance")?
            .progress,
        progress
    );
    Ok(())
}

type GateWait = (oneshot::Sender<ExecutionReceipt>, oneshot::Receiver<()>);

struct RetirementGate {
    schema: Arc<sdk::Schema>,
    wait: Mutex<Option<GateWait>>,
}

impl std::fmt::Debug for RetirementGate {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RetirementGate")
            .finish_non_exhaustive()
    }
}

impl RetirementGate {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            schema: Arc::new(sdk::Schema::new(vec![sdk::Field::new(
                "allowed",
                sdk::DataType::Boolean,
                false,
            )])),
            wait: Mutex::new(None),
        })
    }

    fn arm(&self) -> (oneshot::Receiver<ExecutionReceipt>, oneshot::Sender<()>) {
        let (entered, observed) = oneshot::channel();
        let (release, released) = oneshot::channel();
        *self.wait.lock().unwrap_or_else(|error| error.into_inner()) = Some((entered, released));
        (observed, release)
    }
}

impl PartitionStream for RetirementGate {
    fn schema(&self) -> &Arc<sdk::Schema> {
        &self.schema
    }

    fn execute(&self, context: Arc<TaskContext>) -> SendableRecordBatchStream {
        let wait = self
            .wait
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .take();
        let entered = wait.map(|(entered, released)| {
            (entered, released, ExecutionReceipt::from_context(&context))
        });
        let schema = Arc::clone(&self.schema);
        let stream = futures_util::stream::once(async move {
            if let Some((entered, released, captured)) = entered {
                entered.send(captured?).map_err(|_| {
                    DataFusionError::Execution("retirement capture receiver closed".into())
                })?;
                released
                    .await
                    .map_err(|_| DataFusionError::Execution("retirement gate closed".into()))?;
            }
            sdk::RecordBatch::try_new(
                schema,
                vec![Arc::new(sdk::arrow_array::BooleanArray::from(vec![true]))],
            )
            .map_err(DataFusionError::from)
        });
        Box::pin(RecordBatchStreamAdapter::new(
            Arc::clone(&self.schema),
            stream,
        ))
    }
}

impl Fixture {
    async fn gated_profile(&self, gate: Arc<RetirementGate>) -> TestResult<Arc<crate::Instance>> {
        let image = PackageBundle::try_from(Package::discovery_bundle()?)?;
        self.store
            .install_package_image(self.source.tenant_id, &image, || Ok(()))?;
        let grant = PackageGrantV1 {
            principal: "fixture".into(),
            revision: 1,
            selection: AnalysisSelectionV1::new(self.source.tenant_id, vec![self.source.clone()]),
            expires_utc_ns: None,
            authorization_id: None,
        };
        let control = AnalysisReadControl::default();
        let mut session = self.query.session(grant.selection.clone(), &control, 0)?;
        let partition: Arc<dyn PartitionStream> = gate.clone();
        let provider: Arc<dyn TableProvider> = Arc::new(StreamingTable::try_new(
            Arc::clone(&gate.schema),
            vec![partition],
        )?);
        session.register_table("retirement_gate", provider)?;
        let definition = Definition {
            name: "native-retirement".into(),
            description: String::new(),
            labels: Default::default(),
            program: Program::Sql {
                source: Source::Inline {
                    inline: format!(
                        "SELECT profile.* FROM ({}) AS profile CROSS JOIN retirement_gate WHERE retirement_gate.allowed",
                        Program::call(&image.bundle().root, "live", "snapshot")?.sql()?,
                    ),
                },
            },
        };
        let prepared = session.prepare_definition(&definition).await?;
        let mut selected = None;
        PackageCall::any(&prepared.plan, &mut |call| {
            if call.package() == &image.bundle().root
                && call.export() == "live"
                && call.output() == "snapshot"
            {
                selected = Some(call.clone());
            }
            Ok(false)
        })?;
        let selected = selected.ok_or("Profile selected call")?;
        let host = InstanceHost::new(
            Arc::clone(&self.query),
            Arc::new(Authority(watch::channel(0).0)),
        );
        Ok(host
            .admit_prepared(
                session,
                grant,
                "captured-retirement".into(),
                prepared,
                ManagedDestination::DiscoveryProfile {
                    source: self.source.clone(),
                    call: selected.id(),
                    output: selected.output().into(),
                },
            )
            .await?)
    }
}

#[tokio::test]
async fn native_retirement_rejects_captured() -> TestResult {
    let fixture = Fixture::new(Limits::default())?;
    fixture.append(1)?;
    fixture
        .store
        .register_processor(&fixture.scope(), ProcessorClassV1::Required, 1)?;
    let gate = RetirementGate::new();
    let instance = fixture.gated_profile(Arc::clone(&gate)).await?;
    let first = instance
        .run(
            Fixture::request("retirement-first")?,
            &AnalysisReadControl::default(),
        )
        .await?;
    let profile = fixture.profile()?.ok_or("profile")?;
    assert_eq!(profile.snapshot.accepted_records, 1);
    assert_eq!(profile.snapshot.unresolved_records, 1);
    assert!(!profile.snapshot.coverage.is_empty());
    fixture.append(2)?;
    let (entered, release) = gate.arm();
    let request = Fixture::request("retirement-captured")?;
    let control = AnalysisReadControl::default();
    let error = {
        let mut running = Box::pin(instance.run(request.clone(), &control));
        let captured = tokio::select! {
            result = &mut running => return Err(format!("Profile run ended before captured gate: {result:?}").into()),
            captured = entered => captured?,
        };
        assert!(captured
            .snapshot()
            .page
            .extraction
            .sources
            .iter()
            .any(|source| source.receipt.contiguous_cursor == 2));
        fixture.store.retire_required(&ProcessorRetirementV1 {
            scope: fixture.scope(),
            change_id: "retire-captured".into(),
            reason: "Retire this source processor.".into(),
            expected_cursor: 1,
            cutoff_cursor: 2,
        })?;
        let mut expected = fixture.store.meta()?;
        let mut expected_health = fixture.store.processor_health(&fixture.scope())?;
        release
            .send(())
            .map_err(|_| "retirement gate receiver closed")?;
        let error = running.await.err().ok_or("captured retirement published")?;
        assert!(
            format!("{error:?}").contains("AnalysisConflict"),
            "{error:?}"
        );
        expected.commit_revision += 1;
        assert_eq!(fixture.store.meta()?, expected);
        expected_health
            .as_mut()
            .ok_or("retired processor health")?
            .read_revision = expected.commit_revision;
        assert_eq!(
            fixture.store.processor_health(&fixture.scope())?,
            expected_health
        );
        assert_eq!(fixture.profile()?, Some(profile.clone()));
        error
    };
    drop(error);
    assert_eq!(fixture.profile()?, Some(profile));
    let saved = fixture
        .store
        .managed_instance(
            fixture.source.tenant_id,
            &instance.admitted().spec.id,
            &control,
        )?
        .ok_or("retained Profile instance")?;
    assert_eq!(saved.progress, first.commit_revision);
    let attempt = fixture
        .store
        .managed_attempt(
            fixture.source.tenant_id,
            &saved.spec.id,
            &request.id,
            &control,
        )?
        .ok_or("captured retirement attempt")?;
    assert_eq!(
        attempt
            .terminal()
            .ok_or("captured retirement terminal")?
            .exit,
        ManagedExit::Failed(Code::Conflict)
    );
    assert!(attempt.receipt().is_none());
    assert!(fixture
        .store
        .managed_selected(
            fixture.source.tenant_id,
            &saved.spec.id,
            &request.id,
            &control
        )?
        .is_none());
    drop((instance, gate));
    fixture.released()?;
    Ok(())
}

#[tokio::test]
async fn publication_rejects_auxiliary_returns() -> TestResult {
    for evidence in [false, true] {
        let fixture = Fixture::new(Limits::default())?;
        fixture.append(1)?;
        let mut image = Fixture::constant_bundle("SELECT source_cursor AS value FROM events")?;
        let artifact = &mut image.artifacts[0];
        let PackageImplementationV1::Sql { program, .. } = &mut artifact.implementations[0] else {
            return Err("SQL".into());
        };
        if evidence {
            program.evidence = Some(
                "SELECT 'data' AS output_dataset, __row_index AS output_row, 'events' AS input_dataset, __row_index AS input_row FROM events".into(),
            );
        } else {
            let details = artifact.descriptor.exports[0].outputs[0].schema.clone();
            artifact.descriptor.exports[0].reasons.push(sdk::Reason {
                code: "setup-fixture.note".into(),
                details,
            });
            program.reasons.push(SqlReasonV1 {
                output: "data".into(),
                code: "setup-fixture.note".into(),
                sql: "SELECT __row_index AS output_row, value FROM output_data".into(),
            });
        }
        let image = Arc::new(PackageBundle::try_from(image)?);
        fixture
            .store
            .install_package_image(fixture.source.tenant_id, &image, || Ok(()))?;
        let authority: Arc<dyn PackageAuthorization> = Arc::new(Authority(watch::channel(0).0));
        let package = Package::new(
            Arc::clone(&fixture.query),
            Arc::clone(&authority),
            PackageGrantV1 {
                principal: "fixture".into(),
                revision: 1,
                selection: AnalysisSelectionV1::tenant(fixture.source.tenant_id),
                expires_utc_ns: None,
                authorization_id: None,
            },
            image,
            "constant",
            "data",
        )?;
        let before = fixture.store.meta()?;
        let mut stream = package.subscribe(Some(&fixture.source), false).await?;
        let update = stream.next().await.ok_or("auxiliary update")??;
        let (_, call) = package.prepared().await?;
        assert_eq!(update.calls.len(), 1);
        let returned = update.calls.get(&call.id()).ok_or("auxiliary return")?;
        assert!(returned.belongs_to(call));
        assert_eq!(returned.output().evidence.is_empty(), !evidence);
        assert_eq!(returned.output().reasons.is_empty(), evidence);
        assert!(returned.output().checkpoint.is_none());
        assert_eq!(fixture.store.meta()?, before);
        stream.cancel_and_join().await?;
        drop(update);
        let host = crate::InstanceHost::new(Arc::clone(&fixture.query), authority);
        let owner = DiscoveryOwner::new(vec![package], host)?;
        let control = AnalysisReadControl::default();
        let instance = owner
            .admit(&fixture.source, &control)
            .await?
            .ok_or("Profile admission")?;
        assert!(!instance.admitted().running);
        assert!(owner.profile(&fixture.source)?.is_none());
        let health = fixture
            .store
            .processor_health(&fixture.scope())?
            .ok_or("registered processor health")?;
        let before = fixture.store.meta()?;
        assert_eq!(health.read_revision, before.commit_revision);
        let error = instance
            .run(Fixture::request("auxiliary")?, &control)
            .await
            .err()
            .ok_or("auxiliary Profile published")?;
        assert_eq!(error.status_code(), StatusCode::Unsupported);
        assert!(
            format!("{error:?}").contains("discovery auxiliary return"),
            "{error:?}"
        );
        assert_failed_profile(&fixture, &instance, "auxiliary", Code::Unsupported, 0)?;
        assert!(owner.profile(&fixture.source)?.is_none());
        assert_eq!(
            fixture.store.processor_health(&fixture.scope())?,
            Some(araphor_data::ProcessorHealthV1 {
                read_revision: before.commit_revision + 2,
                ..health
            })
        );
        assert_eq!(
            fixture.store.meta()?.commit_revision,
            before.commit_revision + 2
        );
        drop((error, instance, owner));
        fixture.released()?;
    }
    Ok(())
}
