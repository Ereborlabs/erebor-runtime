use std::{
    collections::BTreeMap,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};

use araphor_analysis::{Instance, InstanceHost};
use araphor_analysis_sdk as sdk;
use araphor_data::{
    analysis::native::NativeStore, AnalysisReadControl, AnalysisSelectionV1,
    EvidenceIntakeIdentityV1, EvidenceRecord, ManagedReceipt, ManagedRequest, PackageActionV1,
    PackageAuthorization, PackageErrorCodeV1 as Code, PackageGrantV1, ValidatedEvidenceBatchV1,
};
use araphor_discovery_definition::{Definition, Program, Source};
use araphor_package::{
    PackageArtifactV1, PackageBundle, PackageBundleV1, PackageImplementationV1, SqlModelV1,
};
use araphor_query::execution::{Engine, Limits};
use araphor_query::follow::{Clock as _, SystemClock};
use tokio::sync::watch;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;
const TENANT: [u8; 16] = [1; 16];

#[path = "native_instance/recovery.rs"]
mod recovery;

struct Authority {
    changes: watch::Sender<u64>,
    reject: AtomicBool,
}

impl PackageAuthorization for Authority {
    fn check(&self, grant: &PackageGrantV1, _: PackageActionV1) -> araphor_data::Result<()> {
        grant.remaining().map(|_| ())
    }

    fn admit(&self, _: &PackageGrantV1, _: &PackageBundle) -> araphor_data::Result<()> {
        Ok(())
    }

    fn commit(
        &self,
        grant: &PackageGrantV1,
        action: PackageActionV1,
        bundle: &PackageBundle,
        operation: &mut dyn FnMut() -> araphor_data::Result<()>,
    ) -> araphor_data::Result<()> {
        self.commit_many(&[(grant, action, Some(bundle))], operation)
    }

    fn commit_many(
        &self,
        grants: &[(&PackageGrantV1, PackageActionV1, Option<&PackageBundle>)],
        operation: &mut dyn FnMut() -> araphor_data::Result<()>,
    ) -> araphor_data::Result<()> {
        for (grant, action, _) in grants {
            self.check(grant, *action)?;
        }
        if self.reject.load(Ordering::Acquire) {
            return Err(Code::Denied.error("native instance authority"));
        }
        operation()
    }

    fn changes(&self) -> watch::Receiver<u64> {
        self.changes.subscribe()
    }
}

struct Fixture {
    directory: tempfile::TempDir,
    engine: Arc<Engine>,
    authority: Arc<Authority>,
    grant: PackageGrantV1,
}

impl Fixture {
    fn new() -> TestResult<Self> {
        let directory = tempfile::tempdir()?;
        let store = Arc::new(NativeStore::open(&directory.path().join("data"))?);
        let engine = Engine::new(store, Limits::default())?;
        let schema = sdk::Schema::new(vec![sdk::Field::new("value", sdk::DataType::UInt64, false)]);
        let artifact = PackageArtifactV1 {
            descriptor: sdk::Package::new(
                "native-host",
                "1",
                vec![sdk::Model::new(
                    "copy",
                    vec![sdk::Port::new("input", schema.clone())],
                    vec![sdk::Port::new("rows", schema)],
                )],
            ),
            implementations: vec![PackageImplementationV1::Sql {
                export: "copy".into(),
                program: SqlModelV1 {
                    outputs: BTreeMap::from([("rows".into(), "SELECT value FROM input".into())]),
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
        engine
            .store()
            .install_package_image(TENANT, &image, || Ok(()))?;
        Ok(Self {
            directory,
            engine,
            authority: Arc::new(Authority {
                changes: watch::channel(0).0,
                reject: AtomicBool::new(false),
            }),
            grant: PackageGrantV1 {
                principal: "native-host".into(),
                revision: 1,
                selection: AnalysisSelectionV1::tenant(TENANT),
                expires_utc_ns: None,
                authorization_id: Some("native-host".into()),
            },
        })
    }

    fn event(&self, cursor: u64) -> araphor_data::Result<()> {
        let frame = Vec::<u8>::try_from(&EvidenceRecord {
            task_cookie: cursor,
            ..Default::default()
        })?;
        self.engine.store().accept_validated_batch(
            EvidenceIntakeIdentityV1 {
                tenant_id: TENANT,
                node_id: "native-host".into(),
                node_boot_id: [2; 16],
                label_epoch: 1,
                source_id: [3; 16],
                source_epoch: 1,
            },
            ValidatedEvidenceBatchV1 {
                cpu_id: 0,
                first_cursor: cursor,
                last_cursor: cursor,
                intake_utc_ns: cursor,
                frame_ends: vec![frame.len()],
                framed_records: frame.into(),
            },
        )?;
        Ok(())
    }

    async fn admit(&self) -> TestResult<Arc<Instance>> {
        let definition = Definition {
            name: "native-host".into(), description: String::new(), labels: BTreeMap::new(),
            program: Program::Sql { source: Source::Inline {
                inline: r#"SELECT * FROM "native-host"."1".copy(input => (SELECT source_cursor AS value FROM events))"#.into(),
            } },
        };
        let prepared = self
            .engine
            .prepare_definition(
                TENANT,
                &definition,
                Arc::new(AnalysisReadControl::default()),
            )
            .await?;
        self.engine
            .store()
            .admit_definition(TENANT, prepared.resolved(), || Ok(()))?;
        Ok(Instance::admit(
            self.engine.clone(),
            self.authority.clone(),
            self.grant.clone(),
            "instance".into(),
            prepared.resolved().clone(),
            &AnalysisReadControl::default(),
        )
        .await?)
    }

    async fn progress(&self, after: u64) -> TestResult<ManagedReceipt> {
        let mut changes = self.engine.store().subscribe_revision();
        tokio::time::timeout(Duration::from_secs(30), async {
            loop {
                let history = self.engine.store().managed_history(
                    &self.grant.selection,
                    "instance",
                    &AnalysisReadControl::default(),
                )?;
                if let Some(receipt) = history
                    .last()
                    .filter(|receipt| receipt.commit_revision > after)
                {
                    return Ok(receipt.clone());
                }
                changes.changed().await?;
            }
        })
        .await?
    }
}

fn request(id: &str) -> ManagedRequest {
    ManagedRequest {
        id: id.into(),
        time_utc_ns: 1000,
        seed: Some(1),
        rebuild: false,
        witness_expiry: u64::MAX,
        frontier: None,
    }
}

#[tokio::test]
async fn native_publication_and_replay() -> TestResult {
    let fixture = Fixture::new()?;
    fixture.event(1)?;
    let instance = fixture.admit().await?;
    let control = AnalysisReadControl::default();
    let receipt = instance.run(request("first"), &control).await?;
    assert_eq!(receipt.results.len(), 1);
    fixture.event(2)?;
    let output = instance
        .replay(&receipt.selected.result_id, &control)
        .await?;
    assert_eq!(output.calls.len(), 1);
    let values = output
        .batches
        .iter()
        .map(|batch| {
            batch
                .column(0)
                .as_any()
                .downcast_ref::<sdk::arrow_array::UInt64Array>()
                .ok_or("replayed value type")
                .map(|values| values.values().to_vec())
        })
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();
    assert_eq!(values, vec![1]);
    assert_eq!(
        fixture
            .engine
            .store()
            .managed_history(&fixture.grant.selection, "instance", &control)?
            .len(),
        1
    );
    Ok(())
}

#[tokio::test]
async fn native_authority_rejection() -> TestResult {
    let fixture = Fixture::new()?;
    fixture.event(1)?;
    let instance = fixture.admit().await?;
    let control = AnalysisReadControl::default();
    fixture.authority.reject.store(true, Ordering::Release);
    assert!(instance.run(request("rejected"), &control).await.is_err());
    assert!(fixture
        .engine
        .store()
        .managed_history(&fixture.grant.selection, "instance", &control)?
        .is_empty());
    let resume = fixture
        .engine
        .store()
        .managed_resume(TENANT, "instance", &control)?;
    assert_eq!(resume.instance.progress, 0);
    fixture.authority.reject.store(false, Ordering::Release);
    let receipt = instance.run(request("accepted"), &control).await?;
    assert!(receipt.commit_revision > 0);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn native_host_resume() -> TestResult {
    let fixture = Fixture::new()?;
    fixture.event(1)?;
    let instance = fixture.admit().await?;
    let control = AnalysisReadControl::default();
    let host = InstanceHost::new(fixture.engine.clone(), fixture.authority.clone());
    let (stop, stopped) = watch::channel(false);
    let worker = tokio::spawn(host.clone().serve(stopped, u64::MAX));
    let running = host
        .start(instance.clone(), instance.admitted().lifecycle, &control)
        .await?;
    let first = fixture.progress(0).await?;
    let lifecycle = running.admitted().lifecycle;
    let stopped = host.stop(running, lifecycle, &control).await?;
    fixture.event(2)?;
    let running = host
        .start(stopped.clone(), stopped.admitted().lifecycle, &control)
        .await?;
    let second = fixture.progress(first.commit_revision).await?;
    assert!(second.commit_revision > first.commit_revision);
    stop.send_replace(true);
    tokio::time::timeout(Duration::from_secs(30), worker).await???;
    assert!(
        fixture
            .engine
            .store()
            .managed_resume(TENANT, "instance", &control)?
            .instance
            .running
    );
    drop((instance, running, stopped, host));
    let root = fixture.directory.path().join("data");
    let Fixture {
        directory,
        engine,
        authority,
        grant,
    } = fixture;
    drop(engine);
    let fixture = Fixture {
        directory,
        authority,
        grant,
        engine: Engine::new(Arc::new(NativeStore::open(&root)?), Limits::default())?,
    };
    fixture.event(3)?;
    let host = InstanceHost::new(fixture.engine.clone(), fixture.authority.clone());
    let (stop, stopped) = watch::channel(false);
    let worker = tokio::spawn(host.clone().serve(stopped, u64::MAX));
    let third = fixture.progress(second.commit_revision).await?;
    assert_eq!(third.results.len(), 1);
    let now = SystemClock::default().now_ns()?;
    let resume = fixture
        .engine
        .store()
        .managed_resume(TENANT, "instance", &control)?;
    let current = fixture.engine.store().managed_result(
        &resume.instance,
        &third.selected.result_id,
        now,
        &control,
    )?;
    let prior = fixture.engine.store().managed_result(
        &resume.instance,
        &second.selected.result_id,
        now,
        &control,
    )?;
    assert!(current.source.commit_revision > prior.source.commit_revision);
    stop.send_replace(true);
    tokio::time::timeout(Duration::from_secs(30), worker).await???;
    drop(fixture.engine.store().lease_managed()?);
    Ok(())
}

#[tokio::test]
async fn native_host_versions() -> TestResult {
    let fixture = Fixture::new()?;
    fixture.event(1)?;
    let instance = fixture.admit().await?;
    let control = AnalysisReadControl::default();
    let receipt = instance.run(request("original"), &control).await?;
    let host = InstanceHost::new(fixture.engine.clone(), fixture.authority.clone());
    let mut grant = fixture.grant.clone();
    grant.revision = 2;
    let renewed = host
        .renew(
            grant.clone(),
            "instance".into(),
            instance.admitted().lifecycle,
            &control,
        )
        .await?;
    assert_eq!(
        renewed.admitted().generation,
        instance.admitted().generation
    );
    assert_eq!(renewed.admitted().grant, grant);
    let mut target = instance.admitted().spec.definition.clone();
    target.definition.description = "Changed metadata.".into();
    fixture
        .engine
        .store()
        .admit_definition(TENANT, &target, || Ok(()))?;
    let updated = host
        .update(
            renewed.clone(),
            renewed.admitted().lifecycle,
            target,
            false,
            u64::MAX,
            &control,
        )
        .await?;
    assert!(updated.admitted().generation > renewed.admitted().generation);
    assert_eq!(
        updated.admitted().spec.manifest.calls,
        renewed.admitted().spec.manifest.calls
    );
    let rolled = host
        .rollback(
            updated.clone(),
            updated.admitted().lifecycle,
            instance.admitted().generation,
            false,
            u64::MAX,
            &control,
        )
        .await?;
    assert_eq!(rolled.admitted().spec, instance.admitted().spec);
    assert_eq!(rolled.admitted().generation, instance.admitted().generation);
    let removed = host
        .remove(
            grant.clone(),
            "instance".into(),
            rolled.admitted().lifecycle,
            &control,
        )
        .await?;
    assert!(removed.removed);
    let recreated = host
        .recreate(
            grant,
            "instance".into(),
            removed.lifecycle,
            instance.admitted().spec.definition.clone(),
            &control,
        )
        .await?;
    assert!(recreated.admitted().generation > removed.generation);
    let latest = recreated.run(request("recreated"), &control).await?;
    let history =
        fixture
            .engine
            .store()
            .managed_history(&fixture.grant.selection, "instance", &control)?;
    assert_eq!(history.len(), 4);
    assert!(history.contains(&receipt));
    assert!(history.contains(&latest));
    let root = fixture.directory.path().join("data");
    let current = recreated.admitted().clone();
    drop((instance, renewed, updated, rolled, recreated, host));
    let Fixture {
        directory, engine, ..
    } = fixture;
    drop(engine);
    let store = NativeStore::open(&root)?;
    assert_eq!(
        store.managed_history(&AnalysisSelectionV1::tenant(TENANT), "instance", &control)?,
        history
    );
    let result = store.managed_result(
        &current,
        &receipt.selected.result_id,
        SystemClock::default().now_ns()?,
        &control,
    )?;
    assert_eq!(result.receipt, receipt);
    drop((store, directory));
    Ok(())
}
