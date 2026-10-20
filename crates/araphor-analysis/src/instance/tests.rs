use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use araphor_analysis_sdk as sdk;
use araphor_data::{AnalysisSelectionV1, AnalysisStore};
use araphor_discovery_definition::{Definition, Program, Source};
use araphor_package::{
    PackageArtifactV1, PackageBundleV1, PackageImplementationV1, PackageRefV1, SqlModelV1,
    SqlReasonV1,
};
use erebor_runtime_error::ErrorExt as _;
use sdk::arrow_array::{Array as _, UInt64Array};

use super::*;

mod history;

pub(super) type TestResult<T = ()> =
    std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

pub(super) struct Authority {
    allowed: Mutex<bool>,
    images: Mutex<BTreeSet<String>>,
    changes: tokio::sync::watch::Sender<u64>,
    deny_next: AtomicBool,
}

impl Authority {
    pub(super) fn set(&self, allowed: bool) {
        *self
            .allowed
            .lock()
            .unwrap_or_else(|error| error.into_inner()) = allowed;
        self.changes.send_modify(|revision| *revision += 1);
    }
}

impl PackageAuthorization for Authority {
    fn check(&self, grant: &PackageGrantV1, _: PackageActionV1) -> araphor_data::Result<()> {
        grant.remaining()?;
        if !*self
            .allowed
            .lock()
            .unwrap_or_else(|error| error.into_inner())
        {
            return Err(Code::Denied.error("instance fixture authority"));
        }
        Ok(())
    }
    fn admit(&self, _: &PackageGrantV1, bundle: &PackageBundleRef<'_>) -> araphor_data::Result<()> {
        if !self
            .images
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .contains(bundle.digest())
        {
            return Err(Code::Denied.error("instance fixture trust"));
        }
        Ok(())
    }
    fn commit(
        &self,
        grant: &PackageGrantV1,
        action: PackageActionV1,
        bundle: &PackageBundleRef<'_>,
        operation: &mut dyn FnMut() -> araphor_data::Result<()>,
    ) -> araphor_data::Result<()> {
        self.commit_many(&[(grant, None), (grant, Some(bundle))], action, operation)
    }
    fn commit_many(
        &self,
        grants: &[(&PackageGrantV1, Option<&PackageBundleRef<'_>>)],
        _: PackageActionV1,
        operation: &mut dyn FnMut() -> araphor_data::Result<()>,
    ) -> araphor_data::Result<()> {
        if self.deny_next.swap(false, Ordering::SeqCst) {
            return Err(Code::Denied.error("instance fixture acknowledgment"));
        }
        let allowed = self
            .allowed
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let images = self
            .images
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if !*allowed || grants.is_empty() || !grants.iter().any(|(_, bundle)| bundle.is_none()) {
            return Err(Code::Denied.error("instance fixture authority set"));
        }
        for (grant, bundle) in grants {
            grant.remaining()?;
            if bundle.is_some_and(|bundle| !images.contains(bundle.digest())) {
                return Err(Code::Denied.error("instance fixture trust set"));
            }
        }
        operation()
    }
    fn changes(&self) -> tokio::sync::watch::Receiver<u64> {
        self.changes.subscribe()
    }
}

pub(super) struct Fixture {
    directory: tempfile::TempDir,
    pub(super) query: Arc<Engine>,
    pub(super) authority: Arc<Authority>,
    grant: PackageGrantV1,
}

impl Fixture {
    pub(super) fn new(limits: araphor_query::execution::Limits) -> TestResult<Self> {
        let directory = tempfile::tempdir()?;
        let store = Arc::new(AnalysisStore::open(directory.path().join("data"))?);
        Ok(Self {
            directory,
            query: Engine::new(store, limits)?,
            authority: Arc::new(Authority {
                allowed: Mutex::new(true),
                images: Mutex::default(),
                changes: tokio::sync::watch::channel(0).0,
                deny_next: AtomicBool::new(false),
            }),
            grant: PackageGrantV1 {
                principal: "instance-fixture".into(),
                revision: 1,
                selection: AnalysisSelectionV1::tenant([1; 16]),
                expires_utc_ns: None,
                authorization_id: None,
            },
        })
    }

    async fn image_limits(
        mut limits: araphor_query::execution::Limits,
        image: &PackageBundleV1,
        sql: &str,
    ) -> TestResult<Self> {
        let mut fixture = Self::new(Default::default())?;
        fixture.install(image)?;
        if let Some(capacity) = limits.input_capacity {
            let prepared = fixture
                .query
                .prepare_definition(
                    [1; 16],
                    &Self::definition(sql),
                    Arc::new(AnalysisReadControl::default()),
                )
                .await?;
            let retained = fixture.query.memory().input_reserved();
            limits.input_capacity = Some(capacity.checked_add(retained).ok_or("image capacity")?);
            drop(prepared);
            assert_eq!(fixture.query.memory().input_reserved(), 0);
        }
        fixture.query = Engine::new(Arc::clone(fixture.query.store()), limits)?;
        Ok(fixture)
    }

    fn definition(sql: &str) -> Definition {
        Definition {
            name: "instance-fixture".into(),
            description: String::new(),
            labels: BTreeMap::new(),
            program: Program::Sql {
                source: Source::Inline { inline: sql.into() },
            },
        }
    }

    pub(super) fn install(&self, bundle: &PackageBundleV1) -> TestResult {
        self.query
            .store()
            .install_package_image([1; 16], bundle, || Ok(()))?;
        self.authority
            .images
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .insert(bundle.digest()?);
        Ok(())
    }

    pub(super) async fn admit(&self, id: &str, sql: &str) -> TestResult<Arc<Instance>> {
        let definition = Self::definition(sql);
        let definition = self
            .query
            .admit_definition(
                [1; 16],
                definition,
                Arc::new(AnalysisReadControl::default()),
            )
            .await?;
        self.query
            .store()
            .admit_definition([1; 16], &definition, || Ok(()))?;
        Ok(Instance::admit(
            Arc::clone(&self.query),
            self.authority.clone(),
            self.grant.clone(),
            id.into(),
            definition,
            &AnalysisReadControl::default(),
        )
        .await?)
    }

    pub(super) fn progress(&self, id: &str) -> TestResult<u64> {
        Ok(self
            .query
            .store()
            .managed_instance([1; 16], id, &AnalysisReadControl::default())?
            .ok_or("managed instance")?
            .progress)
    }

    pub(in crate::instance) fn selected(
        &self,
        instance: &str,
        attempt: &str,
    ) -> TestResult<Vec<u64>> {
        let selected = self
            .query
            .store()
            .managed_selected([1; 16], instance, attempt, &AnalysisReadControl::default())?
            .ok_or("managed selected")?;
        values(&selected.data.batches)
    }
}

fn request(id: &str) -> ManagedRequest {
    ManagedRequest {
        id: id.into(),
        time_utc_ns: 10,
        seed: Some(7),
        rebuild: false,
        witness_expiry: u64::MAX,
        frontier: None,
    }
}

fn values(batches: &[sdk::RecordBatch]) -> TestResult<Vec<u64>> {
    let mut values = Vec::new();
    for batch in batches {
        let column = batch
            .column(0)
            .as_any()
            .downcast_ref::<UInt64Array>()
            .ok_or("selected UInt64")?;
        assert_eq!(column.null_count(), 0);
        values.extend_from_slice(column.values());
    }
    values.sort_unstable();
    Ok(values)
}

pub(super) fn bundle(target: &str) -> TestResult<PackageBundleV1> {
    let schema = sdk::Schema::new(vec![sdk::Field::new("value", sdk::DataType::UInt64, false)]);
    let mut output = sdk::Port::new("data", schema.clone());
    output.evidence_required = target == "sql";
    let mut model = sdk::Model::new(
        "accumulate",
        vec![sdk::Port::new("input", schema.clone())],
        vec![output],
    );
    model.limits.max_bytes = 1024 * 1024;
    model.limits.max_checkpoint_bytes = 1024 * 1024;
    model.checkpoint = Some(sdk::CheckpointSpec {
        version: 1,
        datasets: vec![sdk::Port::new("state", schema.clone())],
    });
    let implementation = match target {
        "sql" => {
            model.reasons.push(sdk::Reason {
                code: "runtime-fixture.sum".into(),
                details: schema,
            });
            PackageImplementationV1::Sql { export: "accumulate".into(), program: SqlModelV1 {
                outputs: BTreeMap::from([("data".into(), "SELECT CAST(COALESCE((SELECT SUM(value) FROM input), 0) + COALESCE((SELECT SUM(value) FROM prior_state), 0) AS BIGINT UNSIGNED) AS value".into())]),
                checkpoint: BTreeMap::from([("state".into(), "SELECT value FROM output_data".into())]),
                evidence: Some("SELECT 'data' AS output_dataset, CAST(0 AS BIGINT UNSIGNED) AS output_row, 'input' AS input_dataset, __row_index AS input_row FROM input".into()),
                reasons: vec![SqlReasonV1 { output: "data".into(), code: "runtime-fixture.sum".into(), sql: "SELECT __row_index AS output_row, value FROM output_data".into() }],
            } }
        }
        "wasm" => PackageImplementationV1::Wasm {
            exports: vec!["accumulate".into()],
            artifact: araphor_analysis_builtins::components::RUNTIME.to_vec(),
        },
        "native" => {
            let directory = std::path::PathBuf::from(
                std::env::var_os("ARAPHOR_NATIVE_DIR").ok_or("ARAPHOR_NATIVE_DIR is required")?,
            );
            let artifact = std::fs::read(
                directory.join(format!("runtime.{}", std::env::consts::DLL_EXTENSION)),
            )?;
            let qualification = araphor_package::Qualification::inspect(
                &artifact,
                vec!["accumulate".into()],
                std::env::var("ARAPHOR_NATIVE_TARGET")?,
            )?;
            PackageImplementationV1::Native {
                export: "accumulate".into(),
                artifact,
                qualification: Some(qualification),
            }
        }
        _ => return Err("fixture target".into()),
    };
    Ok(PackageBundleV1 {
        schema_version: 1,
        root: PackageRefV1 {
            package_id: "runtime-fixture".into(),
            revision: "1".into(),
        },
        artifacts: vec![PackageArtifactV1 {
            descriptor: sdk::Package::new("runtime-fixture", "1", vec![model]),
            implementations: vec![implementation],
            fixtures: Vec::new(),
        }],
    })
}

#[tokio::test]
async fn sql_instance_is_inert() -> TestResult {
    let fixture = Fixture::new(Default::default())?;
    let instance = fixture
        .admit("sql", "SELECT CAST(7 AS BIGINT UNSIGNED) AS value")
        .await?;
    assert_eq!(fixture.progress("sql")?, 0);
    assert!(instance.admitted().spec.manifest.calls.is_empty());
    assert!(fixture
        .query
        .store()
        .managed_attempt([1; 16], "sql", "once", &AnalysisReadControl::default())?
        .is_none());
    let receipt = instance
        .run(request("once"), &AnalysisReadControl::default())
        .await?;
    assert!(receipt.results.is_empty());
    assert_eq!(fixture.selected("sql", "once")?, [7]);
    let meta = fixture.query.store().meta()?;
    assert_eq!(
        instance
            .run(request("once"), &AnalysisReadControl::default())
            .await?,
        receipt
    );
    assert_eq!(fixture.query.store().meta()?, meta);
    let mut changed = request("once");
    changed.seed = Some(8);
    assert!(instance
        .run(changed, &AnalysisReadControl::default())
        .await
        .is_err());
    assert_eq!(fixture.query.store().meta()?, meta);
    fixture.authority.set(false);
    let error = instance
        .run(request("once"), &AnalysisReadControl::default())
        .await
        .err()
        .ok_or("revoked SQL retry succeeded")?;
    assert_eq!(
        error.status_code(),
        erebor_runtime_error::StatusCode::PermissionDenied
    );
    assert_eq!(fixture.query.store().meta()?, meta);
    Ok(())
}

#[tokio::test]
async fn completed_retry_survives_reopen() -> TestResult {
    let capacity = 1024 * 1024;
    let limits = araphor_query::execution::Limits {
        input_capacity: Some(capacity),
        global_evaluations: Some(1),
        tenant_evaluations: Some(1),
        ..Default::default()
    };
    let fixture = Fixture::new(limits.clone())?;
    fixture.install(&bundle("sql")?)?;
    let instance = fixture
        .admit("reopen", r#"SELECT * FROM "runtime-fixture"."1".accumulate(input => (SELECT CAST(11 AS BIGINT UNSIGNED) AS value))"#)
        .await?;
    let definition = instance.admitted().spec.definition.clone();
    let receipt = instance
        .run(request("once"), &AnalysisReadControl::default())
        .await?;
    drop(instance);
    let Fixture {
        directory,
        query,
        authority,
        grant,
    } = fixture;
    drop(query);
    let store = Arc::new(AnalysisStore::open(directory.path().join("data"))?);
    let query = Engine::new(Arc::clone(&store), limits)?;
    let reopened = Instance::admit(
        Arc::clone(&query),
        authority,
        grant,
        "reopen".into(),
        definition,
        &AnalysisReadControl::default(),
    )
    .await?;
    let meta = store.meta()?;
    let retained = query.memory().input_reserved();
    let held = query
        .memory()
        .reserve_input(capacity.saturating_sub(retained))?;
    assert!(query.memory().reserve_input(1).is_err());
    let permit = query.reserve_evaluation([1; 16])?;
    assert_eq!(
        reopened
            .run(request("once"), &AnalysisReadControl::default())
            .await?,
        receipt
    );
    assert_eq!(store.meta()?, meta);
    let selected = store
        .managed_selected([1; 16], "reopen", "once", &AnalysisReadControl::default())?
        .ok_or("saved selected")?;
    assert_eq!(values(&selected.data.batches)?, [11]);
    assert_eq!(receipt.results.len(), 1);
    let returned = receipt.results.values().next().ok_or("saved call")?;
    let saved = store.managed_result(
        reopened.admitted(),
        &returned.result_id,
        10,
        &AnalysisReadControl::default(),
    )?;
    assert_eq!(saved.commit_revision, receipt.commit_revision);
    let checkpoint = saved.output.checkpoint.as_ref().ok_or("saved checkpoint")?;
    assert_eq!(checkpoint.version, 1);
    assert_eq!(values(&checkpoint.datasets[0].batches)?, [11]);
    let mut changed = request("once");
    changed.time_utc_ns += 1;
    assert!(reopened
        .run(changed, &AnalysisReadControl::default())
        .await
        .is_err());
    assert_eq!(store.meta()?, meta);
    drop(permit);
    drop(held);
    drop(query.reserve_evaluation([1; 16])?);
    assert_eq!(query.memory().input_reserved(), retained);
    drop(reopened);
    drop(query.memory().reserve_input(capacity)?);
    Ok(())
}

async fn stateful_calls(target: &str) -> TestResult {
    let fixture = Fixture::new(Default::default())?;
    fixture.install(&bundle(target)?)?;
    let sql = r#"SELECT * FROM "runtime-fixture"."1".accumulate(input => (SELECT CAST(10 AS BIGINT UNSIGNED) AS value)) UNION ALL SELECT * FROM "runtime-fixture"."1".accumulate(input => (SELECT CAST(20 AS BIGINT UNSIGNED) AS value))"#;
    let instance = fixture.admit("state", sql).await?;
    let calls = &instance.admitted().spec.manifest.calls;
    assert_eq!(calls.len(), 2);
    let arguments = calls
        .values()
        .map(|call| &call.arguments)
        .collect::<BTreeSet<_>>();
    assert_eq!(arguments.len(), 2);
    assert_eq!(fixture.progress("state")?, 0);
    for (id, rebuild, expected) in [
        ("first", false, vec![10, 20]),
        ("second", false, vec![20, 40]),
        ("rebuild", true, vec![10, 20]),
    ] {
        let mut input = request(id);
        input.rebuild = rebuild;
        let receipt = instance.run(input, &AnalysisReadControl::default()).await?;
        assert_eq!(fixture.selected("state", id)?, expected, "{target}");
        assert_eq!(receipt.results.len(), 2);
        let mut states = Vec::new();
        for returned in receipt.results.values() {
            let saved = fixture.query.store().managed_result(
                instance.admitted(),
                &returned.result_id,
                10,
                &AnalysisReadControl::default(),
            )?;
            assert_eq!(saved.commit_revision, receipt.commit_revision);
            assert_eq!(saved.output.datasets.len(), 1);
            let state = saved.output.checkpoint.as_ref().ok_or("saved checkpoint")?;
            assert_eq!(state.version, 1);
            states.extend(values(&state.datasets[0].batches)?);
            if target == "sql" {
                assert_eq!(saved.output.evidence.len(), 1);
                assert_eq!(saved.output.reasons.len(), 1);
                assert_eq!(saved.output.reasons[0].code, "runtime-fixture.sum");
                assert_eq!(
                    values(std::slice::from_ref(&saved.output.reasons[0].details))?,
                    values(&saved.output.datasets[0].batches)?
                );
            }
        }
        states.sort_unstable();
        assert_eq!(states, expected);
        assert_eq!(fixture.progress("state")?, receipt.commit_revision);
    }
    Ok(())
}

#[tokio::test]
async fn sql_wasm_keep_state() -> TestResult {
    stateful_calls("sql").await?;
    stateful_calls("wasm").await
}

#[tokio::test]
#[ignore = "requires source-built native artifacts in ARAPHOR_NATIVE_DIR"]
async fn native_keeps_call_state() -> TestResult {
    stateful_calls("native").await
}

#[tokio::test]
async fn selected_pressure_keeps_progress() -> TestResult {
    let fixture = Fixture::new(araphor_query::execution::Limits {
        output_rows: 1,
        ..Default::default()
    })?;
    let instance = fixture.admit("pressure", "SELECT CAST(1 AS BIGINT UNSIGNED) AS value UNION ALL SELECT CAST(2 AS BIGINT UNSIGNED) AS value").await?;
    assert!(instance
        .run(request("too-many"), &AnalysisReadControl::default())
        .await
        .is_err());
    assert_eq!(fixture.progress("pressure")?, 0);
    let attempt = fixture
        .query
        .store()
        .managed_attempt(
            [1; 16],
            "pressure",
            "too-many",
            &AnalysisReadControl::default(),
        )?
        .ok_or("registered attempt")?;
    assert!(attempt.receipt().is_none());
    let read = AnalysisReadControl::default();
    read.on_read_step(|| Err(Code::Invalid.error("pending retry recaptured")))?;
    let error = instance
        .run(request("too-many"), &read)
        .await
        .err()
        .ok_or("pending retry executed")?;
    assert!(format!("{error:?}").contains("managed pending attempt"));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn revoked_guest_joins_attempt() -> TestResult {
    let fixture = Fixture::new(araphor_query::execution::Limits {
        global_evaluations: Some(1),
        tenant_evaluations: Some(1),
        ..Default::default()
    })?;
    let mut image = bundle("wasm")?;
    let model = &mut image.artifacts[0].descriptor.exports[0];
    model.name = "evaluate".into();
    model.inputs.clear();
    model.checkpoint = None;
    model.parameters = sdk::Schema::new(vec![
        sdk::Field::new("mode", sdk::DataType::Utf8, false),
        sdk::Field::new("amount", sdk::DataType::UInt64, false),
    ]);
    let PackageImplementationV1::Wasm { exports, .. } = &mut image.artifacts[0].implementations[0]
    else {
        return Err("Wasm fixture absent".into());
    };
    *exports = vec!["evaluate".into()];
    fixture.install(&image)?;
    let instance = fixture
        .admit(
            "revoke",
            r#"SELECT * FROM "runtime-fixture"."1".evaluate(mode => 'cancel', amount => 7)"#,
        )
        .await?;
    let (entry, observed) = std::sync::mpsc::channel();
    let (release, waiting) = std::sync::mpsc::channel();
    fixture.query.guest_entry(entry, Some(waiting))?;
    let control = Arc::new(AnalysisReadControl::default());
    let stage = Arc::clone(&control);
    let worker = tokio::spawn(async move { instance.run(request("cancelled"), &stage).await });
    let entered =
        tokio::task::spawn_blocking(move || observed.recv_timeout(Duration::from_secs(30))).await?;
    if let Err(error) = entered {
        let _released = release.send(());
        control.cancel()?;
        let result = worker.await?;
        return Err(format!("guest entry failed: {error}; execution: {result:?}").into());
    }
    let pending = fixture
        .query
        .store()
        .managed_attempt(
            [1; 16],
            "revoke",
            "cancelled",
            &AnalysisReadControl::default(),
        )?
        .ok_or("attempt was not registered before guest entry")?;
    assert!(pending.receipt().is_none());
    fixture.authority.set(false);
    tokio::task::yield_now().await;
    assert!(!worker.is_finished());
    assert!(fixture.query.reserve_evaluation([1; 16]).is_err());
    release.send(())?;
    let error = tokio::time::timeout(Duration::from_secs(30), worker)
        .await??
        .err()
        .ok_or("revoked guest published")?;
    assert_eq!(
        error.status_code(),
        erebor_runtime_error::StatusCode::PermissionDenied
    );
    control.check()?;
    assert_eq!(fixture.progress("revoke")?, 0);
    drop(fixture.query.reserve_evaluation([1; 16])?);
    assert!(fixture
        .query
        .store()
        .managed_attempt(
            [1; 16],
            "revoke",
            "cancelled",
            &AnalysisReadControl::default()
        )?
        .ok_or("retained pending attempt")?
        .receipt()
        .is_none());
    Ok(())
}

#[tokio::test]
async fn later_failure_is_atomic() -> TestResult {
    let fixture = Fixture::new(Default::default())?;
    let mut image = bundle("sql")?;
    let PackageImplementationV1::Sql { program, .. } = &mut image.artifacts[0].implementations[0]
    else {
        return Err("SQL implementation".into());
    };
    program.outputs.insert("data".into(), "SELECT CAST(CASE WHEN SUM(value) > 20 THEN 'bad' ELSE '7' END AS BIGINT UNSIGNED) AS value FROM input".into());
    fixture.install(&image)?;
    let instance = fixture.admit("atomic", r#"SELECT * FROM "runtime-fixture"."1".accumulate(input => (SELECT CAST(10 AS BIGINT UNSIGNED) AS value)) UNION ALL SELECT * FROM "runtime-fixture"."1".accumulate(input => (SELECT CAST(30 AS BIGINT UNSIGNED) AS value))"#).await?;
    assert!(instance
        .run(request("failure"), &AnalysisReadControl::default())
        .await
        .is_err());
    assert_eq!(fixture.progress("atomic")?, 0);
    let pending = fixture
        .query
        .store()
        .managed_attempt(
            [1; 16],
            "atomic",
            "failure",
            &AnalysisReadControl::default(),
        )?
        .ok_or("retained failed attempt")?;
    assert!(pending.receipt().is_none());
    assert!(fixture
        .query
        .store()
        .managed_selected(
            [1; 16],
            "atomic",
            "failure",
            &AnalysisReadControl::default()
        )?
        .is_none());
    Ok(())
}

#[tokio::test]
async fn nested_calls_publish_together() -> TestResult {
    let fixture = Fixture::new(Default::default())?;
    fixture.install(&bundle("sql")?)?;
    let instance = fixture.admit("nested", r#"SELECT * FROM "runtime-fixture"."1".accumulate(input => (SELECT value FROM "runtime-fixture"."1".accumulate(input => (SELECT CAST(10 AS BIGINT UNSIGNED) AS value))))"#).await?;
    let declarations = &instance.admitted().spec.manifest.calls;
    assert_eq!(declarations.len(), 2);
    assert_eq!(
        declarations
            .values()
            .map(|call| call.dependencies.len())
            .sum::<usize>(),
        1
    );
    let receipt = instance
        .run(request("nested"), &AnalysisReadControl::default())
        .await?;
    assert_eq!(receipt.results.len(), 2);
    assert_eq!(fixture.selected("nested", "nested")?, [10]);
    for returned in receipt.results.values() {
        assert_eq!(returned.commit_revision, receipt.commit_revision);
    }
    Ok(())
}

#[tokio::test]
async fn denied_ack_keeps_receipt() -> TestResult {
    let fixture = Fixture::new(Default::default())?;
    let instance = fixture
        .admit("ack", "SELECT CAST(17 AS BIGINT UNSIGNED) AS value")
        .await?;
    let authority = Arc::clone(&fixture.authority);
    fixture.query.store().set_commit_hook(
        araphor_data::AnalysisCommitStage::BeforeResultCommit,
        move || {
            authority.deny_next.store(true, Ordering::SeqCst);
            Ok(())
        },
    )?;
    let error = instance
        .run(request("committed"), &AnalysisReadControl::default())
        .await
        .err()
        .ok_or("acknowledgment ignored current authority")?;
    assert_eq!(
        error.status_code(),
        erebor_runtime_error::StatusCode::PermissionDenied
    );
    let saved = fixture
        .query
        .store()
        .managed_attempt([1; 16], "ack", "committed", &AnalysisReadControl::default())?
        .ok_or("committed attempt")?;
    let receipt = saved
        .receipt()
        .ok_or("durable receipt was lost after denied acknowledgment")?;
    assert_eq!(fixture.progress("ack")?, receipt.commit_revision);
    assert_eq!(fixture.selected("ack", "committed")?, [17]);
    let meta = fixture.query.store().meta()?;
    assert_eq!(
        instance
            .run(request("committed"), &AnalysisReadControl::default())
            .await?,
        *receipt
    );
    assert_eq!(fixture.query.store().meta()?, meta);
    Ok(())
}

#[tokio::test]
async fn native_elimination_keeps_step() -> TestResult {
    let fixture = Fixture::new(Default::default())?;
    fixture.install(&bundle("wasm")?)?;
    for (id, suffix) in [("false", "WHERE FALSE"), ("limit", "LIMIT 0")] {
        let instance = fixture.admit(id, &format!(r#"SELECT * FROM "runtime-fixture"."1".accumulate(input => (SELECT CAST(1 AS BIGINT UNSIGNED) AS value)) {suffix}"#)).await?;
        assert_eq!(instance.admitted().spec.manifest.calls.len(), 1);
        let (entry, observed) = std::sync::mpsc::channel();
        fixture.query.guest_entry(entry, None)?;
        let receipt = instance
            .run(request(id), &AnalysisReadControl::default())
            .await?;
        assert!(receipt.results.is_empty());
        assert!(fixture.selected(id, id)?.is_empty());
        assert_eq!(fixture.progress(id)?, receipt.commit_revision);
        assert!(matches!(
            observed.try_recv(),
            Err(std::sync::mpsc::TryRecvError::Empty)
        ));
    }
    Ok(())
}

#[tokio::test]
async fn prior_pressure_preserves_success() -> TestResult {
    let capacity = 64 * 1024;
    let fixture = Fixture::new(araphor_query::execution::Limits {
        input_bytes: capacity,
        input_capacity: Some(capacity),
        ..Default::default()
    })?;
    fixture.install(&bundle("sql")?)?;
    let instance = fixture.admit("prior-pressure", r#"SELECT * FROM "runtime-fixture"."1".accumulate(input => (SELECT CAST(10 AS BIGINT UNSIGNED) AS value))"#).await?;
    let first = instance
        .run(request("first"), &AnalysisReadControl::default())
        .await?;
    assert_eq!(fixture.selected("prior-pressure", "first")?, [10]);
    let retained = fixture.query.memory().input_reserved();
    let pressure = fixture
        .query
        .memory()
        .reserve_input(capacity.saturating_sub(retained).saturating_sub(1))?;
    let last = fixture.query.memory().reserve_input(1)?;
    assert!(fixture.query.memory().reserve_input(1).is_err());
    drop(last);
    assert!(instance
        .run(request("pressure"), &AnalysisReadControl::default())
        .await
        .is_err());
    assert_eq!(fixture.progress("prior-pressure")?, first.commit_revision);
    assert_eq!(fixture.selected("prior-pressure", "first")?, [10]);
    assert!(fixture
        .query
        .store()
        .managed_attempt(
            [1; 16],
            "prior-pressure",
            "pressure",
            &AnalysisReadControl::default()
        )?
        .is_none());
    drop(pressure);
    let second = instance
        .run(request("pressure"), &AnalysisReadControl::default())
        .await?;
    assert_eq!(fixture.selected("prior-pressure", "pressure")?, [20]);
    assert_eq!(fixture.progress("prior-pressure")?, second.commit_revision);
    assert_eq!(fixture.query.memory().input_reserved(), retained);
    drop(instance);
    drop(fixture.query.memory().reserve_input(capacity)?);
    Ok(())
}

impl Fixture {
    pub(super) fn start(&self, instance: &Instance) -> TestResult<u64> {
        let current = instance.admitted();
        Ok(self
            .query
            .store()
            .set_managed_running(
                current.spec.tenant,
                &current.spec.id,
                current.lifecycle,
                true,
                || Ok(()),
            )?
            .lifecycle)
    }

    pub(super) fn context(&self, revision: u64) -> TestResult {
        self.query
            .store()
            .commit_context(&araphor_data::AnalysisContextVersionV1 {
                key: araphor_data::AnalysisContextKeyV1 {
                    tenant_id: [1; 16],
                    owner_id: "instance-context".into(),
                    entity_key: vec![1],
                    lifetime_key: vec![1],
                    owner_revision: revision,
                },
                valid_from_utc_ns: None,
                valid_until_utc_ns: None,
                sensitivity: araphor_data::ContextSensitivityV1::Tenant,
                body: vec![1],
            })?;
        Ok(())
    }
}

#[tokio::test]
async fn sql_subscription_keeps_receipts() -> TestResult {
    use futures_util::StreamExt as _;

    let fixture = Fixture::new(Default::default())?;
    fixture.context(1)?;
    let instance = fixture.admit("follow-sql", "SELECT CAST(7 AS BIGINT UNSIGNED) AS value WHERE EXISTS (SELECT 1 FROM context_versions)").await?;
    let lifecycle = fixture.start(&instance)?;
    let mut stream = instance.subscribe(
        Arc::new(AnalysisReadControl::default()),
        u64::MAX,
        lifecycle,
    )?;
    assert_eq!(fixture.progress("follow-sql")?, 0);
    let first = tokio::time::timeout(Duration::from_secs(30), stream.next())
        .await?
        .ok_or("initial SQL receipt")??;
    assert!(first.results.is_empty());
    assert_eq!(fixture.selected("follow-sql", &first.attempt)?, [7]);
    assert_eq!(fixture.progress("follow-sql")?, first.commit_revision);
    assert!(futures_util::poll!(stream.next()).is_pending());
    fixture.context(2)?;
    let second = tokio::time::timeout(Duration::from_secs(30), stream.next())
        .await?
        .ok_or("changed SQL receipt")??;
    assert_ne!(first.attempt, second.attempt);
    assert!(second.commit_revision > first.commit_revision);
    assert_eq!(fixture.selected("follow-sql", &second.attempt)?, [7]);
    assert_eq!(fixture.progress("follow-sql")?, second.commit_revision);
    assert!(futures_util::poll!(stream.next()).is_pending());
    stream
        .cancel_and_join(&AnalysisReadControl::default())
        .await?;
    assert_eq!(fixture.selected("follow-sql", &first.attempt)?, [7]);
    Ok(())
}

async fn managed_subscription(target: &str) -> TestResult {
    use futures_util::StreamExt as _;

    const INPUT: usize = 2 * 1024 * 1024;
    const OUTPUT: usize = 32 * 1024 * 1024;
    let sql = r#"SELECT * FROM "runtime-fixture"."1".accumulate(input => (SELECT CAST(10 AS BIGINT UNSIGNED) AS value WHERE EXISTS (SELECT 1 FROM context_versions))) UNION ALL SELECT * FROM "runtime-fixture"."1".accumulate(input => (SELECT CAST(20 AS BIGINT UNSIGNED) AS value WHERE EXISTS (SELECT 1 FROM context_versions)))"#;
    let fixture = Fixture::image_limits(
        araphor_query::execution::Limits {
            global_evaluations: Some(1),
            tenant_evaluations: Some(1),
            input_capacity: Some(INPUT),
            output_capacity: Some(OUTPUT),
            ..Default::default()
        },
        &bundle(target)?,
        sql,
    )
    .await?;
    fixture.context(1)?;
    let instance = fixture.admit("follow-state", sql).await?;
    let retained = fixture.query.memory().input_reserved();
    let lifecycle = fixture.start(&instance)?;
    let mut stream = instance.subscribe(
        Arc::new(AnalysisReadControl::default()),
        u64::MAX,
        lifecycle,
    )?;
    let first = tokio::time::timeout(Duration::from_secs(30), stream.next())
        .await?
        .ok_or("initial stateful receipt")??;
    assert_eq!(fixture.selected("follow-state", &first.attempt)?, [10, 20]);
    assert_eq!(first.results.len(), 2);
    assert_eq!(
        first.results.keys().copied().collect::<BTreeSet<_>>(),
        instance
            .admitted
            .spec
            .manifest
            .calls
            .keys()
            .copied()
            .collect(),
    );
    assert!(futures_util::poll!(stream.next()).is_pending());
    fixture.context(2)?;
    let second = tokio::time::timeout(Duration::from_secs(30), stream.next())
        .await?
        .ok_or("changed stateful receipt")??;
    assert_eq!(fixture.selected("follow-state", &second.attempt)?, [10, 20]);
    assert_eq!(second.results.len(), 2);
    assert_ne!(first.attempt, second.attempt);
    let attempt = fixture
        .query
        .store()
        .managed_attempt(
            [1; 16],
            "follow-state",
            &second.attempt,
            &AnalysisReadControl::default(),
        )?
        .ok_or("registered follow attempt")?;
    assert_eq!(attempt.receipt(), Some(&second));
    assert_eq!(
        second.results.keys().copied().collect::<BTreeSet<_>>(),
        instance
            .admitted
            .spec
            .manifest
            .calls
            .keys()
            .copied()
            .collect(),
    );
    for reference in second.results.values() {
        let result = fixture.query.store().managed_result(
            instance.admitted(),
            &reference.result_id,
            u64::MAX,
            &AnalysisReadControl::default(),
        )?;
        assert_eq!(result.commit_revision, second.commit_revision);
        assert_eq!(result.context.context.id, second.attempt);
        assert_eq!(
            result.context.context.time_utc_ns,
            attempt.request().time_utc_ns as i64
        );
        assert!(result.output.checkpoint.is_some());
    }
    assert!(futures_util::poll!(stream.next()).is_pending());
    stream
        .cancel_and_join(&AnalysisReadControl::default())
        .await?;
    drop(fixture.query.reserve_evaluation([1; 16])?);
    assert_eq!(fixture.query.memory().input_reserved(), retained);
    let pressure = fixture.query.memory().reserve_input(
        fixture
            .query
            .limits()
            .input_capacity
            .ok_or("input capacity")?
            .saturating_sub(retained),
    )?;
    assert!(fixture.query.memory().reserve_input(1).is_err());
    drop(pressure);
    drop(fixture.query.memory().reserve_output(OUTPUT)?);
    assert_eq!(fixture.progress("follow-state")?, second.commit_revision);
    assert_eq!(first.results.len(), 2);
    drop(instance);
    let readmitted = fixture.admit("follow-state", sql).await?;
    let lifecycle = fixture.start(&readmitted)?;
    let mut resumed = readmitted.subscribe(
        Arc::new(AnalysisReadControl::default()),
        u64::MAX,
        lifecycle,
    )?;
    fixture.context(3)?;
    let third = tokio::time::timeout(Duration::from_secs(30), resumed.next())
        .await?
        .ok_or("resumed guest receipt")??;
    assert!(third.commit_revision > second.commit_revision);
    assert_ne!(third.attempt, second.attempt);
    assert_eq!(
        third.results.keys().copied().collect::<BTreeSet<_>>(),
        readmitted
            .admitted
            .spec
            .manifest
            .calls
            .keys()
            .copied()
            .collect()
    );
    assert_eq!(fixture.selected("follow-state", &third.attempt)?, [10, 20]);
    assert!(third.frontier.is_some());
    resumed
        .cancel_and_join(&AnalysisReadControl::default())
        .await?;
    drop(fixture.query.reserve_evaluation([1; 16])?);
    drop(readmitted);
    drop(
        fixture.query.memory().reserve_input(
            fixture
                .query
                .limits()
                .input_capacity
                .ok_or("input capacity")?,
        )?,
    );
    drop(fixture.query.memory().reserve_output(OUTPUT)?);
    Ok(())
}

#[tokio::test]
async fn wasm_subscription_one_step() -> TestResult {
    managed_subscription("wasm").await
}

#[tokio::test]
#[ignore = "requires source-built native artifacts in ARAPHOR_NATIVE_DIR"]
async fn native_subscription_one_step() -> TestResult {
    managed_subscription("native").await
}

#[tokio::test]
async fn idle_subscription_checks_authority() -> TestResult {
    use futures_util::StreamExt as _;

    let fixture = Fixture::new(Default::default())?;
    fixture.context(1)?;
    let instance = fixture.admit("follow-authority", "SELECT CAST(7 AS BIGINT UNSIGNED) AS value WHERE EXISTS (SELECT 1 FROM context_versions)").await?;
    let lifecycle = fixture.start(&instance)?;
    let mut stream = instance.subscribe(
        Arc::new(AnalysisReadControl::default()),
        u64::MAX,
        lifecycle,
    )?;
    let receipt = tokio::time::timeout(Duration::from_secs(30), stream.next())
        .await?
        .ok_or("authorized receipt")??;
    assert!(futures_util::poll!(stream.next()).is_pending());
    fixture.authority.set(false);
    let error = tokio::time::timeout(Duration::from_secs(30), stream.next())
        .await?
        .ok_or("authority failure")?
        .err()
        .ok_or("revoked subscription continued")?;
    assert_eq!(
        error.status_code(),
        erebor_runtime_error::StatusCode::PermissionDenied
    );
    stream
        .cancel_and_join(&AnalysisReadControl::default())
        .await?;
    assert_eq!(
        fixture.progress("follow-authority")?,
        receipt.commit_revision
    );
    Ok(())
}

#[tokio::test]
async fn sql_frontier_survives_reopen() -> TestResult {
    use futures_util::StreamExt as _;

    let fixture = Fixture::new(Default::default())?;
    fixture.context(1)?;
    let sql =
        "SELECT CAST(7 AS BIGINT UNSIGNED) AS value WHERE EXISTS (SELECT 1 FROM context_versions)";
    let instance = fixture.admit("durable-sql", sql).await?;
    let lifecycle = fixture.start(&instance)?;
    let mut stream = instance.subscribe(
        Arc::new(AnalysisReadControl::default()),
        u64::MAX,
        lifecycle,
    )?;
    let first = tokio::time::timeout(Duration::from_secs(30), stream.next())
        .await?
        .ok_or("durable first receipt")??;
    stream
        .cancel_and_join(&AnalysisReadControl::default())
        .await?;
    let frontier = first.frontier.clone().ok_or("committed native frontier")?;
    let original = fixture
        .query
        .store()
        .managed_attempt(
            [1; 16],
            "durable-sql",
            &first.attempt,
            &AnalysisReadControl::default(),
        )?
        .ok_or("durable first attempt")?;
    let original_time = original.request().time_utc_ns;
    let Fixture {
        directory,
        query,
        authority,
        grant,
    } = fixture;
    drop(instance);
    drop(query);
    let fixture = Fixture {
        query: Engine::new(
            Arc::new(AnalysisStore::open(directory.path().join("data"))?),
            Default::default(),
        )?,
        directory,
        authority,
        grant,
    };
    let araphor_data::ManagedResume {
        instance: saved,
        frontier: resumed,
        ..
    } = fixture.query.store().managed_resume(
        [1; 16],
        "durable-sql",
        &AnalysisReadControl::default(),
    )?;
    assert_eq!(saved.progress, first.commit_revision);
    assert_eq!(resumed, Some(frontier));
    let instance = fixture.admit("durable-sql", sql).await?;
    fixture.context(2)?;
    let lifecycle = fixture.start(&instance)?;
    let mut stream = instance.subscribe(
        Arc::new(AnalysisReadControl::default()),
        u64::MAX,
        lifecycle,
    )?;
    let second = tokio::time::timeout(Duration::from_secs(30), stream.next())
        .await?
        .ok_or("durable changed receipt")??;
    assert_ne!(second.attempt, first.attempt);
    assert!(second.commit_revision > first.commit_revision);
    assert_eq!(fixture.selected("durable-sql", &first.attempt)?, [7]);
    assert_eq!(fixture.selected("durable-sql", &second.attempt)?, [7]);
    let original = fixture
        .query
        .store()
        .managed_attempt(
            [1; 16],
            "durable-sql",
            &first.attempt,
            &AnalysisReadControl::default(),
        )?
        .ok_or("retained durable attempt")?;
    assert_eq!(original.request().time_utc_ns, original_time);
    assert_eq!(original.receipt(), Some(&first));
    stream
        .cancel_and_join(&AnalysisReadControl::default())
        .await?;
    Ok(())
}

#[tokio::test]
async fn failed_step_blocks_restart() -> TestResult {
    let fixture = Fixture::new(Default::default())?;
    let mut image = bundle("wasm")?;
    let model = &mut image.artifacts[0].descriptor.exports[0];
    model.name = "evaluate".into();
    model.inputs.clear();
    model.checkpoint = None;
    model.parameters = sdk::Schema::new(vec![
        sdk::Field::new("mode", sdk::DataType::Utf8, false),
        sdk::Field::new("amount", sdk::DataType::UInt64, false),
    ]);
    let PackageImplementationV1::Wasm { exports, .. } = &mut image.artifacts[0].implementations[0]
    else {
        return Err("Wasm pending fixture absent".into());
    };
    *exports = vec!["evaluate".into()];
    fixture.install(&image)?;
    let instance = fixture
        .admit(
            "durable-pending",
            r#"SELECT * FROM "runtime-fixture"."1".evaluate(mode => 'trap', amount => 0)"#,
        )
        .await?;
    assert!(instance
        .run(
            request("entered-and-failed"),
            &AnalysisReadControl::default()
        )
        .await
        .is_err());
    assert!(fixture
        .query
        .store()
        .managed_attempt(
            [1; 16],
            "durable-pending",
            "entered-and-failed",
            &AnalysisReadControl::default()
        )?
        .ok_or("failed attempt")?
        .receipt()
        .is_none());
    let lifecycle = fixture.start(&instance)?;
    let before = fixture.query.store().meta()?;
    let error = instance
        .subscribe(
            Arc::new(AnalysisReadControl::default()),
            u64::MAX,
            lifecycle,
        )
        .err()
        .ok_or("pending work silently reopened")?;
    assert!(matches!(
        error,
        crate::Error::Data {
            source: araphor_data::Error::Package {
                code: Code::Incomplete,
                field: "managed pending attempt",
                ..
            }
        }
    ));
    assert_eq!(fixture.query.store().meta()?, before);
    assert_eq!(fixture.progress("durable-pending")?, 0);
    Ok(())
}

#[tokio::test]
async fn stream_keeps_selected_lifecycle() -> TestResult {
    use futures_util::StreamExt as _;

    let fixture = Fixture::new(Default::default())?;
    fixture.context(1)?;
    let instance = fixture.admit("durable-lifecycle",
        "SELECT CAST(7 AS BIGINT UNSIGNED) AS value WHERE EXISTS (SELECT 1 FROM context_versions)").await?;
    let running = fixture.query.store().set_managed_running(
        [1; 16],
        "durable-lifecycle",
        instance.admitted().lifecycle,
        true,
        || Ok(()),
    )?;
    let mut stream = instance.subscribe(
        Arc::new(AnalysisReadControl::default()),
        u64::MAX,
        running.lifecycle,
    )?;
    let first = tokio::time::timeout(Duration::from_secs(30), stream.next())
        .await?
        .ok_or("lifecycle receipt")??;
    let stopped = fixture.query.store().set_managed_running(
        [1; 16],
        "durable-lifecycle",
        running.lifecycle,
        false,
        || Ok(()),
    )?;
    fixture.query.store().set_managed_running(
        [1; 16],
        "durable-lifecycle",
        stopped.lifecycle,
        true,
        || Ok(()),
    )?;
    fixture.context(2)?;
    let error = tokio::time::timeout(Duration::from_secs(30), stream.next())
        .await?
        .ok_or("lifecycle fence result")?
        .err()
        .ok_or("stream adopted a later lifecycle")?;
    assert!(
        error.to_string().contains("managed instance lifecycle"),
        "{error:?}"
    );
    assert_eq!(
        fixture.progress("durable-lifecycle")?,
        first.commit_revision
    );
    stream
        .cancel_and_join(&AnalysisReadControl::default())
        .await?;
    Ok(())
}

#[tokio::test]
async fn subscription_requires_current_lifecycle() -> TestResult {
    use futures_util::StreamExt as _;

    let fixture = Fixture::new(Default::default())?;
    fixture.context(1)?;
    let instance = fixture
        .admit(
            "sealed-lifecycle",
            "SELECT value FROM (VALUES (7)) AS rows(value)",
        )
        .await?;
    let inactive = instance.admitted().lifecycle;
    let before = fixture.query.store().meta()?;
    let error = instance
        .subscribe(Arc::new(AnalysisReadControl::default()), u64::MAX, inactive)
        .err()
        .ok_or("inactive subscription accepted")?;
    assert!(matches!(
        error,
        crate::Error::Data {
            source: araphor_data::Error::Package {
                code: Code::Conflict,
                field: "managed subscription lifecycle",
                ..
            }
        }
    ));
    assert_eq!(fixture.query.store().meta()?, before);
    let lifecycle = fixture.start(&instance)?;
    let before = fixture.query.store().meta()?;
    let error = instance
        .subscribe(Arc::new(AnalysisReadControl::default()), u64::MAX, inactive)
        .err()
        .ok_or("stale subscription accepted")?;
    assert!(matches!(
        error,
        crate::Error::Data {
            source: araphor_data::Error::Package {
                code: Code::Conflict,
                field: "managed subscription lifecycle",
                ..
            }
        }
    ));
    assert_eq!(fixture.query.store().meta()?, before);
    let mut stream = instance.subscribe(
        Arc::new(AnalysisReadControl::default()),
        u64::MAX,
        lifecycle,
    )?;
    let stopped = fixture.query.store().set_managed_running(
        [1; 16],
        "sealed-lifecycle",
        lifecycle,
        false,
        || Ok(()),
    )?;
    let before = fixture.query.store().meta()?;
    let error = tokio::time::timeout(Duration::from_secs(30), stream.next())
        .await?
        .ok_or("stale stream ended without error")?
        .err()
        .ok_or("stopped stream executed")?;
    assert!(
        error.to_string().contains("managed instance lifecycle"),
        "{error:?}"
    );
    stream
        .cancel_and_join(&AnalysisReadControl::default())
        .await?;
    assert_eq!(fixture.query.store().meta()?, before);
    let araphor_data::ManagedResume {
        instance: current,
        frontier,
        ..
    } = fixture.query.store().managed_resume(
        [1; 16],
        "sealed-lifecycle",
        &AnalysisReadControl::default(),
    )?;
    assert_eq!(current.lifecycle, stopped.lifecycle);
    assert!(!current.running);
    assert_eq!(current.progress, 0);
    assert!(frontier.is_none());
    Ok(())
}

#[tokio::test]
async fn instance_shares_admitted_images() -> TestResult {
    const CAPACITY: usize = 1024 * 1024;
    let fixture = Fixture::new(araphor_query::execution::Limits {
        input_capacity: Some(CAPACITY),
        ..Default::default()
    })?;
    fixture.install(&bundle("sql")?)?;
    let instance = fixture
        .admit(
            "shared-image",
            r#"SELECT * FROM "runtime-fixture"."1".accumulate(
        input => (SELECT CAST(11 AS BIGINT UNSIGNED) AS value))"#,
        )
        .await?;
    let images = instance.prepared.images().collect::<Vec<_>>();
    assert_eq!(images.len(), 1);
    assert_eq!(instance.calls.len(), 1);
    let call = instance.calls.values().next().ok_or("call absent")?;
    assert!(std::ptr::eq(
        call.descriptor(),
        &images[0].0.artifacts[0].descriptor
    ));
    let retained = fixture.query.memory().input_reserved();
    assert!(retained > 0 && retained < CAPACITY);
    let pressure = fixture
        .query
        .memory()
        .reserve_input(CAPACITY.saturating_sub(retained))?;
    assert!(fixture.query.memory().reserve_input(1).is_err());
    let copy = Arc::clone(&instance);
    assert!(fixture.query.memory().reserve_input(CAPACITY).is_err());
    drop(images);
    drop(instance);
    assert!(fixture.query.memory().reserve_input(CAPACITY).is_err());
    assert_eq!(fixture.query.memory().input_reserved(), CAPACITY);
    drop(copy);
    assert_eq!(fixture.query.memory().input_reserved(), CAPACITY - retained);
    drop(pressure);
    drop(fixture.query.memory().reserve_input(CAPACITY)?);
    Ok(())
}

#[tokio::test]
async fn image_authority_precedes_preparation() -> TestResult {
    const CAPACITY: usize = 32 * 1024 * 1024;
    let fixture = Fixture::new(araphor_query::execution::Limits {
        input_capacity: Some(CAPACITY),
        ..Default::default()
    })?;
    let image = bundle("wasm")?;
    fixture.install(&image)?;
    fixture
        .authority
        .images
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .clear();
    let (entered, observed) = std::sync::mpsc::channel();
    let (_release, waiting) = std::sync::mpsc::channel();
    fixture.query.preparation_entry(entered, waiting)?;
    let sql = r#"SELECT * FROM "runtime-fixture"."1".accumulate(
        input => (SELECT CAST(11 AS BIGINT UNSIGNED) AS value))"#;
    let error = tokio::time::timeout(
        Duration::from_secs(30),
        fixture.admit("untrusted-image", sql),
    )
    .await?
    .err()
    .ok_or("untrusted image admitted")?;
    let domain = error
        .downcast_ref::<crate::Error>()
        .ok_or("Analysis authority error absent")?;
    assert_eq!(
        domain.status_code(),
        erebor_runtime_error::StatusCode::PermissionDenied
    );
    assert!(matches!(
        observed.try_recv(),
        Err(std::sync::mpsc::TryRecvError::Empty)
    ));
    assert_eq!(fixture.query.memory().input_reserved(), 0);
    drop(fixture.query.memory().reserve_input(CAPACITY)?);
    fixture
        .authority
        .images
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .insert(image.digest()?);
    let instance = fixture.admit("trusted-image", sql).await?;
    assert!(matches!(
        observed.try_recv(),
        Err(std::sync::mpsc::TryRecvError::Empty)
    ));
    drop(instance);
    assert_eq!(fixture.query.memory().input_reserved(), 0);
    drop(fixture.query.memory().reserve_input(CAPACITY)?);
    Ok(())
}

#[tokio::test]
async fn subscription_keeps_selected_progress() -> TestResult {
    use futures_util::StreamExt as _;

    let fixture = Fixture::new(araphor_query::execution::Limits {
        global_evaluations: Some(1),
        tenant_evaluations: Some(1),
        ..Default::default()
    })?;
    let package = bundle("sql")?;
    fixture.install(&package)?;
    fixture.context(1)?;
    let instance = fixture.admit("sealed-progress", r#"SELECT * FROM "runtime-fixture"."1".accumulate(input => (SELECT CAST(10 AS BIGINT UNSIGNED) AS value WHERE EXISTS (SELECT 1 FROM context_versions)))"#).await?;
    let lifecycle = fixture.start(&instance)?;
    let active = Arc::new(AnalysisReadControl::default());
    let waiting = Arc::new(AnalysisReadControl::default());
    let mut stream = instance.subscribe(Arc::clone(&active), u64::MAX, lifecycle)?;
    let mut stale = instance.subscribe(Arc::clone(&waiting), u64::MAX, lifecycle)?;
    let first = tokio::time::timeout(Duration::from_secs(30), stream.next())
        .await?
        .ok_or("initial progress receipt")??;
    assert_eq!(fixture.selected("sealed-progress", &first.attempt)?, [10]);
    assert!(futures_util::poll!(stream.next()).is_pending());
    fixture.context(2)?;
    let second = tokio::time::timeout(Duration::from_secs(30), stream.next())
        .await?
        .ok_or("next progress receipt")??;
    assert!(second.commit_revision > first.commit_revision);
    assert_eq!(fixture.selected("sealed-progress", &second.attempt)?, [10]);
    stream
        .cancel_and_join(&AnalysisReadControl::default())
        .await?;
    waiting.check()?;

    let store = fixture.query.store();
    let control = AnalysisReadControl::default();
    let before = store.meta()?;
    let saved = store.managed_resume([1; 16], "sealed-progress", &control)?;
    assert_eq!(saved.instance.lifecycle, lifecycle);
    assert!(saved.instance.running);
    assert_eq!(saved.instance.progress, second.commit_revision);
    let attempt = store
        .managed_attempt([1; 16], "sealed-progress", &second.attempt, &control)?
        .ok_or("saved progress attempt")?;
    assert_eq!(attempt.receipt(), Some(&second));
    let result = store.managed_result(
        instance.admitted(),
        &second
            .results
            .values()
            .next()
            .ok_or("stateful result")?
            .result_id,
        u64::MAX,
        &control,
    )?;
    let model = &package.artifacts[0].descriptor.exports[0];
    let output = sdk::wire::Output::encode_model(&result.output, model, result.limits)?;

    let rejected = tokio::time::timeout(Duration::from_secs(30), stale.next())
        .await?
        .ok_or("stale progress stream ended")?;
    stale
        .cancel_and_join(&AnalysisReadControl::default())
        .await?;
    assert_eq!(fixture.progress("sealed-progress")?, second.commit_revision);
    assert_eq!(store.meta()?, before);
    assert_eq!(
        store.managed_resume([1; 16], "sealed-progress", &control)?,
        saved
    );
    let error = rejected.err().ok_or("stale progress stream published")?;
    assert!(
        error
            .to_string()
            .contains("managed subscription completion"),
        "{error:?}"
    );
    assert_eq!(
        error.status_code(),
        erebor_runtime_error::StatusCode::AlreadyExists
    );
    let retained = store
        .managed_attempt([1; 16], "sealed-progress", &second.attempt, &control)?
        .ok_or("retained progress attempt")?;
    assert_eq!(retained.request(), attempt.request());
    assert_eq!(retained.instance(), attempt.instance());
    assert_eq!(retained.receipt(), attempt.receipt());
    let retained = store.managed_result(
        instance.admitted(),
        &second
            .results
            .values()
            .next()
            .ok_or("retained stateful result")?
            .result_id,
        u64::MAX,
        &control,
    )?;
    assert_eq!(retained.context, result.context);
    assert_eq!(retained.commit_revision, result.commit_revision);
    assert_eq!(retained.current, result.current);
    assert_eq!(retained.limits, result.limits);
    assert_eq!(
        sdk::wire::Output::encode_model(&retained.output, model, retained.limits)?,
        output
    );
    assert_eq!(fixture.selected("sealed-progress", &first.attempt)?, [10]);
    assert_eq!(fixture.selected("sealed-progress", &second.attempt)?, [10]);
    drop(fixture.query.reserve_evaluation([1; 16])?);
    Ok(())
}
