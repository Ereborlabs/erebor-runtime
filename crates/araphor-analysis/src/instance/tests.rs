use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use araphor_analysis_sdk as sdk;
use araphor_data::{AnalysisSelectionV1, AnalysisStore};
use araphor_discovery_definition::{Definition, Program, Source};
use araphor_package::{
    PackageArtifactV1, PackageImplementationV1, PackageRefV1, SqlModelV1, SqlReasonV1,
};
use erebor_runtime_error::ErrorExt as _;
use sdk::arrow_array::{Array as _, UInt64Array};

use super::*;

mod history;

type TestResult<T = ()> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

struct Authority {
    allowed: Mutex<bool>,
    images: Mutex<BTreeSet<String>>,
    changes: tokio::sync::watch::Sender<u64>,
    deny_next: AtomicBool,
}

impl Authority {
    fn set(&self, allowed: bool) {
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

struct Fixture {
    directory: tempfile::TempDir,
    query: Arc<Engine>,
    authority: Arc<Authority>,
    grant: PackageGrantV1,
}

impl Fixture {
    fn new(limits: araphor_query::execution::Limits) -> TestResult<Self> {
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

    fn install(&self, bundle: &PackageBundleV1) -> TestResult {
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

    async fn admit(&self, id: &str, sql: &str) -> TestResult<Arc<Instance>> {
        let definition = Definition {
            name: "instance-fixture".into(),
            description: String::new(),
            labels: BTreeMap::new(),
            program: Program::Sql {
                source: Source::Inline { inline: sql.into() },
            },
        };
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

    fn progress(&self, id: &str) -> TestResult<u64> {
        Ok(self
            .query
            .store()
            .managed_instance([1; 16], id, &AnalysisReadControl::default())?
            .ok_or("managed instance")?
            .progress)
    }

    fn selected(&self, instance: &str, attempt: &str) -> TestResult<Vec<u64>> {
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

fn bundle(target: &str) -> TestResult<PackageBundleV1> {
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
    let held = query.memory().reserve_input(capacity)?;
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
    let pressure = fixture.query.memory().reserve_input(capacity - 1)?;
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
    drop(fixture.query.memory().reserve_input(capacity)?);
    Ok(())
}
