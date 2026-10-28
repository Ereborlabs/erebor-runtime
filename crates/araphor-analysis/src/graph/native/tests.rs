mod expiry;
mod feed;
mod gates;
mod input;
mod managed;
mod storage;
mod subscription;

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use araphor_data::{
    AnalysisReadControl, AnalysisSelectionV1, AnalysisStore, DiscoveryInputManifestV1,
    EvidenceIntakeIdentityV1, PackageArtifactV1, PackageBundle, PackageBundleV1,
    PackageImplementationV1, ValidatedEvidenceBatchV1,
};
use araphor_query::execution::Engine;
use tokio::sync::watch;

use super::*;

type TestResult<T = ()> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

type GraphHistory = Vec<(
    String,
    araphor_data::GraphSnapshotV1,
    u64,
    Option<Vec<u8>>,
    (
        Vec<araphor_data::AnalysisWitnessV1>,
        Vec<AnalysisContextRefV1>,
    ),
)>;

impl Projection {
    fn observe_capture(&self) -> std::sync::mpsc::Receiver<Arc<Capture>> {
        let (send, receive) = std::sync::mpsc::channel();
        *self
            .observed
            .lock()
            .unwrap_or_else(|error| error.into_inner()) = Some(send);
        receive
    }
}

struct Authority {
    changes: watch::Sender<u64>,
    allowed: AtomicBool,
    trusted: AtomicBool,
    gate: Mutex<
        Option<(
            tokio::sync::oneshot::Sender<()>,
            std::sync::mpsc::Receiver<()>,
        )>,
    >,
}

impl Authority {
    fn set(&self, allowed: bool) {
        self.allowed.store(allowed, Ordering::SeqCst);
        self.changes.send_modify(|revision| *revision += 1);
    }
}

impl PackageAuthorization for Authority {
    fn check(&self, grant: &PackageGrantV1, _: PackageActionV1) -> araphor_data::Result<()> {
        grant.remaining()?;
        if !self.allowed.load(Ordering::SeqCst) {
            return Err(Code::Denied.error("graph fixture authority"));
        }
        Ok(())
    }
    fn admit(&self, grant: &PackageGrantV1, _: &PackageBundle) -> araphor_data::Result<()> {
        if let Some((entered, release)) = self
            .gate
            .lock()
            .map_err(|_| Code::Incomplete.error("Graph admission gate"))?
            .take()
        {
            entered
                .send(())
                .map_err(|_| Code::Incomplete.error("Graph admission observer"))?;
            release
                .recv_timeout(std::time::Duration::from_secs(30))
                .map_err(|_| Code::Incomplete.error("Graph admission release"))?;
        }
        if !self.trusted.load(Ordering::SeqCst) {
            return Err(Code::Denied.error("graph fixture image trust"));
        }
        self.check(grant, PackageActionV1::Run)
    }
    fn commit(
        &self,
        grant: &PackageGrantV1,
        action: PackageActionV1,
        bundle: &PackageBundle,
        operation: &mut dyn FnMut() -> araphor_data::Result<()>,
    ) -> araphor_data::Result<()> {
        self.commit_many(
            &[(grant, action, None), (grant, action, Some(bundle))],
            operation,
        )
    }
    fn commit_many(
        &self,
        grants: &[(&PackageGrantV1, PackageActionV1, Option<&PackageBundle>)],
        operation: &mut dyn FnMut() -> araphor_data::Result<()>,
    ) -> araphor_data::Result<()> {
        if grants.is_empty() || !grants.iter().any(|(_, _, image)| image.is_none()) {
            return Err(Code::Denied.error("graph fixture authority"));
        }
        for (grant, action, image) in grants {
            self.check(grant, *action)?;
            if let Some(image) = image {
                self.admit(grant, image)?;
            }
        }
        operation()
    }
    fn changes(&self) -> watch::Receiver<u64> {
        self.changes.subscribe()
    }
}

#[derive(Default)]
struct Facts {
    first: Mutex<Option<std::time::Instant>>,
    supplied: Mutex<Vec<AnalysisContextVersionV1>>,
    failed: Mutex<Option<EvidenceIntakeIdentityV1>>,
    calls: AtomicUsize,
    changed: Mutex<Option<AnalysisContextVersionV1>>,
    records: Mutex<Option<std::sync::mpsc::Sender<Vec<araphor_data::DiscoveryRecordV1>>>>,
    gate: Mutex<Option<(std::sync::mpsc::Sender<()>, std::sync::mpsc::Receiver<()>)>>,
}

impl GraphFacts for Facts {
    fn facts(
        &self,
        contexts: &[sdk::RecordBatch],
        records: &[araphor_data::DiscoveryRecordV1],
    ) -> araphor_data::Result<(Vec<AnalysisContextVersionV1>, Vec<AnalysisContextRefV1>)> {
        for batch in contexts {
            if batch.schema().field_with_name("body").is_err()
                || batch.schema().field_with_name("commit_revision").is_err()
            {
                return Err(Code::Invalid.error("canonical graph context"));
            }
        }
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.first
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .get_or_insert_with(std::time::Instant::now);
        if self
            .failed
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .as_ref()
            .is_some_and(|source| records.iter().any(|record| &record.id.stream == source))
        {
            return Err(araphor_data::GraphInvalidSnafu {
                field: "Graph source failure fixture",
            }
            .build());
        }
        if let Some(observed) = self
            .records
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .take()
        {
            observed
                .send(records.to_vec())
                .map_err(|_| Code::Invalid.error("Graph record observer fixture"))?;
        }
        if let Some((entry, release)) = self
            .gate
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .take()
        {
            entry
                .send(())
                .map_err(|_| Code::Invalid.error("graph projection entry fixture"))?;
            release
                .recv_timeout(std::time::Duration::from_secs(30))
                .map_err(|_| Code::Invalid.error("graph projection release fixture"))?;
        }
        let mut contexts = records
            .iter()
            .map(|record| {
                let fact = araphor_data::GraphFactV1 {
                    record_id: record.id.clone(),
                    value: araphor_data::GraphFactValueV1::Policy(
                        araphor_data::PolicyObservationProvenanceV1 {
                            source: record.id.stream.clone(),
                            profile_generation_ref_id: record
                                .decode()?
                                .profile_generation_ref_id
                                .unwrap_or(1),
                            observations: vec![record.id.clone()],
                            policy_source_revision_id: None,
                            candidate_content_id: None,
                            target_snapshot_digest: None,
                            node_bound_generation_digest: None,
                            activation_acknowledgement: None,
                            state: araphor_data::PolicyProvenanceStateV1::Missing,
                            limits: vec!["MISSING_ACK".into()],
                        },
                    ),
                };
                Ok(AnalysisContextVersionV1 {
                    key: araphor_data::AnalysisContextKeyV1 {
                        tenant_id: record.id.stream.tenant_id,
                        owner_id: "graph-native-fixture".into(),
                        entity_key: record.id.durable_cursor.to_be_bytes().to_vec(),
                        lifetime_key: record.id.stream.key(),
                        owner_revision: 1,
                    },
                    valid_from_utc_ns: None,
                    valid_until_utc_ns: None,
                    sensitivity: araphor_data::ContextSensitivityV1::Tenant,
                    body: serde_json::to_vec(&fact).map_err(|source| {
                        araphor_data::Error::GraphEncoding {
                            source,
                            location: snafu::location!(),
                        }
                    })?,
                })
            })
            .collect::<araphor_data::Result<Vec<_>>>()?;
        if let Some(changed) = self
            .changed
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .as_ref()
        {
            let context = contexts
                .iter_mut()
                .find(|context| context.key == changed.key)
                .ok_or_else(|| Code::Invalid.error("changed Graph fact fixture"))?;
            *context = changed.clone();
        }
        contexts.extend(
            self.supplied
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .iter()
                .filter(|context| {
                    serde_json::from_slice::<araphor_data::GraphFactV1>(&context.body)
                        .is_ok_and(|fact| records.iter().any(|record| record.id == fact.record_id))
                })
                .cloned(),
        );
        Ok((contexts, Vec::new()))
    }
}

#[derive(Clone, Copy)]
enum Target {
    Sql,
    Wasm,
    Native,
}

struct Fixture {
    query: Arc<Engine>,
    control: Arc<AnalysisReadControl>,
    source: EvidenceIntakeIdentityV1,
    times: (i64, i64),
    records: Vec<araphor_data::DiscoveryRecordV1>,
    facts: Arc<Facts>,
    authority: Arc<Authority>,
    _graph: araphor_data::GraphLease,
    _directory: tempfile::TempDir,
}

impl Fixture {
    fn assert_invalid_graph(
        &self,
        owner: &crate::Instance,
        input: &araphor_data::ManagedRequest,
        before: &araphor_data::AnalysisStoreMetaV1,
        domain: &GraphHistory,
        health: Option<araphor_data::ProcessorHealthV1>,
        usage: (u64, u64, u64, u64),
    ) -> TestResult {
        let instance = owner.admitted();
        assert!(!instance.running);
        assert!(!instance.removed);
        assert_eq!(instance.progress, 0);
        assert!(input.frontier.is_none());
        assert!(domain.is_empty());
        let before_health = health.ok_or("initial Graph health")?;
        assert_eq!(before_health.consumed_cursor, 0);
        assert_eq!(before_health.read_revision, before.commit_revision);
        let store = self.query.store();
        let id = &instance.spec.id;
        let scope = araphor_data::ProcessorScopeV1 {
            processor_id: araphor_data::GRAPH_PROCESSOR.into(),
            method_version: u64::from(araphor_data::GRAPH_SCHEMA_VERSION),
            identity: self.source.clone(),
        };
        let saved = store
            .managed_attempt(self.source.tenant_id, id, &input.id, &self.control)?
            .ok_or("invalid Graph attempt")?;
        let revision = before
            .commit_revision
            .checked_add(2)
            .ok_or("invalid Graph revision overflow")?;
        assert_eq!(
            saved.terminal(),
            Some(&araphor_data::ManagedTerminal {
                instance: id.clone(),
                attempt: input.id.clone(),
                revision,
                exit: araphor_data::ManagedExit::Failed(Code::Invalid),
                suspended: false,
            })
        );
        assert!(saved.receipt().is_none());
        assert_eq!(saved.instance(), instance);
        let mut supplied = saved.request().clone();
        let frontier = supplied.frontier.take().ok_or("invalid native frontier")?;
        assert_eq!(supplied, *input);
        assert!(!frontier.pending);
        assert_eq!(frontier.next_change, None);
        let cursor = araphor_query::follow::Cursor::decode(&frontier.cursor)?;
        assert_eq!(cursor.encode()?, frontier.cursor);
        assert_eq!(cursor.read_revision(), before.commit_revision);
        assert_eq!(
            cursor.position(),
            StorePositionV1 {
                commit_revision: 0,
                ordinal: 0
            }
        );
        let status = store.managed_status(&instance.grant.selection, id, &self.control)?;
        assert_eq!(&status.instance, instance);
        assert_eq!(status.status_progress, instance.progress);
        assert!(matches!(status.readiness,
            araphor_data::PackageReadinessV1::Failed { code: Code::Invalid, field }
                if field == "model evaluation"));
        assert_eq!(
            store.managed_resume(self.source.tenant_id, id, &self.control)?,
            araphor_data::ManagedResume {
                instance: instance.clone(),
                frontier: Some(frontier),
                completed: revision
            }
        );
        let mut expected_meta = before.clone();
        expected_meta.commit_revision = revision;
        assert_eq!(store.meta()?, expected_meta);
        assert_eq!(
            store
                .managed_instance(self.source.tenant_id, id, &self.control)?
                .ok_or("invalid Graph instance")?,
            *instance
        );
        assert!(store
            .managed_history(&instance.grant.selection, id, &self.control)?
            .is_empty());
        assert!(store
            .managed_selected(self.source.tenant_id, id, &input.id, &self.control)?
            .is_none());
        assert_eq!(self.graph_history()?, *domain);
        assert!(store.graph_window_headers(&self.source, None)?.is_empty());
        assert!(store.processor_result(&scope)?.is_none());
        let mut expected_health = before_health;
        expected_health.read_revision = revision;
        expected_health.state = araphor_data::ProcessorStateV1::ProcessingFailed;
        expected_health.incomplete = true;
        assert_eq!(store.processor_health(&scope)?, Some(expected_health));
        let current_usage = store.retained_usage(self.source.tenant_id)?;
        assert_eq!(
            (current_usage.1, current_usage.2, current_usage.3),
            (usage.1, usage.2, usage.3)
        );
        store.verify_state()?;
        Ok(())
    }

    fn graph_history(&self) -> TestResult<GraphHistory> {
        let mut history = Vec::new();
        let mut after = None;
        loop {
            let page = self.query.store().graph_snapshots(
                self.source.tenant_id,
                Some(&self.source),
                after.as_deref(),
                false,
            )?;
            if page.is_empty() {
                break;
            }
            for (id, graph, revision) in page {
                after = Some(id.clone());
                history.push((
                    id.clone(),
                    graph,
                    revision,
                    self.query.store().read_result(self.source.tenant_id, &id)?,
                    self.query
                        .store()
                        .package_evidence(self.source.tenant_id, std::slice::from_ref(&id))?,
                ));
            }
        }
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(history)
    }

    fn serial_guests(&mut self) -> TestResult {
        let mut limits = self.query.limits().clone();
        limits.package.wasm.evaluations = Some(1);
        self.query = Engine::new(Arc::clone(self.query.store()), limits)?;
        Ok(())
    }

    async fn observe_guests<T, E>(
        query: Arc<Engine>,
        execute: impl std::future::Future<Output = std::result::Result<T, E>>,
    ) -> TestResult<(T, usize)>
    where
        E: Into<Box<dyn std::error::Error + Send + Sync>>,
    {
        let (entry, mut entered) = std::sync::mpsc::channel();
        let (mut release, released) = std::sync::mpsc::channel();
        query.guest_entry(entry, Some(released))?;
        let observed = tokio::task::spawn_blocking(move || -> TestResult<usize> {
            let mut count = 0;
            for index in 0..3 {
                entered.recv_timeout(std::time::Duration::from_secs(30))?;
                count += 1;
                if index < 2 {
                    let (entry, next) = std::sync::mpsc::channel();
                    let (send, released) = std::sync::mpsc::channel();
                    query.guest_entry(entry, Some(released))?;
                    release.send(())?;
                    entered = next;
                    release = send;
                } else {
                    release.send(())?;
                }
            }
            Ok(count)
        });
        let (result, observed) = tokio::join!(execute, observed);
        let result =
            result.map_err(|error| -> Box<dyn std::error::Error + Send + Sync> { error.into() })?;
        Ok((result, observed??))
    }

    fn target(target: Target) -> TestResult<Self> {
        let manifest = DiscoveryInputManifestV1::try_from(
            include_bytes!("../../../../mithril-e2e/fixtures/discovery/manifest.json").as_slice(),
        )?;
        let records = manifest.records.into_iter().take(3).collect::<Vec<_>>();
        Self::with_records(target, records)
    }

    fn with_records(
        target: Target,
        records: Vec<araphor_data::DiscoveryRecordV1>,
    ) -> TestResult<Self> {
        let directory = tempfile::tempdir()?;
        let store = Arc::new(AnalysisStore::open(directory.path().join("data"))?);
        Self::stored(target, records, directory, store)
    }

    fn sql(package: &sdk::Package, model: &sdk::Model) -> TestResult<araphor_package::SqlModelV1> {
        use araphor_analysis_builtins::graph as algorithm;
        use datafusion::sql::sqlparser::ast::{Ident, Value};
        let mut program = araphor_package::SqlModelV1::default();
        for port in model.outputs.iter().filter(|port| port.name != "metadata") {
            let empty = sdk::RecordBatch::new_empty(Arc::new(port.schema.clone()));
            program.outputs.insert(
                port.name.clone(),
                crate::graph::tests::execution::Fixture::rows(&[empty])
                    .map_err(|error| error.to_string())?,
            );
        }
        let metadata = algorithm::Metadata::encode(&[algorithm::Metadata {
            record_ids: Vec::new(),
            facts: Vec::new(),
            package: araphor_data::GraphPackageCheckpointV1::from_package(
                package,
                model,
                araphor_data::GraphPackageStateV1::Waiting,
                0,
                0,
            ),
        }])?;
        let values = metadata.batches[0]
            .column_by_name("package")
            .and_then(|array| {
                array
                    .as_any()
                    .downcast_ref::<sdk::arrow_array::StructArray>()
            })
            .ok_or("native package metadata Struct")?;
        let mut fields = Vec::new();
        for (field, column) in values.fields().iter().zip(values.columns()) {
            fields.push(Value::SingleQuotedString(field.name().clone()).to_string());
            fields.push(match field.name().as_str() {
                "accepted_cursor_watermark" => "coalesce((SELECT id.durable_cursor FROM records ORDER BY __row_index DESC LIMIT 1), arrow_cast(0, 'UInt64'))".into(),
                "observed_boottime_watermark_ns" => "(SELECT coalesce(max(observed_boottime_ns), arrow_cast(0, 'UInt64')) FROM records)".into(),
                _ => crate::graph::tests::execution::Fixture::literal(column.as_ref(), 0)
                    .map_err(|error| error.to_string())?,
            });
        }
        let fact_fields = model
            .inputs
            .iter()
            .find(|input| input.port.name == "facts")
            .ok_or("native facts input")?
            .port
            .schema
            .fields()
            .iter()
            .flat_map(|field| {
                [
                    Value::SingleQuotedString(field.name().clone()).to_string(),
                    Ident::with_quote('"', field.name()).to_string(),
                ]
            })
            .collect::<Vec<_>>()
            .join(", ");
        program.outputs.insert("metadata".into(), format!(
            "SELECT (SELECT coalesce(array_agg(id ORDER BY __row_index), make_array()) FROM records) AS record_ids, (SELECT coalesce(array_agg(named_struct({fact_fields}) ORDER BY __row_index), make_array()) FROM facts) AS facts, named_struct({}) AS package",
            fields.join(", "),
        ));
        program.checkpoint.insert(
            "state".into(),
            r#"SELECT CAST('{"value":"WAITING"}' AS BYTEA) AS value"#.into(),
        );
        if let Some(checkpoint) = &model.checkpoint {
            for port in checkpoint.datasets.iter().skip(1) {
                let empty = sdk::RecordBatch::new_empty(Arc::new(port.schema.clone()));
                program.checkpoint.insert(
                    port.name.clone(),
                    crate::graph::tests::execution::Fixture::rows(&[empty])
                        .map_err(|error| error.to_string())?,
                );
            }
        }
        Ok(program)
    }

    fn stored(
        target: Target,
        records: Vec<araphor_data::DiscoveryRecordV1>,
        directory: tempfile::TempDir,
        store: Arc<AnalysisStore>,
    ) -> TestResult<Self> {
        let source = records.first().ok_or("graph records")?.id.stream.clone();
        let times = records
            .iter()
            .map(|record| record.decode().map(|wire| wire.ingested_utc_ns))
            .collect::<araphor_data::Result<Vec<_>>>()?;
        let times = (
            *times.iter().min().ok_or("record time")?,
            *times.iter().max().ok_or("record time")?,
        );
        let graph = store.lease_graph(vec![AnalysisSelectionV1::tenant(source.tenant_id)])?;
        store.register_graph(&source)?;
        for record in &records {
            store.accept_validated_batch(
                source.clone(),
                ValidatedEvidenceBatchV1 {
                    cpu_id: record.id.cpu_id,
                    first_cursor: record.id.durable_cursor,
                    last_cursor: record.id.durable_cursor,
                    intake_utc_ns: record.id.durable_cursor,
                    frame_ends: vec![record.wire_record.len()],
                    framed_records: record.wire_record.clone().into(),
                },
            )?;
        }
        for (detector, bytes) in [
            (
                Detector::Process,
                araphor_analysis_builtins::components::PROCESS,
            ),
            (
                Detector::Credentials,
                araphor_analysis_builtins::components::CREDENTIALS,
            ),
            (
                Detector::Kubernetes,
                araphor_analysis_builtins::components::KUBERNETES,
            ),
        ] {
            let artifact = PackageArtifactV1 {
                descriptor: detector.descriptor(),
                implementations: vec![match target {
                    Target::Wasm => PackageImplementationV1::Wasm {
                        exports: vec!["detect".into()],
                        artifact: bytes.to_vec(),
                    },
                    Target::Native => {
                        let name = match detector {
                            Detector::Process => "process",
                            Detector::Credentials => "credentials",
                            Detector::Kubernetes => "kubernetes",
                        };
                        let directory = std::env::var_os("ARAPHOR_NATIVE_DIR")
                            .ok_or("ARAPHOR_NATIVE_DIR is required")?;
                        let artifact = std::fs::read(
                            std::path::PathBuf::from(directory)
                                .join(format!("{name}.{}", std::env::consts::DLL_EXTENSION)),
                        )?;
                        let qualification = araphor_data::native::Qualification::inspect(
                            &artifact,
                            vec!["detect".into()],
                            std::env::var("ARAPHOR_NATIVE_TARGET")?,
                        )?;
                        PackageImplementationV1::Native {
                            export: "detect".into(),
                            artifact,
                            qualification: Some(qualification),
                        }
                    }
                    Target::Sql => {
                        let package = detector.descriptor();
                        PackageImplementationV1::Sql {
                            export: "detect".into(),
                            program: Self::sql(&package, &package.exports[0])?,
                        }
                    }
                }],
                fixtures: Vec::new(),
            };
            store.install_package_image(
                source.tenant_id,
                &araphor_data::PackageBundle::try_from(PackageBundleV1 {
                    schema_version: 1,
                    root: artifact.reference(),
                    artifacts: vec![artifact],
                })?,
                || Ok(()),
            )?;
        }
        let query = Engine::new(store, Default::default())?;
        Ok(Self {
            query,
            control: Arc::default(),
            source,
            times,
            records,
            facts: Arc::default(),
            authority: Arc::new(Authority {
                changes: watch::channel(0).0,
                allowed: AtomicBool::new(true),
                trusted: AtomicBool::new(true),
                gate: Mutex::default(),
            }),
            _graph: graph,
            _directory: directory,
        })
    }

    fn coverage(&self, revision: u64, state: Option<&str>) -> TestResult {
        use araphor_data::{CoverageInterval, CoverageReport, ValidatedCoverageV1};
        use prost::Message as _;
        let intervals = self
            .records
            .iter()
            .map(|record| {
                let wire = record.decode()?;
                let id: [u8; 16] = wire.coverage_interval_id.as_ref().try_into()?;
                Ok::<_, Box<dyn std::error::Error + Send + Sync>>(id)
            })
            .collect::<TestResult<std::collections::BTreeSet<_>>>()?;
        let intervals = state.map_or_else(Vec::new, |state| {
            intervals
                .into_iter()
                .map(|id| CoverageInterval {
                    interval_id: id.to_vec(),
                    source_epoch: self.source.source_epoch,
                    revision,
                    state: state.into(),
                    first_sequence: 1,
                    last_sequence: Some(u64::MAX),
                    ..Default::default()
                })
                .collect()
        });
        self.query
            .store()
            .accept_validated_coverage(ValidatedCoverageV1 {
                identity: self.source.clone(),
                cpu_id: self.records[0].id.cpu_id,
                revision,
                encoded_report: CoverageReport {
                    source_id: self.source.source_id.to_vec(),
                    source_epoch: self.source.source_epoch,
                    cpu_id: self.records[0].id.cpu_id,
                    revision,
                    intervals,
                }
                .encode_to_vec(),
            })?;
        Ok(())
    }

    async fn prepare(&self, filter: &str) -> TestResult<GraphPublication> {
        let sql = araphor_data::FindingV1::PACKAGES.iter().map(|id| format!(
            "SELECT * FROM \"{id}\".\"1\".detect('subjects', records => (SELECT * FROM records), facts => (SELECT * FROM facts), manifest => (SELECT * FROM manifest))"
        )).collect::<Vec<_>>().join(" UNION ALL ");
        self.prepare_sql("*", filter, sql).await
    }

    async fn prepare_sql(
        &self,
        columns: &str,
        filter: &str,
        call_sql: String,
    ) -> TestResult<GraphPublication> {
        let now = u64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos())?;
        let selection = AnalysisSelectionV1::tenant(self.source.tenant_id);
        let session = self.query.session(selection.clone(), &self.control, now)?;
        let sql = format!("SELECT {columns} FROM events {filter}");
        let events = self.query.prepare(&sql, Vec::new()).await?.0;
        let definition = Definition {
            name: "graph-native-fixture".into(),
            description: String::new(),
            labels: BTreeMap::new(),
            program: Program::Sql {
                source: Source::Inline { inline: call_sql },
            },
        };
        Ok(GraphPublication::prepare(
            session,
            self.authority.clone(),
            PackageGrantV1 {
                principal: "graph-native-fixture".into(),
                revision: 1,
                selection,
                expires_utc_ns: None,
                authorization_id: None,
            },
            events,
            definition,
            self.facts.clone(),
        )
        .await?)
    }
}

#[tokio::test]
async fn captures_once_and_refreshes() -> TestResult {
    captured_source(Target::Wasm).await
}

#[tokio::test]
async fn sql_capture_and_refresh() -> TestResult {
    captured_source(Target::Sql).await
}

#[tokio::test]
#[ignore = "requires source-built native Graph detector artifacts"]
async fn native_graph_source_targets() -> TestResult {
    captured_source(Target::Native).await
}

async fn captured_source(target: Target) -> TestResult {
    let fixture = Fixture::target(target)?;
    let publication = fixture.prepare("").await?;
    let grant = publication.grant.clone();
    let definition = publication.prepared.resolved().clone();
    fixture.admit_definition(&grant, &definition)?;
    drop(publication);
    let instance = fixture
        .managed_graph(
            &grant,
            &definition,
            "native-capture",
            "SELECT * FROM events",
        )
        .await?;
    let held = fixture.query.memory().input_reserved();
    let projection = &instance
        .graph_owner()
        .ok_or("admitted Graph owner")?
        .projection;
    let observed = projection.observe_capture();
    let first = instance
        .run(managed::request("first")?, &fixture.control)
        .await?;
    let captured = observed.try_recv()?;
    assert!(captured
        .graph
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .is_none());
    assert!(captured.source.upgrade().is_none());
    assert_eq!(projection.projections.load(Ordering::SeqCst), 1);
    let metadata = captured
        .inputs
        .iter()
        .map(|input| {
            (
                input.data.name.clone(),
                input.revision.clone(),
                input.coverage.clone(),
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(metadata.len(), 3);
    assert!(metadata
        .windows(2)
        .all(|pair| pair[0].1 == pair[1].1 && pair[0].2 == pair[1].2));
    let range = metadata[0]
        .1
        .window
        .as_ref()
        .ok_or("qualified Graph source range")?;
    assert_eq!(range.source, serde_json::to_vec(&fixture.source)?);
    assert_eq!((range.start_utc_ns, range.end_utc_ns), fixture.times);
    drop(captured);
    assert_eq!(first.results.len(), 3);
    for reference in first.results.values() {
        let saved = fixture.query.store().managed_evaluation(
            instance.admitted(),
            &reference.result_id,
            &fixture.control,
        )?;
        assert_eq!(
            saved
                .inputs
                .iter()
                .map(|input| (
                    input.data.name.clone(),
                    input.revision.clone(),
                    input.coverage.clone()
                ))
                .collect::<Vec<_>>(),
            metadata
        );
    }
    assert_eq!(fixture.facts.calls.load(Ordering::SeqCst), 1);
    let scope = araphor_data::ProcessorScopeV1 {
        processor_id: araphor_data::GRAPH_PROCESSOR.into(),
        method_version: u64::from(araphor_data::GRAPH_SCHEMA_VERSION),
        identity: fixture.source.clone(),
    };
    let graph_result = fixture
        .query
        .store()
        .processor_result(&scope)?
        .ok_or("native Graph head")?;
    assert_eq!(graph_result.commit_revision, first.commit_revision);
    let snapshot = fixture
        .query
        .store()
        .graph_result(fixture.source.tenant_id, &graph_result.result_id)?
        .ok_or("graph result")?;
    assert_eq!(snapshot.input_manifest.evidence.len(), 3);
    assert_eq!(snapshot.input_positions.len(), 3);
    assert_eq!(snapshot.packages.len(), 3);
    assert_eq!(snapshot.packages[0].package_id, "HF-PROC-001");
    assert_eq!(
        snapshot.packages[0].required_inputs,
        ["exact-task-entry-role", "kernel-effect", "source-coverage"]
    );
    assert_eq!(snapshot.packages[0].accepted_cursor_watermark, 3);
    assert_eq!(
        fixture
            .query
            .store()
            .processor_health(&scope)?
            .ok_or("graph progress")?
            .consumed_cursor,
        3
    );
    let before_domain = fixture.graph_history()?;
    let before_meta = fixture.query.store().meta()?;
    let before_instance = fixture
        .query
        .store()
        .managed_instance(fixture.source.tenant_id, "native-capture", &fixture.control)?
        .ok_or("native Graph instance before no-op")?;
    let before_heads = fixture
        .query
        .store()
        .graph_window_headers(&fixture.source, None)?;
    let before_body = fixture
        .query
        .store()
        .read_result(fixture.source.tenant_id, &graph_result.result_id)?;
    let before_evidence = fixture.query.store().package_evidence(
        fixture.source.tenant_id,
        std::slice::from_ref(&graph_result.result_id),
    )?;
    let second = instance
        .run(managed::request("unchanged")?, &fixture.control)
        .await?;
    let captured = observed.try_recv()?;
    assert!(captured
        .graph
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .is_none());
    assert!(captured.source.upgrade().is_none());
    assert_eq!(projection.projections.load(Ordering::SeqCst), 2);
    let current = captured
        .inputs
        .iter()
        .map(|input| {
            (
                input.data.name.clone(),
                input.revision.clone(),
                input.coverage.clone(),
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(current, metadata);
    drop(captured);
    assert_eq!(second.results.len(), 3);
    assert_eq!(
        second.commit_revision,
        before_meta
            .commit_revision
            .checked_add(2)
            .ok_or("native commit revision overflow")?
    );
    assert_eq!(fixture.facts.calls.load(Ordering::SeqCst), 2);
    assert_eq!(
        fixture.query.store().processor_result(&scope)?,
        Some(graph_result.clone())
    );
    assert_eq!(
        fixture
            .query
            .store()
            .graph_window_headers(&fixture.source, None)?,
        before_heads
    );
    assert_eq!(
        fixture
            .query
            .store()
            .graph_result(fixture.source.tenant_id, &graph_result.result_id)?,
        Some(snapshot)
    );
    assert_eq!(
        fixture
            .query
            .store()
            .read_result(fixture.source.tenant_id, &graph_result.result_id)?,
        before_body
    );
    assert_eq!(
        fixture.query.store().package_evidence(
            fixture.source.tenant_id,
            std::slice::from_ref(&graph_result.result_id)
        )?,
        before_evidence
    );
    let saved = fixture
        .query
        .store()
        .managed_instance(fixture.source.tenant_id, "native-capture", &fixture.control)?
        .ok_or("native Graph instance")?;
    assert_eq!(fixture.graph_history()?, before_domain);
    let mut expected_meta = before_meta;
    expected_meta.commit_revision = second.commit_revision;
    assert_eq!(fixture.query.store().meta()?, expected_meta);
    let mut expected_instance = before_instance;
    expected_instance.progress = second.commit_revision;
    assert_eq!(saved, expected_instance);
    assert_eq!(
        fixture.query.store().managed_history(
            &grant.selection,
            "native-capture",
            &fixture.control
        )?,
        vec![first, second]
    );
    let (_, pins) = before_evidence;
    assert!(pins
        .iter()
        .any(|pin| pin.key.owner_id == "native-package-v1"));
    assert_eq!(fixture.query.memory().input_reserved(), held);
    drop(fixture.query.reserve_evaluation(fixture.source.tenant_id)?);
    Ok(())
}

#[tokio::test]
async fn prepared_calls_capture_fresh() -> TestResult {
    let fixture = Fixture::target(Target::Wasm)?;
    let publication = fixture.prepare("").await?;
    let grant = publication.grant.clone();
    let definition = publication.prepared.resolved().clone();
    fixture.admit_definition(&grant, &definition)?;
    drop(publication);
    let instance = fixture
        .managed_graph(
            &grant,
            &definition,
            "prepared-capture",
            "SELECT * FROM events",
        )
        .await?;
    let held = fixture.query.memory().input_reserved();
    let projection = &instance
        .graph_owner()
        .ok_or("admitted Graph owner")?
        .projection;
    let observed = projection.observe_capture();
    let first = instance
        .run(managed::request("first")?, &fixture.control)
        .await?;
    let original = observed.try_recv()?;
    assert_eq!(first.results.len(), 3);
    assert!(original.source.upgrade().is_none());
    assert!(original
        .graph
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .is_none());
    let before_domain = fixture.graph_history()?;
    assert_eq!(before_domain.len(), 1);
    let before_heads = fixture
        .query
        .store()
        .graph_window_headers(&fixture.source, None)?;
    assert_eq!(before_heads.len(), 1);
    let scope = araphor_data::ProcessorScopeV1 {
        processor_id: araphor_data::GRAPH_PROCESSOR.into(),
        method_version: u64::from(araphor_data::GRAPH_SCHEMA_VERSION),
        identity: fixture.source.clone(),
    };
    let before_head = fixture
        .query
        .store()
        .processor_result(&scope)?
        .ok_or("first prepared Graph head")?;
    assert_eq!(before_head.commit_revision, first.commit_revision);
    let before_meta = fixture.query.store().meta()?;
    let before_instance = fixture
        .query
        .store()
        .managed_instance(
            fixture.source.tenant_id,
            "prepared-capture",
            &fixture.control,
        )?
        .ok_or("prepared Graph instance")?;
    let repeated = instance
        .run(managed::request("repeat")?, &fixture.control)
        .await?;
    let next = observed.try_recv()?;
    assert!(!Arc::ptr_eq(&original, &next));
    assert!(next.source.upgrade().is_none());
    assert_eq!(fixture.graph_history()?, before_domain);
    assert_eq!(
        fixture
            .query
            .store()
            .graph_window_headers(&fixture.source, None)?,
        before_heads
    );
    assert_eq!(
        fixture.query.store().processor_result(&scope)?,
        Some(before_head)
    );
    assert_eq!(
        repeated.commit_revision,
        before_meta
            .commit_revision
            .checked_add(2)
            .ok_or("prepared Graph revision overflow")?
    );
    let mut expected_meta = before_meta;
    expected_meta.commit_revision = repeated.commit_revision;
    assert_eq!(fixture.query.store().meta()?, expected_meta);
    let mut expected_instance = before_instance;
    expected_instance.progress = repeated.commit_revision;
    assert_eq!(
        fixture
            .query
            .store()
            .managed_instance(
                fixture.source.tenant_id,
                "prepared-capture",
                &fixture.control
            )?
            .ok_or("repeated Graph instance")?,
        expected_instance
    );
    assert_eq!(
        fixture.query.store().managed_history(
            &grant.selection,
            "prepared-capture",
            &fixture.control
        )?,
        [first.clone(), repeated.clone()]
    );
    assert_eq!(projection.projections.load(Ordering::SeqCst), 2);
    assert_eq!(fixture.facts.calls.load(Ordering::SeqCst), 2);
    assert_eq!(original.inputs.len(), next.inputs.len());
    for (original, next) in original.inputs.iter().zip(&next.inputs) {
        assert_eq!(original.revision, next.revision);
        assert_eq!(original.coverage, next.coverage);
    }
    fixture.coverage(2, Some("HEALTHY"))?;
    let changed = instance
        .run(managed::request("changed")?, &fixture.control)
        .await?;
    let updated = observed.try_recv()?;
    assert!(!Arc::ptr_eq(&original, &updated));
    assert!(!Arc::ptr_eq(&next, &updated));
    assert_eq!(updated.coverage_revision, 2);
    assert!(updated.source.upgrade().is_none());
    assert_eq!(projection.projections.load(Ordering::SeqCst), 3);
    assert_eq!(fixture.facts.calls.load(Ordering::SeqCst), 3);
    let heads = fixture
        .query
        .store()
        .graph_window_headers(&fixture.source, None)?;
    assert_eq!(heads.len(), 1);
    let (id, _, revision) = heads.first().ok_or("changed Graph window")?;
    assert_eq!(*revision, changed.commit_revision);
    assert!(fixture
        .query
        .store()
        .graph_result(fixture.source.tenant_id, id)?
        .is_some());
    let updated_domain = fixture.graph_history()?;
    assert_eq!(updated_domain.len(), before_domain.len() + 1);
    for original in &before_domain {
        assert!(updated_domain.contains(original));
    }
    assert_eq!(
        fixture.query.store().managed_history(
            &grant.selection,
            "prepared-capture",
            &fixture.control
        )?,
        [first, repeated, changed]
    );
    fixture.authority.set(false);
    let before = fixture.query.store().meta()?;
    let before_instance = fixture.query.store().managed_instance(
        fixture.source.tenant_id,
        "prepared-capture",
        &fixture.control,
    )?;
    let before_history = fixture.query.store().managed_history(
        &grant.selection,
        "prepared-capture",
        &fixture.control,
    )?;
    let error = instance
        .run(managed::request("denied")?, &fixture.control)
        .await
        .err()
        .ok_or("revoked prepared Graph published")?;
    assert_eq!(
        erebor_runtime_error::ErrorExt::status_code(&error),
        erebor_runtime_error::StatusCode::PermissionDenied
    );
    assert_eq!(fixture.query.store().meta()?, before);
    assert_eq!(
        fixture.query.store().managed_instance(
            fixture.source.tenant_id,
            "prepared-capture",
            &fixture.control
        )?,
        before_instance
    );
    assert_eq!(
        fixture.query.store().managed_history(
            &grant.selection,
            "prepared-capture",
            &fixture.control
        )?,
        before_history
    );
    assert_eq!(fixture.graph_history()?, updated_domain);
    assert_eq!(
        fixture
            .query
            .store()
            .graph_window_headers(&fixture.source, None)?,
        heads
    );
    assert_eq!(projection.projections.load(Ordering::SeqCst), 3);
    assert_eq!(fixture.facts.calls.load(Ordering::SeqCst), 3);
    assert!(fixture
        .query
        .store()
        .managed_attempt(
            fixture.source.tenant_id,
            "prepared-capture",
            "denied",
            &fixture.control
        )?
        .is_none());
    assert!(observed.try_recv().is_err());
    drop((original, next, updated));
    assert_eq!(fixture.query.memory().input_reserved(), held);
    drop(fixture.query.reserve_evaluation(fixture.source.tenant_id)?);
    Ok(())
}

#[tokio::test]
async fn graph_run_requires_projection() -> TestResult {
    let fixture = Fixture::target(Target::Sql)?;
    let first = fixture.prepare("").await?;
    let second = fixture.prepare("").await?;
    let context = datafusion::execution::TaskContext::default();
    assert!(GraphRun::from_context(&context, &first.projection).is_err());
    let config = context
        .session_config()
        .clone()
        .with_extension(Arc::new(GraphRun {
            projection: Arc::downgrade(&first.projection),
            captured: OnceCell::new(),
        }));
    let context = context.with_session_config(config);
    assert!(GraphRun::from_context(&context, &first.projection).is_ok());
    let error = GraphRun::from_context(&context, &second.projection)
        .err()
        .ok_or("foreign Graph projection was admitted")?;
    assert!(error.to_string().contains("graph execution projection"));
    Ok(())
}

#[tokio::test]
async fn final_cancel_rolls_back() -> TestResult {
    let fixture = Fixture::target(Target::Sql)?;
    let publication = fixture.prepare("").await?;
    let grant = publication.grant.clone();
    let definition = publication.prepared.resolved().clone();
    fixture.admit_definition(&grant, &definition)?;
    drop(publication);
    let instance = fixture
        .managed_graph(&grant, &definition, "final-cancel", "SELECT * FROM events")
        .await?;
    let before_instance = instance.admitted().clone();
    let held = fixture.query.memory().input_reserved();
    let before_domain = fixture.graph_history()?;
    let before_heads = fixture
        .query
        .store()
        .graph_window_headers(&fixture.source, None)?;
    let scope = araphor_data::ProcessorScopeV1 {
        processor_id: araphor_data::GRAPH_PROCESSOR.into(),
        method_version: u64::from(araphor_data::GRAPH_SCHEMA_VERSION),
        identity: fixture.source.clone(),
    };
    let before_health = fixture.query.store().processor_health(&scope)?;
    let before_head = fixture.query.store().processor_result(&scope)?;
    let before_usage = fixture
        .query
        .store()
        .retained_usage(fixture.source.tenant_id)?;
    let before = fixture.query.store().meta()?;
    let control = Arc::new(AnalysisReadControl::default());
    let cancel = Arc::clone(&control);
    fixture.query.store().set_commit_hook(
        araphor_data::AnalysisCommitStage::BeforeResultCommit,
        move || cancel.cancel(),
    )?;
    let input = managed::request("cancelled")?;
    let error = instance
        .run(input.clone(), &control)
        .await
        .err()
        .ok_or("cancelled Graph published")?;
    assert_eq!(
        erebor_runtime_error::ErrorExt::status_code(&error),
        erebor_runtime_error::StatusCode::Cancelled
    );
    assert_eq!(fixture.facts.calls.load(Ordering::SeqCst), 1);
    let saved = fixture
        .query
        .store()
        .managed_attempt(
            fixture.source.tenant_id,
            "final-cancel",
            &input.id,
            &fixture.control,
        )?
        .ok_or("cancelled Graph intent")?;
    let mut supplied = saved.request().clone();
    let frontier = supplied
        .frontier
        .take()
        .ok_or("cancelled native frontier")?;
    assert_eq!(supplied, input);
    assert!(!frontier.pending);
    assert_eq!(frontier.next_change, None);
    let cursor = araphor_query::follow::Cursor::decode(&frontier.cursor)?;
    assert_eq!(cursor.encode()?, frontier.cursor);
    assert_eq!(cursor.read_revision(), before.commit_revision);
    assert_eq!(
        cursor.position(),
        StorePositionV1 {
            commit_revision: 0,
            ordinal: 0
        }
    );
    assert_eq!(saved.instance(), &before_instance);
    assert!(saved.receipt().is_none());
    assert!(saved.terminal().is_none());
    let mut expected_meta = before;
    expected_meta.commit_revision = expected_meta
        .commit_revision
        .checked_add(1)
        .ok_or("cancelled Graph revision overflow")?;
    assert_eq!(fixture.query.store().meta()?, expected_meta);
    assert_eq!(
        fixture
            .query
            .store()
            .managed_instance(fixture.source.tenant_id, "final-cancel", &fixture.control)?
            .ok_or("cancelled Graph instance")?,
        before_instance
    );
    assert!(fixture
        .query
        .store()
        .managed_history(&grant.selection, "final-cancel", &fixture.control)?
        .is_empty());
    assert!(fixture
        .query
        .store()
        .managed_selected(
            fixture.source.tenant_id,
            "final-cancel",
            &input.id,
            &fixture.control
        )?
        .is_none());
    assert!(
        matches!(fixture.query.store().managed_resume(fixture.source.tenant_id,
        "final-cancel", &fixture.control), Err(araphor_data::Error::Package {
            code: Code::Incomplete, field, .. }) if field == "managed pending attempt")
    );
    assert_eq!(fixture.graph_history()?, before_domain);
    assert_eq!(
        fixture
            .query
            .store()
            .graph_window_headers(&fixture.source, None)?,
        before_heads
    );
    assert_eq!(fixture.query.store().processor_result(&scope)?, before_head);
    let expected_health = before_health.map(|mut health| {
        health.read_revision = expected_meta.commit_revision;
        health
    });
    assert_eq!(
        fixture.query.store().processor_health(&scope)?,
        expected_health
    );
    let usage = fixture
        .query
        .store()
        .retained_usage(fixture.source.tenant_id)?;
    assert_eq!(
        (usage.1, usage.2, usage.3),
        (before_usage.1, before_usage.2, before_usage.3)
    );
    fixture.query.store().verify_state()?;
    assert_eq!(fixture.query.memory().input_reserved(), held);
    drop(fixture.query.reserve_evaluation(fixture.source.tenant_id)?);
    Ok(())
}

#[tokio::test]
async fn duplicate_records_are_rejected() -> TestResult {
    let fixture = Fixture::target(Target::Sql)?;
    let publication = fixture.prepare("UNION ALL SELECT * FROM events").await?;
    let grant = publication.grant.clone();
    let definition = publication.prepared.resolved().clone();
    fixture.admit_definition(&grant, &definition)?;
    drop(publication);
    let id = "duplicate-events";
    let owner = fixture
        .managed_graph(
            &grant,
            &definition,
            id,
            "SELECT * FROM events UNION ALL SELECT * FROM events",
        )
        .await?;
    let store = fixture.query.store();
    let initial = store.managed_status(&grant.selection, id, &fixture.control)?;
    assert_eq!(&initial.instance, owner.admitted());
    assert_eq!(initial.status_progress, 0);
    assert!(matches!(
        initial.readiness,
        araphor_data::PackageReadinessV1::Inactive
    ));
    let before_domain = fixture.graph_history()?;
    assert!(store
        .graph_window_headers(&fixture.source, None)?
        .is_empty());
    let scope = araphor_data::ProcessorScopeV1 {
        processor_id: araphor_data::GRAPH_PROCESSOR.into(),
        method_version: u64::from(araphor_data::GRAPH_SCHEMA_VERSION),
        identity: fixture.source.clone(),
    };
    assert!(store.processor_result(&scope)?.is_none());
    let before_health = store.processor_health(&scope)?;
    let before_usage = store.retained_usage(fixture.source.tenant_id)?;
    let before = store.meta()?;
    let input = managed::request("invalid")?;
    assert!(owner.run(input.clone(), &fixture.control).await.is_err());
    assert_eq!(fixture.facts.calls.load(Ordering::SeqCst), 0);
    fixture.assert_invalid_graph(
        owner.as_ref(),
        &input,
        &before,
        &before_domain,
        before_health,
        before_usage,
    )?;
    drop(fixture.query.reserve_evaluation(fixture.source.tenant_id)?);
    Ok(())
}

#[tokio::test]
async fn overlap_keeps_selected_facts() -> TestResult {
    let fixture = Fixture::target(Target::Sql)?;
    let publication = fixture.prepare("").await?;
    let grant = publication.grant.clone();
    let definition = publication.prepared.resolved().clone();
    fixture.admit_definition(&grant, &definition)?;
    drop(publication);
    let owner = fixture
        .managed_graph(&grant, &definition, "wide", "SELECT * FROM events")
        .await?;
    let scope = araphor_data::ProcessorScopeV1 {
        processor_id: araphor_data::GRAPH_PROCESSOR.into(),
        method_version: u64::from(araphor_data::GRAPH_SCHEMA_VERSION),
        identity: fixture.source.clone(),
    };
    let store = fixture.query.store();
    let first_receipt = owner
        .run(managed::request("seed")?, &fixture.control)
        .await?;
    let head = store.processor_result(&scope)?.ok_or("native Graph head")?;
    assert_eq!(head.commit_revision, first_receipt.commit_revision);
    let old = head.result_id;
    let prior = fixture
        .query
        .store()
        .graph_result(fixture.source.tenant_id, &old)?
        .ok_or("prior graph")?;
    assert_eq!(prior.input_manifest.context.len(), 3);
    let before_domain = fixture.graph_history()?;
    let narrow = fixture
        .managed_graph(
            &grant,
            &definition,
            "narrow",
            "SELECT * FROM events WHERE source_cursor >= 2",
        )
        .await?;
    let receipt = narrow
        .run(managed::request("narrow")?, &fixture.control)
        .await?;
    let heads = store.graph_window_headers(&fixture.source, None)?;
    let (id, _, revision) = heads
        .into_iter()
        .find(|(_, header, _)| header.first_cursor == 2)
        .ok_or("native Graph window")?;
    assert_eq!(revision, receipt.commit_revision);
    let current = fixture
        .query
        .store()
        .graph_result(fixture.source.tenant_id, &id)?
        .ok_or("current graph")?;
    assert_eq!(current.input_manifest.evidence.len(), 2);
    assert_eq!(current.input_manifest.context.len(), 2);
    assert!(current
        .graph
        .facts
        .iter()
        .all(|fact| fact.record_id.durable_cursor >= 2));
    assert_eq!(
        current.witness_deadline_utc_ns,
        prior.witness_deadline_utc_ns
    );
    assert_eq!(fixture.facts.calls.load(Ordering::SeqCst), 2);
    let after_domain = fixture.graph_history()?;
    assert_eq!(after_domain.len(), before_domain.len() + 1);
    assert!(before_domain
        .iter()
        .all(|prior| after_domain.contains(prior)));
    Ok(())
}

#[test]
fn frame_copy_is_reserved() -> TestResult {
    use araphor_data::{
        AnalysisExtractLimits, AnalysisReadModeV1, AnalysisTableRead, AnalysisTableRequests,
    };
    let fixture = Fixture::target(Target::Sql)?;
    let fields = AnalysisStore::table_schemas()["events"].fields().len();
    let requests = AnalysisTableRequests::from([("events".into(), Some((0..fields).collect()))]);
    let page = fixture.query.store().read_tables(
        &AnalysisSelectionV1::tenant(fixture.source.tenant_id),
        AnalysisTableRead {
            requests: &requests,
            event_ranges: None,
            inputs: None,
            mode: AnalysisReadModeV1::Complete,
            now: 1,
        },
        AnalysisExtractLimits::default(),
        &AnalysisReadControl::default(),
    )?;
    let batches = page.tables.get("events").ok_or("captured events")?;
    let limited = Memory::new(Some(1), None);
    let reserved = limited.reserve_input(0)?;
    assert!(matches!(
        Projection::records(batches, batches, &reserved),
        Err(DataFusionError::ResourcesExhausted(_))
    ));
    drop(reserved);
    drop(limited.reserve_input(1)?);
    let bytes = batches
        .iter()
        .map(|batch| {
            Projection::column::<sdk::arrow_array::BinaryArray>(batch, "framed_record")
                .map(|frames| frames.iter().flatten().map(<[u8]>::len).sum::<usize>())
        })
        .collect::<datafusion::common::Result<Vec<_>>>()?
        .into_iter()
        .sum::<usize>();
    let memory = Memory::new(Some(bytes), None);
    let reserved = memory.reserve_input(0)?;
    let (records, positions) = Projection::records(batches, batches, &reserved)?;
    assert_eq!(records.len(), 3);
    assert_eq!(positions.len(), 3);
    assert_eq!(reserved.size(), bytes);
    assert!(memory.reserve_input(1).is_err());
    drop((records, positions, reserved));
    drop(memory.reserve_input(bytes)?);
    Ok(())
}

#[tokio::test]
async fn requires_all_detectors() -> TestResult {
    let fixture = Fixture::target(Target::Sql)?;
    let before = fixture.query.store().meta()?;
    let single = r#"SELECT * FROM "HF-PROC-001"."1".detect('subjects', records => (SELECT * FROM records),
        facts => (SELECT * FROM facts), manifest => (SELECT * FROM manifest))"#;
    assert!(fixture.prepare_sql("*", "", single.into()).await.is_err());
    assert_eq!(fixture.facts.calls.load(Ordering::SeqCst), 0);
    assert_eq!(fixture.query.store().meta()?, before);
    Ok(())
}

#[tokio::test]
async fn requires_all_returns() -> TestResult {
    let fixture = Fixture::target(Target::Sql)?;
    let sql = araphor_data::FindingV1::PACKAGES.iter().map(|id| format!(
        "SELECT * FROM \"{id}\".\"1\".detect('subjects', records => (SELECT * FROM records), facts => (SELECT * FROM facts), manifest => (SELECT * FROM manifest)){}",
        if *id == "HF-XNODE-001" { " WHERE FALSE" } else { "" }
    )).collect::<Vec<_>>().join(" UNION ALL ");
    let publication = fixture.prepare_sql("*", "", sql).await?;
    let grant = publication.grant.clone();
    let definition = publication.prepared.resolved().clone();
    fixture.admit_definition(&grant, &definition)?;
    drop(publication);
    let id = "missing-return";
    let owner = fixture
        .managed_graph(&grant, &definition, id, "SELECT * FROM events")
        .await?;
    let store = fixture.query.store();
    let initial = store.managed_status(&grant.selection, id, &fixture.control)?;
    assert_eq!(&initial.instance, owner.admitted());
    assert_eq!(initial.status_progress, 0);
    assert!(matches!(
        initial.readiness,
        araphor_data::PackageReadinessV1::Inactive
    ));
    let before_domain = fixture.graph_history()?;
    assert!(store
        .graph_window_headers(&fixture.source, None)?
        .is_empty());
    let scope = araphor_data::ProcessorScopeV1 {
        processor_id: araphor_data::GRAPH_PROCESSOR.into(),
        method_version: u64::from(araphor_data::GRAPH_SCHEMA_VERSION),
        identity: fixture.source.clone(),
    };
    assert!(store.processor_result(&scope)?.is_none());
    let before_health = store.processor_health(&scope)?;
    let before_usage = store.retained_usage(fixture.source.tenant_id)?;
    let before = store.meta()?;
    let input = managed::request("invalid")?;
    assert_eq!(
        owner
            .graph_owner()
            .ok_or("admitted Graph owner")?
            .calls
            .len(),
        3
    );
    let error = owner
        .run(input.clone(), &fixture.control)
        .await
        .err()
        .ok_or("missing native result published")?;
    assert!(std::iter::successors(
        Some(&error as &(dyn std::error::Error + 'static)),
        |error| error.source()
    )
    .any(|error| error.to_string().contains("required graph detector return")));
    assert_eq!(fixture.facts.calls.load(Ordering::SeqCst), 1);
    fixture.assert_invalid_graph(
        owner.as_ref(),
        &input,
        &before,
        &before_domain,
        before_health,
        before_usage,
    )?;
    drop(fixture.query.reserve_evaluation(fixture.source.tenant_id)?);
    Ok(())
}

#[tokio::test]
async fn projected_events_are_valid() -> TestResult {
    let fixture = Fixture::target(Target::Sql)?;
    let sql = araphor_data::FindingV1::PACKAGES.iter().map(|id| format!(
        "SELECT * FROM \"{id}\".\"1\".detect('subjects', records => (SELECT * FROM records), facts => (SELECT * FROM facts), manifest => (SELECT * FROM manifest))"
    )).collect::<Vec<_>>().join(" UNION ALL ");
    let columns = "tenant_id,node_id,node_boot_id,label_epoch,source_id,source_epoch,cpu_id,source_cursor,framed_record,commit_revision,ordinal,temporal_coverage,kernel_sequence,coverage_interval_id";
    let events = format!("SELECT {columns} FROM events");
    let publication = fixture.prepare_sql(columns, "", sql).await?;
    let grant = publication.grant.clone();
    let definition = publication.prepared.resolved().clone();
    fixture.admit_definition(&grant, &definition)?;
    drop(publication);
    let owner = fixture
        .managed_graph(&grant, &definition, "projected-events", &events)
        .await?;
    let store = fixture.query.store();
    let before_instance = owner.admitted().clone();
    let before = store.meta()?;
    let receipt = owner
        .run(managed::request("projected")?, &fixture.control)
        .await?;
    let heads = store.graph_window_headers(&fixture.source, None)?;
    assert_eq!(heads.len(), 1);
    let (id, _, revision) = heads.first().ok_or("projected Graph window")?;
    assert_eq!(*revision, receipt.commit_revision);
    let retained = store
        .graph_result(fixture.source.tenant_id, id)?
        .ok_or("graph result")?;
    assert_eq!(retained.input_manifest.evidence.len(), 3);
    assert_eq!(retained.packages.len(), 3);
    assert_eq!(fixture.facts.calls.load(Ordering::SeqCst), 1);
    retained.validate()?;
    assert_eq!(receipt.results.len(), 3);
    assert_eq!(
        receipt.commit_revision,
        before
            .commit_revision
            .checked_add(2)
            .ok_or("projected Graph revision overflow")?
    );
    let mut expected_meta = before;
    expected_meta.commit_revision = receipt.commit_revision;
    assert_eq!(store.meta()?, expected_meta);
    let mut expected_instance = before_instance;
    expected_instance.progress = receipt.commit_revision;
    assert_eq!(
        store
            .managed_instance(
                fixture.source.tenant_id,
                "projected-events",
                &fixture.control
            )?
            .ok_or("projected Graph instance")?,
        expected_instance
    );
    assert_eq!(
        store.managed_history(&grant.selection, "projected-events", &fixture.control)?,
        std::slice::from_ref(&receipt)
    );
    assert_eq!(
        store
            .managed_attempt(
                fixture.source.tenant_id,
                "projected-events",
                "projected",
                &fixture.control
            )?
            .ok_or("projected Graph attempt")?
            .receipt(),
        Some(&receipt)
    );
    let head = store
        .processor_result(&retained.scope)?
        .ok_or("projected Graph progress")?;
    assert_eq!(head.result_id, *id);
    assert_eq!(head.commit_revision, receipt.commit_revision);
    assert_eq!(
        store
            .processor_health(&retained.scope)?
            .ok_or("projected Graph health")?
            .consumed_cursor,
        3
    );
    let history = fixture.graph_history()?;
    assert_eq!(history.len(), 1);
    assert_eq!(history[0].0, *id);
    assert_eq!(history[0].1, retained);
    assert_eq!(history[0].2, receipt.commit_revision);
    assert!(history[0].3.as_ref().is_some_and(|body| !body.is_empty()));
    store.verify_state()?;
    Ok(())
}

#[tokio::test]
async fn keeps_frozen_coverage() -> TestResult {
    let fixture = Fixture::target(Target::Sql)?;
    fixture.coverage(1, Some("GAPPED"))?;
    let publication = fixture.prepare("").await?;
    let grant = publication.grant.clone();
    let definition = publication.prepared.resolved().clone();
    fixture.admit_definition(&grant, &definition)?;
    drop(publication);
    let owner = fixture
        .managed_graph(
            &grant,
            &definition,
            "frozen-coverage",
            "SELECT * FROM events",
        )
        .await?;
    let scope = araphor_data::ProcessorScopeV1 {
        processor_id: araphor_data::GRAPH_PROCESSOR.into(),
        method_version: u64::from(araphor_data::GRAPH_SCHEMA_VERSION),
        identity: fixture.source.clone(),
    };
    let store = fixture.query.store();
    let projection = Arc::clone(&owner.graph_owner().ok_or("native Graph owner")?.projection);
    let observed = projection.observe_capture();
    let first_receipt = owner
        .run(managed::request("seed")?, &fixture.control)
        .await?;
    let head = store.processor_result(&scope)?.ok_or("native Graph head")?;
    assert_eq!(head.commit_revision, first_receipt.commit_revision);
    let first = head.result_id;
    let capture = observed.try_recv()?;
    assert!(capture
        .inputs
        .iter()
        .all(|input| input.coverage.state == sdk::CoverageState::Gapped
            && input.coverage.limits == ["SOURCE_COVERAGE_INSUFFICIENT"]));
    drop(capture);
    drop(projection);
    let original = fixture
        .query
        .store()
        .graph_result(fixture.source.tenant_id, &first)?
        .ok_or("first graph")?;
    assert!(!original.input_manifest.coverage.is_empty());
    assert!(original
        .input_manifest
        .coverage
        .iter()
        .all(|key| key.report_revision == 1
            && key.interval_revision == 1
            && key.state == araphor_data::DiscoveryCoverageStateV1::Gapped));
    fixture.coverage(2, Some("HEALTHY"))?;
    let second_receipt = owner
        .run(managed::request("coverage-two")?, &fixture.control)
        .await?;
    let heads = store.graph_window_headers(&fixture.source, None)?;
    let (second, _, revision) = heads
        .into_iter()
        .find(|(_, header, _)| header.first_cursor == 1)
        .ok_or("native Graph window")?;
    assert_eq!(revision, second_receipt.commit_revision);
    let current = fixture
        .query
        .store()
        .graph_result(fixture.source.tenant_id, &second)?
        .ok_or("second graph")?;
    assert_eq!(
        current
            .input_manifest
            .coverage
            .iter()
            .map(|key| key.report_revision)
            .collect::<std::collections::BTreeSet<_>>(),
        [1, 2].into()
    );
    assert!(original
        .input_manifest
        .coverage
        .iter()
        .all(|key| current.input_manifest.coverage.contains(key)));
    fixture.coverage(3, None)?;
    let before_domain = fixture.graph_history()?;
    let before_heads = store.graph_window_headers(&fixture.source, None)?;
    let before_head = store.processor_result(&scope)?;
    let before_health = store.processor_health(&scope)?.ok_or("Graph health")?;
    let before_instance = store
        .managed_instance(
            fixture.source.tenant_id,
            &owner.admitted().spec.id,
            &fixture.control,
        )?
        .ok_or("Graph instance")?;
    let before_history = store.managed_history(
        &grant.selection,
        &owner.admitted().spec.id,
        &fixture.control,
    )?;
    let before = store.meta()?;
    let repeated = owner
        .run(managed::request("fallback")?, &fixture.control)
        .await?;
    assert_eq!(before_heads.len(), 1);
    assert_eq!(before_heads[0].0, second);
    assert_eq!(fixture.graph_history()?, before_domain);
    assert_eq!(
        store.graph_window_headers(&fixture.source, None)?,
        before_heads
    );
    assert_eq!(store.processor_result(&scope)?, before_head);
    assert_eq!(
        repeated.commit_revision,
        before
            .commit_revision
            .checked_add(2)
            .ok_or("native Graph revision")?
    );
    let mut expected_meta = before;
    expected_meta.commit_revision = repeated.commit_revision;
    assert_eq!(store.meta()?, expected_meta);
    let mut expected_instance = before_instance;
    expected_instance.progress = repeated.commit_revision;
    assert_eq!(
        store.managed_instance(
            fixture.source.tenant_id,
            &owner.admitted().spec.id,
            &fixture.control
        )?,
        Some(expected_instance)
    );
    let mut expected_history = before_history;
    expected_history.push(repeated.clone());
    assert_eq!(
        store.managed_history(
            &grant.selection,
            &owner.admitted().spec.id,
            &fixture.control
        )?,
        expected_history
    );
    let mut expected_health = before_health;
    expected_health.read_revision = repeated.commit_revision;
    assert_eq!(store.processor_health(&scope)?, Some(expected_health));
    Ok(())
}

#[tokio::test]
async fn fallback_has_no_keys() -> TestResult {
    let fixture = Fixture::target(Target::Sql)?;
    fixture.coverage(1, None)?;
    let publication = fixture.prepare("").await?;
    let grant = publication.grant.clone();
    let definition = publication.prepared.resolved().clone();
    fixture.admit_definition(&grant, &definition)?;
    drop(publication);
    let owner = fixture
        .managed_graph(
            &grant,
            &definition,
            "unmatched-report",
            "SELECT * FROM events",
        )
        .await?;
    let scope = araphor_data::ProcessorScopeV1 {
        processor_id: araphor_data::GRAPH_PROCESSOR.into(),
        method_version: u64::from(araphor_data::GRAPH_SCHEMA_VERSION),
        identity: fixture.source.clone(),
    };
    let store = fixture.query.store();
    let first_receipt = owner
        .run(managed::request("seed")?, &fixture.control)
        .await?;
    let head = store.processor_result(&scope)?.ok_or("native Graph head")?;
    assert_eq!(head.commit_revision, first_receipt.commit_revision);
    let id = head.result_id;
    let retained = fixture
        .query
        .store()
        .graph_result(fixture.source.tenant_id, &id)?
        .ok_or("fallback graph")?;
    assert!(retained.input_manifest.coverage.is_empty());
    assert!(retained
        .packages
        .iter()
        .all(|package| package.state == araphor_data::GraphPackageStateV1::Waiting));
    Ok(())
}

#[tokio::test]
async fn rejects_changed_coverage_fields() -> TestResult {
    let fixture = Fixture::target(Target::Sql)?;
    let columns = "tenant_id,node_id,node_boot_id,label_epoch,source_id,source_epoch,cpu_id,source_cursor,framed_record,commit_revision,ordinal,temporal_coverage,CAST(18446744073709551615 AS BIGINT UNSIGNED) AS kernel_sequence,coverage_interval_id";
    let sql = araphor_data::FindingV1::PACKAGES.iter().map(|id| format!(
        "SELECT * FROM \"{id}\".\"1\".detect('subjects', records => (SELECT * FROM records), facts => (SELECT * FROM facts), manifest => (SELECT * FROM manifest))"
    )).collect::<Vec<_>>().join(" UNION ALL ");
    let events = format!("SELECT {columns} FROM events");
    let publication = fixture.prepare_sql(columns, "", sql).await?;
    let grant = publication.grant.clone();
    let definition = publication.prepared.resolved().clone();
    fixture.admit_definition(&grant, &definition)?;
    drop(publication);
    let id = "changed-coverage";
    let owner = fixture
        .managed_graph(&grant, &definition, id, &events)
        .await?;
    let store = fixture.query.store();
    let initial = store.managed_status(&grant.selection, id, &fixture.control)?;
    assert_eq!(&initial.instance, owner.admitted());
    assert_eq!(initial.status_progress, 0);
    assert!(matches!(
        initial.readiness,
        araphor_data::PackageReadinessV1::Inactive
    ));
    let before_domain = fixture.graph_history()?;
    assert!(store
        .graph_window_headers(&fixture.source, None)?
        .is_empty());
    let scope = araphor_data::ProcessorScopeV1 {
        processor_id: araphor_data::GRAPH_PROCESSOR.into(),
        method_version: u64::from(araphor_data::GRAPH_SCHEMA_VERSION),
        identity: fixture.source.clone(),
    };
    assert!(store.processor_result(&scope)?.is_none());
    let before_health = store.processor_health(&scope)?;
    let before_usage = store.retained_usage(fixture.source.tenant_id)?;
    let before = store.meta()?;
    let input = managed::request("invalid")?;
    assert!(owner.run(input.clone(), &fixture.control).await.is_err());
    assert_eq!(fixture.facts.calls.load(Ordering::SeqCst), 0);
    fixture.assert_invalid_graph(
        owner.as_ref(),
        &input,
        &before,
        &before_domain,
        before_health,
        before_usage,
    )?;
    Ok(())
}

#[tokio::test]
async fn rejects_foreign_event_call() -> TestResult {
    let fixture = Fixture::target(Target::Sql)?;
    let mut model = sdk::Model::new(
        "evaluate",
        Vec::new(),
        vec![sdk::Port::new(
            "data",
            sdk::Schema::new(vec![sdk::Field::new("value", sdk::DataType::UInt64, false)]),
        )],
    );
    model.parameters = sdk::Schema::new(vec![
        sdk::Field::new("mode", sdk::DataType::Utf8, false),
        sdk::Field::new("amount", sdk::DataType::UInt64, false),
    ]);
    let artifact = PackageArtifactV1 {
        descriptor: sdk::Package::new("runtime-fixture", "1", vec![model]),
        implementations: vec![PackageImplementationV1::Wasm {
            exports: vec!["evaluate".into()],
            artifact: araphor_analysis_builtins::components::RUNTIME.to_vec(),
        }],
        fixtures: Vec::new(),
    };
    fixture.query.store().install_package_image(
        fixture.source.tenant_id,
        &araphor_data::PackageBundle::try_from(PackageBundleV1 {
            schema_version: 1,
            root: artifact.reference(),
            artifacts: vec![artifact],
        })?,
        || Ok(()),
    )?;
    let now = u64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos())?;
    let selection = AnalysisSelectionV1::tenant(fixture.source.tenant_id);
    let session = fixture
        .query
        .session(selection.clone(), &AnalysisReadControl::default(), now)?;
    let foreign = session.prepare_definition(&Definition {
        name: "foreign-event-call".into(), description: String::new(), labels: Default::default(),
        program: Program::Sql { source: Source::Inline { inline:
            r#"SELECT events.* FROM events CROSS JOIN "runtime-fixture"."1".evaluate(mode => 'cancel', amount => 1) AS foreign_call"#.into(),
        }},
    }).await?;
    let mut calls = 0;
    PackageCall::any(&foreign.plan, &mut |_| {
        calls += 1;
        Ok(false)
    })?;
    assert_eq!(calls, 1);
    let (entry, observed) = std::sync::mpsc::channel();
    fixture.query.guest_entry(entry, None)?;
    let before = fixture.query.store().meta()?;
    let sql = araphor_data::FindingV1::PACKAGES.iter().map(|id| format!(
        "SELECT * FROM \"{id}\".\"1\".detect('subjects', records => (SELECT * FROM records), facts => (SELECT * FROM facts), manifest => (SELECT * FROM manifest))"
    )).collect::<Vec<_>>().join(" UNION ALL ");
    let denied = GraphPublication::prepare(
        session,
        fixture.authority.clone(),
        PackageGrantV1 {
            principal: "graph-native-fixture".into(),
            revision: 1,
            selection,
            expires_utc_ns: None,
            authorization_id: None,
        },
        foreign.plan.clone(),
        Definition {
            name: "graph-foreign-call".into(),
            description: String::new(),
            labels: Default::default(),
            program: Program::Sql {
                source: Source::Inline { inline: sql },
            },
        },
        fixture.facts.clone(),
    )
    .await;
    let Err(denied) = denied else {
        return Err("foreign call image was admitted".into());
    };
    assert_eq!(
        erebor_runtime_error::ErrorExt::status_code(&denied),
        erebor_runtime_error::StatusCode::PermissionDenied
    );
    assert!(matches!(
        observed.try_recv(),
        Err(std::sync::mpsc::TryRecvError::Empty)
    ));
    assert_eq!(fixture.facts.calls.load(Ordering::SeqCst), 0);
    assert_eq!(fixture.query.store().meta()?, before);
    Ok(())
}

#[tokio::test]
async fn extra_origin_changes_metadata() -> TestResult {
    let fixture = Fixture::target(Target::Sql)?;
    let sql = araphor_data::FindingV1::PACKAGES.iter().map(|id| format!(
        "SELECT * FROM \"{id}\".\"1\".detect('subjects', records => (WITH unused AS (SELECT * FROM context_versions) SELECT * FROM records), facts => (SELECT * FROM facts), manifest => (SELECT * FROM manifest))"
    )).collect::<Vec<_>>().join(" UNION ALL ");
    let publication = fixture.prepare_sql("*", "", sql).await?;
    let grant = publication.grant.clone();
    let definition = publication.prepared.resolved().clone();
    fixture.admit_definition(&grant, &definition)?;
    drop(publication);
    let id = "extra-origin";
    let owner = fixture
        .managed_graph(&grant, &definition, id, "SELECT * FROM events")
        .await?;
    let store = fixture.query.store();
    let initial = store.managed_status(&grant.selection, id, &fixture.control)?;
    assert_eq!(&initial.instance, owner.admitted());
    assert_eq!(initial.status_progress, 0);
    assert!(matches!(
        initial.readiness,
        araphor_data::PackageReadinessV1::Inactive
    ));
    let before_domain = fixture.graph_history()?;
    assert!(store
        .graph_window_headers(&fixture.source, None)?
        .is_empty());
    let scope = araphor_data::ProcessorScopeV1 {
        processor_id: araphor_data::GRAPH_PROCESSOR.into(),
        method_version: u64::from(araphor_data::GRAPH_SCHEMA_VERSION),
        identity: fixture.source.clone(),
    };
    assert!(store.processor_result(&scope)?.is_none());
    let before_health = store.processor_health(&scope)?;
    let before_usage = store.retained_usage(fixture.source.tenant_id)?;
    let before = store.meta()?;
    let input = managed::request("invalid")?;
    let error = owner
        .run(input.clone(), &fixture.control)
        .await
        .err()
        .ok_or("extra origin retained qualified metadata")?;
    assert!(
        format!("{error:?}").contains("graph qualified input"),
        "{error:?}"
    );
    fixture.assert_invalid_graph(
        owner.as_ref(),
        &input,
        &before,
        &before_domain,
        before_health,
        before_usage,
    )?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancel_joins_projection_capacity() -> TestResult {
    const CAPACITY: usize = 32 * 1024 * 1024;
    let mut fixture = Fixture::target(Target::Sql)?;
    fixture.query = Engine::new(
        Arc::clone(fixture.query.store()),
        araphor_query::execution::Limits {
            global_evaluations: Some(1),
            input_capacity: Some(CAPACITY),
            ..Default::default()
        },
    )?;
    let publication = fixture.prepare("").await?;
    let grant = publication.grant.clone();
    let definition = publication.prepared.resolved().clone();
    fixture.admit_definition(&grant, &definition)?;
    drop(publication);
    let instance = fixture
        .managed_graph(
            &grant,
            &definition,
            "held-projection",
            "SELECT * FROM events",
        )
        .await?;
    let before_instance = instance.admitted().clone();
    assert!(!before_instance.running);
    let held = fixture.query.memory().input_reserved();
    let residual = CAPACITY
        .checked_sub(held)
        .filter(|bytes| *bytes > 0)
        .ok_or("Graph admission consumed input capacity")?;
    drop(fixture.query.memory().reserve_input(residual)?);
    let before_domain = fixture.graph_history()?;
    let before_heads = fixture
        .query
        .store()
        .graph_window_headers(&fixture.source, None)?;
    let scope = araphor_data::ProcessorScopeV1 {
        processor_id: araphor_data::GRAPH_PROCESSOR.into(),
        method_version: u64::from(araphor_data::GRAPH_SCHEMA_VERSION),
        identity: fixture.source.clone(),
    };
    let before_head = fixture.query.store().processor_result(&scope)?;
    let before_health = fixture.query.store().processor_health(&scope)?;
    let before_usage = fixture
        .query
        .store()
        .retained_usage(fixture.source.tenant_id)?;
    let before = fixture.query.store().meta()?;
    let (entry, observed) = std::sync::mpsc::channel();
    let (release, waiting) = std::sync::mpsc::channel();
    *fixture
        .facts
        .gate
        .lock()
        .unwrap_or_else(|error| error.into_inner()) = Some((entry, waiting));
    let input = managed::request("held")?;
    let caller = input.clone();
    let control = Arc::new(AnalysisReadControl::default());
    let stage = Arc::clone(&control);
    let mut execution = tokio::spawn(async move { instance.run(input, &stage).await });
    let mut completed = None;
    let observations =
        async {
            tokio::task::spawn_blocking(move || {
                observed.recv_timeout(std::time::Duration::from_secs(30))
            })
            .await??;
            let evaluation_before = fixture
                .query
                .reserve_evaluation(fixture.source.tenant_id)
                .is_err();
            let input_before = fixture.query.memory().reserve_input(CAPACITY).is_err();
            let residual_before = fixture.query.memory().reserve_input(residual).is_err();
            fixture.authority.set(false);
            let blocked =
                match tokio::time::timeout(std::time::Duration::from_millis(50), &mut execution)
                    .await
                {
                    Ok(result) => {
                        completed = Some(result);
                        false
                    }
                    Err(_) => true,
                };
            let evaluation_after = fixture
                .query
                .reserve_evaluation(fixture.source.tenant_id)
                .is_err();
            let input_after = fixture.query.memory().reserve_input(CAPACITY).is_err();
            let residual_after = fixture.query.memory().reserve_input(residual).is_err();
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>((
                evaluation_before,
                input_before,
                residual_before,
                blocked,
                evaluation_after,
                input_after,
                residual_after,
            ))
        }
        .await;
    if observations.is_err() {
        let _cancelled = control.cancel();
    }
    let released = release.send(());
    let joined = match completed {
        Some(result) => result,
        None => execution.await,
    };
    let (
        evaluation_before,
        input_before,
        residual_before,
        blocked,
        evaluation_after,
        input_after,
        residual_after,
    ) = observations?;
    released?;
    let result = joined?;
    assert!(evaluation_before);
    assert!(input_before);
    assert!(residual_before);
    assert!(blocked);
    assert!(evaluation_after);
    assert!(input_after);
    assert!(residual_after);
    let error = result.err().ok_or("canceled Graph source published")?;
    assert_eq!(
        erebor_runtime_error::ErrorExt::status_code(&error),
        erebor_runtime_error::StatusCode::PermissionDenied
    );
    assert_eq!(fixture.facts.calls.load(Ordering::SeqCst), 1);
    let saved = fixture
        .query
        .store()
        .managed_attempt(
            fixture.source.tenant_id,
            "held-projection",
            &caller.id,
            &fixture.control,
        )?
        .ok_or("denied Graph intent")?;
    let mut supplied = saved.request().clone();
    let frontier = supplied.frontier.take().ok_or("denied native frontier")?;
    assert_eq!(supplied, caller);
    assert!(!frontier.pending);
    assert_eq!(frontier.next_change, None);
    let cursor = araphor_query::follow::Cursor::decode(&frontier.cursor)?;
    assert_eq!(cursor.encode()?, frontier.cursor);
    assert_eq!(cursor.read_revision(), before.commit_revision);
    assert_eq!(
        cursor.position(),
        StorePositionV1 {
            commit_revision: 0,
            ordinal: 0
        }
    );
    assert_eq!(saved.instance(), &before_instance);
    assert!(saved.receipt().is_none());
    let revision = if let Some(terminal) = saved.terminal() {
        let revision = before
            .commit_revision
            .checked_add(2)
            .ok_or("denied Graph revision overflow")?;
        assert_eq!(terminal.instance, "held-projection");
        assert_eq!(terminal.attempt, caller.id);
        assert_eq!(terminal.revision, revision);
        assert_eq!(
            terminal.exit,
            araphor_data::ManagedExit::Failed(Code::Denied)
        );
        assert!(!terminal.suspended);
        let status = fixture.query.store().managed_status(
            &grant.selection,
            "held-projection",
            &fixture.control,
        )?;
        assert_eq!(status.instance, before_instance);
        assert_eq!(status.status_progress, before_instance.progress);
        assert!(
            matches!(status.readiness, araphor_data::PackageReadinessV1::Failed {
            code: Code::Denied, field } if field == "model evaluation")
        );
        assert_eq!(
            fixture.query.store().managed_resume(
                fixture.source.tenant_id,
                "held-projection",
                &fixture.control
            )?,
            araphor_data::ManagedResume {
                instance: before_instance.clone(),
                frontier: None,
                completed: revision
            }
        );
        revision
    } else {
        assert!(
            matches!(fixture.query.store().managed_status(&grant.selection, "held-projection", &fixture.control),
            Err(araphor_data::Error::Package { code: Code::Incomplete, field, .. })
                if field == "managed pending attempt")
        );
        assert!(
            matches!(fixture.query.store().managed_resume(fixture.source.tenant_id,
            "held-projection", &fixture.control), Err(araphor_data::Error::Package {
                code: Code::Incomplete, field, .. }) if field == "managed pending attempt")
        );
        before
            .commit_revision
            .checked_add(1)
            .ok_or("pending Graph revision overflow")?
    };
    let mut expected_meta = before;
    expected_meta.commit_revision = revision;
    assert_eq!(fixture.query.store().meta()?, expected_meta);
    assert_eq!(
        fixture
            .query
            .store()
            .managed_instance(
                fixture.source.tenant_id,
                "held-projection",
                &fixture.control
            )?
            .ok_or("denied Graph instance")?,
        before_instance
    );
    assert!(fixture
        .query
        .store()
        .managed_history(&grant.selection, "held-projection", &fixture.control)?
        .is_empty());
    assert!(fixture
        .query
        .store()
        .managed_selected(
            fixture.source.tenant_id,
            "held-projection",
            &caller.id,
            &fixture.control
        )?
        .is_none());
    assert_eq!(fixture.graph_history()?, before_domain);
    assert_eq!(
        fixture
            .query
            .store()
            .graph_window_headers(&fixture.source, None)?,
        before_heads
    );
    assert_eq!(fixture.query.store().processor_result(&scope)?, before_head);
    let expected_health = before_health.map(|mut health| {
        health.read_revision = revision;
        health
    });
    assert_eq!(
        fixture.query.store().processor_health(&scope)?,
        expected_health
    );
    let usage = fixture
        .query
        .store()
        .retained_usage(fixture.source.tenant_id)?;
    assert_eq!(
        (usage.1, usage.2, usage.3),
        (before_usage.1, before_usage.2, before_usage.3)
    );
    fixture.query.store().verify_state()?;
    drop(fixture.query.reserve_evaluation(fixture.source.tenant_id)?);
    drop(fixture.query.memory().reserve_input(CAPACITY)?);
    Ok(())
}

#[tokio::test]
async fn rejects_missing_frozen_coverage() -> TestResult {
    let fixture = Fixture::target(Target::Sql)?;
    fixture.coverage(1, Some("GAPPED"))?;
    let publication = fixture.prepare("").await?;
    let grant = publication.grant.clone();
    let definition = publication.prepared.resolved().clone();
    fixture.admit_definition(&grant, &definition)?;
    drop(publication);
    let owner = fixture
        .managed_graph(
            &grant,
            &definition,
            "missing-frozen",
            "SELECT * FROM events",
        )
        .await?;
    let scope = araphor_data::ProcessorScopeV1 {
        processor_id: araphor_data::GRAPH_PROCESSOR.into(),
        method_version: u64::from(araphor_data::GRAPH_SCHEMA_VERSION),
        identity: fixture.source.clone(),
    };
    let store = fixture.query.store();
    let first_receipt = owner
        .run(managed::request("seed")?, &fixture.control)
        .await?;
    let head = store.processor_result(&scope)?.ok_or("native Graph head")?;
    assert_eq!(head.commit_revision, first_receipt.commit_revision);
    let id = head.result_id;
    let retained = fixture
        .query
        .store()
        .graph_result(fixture.source.tenant_id, &id)?
        .ok_or("frozen graph")?;
    assert!(retained
        .input_manifest
        .coverage
        .iter()
        .any(|key| key.report_revision == 1));
    fixture.coverage(2, Some("HEALTHY"))?;
    fixture
        .query
        .store()
        .fault_write("DELETE FROM coverage WHERE revision = 1", &[])?;
    let before_domain = fixture.graph_history()?;
    let before_heads = store.graph_window_headers(&fixture.source, None)?;
    let before_head = store.processor_result(&scope)?;
    let before_health = store.processor_health(&scope)?.ok_or("Graph health")?;
    let before_instance = store
        .managed_instance(
            fixture.source.tenant_id,
            &owner.admitted().spec.id,
            &fixture.control,
        )?
        .ok_or("Graph instance")?;
    let before_history = store.managed_history(
        &grant.selection,
        &owner.admitted().spec.id,
        &fixture.control,
    )?;
    let before_status = store.managed_status(
        &grant.selection,
        &owner.admitted().spec.id,
        &fixture.control,
    )?;
    assert!(matches!(
        before_status.readiness,
        araphor_data::PackageReadinessV1::Inactive
    ));
    let before_resume = store.managed_resume(
        fixture.source.tenant_id,
        &owner.admitted().spec.id,
        &fixture.control,
    )?;
    let before_usage = store.retained_usage(fixture.source.tenant_id)?;
    let before = fixture.query.store().meta()?;
    let calls = fixture.facts.calls.load(Ordering::SeqCst);
    let error = owner
        .run(managed::request("invalid")?, &fixture.control)
        .await
        .err()
        .ok_or("missing frozen report used latest fallback")?;
    assert!(format!("{error:?}").contains("frozen graph coverage is absent"));
    assert_eq!(fixture.facts.calls.load(Ordering::SeqCst), calls);
    assert_eq!(fixture.query.store().meta()?, before);
    assert_eq!(fixture.graph_history()?, before_domain);
    assert_eq!(
        store.graph_window_headers(&fixture.source, None)?,
        before_heads
    );
    assert_eq!(store.processor_result(&scope)?, before_head);
    assert_eq!(
        store.managed_instance(
            fixture.source.tenant_id,
            &owner.admitted().spec.id,
            &fixture.control
        )?,
        Some(before_instance)
    );
    assert_eq!(
        store.managed_history(
            &grant.selection,
            &owner.admitted().spec.id,
            &fixture.control
        )?,
        before_history
    );
    assert_eq!(store.processor_health(&scope)?, Some(before_health));
    let status = store.managed_status(
        &grant.selection,
        &owner.admitted().spec.id,
        &fixture.control,
    )?;
    assert_eq!(status.instance, before_status.instance);
    assert_eq!(status.status_progress, before_status.status_progress);
    assert!(matches!(
        status.readiness,
        araphor_data::PackageReadinessV1::Inactive
    ));
    assert_eq!(
        store.managed_resume(
            fixture.source.tenant_id,
            &owner.admitted().spec.id,
            &fixture.control
        )?,
        before_resume
    );
    assert!(store
        .managed_attempt(
            fixture.source.tenant_id,
            &owner.admitted().spec.id,
            "invalid",
            &fixture.control
        )?
        .is_none());
    assert!(store
        .managed_selected(
            fixture.source.tenant_id,
            &owner.admitted().spec.id,
            "invalid",
            &fixture.control
        )?
        .is_none());
    assert_eq!(
        store.retained_usage(fixture.source.tenant_id)?,
        before_usage
    );
    Ok(())
}
