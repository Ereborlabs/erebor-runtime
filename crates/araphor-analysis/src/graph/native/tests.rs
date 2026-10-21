mod gates;

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use araphor_data::{
    AnalysisReadControl, AnalysisSelectionV1, AnalysisStore, DiscoveryInputManifestV1,
    EvidenceIntakeIdentityV1, PackageArtifactV1, PackageBundleV1, PackageImplementationV1,
    ValidatedEvidenceBatchV1,
};
use araphor_query::execution::Engine;
use tokio::sync::watch;

use super::*;

type TestResult<T = ()> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

struct Authority {
    changes: watch::Sender<u64>,
    allowed: AtomicBool,
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
    fn admit(&self, grant: &PackageGrantV1, _: &PackageBundleRef<'_>) -> araphor_data::Result<()> {
        self.check(grant, PackageActionV1::Run)
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
        action: PackageActionV1,
        operation: &mut dyn FnMut() -> araphor_data::Result<()>,
    ) -> araphor_data::Result<()> {
        if grants.is_empty() || !grants.iter().any(|(_, image)| image.is_none()) {
            return Err(Code::Denied.error("graph fixture authority"));
        }
        for (grant, image) in grants {
            self.check(grant, action)?;
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
    calls: AtomicUsize,
    notice: Mutex<Option<(Arc<Authority>, bool)>>,
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
        if let Some((authority, allowed)) = self
            .notice
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .take()
        {
            authority.set(allowed);
        }
        let contexts = records
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
    _directory: tempfile::TempDir,
}

impl Fixture {
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
        store.enable_graph_owner()?;
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
                        let mut program = araphor_package::SqlModelV1::default();
                        for name in ["subjects", "relationships", "findings"] {
                            program.outputs.insert(
                                name.into(),
                                "SELECT value FROM records WHERE FALSE".into(),
                            );
                        }
                        program.checkpoint.insert(
                            "state".into(),
                            r#"SELECT CAST('{"value":"WAITING"}' AS BYTEA) AS value"#.into(),
                        );
                        PackageImplementationV1::Sql {
                            export: "detect".into(),
                            program,
                        }
                    }
                }],
                fixtures: Vec::new(),
            };
            store.install_package_image(
                source.tenant_id,
                &PackageBundleV1 {
                    schema_version: 1,
                    root: artifact.reference(),
                    artifacts: vec![artifact],
                },
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
            }),
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
    let projection = Arc::clone(&publication.projection);
    let first = publication.refresh("graph:native-first".into()).await?;
    let captured = projection
        .captured
        .get()
        .ok_or("graph capture")?
        .as_ref()
        .map_err(|error| error.to_string())?;
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
    drop(projection);
    assert_eq!(first.0, "graph:native-first");
    assert_eq!(fixture.facts.calls.load(Ordering::SeqCst), 1);
    let snapshot = fixture
        .query
        .store()
        .graph_result(fixture.source.tenant_id, &first.0)?
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
    let scope = &snapshot.scope;
    assert_eq!(
        fixture
            .query
            .store()
            .processor_health(scope)?
            .ok_or("graph progress")?
            .consumed_cursor,
        0
    );
    let before = fixture.query.store().meta()?;
    let next = fixture.prepare("").await?;
    let projection = Arc::clone(&next.projection);
    let second = next.refresh("graph:native-unchanged".into()).await?;
    let captured = projection
        .captured
        .get()
        .ok_or("second Graph capture")?
        .as_ref()
        .map_err(|error| error.to_string())?;
    assert_eq!(projection.projections.load(Ordering::SeqCst), 1);
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
    drop(projection);
    assert_eq!(second, first);
    assert_eq!(fixture.facts.calls.load(Ordering::SeqCst), 2);
    assert_eq!(fixture.query.store().meta()?, before);
    assert!(fixture
        .query
        .store()
        .graph_result(fixture.source.tenant_id, "graph:native-unchanged")?
        .is_none());
    let (_, pins) = fixture
        .query
        .store()
        .package_evidence(fixture.source.tenant_id, &[first.0])?;
    assert!(pins
        .iter()
        .any(|pin| pin.key.owner_id == "native-package-v1"));
    drop(fixture.query.reserve_evaluation(fixture.source.tenant_id)?);
    Ok(())
}

#[tokio::test]
async fn empty_window_is_inert() -> TestResult {
    let fixture = Fixture::target(Target::Sql)?;
    let before = fixture.query.store().meta()?;
    assert!(fixture
        .prepare("WHERE FALSE")
        .await?
        .refresh("graph:empty".into())
        .await
        .is_err());
    assert_eq!(fixture.facts.calls.load(Ordering::SeqCst), 0);
    assert_eq!(fixture.query.store().meta()?, before);
    assert!(fixture
        .query
        .store()
        .graph_result(fixture.source.tenant_id, "graph:empty")?
        .is_none());
    drop(fixture.query.reserve_evaluation(fixture.source.tenant_id)?);
    Ok(())
}

#[tokio::test]
async fn final_cancel_rolls_back() -> TestResult {
    let fixture = Fixture::target(Target::Sql)?;
    let owner = fixture.prepare("").await?;
    let cancel = Arc::clone(&fixture.control);
    let before = fixture.query.store().meta()?;
    fixture.query.store().set_commit_hook(
        araphor_data::AnalysisCommitStage::BeforeResultCommit,
        move || cancel.cancel(),
    )?;
    assert!(owner.refresh("graph:cancelled".into()).await.is_err());
    assert_eq!(fixture.facts.calls.load(Ordering::SeqCst), 1);
    assert_eq!(fixture.query.store().meta()?, before);
    assert!(fixture
        .query
        .store()
        .graph_result(fixture.source.tenant_id, "graph:cancelled")?
        .is_none());
    drop(fixture.query.reserve_evaluation(fixture.source.tenant_id)?);
    Ok(())
}

#[tokio::test]
async fn duplicate_records_are_rejected() -> TestResult {
    let fixture = Fixture::target(Target::Sql)?;
    let before = fixture.query.store().meta()?;
    let owner = fixture.prepare("UNION ALL SELECT * FROM events").await?;
    assert!(owner.refresh("graph:duplicate".into()).await.is_err());
    assert_eq!(fixture.facts.calls.load(Ordering::SeqCst), 0);
    assert_eq!(fixture.query.store().meta()?, before);
    assert!(fixture
        .query
        .store()
        .graph_result(fixture.source.tenant_id, "graph:duplicate")?
        .is_none());
    drop(fixture.query.reserve_evaluation(fixture.source.tenant_id)?);
    Ok(())
}

#[tokio::test]
async fn benign_notice_keeps_capture() -> TestResult {
    let fixture = Fixture::target(Target::Sql)?;
    *fixture
        .facts
        .notice
        .lock()
        .unwrap_or_else(|error| error.into_inner()) = Some((Arc::clone(&fixture.authority), true));
    let (id, _) = fixture
        .prepare("")
        .await?
        .refresh("graph:notice".into())
        .await?;
    assert_eq!(fixture.facts.calls.load(Ordering::SeqCst), 1);
    let snapshot = fixture
        .query
        .store()
        .graph_result(fixture.source.tenant_id, &id)?
        .ok_or("graph result")?;
    assert_eq!(snapshot.packages.len(), 3);
    assert_eq!(snapshot.input_positions.len(), 3);
    drop(fixture.query.reserve_evaluation(fixture.source.tenant_id)?);
    Ok(())
}

#[tokio::test]
async fn denied_notice_joins() -> TestResult {
    let fixture = Fixture::target(Target::Sql)?;
    *fixture
        .facts
        .notice
        .lock()
        .unwrap_or_else(|error| error.into_inner()) = Some((Arc::clone(&fixture.authority), false));
    let before = fixture.query.store().meta()?;
    assert!(fixture
        .prepare("")
        .await?
        .refresh("graph:denied".into())
        .await
        .is_err());
    assert_eq!(fixture.facts.calls.load(Ordering::SeqCst), 1);
    assert_eq!(fixture.query.store().meta()?, before);
    assert!(fixture
        .query
        .store()
        .graph_result(fixture.source.tenant_id, "graph:denied")?
        .is_none());
    drop(fixture.query.reserve_evaluation(fixture.source.tenant_id)?);
    Ok(())
}

#[tokio::test]
async fn overlap_keeps_selected_facts() -> TestResult {
    let fixture = Fixture::target(Target::Sql)?;
    let (old, _) = fixture
        .prepare("")
        .await?
        .refresh("graph:wide".into())
        .await?;
    let prior = fixture
        .query
        .store()
        .graph_result(fixture.source.tenant_id, &old)?
        .ok_or("prior graph")?;
    assert_eq!(prior.input_manifest.context.len(), 3);
    let (id, _) = fixture
        .prepare("WHERE source_cursor >= 2")
        .await?
        .refresh("graph:narrow".into())
        .await?;
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
    let before = fixture.query.store().meta()?;
    let sql = araphor_data::FindingV1::PACKAGES.iter().map(|id| format!(
        "SELECT * FROM \"{id}\".\"1\".detect('subjects', records => (SELECT * FROM records), facts => (SELECT * FROM facts), manifest => (SELECT * FROM manifest)){}",
        if *id == "HF-XNODE-001" { " WHERE FALSE" } else { "" }
    )).collect::<Vec<_>>().join(" UNION ALL ");
    let owner = fixture.prepare_sql("*", "", sql).await?;
    assert_eq!(owner.calls.len(), 3);
    let error = owner
        .refresh("graph:missing-return".into())
        .await
        .err()
        .ok_or("missing native result published")?;
    assert!(std::iter::successors(
        Some(&error as &(dyn std::error::Error + 'static)),
        |error| error.source()
    )
    .any(|error| error.to_string().contains("required graph detector return")));
    assert_eq!(fixture.facts.calls.load(Ordering::SeqCst), 1);
    assert_eq!(fixture.query.store().meta()?, before);
    assert!(fixture
        .query
        .store()
        .graph_result(fixture.source.tenant_id, "graph:missing-return")?
        .is_none());
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
    let publication = fixture.prepare_sql(columns, "", sql).await?;
    let (id, _) = publication.refresh("graph:projected".into()).await?;
    let retained = fixture
        .query
        .store()
        .graph_result(fixture.source.tenant_id, &id)?
        .ok_or("graph result")?;
    assert_eq!(retained.input_manifest.evidence.len(), 3);
    assert_eq!(retained.packages.len(), 3);
    assert_eq!(fixture.facts.calls.load(Ordering::SeqCst), 1);
    Ok(())
}

#[tokio::test]
async fn keeps_frozen_coverage() -> TestResult {
    let fixture = Fixture::target(Target::Sql)?;
    fixture.coverage(1, Some("GAPPED"))?;
    let owner = fixture.prepare("").await?;
    let projection = Arc::clone(&owner.projection);
    let (first, _) = owner.refresh("graph:coverage-one".into()).await?;
    let capture = projection
        .captured
        .get()
        .ok_or("coverage capture")?
        .as_ref()
        .map_err(|error| error.to_string())?;
    assert!(capture
        .inputs
        .iter()
        .all(|input| input.coverage.state == sdk::CoverageState::Gapped
            && input.coverage.limits == ["SOURCE_COVERAGE_INSUFFICIENT"]));
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
    let (second, _) = fixture
        .prepare("")
        .await?
        .refresh("graph:coverage-two".into())
        .await?;
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
    let (same, _) = fixture
        .prepare("")
        .await?
        .refresh("graph:coverage-fallback".into())
        .await?;
    assert_eq!(same, second);
    assert!(fixture
        .query
        .store()
        .graph_result(fixture.source.tenant_id, "graph:coverage-fallback")?
        .is_none());
    Ok(())
}

#[tokio::test]
async fn fallback_has_no_keys() -> TestResult {
    let fixture = Fixture::target(Target::Sql)?;
    fixture.coverage(1, None)?;
    let (id, _) = fixture
        .prepare("")
        .await?
        .refresh("graph:unmatched-report".into())
        .await?;
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
    let before = fixture.query.store().meta()?;
    let columns = "tenant_id,node_id,node_boot_id,label_epoch,source_id,source_epoch,cpu_id,source_cursor,framed_record,commit_revision,ordinal,temporal_coverage,CAST(18446744073709551615 AS BIGINT UNSIGNED) AS kernel_sequence,coverage_interval_id";
    let sql = araphor_data::FindingV1::PACKAGES.iter().map(|id| format!(
        "SELECT * FROM \"{id}\".\"1\".detect('subjects', records => (SELECT * FROM records), facts => (SELECT * FROM facts), manifest => (SELECT * FROM manifest))"
    )).collect::<Vec<_>>().join(" UNION ALL ");
    let owner = fixture.prepare_sql(columns, "", sql).await?;
    assert!(owner.refresh("graph:forged-coverage".into()).await.is_err());
    assert_eq!(fixture.facts.calls.load(Ordering::SeqCst), 0);
    assert_eq!(fixture.query.store().meta()?, before);
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
        &PackageBundleV1 {
            schema_version: 1,
            root: artifact.reference(),
            artifacts: vec![artifact],
        },
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
    let before = fixture.query.store().meta()?;
    let error = publication
        .refresh("graph:extra-source".into())
        .await
        .err()
        .ok_or("extra origin retained qualified metadata")?;
    assert!(
        format!("{error:?}").contains("graph qualified input"),
        "{error:?}"
    );
    assert_eq!(fixture.query.store().meta()?, before);
    assert!(fixture
        .query
        .store()
        .graph_result(fixture.source.tenant_id, "graph:extra-source")?
        .is_none());
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
    let (entry, observed) = std::sync::mpsc::channel();
    let (release, waiting) = std::sync::mpsc::channel();
    *fixture
        .facts
        .gate
        .lock()
        .unwrap_or_else(|error| error.into_inner()) = Some((entry, waiting));
    let publication = fixture.prepare("").await?;
    let before = fixture.query.store().meta()?;
    let mut execution =
        tokio::spawn(async move { publication.refresh("graph:held-projection".into()).await });
    tokio::task::spawn_blocking(move || observed.recv_timeout(std::time::Duration::from_secs(30)))
        .await??;
    assert!(fixture
        .query
        .reserve_evaluation(fixture.source.tenant_id)
        .is_err());
    assert!(fixture.query.memory().reserve_input(CAPACITY).is_err());
    fixture.authority.set(false);
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(50), &mut execution)
            .await
            .is_err()
    );
    assert!(fixture
        .query
        .reserve_evaluation(fixture.source.tenant_id)
        .is_err());
    assert!(fixture.query.memory().reserve_input(CAPACITY).is_err());
    release.send(())?;
    let error = execution
        .await?
        .err()
        .ok_or("canceled Graph source published")?;
    assert_eq!(
        erebor_runtime_error::ErrorExt::status_code(&error),
        erebor_runtime_error::StatusCode::PermissionDenied
    );
    assert_eq!(fixture.query.store().meta()?, before);
    assert!(fixture
        .query
        .store()
        .graph_result(fixture.source.tenant_id, "graph:held-projection")?
        .is_none());
    drop(fixture.query.reserve_evaluation(fixture.source.tenant_id)?);
    drop(fixture.query.memory().reserve_input(CAPACITY)?);
    Ok(())
}

#[tokio::test]
async fn rejects_missing_frozen_coverage() -> TestResult {
    let fixture = Fixture::target(Target::Sql)?;
    fixture.coverage(1, Some("GAPPED"))?;
    let (id, _) = fixture
        .prepare("")
        .await?
        .refresh("graph:frozen-before-loss".into())
        .await?;
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
    let before = fixture.query.store().meta()?;
    let calls = fixture.facts.calls.load(Ordering::SeqCst);
    let error = fixture
        .prepare("")
        .await?
        .refresh("graph:missing-frozen".into())
        .await
        .err()
        .ok_or("missing frozen report used latest fallback")?;
    assert!(format!("{error:?}").contains("frozen graph coverage is absent"));
    assert_eq!(fixture.facts.calls.load(Ordering::SeqCst), calls);
    assert_eq!(fixture.query.store().meta()?, before);
    assert!(fixture
        .query
        .store()
        .graph_result(fixture.source.tenant_id, "graph:missing-frozen")?
        .is_none());
    Ok(())
}
