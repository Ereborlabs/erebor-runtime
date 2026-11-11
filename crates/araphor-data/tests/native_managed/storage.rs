use super::*;
use araphor_data::analysis::{
    native::{DataView, ManagedCommit, ManagedReturn},
    PackageResultRefV1,
};
use araphor_data::{ManagedAttempt, ManagedCapture, ManagedRead, ManagedReceipt, ManagedRequest};
use sdk::arrow_array::{StringArray, UInt64Array};

#[path = "storage/calls.rs"]
mod calls;
#[path = "storage/control.rs"]
mod control;
#[path = "storage/output.rs"]
mod output;
#[path = "storage/replay.rs"]
mod replay;
#[path = "storage/retention.rs"]
mod retention;
#[path = "storage/source.rs"]
mod source;
#[path = "storage/terminal.rs"]
mod terminal;

struct StorageFixture {
    instance: ManagedInstance,
    model: sdk::Model,
}

#[derive(serde::Deserialize, serde::Serialize)]
struct Instance {
    tenant: [u8; 16],
    id: String,
    grant: PackageGrantV1,
    generation: u64,
    progress: u64,
    running: bool,
    removed: bool,
    lifecycle: u64,
}

#[derive(serde::Deserialize)]
struct CallHead {
    revision: u64,
    result: Option<String>,
}

impl StorageFixture {
    fn new(
        store: &NativeStore,
        id: &str,
        description: String,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        Self::new_scope(
            store,
            id,
            description,
            AnalysisSelectionV1::new([1; 16], Vec::new()),
        )
    }

    fn new_scope(
        store: &NativeStore,
        id: &str,
        description: String,
        selection: AnalysisSelectionV1,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        Self::new_model(store, id, description, selection, false)
    }

    fn new_model(
        store: &NativeStore,
        id: &str,
        description: String,
        selection: AnalysisSelectionV1,
        extra: bool,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let scalar = sdk::Schema::new(vec![sdk::Field::new("value", sdk::DataType::UInt64, false)]);
        let mut rows = sdk::Port::new("rows", scalar.clone());
        rows.evidence_required = true;
        let mut model = sdk::Model::new(
            "count",
            vec![sdk::Port::new("source", scalar.clone())],
            vec![rows],
        );
        if extra {
            model
                .inputs
                .push(sdk::Port::new("aux", scalar.clone()).into());
        }
        model.parameters = sdk::Schema::new(vec![sdk::Field::new(
            "increment",
            sdk::DataType::UInt64,
            false,
        )]);
        model.checkpoint = Some(sdk::CheckpointSpec {
            version: 1,
            resume_input_changes: false,
            datasets: vec![sdk::Port::new("state", scalar)],
        });
        model.reasons.push(sdk::Reason {
            code: "managed-fixture.counted".into(),
            details: sdk::Schema::new(vec![sdk::Field::new("detail", sdk::DataType::Utf8, false)]),
        });
        let artifact = PackageArtifactV1 {
            descriptor: sdk::Package::new("managed-fixture", "r1", vec![model.clone()]),
            implementations: vec![PackageImplementationV1::Sql { export: "count".into(), program: SqlModelV1 {
                outputs: [("rows".into(), "SELECT value FROM source".into())].into(),
                checkpoint: [("state".into(), "SELECT value FROM source".into())].into(),
                evidence: Some("SELECT 'rows' AS output_dataset, 0::BIGINT UNSIGNED AS output_row, 'source' AS input_dataset, 0::BIGINT UNSIGNED AS input_row".into()),
                reasons: vec![araphor_data::SqlReasonV1 { output: "rows".into(), code: "managed-fixture.counted".into(), sql: "SELECT 0::BIGINT UNSIGNED AS output_row, 'exact context' AS detail".into() }],
            }}], fixtures: Vec::new(),
        };
        let image = PackageBundle::try_from(PackageBundleV1 {
            schema_version: 1,
            root: artifact.reference(),
            artifacts: vec![artifact],
        })?;
        store.install_package_image([1; 16], &image, || Ok(()))?;
        let pin = ImagePin {
            image: image.bundle().root.clone(),
            digest: image.digest().into(),
        };
        let sql = r#"SELECT * FROM "managed-fixture"."r1".count(source => (SELECT 1::BIGINT UNSIGNED AS value), increment => 2) a CROSS JOIN "managed-fixture"."r1".count(source => (SELECT 1::BIGINT UNSIGNED AS value), increment => 3) b"#;
        let sql = if extra {
            sql.replace(
                "), increment",
                "), aux => (SELECT 0::BIGINT UNSIGNED AS value WHERE false), increment",
            )
        } else {
            sql.to_owned()
        };
        let auxiliary = if extra {
            ", aux => (SELECT 0::BIGINT UNSIGNED AS value WHERE false)"
        } else {
            ""
        };
        let definition = ResolvedDefinition::new(
            Definition {
                name: "independent-calls".into(),
                description,
                labels: BTreeMap::new(),
                program: Program::Sql {
                    source: Source::Inline {
                        inline: sql.clone(),
                    },
                },
            },
            sql.into(),
            vec![pin.clone()],
        )?;
        let revision = store.admit_definition([1; 16], &definition, || Ok(()))?;
        let fixture = Fixture { spec: ManagedSpec {
            destination: ManagedDestination::Selected, tenant: [1; 16], id: id.into(), definition,
            manifest: ManagedManifest { format: 1, planner: "datafusion-55/sql-call-1".into(), definition: revision, selected_schema: model.outputs[0].schema.clone(),
                calls: [(10, 2), (11, 3)].into_iter().map(|(id, increment)| (id, ManagedCall { image: pin.clone(), package: image.bundle().root.clone(), export: "count".into(), target: "sql".into(), artifact: None, arguments: vec![format!("source => (SELECT 1::BIGINT UNSIGNED AS value){auxiliary}, increment => {increment}")], dependencies: Default::default() })).collect(),
            },
        }, grant: PackageGrantV1 { principal: "fixture".into(), revision: 1, selection, expires_utc_ns: None, authorization_id: Some("definition-grant".into()) } };
        Ok(Self {
            instance: fixture.admit(store)?,
            model,
        })
    }

    fn capture(&self, store: &NativeStore) -> Result<ManagedCapture, Box<dyn std::error::Error>> {
        self.capture_rebuild(store, false)
    }

    fn capture_rebuild(
        &self,
        store: &NativeStore,
        rebuild: bool,
    ) -> Result<ManagedCapture, Box<dyn std::error::Error>> {
        let instance = self.current(store)?;
        let requests = BTreeMap::new();
        let page = store.read_managed_tables_filtered(
            &instance.grant.selection.project(&requests)?,
            &ManagedRead {
                instance,
                expected: None,
                rebuild,
                follow: false,
                completed: None,
                execution: None,
                source: None,
            },
            araphor_data::AnalysisTableRead {
                requests: &requests,
                event_ranges: None,
                mode: araphor_data::AnalysisReadModeV1::Complete,
                now: 10,
            },
            Default::default(),
            &AnalysisReadControl::default(),
            None,
        )?;
        assert!(page.page.tables.is_empty());
        assert!(page.page.extraction.references.is_empty());
        Ok(page.state)
    }

    fn current(&self, store: &NativeStore) -> Result<ManagedInstance, Box<dyn std::error::Error>> {
        Ok(store
            .view()?
            .managed_instance(
                [1; 16],
                &self.instance.spec.id,
                &AnalysisReadControl::default(),
            )?
            .ok_or("instance")?)
    }

    fn batch(schema: &sdk::Schema, value: u64) -> sdk::Result<sdk::RecordBatch> {
        Ok(sdk::RecordBatch::try_new(
            Arc::new(schema.clone()),
            vec![Arc::new(UInt64Array::from(vec![value]))],
        )?)
    }

    fn evaluation(&self, request: &ManagedRequest, call: u64) -> sdk::Result<sdk::Evaluation> {
        let mut evaluation = sdk::Evaluation {
            export: "count".into(),
            inputs: vec![sdk::Input {
                data: sdk::Dataset {
                    name: "source".into(),
                    batches: vec![Self::batch(&self.model.inputs[0].port.schema, 1)?],
                },
                revision: sdk::Revision {
                    owner: "fixture".into(),
                    id: format!("source-{call}"),
                    window: None,
                },
                coverage: sdk::Coverage {
                    state: sdk::CoverageState::Complete,
                    limits: Vec::new(),
                },
            }],
            parameters: Some(Self::batch(
                &self.model.parameters,
                if call == 10 { 2 } else { 3 },
            )?),
            checkpoint: None,
            previous_outputs: Vec::new(),
            context: sdk::EvaluationContext {
                id: request.id.clone(),
                time_utc_ns: request.time_utc_ns as i64,
                seed: request.seed,
            },
        };
        if self.model.inputs.len() > 1 {
            evaluation.inputs.push(sdk::Input {
                data: sdk::Dataset {
                    name: "aux".into(),
                    batches: Vec::new(),
                },
                revision: sdk::Revision {
                    owner: "fixture".into(),
                    id: format!("aux-{call}"),
                    window: None,
                },
                coverage: sdk::Coverage {
                    state: sdk::CoverageState::Complete,
                    limits: Vec::new(),
                },
            });
        }
        Ok(evaluation)
    }

    fn output(&self, value: u64) -> sdk::Result<sdk::Output> {
        self.output_detail(value, "exact context")
    }

    fn output_detail(&self, value: u64, detail: &str) -> sdk::Result<sdk::Output> {
        let batch = Self::batch(&self.model.outputs[0].schema, value)?;
        Ok(sdk::Output {
            datasets: vec![sdk::Dataset {
                name: "rows".into(),
                batches: vec![batch.clone()],
            }],
            checkpoint: Some(sdk::Checkpoint {
                version: 1,
                datasets: vec![sdk::Dataset {
                    name: "state".into(),
                    batches: vec![batch],
                }],
            }),
            evidence: vec![sdk::EvidenceLink {
                output: sdk::RowRef {
                    dataset: "rows".into(),
                    row: 0,
                },
                input: sdk::RowRef {
                    dataset: "source".into(),
                    row: 0,
                },
            }],
            reasons: vec![sdk::ReasonValue {
                output: sdk::RowRef {
                    dataset: "rows".into(),
                    row: 0,
                },
                code: "managed-fixture.counted".into(),
                details: sdk::RecordBatch::try_new(
                    Arc::new(self.model.reasons[0].details.clone()),
                    vec![Arc::new(StringArray::from(vec![detail]))],
                )?,
            }],
        })
    }

    fn publish(
        &self,
        store: &NativeStore,
        attempt: &ManagedAttempt,
        evaluations: &[sdk::Evaluation],
        outputs: &[sdk::Output],
    ) -> Result<ManagedReceipt, Box<dyn std::error::Error>> {
        self.publish_checked(store, attempt, evaluations, outputs, || Ok(()))
            .map_err(Into::into)
    }

    fn publish_checked(
        &self,
        store: &NativeStore,
        attempt: &ManagedAttempt,
        evaluations: &[sdk::Evaluation],
        outputs: &[sdk::Output],
        check: impl FnOnce() -> araphor_data::Result<()>,
    ) -> araphor_data::Result<ManagedReceipt> {
        let returns = evaluations
            .iter()
            .zip(outputs)
            .enumerate()
            .map(|(index, (evaluation, output))| ManagedReturn {
                call: 10 + index as u64,
                evaluation,
                output,
                changes: None,
                graph: None,
                retained: None,
            })
            .collect::<Vec<_>>();
        let selected = sdk::Dataset {
            name: "selected".into(),
            batches: outputs[0].datasets[0].batches.clone(),
        };
        let control = AnalysisReadControl::default();
        let input = ManagedCommit {
            control: &control,
            budget: &super::graph::Budget,
            completed: true,
            attempt,
            now_utc_ns: 10,
            returns: &returns,
            selected: &selected,
            selected_schema: &self.model.outputs[0].schema,
        };
        store.commit_managed(store.prepare_managed(&input)?, check)
    }
}

fn request(name: &str) -> ManagedRequest {
    ManagedRequest {
        id: name.into(),
        time_utc_ns: 10,
        seed: Some(7),
        rebuild: false,
        witness_expiry: 100,
        frontier: None,
    }
}

fn records(
    view: &DataView,
    prefix: &[u8],
) -> Result<BTreeMap<Vec<u8>, Vec<u8>>, Box<dyn std::error::Error>> {
    view.snapshot()
        .prefix(prefix)
        .map(|entry| {
            let (key, bytes) = entry?;
            Ok((key.to_vec(), bytes.to_vec()))
        })
        .collect()
}

#[test]
fn managed_binary_envelopes() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = NativeStore::open(&directory.path().join("data"))?;
    let fixture = StorageFixture::new(&store, "counter", "Retain independent call state.".into())?;
    let view = store.view()?;
    #[derive(serde::Deserialize)]
    struct Version {
        spec: ManagedSpec,
        scope: AnalysisSelectionV1,
    }
    let versions = records(&view, b"\0data/Z")?;
    assert_eq!(versions.len(), 1);
    let version = versions.values().next().ok_or("version")?;
    assert_eq!(version[0], 0);
    let saved: Version = rmp_serde::from_slice(&version[1..])?;
    assert_eq!(saved.spec, fixture.instance.spec);
    assert_eq!(saved.scope, fixture.instance.grant.selection);
    assert!(serde_json::from_slice::<ManagedSpec>(&version[1..]).is_err());
    let instances = records(&view, b"\0data/J")?;
    assert_eq!(instances.len(), 1);
    let bytes = instances.values().next().ok_or("instance")?;
    let saved: Instance = rmp_serde::from_slice(&bytes[1..])?;
    assert_eq!(saved.tenant, fixture.instance.spec.tenant);
    assert_eq!(saved.id, fixture.instance.spec.id);
    assert_eq!(saved.grant, fixture.instance.grant);
    assert_eq!(
        (
            saved.generation,
            saved.progress,
            saved.running,
            saved.removed,
            saved.lifecycle
        ),
        (
            fixture.instance.generation,
            fixture.instance.progress,
            fixture.instance.running,
            fixture.instance.removed,
            fixture.instance.lifecycle
        )
    );
    assert_eq!(
        view.managed_version(
            [1; 16],
            &saved.id,
            saved.generation,
            &AnalysisReadControl::default()
        )?,
        fixture.instance.spec
    );
    let captured = fixture.capture(&store)?;
    let input = request("binary-attempt");
    let attempt = store.register_managed_attempt(&captured, &input, || Ok(()))?;
    let reloaded = store
        .managed_attempt(
            [1; 16],
            &fixture.instance.spec.id,
            &input.id,
            &AnalysisReadControl::default(),
        )?
        .ok_or("reloaded attempt")?;
    captured.check_current(&reloaded)?;
    #[derive(serde::Deserialize)]
    struct Capture {
        tenant: [u8; 16],
        instance: String,
        grant: PackageGrantV1,
        generation: u64,
        revision: u64,
    }
    #[derive(serde::Deserialize)]
    struct Attempt {
        request: ManagedRequest,
        capture: Capture,
        registered: u64,
        receipt: Option<ManagedReceipt>,
        terminal: Option<araphor_data::ManagedTerminal>,
    }
    let attempts = records(store.view()?.as_ref(), b"\0data/a")?;
    assert_eq!(attempts.len(), 1);
    let bytes = attempts.values().next().ok_or("attempt")?;
    let saved: Attempt = rmp_serde::from_slice(&bytes[1..])?;
    assert_eq!(&saved.request, attempt.request());
    assert_eq!(saved.request, input);
    assert_eq!(saved.capture.tenant, fixture.instance.spec.tenant);
    assert_eq!(saved.capture.instance, fixture.instance.spec.id);
    assert_eq!(saved.capture.grant, fixture.instance.grant);
    assert_eq!(saved.capture.generation, fixture.instance.generation);
    assert_eq!(saved.capture.revision, attempt.captured_revision());
    assert_eq!(saved.registered, store.view()?.revision());
    assert_eq!(saved.receipt.as_ref(), attempt.receipt());
    assert_eq!(saved.terminal.as_ref(), attempt.terminal());
    assert!(serde_json::from_slice::<ManagedRequest>(&bytes[1..]).is_err());
    Ok(())
}

#[derive(serde::Deserialize)]
struct Stored {
    id: String,
    revision: u64,
    body: Body,
}
#[derive(serde::Deserialize)]
enum Body {
    Call {
        instance: String,
        call: u64,
        attempt: String,
    },
    Selected {
        instance: String,
        attempt: String,
        rows: u64,
        dependencies: Vec<PackageResultRefV1>,
    },
}

fn verify_publication(store: &NativeStore, receipt: &ManagedReceipt) -> TestResult {
    let view = store.view()?;
    let results = records(&view, b"\0data/X")?;
    assert_eq!(results.len(), 3);
    let mut ids = BTreeMap::new();
    for (key, bytes) in results {
        assert_eq!(bytes[0], 0);
        let stored: Stored = rmp_serde::from_slice(&bytes[1..])?;
        assert_eq!(stored.revision, receipt.commit_revision);
        let id = u64::from_be_bytes(key[7..].try_into()?);
        match stored.body {
            Body::Call {
                instance,
                call,
                attempt,
            } => {
                assert_eq!(instance, receipt.instance);
                assert_eq!(attempt, receipt.attempt);
                assert_eq!(stored.id, receipt.results[&call].result_id);
                let key = [b"\0data/U".as_slice(), &id.to_be_bytes()].concat();
                let bytes = view.snapshot().get(key)?.ok_or("checkpoint")?;
                let checkpoint: Option<sdk::wire::Checkpoint> = rmp_serde::from_slice(&bytes[1..])?;
                assert!(checkpoint.is_some());
            }
            Body::Selected {
                instance,
                attempt,
                rows,
                dependencies,
            } => {
                assert_eq!(stored.id, receipt.selected.result_id);
                assert_eq!(instance, receipt.instance);
                assert_eq!(attempt, receipt.attempt);
                assert_eq!(rows, 1);
                assert_eq!(
                    dependencies,
                    receipt.results.values().cloned().collect::<Vec<_>>()
                );
            }
        }
        ids.insert(stored.id, id);
    }
    let prefix = b"\0data/ref/dependency/";
    let selected = ids[&receipt.selected.result_id];
    let expected = receipt
        .results
        .values()
        .map(|reference| {
            (
                [
                    prefix.as_slice(),
                    &selected.to_be_bytes(),
                    &ids[&reference.result_id].to_be_bytes(),
                ]
                .concat(),
                receipt.commit_revision.to_be_bytes().to_vec(),
            )
        })
        .collect::<BTreeMap<_, _>>();
    assert_eq!(records(&view, prefix)?, expected);
    let heads = call_heads(&view, &receipt.instance)?;
    assert_eq!(heads.len(), 2);
    for (key, bytes) in heads {
        let call = u64::from_be_bytes(key[key.len() - 8..].try_into()?);
        let head: CallHead = rmp_serde::from_slice(&bytes[1..])?;
        assert_eq!(head.revision, receipt.commit_revision);
        assert_eq!(
            head.result.as_deref(),
            Some(receipt.results[&call].result_id.as_str())
        );
    }
    assert!(records(&view, b"\0data/ref/raw/")?.is_empty());
    assert!(records(&view, b"\0data/ref/context/")?.is_empty());
    Ok(())
}

fn call_heads(
    view: &DataView,
    instance: &str,
) -> Result<BTreeMap<Vec<u8>, Vec<u8>>, Box<dyn std::error::Error>> {
    for (key, bytes) in records(view, b"\0data/J")? {
        let row: Instance = rmp_serde::from_slice(&bytes[1..])?;
        if row.id == instance {
            let prefix = [b"\0data/Q".as_slice(), &key[7..]].concat();
            return records(view, &prefix);
        }
    }
    Err("instance head owner absent".into())
}

#[test]
fn large_contract_preserves_bytes() -> TestResult {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("data");
    let store = NativeStore::open(&root)?;
    let _baseline =
        StorageFixture::new(&store, "counter", "Retain independent call state.".into())?;
    let fixture = StorageFixture::new(&store, "large-contract", "x".repeat(17 * 1024 * 1024))?;
    let spec = fixture.instance.spec.clone();
    #[derive(serde::Deserialize)]
    struct DefinitionRecord {
        tenant: [u8; 16],
        bytes: Vec<u8>,
        revision: u64,
    }
    let definitions = records(store.view()?.as_ref(), b"\0data/D")?;
    assert_eq!(definitions.len(), 2);
    let bytes = definitions
        .iter()
        .find(|(key, _)| key.ends_with(&spec.manifest.definition.to_be_bytes()))
        .map(|(_, bytes)| bytes)
        .ok_or("definition record")?;
    let definition: DefinitionRecord = rmp_serde::from_slice(&bytes[1..])?;
    assert_eq!(definition.tenant, [1; 16]);
    assert_eq!(definition.revision, spec.manifest.definition);
    assert_eq!(definition.bytes, spec.definition.encode()?);
    assert!(serde_json::from_slice::<ResolvedDefinition>(&definition.bytes).is_err());
    let captured = fixture.capture(&store)?;
    let input = request("large-publication");
    let attempt = store.register_managed_attempt(&captured, &input, || Ok(()))?;
    let evaluations = [
        fixture.evaluation(&input, 10)?,
        fixture.evaluation(&input, 11)?,
    ];
    let outputs = [
        fixture.output_detail(2, &"r".repeat(16 * 1024 * 1024 + 1))?,
        fixture.output_detail(3, "exact context")?,
    ];
    assert_eq!(
        outputs[0].reasons[0]
            .details
            .column(0)
            .as_any()
            .downcast_ref::<StringArray>()
            .ok_or("reason type")?
            .value(0)
            .len(),
        16 * 1024 * 1024 + 1
    );
    let held = store.view()?;
    let pending = records(&held, b"\0data/a")?;
    let heads = call_heads(&held, &spec.id)?;
    let initial_heads = heads
        .iter()
        .map(|(key, bytes)| {
            let call = u64::from_be_bytes(key[key.len() - 8..].try_into()?);
            let head: CallHead = rmp_serde::from_slice(&bytes[1..])?;
            Ok::<_, Box<dyn std::error::Error>>((call, (head.revision, head.result)))
        })
        .collect::<Result<BTreeMap<_, _>, _>>()?;
    assert_eq!(initial_heads, [(10, (0, None)), (11, (0, None))].into());
    assert!(store
        .managed_attempt(
            [1; 16],
            &spec.id,
            &input.id,
            &AnalysisReadControl::default()
        )?
        .ok_or("pending")?
        .receipt()
        .is_none());
    let before = store.meta()?;
    let cursor = store.database().inner().journal_head()?;
    let mut checked = false;
    let error = fixture
        .publish_checked(&store, &attempt, &evaluations, &outputs, || {
            checked = true;
            Err(Error::AnalysisReadDenied {
                location: snafu::location!(),
            })
        })
        .err()
        .ok_or("denied publication succeeded")?;
    assert!(checked);
    assert!(matches!(error, Error::AnalysisReadDenied { .. }));
    assert_eq!(store.meta()?, before);
    assert_eq!(store.database().inner().journal_head()?, cursor);
    assert_eq!(fixture.current(&store)?, fixture.instance);
    assert_eq!(records(store.view()?.as_ref(), b"\0data/a")?, pending);
    assert_eq!(call_heads(store.view()?.as_ref(), &spec.id)?, heads);
    assert!(records(store.view()?.as_ref(), b"\0data/X")?.is_empty());
    assert!(records(store.view()?.as_ref(), b"\0data/U")?.is_empty());
    let receipt = fixture.publish_checked(&store, &attempt, &evaluations, &outputs, || Ok(()))?;
    verify_publication(&store, &receipt)?;
    let committed = store.meta()?;
    let journal = store.database().inner().journal_head()?;
    assert_eq!(
        store
            .register_managed_attempt(&captured, &input, || Ok(()))?
            .receipt(),
        Some(&receipt)
    );
    assert_eq!(store.meta()?, committed);
    assert_eq!(store.database().inner().journal_head()?, journal);
    let backup = root.join("backups/large-managed");
    store.backup(&backup)?;
    drop((held, attempt, captured, store));
    let reopened = NativeStore::open(&root)?;
    let restored = NativeStore::restore(&backup, &directory.path().join("restored"))?;
    for store in [&reopened, &restored] {
        let retained = store
            .definition(
                [1; 16],
                &spec.definition.definition.name,
                Some(spec.manifest.definition),
                &AnalysisReadControl::default(),
            )?
            .ok_or("definition")?;
        assert_eq!(retained.1, spec.manifest.definition);
        assert_eq!(retained.0, spec.definition);
        assert_eq!(retained.0.definition.description.len(), 17 * 1024 * 1024);
        let current = fixture.current(store)?;
        assert_eq!(current.spec, spec);
        let prior = fixture.capture(store)?;
        for call in [10, 11] {
            let saved = store.managed_result(
                &current,
                &receipt.results[&call].result_id,
                10,
                &AnalysisReadControl::default(),
            )?;
            assert_eq!(saved.result, receipt.results[&call]);
            assert_eq!(saved.receipt, receipt);
            let checkpoint = prior
                .prior(call)
                .ok_or("prior call")?
                .checkpoint
                .as_ref()
                .ok_or("prior checkpoint")?;
            let expected = outputs[(call - 10) as usize]
                .checkpoint
                .as_ref()
                .ok_or("expected checkpoint")?;
            assert_eq!(checkpoint.version, expected.version);
            assert_eq!(checkpoint.datasets.len(), expected.datasets.len());
            assert_eq!(checkpoint.datasets[0].name, expected.datasets[0].name);
            assert_eq!(checkpoint.datasets[0].batches, expected.datasets[0].batches);
        }
        assert_eq!(
            store.managed_history(
                &current.grant.selection,
                &spec.id,
                &AnalysisReadControl::default()
            )?,
            [receipt.clone()]
        );
        let before = store.meta()?;
        assert!(store
            .register_managed_attempt(
                &ManagedCapture::from(
                    &store
                        .managed_attempt(
                            [1; 16],
                            &spec.id,
                            &input.id,
                            &AnalysisReadControl::default()
                        )?
                        .ok_or("saved attempt")?
                ),
                &input,
                || Err(Error::AnalysisReadDenied {
                    location: snafu::location!()
                })
            )
            .is_err());
        assert_eq!(store.meta()?, before);
        let attempt = store
            .managed_attempt(
                [1; 16],
                &spec.id,
                &input.id,
                &AnalysisReadControl::default(),
            )?
            .ok_or("saved attempt")?;
        assert_eq!(
            store
                .register_managed_attempt(&ManagedCapture::from(&attempt), &input, || Ok(()))?
                .receipt(),
            Some(&receipt)
        );
        assert_eq!(store.meta()?, before);
        let view = store.view()?;
        for _ in 0..65 {
            assert_eq!(
                store
                    .managed_result_at(
                        &view,
                        &current,
                        &receipt.results[&10].result_id,
                        10,
                        &AnalysisReadControl::default()
                    )?
                    .result,
                receipt.results[&10]
            );
        }
        let mut foreign = current;
        foreign.spec.tenant = [2; 16];
        foreign.grant.selection = AnalysisSelectionV1::tenant([2; 16]);
        assert!(store
            .managed_result_at(
                &view,
                &foreign,
                &receipt.results[&10].result_id,
                10,
                &AnalysisReadControl::default()
            )
            .is_err());
        verify_publication(store, &receipt)?;
    }
    Ok(())
}
