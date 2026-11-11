use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use araphor_analysis_sdk as sdk;
use araphor_discovery_definition::{Definition, ImagePin, Program, ResolvedDefinition, Source};

use snafu::ResultExt as _;

use super::codec::ManagedCodec;
use super::*;
use crate::analysis::{
    AnalysisExtractLimits, AnalysisReadModeV1, AnalysisSelectionV1, AnalysisTableRead,
    AnalysisTableRequests,
};
use crate::analysis::{AnalysisStore, ManagedCommit, ManagedReturn, PackageResultRefV1};
use crate::{
    AnalysisReadControl, PackageArtifactV1, PackageBundleV1, PackageGrantV1,
    PackageImplementationV1, SqlModelV1, SqlReasonV1,
};

mod changes;
mod destination;
mod execution;
mod guards;
mod health;
mod history;
mod input;
mod journal;
mod lifecycle;
mod memory;
mod metadata;
mod removal;
mod renewal;
mod replay;
mod retention;
mod source;
mod status;
mod version;

type TestResult<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

fn call_context(result: &crate::InstanceResultV1) -> TestResult<&crate::ResultContext> {
    let crate::InstanceResultKindV1::Call { context, .. } = &result.kind else {
        return Err("call reference kind".into());
    };
    Ok(context)
}

struct TestBudget;

impl ManagedBudget for TestBudget {
    fn limit(&self) -> usize {
        usize::MAX
    }
    fn check(&self) -> crate::Result<()> {
        Ok(())
    }
    fn reserve(&self, _bytes: usize) -> crate::Result<Box<dyn std::any::Any + Send + Sync>> {
        Ok(Box::new(()))
    }
}

struct Fixture {
    instance: ManagedInstance,
    model: sdk::Model,
}

#[derive(serde::Deserialize)]
struct Stored {
    id: String,
    revision: u64,
    body: Body,
}

#[derive(serde::Deserialize)]
enum Body {
    Call {},
    Selected { rows: u64 },
}

impl Fixture {
    fn commit(
        store: &AnalysisStore,
        input: &ManagedCommit<'_>,
        check: impl FnOnce() -> crate::Result<()>,
    ) -> crate::Result<ManagedReceipt> {
        let prepared = store.prepare_managed(input)?;
        store.commit_managed(prepared, check)
    }

    fn receipt(
        store: &AnalysisStore,
        tenant: [u8; 16],
        instance: &str,
        attempt: &str,
        control: &AnalysisReadControl,
    ) -> crate::Result<Option<ManagedReceipt>> {
        Ok(store
            .managed_attempt(tenant, instance, attempt, control)?
            .and_then(|attempt| attempt.receipt().cloned()))
    }

    fn checkpoint(
        &self,
        store: &AnalysisStore,
        reference: &PackageResultRefV1,
    ) -> TestResult<sdk::Checkpoint> {
        let view = store.view()?;
        for entry in view.snapshot().prefix(b"\0data/X") {
            let (key, bytes) = entry?;
            if key.len() != 15 {
                continue;
            }
            assert_eq!(bytes.first(), Some(&0));
            let stored: Stored = rmp_serde::from_slice(&bytes[1..])?;
            if stored.id == reference.result_id {
                assert_eq!(stored.revision, reference.commit_revision);
                assert!(matches!(stored.body, Body::Call { .. }));
                let key = [b"\0data/U".as_slice(), &key[7..]].concat();
                let bytes = view.snapshot().get(key)?.ok_or("checkpoint")?;
                assert_eq!(bytes.first(), Some(&0));
                let wire: Option<sdk::wire::Checkpoint> = rmp_serde::from_slice(&bytes[1..])?;
                return Ok(wire.ok_or("checkpoint")?.decode_model(&self.model)?);
            }
        }
        Err("checkpoint result".into())
    }

    fn rows(store: &AnalysisStore, reference: &PackageResultRefV1) -> TestResult<u64> {
        for entry in store.view()?.snapshot().prefix(b"\0data/X") {
            let (key, bytes) = entry?;
            if key.len() != 15 {
                continue;
            }
            assert_eq!(bytes.first(), Some(&0));
            let stored: Stored = rmp_serde::from_slice(&bytes[1..])?;
            if stored.id == reference.result_id {
                assert_eq!(stored.revision, reference.commit_revision);
                let Body::Selected { rows } = stored.body else {
                    return Err("selected result kind".into());
                };
                return Ok(rows);
            }
        }
        Err("selected result".into())
    }

    fn current(&self, store: &AnalysisStore) -> TestResult<ManagedInstance> {
        store
            .managed_instance(
                self.instance.spec.tenant,
                &self.instance.spec.id,
                &AnalysisReadControl::default(),
            )?
            .ok_or_else(|| "managed instance absent".into())
    }

    fn admit(store: &AnalysisStore) -> TestResult<Self> {
        Self::admit_inputs(store, false)
    }

    fn admit_inputs(store: &AnalysisStore, extra: bool) -> TestResult<Self> {
        Self::admit_scope(store, extra, AnalysisSelectionV1::new([1; 16], Vec::new()))
    }

    fn admit_scope(
        store: &AnalysisStore,
        extra: bool,
        selection: AnalysisSelectionV1,
    ) -> TestResult<Self> {
        Self::admit_model(store, extra, selection, false)
    }

    fn admit_model(
        store: &AnalysisStore,
        extra: bool,
        selection: AnalysisSelectionV1,
        continuation: bool,
    ) -> TestResult<Self> {
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
            resume_input_changes: continuation,
            version: 1,
            datasets: vec![sdk::Port::new("state", scalar.clone())],
        });
        model.reasons.push(sdk::Reason {
            code: "managed-fixture.counted".into(),
            details: sdk::Schema::new(vec![sdk::Field::new("detail", sdk::DataType::Utf8, false)]),
        });
        let artifact = PackageArtifactV1 {
            descriptor: sdk::Package::new("managed-fixture", "r1", vec![model.clone()]),
            implementations: vec![PackageImplementationV1::Sql { export: "count".into(), program: SqlModelV1 {
                outputs: BTreeMap::from([("rows".into(), "SELECT value FROM source".into())]),
                checkpoint: BTreeMap::from([("state".into(), "SELECT value FROM source".into())]),
                evidence: Some("SELECT 'rows' AS output_dataset, 0::BIGINT UNSIGNED AS output_row, 'source' AS input_dataset, 0::BIGINT UNSIGNED AS input_row".into()),
                reasons: vec![SqlReasonV1 { output: "rows".into(), code: "managed-fixture.counted".into(), sql: "SELECT 0::BIGINT UNSIGNED AS output_row, 'exact context' AS detail".into() }],
            }}], fixtures: Vec::new(),
        };
        let image = PackageBundleV1 {
            schema_version: 1,
            root: artifact.reference(),
            artifacts: vec![artifact],
        };
        let image = crate::PackageBundle::try_from(image)?;
        store.install_package_image([1; 16], &image, || Ok(()))?;
        let pin = ImagePin {
            image: image.bundle().root.clone(),
            digest: image.digest().into(),
        };
        let sql = "SELECT * FROM \"managed-fixture\".\"r1\".count(source => (SELECT 1::BIGINT UNSIGNED AS value), increment => 2) a CROSS JOIN \"managed-fixture\".\"r1\".count(source => (SELECT 1::BIGINT UNSIGNED AS value), increment => 3) b".to_owned();
        let sql = if extra {
            sql.replace(
                "), increment",
                "), aux => (SELECT 0::BIGINT UNSIGNED AS value WHERE false), increment",
            )
        } else {
            sql
        };
        let definition = ResolvedDefinition::new(
            Definition {
                name: "independent-calls".into(),
                description: "Retain independent call state.".into(),
                labels: BTreeMap::new(),
                program: Program::Sql {
                    source: Source::Inline {
                        inline: sql.clone(),
                    },
                },
            },
            sql,
            vec![pin.clone()],
        )?;
        let revision = store.admit_definition([1; 16], &definition, || Ok(()))?;
        let grant = PackageGrantV1 {
            principal: "fixture".into(),
            revision: 1,
            selection: selection.clone(),
            expires_utc_ns: None,
            authorization_id: Some("definition-grant".into()),
        };
        let auxiliary = if extra {
            ", aux => (SELECT 0::BIGINT UNSIGNED AS value WHERE false)"
        } else {
            ""
        };
        let spec = ManagedSpec { destination: crate::ManagedDestination::Selected, tenant: [1; 16], id: "counter".into(), manifest: ManagedManifest {
            format: 1, planner: "datafusion-53/sql-call-1".into(), definition: revision, selected_schema: model.outputs[0].schema.clone(), calls: [(10, 2), (11, 3)].into_iter().map(|(id, increment)| (id, ManagedCall {
                image: pin.clone(), package: image.bundle().root.clone(), export: "count".into(), target: "sql".into(), artifact: None, arguments: vec![format!("source => (SELECT 1::BIGINT UNSIGNED AS value){auxiliary}, increment => {increment}")], dependencies: BTreeSet::new(),
            })).collect(),
        }, definition };
        let instance = store.admit_managed(&spec, &grant, || Ok(()))?;
        Ok(Self { instance, model })
    }

    fn capture(&self, store: &AnalysisStore, rebuild: bool) -> TestResult<ManagedCapture> {
        self.capture_execution(store, rebuild, None)
    }

    fn capture_execution(
        &self,
        store: &AnalysisStore,
        rebuild: bool,
        execution: Option<Arc<ManagedExecution>>,
    ) -> TestResult<ManagedCapture> {
        let instance = store
            .managed_instance(
                [1; 16],
                &self.instance.spec.id,
                &AnalysisReadControl::default(),
            )?
            .ok_or("instance absent")?;
        let requests = AnalysisTableRequests::new();
        let page = store.read_managed_tables_filtered(
            &instance.grant.selection.project(&requests)?,
            &ManagedRead {
                source: None,
                execution,
                follow: false,
                expected: None,
                instance: instance.clone(),
                rebuild,
                completed: None,
            },
            AnalysisTableRead {
                requests: &requests,
                event_ranges: None,
                mode: AnalysisReadModeV1::Complete,
                now: 10,
            },
            AnalysisExtractLimits::default(),
            &AnalysisReadControl::default(),
            None,
        )?;
        assert!(page.page.tables.is_empty());
        assert!(page.page.extraction.references.is_empty());
        Ok(page.state)
    }

    fn evaluation(
        &self,
        request: &ManagedRequest,
        call: u64,
        captured: Option<&ManagedCapture>,
    ) -> TestResult<sdk::Evaluation> {
        let input = sdk::Input {
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
        };
        let parameters = Self::batch(&self.model.parameters, if call == 10 { 2 } else { 3 })?;
        let mut inputs = vec![input];
        if self.model.inputs.len() > 1 {
            inputs.push(sdk::Input {
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
        let (checkpoint, previous_outputs) = captured
            .and_then(|capture| capture.prior(call))
            .map(|prior| prior.state(&self.model, &inputs, Some(&parameters), request.rebuild))
            .transpose()?
            .unwrap_or_default();
        Ok(sdk::Evaluation {
            export: "count".into(),
            inputs,
            parameters: Some(parameters),
            checkpoint,
            previous_outputs,
            context: sdk::EvaluationContext {
                id: request.id.clone(),
                time_utc_ns: request.time_utc_ns as i64,
                seed: request.seed,
            },
        })
    }

    fn batch(schema: &sdk::Schema, value: u64) -> TestResult<sdk::RecordBatch> {
        Ok(sdk::RecordBatch::try_new(
            Arc::new(schema.clone()),
            vec![Arc::new(sdk::arrow_array::UInt64Array::from(vec![value]))],
        )?)
    }

    fn output(&self, value: u64) -> TestResult<sdk::Output> {
        let batch = Self::batch(&self.model.outputs[0].schema, value)?;
        Ok(sdk::Output {
            datasets: vec![sdk::Dataset {
                name: "rows".into(),
                batches: vec![batch.clone()],
            }],
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
                    vec![Arc::new(sdk::arrow_array::StringArray::from(vec![
                        "exact context",
                    ]))],
                )?,
            }],
            checkpoint: Some(sdk::Checkpoint {
                version: 1,
                datasets: vec![sdk::Dataset {
                    name: "state".into(),
                    batches: vec![batch],
                }],
            }),
        })
    }

    fn publish(
        &self,
        store: &AnalysisStore,
        attempt: &ManagedAttempt,
        evaluations: &[sdk::Evaluation],
        outputs: &[sdk::Output],
    ) -> TestResult<ManagedReceipt> {
        self.publish_checked(store, attempt, evaluations, outputs, || Ok(()))
    }

    fn publish_checked(
        &self,
        store: &AnalysisStore,
        attempt: &ManagedAttempt,
        evaluations: &[sdk::Evaluation],
        outputs: &[sdk::Output],
        check: impl FnOnce() -> crate::Result<()>,
    ) -> TestResult<ManagedReceipt> {
        let returns = evaluations
            .iter()
            .zip(outputs)
            .enumerate()
            .map(|(index, (evaluation, output))| ManagedReturn {
                graph: None,
                retained: None,
                changes: None,
                call: 10 + index as u64,
                evaluation,
                output,
            })
            .collect::<Vec<_>>();
        let selected = sdk::Dataset {
            name: "selected".into(),
            batches: outputs[0].datasets[0].batches.clone(),
        };
        Ok(Fixture::commit(
            &store,
            &ManagedCommit {
                control: &crate::AnalysisReadControl::default(),
                budget: &crate::analysis::managed::tests::TestBudget,
                completed: true,
                attempt,
                now_utc_ns: 10,
                returns: &returns,
                selected: &selected,
                selected_schema: &self.model.outputs[0].schema,
            },
            check,
        )?)
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

#[test]
fn managed_sql_checks_authority() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = AnalysisStore::open(directory.path().join("store"))?;
    let sql = "SELECT 1::BIGINT UNSIGNED AS value";
    let definition = ResolvedDefinition::new(
        Definition {
            name: "pure".into(),
            description: String::new(),
            labels: BTreeMap::new(),
            program: Program::Sql {
                source: Source::Inline { inline: sql.into() },
            },
        },
        sql.into(),
        Vec::new(),
    )?;
    let revision = store.admit_definition([1; 16], &definition, || Ok(()))?;
    let grant = PackageGrantV1 {
        principal: "fixture".into(),
        revision: 1,
        selection: AnalysisSelectionV1::new([1; 16], Vec::new()),
        expires_utc_ns: None,
        authorization_id: Some("definition-grant".into()),
    };
    let spec = ManagedSpec {
        destination: crate::ManagedDestination::Selected,
        tenant: [1; 16],
        id: "pure".into(),
        manifest: ManagedManifest {
            format: 1,
            planner: "datafusion-53/sql-call-1".into(),
            definition: revision,
            calls: BTreeMap::new(),
            selected_schema: sdk::Schema::new(vec![sdk::Field::new(
                "value",
                sdk::DataType::UInt64,
                false,
            )]),
        },
        definition,
    };
    let before = store.meta()?;
    let mut checked = 0;
    assert!(store
        .admit_managed(&spec, &grant, || {
            checked += 1;
            crate::AnalysisReadDeniedSnafu.fail()
        })
        .is_err());
    assert_eq!(store.meta()?, before);
    let instance = store.admit_managed(&spec, &grant, || {
        checked += 1;
        Ok(())
    })?;
    let requests = AnalysisTableRequests::new();
    let captured = store
        .read_managed_tables_filtered(
            &grant.selection,
            &ManagedRead {
                source: None,
                execution: None,
                follow: false,
                expected: None,
                instance,
                rebuild: false,
                completed: None,
            },
            AnalysisTableRead {
                requests: &requests,
                event_ranges: None,
                mode: AnalysisReadModeV1::Complete,
                now: 10,
            },
            AnalysisExtractLimits::default(),
            &AnalysisReadControl::default(),
            None,
        )?
        .state;
    let input = request("pure-step");
    let attempt = store.register_managed_attempt(&captured, &input, || {
        checked += 1;
        Ok(())
    })?;
    let schema = sdk::Schema::new(vec![sdk::Field::new("value", sdk::DataType::UInt64, false)]);
    let selected = sdk::Dataset {
        name: "selected".into(),
        batches: vec![Fixture::batch(&schema, 1)?],
    };
    let commit = ManagedCommit {
        control: &crate::AnalysisReadControl::default(),
        budget: &crate::analysis::managed::tests::TestBudget,
        completed: true,
        now_utc_ns: 10,
        attempt: &attempt,
        returns: &[],
        selected: &selected,
        selected_schema: &schema,
    };
    let before = store.meta()?;
    assert!(Fixture::commit(&store, &commit, || {
        checked += 1;
        crate::AnalysisReadDeniedSnafu.fail()
    })
    .is_err());
    assert_eq!(store.meta()?, before);
    let receipt = Fixture::commit(&store, &commit, || {
        checked += 1;
        Ok(())
    })?;
    assert!(receipt.results.is_empty());
    assert_eq!(checked, 5);
    let saved = Fixture::receipt(
        &store,
        [1; 16],
        &spec.id,
        &input.id,
        &AnalysisReadControl::default(),
    )?
    .ok_or("pure selected receipt")?;
    assert_eq!(saved, receipt);
    assert_eq!(Fixture::rows(&store, &saved.selected)?, selected.rows());
    Ok(())
}

#[test]
fn managed_recovery_checks_references() -> TestResult {
    for corruption in ["body", "checkpoint", "edge", "context"] {
        let directory = tempfile::tempdir()?;
        let root = directory.path().join("store");
        let store = AnalysisStore::open(&root)?;
        let fixture = Fixture::admit(&store)?;
        let capture = fixture.capture(&store, false)?;
        let input = request("corrupt");
        let attempt = store.register_managed_attempt(&capture, &input, || Ok(()))?;
        let eval = [
            fixture.evaluation(&input, 10, None)?,
            fixture.evaluation(&input, 11, None)?,
        ];
        let receipt = fixture.publish(
            &store,
            &attempt,
            &eval,
            &[fixture.output(2)?, fixture.output(3)?],
        )?;
        let id = &receipt.results[&10].result_id;
        {
            let mut guard = store.writer()?;
            let writer = guard.get_mut()?;
            if corruption == "body" {
                assert_eq!(
                    writer.execute(
                        "UPDATE analysis_results SET body = X'00' WHERE result_id = ?",
                        params![id]
                    )?,
                    1
                );
            } else if corruption == "edge" {
                assert_eq!(
                    writer.execute(
                        "DELETE FROM managed_edges WHERE result_id = ?",
                        params![receipt.selected.result_id]
                    )?,
                    2
                );
            } else if corruption == "checkpoint" {
                let (_, mut state, _) = AnalysisStore::managed_state_from(writer, [1; 16], id)?;
                state.as_mut().ok_or("checkpoint")?.version += 1;
                assert_eq!(
                    writer.execute(
                        "UPDATE analysis_results SET body = ? WHERE result_id = ?",
                        params![ManagedCodec::encode(&state)?, id]
                    )?,
                    1
                );
            } else {
                let bytes: Vec<u8> = writer.query_row(
                    "SELECT request_meta FROM analysis_results WHERE result_id = ?",
                    params![id],
                    |row| row.get(0),
                )?;
                let mut record: model::Record = ManagedCodec::decode(&bytes)?;
                record.context.target = "wasm32-wasip2".into();
                assert_eq!(
                    writer.execute(
                        "UPDATE analysis_results SET request_meta = ? WHERE result_id = ?",
                        params![ManagedCodec::encode(&record)?, id]
                    )?,
                    1
                );
            }
        }
        if matches!(corruption, "body" | "checkpoint") {
            assert!(fixture.capture(&store, false).is_err(), "{corruption}");
        } else {
            let reference = if corruption == "edge" {
                &receipt.selected
            } else {
                &receipt.results[&10]
            };
            assert!(
                store
                    .managed_result(
                        &fixture.instance,
                        &reference.result_id,
                        10,
                        &AnalysisReadControl::default()
                    )
                    .is_err(),
                "{corruption}"
            );
        }
        drop(store);
        assert!(AnalysisStore::open(&root).is_err(), "{corruption}");
    }
    Ok(())
}

#[test]
fn managed_commit_crashes() -> TestResult {
    if let Some(root) = std::env::var_os("ARAPHOR_MANAGED_ROOT") {
        let store = AnalysisStore::open(std::path::PathBuf::from(root))?;
        let fixture = Fixture::admit(&store)?;
        let upgrade = std::env::var("ARAPHOR_MANAGED_UPGRADE")? == "true";
        let capture = if upgrade {
            let current = fixture.current(&store)?;
            let spec = version::target(&store, &current, "Prepare the crash version.")?;
            let target = store.prepare_managed_version(&current, &spec, || Ok(()))?;
            version::capture(&store, &current, &target, false)?
        } else {
            fixture.capture(&store, false)?
        };
        let input = request("crash");
        let attempt = store.register_managed_attempt(&capture, &input, || Ok(()))?;
        let eval = [
            fixture.evaluation(&input, 10, Some(&capture))?,
            fixture.evaluation(&input, 11, Some(&capture))?,
        ];
        if upgrade {
            for (evaluation, value) in eval.iter().zip([12, 103]) {
                assert_eq!(
                    evaluation
                        .checkpoint
                        .as_ref()
                        .ok_or("old checkpoint absent")?
                        .datasets[0]
                        .batches,
                    fixture
                        .output(value)?
                        .checkpoint
                        .ok_or("expected old checkpoint absent")?
                        .datasets[0]
                        .batches,
                );
            }
        }
        let outputs = [fixture.output(2)?, fixture.output(3)?];
        fixture.publish(&store, &attempt, &eval, &outputs)?;
        return Err("the requested managed crash did not occur".into());
    }
    let heads = |store: &AnalysisStore| {
        store.read_snapshot(|reader| {
            let mut statement = reader.prepare(
                "SELECT call_id, state_revision, result_id FROM managed_calls WHERE tenant_id = ? AND instance_id = 'counter' ORDER BY call_id",
            ).context(crate::AnalysisDatabaseSnafu { operation: "prepare crash call heads" })?;
            let rows = statement.query_map(params![[1u8; 16].as_slice()], |row| {
                Ok((row.get::<_, u64>(0)?, row.get::<_, u64>(1)?, row.get::<_, Option<String>>(2)?))
            }).context(crate::AnalysisDatabaseSnafu { operation: "read crash call heads" })?
                .collect::<duckdb::Result<Vec<_>>>()
                .context(crate::AnalysisDatabaseSnafu { operation: "decode crash call heads" })?;
            Ok(rows)
        })
    };
    let rows = |store: &AnalysisStore| {
        store.read_snapshot(|reader| {
            let mut statement = reader.prepare("SELECT result_id, processor_id, commit_revision, body, request_meta FROM analysis_results ORDER BY result_id")
                .context(crate::AnalysisDatabaseSnafu { operation: "prepare crash canonical rows" })?;
            statement.query_map([], |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, u64>(2)?, row.get::<_, Vec<u8>>(3)?, row.get::<_, Vec<u8>>(4)?)))
                .context(crate::AnalysisDatabaseSnafu { operation: "read crash canonical rows" })?
                .collect::<duckdb::Result<Vec<_>>>()
                .context(crate::AnalysisDatabaseSnafu { operation: "decode crash canonical rows" })
        })
    };
    for upgrade in [false, true] {
        for point in ["managed.before", "managed.after"] {
            let directory = tempfile::tempdir()?;
            let root = directory.path().join("store");
            let store = AnalysisStore::open(&root)?;
            let fixture = Fixture::admit(&store)?;
            let original = if upgrade {
                let capture = fixture.capture(&store, false)?;
                let input = request("original");
                let attempt = store.register_managed_attempt(&capture, &input, || Ok(()))?;
                let eval = [
                    fixture.evaluation(&input, 10, Some(&capture))?,
                    fixture.evaluation(&input, 11, Some(&capture))?,
                ];
                Some(fixture.publish(
                    &store,
                    &attempt,
                    &eval,
                    &[fixture.output(12)?, fixture.output(103)?],
                )?)
            } else {
                None
            };
            let prior = fixture.current(&store)?;
            let target = if upgrade {
                let spec = version::target(&store, &prior, "Prepare the crash version.")?;
                Some(store.prepare_managed_version(&prior, &spec, || Ok(()))?)
            } else {
                None
            };
            assert_eq!(fixture.current(&store)?, prior);
            let prior_heads = heads(&store)?;
            let prior_rows = rows(&store)?;
            drop(store);
            let status = std::process::Command::new(std::env::current_exe()?)
                .args([
                    "--exact",
                    "analysis::managed::tests::managed_commit_crashes",
                ])
                .env("ARAPHOR_MANAGED_ROOT", &root)
                .env("ARAPHOR_MANAGED_UPGRADE", upgrade.to_string())
                .env("ARAPHOR_CRASH_ROOT", &root)
                .env("ARAPHOR_CRASH_POINT", point)
                .status()?;
            assert_eq!(status.code(), Some(73), "{point}, upgrade={upgrade}");
            let store = AnalysisStore::open(&root)?;
            let control = AnalysisReadControl::default();
            let pending = store
                .managed_attempt([1; 16], "counter", "crash", &control)?
                .ok_or("crash attempt absent")?;
            assert!(pending.terminal().is_none());
            if let Some(target) = &target {
                assert_eq!(pending.instance().generation, target.generation);
                assert_eq!(pending.instance().spec, target.spec);
                assert_eq!(
                    store.managed_version([1; 16], "counter", target.generation, &control)?,
                    target.spec
                );
            }
            let current = fixture.current(&store)?;
            let captured = fixture.capture(&store, false)?;
            let retained_rows = rows(&store)?;
            if point == "managed.after" {
                let receipt = pending.receipt().ok_or("committed receipt absent")?.clone();
                assert_eq!(pending.receipt(), Some(&receipt));
                assert_eq!(receipt.results.len(), 2);
                assert_eq!(receipt.selected.commit_revision, receipt.commit_revision);
                assert_eq!(current.progress, receipt.commit_revision);
                assert_eq!(captured.instance().progress, receipt.commit_revision);
                assert_eq!(
                    current.generation,
                    target
                        .as_ref()
                        .map_or(prior.generation, |target| target.generation)
                );
                assert_eq!(
                    &current.spec,
                    target.as_ref().map_or(&prior.spec, |target| &target.spec)
                );
                assert_eq!(
                    current.lifecycle,
                    if upgrade {
                        receipt.commit_revision
                    } else {
                        prior.lifecycle
                    }
                );
                let expected_heads = receipt
                    .results
                    .iter()
                    .map(|(call, reference)| {
                        (
                            *call,
                            reference.commit_revision,
                            Some(reference.result_id.clone()),
                        )
                    })
                    .collect::<Vec<_>>();
                assert_eq!(heads(&store)?, expected_heads);
                let mut expected_shapes = Vec::new();
                for (call, value) in [(10, 2), (11, 3)] {
                    let reference = &receipt.results[&call];
                    assert_eq!(reference.commit_revision, receipt.commit_revision);
                    let saved = captured.prior(call).ok_or("new checkpoint absent")?;
                    assert_eq!(saved.result, reference.result_id);
                    assert_eq!(saved.revision, reference.commit_revision);
                    assert_eq!(
                        saved
                            .checkpoint
                            .as_ref()
                            .ok_or("new state absent")?
                            .datasets[0]
                            .batches,
                        fixture
                            .output(value)?
                            .checkpoint
                            .ok_or("expected new state absent")?
                            .datasets[0]
                            .batches,
                    );
                    let result =
                        store.managed_result(&current, &reference.result_id, 10, &control)?;
                    assert!(result.current);
                    assert_eq!(result.result, *reference);
                    assert_eq!(result.receipt, receipt);
                    let expected = fixture.evaluation(&request("crash"), call, None)?;
                    assert_eq!(call_context(&result)?.context, expected.context);
                    assert!(call_context(&result)?.matches(&expected.inputs));
                    assert_eq!(
                        result.prior.get(&call).and_then(Option::as_ref),
                        original.as_ref().map(|receipt| &receipt.results[&call])
                    );
                    expected_shapes.push((
                        reference.result_id.clone(),
                        "managed-package-v1".to_owned(),
                        receipt.commit_revision,
                    ));
                }
                expected_shapes.push((
                    receipt.selected.result_id.clone(),
                    "managed-definition-v1".into(),
                    receipt.commit_revision,
                ));
                expected_shapes.sort();
                let original_ids = prior_rows
                    .iter()
                    .map(|row| row.0.as_str())
                    .collect::<BTreeSet<_>>();
                let original_rows = retained_rows
                    .iter()
                    .filter(|row| original_ids.contains(row.0.as_str()))
                    .cloned()
                    .collect::<Vec<_>>();
                assert_eq!(original_rows, prior_rows);
                let new_rows = retained_rows
                    .iter()
                    .filter(|row| !original_ids.contains(row.0.as_str()))
                    .collect::<Vec<_>>();
                assert!(new_rows
                    .iter()
                    .all(|row| !row.3.is_empty() && !row.4.is_empty()));
                let shapes = new_rows
                    .iter()
                    .map(|row| (row.0.clone(), row.1.clone(), row.2))
                    .collect::<Vec<_>>();
                assert_eq!(shapes, expected_shapes);
                assert_eq!(
                    Fixture::receipt(&store, [1; 16], "counter", "crash", &control)?,
                    Some(receipt.clone())
                );
                assert_eq!(Fixture::rows(&store, &receipt.selected)?, 1);
                let mut history = original.iter().cloned().collect::<Vec<_>>();
                history.push(receipt);
                assert_eq!(
                    store.managed_history(&current.grant.selection, "counter", &control)?,
                    history
                );
            } else {
                assert!(pending.receipt().is_none());
                assert_eq!(current, prior);
                assert_eq!(heads(&store)?, prior_heads);
                assert_eq!(retained_rows, prior_rows);
                assert!(Fixture::receipt(&store, [1; 16], "counter", "crash", &control)?.is_none());
                assert_eq!(
                    store.managed_history(&current.grant.selection, "counter", &control)?,
                    original.iter().cloned().collect::<Vec<_>>()
                );
                for (call, value) in [(10, 12), (11, 103)] {
                    if let Some(original) = &original {
                        let saved = captured.prior(call).ok_or("original checkpoint absent")?;
                        assert_eq!(saved.result, original.results[&call].result_id);
                        assert_eq!(saved.revision, original.results[&call].commit_revision);
                        assert_eq!(
                            saved
                                .checkpoint
                                .as_ref()
                                .ok_or("original state absent")?
                                .datasets[0]
                                .batches,
                            fixture
                                .output(value)?
                                .checkpoint
                                .ok_or("expected original state absent")?
                                .datasets[0]
                                .batches
                        );
                    } else {
                        assert!(captured.prior(call).is_none());
                    }
                }
            }
            if let Some(original) = &original {
                let retained = store
                    .managed_attempt([1; 16], "counter", "original", &control)?
                    .ok_or("original receipt absent")?;
                assert_eq!(retained.receipt(), Some(original));
                for (call, value) in [(10, 12), (11, 103)] {
                    let result = store.managed_result(
                        &current,
                        &original.results[&call].result_id,
                        10,
                        &control,
                    )?;
                    assert_eq!(result.result, original.results[&call]);
                    assert_eq!(result.receipt, *original);
                    assert_eq!(
                        fixture.checkpoint(&store, &result.result)?.datasets[0].batches,
                        fixture
                            .output(value)?
                            .checkpoint
                            .ok_or("original checkpoint")?
                            .datasets[0]
                            .batches
                    );
                    assert_eq!(result.current, point == "managed.before");
                }
                assert_eq!(
                    Fixture::receipt(&store, [1; 16], "counter", "original", &control)?,
                    Some(original.clone())
                );
                assert_eq!(Fixture::rows(&store, &original.selected)?, 1);
            }
            if point == "managed.before" && !upgrade {
                assert!(captured.prior(10).is_none());
                assert!(captured.prior(11).is_none());
                assert_eq!(captured.instance().progress, 0);
                let input = request("recovered");
                let attempt = store.register_managed_attempt(&captured, &input, || Ok(()))?;
                let eval = [
                    fixture.evaluation(&input, 10, None)?,
                    fixture.evaluation(&input, 11, None)?,
                ];
                let outputs = [fixture.output(2)?, fixture.output(3)?];
                fixture.publish(&store, &attempt, &eval, &outputs)?;
            }
        }
    }
    Ok(())
}

#[test]
fn managed_native_selected_roundtrip() -> TestResult {
    use sdk::arrow_array::builder::{MapBuilder, StringBuilder, UInt64Builder};
    use sdk::arrow_array::types::Int8Type;
    use sdk::arrow_array::{DictionaryArray, Int8Array, StringArray};

    let directory = tempfile::tempdir()?;
    let root = directory.path().join("store");
    let store = AnalysisStore::open(&root)?;
    let sql = "SELECT 1";
    let definition = ResolvedDefinition::new(
        Definition {
            name: "native-selected".into(),
            description: String::new(),
            labels: BTreeMap::new(),
            program: Program::Sql {
                source: Source::Inline { inline: sql.into() },
            },
        },
        sql.into(),
        Vec::new(),
    )?;
    let revision = store.admit_definition([1; 16], &definition, || Ok(()))?;
    let grant = PackageGrantV1 {
        principal: "fixture".into(),
        revision: 1,
        selection: AnalysisSelectionV1::new([1; 16], Vec::new()),
        expires_utc_ns: None,
        authorization_id: Some("definition-grant".into()),
    };
    let dictionary = DictionaryArray::<Int8Type>::try_new(
        Int8Array::from(vec![0, 1, 0]),
        Arc::new(StringArray::from(vec!["one", "two"])),
    )?;
    let dictionary = sdk::RecordBatch::try_from_iter([(
        "value",
        Arc::new(dictionary) as sdk::arrow_array::ArrayRef,
    )])?;
    let empty = sdk::RecordBatch::try_new_with_options(
        Arc::new(sdk::Schema::empty()),
        Vec::new(),
        &sdk::arrow_array::RecordBatchOptions::new().with_row_count(Some(17)),
    )?;
    let mut builder = MapBuilder::new(None, StringBuilder::new(), UInt64Builder::new());
    builder.keys().append_value("key");
    builder.values().append_value(1);
    builder.append(true)?;
    let map = sdk::RecordBatch::try_from_iter([(
        "value",
        Arc::new(builder.finish()) as sdk::arrow_array::ArrayRef,
    )])?;
    let scalar_schema =
        sdk::Schema::new(vec![sdk::Field::new("value", sdk::DataType::UInt64, false)]);
    let scalar = Fixture::batch(&scalar_schema, 1)?;
    let mut receipts = Vec::new();
    for (index, batch) in [dictionary, map, empty, scalar].into_iter().enumerate() {
        let spec = ManagedSpec {
            destination: crate::ManagedDestination::Selected,
            tenant: [1; 16],
            id: format!("native-selected-{index}"),
            manifest: ManagedManifest {
                format: 1,
                planner: "datafusion-53/sql-call-1".into(),
                definition: revision,
                calls: BTreeMap::new(),
                selected_schema: batch.schema_ref().as_ref().clone(),
            },
            definition: definition.clone(),
        };
        store.admit_managed(&spec, &grant, || Ok(()))?;
        let selected = sdk::Dataset {
            name: "selected".into(),
            batches: vec![batch.clone()],
        };
        let instance = store
            .managed_instance([1; 16], &spec.id, &AnalysisReadControl::default())?
            .ok_or("native instance absent")?;
        let requests = AnalysisTableRequests::new();
        let capture = store
            .read_managed_tables_filtered(
                &grant.selection,
                &ManagedRead {
                    source: None,
                    execution: None,
                    follow: false,
                    expected: None,
                    instance,
                    rebuild: false,
                    completed: None,
                },
                AnalysisTableRead {
                    requests: &requests,
                    event_ranges: None,
                    mode: AnalysisReadModeV1::Complete,
                    now: 10,
                },
                AnalysisExtractLimits::default(),
                &AnalysisReadControl::default(),
                None,
            )?
            .state;
        let input = request(&format!("native-{index}"));
        let attempt = store.register_managed_attempt(&capture, &input, || Ok(()))?;
        let receipt = Fixture::commit(
            &store,
            &ManagedCommit {
                control: &crate::AnalysisReadControl::default(),
                budget: &crate::analysis::managed::tests::TestBudget,
                completed: true,
                now_utc_ns: 10,
                attempt: &attempt,
                returns: &[],
                selected: &selected,
                selected_schema: batch.schema_ref(),
            },
            || Ok(()),
        )?;
        let retained = Fixture::receipt(
            &store,
            [1; 16],
            &spec.id,
            &input.id,
            &AnalysisReadControl::default(),
        )?
        .ok_or("native selected result absent")?;
        assert_eq!(retained, receipt);
        assert_eq!(
            Fixture::rows(&store, &receipt.selected)?,
            batch.num_rows() as u64
        );
        let result = store.managed_result(
            attempt.instance(),
            &receipt.selected.result_id,
            10,
            &AnalysisReadControl::default(),
        )?;
        assert_eq!(result.result, receipt.selected);
        assert!(matches!(
            &result.kind,
            crate::InstanceResultKindV1::Selected
        ));
        receipts.push((spec.id, input.id, receipt, selected));
    }
    drop(store);
    let store = AnalysisStore::open(&root)?;
    for (instance, attempt, receipt, selected) in receipts {
        let retained = Fixture::receipt(
            &store,
            [1; 16],
            &instance,
            &attempt,
            &AnalysisReadControl::default(),
        )?
        .ok_or("recovered native result absent")?;
        assert_eq!(retained, receipt);
        assert_eq!(Fixture::rows(&store, &receipt.selected)?, selected.rows());
    }
    Ok(())
}

#[test]
fn managed_registration_keeps_cut() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = AnalysisStore::open(directory.path().join("store"))?;
    let mut fixture = Fixture::admit(&store)?;
    let context = crate::AnalysisContextVersionV1 {
        key: crate::AnalysisContextKeyV1 {
            tenant_id: [1; 16],
            owner_id: "fixture".into(),
            entity_key: vec![1],
            lifetime_key: vec![1],
            owner_revision: 1,
        },
        valid_from_utc_ns: None,
        valid_until_utc_ns: None,
        sensitivity: crate::ContextSensitivityV1::Tenant,
        body: b"first".to_vec(),
    };
    store.commit_context(&context)?;
    let mut spec = fixture.instance.spec.clone();
    let mut grant = fixture.instance.grant.clone();
    spec.id = "contextual".into();
    grant.selection.contexts = crate::Selection::Exact(vec![context.key.clone()]);

    fixture.instance = store.admit_managed(&spec, &grant, || Ok(()))?;
    let instance = fixture.instance.clone();
    let requests = AnalysisTableRequests::new();
    let captured = store
        .read_managed_tables_filtered(
            &grant.selection,
            &ManagedRead {
                source: None,
                execution: None,
                follow: false,
                expected: None,
                instance,
                rebuild: false,
                completed: None,
            },
            AnalysisTableRead {
                requests: &requests,
                event_ranges: None,
                mode: AnalysisReadModeV1::Complete,
                now: 10,
            },
            AnalysisExtractLimits::default(),
            &AnalysisReadControl::default(),
            None,
        )?
        .state;
    let input = request("context-step");
    let first = store.register_managed_attempt(&captured, &input, || Ok(()))?;
    assert!(store.meta()?.commit_revision > captured.revision());
    let evaluations = [
        fixture.evaluation(&input, 10, None)?,
        fixture.evaluation(&input, 11, None)?,
    ];
    let outputs = [fixture.output(2)?, fixture.output(3)?];
    fixture.publish(&store, &first, &evaluations, &outputs)?;
    let instance = store
        .managed_instance([1; 16], &spec.id, &AnalysisReadControl::default())?
        .ok_or("contextual instance absent")?;
    let captured = store
        .read_managed_tables_filtered(
            &grant.selection,
            &ManagedRead {
                source: None,
                execution: None,
                follow: false,
                expected: None,
                instance,
                rebuild: false,
                completed: None,
            },
            AnalysisTableRead {
                requests: &requests,
                event_ranges: None,
                mode: AnalysisReadModeV1::Complete,
                now: 10,
            },
            AnalysisExtractLimits::default(),
            &AnalysisReadControl::default(),
            None,
        )?
        .state;
    let input = request("changed-context");
    let second = store.register_managed_attempt(&captured, &input, || Ok(()))?;
    let evaluations = [
        fixture.evaluation(&input, 10, Some(&captured))?,
        fixture.evaluation(&input, 11, Some(&captured))?,
    ];
    let mut next = context;
    next.key.owner_revision = 2;
    next.body = b"second".to_vec();
    store.commit_context(&next)?;
    let before = store.meta()?;
    assert!(fixture
        .publish(&store, &second, &evaluations, &outputs)
        .is_err());
    assert_eq!(store.meta()?, before);
    Ok(())
}

#[test]
fn managed_witness_lifetime_check() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = AnalysisStore::open(directory.path().join("store"))?;
    let mut fixture = Fixture::admit(&store)?;
    let source = crate::analysis::tests::identity();
    store.accept_validated_batch(
        source.clone(),
        crate::ValidatedEvidenceBatchV1 {
            cpu_id: 0,
            first_cursor: 1,
            last_cursor: 1,
            intake_utc_ns: 10,
            framed_records: b"a".to_vec().into(),
            frame_ends: vec![1],
        },
    )?;
    let mut spec = fixture.instance.spec.clone();
    let mut grant = fixture.instance.grant.clone();
    spec.id = "witnessed".into();
    grant.selection.sources = crate::Selection::Exact(vec![source.clone()]);
    fixture.instance = store.admit_managed(&spec, &grant, || Ok(()))?;
    let cursor = crate::AnalysisStore::table_schemas()["events"].index_of("source_cursor")?;
    let requests = AnalysisTableRequests::from([("events".into(), Some(BTreeSet::from([cursor])))]);
    let capture = store
        .read_managed_tables_filtered(
            &grant.selection,
            &ManagedRead {
                source: None,
                execution: None,
                follow: false,
                expected: None,
                instance: fixture.instance.clone(),
                rebuild: false,
                completed: None,
            },
            AnalysisTableRead {
                requests: &requests,
                event_ranges: None,
                mode: AnalysisReadModeV1::Complete,
                now: 10,
            },
            AnalysisExtractLimits::default(),
            &AnalysisReadControl::default(),
            None,
        )?
        .state;
    let mut input = request("witness");
    input.witness_expiry = 20;
    let attempt = store.register_managed_attempt(&capture, &input, || Ok(()))?;
    let evaluations = [
        fixture.evaluation(&input, 10, None)?,
        fixture.evaluation(&input, 11, None)?,
    ];
    let outputs = [fixture.output(2)?, fixture.output(3)?];
    let returns = [
        ManagedReturn {
            graph: None,
            retained: None,
            changes: None,
            call: 10,
            evaluation: &evaluations[0],
            output: &outputs[0],
        },
        ManagedReturn {
            graph: None,
            retained: None,
            changes: None,
            call: 11,
            evaluation: &evaluations[1],
            output: &outputs[1],
        },
    ];
    let selected = sdk::Dataset {
        name: "selected".into(),
        batches: outputs[0].datasets[0].batches.clone(),
    };
    let mut commit = ManagedCommit {
        control: &crate::AnalysisReadControl::default(),
        budget: &crate::analysis::managed::tests::TestBudget,
        completed: true,
        attempt: &attempt,
        now_utc_ns: 21,
        returns: &returns,
        selected: &selected,
        selected_schema: &fixture.model.outputs[0].schema,
    };
    let before = store.meta()?;
    assert!(matches!(
        Fixture::commit(&store, &commit, || Ok(())),
        Err(crate::Error::Package {
            code: crate::PackageErrorCodeV1::Incomplete,
            field: "managed witness lifetime",
            ..
        })
    ));
    assert_eq!(store.meta()?, before);
    commit.now_utc_ns = 20;
    assert!(matches!(
        Fixture::commit(&store, &commit, || Ok(())),
        Err(crate::Error::Package {
            code: crate::PackageErrorCodeV1::Incomplete,
            field: "managed witness lifetime",
            ..
        })
    ));
    assert_eq!(store.meta()?, before);
    commit.now_utc_ns = 19;
    assert!(Fixture::commit(&store, &commit, || crate::AnalysisReadDeniedSnafu.fail()).is_err());
    assert_eq!(store.meta()?, before);
    let count: u64 = store.read_snapshot(|reader| {
        reader
            .query_row("SELECT count(*) FROM evidence_refs", [], |row| row.get(0))
            .context(crate::AnalysisDatabaseSnafu {
                operation: "count rolled back witness refs",
            })
    })?;
    assert_eq!(count, 0);
    let receipt = Fixture::commit(&store, &commit, || Ok(()))?;
    let count: u64 = store.read_snapshot(|reader| {
        reader
            .query_row("SELECT count(*) FROM evidence_refs", [], |row| row.get(0))
            .context(crate::AnalysisDatabaseSnafu {
                operation: "count committed witness refs",
            })
    })?;
    assert_eq!(count, 3);
    assert!(
        store
            .managed_result(
                &fixture.instance,
                &receipt.results[&10].result_id,
                19,
                &AnalysisReadControl::default()
            )?
            .current
    );
    assert!(
        !store
            .managed_result(
                &fixture.instance,
                &receipt.results[&10].result_id,
                20,
                &AnalysisReadControl::default()
            )?
            .current
    );
    assert!(
        !store
            .managed_result(
                &fixture.instance,
                &receipt.results[&10].result_id,
                21,
                &AnalysisReadControl::default()
            )?
            .current
    );
    assert_eq!(
        store
            .source_status(&source)?
            .ok_or("source absent")?
            .retained_event_count,
        1
    );
    Ok(())
}

mod frontier;

mod readiness;
