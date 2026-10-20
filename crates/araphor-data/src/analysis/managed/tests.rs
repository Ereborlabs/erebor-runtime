use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use araphor_analysis_sdk as sdk;
use araphor_discovery_definition::{Definition, ImagePin, Program, ResolvedDefinition, Source};
use duckdb::params;
use snafu::ResultExt as _;

use super::*;
use crate::analysis::{
    AnalysisExtractLimits, AnalysisReadModeV1, AnalysisSelectionV1, AnalysisStore,
    AnalysisTableRead, AnalysisTableRequests,
};
use crate::{
    AnalysisReadControl, PackageArtifactV1, PackageBundleV1, PackageGrantV1,
    PackageImplementationV1, SqlModelV1, SqlReasonV1,
};

type TestResult<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

struct Fixture {
    instance: ManagedInstance,
    model: sdk::Model,
}

impl Fixture {
    fn admit(store: &AnalysisStore) -> TestResult<Self> {
        let scalar = sdk::Schema::new(vec![sdk::Field::new("value", sdk::DataType::UInt64, false)]);
        let mut rows = sdk::Port::new("rows", scalar.clone());
        rows.evidence_required = true;
        let mut model = sdk::Model::new(
            "count",
            vec![sdk::Port::new("source", scalar.clone())],
            vec![rows],
        );
        model.parameters = sdk::Schema::new(vec![sdk::Field::new(
            "increment",
            sdk::DataType::UInt64,
            false,
        )]);
        model.checkpoint = Some(sdk::CheckpointSpec {
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
        store.install_package_image([1; 16], &image, || Ok(()))?;
        let pin = ImagePin {
            image: image.root.clone(),
            digest: image.digest()?,
        };
        let sql = "SELECT * FROM \"managed-fixture\".\"r1\".count(source => (SELECT 1::BIGINT UNSIGNED AS value), increment => 2) a CROSS JOIN \"managed-fixture\".\"r1\".count(source => (SELECT 1::BIGINT UNSIGNED AS value), increment => 3) b".to_owned();
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
        store.admit_definition([1; 16], &definition, || Ok(()))?;
        let selection = AnalysisSelectionV1::new([1; 16], Vec::new());
        let spec = ManagedSpec { tenant: [1; 16], id: "counter".into(), grant: PackageGrantV1 { principal: "fixture".into(), revision: 1, selection: selection.clone(), expires_utc_ns: None, authorization_id: Some("definition-grant".into()) }, manifest: ManagedManifest {
            format: 1, planner: "datafusion-53/sql-call-1".into(), definition: definition.digest()?, calls: [(10, 2), (11, 3)].into_iter().map(|(id, increment)| (id, ManagedCall {
                image: pin.clone(), package: image.root.clone(), export: "count".into(), target: "sql".into(), artifact: None, arguments: vec![format!("source => (SELECT 1::BIGINT UNSIGNED AS value), increment => {increment}")], dependencies: BTreeSet::new(),
            })).collect(),
        }, definition };
        let instance = store.admit_managed(&spec, || Ok(()))?;
        Ok(Self { instance, model })
    }

    fn capture(&self, store: &AnalysisStore, rebuild: bool) -> TestResult<ManagedCapture> {
        let instance = store
            .managed_instance(
                [1; 16],
                &self.instance.spec.id,
                &AnalysisReadControl::default(),
            )?
            .ok_or("instance absent")?;
        let requests = AnalysisTableRequests::new();
        let page = store.read_managed_tables(
            &instance.spec.grant.selection,
            &ManagedRead {
                instance: instance.clone(),
                rebuild,
            },
            AnalysisTableRead {
                requests: &requests,
                event_ranges: None,
                inputs: None,
                mode: AnalysisReadModeV1::Complete,
                now: 10,
            },
            AnalysisExtractLimits::default(),
            &AnalysisReadControl::default(),
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
        let inputs = vec![input];
        let checkpoint = captured
            .and_then(|capture| capture.prior(call))
            .map(|prior| prior.checkpoint(&self.model, &inputs, Some(&parameters), request.rebuild))
            .transpose()?
            .flatten();
        Ok(sdk::Evaluation {
            export: "count".into(),
            inputs,
            parameters: Some(parameters),
            checkpoint,
            context: sdk::EvaluationContext {
                id: request.id.clone(),
                time_utc_ns: request.time_utc_ns as i64,
                seed: request.seed,
                limits: self.model.limits,
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
        let returns = evaluations
            .iter()
            .zip(outputs)
            .enumerate()
            .map(|(index, (evaluation, output))| ManagedReturn {
                call: 10 + index as u64,
                evaluation,
                output,
            })
            .collect::<Vec<_>>();
        let selected = sdk::Dataset {
            name: "selected".into(),
            batches: outputs[0].datasets[0].batches.clone(),
        };
        Ok(store.commit_managed(
            &ManagedCommit {
                attempt,
                now_utc_ns: 10,
                returns: &returns,
                selected: &selected,
                selected_schema: &self.model.outputs[0].schema,
                selected_limits: self.model.limits,
            },
            || Ok(()),
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
    }
}

#[test]
fn retained_limits_keep_descriptor() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = AnalysisStore::open(directory.path().join("store"))?;
    let fixture = Fixture::admit(&store)?;
    let captured = fixture.capture(&store, false)?;
    let request = request("limited-writer");
    let attempt = store.register_managed_attempt(&captured, &request, || Ok(()))?;
    let mut evaluations = [
        fixture.evaluation(&request, 10, None)?,
        fixture.evaluation(&request, 11, None)?,
    ];
    for evaluation in &mut evaluations {
        evaluation.context.limits.max_rows = 2;
    }
    let receipt = fixture.publish(
        &store,
        &attempt,
        &evaluations,
        &[fixture.output(12)?, fixture.output(103)?],
    )?;
    for reference in receipt.results.values() {
        let result = store.managed_result(
            &fixture.instance,
            &reference.result_id,
            10,
            &AnalysisReadControl::default(),
        )?;
        assert_eq!(result.context.context.limits.max_rows, 2);
        assert_eq!(result.limits, fixture.model.limits);
        assert!(result.limits.max_rows > 2);
    }
    Ok(())
}

#[test]
fn managed_calls_commit_atomically() -> TestResult {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("store");
    let store = AnalysisStore::open(&root)?;
    let fixture = Fixture::admit(&store)?;
    let mut checked = false;
    assert_eq!(
        store.admit_managed(&fixture.instance.spec, || {
            checked = true;
            Ok(())
        })?,
        fixture.instance
    );
    assert!(checked);
    let mut changed = fixture.instance.spec.clone();
    changed
        .manifest
        .calls
        .get_mut(&10)
        .ok_or("call absent")?
        .arguments
        .push("changed => 1".into());
    assert!(matches!(
        store.admit_managed(&changed, || Ok(())),
        Err(crate::Error::AnalysisConflict { .. })
    ));
    let captured = fixture.capture(&store, false)?;
    assert!(captured.prior(10).is_none());
    assert!(captured.prior(11).is_none());
    let input = request("step-1");
    let attempt = store.register_managed_attempt(&captured, &input, || Ok(()))?;
    assert!(matches!(
        store.register_managed_attempt(&captured, &input, || Ok(())),
        Err(crate::Error::Package {
            code: crate::PackageErrorCodeV1::Incomplete,
            field: "managed pending attempt",
            ..
        })
    ));
    let evaluations = [
        fixture.evaluation(&input, 10, None)?,
        fixture.evaluation(&input, 11, None)?,
    ];
    let outputs = [fixture.output(12)?, fixture.output(103)?];
    let receipt = fixture.publish(&store, &attempt, &evaluations, &outputs)?;
    assert_eq!(receipt.results.len(), 2);
    assert_eq!(receipt.selected.commit_revision, receipt.commit_revision);
    let after = store.meta()?;
    assert!(fixture
        .publish(&store, &attempt, &evaluations, &outputs)
        .is_err());
    assert_eq!(
        store
            .managed_attempt(
                [1; 16],
                "counter",
                &input.id,
                &AnalysisReadControl::default()
            )?
            .and_then(|attempt| attempt.receipt().cloned()),
        Some(receipt.clone())
    );
    assert_eq!(store.meta()?, after);
    for call in [10, 11] {
        let retained = store.managed_result(
            &fixture.instance,
            &receipt.results[&call].result_id,
            10,
            &AnalysisReadControl::default(),
        )?;
        assert!(retained.current);
        assert_eq!(retained.commit_revision, receipt.commit_revision);
        let expected = &outputs[(call - 10) as usize];
        assert_eq!(
            retained.output.datasets[0].batches,
            expected.datasets[0].batches
        );
        assert_eq!(retained.output.evidence, expected.evidence);
        assert_eq!(
            retained.output.reasons[0].details,
            expected.reasons[0].details
        );
        assert_eq!(
            retained
                .output
                .checkpoint
                .ok_or("retained checkpoint absent")?
                .datasets[0]
                .batches,
            expected
                .checkpoint
                .as_ref()
                .ok_or("checkpoint absent")?
                .datasets[0]
                .batches
        );
    }
    let selected = store
        .managed_selected(
            [1; 16],
            "counter",
            "step-1",
            &AnalysisReadControl::default(),
        )?
        .ok_or("selected result absent")?;
    assert_eq!(selected.data.batches, outputs[0].datasets[0].batches);
    assert_eq!(selected.commit_revision, receipt.commit_revision);
    assert!(store
        .managed_selected(
            [2; 16],
            "counter",
            "step-1",
            &AnalysisReadControl::default()
        )?
        .is_none());
    let next = fixture.capture(&store, false)?;
    assert_eq!(next.instance().progress, receipt.commit_revision);
    assert_ne!(
        next.prior(10).ok_or("first prior absent")?.result,
        next.prior(11).ok_or("second prior absent")?.result
    );
    assert_eq!(
        fixture
            .evaluation(&request("step-2"), 10, Some(&next))?
            .checkpoint
            .ok_or("first state absent")?
            .datasets[0]
            .batches,
        outputs[0]
            .checkpoint
            .as_ref()
            .ok_or("state absent")?
            .datasets[0]
            .batches
    );
    assert_eq!(
        fixture
            .evaluation(&request("step-2"), 11, Some(&next))?
            .checkpoint
            .ok_or("second state absent")?
            .datasets[0]
            .batches,
        outputs[1]
            .checkpoint
            .as_ref()
            .ok_or("state absent")?
            .datasets[0]
            .batches
    );
    let (headers, payloads, activation): (u64, u64, u64) = store.read_snapshot(|reader| reader.query_row(
        "SELECT (SELECT count(*) FROM analysis_results WHERE processor_id LIKE 'managed-%' AND decode(body) LIKE '%\"arrow_ipc\":[]%'), (SELECT count(*) FROM managed_arrow), (SELECT count(*) FROM package_activations)", [], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?))).context(crate::AnalysisDatabaseSnafu { operation: "read managed BLOB qualification" }))?;
    assert_eq!((headers, payloads, activation), (3, 9, 0));
    let second = request("step-2");
    let second_attempt = store.register_managed_attempt(&next, &second, || Ok(()))?;
    let second_evaluations = [
        fixture.evaluation(&second, 10, Some(&next))?,
        fixture.evaluation(&second, 11, Some(&next))?,
    ];
    let second_outputs = [fixture.output(22)?, fixture.output(203)?];
    let second_receipt = fixture.publish(
        &store,
        &second_attempt,
        &second_evaluations,
        &second_outputs,
    )?;
    assert!(second_receipt.commit_revision > receipt.commit_revision);
    let before_collection = store.meta()?;
    for pin in &fixture.instance.spec.definition.images {
        store.collect_package([1; 16], &pin.image.package_id, &pin.image.revision)?;
    }
    store.collect_package_admissions()?;
    assert_eq!(store.meta()?, before_collection);
    let backup = root.join("backups/managed");
    store.backup(&backup)?;
    drop(store);
    let reopened = AnalysisStore::open(&root)?;
    let retry = reopened
        .managed_attempt(
            [1; 16],
            "counter",
            "step-1",
            &AnalysisReadControl::default(),
        )?
        .ok_or("attempt absent")?;
    assert_eq!(retry.receipt().cloned(), Some(receipt.clone()));
    let latest = fixture.capture(&reopened, false)?;
    assert_eq!(latest.instance().progress, second_receipt.commit_revision);
    for call in [10, 11] {
        let retained = reopened.managed_result(
            &fixture.instance,
            &receipt.results[&call].result_id,
            second.time_utc_ns,
            &AnalysisReadControl::default(),
        )?;
        assert!(!retained.current);
        assert_eq!(retained.commit_revision, receipt.commit_revision);
        let expected = &outputs[(call - 10) as usize];
        assert_eq!(
            retained.output.datasets[0].batches,
            expected.datasets[0].batches
        );
        assert_eq!(retained.output.evidence, expected.evidence);
        assert_eq!(
            retained.output.reasons[0].details,
            expected.reasons[0].details
        );
        assert_eq!(
            retained
                .output
                .checkpoint
                .ok_or("historical checkpoint absent")?
                .datasets[0]
                .batches,
            expected
                .checkpoint
                .as_ref()
                .ok_or("expected historical checkpoint absent")?
                .datasets[0]
                .batches
        );
        let prior = latest.prior(call).ok_or("current checkpoint absent")?;
        assert_eq!(prior.result, second_receipt.results[&call].result_id);
        assert_eq!(
            prior.revision,
            second_receipt.results[&call].commit_revision
        );
        assert_eq!(
            prior
                .checkpoint(
                    &fixture.model,
                    &second_evaluations[(call - 10) as usize].inputs,
                    second_evaluations[(call - 10) as usize].parameters.as_ref(),
                    false,
                )?
                .ok_or("eligible current checkpoint absent")?
                .datasets[0]
                .batches,
            second_outputs[(call - 10) as usize]
                .checkpoint
                .as_ref()
                .ok_or("expected current checkpoint absent")?
                .datasets[0]
                .batches
        );
    }
    let historical_selected = reopened
        .managed_selected(
            [1; 16],
            "counter",
            "step-1",
            &AnalysisReadControl::default(),
        )?
        .ok_or("historical selected result absent")?;
    assert_eq!(historical_selected.commit_revision, receipt.commit_revision);
    assert_eq!(
        historical_selected.data.batches,
        outputs[0].datasets[0].batches
    );
    for pin in &fixture.instance.spec.definition.images {
        let image = reopened
            .package_image(
                [1; 16],
                &pin.image.package_id,
                Some(&pin.image.revision),
                &AnalysisReadControl::default(),
            )?
            .ok_or("retained image absent")?;
        assert_eq!(image.root, pin.image);
        assert_eq!(image.digest()?, pin.digest);
    }
    let restored = AnalysisStore::restore(&backup, &directory.path().join("restored"))?;
    let retry = restored
        .managed_attempt(
            [1; 16],
            "counter",
            "step-1",
            &AnalysisReadControl::default(),
        )?
        .ok_or("restored attempt absent")?;
    assert_eq!(retry.receipt().cloned(), Some(receipt.clone()));
    Ok(())
}

#[test]
fn managed_failure_is_atomic() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = AnalysisStore::open(directory.path().join("store"))?;
    let fixture = Fixture::admit(&store)?;
    let captured = fixture.capture(&store, false)?;
    let input = request("atomic");
    let attempt = store.register_managed_attempt(&captured, &input, || Ok(()))?;
    let evaluations = [
        fixture.evaluation(&input, 10, None)?,
        fixture.evaluation(&input, 11, None)?,
    ];
    let mut outputs = [fixture.output(2)?, fixture.output(3)?];
    let before = store.meta()?;
    let mut changed = evaluations.clone();
    changed[0].context.time_utc_ns += 1;
    let error = fixture
        .publish(&store, &attempt, &changed, &outputs)
        .err()
        .ok_or("wrong evaluation time was published")?;
    assert!(matches!(
        error.downcast_ref::<crate::Error>(),
        Some(crate::Error::Package {
            code: crate::PackageErrorCodeV1::Invalid,
            field: "managed evaluation request",
            ..
        })
    ));
    assert_eq!(store.meta()?, before);
    outputs[1].evidence[0].input.row = 1;
    assert!(fixture
        .publish(&store, &attempt, &evaluations, &outputs)
        .is_err());
    assert_eq!(store.meta()?, before);
    let state = fixture.capture(&store, false)?;
    assert!(state.prior(10).is_none());
    assert!(state.prior(11).is_none());
    outputs[1].evidence[0].input.row = 0;
    let returns = [
        ManagedReturn {
            call: 10,
            evaluation: &evaluations[0],
            output: &outputs[0],
        },
        ManagedReturn {
            call: 11,
            evaluation: &evaluations[1],
            output: &outputs[1],
        },
    ];
    let selected = sdk::Dataset {
        name: "selected".into(),
        batches: outputs[0].datasets[0].batches.clone(),
    };
    let commit = ManagedCommit {
        now_utc_ns: 10,
        attempt: &attempt,
        returns: &returns,
        selected: &selected,
        selected_schema: &fixture.model.outputs[0].schema,
        selected_limits: fixture.model.limits,
    };
    let mut checked = 0;
    assert!(matches!(
        store.commit_managed(&commit, || {
            checked += 1;
            crate::AnalysisReadDeniedSnafu.fail()
        }),
        Err(crate::Error::AnalysisReadDenied { .. })
    ));
    assert_eq!(checked, 1);
    assert_eq!(store.meta()?, before);
    let receipt = store.commit_managed(&commit, || {
        checked += 1;
        Ok(())
    })?;
    assert_eq!(checked, 2);
    let after = store.meta()?;
    assert!(store
        .commit_managed(&commit, || {
            checked += 1;
            crate::AnalysisReadDeniedSnafu.fail()
        })
        .is_err());
    assert_eq!(checked, 2);
    assert_eq!(store.meta()?, after);
    assert!(matches!(
        store.commit_managed(&commit, || Ok(())),
        Err(crate::Error::AnalysisConflict { .. })
    ));
    assert_eq!(
        store
            .managed_attempt(
                [1; 16],
                "counter",
                "atomic",
                &AnalysisReadControl::default()
            )?
            .and_then(|attempt| attempt.receipt().cloned()),
        Some(receipt)
    );
    let mut conflicting = outputs.clone();
    conflicting[1] = fixture.output(99)?;
    assert!(
        matches!(fixture.publish(&store, &attempt, &evaluations, &conflicting), Err(error) if matches!(error.downcast_ref::<crate::Error>(), Some(crate::Error::AnalysisConflict { .. })))
    );
    assert_eq!(store.meta()?, after);
    Ok(())
}

#[test]
fn managed_capture_keeps_guards() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = AnalysisStore::open(directory.path().join("store"))?;
    let fixture = Fixture::admit(&store)?;
    let captured = fixture.capture(&store, false)?;
    let first = request("first");
    let attempt = store.register_managed_attempt(&captured, &first, || Ok(()))?;
    let second = request("second");
    let stale = store.register_managed_attempt(&captured, &second, || Ok(()))?;
    let eval = [
        fixture.evaluation(&first, 10, None)?,
        fixture.evaluation(&first, 11, None)?,
    ];
    let outputs = [fixture.output(12)?, fixture.output(13)?];
    fixture.publish(&store, &attempt, &eval, &outputs)?;
    let eval = [
        fixture.evaluation(&second, 10, None)?,
        fixture.evaluation(&second, 11, None)?,
    ];
    let before = store.meta()?;
    assert!(fixture.publish(&store, &stale, &eval, &outputs).is_err());
    assert_eq!(store.meta()?, before);
    let captured = fixture.capture(&store, false)?;
    let input = request("guarded");
    let evaluation = fixture.evaluation(&input, 10, Some(&captured))?;
    let prior = captured.prior(10).ok_or("prior absent")?;
    assert!(prior
        .checkpoint(
            &fixture.model,
            &evaluation.inputs,
            evaluation.parameters.as_ref(),
            false
        )?
        .is_some());
    let mut version = prior.clone();
    version
        .checkpoint
        .as_mut()
        .ok_or("checkpoint absent")?
        .version += 1;
    let mut dataset = prior.clone();
    dataset
        .checkpoint
        .as_mut()
        .ok_or("checkpoint absent")?
        .datasets[0]
        .name = "unknown-state".into();
    let mut schema = prior.clone();
    schema
        .checkpoint
        .as_mut()
        .ok_or("checkpoint absent")?
        .datasets[0]
        .batches = vec![Fixture::batch(
        &sdk::Schema::new(vec![sdk::Field::new("other", sdk::DataType::UInt64, false)]),
        12,
    )?];
    for incompatible in [version, dataset, schema] {
        assert!(incompatible
            .checkpoint(
                &fixture.model,
                &evaluation.inputs,
                evaluation.parameters.as_ref(),
                false
            )?
            .is_none());
    }
    let mut changed = evaluation.inputs.clone();
    changed[0].revision.id.push_str("-changed");
    assert!(prior
        .checkpoint(
            &fixture.model,
            &changed,
            evaluation.parameters.as_ref(),
            false
        )?
        .is_none());
    let mut changed = evaluation.inputs.clone();
    changed[0].coverage.state = sdk::CoverageState::Gapped;
    assert!(prior
        .checkpoint(
            &fixture.model,
            &changed,
            evaluation.parameters.as_ref(),
            false
        )?
        .is_none());
    let parameters = Fixture::batch(&fixture.model.parameters, 99)?;
    assert!(prior
        .checkpoint(&fixture.model, &evaluation.inputs, Some(&parameters), false)?
        .is_none());
    assert!(prior
        .checkpoint(
            &fixture.model,
            &evaluation.inputs,
            evaluation.parameters.as_ref(),
            true
        )?
        .is_none());
    let mut changed = input.clone();
    changed.seed = Some(9);
    let attempt = store.register_managed_attempt(&captured, &input, || Ok(()))?;
    assert!(store
        .register_managed_attempt(&captured, &changed, || Ok(()))
        .is_err());
    let recovered = store
        .managed_attempt(
            [1; 16],
            "counter",
            &input.id,
            &AnalysisReadControl::default(),
        )?
        .ok_or("pending attempt absent")?;
    let eval = [
        fixture.evaluation(&input, 10, Some(&captured))?,
        fixture.evaluation(&input, 11, Some(&captured))?,
    ];
    assert!(fixture
        .publish(&store, &recovered, &eval, &outputs)
        .is_err());
    let before = store.meta()?;
    for coverage in [false, true] {
        let mut changed = eval.clone();
        assert!(changed[0].checkpoint.is_some());
        if coverage {
            changed[0].inputs[0].coverage.state = sdk::CoverageState::Gapped;
        } else {
            changed[0].inputs[0].revision.id.push_str("-changed");
        }
        let error = fixture
            .publish(&store, &attempt, &changed, &outputs)
            .err()
            .ok_or("changed inputs reused captured state")?;
        assert!(matches!(
            error.downcast_ref::<crate::Error>(),
            Some(crate::Error::Package {
                code: crate::PackageErrorCodeV1::Conflict,
                field: "managed captured checkpoint",
                ..
            })
        ));
        assert_eq!(store.meta()?, before);
    }
    fixture.publish(&store, &attempt, &eval, &outputs)?;
    Ok(())
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
    store.admit_definition([1; 16], &definition, || Ok(()))?;
    let spec = ManagedSpec {
        tenant: [1; 16],
        id: "pure".into(),
        grant: PackageGrantV1 {
            principal: "fixture".into(),
            revision: 1,
            selection: AnalysisSelectionV1::new([1; 16], Vec::new()),
            expires_utc_ns: None,
            authorization_id: Some("definition-grant".into()),
        },
        manifest: ManagedManifest {
            format: 1,
            planner: "datafusion-53/sql-call-1".into(),
            definition: definition.digest()?,
            calls: BTreeMap::new(),
        },
        definition,
    };
    let before = store.meta()?;
    let mut checked = 0;
    assert!(store
        .admit_managed(&spec, || {
            checked += 1;
            crate::AnalysisReadDeniedSnafu.fail()
        })
        .is_err());
    assert_eq!(store.meta()?, before);
    let instance = store.admit_managed(&spec, || {
        checked += 1;
        Ok(())
    })?;
    let requests = AnalysisTableRequests::new();
    let captured = store
        .read_managed_tables(
            &spec.grant.selection,
            &ManagedRead {
                instance,
                rebuild: false,
            },
            AnalysisTableRead {
                requests: &requests,
                event_ranges: None,
                inputs: None,
                mode: AnalysisReadModeV1::Complete,
                now: 10,
            },
            AnalysisExtractLimits::default(),
            &AnalysisReadControl::default(),
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
        now_utc_ns: 10,
        attempt: &attempt,
        returns: &[],
        selected: &selected,
        selected_schema: &schema,
        selected_limits: sdk::Limits::default(),
    };
    let before = store.meta()?;
    assert!(store
        .commit_managed(&commit, || {
            checked += 1;
            crate::AnalysisReadDeniedSnafu.fail()
        })
        .is_err());
    assert_eq!(store.meta()?, before);
    let receipt = store.commit_managed(&commit, || {
        checked += 1;
        Ok(())
    })?;
    assert!(receipt.results.is_empty());
    assert_eq!(checked, 5);
    assert_eq!(
        store
            .managed_selected(
                [1; 16],
                "pure",
                "pure-step",
                &AnalysisReadControl::default()
            )?
            .ok_or("pure selected result absent")?
            .data
            .batches,
        selected.batches
    );
    Ok(())
}

#[test]
fn managed_recovery_checks_outputs() -> TestResult {
    for corruption in [
        "ipc",
        "evidence",
        "checkpoint",
        "parameters",
        "edge",
        "context",
    ] {
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
        let outputs = [fixture.output(2)?, fixture.output(3)?];
        let receipt = fixture.publish(&store, &attempt, &eval, &outputs)?;
        let id = &receipt.results[&10].result_id;
        {
            let mut writer = store.writer()?;
            let writer = writer.get_mut()?;
            match corruption {
                "ipc" => {
                    writer.execute(
                        "UPDATE managed_arrow SET ipc = ? WHERE result_id = ? AND role = 'output'",
                        params![b"broken".as_slice(), id],
                    )?;
                }
                "parameters" => {
                    writer.execute(
                        "DELETE FROM managed_arrow WHERE result_id = ? AND role = 'parameters'",
                        params![id],
                    )?;
                }
                "edge" => {
                    writer.execute(
                        "DELETE FROM managed_edges WHERE result_id = ?",
                        params![receipt.selected.result_id],
                    )?;
                }
                "context" => {
                    let mut record: model::Record = serde_json::from_slice(&writer.query_row(
                        "SELECT request_meta FROM analysis_results WHERE result_id = ?",
                        params![id],
                        |row| row.get::<_, Vec<u8>>(0),
                    )?)?;
                    record.context.target = "wasm32-wasip2".into();
                    writer.execute(
                        "UPDATE analysis_results SET request_meta = ? WHERE result_id = ?",
                        params![serde_json::to_vec(&record)?, id],
                    )?;
                }
                _ => {
                    let mut output: sdk::wire::Output =
                        serde_json::from_slice(&writer.query_row(
                            "SELECT body FROM analysis_results WHERE result_id = ?",
                            params![id],
                            |row| row.get::<_, Vec<u8>>(0),
                        )?)?;
                    if corruption == "evidence" {
                        output.evidence[0].input.row = 1;
                    } else {
                        output
                            .checkpoint
                            .as_mut()
                            .ok_or("checkpoint absent")?
                            .version = 2;
                    }
                    writer.execute(
                        "UPDATE analysis_results SET body = ? WHERE result_id = ?",
                        params![serde_json::to_vec(&output)?, id],
                    )?;
                }
            }
        }
        drop(store);
        assert!(
            AnalysisStore::open(&root).is_err(),
            "corruption {corruption}"
        );
    }
    Ok(())
}

#[test]
fn managed_commit_crashes() -> TestResult {
    if let Some(root) = std::env::var_os("ARAPHOR_MANAGED_ROOT") {
        let store = AnalysisStore::open(std::path::PathBuf::from(root))?;
        let fixture = Fixture::admit(&store)?;
        let capture = fixture.capture(&store, false)?;
        let input = request("crash");
        let attempt = store.register_managed_attempt(&capture, &input, || Ok(()))?;
        let eval = [
            fixture.evaluation(&input, 10, None)?,
            fixture.evaluation(&input, 11, None)?,
        ];
        let outputs = [fixture.output(2)?, fixture.output(3)?];
        fixture.publish(&store, &attempt, &eval, &outputs)?;
        return Err("the requested managed crash did not occur".into());
    }
    for point in ["managed.before", "managed.after"] {
        let directory = tempfile::tempdir()?;
        let root = directory.path().join("store");
        let store = AnalysisStore::open(&root)?;
        let fixture = Fixture::admit(&store)?;
        drop(store);
        let status = std::process::Command::new(std::env::current_exe()?)
            .args([
                "--exact",
                "analysis::managed::tests::managed_commit_crashes",
            ])
            .env("ARAPHOR_MANAGED_ROOT", &root)
            .env("ARAPHOR_CRASH_ROOT", &root)
            .env("ARAPHOR_CRASH_POINT", point)
            .status()?;
        assert_eq!(status.code(), Some(73), "{point}");
        let store = AnalysisStore::open(&root)?;
        let pending = store
            .managed_attempt([1; 16], "counter", "crash", &AnalysisReadControl::default())?
            .ok_or("crash attempt absent")?;
        if point == "managed.after" {
            let receipt = pending.receipt().ok_or("committed receipt absent")?.clone();
            assert_eq!(pending.receipt(), Some(&receipt));
            assert_eq!(
                fixture.capture(&store, false)?.instance().progress,
                receipt.commit_revision
            );
        } else {
            assert!(pending.receipt().is_none());
            let captured = fixture.capture(&store, false)?;
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
    store.admit_definition([1; 16], &definition, || Ok(()))?;
    let spec = ManagedSpec {
        tenant: [1; 16],
        id: "native-selected".into(),
        grant: PackageGrantV1 {
            principal: "fixture".into(),
            revision: 1,
            selection: AnalysisSelectionV1::new([1; 16], Vec::new()),
            expires_utc_ns: None,
            authorization_id: Some("definition-grant".into()),
        },
        manifest: ManagedManifest {
            format: 1,
            planner: "datafusion-53/sql-call-1".into(),
            definition: definition.digest()?,
            calls: BTreeMap::new(),
        },
        definition,
    };
    store.admit_managed(&spec, || Ok(()))?;
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
        let selected = sdk::Dataset {
            name: "selected".into(),
            batches: vec![batch.clone()],
        };
        let instance = store
            .managed_instance([1; 16], &spec.id, &AnalysisReadControl::default())?
            .ok_or("native instance absent")?;
        let requests = AnalysisTableRequests::new();
        let capture = store
            .read_managed_tables(
                &spec.grant.selection,
                &ManagedRead {
                    instance,
                    rebuild: false,
                },
                AnalysisTableRead {
                    requests: &requests,
                    event_ranges: None,
                    inputs: None,
                    mode: AnalysisReadModeV1::Complete,
                    now: 10,
                },
                AnalysisExtractLimits::default(),
                &AnalysisReadControl::default(),
            )?
            .state;
        let input = request(&format!("native-{index}"));
        let attempt = store.register_managed_attempt(&capture, &input, || Ok(()))?;
        let receipt = store.commit_managed(
            &ManagedCommit {
                now_utc_ns: 10,
                attempt: &attempt,
                returns: &[],
                selected: &selected,
                selected_schema: batch.schema_ref(),
                selected_limits: sdk::Limits {
                    max_bytes: batch.get_array_memory_size() as u64,
                    ..sdk::Limits::default()
                },
            },
            || Ok(()),
        )?;
        let retained = store
            .managed_selected(
                [1; 16],
                &spec.id,
                &input.id,
                &AnalysisReadControl::default(),
            )?
            .ok_or("native selected result absent")?;
        assert_eq!(retained.data.batches, selected.batches);
        assert_eq!(retained.data.rows(), batch.num_rows() as u64);
        if index < 2 {
            let packet =
                sdk::wire::Dataset::encode(&selected, batch.schema_ref(), sdk::Limits::default())?;
            assert!(packet.decode_any(sdk::Limits::default()).is_err());
        }
        receipts.push((input.id, receipt, selected));
    }
    drop(store);
    let store = AnalysisStore::open(&root)?;
    for (attempt, receipt, selected) in receipts {
        let retained = store
            .managed_selected([1; 16], &spec.id, &attempt, &AnalysisReadControl::default())?
            .ok_or("recovered native result absent")?;
        assert_eq!(retained.commit_revision, receipt.commit_revision);
        assert_eq!(retained.data.batches, selected.batches);
    }
    Ok(())
}

#[test]
fn native_selection_row_overflow() -> TestResult {
    let rows = usize::try_from(i64::MAX)?;
    assert!(u64::try_from(rows)?.checked_mul(3).is_none());
    let schema = Arc::new(sdk::Schema::empty());
    let batch = sdk::RecordBatch::try_new_with_options(
        Arc::clone(&schema),
        Vec::new(),
        &sdk::arrow_array::RecordBatchOptions::new().with_row_count(Some(rows)),
    )?;
    let mut ipc = Vec::new();
    let mut writer = arrow_ipc::writer::StreamWriter::try_new(&mut ipc, &schema)?;
    for _ in 0..3 {
        writer.write(&batch)?;
    }
    writer.finish()?;
    drop(writer);
    assert!(ipc.len() < 4096);
    let packet = sdk::wire::Dataset {
        name: "selected".into(),
        arrow_ipc: ipc,
    };
    assert!(AnalysisStore::decode_selected(&packet).is_err());
    Ok(())
}

#[test]
fn native_selection_rejects_corruption() -> TestResult {
    use arrow_ipc::writer::{
        write_message, DictionaryTracker, EncodedData, IpcDataGenerator, IpcWriteOptions,
    };

    let options = IpcWriteOptions::default();
    for (length, surplus, compressed, dictionary) in [
        (0, true, false, false),
        (-1, false, false, false),
        (i64::MAX, false, false, false),
        (0, false, true, false),
        (0, false, true, true),
    ] {
        let mut ipc = Vec::new();
        let mut dictionaries = DictionaryTracker::new(false);
        let schema = IpcDataGenerator::default().schema_to_bytes_with_dictionary_tracker(
            &sdk::Schema::empty(),
            &mut dictionaries,
            &options,
        );
        write_message(&mut ipc, schema, &options)?;
        let mut builder = flatbuffers::FlatBufferBuilder::new();
        let nodes = builder.create_vector::<arrow_ipc::FieldNode>(&[]);
        let buffers = builder.create_vector::<arrow_ipc::Buffer>(&[]);
        let variadic = surplus.then(|| builder.create_vector(&[1_i64]));
        let compression = compressed.then(|| {
            arrow_ipc::BodyCompression::create(
                &mut builder,
                &arrow_ipc::BodyCompressionArgs::default(),
            )
        });
        let batch = arrow_ipc::RecordBatch::create(
            &mut builder,
            &arrow_ipc::RecordBatchArgs {
                nodes: Some(nodes),
                buffers: Some(buffers),
                variadicBufferCounts: variadic,
                compression,
                ..Default::default()
            },
        );
        let (header_type, header) = if dictionary {
            let dictionary = arrow_ipc::DictionaryBatch::create(
                &mut builder,
                &arrow_ipc::DictionaryBatchArgs {
                    data: Some(batch),
                    ..Default::default()
                },
            );
            (
                arrow_ipc::MessageHeader::DictionaryBatch,
                dictionary.as_union_value(),
            )
        } else {
            (
                arrow_ipc::MessageHeader::RecordBatch,
                batch.as_union_value(),
            )
        };
        let message = arrow_ipc::Message::create(
            &mut builder,
            &arrow_ipc::MessageArgs {
                version: arrow_ipc::MetadataVersion::V5,
                header_type,
                header: Some(header),
                bodyLength: length,
                ..Default::default()
            },
        );
        builder.finish(message, None);
        write_message(
            &mut ipc,
            EncodedData {
                ipc_message: builder.finished_data().to_vec(),
                arrow_data: Vec::new(),
            },
            &options,
        )?;
        assert!(ipc.len() < 4096);
        let packet = sdk::wire::Dataset {
            name: "selected".into(),
            arrow_ipc: ipc,
        };
        assert_eq!(packet.validate_envelope().is_ok(), surplus);
        let error = AnalysisStore::decode_selected(&packet)
            .err()
            .ok_or("malformed native IPC was accepted")?;
        let expected = if surplus {
            "native selected IPC stream"
        } else if compressed {
            "compressed arrow stream"
        } else {
            "arrow framing"
        };
        assert!(format!("{error:?}").contains(expected), "{error:?}");
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
    spec.id = "contextual".into();
    spec.grant.selection.contexts = crate::Selection::Exact(vec![context.key.clone()]);

    fixture.instance = store.admit_managed(&spec, || Ok(()))?;
    let instance = fixture.instance.clone();
    let requests = AnalysisTableRequests::new();
    let captured = store
        .read_managed_tables(
            &spec.grant.selection,
            &ManagedRead {
                instance,
                rebuild: false,
            },
            AnalysisTableRead {
                requests: &requests,
                event_ranges: None,
                inputs: None,
                mode: AnalysisReadModeV1::Complete,
                now: 10,
            },
            AnalysisExtractLimits::default(),
            &AnalysisReadControl::default(),
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
        .read_managed_tables(
            &spec.grant.selection,
            &ManagedRead {
                instance,
                rebuild: false,
            },
            AnalysisTableRead {
                requests: &requests,
                event_ranges: None,
                inputs: None,
                mode: AnalysisReadModeV1::Complete,
                now: 10,
            },
            AnalysisExtractLimits::default(),
            &AnalysisReadControl::default(),
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
    spec.id = "witnessed".into();
    spec.grant.selection.sources = crate::Selection::Exact(vec![source.clone()]);
    fixture.instance = store.admit_managed(&spec, || Ok(()))?;
    let cursor = AnalysisStore::table_schemas()["events"].index_of("source_cursor")?;
    let requests = AnalysisTableRequests::from([("events".into(), Some(BTreeSet::from([cursor])))]);
    let capture = store
        .read_managed_tables(
            &spec.grant.selection,
            &ManagedRead {
                instance: fixture.instance.clone(),
                rebuild: false,
            },
            AnalysisTableRead {
                requests: &requests,
                event_ranges: None,
                inputs: None,
                mode: AnalysisReadModeV1::Complete,
                now: 10,
            },
            AnalysisExtractLimits::default(),
            &AnalysisReadControl::default(),
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
            call: 10,
            evaluation: &evaluations[0],
            output: &outputs[0],
        },
        ManagedReturn {
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
        attempt: &attempt,
        now_utc_ns: 21,
        returns: &returns,
        selected: &selected,
        selected_schema: &fixture.model.outputs[0].schema,
        selected_limits: fixture.model.limits,
    };
    let before = store.meta()?;
    assert!(matches!(
        store.commit_managed(&commit, || Ok(())),
        Err(crate::Error::Package {
            code: crate::PackageErrorCodeV1::Incomplete,
            field: "managed witness lifetime",
            ..
        })
    ));
    assert_eq!(store.meta()?, before);
    commit.now_utc_ns = 19;
    assert!(store
        .commit_managed(&commit, || crate::AnalysisReadDeniedSnafu.fail())
        .is_err());
    assert_eq!(store.meta()?, before);
    let count: u64 = store.read_snapshot(|reader| {
        reader
            .query_row("SELECT count(*) FROM evidence_refs", [], |row| row.get(0))
            .context(crate::AnalysisDatabaseSnafu {
                operation: "count rolled back witness refs",
            })
    })?;
    assert_eq!(count, 0);
    let receipt = store.commit_managed(&commit, || Ok(()))?;
    let count: u64 = store.read_snapshot(|reader| {
        reader
            .query_row("SELECT count(*) FROM evidence_refs", [], |row| row.get(0))
            .context(crate::AnalysisDatabaseSnafu {
                operation: "count committed witness refs",
            })
    })?;
    assert_eq!(count, 3);
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
