use araphor_analysis_sdk as sdk;

use super::{bundle, run, Fixture, TestResult};
use crate::analysis::PackageResultRefV1;
use crate::package::evaluation::ResultContext;
use crate::package::{PackageReadinessV1, PackageRequestV1};

#[tokio::test]
async fn query_reads_later_output() -> TestResult {
    let mut fixture = Fixture::new()?;
    for (revision, query, expected) in [
        (
            "1",
            "SELECT count FROM source",
            serde_json::json!([{"count": 3}]),
        ),
        (
            "2",
            "SELECT count FROM source WHERE false",
            serde_json::json!([]),
        ),
    ] {
        let mut package = bundle(revision, "SELECT count FROM selected");
        let model = &mut package.artifacts[0].descriptor.exports[0];
        let schema = model.outputs[0].schema.clone();
        model.inputs = vec![
            sdk::InputPort {
                port: sdk::Port::new("selected", schema.clone()),
                source: sdk::InputSource::Query(query.into()),
            },
            sdk::InputPort {
                port: sdk::Port::new("source", schema.clone()),
                source: sdk::InputSource::Table(sdk::TableRef::Output(sdk::OutputRef {
                    package: "test.upstream".into(),
                    revision: "1".into(),
                    export: "count".into(),
                    output: "rows".into(),
                })),
            },
        ];
        let mut upstream = bundle("1", "SELECT 3::BIGINT UNSIGNED AS count")
            .artifacts
            .remove(0);
        upstream.descriptor.id = "test.upstream".into();
        package.artifacts.push(upstream);
        let installed = if revision == "1" {
            fixture.install(package, None).await?
        } else {
            fixture
                .execute(PackageRequestV1::Update {
                    scope_id: "test".into(),
                    bundle: package,
                })
                .await?
        };
        assert!(matches!(
            installed.exports[0].readiness,
            PackageReadinessV1::Ready
        ));
        let initial = &installed.exports[0].results[0];
        assert_eq!(initial.input_revisions.len(), 2);
        let id = format!("relations.{revision}");
        let response = fixture.execute(run(&id)).await?;
        let status = &response.exports[0];
        assert!(status.active);
        assert_eq!(status.revision, revision);
        assert_eq!(status.descriptor.input_mode, sdk::InputMode::Resolved);
        assert!(matches!(status.readiness, PackageReadinessV1::Ready));
        let receipt = &status.results[0];
        assert_eq!(receipt.target, "sql");
        assert!(!receipt.stale);
        let packet = fixture.output("test.model", "count", &receipt.result_id)?;
        assert_eq!(
            crate::AnalysisPackageOwner::output_rows(&packet)?["rows"],
            expected
        );
        let output = crate::AnalysisPackageOwner::decode_output(&packet, &status.descriptor)?;
        assert_eq!(output.datasets[0].name, "rows");
        assert!(output.datasets[0]
            .batches
            .iter()
            .all(|batch| batch.schema().as_ref() == &schema));
        let upstream = fixture
            .execute(PackageRequestV1::Inspect {
                scope_id: "test".into(),
                package_id: "test.upstream".into(),
            })
            .await?;
        let source = &upstream.exports[0].results[0];
        assert_eq!(receipt.input_revisions.len(), 2);
        assert_ne!(receipt.input_revisions[1], initial.input_revisions[1]);
        assert_ne!(receipt.input_revisions[0], initial.input_revisions[0]);
        assert_eq!(
            receipt.input_revisions[0].owner,
            "araphor-analysis.ModelRun"
        );
        assert!(!receipt.input_revisions[0].id.is_empty());
        assert_eq!(
            receipt.input_revisions[1],
            sdk::Revision {
                owner: "test.upstream.count".into(),
                id: format!("{}:{}", source.result_id, source.commit_revision),
                window: None,
            }
        );
        let stored = fixture.result(&receipt.result_id)?;
        assert_eq!(
            stored.commit.dependencies,
            vec![PackageResultRefV1 {
                result_id: source.result_id.clone(),
                commit_revision: source.commit_revision,
            }]
        );
        let metadata: ResultContext = serde_json::from_slice(&stored.commit.metadata)?;
        assert_eq!(metadata.inputs, receipt.input_revisions);
        assert_eq!(metadata.input_coverage.len(), 2);
        for reopen in [false, true] {
            if reopen {
                fixture = fixture.reopen()?;
            }
            let retry = fixture.execute(run(&id)).await?;
            assert_eq!(
                serde_json::to_value(&retry.exports[0].results[0])?,
                serde_json::to_value(receipt)?
            );
            assert_eq!(
                fixture.store.package_result([1; 16], &receipt.result_id)?,
                Some(stored.clone())
            );
        }
    }
    Ok(())
}

#[tokio::test]
async fn output_read_shares_capacity() -> TestResult {
    use std::time::Duration;

    use crate::analysis::PackageKeyV1;
    use crate::model::{AdmittedExport, ModelInputRequest, ModelRun};
    use crate::{AnalysisReadControl, Limits};

    let fixture = Fixture::new_limits(Limits {
        global_evaluations: 1,
        tenant_evaluations: 1,
        input_capacity: 3 * Limits::default().input_bytes,
        extract_timeout: Duration::from_secs(30),
        evaluate_timeout: Duration::from_secs(30),
        ..Default::default()
    })?;
    let installed = fixture
        .install(bundle("1", "SELECT 3::BIGINT UNSIGNED AS count"), None)
        .await?;
    let receipt = &installed.exports[0].results[0];
    let active = fixture
        .store
        .package_activation(&PackageKeyV1 {
            tenant_id: [1; 16],
            scope_id: "test".into(),
            package_id: "test.model".into(),
            export: "count".into(),
        })?
        .ok_or("activation absent")?;
    let mut model = installed.exports[0].descriptor.clone();
    let port = sdk::Port::new("source", model.outputs[0].schema.clone());
    model.inputs = vec![sdk::InputPort {
        port,
        source: sdk::InputSource::Query("SELECT 1::BIGINT UNSIGNED AS count".into()),
    }];
    let control = AnalysisReadControl::with_timeout(Duration::from_secs(30))?;
    let now = crate::package::AnalysisPackageOwner::now();
    let mut held = ModelRun::new(&fixture.owner.query, [1; 16], &control)?;
    held.prepare_inputs(
        ModelInputRequest {
            activation: &active,
            model: &model,
            grant: &fixture.grant,
            now,
        },
        &AdmittedExport::admit(&fixture.owner.query, &model, None)?,
        || Ok(()),
    )?;
    let held_inputs = held.take_inputs()?;
    drop(fixture.owner.query.reserve_evaluation([1; 16])?);
    assert!(fixture
        .owner
        .query
        .memory()
        .reserve_input(fixture.owner.query.limits().input_capacity)
        .is_err());
    model.inputs[0].source = sdk::InputSource::Table(sdk::TableRef::Output(sdk::OutputRef {
        package: "test.model".into(),
        revision: "1".into(),
        export: "count".into(),
        output: "rows".into(),
    }));
    let mut operation = ModelRun::new(&fixture.owner.query, [1; 16], &control)?;
    operation.prepare_inputs(
        ModelInputRequest {
            activation: &active,
            model: &model,
            grant: &fixture.grant,
            now,
        },
        &AdmittedExport::admit(&fixture.owner.query, &model, None)?,
        || Ok(()),
    )?;
    let inputs = operation.take_inputs()?;
    let values = inputs.inputs[0].data.batches[0]
        .column(0)
        .as_any()
        .downcast_ref::<sdk::arrow_array::UInt64Array>()
        .ok_or("count column")?;
    assert_eq!(values.values().as_ref(), &[3]);
    assert_eq!(inputs.inputs[0].revision.owner, "test.model.count");
    assert_eq!(
        inputs.inputs[0].revision.id,
        format!("{}:{}", receipt.result_id, receipt.commit_revision)
    );
    assert_eq!(
        inputs.dependencies,
        vec![PackageResultRefV1 {
            result_id: receipt.result_id.clone(),
            commit_revision: receipt.commit_revision,
        }]
    );
    drop((operation, held, inputs, held_inputs));
    drop(
        fixture
            .owner
            .query
            .memory()
            .reserve_input(fixture.owner.query.limits().input_capacity)?,
    );
    let released = ModelRun::new(&fixture.owner.query, [1; 16], &control)?.query_datasets(
        &[],
        "SELECT 1::BIGINT UNSIGNED AS count",
        sdk::Limits::default(),
    )?;
    assert_eq!(released.data.batches[0].num_rows(), 1);
    Ok(())
}

#[tokio::test]
async fn alias_import_budget() -> TestResult {
    use std::time::Duration;

    use crate::analysis::PackageKeyV1;
    use crate::model::{AdmittedExport, ModelInputRequest, ModelRun};
    use crate::{AnalysisReadControl, Engine, Limits};

    let fixture = Fixture::new_limits(Limits {
        global_evaluations: 1,
        tenant_evaluations: 1,
        extract_timeout: Duration::from_secs(30),
        evaluate_timeout: Duration::from_secs(30),
        ..Default::default()
    })?;
    let mut package = bundle("1", "SELECT count FROM supplied");
    let schema = package.artifacts[0].descriptor.exports[0].outputs[0]
        .schema
        .clone();
    package.artifacts[0].descriptor.exports[0]
        .inputs
        .push(sdk::InputPort {
            port: sdk::Port::new("supplied", schema.clone()),
            source: sdk::InputSource::Query(
            "SELECT 3::BIGINT UNSIGNED AS count FROM catalog a JOIN catalog b ON a.readiness = b.readiness LIMIT 1024".into(),
            ),
        });
    let installed = fixture.install(package, None).await?;
    let receipt = &installed.exports[0].results[0];
    let packet = fixture.output("test.model", "count", &receipt.result_id)?;
    let data = packet.datasets[0].decode(&schema, sdk::Limits::default())?;
    let rows: usize = data.batches.iter().map(sdk::RecordBatch::num_rows).sum();
    let arrow: usize = data
        .batches
        .iter()
        .map(sdk::RecordBatch::get_array_memory_size)
        .sum();
    assert_eq!(rows, 1024);
    let physical = arrow + rows * 8;
    let active = fixture
        .store
        .package_activation(&PackageKeyV1 {
            tenant_id: [1; 16],
            scope_id: "test".into(),
            package_id: "test.model".into(),
            export: "count".into(),
        })?
        .ok_or("activation absent")?;
    let source = sdk::InputPort {
        port: sdk::Port::new("left_input", schema.clone()),
        source: sdk::InputSource::Table(sdk::TableRef::Output(sdk::OutputRef {
            package: "test.model".into(),
            revision: "1".into(),
            export: "count".into(),
            output: "rows".into(),
        })),
    };
    let now = crate::package::AnalysisPackageOwner::now();
    let mut catalog_count = None;
    for (combined, wide) in [(false, false), (true, false), (true, true)] {
        let control = AnalysisReadControl::with_timeout(Duration::from_secs(30))?;
        let mut model = installed.exports[0].descriptor.clone();
        let (limit, resource) = if combined {
            model.inputs = vec![
                source.clone(),
                sdk::InputPort {
                    port: sdk::Port::new("selected", schema.clone()),
                    source: sdk::InputSource::Query(
                        "SELECT count FROM left_input WHERE false".into(),
                    ),
                },
                sdk::InputPort {
                    port: sdk::Port::new("later", schema.clone()),
                    source: sdk::InputSource::Query(
                        if wide {
                            "SELECT COUNT(*)::BIGINT UNSIGNED AS count FROM catalog WHERE LENGTH(description) > 0"
                        } else {
                            "SELECT COUNT(*)::BIGINT UNSIGNED AS count FROM catalog"
                        }
                        .into(),
                    ),
                },
            ];
            (physical + 64 * 1024, "selected input bytes")
        } else {
            let mut right = source.clone();
            right.port.name = "right_input".into();
            model.inputs = vec![
                source.clone(),
                right,
                sdk::InputPort {
                    port: sdk::Port::new("selected", schema.clone()),
                    source: sdk::InputSource::Query(
                        "SELECT a.count FROM left_input a JOIN right_input b ON a.count = b.count WHERE false"
                            .into(),
                    ),
                },
            ];
            let limit = (arrow * 2).max(packet.datasets[0].arrow_ipc.len()) + 1024;
            assert!(arrow * 2 <= limit);
            assert!(physical <= limit && physical * 2 > limit);
            (limit, "model input bytes")
        };
        let owner = Engine::new(
            fixture.store.clone(),
            Limits {
                input_bytes: limit,
                global_evaluations: 1,
                tenant_evaluations: 1,
                extract_timeout: Duration::from_secs(30),
                evaluate_timeout: Duration::from_secs(30),
                ..Default::default()
            },
        )?;
        let mut calls = 0;
        let mut operation = ModelRun::new(&owner, [1; 16], &control)?;
        let result = operation
            .prepare_inputs(
                ModelInputRequest {
                    activation: &active,
                    model: &model,
                    grant: &fixture.grant,
                    now,
                },
                &AdmittedExport::admit(&owner, &model, None)?,
                || {
                    calls += 1;
                    Ok(())
                },
            )
            .and_then(|_| operation.take_inputs());
        drop(operation);
        let actual = if combined && !wide {
            Some(result?)
        } else {
            let error = result.as_ref().err().ok_or("input budget denial absent")?;
            assert_eq!(
                error.package_code(),
                crate::PackageErrorCodeV1::Limit,
                "combined={combined}, wide={wide}, calls={calls}, expected={resource}, error={error:?}"
            );
            None
        };
        assert_eq!(
            calls,
            if !combined {
                2
            } else if wide {
                6
            } else {
                7
            }
        );
        let control = AnalysisReadControl::with_timeout(Duration::from_secs(30))?;
        let released = ModelRun::new(&owner, [1; 16], &control)?.query_datasets(
            &[],
            "SELECT 1::BIGINT UNSIGNED AS count",
            sdk::Limits::default(),
        )?;
        assert_eq!(released.data.batches[0].num_rows(), 1);
        drop(released);
        let mut operation = ModelRun::new(&fixture.owner.query, [1; 16], &control)?;
        operation.prepare_inputs(
            ModelInputRequest {
                activation: &active,
                model: &model,
                grant: &fixture.grant,
                now,
            },
            &AdmittedExport::admit(&fixture.owner.query, &model, None)?,
            || Ok(()),
        )?;
        let inputs = operation.take_inputs()?;
        assert_eq!(
            inputs.inputs[0]
                .data
                .batches
                .iter()
                .map(sdk::RecordBatch::num_rows)
                .sum::<usize>(),
            rows
        );
        assert!(inputs
            .inputs
            .iter()
            .find(|input| input.data.name == "selected")
            .ok_or("selected input")?
            .data
            .batches
            .iter()
            .all(|batch| batch.num_rows() == 0));
        if combined {
            let later = &inputs
                .inputs
                .iter()
                .find(|input| input.data.name == "later")
                .ok_or("later input")?
                .data;
            assert_eq!(later.batches.len(), 1);
            assert_eq!(later.batches[0].num_rows(), 1);
            let count = later.batches[0]
                .column(0)
                .as_any()
                .downcast_ref::<sdk::arrow_array::UInt64Array>()
                .ok_or("catalog count")?
                .value(0);
            assert!(count > 0);
            assert_eq!(count, *catalog_count.get_or_insert(count));
        }
        if let Some(actual) = actual {
            assert_eq!(actual.inputs.len(), inputs.inputs.len());
            for (actual, expected) in actual.inputs.iter().zip(&inputs.inputs) {
                assert_eq!(actual.data.name, expected.data.name);
                assert_eq!(actual.data.batches, expected.data.batches);
                assert_eq!(actual.revision, expected.revision);
                assert_eq!(actual.coverage, expected.coverage);
            }
            assert_eq!(actual.dependencies, inputs.dependencies);
            assert_eq!(actual.source_revisions, inputs.source_revisions);
            assert_eq!(actual.witnesses, inputs.witnesses);
            assert_eq!(actual.contexts, inputs.contexts);
        }
        drop(operation);
        drop(inputs);
        drop(
            owner
                .memory()
                .reserve_input(owner.limits().input_capacity)?,
        );
    }
    Ok(())
}
