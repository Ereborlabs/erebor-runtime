use araphor_analysis_sdk as sdk;

use super::{bundle, run, Fixture, TestResult};
use crate::analysis::PackageResultRefV1;
use crate::package::evaluation::ResultContext;
use crate::package::{PackageReadinessV1, PackageRequestV1};

fn available_input_bytes(engine: &crate::Engine) -> usize {
    let (mut available, mut upper) = (0, engine.limits().input_capacity);
    while available < upper {
        let bytes = available + (upper - available).div_ceil(2);
        if engine.memory().reserve_input(bytes).is_ok() {
            available = bytes;
        } else {
            upper = bytes - 1;
        }
    }
    available
}

#[tokio::test]
async fn inspect_incomplete_input_marks_stale() -> TestResult {
    use std::sync::Arc;

    use crate::analysis::PackageCommitV1;
    use crate::AnalysisReadControl;
    use araphor_data::{ClockDependency, InstalledContext};

    let fixture = Fixture::new()?;
    let mut package = bundle("1", "SELECT count FROM source");
    let model = &mut package.artifacts[0].descriptor.exports[0];
    let schema = model.outputs[0].schema.clone();
    model.inputs = vec![
        sdk::InputPort {
            port: sdk::Port::new("source", schema.clone()),
            source: sdk::InputSource::Table(sdk::TableRef::Output(sdk::OutputRef {
                package: "test.upstream".into(),
                revision: "1".into(),
                export: "count".into(),
                output: "rows".into(),
            })),
        },
        sdk::InputPort {
            port: sdk::Port::new("clocked", schema.clone()),
            source: sdk::InputSource::Query(
                "SELECT 1::BIGINT UNSIGNED AS count WHERE now() IS NOT NULL".into(),
            ),
        },
    ];
    let model = model.clone();
    let mut upstream = bundle("1", "SELECT 3::BIGINT UNSIGNED AS count")
        .artifacts
        .remove(0);
    upstream.descriptor.id = "test.upstream".into();
    package.artifacts.push(upstream);
    let installed = fixture.install(package.clone(), None).await?;
    assert!(matches!(
        installed.exports[0].readiness,
        PackageReadinessV1::Ready
    ));
    assert_eq!(installed.exports[0].results.len(), 1);
    let upstream = fixture.activation("test.upstream")?;
    fixture
        .store
        .suspend_package(&upstream.key, upstream.generation, || Ok(()))?;
    assert!(!fixture.activation("test.upstream")?.active);
    let active = fixture.activation("test.model")?;
    assert!(
        fixture
            .result(
                active
                    .result_id
                    .as_deref()
                    .ok_or("previous downstream result")?
            )?
            .stale
    );
    let context: InstalledContext = serde_json::from_slice(&active.metadata)?;
    assert_eq!(context.clock, ClockDependency::Inputs);
    let data = sdk::Dataset {
        name: "rows".into(),
        batches: vec![sdk::RecordBatch::try_new(
            Arc::new(schema.clone()),
            vec![Arc::new(sdk::arrow_array::UInt64Array::from(vec![3]))],
        )?],
    };
    // Keep a stored downstream result after its upstream is suspended.
    let reference = fixture.store.commit_package(
        &PackageCommitV1 {
            expected_checkpoint_revision: active.checkpoint_revision,
            activation: active.clone(),
            window_id: "snapshot".into(),
            result_id: "retained-downstream".into(),
            request: b"retained".to_vec(),
            metadata: serde_json::to_vec(&ResultContext::new("retained", 1_000, &model, &[]))?,
            datasets: serde_json::to_vec(&sdk::wire::Output {
                datasets: vec![sdk::wire::Dataset::encode(&data, &schema, model.limits)?],
                ..Default::default()
            })?,
            checkpoint: Vec::new(),
            dependencies: Vec::new(),
            source_revisions: Vec::new(),
            witnesses: Vec::new(),
            context_refs: Vec::new(),
            created_utc_ns: 1_000,
        },
        || Ok(()),
    )?;
    assert!(!fixture.result(&reference.result_id)?.stale);
    let prior_results = fixture.store.package_results(&active.key)?;
    let _installed = fixture.owner.load_installed([1; 16], &package.root)?;
    let available = available_input_bytes(&fixture.owner.query);
    assert!(available > 0);
    let control = AnalysisReadControl::with_timeout(std::time::Duration::from_secs(30))?;
    let response = fixture
        .owner
        .inspect(&fixture.grant, "test", "test.model", None, &control)?;
    control.check()?;
    let result = fixture.result(&reference.result_id)?;
    assert!(result.stale);
    assert_eq!(result.commit_revision, reference.commit_revision);
    let receipt = response.exports[0]
        .results
        .iter()
        .find(|receipt| receipt.result_id == reference.result_id)
        .ok_or("retained result receipt")?;
    assert!(receipt.stale);
    assert_eq!(
        fixture.store.package_results(&active.key)?.len(),
        prior_results.len()
    );
    assert_eq!(
        fixture.activation("test.model")?.result_id.as_deref(),
        Some("retained-downstream")
    );
    drop(fixture.owner.query.reserve_evaluation([1; 16])?);
    drop(fixture.owner.query.memory().reserve_input(available)?);
    assert_eq!(available_input_bytes(&fixture.owner.query), available);

    let initial = Fixture::new()?;
    let store = initial.store.clone();
    let key = upstream.key.clone();
    let mut suspended = false;
    *initial
        .authority
        .after_commit
        .lock()
        .map_err(|_| "fixture commit observer")? = Some(Box::new(move || {
        if !suspended {
            if let Some(active) = store
                .package_activation(&key)?
                .filter(|active| active.result_id.is_some())
            {
                store.suspend_package(&key, active.generation, || Ok(()))?;
                suspended = true;
            }
        }
        Ok(())
    }));
    let response = initial.install(package, None).await?;
    assert!(
        matches!(&response.exports[0].readiness, PackageReadinessV1::MissingInput { input } if input == "dependency activation")
    );
    assert!(response.exports[0].results.is_empty());
    assert!(!initial.activation("test.upstream")?.active);
    assert!(initial.activation("test.model")?.result_id.is_none());
    drop(initial.owner.query.reserve_evaluation([1; 16])?);
    Ok(())
}

#[tokio::test]
async fn input_authority_rejects_foreign_or_revoked_grants() -> TestResult {
    use crate::package::evaluation::RunPreparation;
    use crate::package::{AnalysisPackageOwner, PackageActionV1, PackageErrorCodeV1};

    let fixture = Fixture::new()?;
    let mut package = bundle("1", "SELECT count FROM source");
    let model = &mut package.artifacts[0].descriptor.exports[0];
    model.inputs.push(sdk::InputPort {
        port: sdk::Port::new("source", model.outputs[0].schema.clone()),
        source: sdk::InputSource::Query("SELECT 3::BIGINT UNSIGNED AS count".into()),
    });
    fixture.install(package.clone(), None).await?;
    let active = fixture.activation("test.model")?;
    let installed = fixture.owner.load_installed([1; 16], &package.root)?;
    let available = available_input_bytes(&fixture.owner.query);
    assert!(available > 0);
    let before = fixture.store.package_results(&active.key)?;
    let context: araphor_data::InstalledContext = serde_json::from_slice(&active.metadata)?;
    for foreign in [true, false] {
        let mut denied = context.clone();
        if foreign {
            denied.grant.selection.tenant_id = [9; 16];
        } else {
            denied.grant.revision += 1;
        }
        let error = fixture
            .owner
            .prepare_model(
                &active,
                &denied,
                &installed,
                RunPreparation {
                    inputs: None,
                    id: "denied-input",
                    rebuild: false,
                    now: AnalysisPackageOwner::now(),
                },
                PackageActionV1::Run,
                &crate::AnalysisReadControl::default(),
            )
            .err()
            .ok_or("input authority accepted")?;
        assert_eq!(error.package_code(), PackageErrorCodeV1::Denied);
        assert_eq!(
            fixture.store.package_activation(&active.key)?,
            Some(active.clone())
        );
        assert_eq!(fixture.store.package_results(&active.key)?, before);
        drop(fixture.owner.query.reserve_evaluation([1; 16])?);
        drop(fixture.owner.query.memory().reserve_input(available)?);
        assert_eq!(available_input_bytes(&fixture.owner.query), available);
    }
    Ok(())
}

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
        assert_eq!(receipt.input_revisions[0].owner, "araphor-query.Inputs");
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
    use crate::model::AdmittedExport;
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
    let held_inputs = AdmittedExport::admit(&fixture.owner.query, &model, None)?
        .inputs
        .read(
            fixture.owner.query.clone(),
            fixture.grant.selection.clone(),
            active.key.scope_id.clone(),
            &control,
            now,
        )?;
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
    let inputs = AdmittedExport::admit(&fixture.owner.query, &model, None)?
        .inputs
        .read(
            fixture.owner.query.clone(),
            fixture.grant.selection.clone(),
            active.key.scope_id.clone(),
            &control,
            now,
        )?;
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
        inputs.dependencies().cloned().collect::<Vec<_>>(),
        vec![PackageResultRefV1 {
            result_id: receipt.result_id.clone(),
            commit_revision: receipt.commit_revision,
        }]
    );
    drop((inputs, held_inputs));
    drop(
        fixture
            .owner
            .query
            .memory()
            .reserve_input(fixture.owner.query.limits().input_capacity)?,
    );
    let released = crate::SqlDatasetOutputV1::query(
        &fixture.owner.query,
        [1; 16],
        &control,
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
    use crate::model::AdmittedExport;
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
                            "SELECT COUNT(*)::BIGINT UNSIGNED AS count FROM catalog WHERE LENGTH(description) + LENGTH(join_keys) + LENGTH(owner) > 0"
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
        let result = AdmittedExport::admit(&owner, &model, None)?
            .inputs
            .read(
                owner.clone(),
                fixture.grant.selection.clone(),
                active.key.scope_id.clone(),
                &control,
                now,
            )
            .map_err(crate::Error::from);
        let actual = if combined && !wide {
            Some(result.map_err(|error| format!("narrow input failed: limit={limit}, arrays={physical}, ipc={}, error={error:?}", packet.datasets[0].arrow_ipc.len()))?)
        } else {
            let error = result.as_ref().err().ok_or_else(|| {
                format!("input budget denial absent: combined={combined}, wide={wide}, limit={limit}, arrays={physical}, ipc={}", packet.datasets[0].arrow_ipc.len())
            })?;
            assert_eq!(
                error.package_code(),
                crate::PackageErrorCodeV1::Limit,
                "combined={combined}, wide={wide}, expected={resource}, error={error:?}"
            );
            None
        };
        let control = AnalysisReadControl::with_timeout(Duration::from_secs(30))?;
        let released = crate::SqlDatasetOutputV1::query(
            &owner,
            [1; 16],
            &control,
            &[],
            "SELECT 1::BIGINT UNSIGNED AS count",
            sdk::Limits::default(),
        )?;
        assert_eq!(released.data.batches[0].num_rows(), 1);
        drop(released);
        let inputs = AdmittedExport::admit(&fixture.owner.query, &model, None)?
            .inputs
            .read(
                fixture.owner.query.clone(),
                fixture.grant.selection.clone(),
                active.key.scope_id.clone(),
                &control,
                now,
            )?;
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
            assert_eq!(
                actual.dependencies().collect::<Vec<_>>(),
                inputs.dependencies().collect::<Vec<_>>()
            );
            assert_eq!(actual.source_revisions(), inputs.source_revisions());
            assert_eq!(
                actual.witnesses().collect::<Vec<_>>(),
                inputs.witnesses().collect::<Vec<_>>()
            );
            assert_eq!(
                actual.contexts().collect::<Vec<_>>(),
                inputs.contexts().collect::<Vec<_>>()
            );
        }
        drop(inputs);
        drop(
            owner
                .memory()
                .reserve_input(owner.limits().input_capacity)?,
        );
    }
    Ok(())
}
