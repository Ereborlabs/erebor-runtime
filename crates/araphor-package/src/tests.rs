use std::collections::BTreeMap;

use araphor_analysis_sdk as sdk;

use super::*;

pub(super) type TestResult<T = ()> =
    std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

pub(super) fn bundle(revision: &str, sql: &str) -> PackageBundleV1 {
    let mut descriptor = sdk::Package::new(
        "test.model",
        revision,
        vec![sdk::Model::new(
            "count",
            Vec::new(),
            vec![sdk::Port::new(
                "rows",
                sdk::Schema::new(vec![sdk::Field::new("count", sdk::DataType::UInt64, false)]),
            )],
        )],
    );
    descriptor.exports[0].input_mode = sdk::InputMode::Resolved;
    PackageBundleV1 {
        schema_version: 1,
        root: PackageRefV1 {
            package_id: descriptor.id.clone(),
            revision: revision.into(),
        },
        artifacts: vec![PackageArtifactV1 {
            descriptor,
            implementations: vec![PackageImplementationV1::Sql {
                export: "count".into(),
                program: SqlModelV1 {
                    outputs: BTreeMap::from([("rows".into(), sql.into())]),
                    ..Default::default()
                },
            }],
            fixtures: Vec::new(),
        }],
    }
}

#[test]
fn image_roundtrip_keeps_contract() -> TestResult {
    let mut image = bundle("1", "SELECT count FROM source");
    let artifact = &mut image.artifacts[0];
    let model = &mut artifact.descriptor.exports[0];
    let mut source = model.outputs[0].clone();
    source.name = "source".into();
    model.inputs = vec![
        sdk::InputPort {
            port: source.clone(),
            source: sdk::InputSource::Query("SELECT 1::BIGINT UNSIGNED AS count".into()),
        },
        sdk::InputPort {
            port: sdk::Port::new("baseline", source.schema.clone()),
            source: sdk::InputSource::Table(sdk::TableRef::Named("retained_baseline".into())),
        },
    ];
    model.parameters = sdk::Schema::new(vec![sdk::Field::new(
        "threshold",
        sdk::DataType::UInt64,
        false,
    )]);
    model.outputs[0].evidence_required = true;
    let mut details = sdk::Port::new(
        "details",
        sdk::Schema::new(vec![sdk::Field::new("reason", sdk::DataType::Utf8, false)]),
    );
    details.evidence_required = true;
    model.outputs.push(details.clone());
    model.checkpoint = Some(sdk::CheckpointSpec {
        version: 7,
        datasets: vec![sdk::Port::new("state", source.schema)],
    });
    model.reasons = vec![sdk::Reason {
        code: "test.model.MATCH".into(),
        details: details.schema,
    }];
    model.limits = sdk::Limits {
        max_batches: 17,
        max_rows: 8192,
        max_bytes: 128 * 1024,
        max_checkpoint_bytes: 32 * 1024,
    };
    model.tolerance = sdk::NumericTolerance {
        absolute: 0.001,
        relative: 0.0001,
    };
    let native = vec![0, 255, 4, 9];
    let dependency = vec![8, 1, 0, 254];
    artifact.implementations = vec![PackageImplementationV1::Native {
        export: "count".into(),
        artifact: native.clone(),
        qualification: Some(Qualification {
            exports: vec!["count".into()],
            target: "x86_64-unknown-linux-gnu".into(),
            cpu_features: vec!["sse2".into()],
            contract_version: 1,
            system_libraries: vec![LibraryRequirement {
                name: "libc.so.6".into(),
                symbols: vec!["memcpy".into()],
                versions: vec!["GLIBC_2.14".into()],
            }],
            dependencies: vec![Dependency {
                name: "helper.so".into(),
                digest: Qualification::digest(&dependency),
                artifact: dependency,
            }],
        }),
    }];
    let state = sdk::wire::Checkpoint {
        version: 7,
        datasets: vec![sdk::wire::Dataset {
            name: "state".into(),
            arrow_ipc: vec![0, 255, 3],
        }],
    };
    artifact.fixtures = (0..65)
        .map(|index| PackageFixtureV1 {
            name: format!("fixture-{index}"),
            export: "count".into(),
            time_utc_ns: 123,
            seed: Some(99),
            inputs: vec![sdk::wire::Input {
                data: sdk::wire::Dataset {
                    name: "source".into(),
                    arrow_ipc: vec![255, 1, 0],
                },
                revision: sdk::Revision {
                    owner: "fixture".into(),
                    id: "source-1".into(),
                    window: None,
                },
                coverage: sdk::Coverage {
                    state: sdk::CoverageState::Unknown,
                    limits: vec!["retained gap".into()],
                },
            }],
            parameters: Some(serde_json::json!({"threshold": 3})),
            checkpoint: Some(state.clone()),
            expected: sdk::wire::Output {
                datasets: vec![sdk::wire::Dataset {
                    name: "rows".into(),
                    arrow_ipc: vec![1, 0, 255],
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
                reasons: vec![sdk::wire::ReasonValue {
                    output: sdk::RowRef {
                        dataset: "rows".into(),
                        row: 0,
                    },
                    code: "test.model.MATCH".into(),
                    details: vec![9, 0, 255],
                }],
                checkpoint: Some(state.clone()),
            },
        })
        .collect();
    image.validate()?;
    let digest = image.digest()?;
    let bytes = image.encode()?;
    let restored = PackageBundleV1::from_bytes(&bytes)?;
    assert_eq!(restored.artifacts, image.artifacts);
    assert_eq!(restored.digest()?, digest);
    let metadata = restored.metadata()?;
    assert_eq!(metadata.root, restored.root);
    assert_eq!(metadata.digest, digest);
    assert_eq!(
        metadata.artifacts[0].descriptor,
        restored.artifacts[0].descriptor
    );
    assert_eq!(metadata.artifacts[0].fixtures.len(), 65);
    let implementation = &metadata.artifacts[0].implementations[0];
    assert_eq!(implementation.exports, vec!["count"]);
    assert_eq!(implementation.target, "native");
    assert_eq!(
        implementation
            .artifact
            .as_ref()
            .ok_or("artifact identity")?
            .digest,
        Qualification::digest(&native)
    );
    let json = serde_json::to_value(metadata)?;
    let implementation = &json["artifacts"][0]["implementations"][0];
    assert!(implementation.get("program").is_none());
    assert!(implementation.get("qualification").is_none());
    assert!(implementation["artifact"].is_object());
    Ok(())
}

#[test]
fn image_closure_has_no_count_cap() -> TestResult {
    let mut artifacts = Vec::new();
    for index in 0..300 {
        let mut artifact = bundle("1", "SELECT count FROM source").artifacts.remove(0);
        artifact.descriptor.id = format!("image{index}");
        if index != 299 {
            artifact.descriptor.exports[0].inputs = vec![sdk::InputPort {
                port: sdk::Port::new(
                    "source",
                    artifact.descriptor.exports[0].outputs[0].schema.clone(),
                ),
                source: sdk::InputSource::Table(sdk::TableRef::Output(sdk::OutputRef {
                    package: format!("image{}", index + 1),
                    revision: "1".into(),
                    export: "count".into(),
                    output: "rows".into(),
                })),
            }];
        }
        artifacts.push(artifact);
    }
    let mut image = PackageBundleV1 {
        schema_version: 1,
        root: artifacts[0].reference(),
        artifacts,
    };
    image.validate()?;
    let order = image.order()?;
    assert_eq!(order.len(), 300);
    assert_eq!(
        order.first().ok_or("first dependency")?.package.package_id,
        "image299"
    );
    assert_eq!(
        order.last().ok_or("root dependency")?.package.package_id,
        "image0"
    );
    let input = image.artifacts[0].descriptor.exports[0].outputs[0].clone();
    image.artifacts[299].descriptor.exports[0].inputs = vec![sdk::InputPort {
        port: input,
        source: sdk::InputSource::Table(sdk::TableRef::Output(sdk::OutputRef {
            package: "image0".into(),
            revision: "1".into(),
            export: "count".into(),
            output: "rows".into(),
        })),
    }];
    assert!(matches!(
        image.validate(),
        Err(Error::Package {
            code: ErrorCode::Invalid,
            ..
        })
    ));
    Ok(())
}
