use araphor_analysis_sdk as sdk;

use super::*;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn fixture() -> sdk::Result<sdk::Fixture> {
    let operation = Operation {
        family: 1,
        operation: 1,
        argument: 0,
        wildcard: false,
    };
    let records: Vec<_> = [1, 2, 1]
        .into_iter()
        .map(|cursor| Record {
            id: Identity {
                order: cursor,
                value: format!("source/cpu3/{cursor}"),
            },
            bytes: format!("exact-frame-{cursor}"),
            cursor,
            range: 0,
            temporal: 1,
            operation: operation.clone(),
            generation: Some(9_007_199_254_740_999),
            object: vec![7; 16],
            decision: 1,
            kernel_result: -13,
            original_sequence: Some(cursor + 100),
            source: None,
        })
        .collect();
    let contexts: Vec<_> = (1..=2)
        .map(|cursor| Context {
            atom_key: Some("complete-host-atom-key".into()),
            record: format!("source/cpu3/{cursor}"),
            operation: operation.clone(),
            lifetime: Lifetime {
                process: vec![1; 16],
                entry: vec![2; 16],
                binding: vec![3; 16],
                role: 1,
                state: 1,
                rule: 1,
                sequence: 0,
            },
        })
        .collect();
    let datasets = vec![
        Rows::encode(
            &Discovery::port::<Record>("records"),
            &records,
            Discovery::limits(),
        )?,
        Rows::encode(
            &Discovery::port::<Context>("contexts"),
            &contexts,
            Discovery::limits(),
        )?,
        Rows::encode::<Disposition>(
            &Discovery::port::<Disposition>("exclusions"),
            &[],
            Discovery::limits(),
        )?,
        Rows::encode::<Lifecycle>(
            &Discovery::port::<Lifecycle>("lifecycle"),
            &[],
            Discovery::limits(),
        )?,
        Rows::encode(
            &Discovery::port::<bool>("observed"),
            &[false],
            Discovery::limits(),
        )?,
        Rows::encode(
            &Discovery::port::<Coverage>("coverage"),
            &[Coverage {
                source: "complete-source-identity".into(),
                cpu: 3,
                first: 1,
                last: 2,
                expected: 2,
                revision: 9_007_199_254_740_999,
                interval: [4; 16],
                state: CoverageState::Healthy,
                gaps: Vec::new(),
            }],
            Discovery::limits(),
        )?,
    ];
    Ok(sdk::Fixture {
        implementation: "trusted-builtins-rust".into(),
        revision: "recorded-derivation-v1".into(),
        evaluation: sdk::Evaluation {
            export: "atoms".into(),
            inputs: datasets
                .into_iter()
                .map(|data| sdk::Input {
                    data,
                    revision: sdk::Revision {
                        owner: "fixture".into(),
                        id: "9007199254740999".into(),
                        window: Some(sdk::SourceWindow {
                            source: vec![7],
                            start_utc_ns: 9_007_199_254_740_993,
                            end_utc_ns: 9_007_199_254_740_999,
                        }),
                    },
                    coverage: sdk::Coverage {
                        state: sdk::CoverageState::Complete,
                        limits: Vec::new(),
                    },
                })
                .collect(),
            parameters: None,
            context: sdk::EvaluationContext {
                id: "fixture".into(),
                time_utc_ns: 9_007_199_254_740_999,
                seed: None,
                limits: Discovery::limits(),
            },
            checkpoint: None,
        },
    })
}

fn output<T: serde::de::DeserializeOwned + JsonSchema>(
    result: &sdk::Output,
    name: &str,
) -> sdk::Result<Vec<T>> {
    let data = result
        .datasets
        .iter()
        .find(|data| data.name == name)
        .ok_or_else(|| sdk::Error::contract(sdk::ErrorCode::Invalid, "fixture output"))?;
    Rows::decode(&Discovery::port::<T>(name), data, Discovery::limits())
}

#[test]
fn sdk_derivation_fixture() -> TestResult {
    let fixture = fixture()?;
    let package = Discovery::package();
    let report = package.test(&fixture, Discovery::evaluate)?;
    assert_eq!(report.package_id, "discovery");
    assert_eq!(report.context.time_utc_ns, 9_007_199_254_740_999);
    let counts = output::<Counts>(&report.output, "counts")?;
    assert_eq!(
        counts,
        vec![Counts {
            duplicates: 1,
            accepted: 2,
            included: 2,
            unresolved: 0,
            excluded: 0
        }]
    );
    let atoms = output::<Atom>(&report.output, "atoms")?;
    assert_eq!(atoms.len(), 1);
    assert_eq!(atoms[0].count, 2);
    assert!(atoms[0].prevented);
    assert_eq!(
        atoms[0]
            .samples
            .iter()
            .map(|id| id.order)
            .collect::<Vec<_>>(),
        vec![1, 2]
    );
    assert_eq!(
        output::<Coverage>(&report.output, "coverage")?[0].revision,
        9_007_199_254_740_999
    );
    assert_eq!(output::<Lifecycle>(&report.output, "lifecycle")?.len(), 9);
    Ok(())
}

#[test]
fn sdk_conflicting_record() -> TestResult {
    let mut fixture = fixture()?;
    let input = fixture
        .evaluation
        .inputs
        .iter_mut()
        .find(|input| input.data.name == "records")
        .ok_or("records absent")?;
    let port = Discovery::port::<Record>("records");
    let mut records: Vec<Record> = Rows::decode(&port, &input.data, Discovery::limits())?;
    records[2].bytes.push_str("changed");
    input.data = Rows::encode(&port, &records, Discovery::limits())?;
    assert!(
        matches!(Discovery::package().test(&fixture, Discovery::evaluate), Err(sdk::Error::Contract { code: sdk::ErrorCode::Incompatible, field, .. }) if field == "record bytes")
    );
    Ok(())
}

#[test]
fn sdk_bounded_derivation() -> TestResult {
    let mut fixture = fixture()?;
    fixture.evaluation.context.limits.max_rows = 1;
    assert!(matches!(
        Discovery::evaluate(&fixture.evaluation),
        Err(sdk::Error::Contract {
            code: sdk::ErrorCode::Limit,
            ..
        })
    ));
    fixture.evaluation.context.limits = Discovery::limits();
    fixture.evaluation.context.limits.max_bytes = 64;
    assert!(matches!(
        Discovery::evaluate(&fixture.evaluation),
        Err(sdk::Error::Contract {
            code: sdk::ErrorCode::Limit,
            ..
        })
    ));
    let port = Discovery::port::<Record>("records");
    let schema = &port.schema.field(0).metadata()["araphor.json_schema"];
    assert!(schema.contains("original_sequence"));
    assert!(schema.contains("generation"));
    Ok(())
}
