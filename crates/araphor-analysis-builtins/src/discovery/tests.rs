use araphor_analysis_sdk as sdk;

use super::*;
use super::{
    BehaviorAtomV1 as Atom, DiscoveryCoverageStateV1 as CoverageState,
    DiscoveryCoverageV1 as Coverage, DiscoveryLifecycleEntryV1 as Lifecycle,
    DiscoveryUnresolvedV1 as Disposition,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn declaration_clones_keep_ports() -> TestResult {
    let mut first = Discovery::package();
    let second = Discovery::package();
    assert_eq!(first, second);
    assert!(std::sync::Arc::ptr_eq(
        &first.exports[0].inputs[0].port.schema.fields()[0],
        &second.exports[0].inputs[0].port.schema.fields()[0],
    ));
    first.exports[0].inputs[0].port.name = "changed".into();
    assert_eq!(Discovery::package(), second);
    let fixture = fixture()?;
    let mut other = second;
    other.id = "other".into();
    let checked = other.check_evaluation(&fixture.evaluation)?;
    assert!(
        matches!(<Discovery as sdk::Guest>::compute(&checked), Err(sdk::Error::Contract {
        code: sdk::ErrorCode::Incompatible, field, ..
    }) if field == "discovery package")
    );
    Ok(())
}

#[test]
fn checked_input_keeps_json_errors() -> TestResult {
    let package = Discovery::package();
    let mut fixture = fixture()?;
    let contexts = &mut fixture.evaluation.inputs[1].data;
    contexts.batches = vec![sdk::RecordBatch::try_new(
        contexts.batches[0].schema(),
        vec![std::sync::Arc::new(sdk::arrow_array::BinaryArray::from(
            vec![b"{".as_slice()],
        ))],
    )?];
    let checked = package.check_evaluation(&fixture.evaluation)?;
    assert!(matches!(
        <Discovery as sdk::Guest>::compute(&checked),
        Err(sdk::Error::Encoding { .. })
    ));
    Ok(())
}

fn fixture() -> sdk::Result<sdk::Fixture> {
    let key = atom_key();
    let id = |cursor| DiscoveryRecordIdV1 {
        stream: key.stream.clone(),
        cpu_id: 3,
        durable_cursor: cursor,
    };
    let records: Vec<_> = [1, 2, 1]
        .into_iter()
        .map(|cursor| Record {
            id: id(cursor),
            bytes: format!("exact-frame-{cursor}").into_bytes().into(),
            temporal: 1,
            effect: key.effect.clone(),
            generation: Some(9_007_199_254_740_999),
            original_sequence: Some(cursor + 100),
            source: None,
        })
        .collect();
    let contexts: Vec<_> = (1..=2)
        .map(|cursor| Context {
            atom_key: Some(key.clone()),
            record_id: id(cursor),
        })
        .collect();
    let datasets = vec![
        Record::encode(&records)?,
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
                stream: key.stream.clone(),
                cpu_id: 3,
                first_cursor: 1,
                last_cursor: 2,
                expected_records: 2,
                coverage_revision: 9_007_199_254_740_999,
                coverage_interval_id: [4; 16],
                state: CoverageState::Healthy,
                gap_reasons: Vec::new(),
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
    assert_eq!(
        atoms[0].key.physical_result,
        DiscoveryPhysicalResultV1::Prevented
    );
    assert_eq!(
        atoms[0]
            .evidence_sample
            .iter()
            .map(|id| id.durable_cursor)
            .collect::<Vec<_>>(),
        vec![1, 2]
    );
    assert_eq!(
        output::<Coverage>(&report.output, "coverage")?[0].coverage_revision,
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
    let mut records = Record::decode(&input.data)?;
    records[2].bytes.to_mut().extend_from_slice(b"changed");
    let changed = Record::encode(&records)?;
    drop(records);
    input.data = changed;
    assert!(
        matches!(Discovery::package().test(&fixture, Discovery::evaluate), Err(sdk::Error::Contract { code: sdk::ErrorCode::Incompatible, field, .. }) if field == "record bytes")
    );
    Ok(())
}

#[test]
fn sdk_bounded_derivation() -> TestResult {
    let mut fixture = fixture()?;
    for bounds in [
        sdk::Limits {
            max_rows: 1,
            ..Discovery::limits()
        },
        sdk::Limits {
            max_bytes: 64,
            ..Discovery::limits()
        },
    ] {
        fixture.evaluation.context.limits = bounds;
        assert!(matches!(
            Discovery::evaluate(&fixture.evaluation),
            Err(sdk::Error::Contract {
                code: sdk::ErrorCode::Limit,
                ..
            })
        ));
    }
    let port = Record::port();
    for name in ["original_sequence", "generation"] {
        let field = port.schema.field_with_name(name)?;
        assert_eq!(field.data_type(), &sdk::DataType::UInt64);
        assert!(field.is_nullable());
    }
    Ok(())
}

#[test]
fn native_record_roundtrip() -> TestResult {
    let fixture = fixture()?;
    let data = &fixture.evaluation.inputs[0].data;
    let bytes = data.batches[0]
        .column(1)
        .as_any()
        .downcast_ref::<sdk::arrow_array::BinaryArray>()
        .ok_or("frame column")?;
    let mut records = Record::decode(data)?;
    assert!(matches!(records[0].bytes, std::borrow::Cow::Borrowed(_)));
    assert_eq!(records[0].bytes.as_ptr(), bytes.value(0).as_ptr());
    records[0].source = Some(Lifetime {
        process: vec![1; 16],
        entry: vec![2; 16],
        binding: vec![3; 16],
        role: 4,
        state: 5,
        rule: 6,
        sequence: u64::MAX,
    });
    records[0].effect.exact_file_object = Some(DiscoveryFileObjectV1 {
        profile_generation_ref_id: u64::MAX,
        mount_id_unique: 2,
        inode: 3,
        inode_generation: 4,
        mount_namespace_inode: 5,
        filesystem_device: 6,
    });
    records[0].effect.target_task_cookie = Some(u64::MAX);
    records[0].effect.operation_argument = None;
    records[0].generation = None;
    records[0].original_sequence = Some(u64::MAX);
    records[0].bytes = (&b"\0\xfforiginal-frame"[..]).into();
    let encoded = Record::encode(&records)?;
    let decoded = Record::decode(&encoded)?;
    assert_eq!(
        serde_json::to_value(&decoded)?,
        serde_json::to_value(&records)?
    );
    let mut empty = encoded.clone();
    empty.batches.clear();
    assert!(Record::decode(&empty)?.is_empty());
    assert_eq!(Record::encode(&[])?.batches[0].num_rows(), 0);
    let mut invalid = serde_json::to_value(&records)?;
    invalid[0]["id"]["stream"]["tenant_id"] = serde_json::json!([1, 2]);
    let batch = serde_arrow::to_record_batch(Record::port().schema.fields(), &invalid)?;
    let invalid = sdk::Dataset {
        name: "records".into(),
        batches: vec![batch],
    };
    assert!(matches!(
        Record::decode(&invalid),
        Err(sdk::Error::Batch { .. })
    ));
    Ok(())
}

#[test]
fn record_pages_keep_proof() -> TestResult {
    let mut fixture = fixture()?;
    let expected = Discovery::evaluate(&fixture.evaluation)?;
    {
        let data = &mut fixture.evaluation.inputs[0].data;
        let batch = data.batches.remove(0);
        data.batches = vec![batch.slice(0, 2), batch.slice(2, 1)];
    }
    let actual = Discovery::evaluate(&fixture.evaluation)?;
    assert_eq!(actual.datasets.len(), expected.datasets.len());
    for (actual, expected) in actual.datasets.iter().zip(&expected.datasets) {
        assert_eq!(actual.name, expected.name);
        assert_eq!(actual.batches, expected.batches);
    }
    let mut records = Record::decode(&fixture.evaluation.inputs[0].data)?;
    records[1].id.cpu_id += 1;
    let changed = Record::encode(&records)?;
    drop(records);
    fixture.evaluation.inputs[0].data = changed;
    assert!(matches!(
        Discovery::evaluate(&fixture.evaluation),
        Err(sdk::Error::Contract {
            code: sdk::ErrorCode::Invalid,
            field,
            ..
        }) if field == "orphan context"
    ));
    fixture.evaluation.inputs[1].data.batches.clear();
    assert!(matches!(
        Discovery::evaluate(&fixture.evaluation),
        Err(sdk::Error::Contract {
            code: sdk::ErrorCode::Invalid,
            field,
            ..
        }) if field == "record range"
    ));
    Ok(())
}

fn atom_key() -> BehaviorAtomKeyV1 {
    BehaviorAtomKeyV1 {
        stream: EvidenceIntakeIdentityV1 {
            tenant_id: [1; 16],
            node_id: "node".into(),
            node_boot_id: [2; 16],
            label_epoch: 1,
            source_id: [3; 16],
            source_epoch: 1,
        },
        cpu_id: 3,
        subject_revision: "subject".into(),
        image_digest: "image".into(),
        configuration_digest: "config".into(),
        process_instance_id: [1; 16],
        entry_instance_id: [2; 16],
        binding_id: [3; 16],
        role_id: 1,
        state_id: 1,
        entry_rule_id: 1,
        catalog_revision: 1,
        static_key: DiscoveryPolicyKeyV1 {
            workload_selector_id: "workload".into(),
            protected_scope_id: "scope".into(),
            execution_set_id: "execution".into(),
            entry_kind: "entry".into(),
            role_id: "role".into(),
            process_state_id: "state".into(),
            effect_family: 1,
            operation_id: "operation".into(),
            operation: 1,
            operation_argument: 0,
            argument_wildcard: false,
            object_selector: "object".into(),
            binding_lifecycle: "lifecycle".into(),
        },
        policy_revision: DiscoveryPolicyRevisionV1 {
            profile_id: "profile".into(),
            profile_version: 1,
            source_revision_id: "source".into(),
            signed_profile_digest: "digest".into(),
        },
        generation: 9_007_199_254_740_999,
        coverage_interval_id: [4; 16],
        temporal_coverage: 1,
        effect: DiscoveryEffectKeyV1 {
            task_cookie: 7,
            target_task_cookie: None,
            process_lineage_id: Vec::new(),
            authority_domain_id: Vec::new(),
            execution_set_id: Vec::new(),
            exact_object_id: vec![7; 16],
            destination_id: 0,
            policy_rule_id: 1,
            reason: 0,
            decision: 1,
            effect_family: 1,
            operation: 1,
            operation_argument: Some(0),
            configured_errno: -13,
            kernel_result: -13,
            exact_file_object: None,
        },
        physical_result: DiscoveryPhysicalResultV1::Unknown,
        proof_kind: DiscoveryProofKindV1::RecordedInput,
    }
}
