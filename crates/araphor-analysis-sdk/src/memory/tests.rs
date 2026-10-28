use std::collections::HashMap;
use std::mem::size_of;
use std::sync::Arc;

use crate::{
    wire, CheckpointSpec, Coverage, CoverageState, DataType, Evaluation, EvaluationContext, Field,
    Input, InputPort, InputSource, Model, OutputRef, Package, Port, Reason, RecordBatch, Revision,
    Schema, SourceWindow, TableRef,
};

type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;

#[test]
fn package_reserves_are_charged() -> TestResult {
    let mut package = Package::new(
        "example",
        "1",
        vec![Model::new("run", Vec::new(), Vec::new())],
    );
    package.exports[0].inputs.push(InputPort {
        port: Port::new("input", Schema::empty()),
        source: InputSource::Table(TableRef::Output(OutputRef {
            package: "dependency".into(),
            revision: "1".into(),
            export: "run".into(),
            output: "output".into(),
        })),
    });
    let original = serde_json::to_vec(&package)?;
    let initial = package.allocated_bytes();
    let capacity = package.exports[0].inputs.capacity();
    package.exports[0].inputs.reserve_exact(capacity + 32);
    package.exports.reserve_exact(8);
    package.id.reserve_exact(256);
    package.revision.reserve_exact(128);
    let input = &mut package.exports[0].inputs[0];
    let InputSource::Table(TableRef::Output(dependency)) = &mut input.source else {
        return Err("output source absent".into());
    };
    for value in [
        &mut input.port.name,
        &mut dependency.package,
        &mut dependency.revision,
        &mut dependency.export,
        &mut dependency.output,
    ] {
        value.reserve_exact(64);
    }
    assert!(
        package.allocated_bytes()
            >= initial + 32 * size_of::<InputPort>() + 8 * size_of::<Model>() + 704
    );
    assert_eq!(serde_json::to_vec(&package)?, original);
    for source in [
        InputSource::Table(TableRef::Named("input".into())),
        InputSource::Query("SELECT 1".into()),
    ] {
        package.exports[0].inputs[0].source = source;
        let original = serde_json::to_vec(&package)?;
        let before = package.allocated_bytes();
        let (InputSource::Table(TableRef::Named(value)) | InputSource::Query(value)) =
            &mut package.exports[0].inputs[0].source
        else {
            return Err("table or query source absent".into());
        };
        value.reserve_exact(4096);
        assert!(package.allocated_bytes() >= before + 4096);
        assert_eq!(serde_json::to_vec(&package)?, original);
    }
    Ok(())
}

#[test]
fn model_reserves_are_charged() -> TestResult {
    let mut model = Model::new("run", Vec::new(), Vec::new());
    model.checkpoint = Some(CheckpointSpec {
        resume_input_changes: false,
        version: 1,
        datasets: Vec::new(),
    });
    let mut package = Package::new("example", "1", vec![model]);
    let original = serde_json::to_vec(&package)?;
    let initial = package.allocated_bytes();
    let model = &mut package.exports[0];
    model.inputs.reserve_exact(32);
    model.outputs.reserve_exact(32);
    model.reasons.reserve_exact(32);
    model.name.reserve_exact(64);
    model
        .checkpoint
        .as_mut()
        .ok_or("checkpoint missing")?
        .datasets
        .reserve_exact(32);
    assert!(
        package.allocated_bytes()
            >= initial
                + 64 * size_of::<Port>()
                + 32 * size_of::<InputPort>()
                + 32 * size_of::<Reason>()
                + 64
    );
    assert_eq!(serde_json::to_vec(&package)?, original);
    Ok(())
}

#[test]
fn empty_metadata_is_charged() -> TestResult {
    let mut package = Package::new(
        "example",
        "1",
        vec![Model::new("run", Vec::new(), Vec::new())],
    );
    let original = serde_json::to_vec(&package)?;
    let initial = package.allocated_bytes();
    package.exports[0].parameters = Schema::empty().with_metadata(HashMap::with_capacity(64));
    assert!(package.allocated_bytes() >= initial + 64 * size_of::<(String, String)>());
    assert_eq!(serde_json::to_vec(&package)?, original);
    Ok(())
}

#[test]
fn schemas_include_nested_metadata() -> TestResult {
    let mut model = Model::new(
        "run",
        vec![Port::new("input", Schema::empty())],
        vec![Port::new("output", Schema::empty())],
    );
    model.checkpoint = Some(CheckpointSpec {
        resume_input_changes: false,
        version: 1,
        datasets: vec![Port::new("state", Schema::empty())],
    });
    model.reasons.push(Reason {
        code: "example.reason".into(),
        details: Schema::empty(),
    });
    let mut package = Package::new("example", "1", vec![model]);
    for index in 0..5 {
        let initial = package.allocated_bytes();
        let mut field_text = String::with_capacity(4096);
        field_text.push('x');
        let field = Field::new("item", DataType::Binary, true)
            .with_metadata(HashMap::from([("detail".into(), field_text)]));
        let mut schema_text = String::with_capacity(8192);
        schema_text.push('x');
        let schema = Schema::new(vec![Field::new(
            "items",
            DataType::List(Arc::new(field)),
            false,
        )])
        .with_metadata(HashMap::from([("description".into(), schema_text)]));
        let model = &mut package.exports[0];
        match index {
            0 => model.parameters = schema,
            1 => model.inputs[0].port.schema = schema,
            2 => model.outputs[0].schema = schema,
            3 => model.reasons[0].details = schema,
            _ => {
                model
                    .checkpoint
                    .as_mut()
                    .ok_or("checkpoint missing")?
                    .datasets[0]
                    .schema = schema;
            }
        }
        assert!(
            package.allocated_bytes() >= initial + 12 * 1024,
            "schema {index}"
        );
    }
    Ok(())
}

#[test]
fn wire_reserves_are_charged() -> TestResult {
    let mut evaluation = wire::Evaluation {
        previous_outputs: vec![wire::Dataset {
            name: "previous".into(),
            arrow_ipc: Vec::new(),
        }],
        export_name: "run".into(),
        inputs: vec![wire::Input {
            data: wire::Dataset {
                name: "input".into(),
                arrow_ipc: Vec::new(),
            },
            revision: Revision {
                owner: "owner".into(),
                id: "1".into(),
                window: None,
            },
            coverage: Coverage {
                state: CoverageState::Complete,
                limits: Vec::new(),
            },
        }],
        parameters: Some(Vec::new()),
        context: EvaluationContext {
            id: "evaluation".into(),
            time_utc_ns: 1,
            seed: None,
        },
        checkpoint: Some(wire::Checkpoint {
            version: 1,
            datasets: vec![wire::Dataset {
                name: "state".into(),
                arrow_ipc: Vec::new(),
            }],
        }),
    };
    let initial = evaluation.allocated_bytes();
    evaluation.previous_outputs.reserve_exact(3);
    evaluation.previous_outputs[0].arrow_ipc.reserve_exact(512);
    evaluation.inputs.reserve_exact(4);
    evaluation.inputs[0].data.arrow_ipc.reserve_exact(4096);
    evaluation
        .parameters
        .as_mut()
        .ok_or("parameters missing")?
        .reserve_exact(2048);
    evaluation.export_name.reserve_exact(64);
    evaluation.context.id.reserve_exact(64);
    let checkpoint = evaluation.checkpoint.as_mut().ok_or("checkpoint missing")?;
    checkpoint.datasets.reserve_exact(4);
    checkpoint.datasets[0].arrow_ipc.reserve_exact(1024);
    assert!(
        evaluation.allocated_bytes()
            >= initial + 7808 + 4 * size_of::<wire::Input>() + 7 * size_of::<wire::Dataset>()
    );
    assert!(evaluation.previous_outputs[0].arrow_ipc.is_empty());
    assert!(evaluation.inputs[0].data.arrow_ipc.is_empty());
    assert!(evaluation
        .parameters
        .as_ref()
        .ok_or("parameters missing")?
        .is_empty());
    Ok(())
}

#[test]
fn wire_retains_input_metadata() -> TestResult {
    let schema = Schema::new(vec![Field::new("value", DataType::UInt64, false)]);
    let package = Package::new(
        "example",
        "1",
        vec![Model::new(
            "run",
            vec![Port::new("input", schema.clone())],
            vec![Port::new("output", schema.clone())],
        )],
    );
    let mut evaluation = Evaluation {
        previous_outputs: Vec::new(),
        export: "run".into(),
        inputs: vec![Input {
            data: crate::Dataset {
                name: "input".into(),
                batches: vec![RecordBatch::new_empty(Arc::new(schema))],
            },
            revision: Revision {
                owner: "owner".into(),
                id: "1".into(),
                window: None,
            },
            coverage: Coverage {
                state: CoverageState::Complete,
                limits: Vec::new(),
            },
        }],
        parameters: None,
        context: EvaluationContext {
            id: "evaluation".into(),
            time_utc_ns: 1,
            seed: None,
        },
        checkpoint: None,
    };
    let original = package.check_evaluation(&evaluation)?.encode()?;
    let input = &mut evaluation.inputs[0];
    input.revision.owner = "o".repeat(128);
    input.revision.id = "r".repeat(3072);
    input.revision.window = Some(SourceWindow {
        source: vec![0; 2048],
        start_utc_ns: 0,
        end_utc_ns: 1,
    });
    input.coverage = Coverage {
        state: CoverageState::Gapped,
        limits: vec!["gap".repeat(1024)],
    };
    let retained = package.check_evaluation(&evaluation)?.encode()?;
    assert_eq!(
        retained.inputs[0].data.arrow_ipc,
        original.inputs[0].data.arrow_ipc
    );
    assert!(retained.allocated_bytes() >= original.allocated_bytes() + 8192);
    assert_eq!(retained.inputs[0].revision, evaluation.inputs[0].revision);
    assert_eq!(retained.inputs[0].coverage, evaluation.inputs[0].coverage);
    Ok(())
}

#[test]
fn dataset_metadata_keeps_headers() -> TestResult {
    use arrow_array::{ArrayRef, NullArray, StructArray, UInt64Array};

    let child = Arc::new(Field::new("missing", DataType::Null, true));
    let nested: ArrayRef = Arc::new(StructArray::from(vec![(
        child,
        Arc::new(NullArray::new(1)) as ArrayRef,
    )]));
    let schema = Arc::new(Schema::new(vec![
        Field::new("left", DataType::UInt64, false),
        Field::new("right", DataType::UInt64, false),
        Field::new("nested", nested.data_type().clone(), false),
    ]));
    let dataset = |array: ArrayRef| -> crate::Result<crate::Dataset> {
        Ok(crate::Dataset {
            name: "rows".into(),
            batches: vec![RecordBatch::try_new(
                Arc::clone(&schema),
                vec![Arc::clone(&array), array, Arc::clone(&nested)],
            )?],
        })
    };
    let allocation: ArrayRef = Arc::new(UInt64Array::from(vec![7; 4096]));
    let mut aliased = dataset(allocation.slice(2048, 1))?;
    let compact = dataset(Arc::new(UInt64Array::from(vec![7])))?;
    assert!(aliased.allocated_bytes() > compact.allocated_bytes() + 4096);
    assert_eq!(aliased.metadata_bytes(), compact.metadata_bytes());
    assert!(
        aliased.metadata_bytes()
            >= 2 * size_of::<UInt64Array>()
                + size_of::<StructArray>()
                + size_of::<NullArray>()
                + 3 * size_of::<ArrayRef>()
    );
    let before = aliased.metadata_bytes();
    let mut metadata = HashMap::new();
    metadata.reserve(64);
    let schema = Arc::new(Schema::new_with_metadata(schema.fields().clone(), metadata));
    aliased.batches[0] = RecordBatch::try_new(schema, aliased.batches[0].columns().to_vec())?;
    assert!(aliased.metadata_bytes() >= before + 64 * size_of::<(String, String)>());

    let mut input = Input {
        data: aliased,
        revision: Revision {
            owner: "owner".into(),
            id: "1".into(),
            window: Some(SourceWindow {
                source: Vec::new(),
                start_utc_ns: 0,
                end_utc_ns: 1,
            }),
        },
        coverage: Coverage {
            state: CoverageState::Complete,
            limits: Vec::new(),
        },
    };
    let before = input.metadata_bytes();
    let data_metadata = input.data.metadata_bytes();
    input.revision.owner.reserve_exact(1024);
    input.revision.id.reserve_exact(1024);
    input
        .revision
        .window
        .as_mut()
        .ok_or("input window")?
        .source
        .reserve_exact(2048);
    input.coverage.limits.reserve_exact(64);
    assert!(input.metadata_bytes() >= before + 4096 + 64 * size_of::<String>());
    assert_eq!(input.data.metadata_bytes(), data_metadata);
    Ok(())
}

#[test]
fn prior_buffers_are_charged() -> TestResult {
    let mut evaluation = crate::tests::files_count::FilesCount::fixture()?.evaluation;
    let before = evaluation.allocated_bytes();
    let scratch = evaluation.encoding_scratch_bytes()?;
    let output = crate::tests::files_count::FilesCount::evaluate(&evaluation)?;
    evaluation.previous_outputs = output.datasets;
    let state_bytes = evaluation
        .previous_outputs
        .iter()
        .flat_map(|data| &data.batches)
        .map(RecordBatch::get_array_memory_size)
        .sum::<usize>();
    assert!(state_bytes > 0);
    assert!(evaluation.allocated_bytes() >= before + state_bytes);
    let state_scratch = evaluation
        .previous_outputs
        .iter()
        .flat_map(|data| &data.batches)
        .try_fold(0usize, |bytes, batch| {
            wire::Dataset::encoding_scratch(batch).map(|next| bytes + next)
        })?;
    assert!(state_scratch > 0);
    assert_eq!(
        evaluation.encoding_scratch_bytes()?,
        scratch + state_scratch
    );
    Ok(())
}
