use std::collections::HashMap;
use std::mem::size_of;
use std::sync::Arc;

use crate::{
    CheckpointSpec, Coverage, CoverageState, DataType, Dependency, Evaluation, EvaluationContext,
    Field, Input, Limits, Model, Package, Port, Reason, RecordBatch, Revision, Schema,
    SourceWindow, wire,
};

type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;

#[test]
fn package_reserves_are_charged() -> TestResult {
    let mut package = Package::new(
        "example",
        "1",
        vec![Model::new("run", Vec::new(), Vec::new())],
    );
    package.dependencies.push(Dependency {
        model: "run".into(),
        input: "input".into(),
        package: "dependency".into(),
        revision: "1".into(),
        export: "run".into(),
        output: "output".into(),
    });
    let original = serde_json::to_vec(&package)?;
    let initial = package.allocated_bytes();
    let capacity = package.dependencies.capacity();
    package.dependencies.reserve_exact(capacity + 32);
    package.exports.reserve_exact(8);
    package.id.reserve_exact(256);
    package.revision.reserve_exact(128);
    let dependency = &mut package.dependencies[0];
    for value in [
        &mut dependency.model,
        &mut dependency.input,
        &mut dependency.package,
        &mut dependency.revision,
        &mut dependency.export,
        &mut dependency.output,
    ] {
        value.reserve_exact(64);
    }
    assert!(
        package.allocated_bytes()
            >= initial + 32 * size_of::<Dependency>() + 8 * size_of::<Model>() + 768
    );
    assert_eq!(serde_json::to_vec(&package)?, original);
    Ok(())
}

#[test]
fn model_reserves_are_charged() -> TestResult {
    let mut model = Model::new("run", Vec::new(), Vec::new());
    model.checkpoint = Some(CheckpointSpec {
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
            >= initial + 96 * size_of::<Port>() + 32 * size_of::<Reason>() + 64
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
            1 => model.inputs[0].schema = schema,
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
            limits: Limits::default(),
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
            >= initial + 7296 + 4 * size_of::<wire::Input>() + 4 * size_of::<wire::Dataset>()
    );
    assert!(evaluation.inputs[0].data.arrow_ipc.is_empty());
    assert!(
        evaluation
            .parameters
            .as_ref()
            .ok_or("parameters missing")?
            .is_empty()
    );
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
            limits: Limits::default(),
        },
        checkpoint: None,
    };
    let original = wire::Evaluation::encode(&package, &evaluation)?;
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
    let retained = wire::Evaluation::encode(&package, &evaluation)?;
    assert_eq!(
        retained.inputs[0].data.arrow_ipc,
        original.inputs[0].data.arrow_ipc
    );
    assert!(retained.allocated_bytes() >= original.allocated_bytes() + 8192);
    assert_eq!(retained.inputs[0].revision, evaluation.inputs[0].revision);
    assert_eq!(retained.inputs[0].coverage, evaluation.inputs[0].coverage);
    Ok(())
}
