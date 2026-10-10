use arrow_array::{BinaryArray, BooleanArray};

use super::*;

#[test]
fn selected_graph_keeps_version_manifest() -> TestResult {
    let mut package = FilesCount::package();
    let subjects = Schema::new(vec![
        Field::new("result_id", DataType::Utf8, false),
        Field::new("subject_key", DataType::Binary, false),
    ]);
    let manifest = Schema::new(vec![
        Field::new("result_id", DataType::Utf8, false),
        Field::new("source_key", DataType::Binary, false),
        Field::new("hop_boundary", DataType::Boolean, false),
    ]);
    package.exports[0].inputs.extend([
        Port::new("subjects", subjects.clone()),
        Port::new("selection", manifest.clone()),
    ]);
    let mut fixture = FilesCount::fixture()?;
    let keys: Vec<&[u8]> = vec![
        b"tenant.1/node.1/boot.1/process.1",
        b"tenant.1/node.2/boot.2/process.1",
    ];
    let sources: Vec<&[u8]> = vec![
        b"tenant.1/node.1/boot.1/source.1",
        b"tenant.1/node.2/boot.2/source.2",
    ];
    for (name, schema, arrays) in [
        (
            "subjects",
            subjects,
            vec![
                Arc::new(StringArray::from(vec!["result.1", "result.1"])) as arrow_array::ArrayRef,
                Arc::new(BinaryArray::from(keys.clone())),
            ],
        ),
        (
            "selection",
            manifest,
            vec![
                Arc::new(StringArray::from(vec!["result.1", "replacement.empty.2"]))
                    as arrow_array::ArrayRef,
                Arc::new(BinaryArray::from(sources)),
                Arc::new(BooleanArray::from(vec![true, false])),
            ],
        ),
    ] {
        fixture.evaluation.inputs.push(Input {
            data: Dataset {
                name: name.into(),
                batches: vec![RecordBatch::try_new(Arc::new(schema), arrays)?],
            },
            revision: Revision {
                owner: "AnalysisStore".into(),
                id: "read.revision.7".into(),
                window: None,
            },
            coverage: Coverage {
                state: CoverageState::Complete,
                limits: vec![],
            },
        });
    }
    let report = package.test(&fixture, FilesCount::evaluate)?;
    assert_eq!(report.inputs["selection"].0.id, "read.revision.7");
    let batch = &fixture.evaluation.inputs[1].data.batches[0];
    let retained = batch
        .column(1)
        .as_any()
        .downcast_ref::<BinaryArray>()
        .ok_or("subject keys")?;
    assert_eq!(retained.value(0), keys[0]);
    assert_eq!(retained.value(1), keys[1]);
    let manifest = &fixture.evaluation.inputs[2].data.batches[0];
    assert_eq!(manifest.num_rows(), 2);
    assert_eq!(
        manifest
            .column(0)
            .as_any()
            .downcast_ref::<StringArray>()
            .ok_or("result IDs")?
            .value(1),
        "replacement.empty.2"
    );
    Ok(())
}

#[test]
fn dependency_has_one_input_binding() -> TestResult {
    let mut package = FilesCount::package();
    let output = package.exports[0].outputs[0].clone();
    package.exports.push(Model::new(
        "count.review",
        vec![Port::new("prior", output.schema.clone())],
        vec![Port::new("selected", output.schema)],
    ));
    let dependency = Dependency {
        model: "count.review".into(),
        input: "prior".into(),
        package: package.id.clone(),
        revision: package.revision.clone(),
        export: "files.count".into(),
        output: "counts".into(),
    };
    package.dependencies.push(dependency.clone());
    package.validate()?;
    let decoded: Package = serde_json::from_str(&package.inspect()?)?;
    assert_eq!(decoded.dependencies, package.dependencies);
    package.dependencies.push(dependency);
    assert!(package.validate().is_err());
    package.dependencies.pop();
    package.dependencies[0].input = "absent".into();
    assert!(package.validate().is_err());
    Ok(())
}
