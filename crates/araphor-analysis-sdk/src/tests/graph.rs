use arrow_array::{BinaryArray, BooleanArray, TimestampNanosecondArray};

use super::*;

mod fixture;
use fixture::{SelectedGraph, KEYS, SOURCES, WINDOW_START};

#[test]
fn graph_keeps_version_manifest() -> TestResult {
    let graph = SelectedGraph::new()?;
    let report = graph
        .package
        .test(&graph.fixture, |input| graph.evaluate(input))?;
    let subjects = &report.output.datasets[0].batches[0];
    assert_eq!(
        SelectedGraph::column::<StringArray>(subjects, 0)?
            .iter()
            .flatten()
            .collect::<Vec<_>>(),
        ["result.1", "result.1", "result.2", "result.2"]
    );
    let keys = SelectedGraph::column::<BinaryArray>(subjects, 1)?;
    assert_eq!(
        keys.iter().flatten().collect::<Vec<_>>(),
        [KEYS[0], KEYS[1], KEYS[0], KEYS[2]]
    );
    let relationships = &report.output.datasets[1].batches[0];
    assert_eq!(
        SelectedGraph::column::<BinaryArray>(relationships, 1)?
            .iter()
            .flatten()
            .collect::<Vec<_>>(),
        [KEYS[0], KEYS[0]]
    );
    assert_eq!(
        SelectedGraph::column::<BinaryArray>(relationships, 2)?
            .iter()
            .flatten()
            .collect::<Vec<_>>(),
        [KEYS[1], KEYS[2]]
    );
    let selection = &report.output.datasets[2].batches[0];
    assert_eq!(
        SelectedGraph::column::<StringArray>(selection, 0)?
            .iter()
            .flatten()
            .collect::<Vec<_>>(),
        ["result.1", "result.2", "replacement.empty.3"]
    );
    assert_eq!(
        SelectedGraph::column::<BinaryArray>(selection, 1)?
            .iter()
            .flatten()
            .collect::<Vec<_>>(),
        [SOURCES[0], SOURCES[1], SOURCES[0]]
    );
    assert_eq!(
        SelectedGraph::column::<BooleanArray>(selection, 2)?
            .values()
            .iter()
            .collect::<Vec<_>>(),
        [true, false, false]
    );
    assert_eq!(
        SelectedGraph::column::<TimestampNanosecondArray>(selection, 3)?.value(2),
        WINDOW_START + 10
    );
    assert_eq!(
        SelectedGraph::column::<TimestampNanosecondArray>(selection, 4)?.value(2),
        WINDOW_START + 19
    );
    assert_eq!(
        SelectedGraph::column::<UInt64Array>(selection, 5)?
            .values()
            .as_ref(),
        [2, 2, 0]
    );
    assert_eq!(
        SelectedGraph::column::<UInt64Array>(selection, 6)?
            .values()
            .as_ref(),
        [1, 1, 0]
    );
    assert_eq!(report.output.evidence.len(), 9);
    let mut limited = graph.fixture.clone();
    limited.evaluation.context.limits.max_rows = 8;
    let mut executed = false;
    let result = graph.package.test(&limited, |_| {
        executed = true;
        Ok(Output::default())
    });
    assert_eq!(
        result.err().ok_or("oversized input passed")?.code(),
        ErrorCode::Limit
    );
    assert!(!executed);
    Ok(())
}

#[test]
fn dependency_has_one_binding() -> TestResult {
    let mut package = FilesCount::package();
    let output = package.exports[0].outputs[0].clone();
    package.exports.push(Model::new(
        "count.review",
        vec![Port::new("prior", output.schema.clone())],
        vec![Port::new("selected", output.schema)],
    ));
    package.exports[1].inputs[0].source = InputSource::Table(TableRef::Output(OutputRef {
        package: package.id.clone(),
        revision: package.revision.clone(),
        export: "files.count".into(),
        output: "counts".into(),
    }));
    package.validate()?;
    let decoded: Package = serde_json::from_str(&package.inspect()?)?;
    assert_eq!(decoded, package);
    for mode in [InputMode::Provided, InputMode::Resolved] {
        package.exports[0].inputs[0].source = InputSource::Table(TableRef::Named("events".into()));
        package.exports[0].input_mode = InputMode::Provided;
        package.exports[1].input_mode = mode;
        package.validate()?;
        for source in [
            InputSource::Table(TableRef::Named("events".into())),
            InputSource::Query("SELECT 1".into()),
        ] {
            let valid = matches!(
                (mode, &source),
                (_, InputSource::Table(_)) | (InputMode::Resolved, InputSource::Query(_))
            );
            package.exports[0].inputs[0].source = source;
            package.exports[0].input_mode = mode;
            assert_eq!(package.validate().is_ok(), valid);
        }
        let inputs = std::mem::take(&mut package.exports[0].inputs);
        let restored: Package = serde_json::from_str(&package.inspect()?)?;
        assert_eq!(restored.exports[0].input_mode, mode);
        package.exports[0].inputs = inputs;
    }
    package.exports.remove(0);
    let input = &mut package.exports[0].inputs[0];
    input.source = InputSource::Table(TableRef::Output(OutputRef {
        package: "example".into(),
        revision: "1".into(),
        export: "run".into(),
        output: "rows".into(),
    }));
    package.id = "example".into();
    package.revision = "1".into();
    package.exports[0].name = "run".into();
    package.exports[0].outputs[0].name = "rows".into();
    let original = package.exports[0].inputs[0].clone();
    for failure in ["output", "revision", "schema", "kind"] {
        package.exports[0].inputs[0] = original.clone();
        let input = &mut package.exports[0].inputs[0];
        let InputSource::Table(TableRef::Output(output)) = &mut input.source else {
            return Err("output source absent".into());
        };
        match failure {
            "output" => output.output = "absent".into(),
            "revision" => output.revision = "other".into(),
            "schema" => input.port.schema = Schema::empty(),
            _ => input.port.kind = OutputKind::Findings,
        }
        assert!(package.validate().is_err());
    }
    package.exports[0].inputs = (0..64)
        .map(|index| {
            let mut input = original.clone();
            input.port.name = format!("input{index}");
            input
        })
        .collect();
    package.validate()?;
    assert_eq!(package.exports[0].dependencies().count(), 64);
    let mut extra = package.exports[0].clone();
    extra.name = "extra".into();
    extra.inputs.truncate(1);
    package.exports.push(extra);
    assert_eq!(
        package
            .validate()
            .err()
            .ok_or("65 output references accepted")?
            .code(),
        ErrorCode::Limit
    );
    Ok(())
}

#[test]
fn input_sources_keep_identity() -> TestResult {
    for (source, value) in [
        (
            InputSource::Table(TableRef::Named("events".into())),
            serde_json::json!({"kind": "table", "value": {"kind": "named", "value": "events"}}),
        ),
        (
            InputSource::Table(TableRef::Output(OutputRef {
                package: "example".into(),
                revision: "1".into(),
                export: "run".into(),
                output: "rows".into(),
            })),
            serde_json::json!({"kind": "table", "value": {"kind": "output", "value": {
                "package": "example", "revision": "1", "export": "run", "output": "rows"
            }}}),
        ),
        (
            InputSource::Query("SELECT subject FROM events".into()),
            serde_json::json!({"kind": "query", "value": "SELECT subject FROM events"}),
        ),
    ] {
        assert_eq!(serde_json::to_value(&source)?, value);
        assert_eq!(serde_json::from_value::<InputSource>(value)?, source);
    }
    for value in [
        serde_json::json!({"kind": "provided"}),
        serde_json::json!({"kind": "sql", "value": "SELECT 1"}),
        serde_json::json!({"kind": "output", "value": {
            "package": "example", "revision": "1", "export": "run", "output": "rows"
        }}),
        serde_json::json!({"kind": "table", "value": {
            "kind": "named", "value": "events", "extra": true
        }}),
    ] {
        assert!(serde_json::from_value::<InputSource>(value).is_err());
    }
    Ok(())
}

#[test]
fn named_inputs_check_names() -> TestResult {
    let mut package = FilesCount::package();
    assert_eq!(package.exports[0].input_mode, InputMode::Provided);
    assert_eq!(
        package.exports[0].inputs[0].source,
        InputSource::Table(TableRef::Named(
            package.exports[0].inputs[0].port.name.clone()
        ))
    );
    for mode in [InputMode::Provided, InputMode::Resolved] {
        package.exports[0].input_mode = mode;
        package.exports[0].inputs[0].source =
            InputSource::Table(TableRef::Named("events.v1-current".into()));
        package.validate()?;
        for name in [
            "",
            "SELECT * FROM events",
            "events;DROP TABLE events",
            "évents",
        ] {
            package.exports[0].inputs[0].source = InputSource::Table(TableRef::Named(name.into()));
            assert_eq!(
                package
                    .validate()
                    .err()
                    .ok_or("invalid table name accepted")?
                    .code(),
                ErrorCode::Invalid
            );
        }
    }
    Ok(())
}
