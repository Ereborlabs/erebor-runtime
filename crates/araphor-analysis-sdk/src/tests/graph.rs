use arrow_array::{BinaryArray, BooleanArray, TimestampNanosecondArray};

use super::*;

mod fixture;
use fixture::{SelectedGraph, KEYS, SOURCES, WINDOW_START};

#[test]
fn graph_keeps_version_manifest() -> TestResult {
    let graph = SelectedGraph::new();
    let report = graph
        .package
        .test(&graph.fixture, |input| graph.evaluate(input))?;
    let subjects = &report.output.datasets[0].batches[0];
    assert_eq!(
        SelectedGraph::column::<StringArray>(subjects, 0)
            .iter()
            .flatten()
            .collect::<Vec<_>>(),
        ["result.1", "result.1", "result.2", "result.2"]
    );
    let keys = SelectedGraph::column::<BinaryArray>(subjects, 1);
    assert_eq!(
        keys.iter().flatten().collect::<Vec<_>>(),
        [KEYS[0], KEYS[1], KEYS[0], KEYS[2]]
    );
    let relationships = &report.output.datasets[1].batches[0];
    assert_eq!(
        SelectedGraph::column::<BinaryArray>(relationships, 1)
            .iter()
            .flatten()
            .collect::<Vec<_>>(),
        [KEYS[0], KEYS[0]]
    );
    assert_eq!(
        SelectedGraph::column::<BinaryArray>(relationships, 2)
            .iter()
            .flatten()
            .collect::<Vec<_>>(),
        [KEYS[1], KEYS[2]]
    );
    let selection = &report.output.datasets[2].batches[0];
    assert_eq!(
        SelectedGraph::column::<StringArray>(selection, 0)
            .iter()
            .flatten()
            .collect::<Vec<_>>(),
        ["result.1", "result.2", "replacement.empty.3"]
    );
    assert_eq!(
        SelectedGraph::column::<BinaryArray>(selection, 1)
            .iter()
            .flatten()
            .collect::<Vec<_>>(),
        [SOURCES[0], SOURCES[1], SOURCES[0]]
    );
    assert_eq!(
        SelectedGraph::column::<BooleanArray>(selection, 2)
            .values()
            .iter()
            .collect::<Vec<_>>(),
        [true, false, false]
    );
    assert_eq!(
        SelectedGraph::column::<TimestampNanosecondArray>(selection, 3).value(2),
        WINDOW_START + 10
    );
    assert_eq!(
        SelectedGraph::column::<TimestampNanosecondArray>(selection, 4).value(2),
        WINDOW_START + 19
    );
    assert_eq!(
        SelectedGraph::column::<UInt64Array>(selection, 5)
            .values()
            .as_ref(),
        [2, 2, 0]
    );
    assert_eq!(
        SelectedGraph::column::<UInt64Array>(selection, 6)
            .values()
            .as_ref(),
        [1, 1, 0]
    );
    assert_eq!(report.output.evidence.len(), 9);
    let mut limited = graph.fixture.clone();
    limited.evaluation.context.limits.max_rows = 8;
    assert_eq!(
        graph
            .package
            .test(&limited, |_| panic!("oversized input ran"))
            .unwrap_err()
            .code(),
        ErrorCode::Limit
    );
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
