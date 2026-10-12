use super::*;

#[test]
fn component_keeps_input_batches() -> TestResult {
    let runtime = WasmExecution::fixture_code(WasmLimits::default())?;
    let mut package = package();
    let mut model = package.exports[0].clone();
    model.name = "count-input".into();
    let schema = Arc::new(model.outputs[0].schema.clone());
    model.inputs = vec![sdk::Port::new("input", schema.as_ref().clone())];
    package.exports.push(model);
    let mut input = evaluation(&package, "sum-input", 0)?;
    input.export = "count-input".into();
    input.inputs = vec![sdk::Input {
        data: sdk::Dataset {
            name: "input".into(),
            batches: [vec![2, 3], Vec::new(), vec![5]]
                .into_iter()
                .map(|values| {
                    sdk::RecordBatch::try_new(
                        schema.clone(),
                        vec![Arc::new(UInt64Array::from(values))],
                    )
                })
                .collect::<std::result::Result<_, _>>()?,
        },
        revision: sdk::Revision {
            owner: "batch-fixture".into(),
            id: "1".into(),
            window: None,
        },
        coverage: sdk::Coverage {
            state: sdk::CoverageState::Complete,
            limits: Vec::new(),
        },
    }];
    assert_eq!(input.inputs[0].data.batches.len(), 3);
    let control = AnalysisReadControl::with_timeout(Duration::from_secs(30))?;
    assert_eq!(
        value(&runtime.evaluate(&package, &input, COMPONENT, &control)?)?,
        10
    );
    Ok(())
}
