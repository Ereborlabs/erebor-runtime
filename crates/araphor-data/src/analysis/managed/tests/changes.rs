use super::*;

#[test]
fn change_base_matches_basis() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = AnalysisStore::open(directory.path().join("store"))?;
    let fixture = Fixture::admit(&store)?;
    let captured = fixture.capture(&store, false)?;
    let requested = request("change-basis");
    let attempt = store.register_managed_attempt(&captured, &requested, || Ok(()))?;
    let evaluations = (10..12)
        .map(|call| fixture.evaluation(&requested, call, Some(&captured)))
        .collect::<TestResult<Vec<_>>>()?;
    let outputs = [fixture.output(1)?, fixture.output(1)?];
    let receipt = fixture.publish_checked(&store, &attempt, &evaluations, &outputs, || Ok(()))?;
    let reference = &receipt.results[&10];
    let mut lease = store.reader()?;
    let reader = lease.get_mut()?;
    let (mut record, _, _) =
        AnalysisStore::managed_header_from(reader, [1; 16], &reference.result_id)?;
    let mut model = fixture.model.clone();
    model
        .inputs
        .push(sdk::Port::new("before", model.inputs[0].port.schema.clone()).into());
    model
        .inputs
        .push(sdk::ChangeInputs::reset_port("reset").into());
    model
        .checkpoint
        .as_mut()
        .ok_or("checkpoint")?
        .resume_input_changes = true;
    model.change_inputs = Some(sdk::ChangeInputs {
        reset: "reset".into(),
        ports: vec![sdk::ChangeInput {
            before: "before".into(),
            after: "source".into(),
        }],
    });
    record.changes = Some(super::super::model::RecordChanges {
        base: None,
        targets: record
            .inputs
            .iter()
            .enumerate()
            .map(|(slot, input)| super::super::model::RecordTarget {
                input: sdk::wire::Input {
                    data: sdk::wire::Dataset {
                        name: input.name.clone(),
                        arrow_ipc: Vec::new(),
                    },
                    revision: record.context.inputs[slot].clone(),
                    coverage: record.context.input_coverage[slot].clone(),
                },
                rows: input.rows,
                batches: input.batches,
            })
            .collect(),
    });
    for name in ["before", "reset"] {
        record.inputs.push(super::super::model::RecordInput {
            name: name.into(),
            rows: u64::from(name == "reset"),
            batches: 1,
        });
        record.context.inputs.push(record.context.inputs[0].clone());
        record
            .context
            .input_coverage
            .push(record.context.input_coverage[0].clone());
    }
    AnalysisStore::check_change_record(reader, [1; 16], &record, &model, &attempt.0)?;
    for (basis, base) in [
        (super::super::model::InputBasis::Complete, None),
        (
            super::super::model::InputBasis::None,
            Some(reference.clone()),
        ),
        (
            super::super::model::InputBasis::Progress,
            Some(reference.clone()),
        ),
    ] {
        record.input_basis = basis;
        record.changes.as_mut().ok_or("changes")?.base = base;
        let error =
            AnalysisStore::check_change_record(reader, [1; 16], &record, &model, &attempt.0)
                .err()
                .ok_or("unbound change base accepted")?;
        assert!(
            error.to_string().contains("managed change input basis"),
            "{error:?}"
        );
    }
    Ok(())
}
