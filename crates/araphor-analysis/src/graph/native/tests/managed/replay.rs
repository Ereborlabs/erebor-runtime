use super::*;

#[tokio::test]
async fn graph_replay_survives_removal() -> TestResult {
    let fixture = Fixture::target(Target::Sql)?;
    let publication = fixture.prepare("").await?;
    let grant = publication.grant.clone();
    let definition = publication.prepared.resolved().clone();
    fixture.admit_definition(&grant, &definition)?;
    drop(publication);
    let job = GraphPublication::admit(
        Arc::clone(&fixture.query),
        fixture.authority.clone(),
        fixture.facts.clone(),
        grant.clone(),
        "removed-graph-replay".into(),
        fixture.source.clone(),
        "SELECT * FROM events".into(),
        Fixture::control_sql("SELECT * FROM events"),
        (definition, None),
        &fixture.control,
    )
    .await?;
    let mut input = request("original-graph")?;
    input.seed = Some(17);
    let receipt = job.run(input.clone(), &fixture.control).await?;
    assert_eq!(receipt.results.len(), 3);
    let expected = fixture
        .records
        .iter()
        .map(|record| record.id.clone())
        .collect::<BTreeSet<_>>();
    let host = crate::InstanceHost::with_graph_facts(
        Arc::clone(&fixture.query),
        fixture.authority.clone(),
        fixture.facts.clone(),
    );
    let removed = host
        .remove(
            grant.clone(),
            job.admitted().spec.id.clone(),
            job.admitted().lifecycle,
            &fixture.control,
        )
        .await?;
    assert!(removed.removed);
    assert!(!removed.running);
    for image in &removed.spec.definition.images {
        assert!(fixture.query.store().uninstall_package_image(
            fixture.source.tenant_id,
            image,
            || Ok(())
        )?);
    }
    drop((job, host));
    let record = fixture.records.first().ok_or("live Graph record")?;
    fixture.query.store().accept_validated_batch(
        fixture.source.clone(),
        ValidatedEvidenceBatchV1 {
            cpu_id: record.id.cpu_id,
            first_cursor: 4,
            last_cursor: 4,
            intake_utc_ns: 4,
            frame_ends: vec![record.wire_record.len()],
            framed_records: record.wire_record.clone().into(),
        },
    )?;
    let scope = araphor_data::ProcessorScopeV1 {
        processor_id: araphor_data::GRAPH_PROCESSOR.into(),
        method_version: u64::from(araphor_data::GRAPH_SCHEMA_VERSION),
        identity: fixture.source.clone(),
    };
    let before = fixture.query.store().meta()?;
    let health = fixture.query.store().processor_health(&scope)?;
    let head = fixture.query.store().processor_result(&scope)?;
    let snapshot = fixture.query.store().graph_snapshot(&fixture.source)?;
    let history = fixture.query.store().managed_history(
        &grant.selection,
        &removed.spec.id,
        &fixture.control,
    )?;
    let held = fixture.query.memory().input_reserved();
    let facts = fixture.facts.calls.load(Ordering::SeqCst);
    let missing = crate::Instance::replay_result(
        Arc::clone(&fixture.query),
        fixture.authority.clone(),
        None,
        grant.clone(),
        &removed.spec.id,
        &receipt
            .results
            .values()
            .next()
            .ok_or("Graph replay reference")?
            .result_id,
        &fixture.control,
    )
    .await
    .err()
    .ok_or("Graph replay omitted facts owner")?;
    let mut cause: &dyn std::error::Error = &missing;
    while let Some(source) = cause.source() {
        cause = source;
    }
    assert_eq!(
        cause.to_string(),
        Code::Incomplete.error("Graph facts owner").to_string()
    );
    assert_eq!(fixture.query.store().meta()?, before);
    assert_eq!(fixture.facts.calls.load(Ordering::SeqCst), facts);
    assert_eq!(fixture.query.memory().input_reserved(), held);
    for (index, (call, reference)) in receipt.results.iter().enumerate() {
        let stored = fixture.query.store().managed_result(
            &removed,
            &reference.result_id,
            input.time_utc_ns,
            &fixture.control,
        )?;
        let descriptor =
            Detector::from_id(&removed.spec.manifest.calls[call].package.package_id)?.descriptor();
        let araphor_data::InstanceResultKindV1::Call {
            call: stored_call,
            context: original,
            ..
        } = &stored.kind
        else {
            return Err("original Graph call metadata".into());
        };
        assert_eq!(stored_call, call);
        let model = descriptor
            .exports
            .iter()
            .find(|model| model.name == removed.spec.manifest.calls[call].export)
            .ok_or("original Graph export")?;
        let replayed = crate::Instance::replay_result(
            Arc::clone(&fixture.query),
            fixture.authority.clone(),
            Some(fixture.facts.clone()),
            grant.clone(),
            &removed.spec.id,
            &reference.result_id,
            &fixture.control,
        )
        .await?;
        assert_eq!(replayed.calls.len(), 1);
        let returned = replayed
            .calls
            .get(call)
            .ok_or("exact retained Graph call")?;
        let actual = returned.evaluation();
        descriptor.check_evaluation(actual)?;
        assert_eq!(actual.export, model.name);
        assert_eq!(actual.inputs.len(), model.inputs.len());
        assert_eq!(
            actual
                .inputs
                .iter()
                .map(|input| input.revision.clone())
                .collect::<Vec<_>>(),
            original.inputs
        );
        assert_eq!(
            actual
                .inputs
                .iter()
                .map(|input| input.coverage.clone())
                .collect::<Vec<_>>(),
            original.input_coverage
        );
        assert!(actual.parameters.is_none());
        assert!(actual.checkpoint.is_none());
        assert!(actual.previous_outputs.is_empty());
        assert!(model
            .change_inputs
            .as_ref()
            .ok_or("Graph change inputs")?
            .is_reset(actual)?);
        assert_eq!(actual.input("unit_removals")?.data.rows(), 0);
        assert_eq!(actual.context, original.context);
        assert_eq!(actual.context.id, input.id);
        assert_eq!(actual.context.time_utc_ns, input.time_utc_ns as i64);
        assert_eq!(actual.context.seed, input.seed);
        let records =
            araphor_analysis_builtins::graph::Observation::decode(&actual.input("records")?.data)?;
        assert_eq!(records.len(), expected.len());
        assert_eq!(
            records
                .into_iter()
                .map(|record| record.id)
                .collect::<BTreeSet<_>>(),
            expected
        );
        let units = araphor_analysis_builtins::graph::Unit::decode(&actual.input("units")?.data)?;
        assert_eq!(units.len(), expected.len());
        assert_eq!(
            units
                .into_iter()
                .map(|unit| unit.record)
                .collect::<BTreeSet<_>>(),
            expected
        );
        let dataset = |name| {
            returned
                .output()
                .datasets
                .iter()
                .find(|data| data.name == name)
                .ok_or("Graph replay output")
        };
        assert_eq!(
            araphor_analysis_builtins::graph::GraphPackageStateV1::decode(dataset("state")?)?,
            [araphor_analysis_builtins::graph::GraphPackageStateV1::Waiting]
        );
        for name in ["subjects", "relationships", "findings"] {
            assert_eq!(dataset(name)?.rows(), 0);
        }
        let contributions =
            araphor_analysis_builtins::graph::Contribution::decode(dataset("contributions")?)?;
        assert_eq!(contributions.len(), expected.len());
        assert_eq!(
            contributions
                .iter()
                .map(|row| row.record.clone())
                .collect::<BTreeSet<_>>(),
            expected
        );
        assert!(contributions.iter().all(|row| row.subjects.is_empty()
            && row.relationships.is_empty()
            && row.findings.is_empty()
            && row.state.is_none()));
        assert!(returned.output().evidence.is_empty());
        assert!(returned.output().reasons.is_empty());
        assert!(returned.output().checkpoint.is_none());
        assert_eq!(stored.result, *reference);
        assert_eq!(stored.receipt, receipt);
        drop((replayed, stored));
        assert_eq!(fixture.query.store().meta()?, before);
        assert_eq!(fixture.query.store().processor_health(&scope)?, health);
        assert_eq!(fixture.query.store().processor_result(&scope)?, head);
        assert_eq!(
            fixture.query.store().graph_snapshot(&fixture.source)?,
            snapshot
        );
        assert_eq!(
            fixture.query.store().managed_instance(
                fixture.source.tenant_id,
                &removed.spec.id,
                &fixture.control
            )?,
            Some(removed.clone())
        );
        assert_eq!(
            fixture.query.store().managed_history(
                &grant.selection,
                &removed.spec.id,
                &fixture.control
            )?,
            history
        );
        assert_eq!(
            fixture.facts.calls.load(Ordering::SeqCst),
            facts + index + 1
        );
        assert_eq!(fixture.query.memory().input_reserved(), held);
    }
    Ok(())
}
