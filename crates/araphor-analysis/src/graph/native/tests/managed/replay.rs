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
        definition,
        &fixture.control,
    )
    .await?;
    let mut input = request("original-graph")?;
    input.seed = Some(17);
    let receipt = job.run(input.clone(), &fixture.control).await?;
    assert_eq!(receipt.results.len(), 3);
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
    for (call, reference) in &receipt.results {
        let original = fixture.query.store().managed_evaluation(
            &removed,
            &reference.result_id,
            &fixture.control,
        )?;
        let stored = fixture.query.store().managed_result(
            &removed,
            &reference.result_id,
            input.time_utc_ns,
            &fixture.control,
        )?;
        let descriptor =
            Detector::from_id(&removed.spec.manifest.calls[call].package.package_id)?.descriptor();
        let model = descriptor
            .exports
            .iter()
            .find(|model| model.name == original.export)
            .ok_or("original Graph export")?;
        let expected = descriptor.check_evaluation(&original)?.encode()?;
        let replayed = crate::Instance::replay_result(
            Arc::clone(&fixture.query),
            fixture.authority.clone(),
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
        let actual = descriptor
            .check_evaluation(returned.evaluation())?
            .encode()?;
        assert_eq!(actual.export_name, expected.export_name);
        assert_eq!(actual.inputs, expected.inputs);
        assert_eq!(actual.inputs.len(), 3);
        assert_eq!(actual.parameters, expected.parameters);
        assert_eq!(actual.checkpoint, expected.checkpoint);
        assert_eq!(actual.previous_outputs, expected.previous_outputs);
        assert_eq!(actual.context, expected.context);
        assert_eq!(actual.context.id, input.id);
        assert_eq!(actual.context.time_utc_ns, input.time_utc_ns as i64);
        assert_eq!(actual.context.seed, input.seed);
        assert_eq!(
            sdk::wire::Output::encode_model(returned.output(), model)?,
            sdk::wire::Output::encode_model(&stored.output, model)?
        );
        drop((replayed, original, stored));
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
        assert_eq!(fixture.facts.calls.load(Ordering::SeqCst), 1);
        assert_eq!(fixture.query.memory().input_reserved(), held);
    }
    Ok(())
}
