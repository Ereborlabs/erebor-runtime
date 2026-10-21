use super::*;

fn mixed_image() -> TestResult<PackageBundleV1> {
    let mut image = component("wasm", "count-input")?;
    let artifact = &mut image.artifacts[0];
    artifact.descriptor.exports[0].limits.max_bytes = 64 * 1024;
    artifact.descriptor.exports[0].inputs[0].source =
        sdk::InputSource::Table(sdk::TableRef::Output(sdk::OutputRef {
            package: artifact.descriptor.id.clone(),
            revision: artifact.descriptor.revision.clone(),
            export: "aux".into(),
            output: "rows".into(),
        }));
    artifact.descriptor.exports.push(sdk::Model::new(
        "aux",
        Vec::new(),
        vec![sdk::Port::new("rows", Fixture::schema("value"))],
    ));
    artifact.implementations.push(PackageImplementationV1::Sql {
        export: "aux".into(),
        program: SqlModelV1 {
            outputs: BTreeMap::from([(
                "rows".into(),
                "SELECT CAST(7 AS BIGINT UNSIGNED) AS value".into(),
            )]),
            ..Default::default()
        },
    });
    image.validate()?;
    Ok(image)
}

#[tokio::test]
async fn selected_descriptor_keeps_auxiliary() -> TestResult {
    const OUTPUT: usize = 1024 * 1024;
    let fixture = Fixture::limits(Limits {
        input_capacity: Some(128 * 1024 * 1024),
        output_capacity: Some(OUTPUT),
        global_evaluations: Some(1),
        tenant_evaluations: Some(1),
        ..Default::default()
    })?;
    let image = mixed_image()?;
    fixture.install(&image)?;
    let before = fixture.engine.store().meta()?;
    let prepared = fixture.prepare(&Fixture::sql(
        r#"SELECT * FROM "runtime-fixture"."1"."count-input"(mode => 'sum-input', amount => 0)"#,
    )).await?;
    assert_eq!(prepared.images().count(), 1);
    assert_eq!(prepared.resolved().images.len(), 1);
    assert_eq!(prepared.resolved().images[0].image, image.root);
    let calls = Fixture::calls(&prepared.plan)?;
    assert_eq!(calls.len(), 2);
    let call = calls
        .iter()
        .find(|call| call.export() == "count-input")
        .ok_or("selected call")?;
    assert_eq!(call.descriptor(), &image.artifacts[0].descriptor);
    call.descriptor().validate()?;
    assert_eq!(call.package(), &image.root);
    let guests = calls
        .iter()
        .filter(|call| {
            matches!(
                image.artifacts[0].implementation(call.export()),
                Ok(PackageImplementationV1::Wasm { .. })
            )
        })
        .map(|call| call.export())
        .collect::<Vec<_>>();
    assert_eq!(guests, ["count-input"]);
    let first = fixture
        .execute(&prepared, invocation("selected-descriptor"))
        .await?;
    let direct = first.calls.get(&call.id()).ok_or("selected return")?;
    assert!(direct.belongs_to(call));
    image.artifacts[0]
        .descriptor
        .validate_output(direct.evaluation(), direct.output())?;
    assert_eq!(direct.output().datasets.len(), 1);
    assert_eq!(direct.output().datasets[0].name, "data");
    assert_eq!(direct.output().datasets[0].batches.len(), 1);
    assert_eq!(values(&direct.output().datasets[0].batches)?, [7]);
    assert!(direct.output().evidence.is_empty());
    assert!(direct.output().reasons.is_empty());
    assert!(direct.output().checkpoint.is_none());
    let revision = call.package().revision.clone();
    let context = direct.evaluation().context.clone();
    let parameters = direct.evaluation().parameters.clone();
    let schema = &call.descriptor().exports[0].outputs[0].schema;
    let expected =
        sdk::wire::Dataset::encode(&direct.output().datasets[0], schema, sdk::Limits::default())?
            .decode(schema, sdk::Limits::default())?;
    let batches = direct.output().datasets[0].batches.clone();
    let retained = batches[0].column(0).get_buffer_memory_size();
    assert!(retained > 0 && retained < OUTPUT);
    assert!(fixture.engine.memory().reserve_output(OUTPUT).is_err());
    drop(fixture.engine.reserve_evaluation([1; 16])?);
    let filled = fixture.engine.memory().prepare_output(OUTPUT)?;
    assert!(fixture.engine.memory().reserve_output(1).is_err());
    let pressure = fixture
        .execute(&prepared, invocation("selected-descriptor"))
        .await
        .err()
        .ok_or("retained output pressure accepted")?;
    assert_eq!(
        crate::Failure::from(&pressure),
        crate::Failure::Busy,
        "{pressure:?}"
    );
    drop(filled);
    drop(first);
    assert_eq!(values(&batches)?, [7]);
    assert!(fixture.engine.memory().reserve_output(OUTPUT).is_err());
    let held = fixture.engine.memory().reserve_output(OUTPUT - retained)?;
    assert!(fixture.engine.memory().reserve_output(1).is_err());
    drop(fixture.engine.reserve_evaluation([1; 16])?);
    let error = fixture
        .execute(&prepared, invocation("selected-descriptor"))
        .await
        .err()
        .ok_or("output pressure accepted")?;
    assert_eq!(
        crate::Failure::from(&error),
        crate::Failure::Busy,
        "{error:?}"
    );
    let mut source: Option<&(dyn std::error::Error + 'static)> = Some(&error);
    let mut output = false;
    while let Some(error) = source {
        output |= matches!(
            error.downcast_ref::<crate::Error>(),
            Some(crate::Error::Capacity {
                resource: "shared output",
                ..
            })
        );
        source = error.source();
    }
    assert!(output, "{error:?}");
    assert_eq!(values(&batches)?, [7]);
    drop(batches);
    drop(fixture.engine.memory().reserve_output(retained)?);
    drop(held);
    let result = fixture
        .execute(&prepared, invocation("selected-descriptor"))
        .await?;
    let returned = result.calls.get(&call.id()).ok_or("replayed return")?;
    assert!(returned.belongs_to(call));
    assert_eq!(call.descriptor(), &image.artifacts[0].descriptor);
    assert_eq!(call.package().revision, revision);
    assert_eq!(returned.evaluation().context, context);
    assert_eq!(returned.evaluation().parameters, parameters);
    assert_eq!(returned.output().datasets[0].batches, expected.batches);
    image.artifacts[0]
        .descriptor
        .validate_output(returned.evaluation(), returned.output())?;
    assert_eq!(returned.output().datasets.len(), 1);
    assert_eq!(returned.output().datasets[0].name, "data");
    assert_eq!(returned.output().datasets[0].batches.len(), 1);
    assert_eq!(values(&returned.output().datasets[0].batches)?, [7]);
    assert!(returned.output().evidence.is_empty());
    assert!(returned.output().reasons.is_empty());
    assert!(returned.output().checkpoint.is_none());
    assert_eq!(fixture.engine.store().meta()?, before);
    drop((result, calls, prepared, parameters));
    capacity_released(&fixture)?;
    Ok(())
}
