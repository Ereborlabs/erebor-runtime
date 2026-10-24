use super::*;

fn image(value: u64) -> PackageBundleV1 {
    let mut model = sdk::Model::new(
        "count",
        Vec::new(),
        vec![sdk::Port::new("rows", Fixture::schema("count"))],
    );
    model.input_mode = sdk::InputMode::Resolved;
    bundle(
        model,
        SqlModelV1 {
            outputs: BTreeMap::from([(
                "rows".into(),
                format!("SELECT CAST({value} AS BIGINT UNSIGNED) AS count"),
            )]),
            ..Default::default()
        },
    )
}

fn derived(artifact: &mut PackageArtifactV1, source: &PackageRefV1) {
    let mut model = artifact.descriptor.exports[0].clone();
    model.name = "derived".into();
    let mut input = model.outputs[0].clone();
    input.name = "source".into();
    model.inputs.push(sdk::InputPort {
        port: input,
        source: sdk::InputSource::Table(sdk::TableRef::Output(sdk::OutputRef {
            package: source.package_id.clone(),
            revision: source.revision.clone(),
            export: "count".into(),
            output: "rows".into(),
        })),
    });
    artifact.descriptor.exports.push(model);
    artifact.implementations.push(PackageImplementationV1::Sql {
        export: "derived".into(),
        program: SqlModelV1 {
            outputs: BTreeMap::from([(
                "rows".into(),
                "SELECT CAST(count + 1 AS BIGINT UNSIGNED) AS count FROM source".into(),
            )]),
            ..Default::default()
        },
    });
}

#[tokio::test]
async fn image_rejects_artifact_cycles() -> TestResult {
    let fixture = Fixture::limits(capacity_limits())?;
    let mut selected = image(3);
    let mut upstream = image(2).artifacts.remove(0);
    upstream.descriptor.id = "upstream".into();
    derived(&mut selected.artifacts[0], &upstream.reference());
    derived(&mut upstream, &selected.root);
    selected.artifacts.push(upstream);
    for artifact in &selected.artifacts {
        artifact.descriptor.validate()?;
    }
    assert_eq!(selected.order()?.len(), 3);
    let before = fixture.engine.store().meta()?;
    assert!(matches!(
        fixture
            .engine
            .store()
            .install_package_image([1; 16], &selected, || Ok(())),
        Err(araphor_data::Error::Package {
            code: araphor_data::PackageErrorCodeV1::Invalid,
            field: "artifact dependency cycle",
            ..
        })
    ));
    assert_eq!(fixture.engine.store().meta()?, before);
    assert!(fixture
        .engine
        .store()
        .package_revisions([1; 16])?
        .is_empty());
    assert!(fixture
        .engine
        .store()
        .active_managed(&araphor_data::AnalysisReadControl::default())?
        .1
        .is_empty());
    capacity_released(&fixture)?;
    Ok(())
}

#[tokio::test]
async fn image_preserves_internal_calls() -> TestResult {
    let fixture = Fixture::limits(capacity_limits())?;
    let mut selected = image(3);
    let reference = selected.root.clone();
    derived(&mut selected.artifacts[0], &reference);
    selected.validate()?;
    fixture.install(&selected)?;
    assert!(fixture
        .engine
        .store()
        .active_managed(&araphor_data::AnalysisReadControl::default())?
        .1
        .is_empty());
    let before = fixture.engine.store().meta()?;
    let prepared = fixture
        .prepare(&Fixture::sql(r#"SELECT * FROM "fixture"."r1".derived()"#))
        .await?;
    assert_eq!(prepared.images().count(), 1);
    let calls = Fixture::calls(&prepared.plan)?;
    assert_eq!(calls.len(), 2);
    let output = fixture
        .execute(&prepared, invocation("internal-composition"))
        .await?;
    assert_eq!(values(&output.batches)?, [4]);
    assert_eq!(output.batches[0].schema().field(0).name(), "count");
    assert_eq!(output.calls.len(), 2);
    for call in &calls {
        assert_eq!(call.descriptor(), &selected.artifacts[0].descriptor);
        let result = output.calls.get(&call.id()).ok_or("composition return")?;
        assert!(result.belongs_to(call));
        assert_eq!(
            values(&result.output().datasets[0].batches)?,
            [if call.export() == "derived" { 4 } else { 3 }]
        );
    }
    assert_eq!(fixture.engine.store().meta()?, before);
    drop((output, calls, prepared));
    capacity_released(&fixture)?;
    Ok(())
}
