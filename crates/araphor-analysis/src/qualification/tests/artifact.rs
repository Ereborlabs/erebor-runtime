use super::*;

#[tokio::test]
async fn fixture_selects_contained_artifact() -> TestResult {
    let model = sdk::Model::new(
        "evaluate",
        Vec::new(),
        vec![sdk::Port::new("data", Fixture::schema())],
    );
    let mut bundle = Fixture::bundle(
        "sql",
        model.clone(),
        SqlModelV1 {
            outputs: BTreeMap::from([(
                "data".into(),
                "SELECT CAST(37 AS BIGINT UNSIGNED) AS value".into(),
            )]),
            ..Default::default()
        },
    )?;
    Fixture::save(
        &mut bundle,
        &Fixture::evaluation(&model),
        &sdk::Output {
            datasets: vec![Fixture::data("data", &[37])?],
            ..Default::default()
        },
        None,
    )?;
    let artifact = bundle.root.clone();
    let mut root = model;
    root.inputs.push(sdk::InputPort {
        port: sdk::Port::new("source", Fixture::schema()),
        source: sdk::InputSource::Table(sdk::TableRef::Output(sdk::OutputRef {
            package: artifact.package_id.clone(),
            revision: artifact.revision.clone(),
            export: "evaluate".into(),
            output: "data".into(),
        })),
    });
    bundle.root = PackageRefV1 {
        package_id: "fixture-image".into(),
        revision: "image-1".into(),
    };
    bundle.artifacts.insert(
        0,
        PackageArtifactV1 {
            descriptor: sdk::Package::new("fixture-image", "image-1", vec![root]),
            implementations: vec![PackageImplementationV1::Sql {
                export: "evaluate".into(),
                program: SqlModelV1 {
                    outputs: BTreeMap::from([(
                        "data".into(),
                        "SELECT CAST(99 AS BIGINT UNSIGNED) AS value".into(),
                    )]),
                    ..Default::default()
                },
            }],
            fixtures: Vec::new(),
        },
    );
    let fixture = Fixture::new(&bundle)?;
    let store = fixture.owner.query.store();
    let before = store.meta()?;
    assert!(store
        .package_image(
            [1; 16],
            &artifact.package_id,
            Some(&artifact.revision),
            &AnalysisReadControl::default()
        )?
        .is_none());
    assert!(fixture.run(&bundle).await?.is_empty());
    assert_eq!(
        fixture
            .owner
            .run_artifact(
                &fixture.grant,
                &bundle.root,
                &artifact,
                Some("case"),
                &AnalysisReadControl::default()
            )
            .await?,
        vec![FixtureResult {
            fixture: "case".into(),
            passed: true
        }]
    );
    assert!(fixture
        .owner
        .run_artifact(
            &fixture.grant,
            &bundle.root,
            &PackageRefV1 {
                revision: "absent".into(),
                ..artifact
            },
            None,
            &AnalysisReadControl::default()
        )
        .await
        .is_err());
    assert_eq!(store.meta()?, before);
    assert_eq!(fixture.owner.query.memory().input_reserved(), 0);
    Ok(())
}
