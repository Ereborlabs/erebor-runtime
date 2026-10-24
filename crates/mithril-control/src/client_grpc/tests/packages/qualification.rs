use super::*;
use araphor_analysis_sdk as sdk;
use sdk::arrow_array::Float64Array;

fn fixtures() -> TestResult<PackageBundleV1> {
    let schema = Schema::new(vec![Field::new("count", DataType::Float64, false)]);
    let batch = |values: Vec<f64>| {
        sdk::RecordBatch::try_new(
            Arc::new(schema.clone()),
            vec![Arc::new(Float64Array::from(values))],
        )
    };
    let mut image = bundle();
    let model = &mut image.artifacts[0].descriptor.exports[0];
    model.outputs = vec![
        Port::new("rows", schema.clone()),
        Port::new("other", schema.clone()),
    ];
    model.tolerance.absolute = 0.01;
    let sql = SqlModelV1 {
        outputs: BTreeMap::from([
            (
                "rows".into(),
                "SELECT 1::DOUBLE AS count UNION ALL SELECT 2::DOUBLE AS count ORDER BY count"
                    .into(),
            ),
            ("other".into(), "SELECT 1::DOUBLE AS count".into()),
        ]),
        ..Default::default()
    };
    let expected = sdk::Output {
        datasets: vec![
            sdk::Dataset {
                name: "other".into(),
                batches: vec![batch(vec![1.005])?],
            },
            sdk::Dataset {
                name: "rows".into(),
                batches: vec![batch(vec![1.005])?, batch(vec![2.005])?],
            },
        ],
        ..Default::default()
    };
    let equal = araphor_data::PackageFixtureV1 {
        name: "equal".into(),
        export: model.name.clone(),
        time_utc_ns: 0,
        seed: None,
        inputs: Vec::new(),
        parameters: None,
        checkpoint: None,
        expected: sdk::wire::Output::encode_model(&expected, model)?,
    };
    let mut mismatch = expected;
    mismatch.datasets[1].batches = vec![batch(vec![1.1, 2.0])?];
    let mut different = equal.clone();
    different.name = "different".into();
    different.expected = sdk::wire::Output::encode_model(&mismatch, model)?;
    image.artifacts[0].implementations[0] = PackageImplementationV1::Sql {
        export: "count".into(),
        program: sql,
    };
    image.artifacts[0].fixtures = vec![equal, different];
    Ok(image)
}

fn container(mut image: PackageBundleV1) -> TestResult<PackageBundleV1> {
    for package in ["api.fixture-bridge", "api.fixture-container"] {
        let dependency = image.root.clone();
        let source = image.artifact(&dependency)?.descriptor.exports[0].outputs[0].clone();
        let mut artifact = bundle().artifacts.remove(0);
        artifact.descriptor.id = package.into();
        artifact.descriptor.exports[0].inputs.push(sdk::InputPort {
            port: Port::new("source", source.schema),
            source: sdk::InputSource::Table(sdk::TableRef::Output(sdk::OutputRef {
                package: dependency.package_id,
                revision: dependency.revision,
                export: "count".into(),
                output: "rows".into(),
            })),
        });
        image.root = artifact.reference();
        image.artifacts.push(artifact);
    }
    image.validate()?;
    Ok(image)
}

#[tokio::test]
async fn image_rpc_selects_artifact() -> TestResult {
    let fixture = Fixture::new()?;
    let child = fixtures()?;
    let artifact = child.root.clone();
    let image = container(child)?;
    let mut foreign = fixtures()?;
    foreign.root.package_id = "api.foreign".into();
    foreign.artifacts[0].descriptor.id = foreign.root.package_id.clone();
    fixture
        .service
        .auth
        .replace_package_managers(vec![crate::InvestigateGrant {
            subject: "alice".into(),
            tenant_id: uuid::Uuid::from_bytes([1; 16]).to_string(),
        }])?;
    fixture.service.auth.replace_package_trust(
        [&image, &foreign]
            .into_iter()
            .map(|image| {
                Ok(crate::PackageTrustPinV1 {
                    tenant_id: uuid::Uuid::from_bytes([1; 16]).to_string(),
                    bundle_digest: image.digest()?,
                })
            })
            .collect::<araphor_data::Result<Vec<_>>>()?,
    )?;
    for image in [&image, &foreign] {
        fixture
            .package(
                PackageRequestV1::InstallImage {
                    bundle: image.clone(),
                },
                true,
            )
            .await?;
    }
    let data = fixture.service.data()?.store.clone();
    let before = data.meta()?;
    let notices = data.subscribe_revision();
    let lifecycle = data.subscribe_activations();
    let active = data.active_managed(&AnalysisReadControl::default())?;
    assert!(data
        .package_image(
            [1; 16],
            &artifact.package_id,
            Some(&artifact.revision),
            &AnalysisReadControl::default()
        )?
        .is_none());
    let operation = |target, name| PackageRequestV1::TestImage {
        image: image.root.clone(),
        artifact: target,
        fixture: name,
    };
    assert!(
        matches!(fixture.package(operation(None, None), true).await?, PackageResponseV1::Tests(tests) if tests.is_empty())
    );
    let PackageResponseV1::Tests(tests) = fixture
        .package(operation(Some(artifact.clone()), None), true)
        .await?
    else {
        return Err("contained fixture results".into());
    };
    assert_eq!(
        tests,
        vec![
            araphor_data::FixtureResult {
                fixture: "equal".into(),
                passed: true
            },
            araphor_data::FixtureResult {
                fixture: "different".into(),
                passed: false
            },
        ]
    );
    assert!(
        matches!(fixture.package(operation(Some(artifact.clone()), Some("equal".into())), true).await?, PackageResponseV1::Tests(named) if named == vec![tests[0].clone()])
    );
    for (target, name) in [
        (artifact.clone(), Some("missing".into())),
        (
            PackageRefV1 {
                revision: "missing".into(),
                ..artifact.clone()
            },
            None,
        ),
        (foreign.root.clone(), None),
    ] {
        assert_eq!(
            fixture
                .package(operation(Some(target), name), true)
                .await
                .err()
                .map(|error| error.code()),
            Some(tonic::Code::NotFound)
        );
    }
    fixture.service.auth.replace_package_trust(Vec::new())?;
    assert_eq!(
        fixture
            .package(operation(Some(artifact.clone()), None), true)
            .await
            .err()
            .map(|error| error.code()),
        Some(tonic::Code::PermissionDenied)
    );
    fixture.service.auth.replace_package_managers(Vec::new())?;
    assert_eq!(
        fixture
            .package(operation(Some(artifact), None), true)
            .await
            .err()
            .map(|error| error.code()),
        Some(tonic::Code::PermissionDenied)
    );
    assert_eq!(data.meta()?, before);
    assert!(!notices.has_changed()?);
    assert!(!lifecycle.has_changed()?);
    assert_eq!(
        data.active_managed(&AnalysisReadControl::default())?,
        active
    );
    Ok(())
}

#[tokio::test]
async fn image_rpc_tests_fixtures() -> TestResult {
    let fixture = Fixture::new()?;
    let image = fixtures()?;
    let mut empty = image.clone();
    empty.root.revision = "empty".into();
    empty.artifacts[0].descriptor.revision = "empty".into();
    empty.artifacts[0].fixtures.clear();
    let operation = PackageRequestV1::TestImage {
        artifact: None,
        image: image.root.clone(),
        fixture: None,
    };
    assert_eq!(
        fixture
            .package(operation.clone(), true)
            .await
            .err()
            .map(|error| error.code()),
        Some(tonic::Code::PermissionDenied)
    );
    fixture
        .service
        .auth
        .replace_package_managers(vec![crate::InvestigateGrant {
            subject: "alice".into(),
            tenant_id: uuid::Uuid::from_bytes([1; 16]).to_string(),
        }])?;
    fixture.service.auth.replace_package_trust(
        [&image, &empty]
            .into_iter()
            .map(|image| {
                Ok(crate::PackageTrustPinV1 {
                    tenant_id: uuid::Uuid::from_bytes([1; 16]).to_string(),
                    bundle_digest: image.digest()?,
                })
            })
            .collect::<araphor_data::Result<Vec<_>>>()?,
    )?;
    let data = fixture.service.data()?.store.clone();
    let members = data.active_managed(&AnalysisReadControl::default())?.1;
    let lifecycle = data.subscribe_activations();
    fixture
        .package(
            PackageRequestV1::InstallImage {
                bundle: image.clone(),
            },
            true,
        )
        .await?;
    assert_eq!(
        data.active_managed(&AnalysisReadControl::default())?.1,
        members
    );
    assert!(!lifecycle.has_changed()?);
    fixture
        .package(
            PackageRequestV1::InstallImage {
                bundle: empty.clone(),
            },
            true,
        )
        .await?;
    let before = data.meta()?;
    let notices = data.subscribe_revision();
    assert!(
        matches!(fixture.package(PackageRequestV1::TestImage { artifact: None, image:empty.root, fixture:None }, true).await?, PackageResponseV1::Tests(tests) if tests.is_empty())
    );
    let PackageResponseV1::Tests(tests) = fixture.package(operation.clone(), true).await? else {
        return Err("fixture results".into());
    };
    assert_eq!(
        tests,
        vec![
            araphor_data::FixtureResult {
                fixture: "equal".into(),
                passed: true
            },
            araphor_data::FixtureResult {
                fixture: "different".into(),
                passed: false
            }
        ]
    );
    let PackageResponseV1::Tests(named) = fixture
        .package(
            PackageRequestV1::TestImage {
                artifact: None,
                image: image.root.clone(),
                fixture: Some("different".into()),
            },
            true,
        )
        .await?
    else {
        return Err("named fixture results".into());
    };
    assert_eq!(named, vec![tests[1].clone()]);
    for (reference, name) in [
        (image.root.clone(), Some("missing".into())),
        (
            PackageRefV1 {
                revision: "missing".into(),
                ..image.root.clone()
            },
            None,
        ),
    ] {
        assert_eq!(
            fixture
                .package(
                    PackageRequestV1::TestImage {
                        artifact: None,
                        image: reference,
                        fixture: name
                    },
                    true
                )
                .await
                .err()
                .map(|error| error.code()),
            Some(tonic::Code::NotFound)
        );
    }
    assert_eq!(
        fixture
            .package(operation.clone(), false)
            .await
            .err()
            .map(|error| error.code()),
        Some(tonic::Code::Unauthenticated)
    );
    let narrowed = fixture.request(
        proto::PackageOperationRequest {
            definition: operation.encode()?,
            selection: Some(proto::InputSelection {
                node_ids: vec!["node-a".into()],
                ..Default::default()
            }),
        },
        true,
    )?;
    assert_eq!(
        fixture
            .service
            .package_operation(narrowed)
            .await
            .err()
            .map(|error| error.code()),
        Some(tonic::Code::InvalidArgument)
    );
    fixture.service.auth.replace_package_trust(Vec::new())?;
    assert_eq!(
        fixture
            .package(operation.clone(), true)
            .await
            .err()
            .map(|error| error.code()),
        Some(tonic::Code::PermissionDenied)
    );
    assert_eq!(data.meta()?, before);
    assert!(!notices.has_changed()?);
    assert_eq!(
        data.active_managed(&AnalysisReadControl::default())?.1,
        members
    );
    assert!(!lifecycle.has_changed()?);
    assert!(data
        .active_managed(&AnalysisReadControl::default())?
        .1
        .is_empty());
    fixture.service.auth.replace_package_managers(Vec::new())?;
    assert!(matches!(
        fixture
            .package(
                PackageRequestV1::InspectImage {
                    package_id: image.root.package_id.clone(),
                    revision: Some(image.root.revision.clone())
                },
                false
            )
            .await?,
        PackageResponseV1::Image(_)
    ));
    assert_eq!(
        fixture
            .package(operation, true)
            .await
            .err()
            .map(|error| error.code()),
        Some(tonic::Code::PermissionDenied)
    );
    Ok(())
}

#[test]
fn image_reply_checks_trust() -> TestResult {
    const WAIT: std::time::Duration = std::time::Duration::from_secs(30);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .max_blocking_threads(1)
        .build()?;
    runtime.block_on(async {
        let fixture = Fixture::new()?;
        let child = fixtures()?;
        let artifact = child.root.clone();
        let image = container(child)?;
        let digest = image.digest()?;
        fixture
            .service
            .auth
            .replace_package_managers(vec![crate::InvestigateGrant {
                subject: "alice".into(),
                tenant_id: uuid::Uuid::from_bytes([1; 16]).to_string(),
            }])?;
        let trust = crate::PackageTrustPinV1 {
            tenant_id: uuid::Uuid::from_bytes([1; 16]).to_string(),
            bundle_digest: digest,
        };
        fixture.service.auth.replace_package_trust(vec![trust.clone()])?;
        fixture
            .package(PackageRequestV1::InstallImage { bundle: image.clone() }, true)
            .await?;
        let data = fixture.service.data()?.store.clone();
        let before = data.meta()?;
        let notices = data.subscribe_revision();
        let request = PackageRequestV1::TestImage { artifact: Some(artifact),
            image: image.root,
            fixture: None,
        };
        let rpc = fixture.service.package_operation(fixture.request(
            proto::PackageOperationRequest {
                definition: request.encode()?,
                selection: None,
            },
            true,
        )?);
        tokio::pin!(rpc);
        let (first_entered, first_entry) = tokio::sync::oneshot::channel();
        let (first_release, first_receiver) = std::sync::mpsc::channel();
        let first = tokio::task::spawn_blocking(move || {
            let _sent = first_entered.send(());
            first_receiver.recv()
        });
        tokio::time::timeout(WAIT, first_entry).await??;
        assert!(futures_util::poll!(rpc.as_mut()).is_pending());
        let (second_entered, second_entry) = tokio::sync::oneshot::channel();
        let (second_release, second_receiver) = std::sync::mpsc::channel();
        let second = tokio::task::spawn_blocking(move || {
            let _sent = second_entered.send(());
            second_receiver.recv()
        });
        first_release.send(())?;
        first.await??;
        tokio::time::timeout(WAIT, second_entry).await??;
        assert!(futures_util::poll!(rpc.as_mut()).is_pending());
        fixture.service.auth.replace_package_trust(Vec::new())?;
        second_release.send(())?;
        let reply = tokio::time::timeout(WAIT, rpc).await?;
        second.await??;
        assert_eq!(reply.err().map(|error| error.code()), Some(tonic::Code::PermissionDenied));
        assert_eq!(data.meta()?, before);
        assert!(!notices.has_changed()?);
        fixture.service.auth.replace_package_trust(vec![trust])?;
        assert!(matches!(fixture.package(request, true).await?, PackageResponseV1::Tests(tests) if tests.len() == 2));
        assert_eq!(data.meta()?, before);
        Ok(())
    })
}
