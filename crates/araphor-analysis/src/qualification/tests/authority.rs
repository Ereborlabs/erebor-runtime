use super::*;

#[tokio::test]
async fn fixtures_enforce_authority() -> TestResult {
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
                "SELECT CAST(7 AS BIGINT UNSIGNED) AS value".into(),
            )]),
            ..Default::default()
        },
    )?;
    Fixture::save(
        &mut bundle,
        &Fixture::evaluation(&model),
        &sdk::Output {
            datasets: vec![Fixture::data("data", &[7])?],
            ..Default::default()
        },
        None,
    )?;
    for limit in [1, 4] {
        let fixture = Fixture::new(&bundle)?;
        fixture.authority.deny_at.store(limit, Ordering::SeqCst);
        assert!(matches!(
            fixture.run(&bundle).await,
            Err(crate::Error::Data {
                source: araphor_data::Error::Package {
                    code: Code::Denied,
                    field: "fixture authority",
                    ..
                }
            })
        ));
        assert_eq!(fixture.authority.checks.load(Ordering::SeqCst), limit);
    }
    let mut fixture = Fixture::new(&bundle)?;
    fixture.authority = Arc::new(Authority {
        digest: "untrusted".into(),
        checks: AtomicUsize::new(0),
        deny_at: AtomicUsize::new(usize::MAX),
        changes: tokio::sync::watch::channel(0).0,
    });
    fixture.owner.authority = fixture.authority.clone();
    assert!(matches!(
        fixture.run(&bundle).await,
        Err(crate::Error::Data {
            source: araphor_data::Error::Package {
                code: Code::Denied,
                field: "fixture trust",
                ..
            }
        })
    ));
    let fixture = Fixture::new(&bundle)?;
    assert!(matches!(
        fixture
            .owner
            .run(
                &fixture.grant,
                &bundle.root,
                Some("absent"),
                &AnalysisReadControl::default()
            )
            .await,
        Err(crate::Error::Data {
            source: araphor_data::Error::Package {
                code: Code::Missing,
                field: "package fixture",
                ..
            }
        })
    ));
    let mut grant = fixture.grant.clone();
    grant.selection = AnalysisSelectionV1::tenant([2; 16]);
    assert!(matches!(
        fixture
            .owner
            .run(&grant, &bundle.root, None, &AnalysisReadControl::default())
            .await,
        Err(crate::Error::Data {
            source: araphor_data::Error::Package {
                code: Code::Missing,
                field: "installed package image",
                ..
            }
        })
    ));
    bundle.artifacts[0].fixtures[0].time_utc_ns = -1;
    let fixture = Fixture::new(&bundle)?;
    assert!(matches!(
        fixture.run(&bundle).await,
        Err(crate::Error::Data {
            source: araphor_data::Error::Package {
                code: Code::Unsupported,
                field: "negative fixture time",
                ..
            }
        })
    ));
    Ok(())
}
