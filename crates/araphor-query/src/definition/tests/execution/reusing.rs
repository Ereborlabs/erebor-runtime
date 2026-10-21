use super::*;

#[tokio::test]
async fn prepared_closures_stay_pinned() -> TestResult {
    const CAPACITY: usize = 4 * 1024 * 1024;
    let fixture = Fixture::limits(Limits {
        input_capacity: Some(CAPACITY),
        output_capacity: Some(CAPACITY),
        global_evaluations: Some(1),
        tenant_evaluations: Some(1),
        ..Default::default()
    })?;
    for revision in ["r1", "r2", "r3"] {
        let mut image = Fixture::bundle();
        image.root.revision = revision.into();
        image.artifacts[0].descriptor.revision = revision.into();
        fixture.install(&image)?;
    }
    let first = r#"SELECT * FROM "fixture"."r1".count(
        source => (SELECT CAST(7 AS BIGINT UNSIGNED) AS value), increment => 2)"#;
    let second = r#"SELECT * FROM "fixture"."r2".count(
        source => (SELECT CAST(11 AS BIGINT UNSIGNED) AS value), increment => 3)"#;
    let prepared = fixture.prepare(&Fixture::sql(first)).await?;
    let copy = prepared.clone();
    assert!(Arc::ptr_eq(&prepared.admission, &copy.admission));
    let admission = Arc::downgrade(&prepared.admission);
    let image = Arc::downgrade(&prepared.admission.images[0].0);
    let charge = Arc::downgrade(&prepared.admission.images[0].2);
    let pins = prepared.resolved().images.clone();
    assert_eq!(pins.len(), 1);
    assert_eq!(pins[0].image.revision, "r1");
    assert_eq!(prepared.images().count(), 1);
    let calls = Fixture::calls(&copy.plan)?;
    let code = Arc::downgrade(&calls.first().ok_or("call absent")?.admitted);
    let metadata = Arc::downgrade(&calls.first().ok_or("call absent")?._metadata);
    for call in &calls {
        assert!(Arc::ptr_eq(&call.bundle, &prepared.admission.images[0].0));
        assert!(Arc::ptr_eq(&call._image, &prepared.admission.images[0].2));
    }
    drop(calls);
    let before = fixture.engine.store().meta()?;
    for id in ["first", "second"] {
        let output = fixture.execute(&copy, invocation(id)).await?;
        assert_eq!(values(&output.batches)?, [9]);
        assert_eq!(output.calls.len(), 1);
        assert_eq!(
            output
                .calls
                .values()
                .next()
                .ok_or("call absent")?
                .evaluation()
                .context
                .id,
            id
        );
        assert_eq!(copy.resolved().images, pins);
    }
    let both = fixture
        .prepare(&Fixture::sql(format!("{first} UNION ALL {second}")))
        .await?;
    assert_eq!(both.images().count(), 2);
    assert_eq!(
        both.resolved()
            .images
            .iter()
            .map(|pin| pin.image.revision.as_str())
            .collect::<Vec<_>>(),
        ["r1", "r2"]
    );
    let added = Arc::downgrade(&both.admission.images[1].0);
    {
        let output = fixture.execute(&both, invocation("both")).await?;
        let mut returned = values(&output.batches)?;
        returned.sort_unstable();
        assert_eq!(returned, [9, 14]);
        assert_eq!(output.calls.len(), 2);
    }
    let remaining = fixture.prepare(&Fixture::sql(second)).await?;
    assert_eq!(remaining.images().count(), 1);
    assert_eq!(remaining.resolved().images[0].image.revision, "r2");
    let last = Arc::downgrade(&remaining.admission.images[0].0);
    {
        let output = fixture.execute(&remaining, invocation("remaining")).await?;
        assert_eq!(values(&output.batches)?, [14]);
        assert_eq!(output.calls.len(), 1);
        let original = fixture.execute(&prepared, invocation("original")).await?;
        assert_eq!(values(&original.batches)?, [9]);
        assert_eq!(prepared.resolved().images, pins);
    }
    let empty = fixture
        .prepare(&Fixture::sql("SELECT CAST(7 AS BIGINT UNSIGNED) AS value"))
        .await?;
    assert_eq!(empty.images().count(), 0);
    assert!(empty.resolved().images.is_empty());
    {
        let output = fixture.execute(&empty, invocation("empty")).await?;
        assert_eq!(values(&output.batches)?, [7]);
        assert!(output.calls.is_empty());
    }
    assert_eq!(fixture.engine.store().meta()?, before);
    drop(both);
    assert!(added.upgrade().is_none());
    assert!(last.upgrade().is_some());
    drop(remaining);
    assert!(last.upgrade().is_none());
    drop(empty);
    drop(prepared);
    assert!(admission.upgrade().is_some());
    assert!(image.upgrade().is_some());
    assert!(charge.upgrade().is_some());
    assert!(code.upgrade().is_some());
    assert!(metadata.upgrade().is_some());
    drop(copy);
    assert!(admission.upgrade().is_none());
    assert!(image.upgrade().is_none());
    assert!(charge.upgrade().is_none());
    assert!(code.upgrade().is_none());
    assert!(metadata.upgrade().is_none());
    assert_eq!(fixture.engine.memory().input_reserved(), 0);
    drop(fixture.engine.memory().reserve_output(CAPACITY)?);
    drop(fixture.engine.memory().reserve_input(CAPACITY)?);
    drop(fixture.engine.memory().reserve_output(CAPACITY)?);
    drop(fixture.engine.reserve_evaluation([1; 16])?);
    Ok(())
}

#[tokio::test]
async fn prepared_owners_keep_scope() -> TestResult {
    const CAPACITY: usize = 4 * 1024 * 1024;
    let limits = Limits {
        input_capacity: Some(CAPACITY),
        output_capacity: Some(CAPACITY),
        ..Default::default()
    };
    let fixture = Fixture::limits(limits.clone())?;
    let image = Fixture::bundle();
    fixture.install(&image)?;
    let definition = Fixture::sql(
        r#"SELECT * FROM "fixture"."r1".count(
        source => (SELECT CAST(7 AS BIGINT UNSIGNED) AS value), increment => 2)"#,
    );
    let prepared = fixture.prepare(&definition).await?;
    let first = Arc::downgrade(&prepared.admission.images[0].0);
    let foreign = Engine::new(Arc::clone(fixture.engine.store()), limits)?;
    let other = foreign
        .prepare_definition(
            [1; 16],
            &definition,
            Arc::new(AnalysisReadControl::default()),
        )
        .await?;
    assert_eq!(other.resolved(), prepared.resolved());
    assert!(!Arc::ptr_eq(
        &other.admission.images[0].0,
        &prepared.admission.images[0].0
    ));
    assert!(!Arc::ptr_eq(
        &other.admission.images[0].2,
        &prepared.admission.images[0].2
    ));
    let second = Arc::downgrade(&other.admission.images[0].0);
    let missing = foreign
        .prepare_definition(
            [2; 16],
            &definition,
            Arc::new(AnalysisReadControl::default()),
        )
        .await
        .err()
        .ok_or("foreign tenant image loaded")?;
    assert!(matches!(
        missing,
        crate::Error::Data {
            source: araphor_data::Error::Package {
                code: araphor_data::PackageErrorCodeV1::Missing,
                field: "definition image revision",
                ..
            }
        }
    ));
    fixture
        .engine
        .store()
        .install_package_image([2; 16], &image, || Ok(()))?;
    let tenant = foreign
        .prepare_definition(
            [2; 16],
            &definition,
            Arc::new(AnalysisReadControl::default()),
        )
        .await?;
    assert_eq!(tenant.admission.tenant, [2; 16]);
    assert!(!Arc::ptr_eq(
        &tenant.admission.images[0].0,
        &other.admission.images[0].0
    ));
    let before = fixture.engine.store().meta()?;
    let session = foreign.session(
        AnalysisSelectionV1::tenant([2; 16]),
        &AnalysisReadControl::default(),
        NOW,
    )?;
    let denied = session
        .execute_definition(&prepared, invocation("wrong-tenant"))
        .await
        .err()
        .ok_or("foreign tenant plan executed")?;
    assert_eq!(crate::Failure::from(&denied), crate::Failure::Denied);
    {
        let output = session
            .execute_definition(&tenant, invocation("second-tenant"))
            .await?;
        assert_eq!(values(&output.batches)?, [9]);
        let output = foreign
            .session(
                AnalysisSelectionV1::tenant([1; 16]),
                &AnalysisReadControl::default(),
                NOW,
            )?
            .execute_definition(&other, invocation("other-owner"))
            .await?;
        assert_eq!(values(&output.batches)?, [9]);
    }
    drop(session);
    assert_eq!(fixture.engine.store().meta()?, before);
    drop(prepared);
    assert!(first.upgrade().is_none());
    assert!(second.upgrade().is_some());
    assert_eq!(fixture.engine.memory().input_reserved(), 0);
    assert!(foreign.memory().input_reserved() > 0);
    drop(other);
    assert!(second.upgrade().is_none());
    drop(tenant);
    assert_eq!(foreign.memory().input_reserved(), 0);
    drop(fixture.engine.memory().reserve_output(CAPACITY)?);
    drop(foreign.memory().reserve_output(CAPACITY)?);
    for engine in [&fixture.engine, &foreign] {
        drop(engine.memory().reserve_input(CAPACITY)?);
        drop(engine.memory().reserve_output(CAPACITY)?);
        drop(engine.reserve_evaluation([1; 16])?);
        drop(engine.reserve_evaluation([2; 16])?);
    }
    Ok(())
}

#[tokio::test]
async fn prepared_dependency_stays_pinned() -> TestResult {
    const CAPACITY: usize = 4 * 1024 * 1024;
    let fixture = Fixture::limits(Limits {
        input_capacity: Some(CAPACITY),
        output_capacity: Some(CAPACITY),
        ..Default::default()
    })?;
    let mut original = Fixture::bundle();
    original.root.package_id = "consumer".into();
    let root = &mut original.artifacts[0];
    root.descriptor.id = "consumer".into();
    root.descriptor.exports[0].reasons[0].code = "consumer.note".into();
    root.descriptor.exports[0].inputs[0].source =
        sdk::InputSource::Table(sdk::TableRef::Output(sdk::OutputRef {
            package: "fixture".into(),
            revision: "r1".into(),
            export: "count".into(),
            output: "result".into(),
        }));
    let PackageImplementationV1::Sql { program, .. } = &mut root.implementations[0] else {
        return Err("SQL root absent".into());
    };
    program.reasons[0].code = "consumer.note".into();
    original.artifacts.push(PackageArtifactV1 {
        descriptor: sdk::Package::new(
            "fixture",
            "r1",
            vec![sdk::Model::new(
                "count",
                vec![],
                vec![sdk::Port::new("result", Fixture::schema("value"))],
            )],
        ),
        implementations: vec![PackageImplementationV1::Sql {
            export: "count".into(),
            program: SqlModelV1 {
                outputs: BTreeMap::from([(
                    "result".into(),
                    "SELECT CAST(7 AS BIGINT UNSIGNED) AS value".into(),
                )]),
                ..Default::default()
            },
        }],
        fixtures: vec![],
    });
    original.artifacts.sort_by_key(PackageArtifactV1::reference);
    fixture.install(&original)?;
    let prepared = fixture
        .prepare(&Fixture::sql(
            r#"SELECT * FROM "consumer"."r1".count(increment => 2)"#,
        ))
        .await?;
    let retained = Arc::downgrade(&prepared.admission.images[0].0);
    let charge = Arc::downgrade(&prepared.admission.images[0].2);
    let mut replacement = original.clone();
    replacement.root.revision = "r2".into();
    replacement.artifacts[0].descriptor.revision = "r2".into();
    let sdk::InputSource::Table(sdk::TableRef::Output(source)) =
        &mut replacement.artifacts[0].descriptor.exports[0].inputs[0].source
    else {
        return Err("dependency input absent".into());
    };
    source.revision = "r2".into();
    replacement.artifacts[1].descriptor.revision = "r2".into();
    let PackageImplementationV1::Sql { program, .. } =
        &mut replacement.artifacts[1].implementations[0]
    else {
        return Err("SQL dependency absent".into());
    };
    program.outputs.insert(
        "result".into(),
        "SELECT CAST(17 AS BIGINT UNSIGNED) AS value".into(),
    );
    let mut changed = replacement.clone();
    changed.root.revision = "r1".into();
    changed.artifacts[0].descriptor.revision = "r1".into();
    let before = fixture.engine.store().meta()?;
    assert!(matches!(
        fixture
            .engine
            .store()
            .install_package_image([1; 16], &changed, || Ok(())),
        Err(araphor_data::Error::AnalysisConflict { .. })
    ));
    assert_eq!(fixture.engine.store().meta()?, before);
    assert!(fixture
        .engine
        .store()
        .package_revision([1; 16], "fixture", "r2")?
        .is_none());
    fixture.install(&replacement)?;
    let updated = fixture
        .prepare(&Fixture::sql(
            r#"SELECT * FROM "consumer"."r2".count(increment => 2)"#,
        ))
        .await?;
    assert_eq!(prepared.images().count(), 1);
    assert_eq!(updated.images().count(), 1);
    for (definition, expected) in [(&prepared, &original), (&updated, &replacement)] {
        let (image, digest) = definition.images().next().ok_or("image absent")?;
        assert_eq!(image.root, expected.root);
        assert_eq!(image.artifacts, expected.artifacts);
        assert_eq!(digest, expected.digest()?);
        assert_eq!(definition.resolved().images.len(), 1);
        assert_eq!(definition.resolved().images[0].image, expected.root);
        assert_eq!(definition.resolved().images[0].digest, digest);
        let packages = Fixture::calls(&definition.plan)?
            .into_iter()
            .map(|call| call.package().clone())
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(
            packages,
            image
                .artifacts
                .iter()
                .map(PackageArtifactV1::reference)
                .collect::<std::collections::BTreeSet<_>>()
        );
    }
    let before = fixture.engine.store().meta()?;
    for (definition, id, expected) in [
        (&prepared, "old-before", 9),
        (&updated, "new", 19),
        (&prepared, "old-after", 9),
    ] {
        let output = fixture.execute(definition, invocation(id)).await?;
        assert_eq!(values(&output.batches)?, [expected]);
        assert_eq!(output.calls.len(), 2);
    }
    assert_eq!(fixture.engine.store().meta()?, before);
    assert!(retained.upgrade().is_some());
    drop(updated);
    assert!(retained.upgrade().is_some());
    drop(prepared);
    assert!(retained.upgrade().is_none());
    assert!(charge.upgrade().is_none());
    assert_eq!(fixture.engine.memory().input_reserved(), 0);
    drop(fixture.engine.memory().reserve_output(CAPACITY)?);
    drop(fixture.engine.memory().reserve_input(CAPACITY)?);
    drop(fixture.engine.memory().reserve_output(CAPACITY)?);
    Ok(())
}
