use super::*;

#[tokio::test]
async fn retained_runs_check_authority() -> TestResult {
    const CAPACITY: usize = 4 * 1024 * 1024;
    let fixture = Fixture::new(araphor_query::execution::Limits {
        input_capacity: Some(CAPACITY),
        output_capacity: Some(CAPACITY),
        global_evaluations: Some(1),
        tenant_evaluations: Some(1),
        ..Default::default()
    })?;
    let image = bundle("sql")?;
    fixture.install(&image)?;
    let instance = fixture
        .admit(
            "retained-authority",
            r#"SELECT * FROM "runtime-fixture"."1".accumulate(
        input => (SELECT CAST(11 AS BIGINT UNSIGNED) AS value))"#,
        )
        .await?;
    let owner = Arc::downgrade(&instance);
    let definition = instance.prepared.resolved().clone();
    let manifest = instance.admitted().spec.manifest.clone();
    let pointer = instance.prepared.images().next().ok_or("image absent")?.0
        as *const PackageBundleV1 as usize;
    let retained = fixture.query.memory().input_reserved();
    assert!(retained > 0 && retained < CAPACITY);
    assert_eq!(instance.prepared.images().count(), 1);
    assert_eq!(fixture.progress("retained-authority")?, 0);
    fixture.query.store().fault_write(
        "UPDATE package_revisions SET artifact = 'invalid'::BLOB",
        &[],
    )?;
    let session = fixture.query.session(
        fixture.grant.selection.clone(),
        &AnalysisReadControl::default(),
        10,
    )?;
    let error = session
        .prepare_resolved(&definition)
        .await
        .err()
        .ok_or("cold corrupted image accepted")?;
    assert!(
        matches!(
            &error,
            araphor_query::Error::Data {
                source: araphor_data::Error::AnalysisContract {
                    source: sdk::Error::Io { path, .. },
                    ..
                }
            }
            if path.as_path() == std::path::Path::new("<OCI archive>")
        ),
        "{error:?}"
    );
    drop(session);
    assert_eq!(fixture.query.memory().input_reserved(), retained);
    for (id, expected) in [("first", 11), ("second", 22)] {
        let receipt = instance
            .run(request(id), &AnalysisReadControl::default())
            .await?;
        assert_eq!(fixture.selected("retained-authority", id)?, [expected]);
        assert_eq!(receipt.results.len(), 1);
        assert_eq!(
            fixture.progress("retained-authority")?,
            receipt.commit_revision
        );
        assert_eq!(instance.prepared.resolved(), &definition);
        assert_eq!(instance.admitted().spec.manifest, manifest);
        assert_eq!(
            instance.prepared.images().next().ok_or("image absent")?.0 as *const PackageBundleV1
                as usize,
            pointer
        );
        assert_eq!(fixture.query.memory().input_reserved(), retained);
        drop(fixture.query.memory().reserve_output(CAPACITY)?);
        drop(fixture.query.reserve_evaluation([1; 16])?);
    }
    let before = fixture.query.store().meta()?;
    let progress = fixture.progress("retained-authority")?;
    *fixture
        .authority
        .allowed
        .lock()
        .map_err(|_| "authority lock")? = false;
    for id in ["grant-denied", "second"] {
        let error = instance
            .run(request(id), &AnalysisReadControl::default())
            .await
            .err()
            .ok_or("retained plan used a revoked grant")?;
        assert!(matches!(
            error,
            crate::Error::Data {
                source: araphor_data::Error::Package {
                    code: Code::Denied,
                    field: "instance fixture authority",
                    ..
                }
            }
        ));
        assert_eq!(fixture.query.store().meta()?, before);
    }
    assert!(fixture
        .query
        .store()
        .managed_attempt(
            [1; 16],
            "retained-authority",
            "grant-denied",
            &AnalysisReadControl::default(),
        )?
        .is_none());
    *fixture
        .authority
        .allowed
        .lock()
        .map_err(|_| "authority lock")? = true;
    fixture
        .authority
        .images
        .lock()
        .map_err(|_| "image trust lock")?
        .clear();
    let error = instance
        .run(request("trust-denied"), &AnalysisReadControl::default())
        .await
        .err()
        .ok_or("retained plan used an untrusted image")?;
    assert!(matches!(
        error,
        crate::Error::Data {
            source: araphor_data::Error::Package {
                code: Code::Denied,
                field: "instance fixture trust",
                ..
            }
        }
    ));
    assert_eq!(fixture.query.store().meta()?, before);
    assert_eq!(fixture.progress("retained-authority")?, progress);
    assert!(fixture
        .query
        .store()
        .managed_attempt(
            [1; 16],
            "retained-authority",
            "trust-denied",
            &AnalysisReadControl::default(),
        )?
        .is_none());
    assert_eq!(fixture.query.memory().input_reserved(), retained);
    drop(fixture.query.memory().reserve_output(CAPACITY)?);
    fixture
        .authority
        .images
        .lock()
        .map_err(|_| "image trust lock")?
        .insert(image.digest()?);
    let receipt = instance
        .run(request("restored"), &AnalysisReadControl::default())
        .await?;
    assert_eq!(fixture.selected("retained-authority", "restored")?, [33]);
    assert_eq!(
        fixture.progress("retained-authority")?,
        receipt.commit_revision
    );
    assert_eq!(instance.prepared.resolved(), &definition);
    assert_eq!(instance.admitted().spec.manifest, manifest);
    drop(instance);
    assert!(owner.upgrade().is_none());
    assert_eq!(fixture.query.memory().input_reserved(), 0);
    drop(fixture.query.memory().reserve_output(CAPACITY)?);
    drop(fixture.query.memory().reserve_input(CAPACITY)?);
    drop(fixture.query.memory().reserve_output(CAPACITY)?);
    drop(fixture.query.reserve_evaluation([1; 16])?);
    Ok(())
}
