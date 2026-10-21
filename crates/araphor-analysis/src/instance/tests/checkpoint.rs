use super::*;

fn checkpoint_output(
    fixture: &Fixture,
    instance: &Instance,
    receipt: &ManagedReceipt,
    target: &str,
    value: u64,
) -> TestResult<araphor_data::ManagedResult> {
    assert_eq!(fixture.selected("checkpoint", &receipt.attempt)?, [value]);
    assert_eq!(receipt.results.len(), 1);
    let reference = receipt.results.values().next().ok_or("checkpoint result")?;
    let result = fixture.query.store().managed_result(
        instance.admitted(),
        &reference.result_id,
        10,
        &AnalysisReadControl::default(),
    )?;
    assert_eq!(reference.commit_revision, receipt.commit_revision);
    assert_eq!(result.commit_revision, receipt.commit_revision);
    assert_eq!(result.context.target, target);
    if target == "native" {
        assert!(result.context.artifact.is_some());
    }
    assert_eq!(result.output.datasets.len(), 1);
    assert_eq!(result.output.datasets[0].name, "data");
    assert_eq!(values(&result.output.datasets[0].batches)?, [value]);
    let checkpoint = result
        .output
        .checkpoint
        .as_ref()
        .ok_or("saved checkpoint")?;
    assert_eq!(checkpoint.version, 1);
    assert_eq!(checkpoint.datasets.len(), 1);
    assert_eq!(checkpoint.datasets[0].name, "state");
    assert_eq!(values(&checkpoint.datasets[0].batches)?, [value]);
    Ok(result)
}

async fn checkpoint_replay(target: &str) -> TestResult {
    let limits = araphor_query::execution::Limits {
        global_evaluations: Some(1),
        tenant_evaluations: Some(1),
        extract_timeout: Some(Duration::from_secs(30)),
        evaluate_timeout: Some(Duration::from_secs(30)),
        ..Default::default()
    };
    let fixture = Fixture::new(limits.clone())?;
    let image = bundle(target)?;
    fixture.install(&image)?;
    let instance = fixture.admit("checkpoint", r#"SELECT * FROM "runtime-fixture"."1".accumulate(input => (SELECT CAST(3 AS BIGINT UNSIGNED) AS value))"#).await?;
    assert_eq!(fixture.progress("checkpoint")?, 0);
    let initial = instance
        .run(request("initial"), &AnalysisReadControl::default())
        .await?;
    let installed = checkpoint_output(&fixture, &instance, &initial, target, 3)?;
    assert_eq!(fixture.progress("checkpoint")?, initial.commit_revision);
    if let PackageImplementationV1::Native {
        artifact,
        qualification,
        ..
    } = &image.artifacts[0].implementations[0]
    {
        let identity = installed
            .context
            .artifact
            .as_ref()
            .ok_or("native artifact")?;
        assert_eq!(
            identity.digest,
            araphor_package::Qualification::digest(artifact)
        );
        assert_eq!(
            identity.closure_digest.as_ref(),
            Some(
                &qualification
                    .as_ref()
                    .ok_or("native qualification")?
                    .closure_digest(artifact)?
            )
        );
        assert_eq!(
            identity.platform.as_deref(),
            Some(std::env::var("ARAPHOR_NATIVE_TARGET")?.as_str())
        );
    }
    let first = instance
        .run(request("first"), &AnalysisReadControl::default())
        .await?;
    let original = checkpoint_output(&fixture, &instance, &first, target, 6)?;
    assert_eq!(fixture.progress("checkpoint")?, first.commit_revision);
    let model = &image.artifacts[0].descriptor.exports[0];
    let packet = sdk::wire::Output::encode_model(&original.output, model, original.limits)?;
    let before = fixture.query.store().meta()?;
    assert_eq!(
        instance
            .run(request("first"), &AnalysisReadControl::default())
            .await?,
        first
    );
    checkpoint_output(&fixture, &instance, &first, target, 6)?;
    assert_eq!(fixture.progress("checkpoint")?, first.commit_revision);
    assert_eq!(fixture.query.store().meta()?, before);
    let definition = instance.admitted().spec.definition.clone();
    drop(instance);
    let Fixture {
        directory,
        query,
        authority,
        grant,
    } = fixture;
    drop(query);
    let query = Engine::new(
        Arc::new(AnalysisStore::open(directory.path().join("data"))?),
        limits,
    )?;
    let instance = Instance::admit(
        Arc::clone(&query),
        authority.clone(),
        grant.clone(),
        "checkpoint".into(),
        definition,
        &AnalysisReadControl::default(),
    )
    .await?;
    let fixture = Fixture {
        directory,
        query,
        authority,
        grant,
    };
    let before = fixture.query.store().meta()?;
    assert_eq!(
        instance
            .run(request("first"), &AnalysisReadControl::default())
            .await?,
        first
    );
    checkpoint_output(&fixture, &instance, &first, target, 6)?;
    assert_eq!(fixture.progress("checkpoint")?, first.commit_revision);
    assert_eq!(fixture.query.store().meta()?, before);
    let second = instance
        .run(request("second"), &AnalysisReadControl::default())
        .await?;
    checkpoint_output(&fixture, &instance, &second, target, 9)?;
    assert_ne!(second.results, first.results);
    assert_eq!(fixture.progress("checkpoint")?, second.commit_revision);
    let retained = checkpoint_output(&fixture, &instance, &first, target, 6)?;
    assert!(!retained.current);
    assert_eq!(retained.context, original.context);
    assert_eq!(retained.commit_revision, original.commit_revision);
    assert_eq!(retained.limits, original.limits);
    assert_eq!(
        sdk::wire::Output::encode_model(&retained.output, model, retained.limits)?,
        packet
    );
    let before = fixture.query.store().meta()?;
    assert_eq!(
        instance
            .run(request("first"), &AnalysisReadControl::default())
            .await?,
        first
    );
    assert_eq!(fixture.progress("checkpoint")?, second.commit_revision);
    assert_eq!(
        instance
            .run(request("second"), &AnalysisReadControl::default())
            .await?,
        second
    );
    checkpoint_output(&fixture, &instance, &second, target, 9)?;
    assert_eq!(fixture.progress("checkpoint")?, second.commit_revision);
    assert_eq!(fixture.query.store().meta()?, before);
    drop(fixture.query.reserve_evaluation([1; 16])?);
    Ok(())
}

#[tokio::test]
async fn wasm_checkpoint_reopens() -> TestResult {
    checkpoint_replay("wasm").await
}

#[tokio::test]
#[ignore = "requires source-built native artifacts in ARAPHOR_NATIVE_DIR"]
async fn native_checkpoint_reopens() -> TestResult {
    checkpoint_replay("native").await
}

#[tokio::test]
#[ignore = "requires source-built native artifacts in ARAPHOR_NATIVE_DIR"]
async fn native_overflow_keeps_checkpoint() -> TestResult {
    let fixture = Fixture::new(araphor_query::execution::Limits {
        global_evaluations: Some(4),
        tenant_evaluations: Some(4),
        ..Default::default()
    })?;
    let image = bundle("native")?;
    fixture.install(&image)?;
    let instance = fixture.admit("checkpoint", r#"SELECT * FROM "runtime-fixture"."1".accumulate(input => (SELECT CAST(18446744073709551615 AS BIGINT UNSIGNED) AS value))"#).await?;
    let receipt = instance
        .run(request("initial"), &AnalysisReadControl::default())
        .await?;
    let stored = checkpoint_output(&fixture, &instance, &receipt, "native", u64::MAX)?;
    let model = &image.artifacts[0].descriptor.exports[0];
    let packet = sdk::wire::Output::encode_model(&stored.output, model, stored.limits)?;
    let before = fixture
        .query
        .store()
        .managed_instance([1; 16], "checkpoint", &AnalysisReadControl::default())?
        .ok_or("managed instance")?;
    let error = instance
        .run(request("overflow"), &AnalysisReadControl::default())
        .await
        .err()
        .ok_or("overflow published")?;
    let crate::Error::Query { source } = &error else {
        return Err(format!("overflow lost Query error: {error:?}").into());
    };
    assert_eq!(
        araphor_query::Failure::from(source),
        araphor_query::Failure::InputTooLarge
    );
    assert_eq!(
        Subscription::failure(&error),
        araphor_data::ManagedExit::Failed(Code::Limit)
    );
    let mut source: Option<&(dyn std::error::Error + 'static)> = Some(&error);
    let mut limit = false;
    while let Some(current) = source {
        if matches!(current.downcast_ref::<sdk::Error>(), Some(sdk::Error::Contract { code: sdk::ErrorCode::Limit, field, .. }) if field == "checkpoint sum")
        {
            limit = true;
            break;
        }
        source = current.source();
    }
    assert!(
        limit,
        "native checkpoint overflow lost its SDK error: {error:?}"
    );
    let after = fixture
        .query
        .store()
        .managed_instance([1; 16], "checkpoint", &AnalysisReadControl::default())?
        .ok_or("managed instance")?;
    assert_eq!(after, before);
    let original = checkpoint_output(&fixture, &instance, &receipt, "native", u64::MAX)?;
    assert!(original.current);
    assert_eq!(original.context, stored.context);
    assert_eq!(original.commit_revision, stored.commit_revision);
    assert_eq!(
        sdk::wire::Output::encode_model(&original.output, model, original.limits)?,
        packet
    );
    assert_eq!(
        fixture.query.store().managed_history(
            &fixture.grant.selection,
            "checkpoint",
            &AnalysisReadControl::default()
        )?,
        [receipt]
    );
    let failed = fixture
        .query
        .store()
        .managed_attempt(
            [1; 16],
            "checkpoint",
            "overflow",
            &AnalysisReadControl::default(),
        )?
        .ok_or("overflow attempt")?;
    assert!(failed.receipt().is_none());
    assert_eq!(
        failed.terminal().ok_or("overflow terminal")?.exit,
        araphor_data::ManagedExit::Failed(Code::Limit)
    );
    assert!(fixture
        .query
        .store()
        .managed_selected(
            [1; 16],
            "checkpoint",
            "overflow",
            &AnalysisReadControl::default()
        )?
        .is_none());
    let mut permits = Vec::new();
    for _ in 0..4 {
        permits.push(fixture.query.reserve_evaluation([1; 16])?);
    }
    assert!(fixture.query.reserve_evaluation([1; 16]).is_err());
    drop(permits);
    Ok(())
}
