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
    let packet = sdk::wire::Output::encode_model(&original.output, model)?;
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
    assert_eq!(
        sdk::wire::Output::encode_model(&retained.output, model)?,
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
    let limits = araphor_query::execution::Limits {
        global_evaluations: Some(4),
        tenant_evaluations: Some(4),
        ..Default::default()
    };
    let fixture = Fixture::new(limits.clone())?;
    let image = bundle("native")?;
    fixture.install(&image)?;
    let instance = fixture.admit("checkpoint", r#"SELECT * FROM "runtime-fixture"."1".accumulate(input => (SELECT CAST(18446744073709551615 AS BIGINT UNSIGNED) AS value))"#).await?;
    let receipt = instance
        .run(request("initial"), &AnalysisReadControl::default())
        .await?;
    let stored = checkpoint_output(&fixture, &instance, &receipt, "native", u64::MAX)?;
    let model = &image.artifacts[0].descriptor.exports[0];
    let packet = sdk::wire::Output::encode_model(&stored.output, model)?;
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
        sdk::wire::Output::encode_model(&original.output, model)?,
        packet
    );
    assert_eq!(
        fixture.query.store().managed_history(
            &fixture.grant.selection,
            "checkpoint",
            &AnalysisReadControl::default()
        )?,
        std::slice::from_ref(&receipt)
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
    let terminal = failed.terminal().ok_or("overflow terminal")?.clone();
    assert_eq!(
        terminal.exit,
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
    let definition = instance.admitted().spec.definition.clone();
    drop(instance);
    let Fixture {
        directory,
        query,
        authority,
        grant,
    } = fixture;
    drop(query);
    let fixture = Fixture {
        query: Engine::new(
            Arc::new(AnalysisStore::open(directory.path().join("data"))?),
            limits,
        )?,
        directory,
        authority,
        grant,
    };
    assert_eq!(
        fixture.query.store().managed_instance(
            [1; 16],
            "checkpoint",
            &AnalysisReadControl::default()
        )?,
        Some(before)
    );
    let instance = Instance::admit(
        Arc::clone(&fixture.query),
        fixture.authority.clone(),
        fixture.grant.clone(),
        "checkpoint".into(),
        definition,
        &AnalysisReadControl::default(),
    )
    .await?;
    let recovered = checkpoint_output(&fixture, &instance, &receipt, "native", u64::MAX)?;
    assert!(recovered.current);
    assert_eq!(recovered.context, stored.context);
    assert_eq!(recovered.commit_revision, stored.commit_revision);
    assert_eq!(
        sdk::wire::Output::encode_model(&recovered.output, model)?,
        packet
    );
    assert_eq!(fixture.progress("checkpoint")?, receipt.commit_revision);
    assert_eq!(
        fixture.query.store().managed_history(
            &fixture.grant.selection,
            "checkpoint",
            &AnalysisReadControl::default()
        )?,
        [receipt]
    );
    let reopened = fixture
        .query
        .store()
        .managed_attempt(
            [1; 16],
            "checkpoint",
            "overflow",
            &AnalysisReadControl::default(),
        )?
        .ok_or("reopened overflow attempt")?;
    assert_eq!(reopened.request(), failed.request());
    assert_eq!(reopened.terminal(), Some(&terminal));
    assert!(reopened.receipt().is_none());
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
    let fence = fixture.query.store().meta()?;
    let error = instance
        .run(request("overflow"), &AnalysisReadControl::default())
        .await
        .err()
        .ok_or("overflow terminal replayed")?;
    assert!(matches!(
        error,
        crate::Error::Data {
            source: araphor_data::Error::Package {
                code: Code::Conflict,
                field: "managed attempt terminated",
                ..
            }
        }
    ));
    assert_eq!(fixture.query.store().meta()?, fence);
    let mut permits = Vec::new();
    for _ in 0..4 {
        permits.push(fixture.query.reserve_evaluation([1; 16])?);
    }
    assert!(fixture.query.reserve_evaluation([1; 16]).is_err());
    drop(permits);
    Ok(())
}

#[cfg(target_os = "linux")]
#[tokio::test]
#[ignore = "requires source-built native artifacts in ARAPHOR_NATIVE_DIR"]
async fn native_faults_reopen() -> TestResult {
    use std::os::unix::process::ExitStatusExt as _;
    use std::process::Command;

    const NEXT: &str = r#"SELECT * FROM "runtime-fixture"."2".accumulate(input => (SELECT CAST(3 AS BIGINT UNSIGNED) AS value))"#;
    let limits = araphor_query::execution::Limits {
        global_evaluations: Some(4),
        tenant_evaluations: Some(4),
        ..Default::default()
    };
    let control = AnalysisReadControl::default();
    if let Some(root) = std::env::var_os("ARAPHOR_NATIVE_HOST_ROOT") {
        let query = Engine::new(
            Arc::new(AnalysisStore::open(
                std::path::PathBuf::from(root).join("data"),
            )?),
            limits,
        )?;
        let before = query
            .store()
            .managed_instance([1; 16], "checkpoint", &control)?
            .ok_or("Native fault instance")?;
        let definition = query
            .admit_definition(
                [1; 16],
                Fixture::definition(NEXT),
                Arc::new(AnalysisReadControl::default()),
            )
            .await?;
        query
            .store()
            .admit_definition([1; 16], &definition, || Ok(()))?;
        let authority = Arc::new(Authority {
            allowed: Mutex::new(true),
            images: Mutex::new(
                before
                    .spec
                    .definition
                    .images
                    .iter()
                    .chain(&definition.images)
                    .map(|image| image.digest.clone())
                    .collect(),
            ),
            changes: tokio::sync::watch::channel(0).0,
            deny_next: AtomicBool::new(false),
            checked: Mutex::default(),
            revoked: Mutex::default(),
        });
        let instance = Instance::admit(
            Arc::clone(&query),
            authority.clone(),
            before.grant.clone(),
            "checkpoint".into(),
            before.spec.definition.clone(),
            &control,
        )
        .await?;
        let host = InstanceHost::new(Arc::clone(&query), authority);
        let history =
            query
                .store()
                .managed_history(&before.grant.selection, "checkpoint", &control)?;
        let mode = std::env::var("ARAPHOR_NATIVE_FIXTURE_FAULT")?;
        let error = tokio::time::timeout(
            Duration::from_secs(30),
            host.update(
                Arc::clone(&instance),
                before.lifecycle,
                definition,
                true,
                u64::MAX,
                &control,
            ),
        )
        .await?
        .err()
        .ok_or("Native fault published an update")?;
        if mode == "abort" {
            return Err(format!("Native abort returned: {error:?}").into());
        }
        assert_eq!(mode, "panic");
        assert_eq!(
            Subscription::failure(&error),
            araphor_data::ManagedExit::Failed(Code::Incomplete),
            "{error:?}"
        );
        let mut source: Option<&(dyn std::error::Error + 'static)> = Some(&error);
        let mut caught = false;
        while let Some(current) = source {
            if matches!(current.downcast_ref::<sdk::Error>(), Some(sdk::Error::Contract { code: sdk::ErrorCode::Failed, field, .. }) if field == "native panic")
            {
                caught = true;
                break;
            }
            source = current.source();
        }
        assert!(caught, "Native panic lost SDK cause: {error:?}");
        assert_eq!(
            query
                .store()
                .managed_instance([1; 16], "checkpoint", &control)?,
            Some(before.clone())
        );
        assert_eq!(
            query
                .store()
                .managed_history(&before.grant.selection, "checkpoint", &control)?,
            history
        );
        let permits = (0..4)
            .map(|_| query.reserve_evaluation([1; 16]))
            .collect::<araphor_query::Result<Vec<_>>>()?;
        assert!(query.reserve_evaluation([1; 16]).is_err());
        drop(permits);
        let recovered = instance.run(request("after-panic"), &control).await?;
        assert!(recovered.commit_revision > before.progress);
        return Ok(());
    }

    let mut fixture = Fixture::new(limits.clone())?;
    let image = bundle("native")?;
    fixture.install(&image)?;
    let instance = fixture.admit("checkpoint", r#"SELECT * FROM "runtime-fixture"."1".accumulate(input => (SELECT CAST(3 AS BIGINT UNSIGNED) AS value))"#).await?;
    let initial = instance.run(request("initial"), &control).await?;
    checkpoint_output(&fixture, &instance, &initial, "native", 3)?;
    let prior = instance.run(request("before-fault"), &control).await?;
    checkpoint_output(&fixture, &instance, &prior, "native", 6)?;
    let definition = instance.admitted().spec.definition.clone();
    drop(instance);
    let mut next = image.clone();
    next.root.revision = "2".into();
    next.artifacts[0].descriptor.revision = "2".into();
    fixture.install(&next)?;
    let prepared = fixture
        .query
        .prepare_definition(
            [1; 16],
            &Fixture::definition(NEXT),
            Arc::new(AnalysisReadControl::default()),
        )
        .await?;
    let target = prepared.resolved().clone();
    fixture
        .query
        .store()
        .admit_definition([1; 16], &target, || Ok(()))?;
    let target_spec = ManagedSpec {
        tenant: [1; 16],
        id: "checkpoint".into(),
        definition: target.clone(),
        manifest: Instance::manifest(&prepared)?.0,
        destination: araphor_data::ManagedDestination::Selected,
    };
    drop(prepared);
    let model = &image.artifacts[0].descriptor.exports[0];
    let mut candidate_generation = None;
    for mode in ["panic", "abort"] {
        let before = fixture
            .query
            .store()
            .managed_instance([1; 16], "checkpoint", &control)?
            .ok_or("prior Native instance")?;
        let instance = Instance::admit(
            Arc::clone(&fixture.query),
            fixture.authority.clone(),
            fixture.grant.clone(),
            "checkpoint".into(),
            definition.clone(),
            &control,
        )
        .await?;
        let prior_history = fixture.query.store().managed_history(
            &fixture.grant.selection,
            "checkpoint",
            &control,
        )?;
        assert_eq!(prior_history.len(), if mode == "panic" { 2 } else { 3 });
        let stored = prior_history
            .iter()
            .zip([3, 6, 9])
            .map(|(receipt, value)| {
                let result = checkpoint_output(&fixture, &instance, receipt, "native", value)?;
                let packet = sdk::wire::Output::encode_model(&result.output, model)?;
                Ok((receipt.clone(), result.context, packet))
            })
            .collect::<TestResult<Vec<_>>>()?;
        drop(instance);
        let Fixture {
            directory,
            query,
            authority,
            grant,
        } = fixture;
        drop(query);
        let marker = directory.path().join(mode);
        let status = Command::new(std::env::current_exe()?)
            .args([
                "--exact",
                "instance::tests::checkpoint::native_faults_reopen",
                "--ignored",
                "--nocapture",
            ])
            .env("ARAPHOR_NATIVE_HOST_ROOT", directory.path())
            .env("ARAPHOR_NATIVE_FIXTURE_FAULT", mode)
            .env("ARAPHOR_NATIVE_FIXTURE_MARKER", &marker)
            .status()?;
        assert_eq!(std::fs::read_to_string(&marker)?, mode);
        if mode == "panic" {
            assert!(status.success(), "Native panic child: {status}");
        } else {
            // SIGABRT is signal 6 on Linux.
            assert_eq!(status.signal(), Some(6), "Native abort child: {status}");
        }
        fixture = Fixture {
            query: Engine::new(
                Arc::new(AnalysisStore::open(directory.path().join("data"))?),
                limits.clone(),
            )?,
            directory,
            authority,
            grant,
        };
        let instance = Instance::admit(
            Arc::clone(&fixture.query),
            fixture.authority.clone(),
            fixture.grant.clone(),
            "checkpoint".into(),
            definition.clone(),
            &control,
        )
        .await?;
        let current = fixture
            .query
            .store()
            .managed_instance([1; 16], "checkpoint", &control)?
            .ok_or("reopened Native instance")?;
        let mut expected = before.clone();
        if mode == "panic" {
            assert!(current.progress > expected.progress);
            expected.progress = current.progress;
        }
        assert_eq!(current, expected);
        if mode == "panic" {
            let fence = fixture.query.store().meta()?;
            let candidate =
                fixture
                    .query
                    .store()
                    .prepare_managed_version(&current, &target_spec, || Ok(()))?;
            assert_eq!(fixture.query.store().meta()?, fence);
            assert_eq!(candidate.spec, target_spec);
            assert!(candidate.generation > current.generation);
            assert!(candidate.generation < current.progress);
            candidate_generation = Some(candidate.generation);
        } else {
            let generation = candidate_generation.ok_or("Native update candidate generation")?;
            assert_eq!(
                fixture.query.store().managed_version(
                    [1; 16],
                    "checkpoint",
                    generation,
                    &control
                )?,
                target_spec
            );
            let fence = fixture.query.store().meta()?;
            let error = fixture
                .query
                .store()
                .prepare_managed_version(&current, &target_spec, || Ok(()))
                .err()
                .ok_or("aborted candidate was not pending")?;
            assert!(matches!(
                error,
                araphor_data::Error::Package {
                    code: Code::Incomplete,
                    field: "managed pending attempt",
                    ..
                }
            ));
            assert_eq!(fixture.query.store().meta()?, fence);
            let recovered = instance.run(request("after-abort"), &control).await?;
            checkpoint_output(&fixture, &instance, &recovered, "native", 12)?;
            assert!(recovered.commit_revision > current.progress);
            let current = fixture
                .query
                .store()
                .managed_instance([1; 16], "checkpoint", &control)?
                .ok_or("Native instance after abort recovery")?;
            expected.progress = recovered.commit_revision;
            assert_eq!(current, expected);
            let fence = fixture.query.store().meta()?;
            let host = InstanceHost::new(Arc::clone(&fixture.query), fixture.authority.clone());
            let error = host
                .update(
                    Arc::clone(&instance),
                    current.lifecycle,
                    target.clone(),
                    true,
                    u64::MAX,
                    &control,
                )
                .await
                .err()
                .ok_or("aborted candidate update was repeated")?;
            assert!(
                matches!(
                    &error,
                    crate::Error::Query {
                        source: araphor_query::Error::Data {
                            source: araphor_data::Error::Package {
                                code: Code::Incomplete,
                                field: "managed pending attempt",
                                ..
                            }
                        }
                    }
                ),
                "Native update lost pending candidate: {error:?}"
            );
            assert_eq!(fixture.query.store().meta()?, fence);
            assert_eq!(
                fixture
                    .query
                    .store()
                    .managed_instance([1; 16], "checkpoint", &control)?,
                Some(current)
            );
            assert_eq!(
                fixture.query.store().managed_version(
                    [1; 16],
                    "checkpoint",
                    generation,
                    &control
                )?,
                target_spec
            );
        }
        let history = fixture.query.store().managed_history(
            &fixture.grant.selection,
            "checkpoint",
            &control,
        )?;
        assert_eq!(history.len(), if mode == "panic" { 3 } else { 4 });
        assert_eq!(&history[..prior_history.len()], prior_history.as_slice());
        let recovered = history.last().ok_or("Native fault recovery receipt")?;
        assert_eq!(
            recovered.attempt,
            if mode == "panic" {
                "after-panic"
            } else {
                "after-abort"
            }
        );
        checkpoint_output(
            &fixture,
            &instance,
            recovered,
            "native",
            if mode == "panic" { 9 } else { 12 },
        )?;
        let fence = fixture.query.store().meta()?;
        for ((receipt, context, packet), value) in stored.iter().zip([3, 6, 9]) {
            let result = checkpoint_output(&fixture, &instance, receipt, "native", value)?;
            assert_eq!(&result.context, context);
            assert_eq!(
                &sdk::wire::Output::encode_model(&result.output, model)?,
                packet
            );
            assert_eq!(
                instance.run(request(&receipt.attempt), &control).await?,
                *receipt
            );
        }
        assert_eq!(
            instance.run(request(&recovered.attempt), &control).await?,
            *recovered
        );
        assert_eq!(fixture.query.store().meta()?, fence);
        let permits = (0..4)
            .map(|_| fixture.query.reserve_evaluation([1; 16]))
            .collect::<araphor_query::Result<Vec<_>>>()?;
        assert!(fixture.query.reserve_evaluation([1; 16]).is_err());
        drop(permits);
        drop(instance);
    }
    Ok(())
}
