use std::sync::atomic::AtomicUsize;

use araphor_data::ManagedExit;

use super::*;

fn saved_request(actual: &ManagedRequest, supplied: &ManagedRequest) -> TestResult {
    let frontier = actual.frontier.as_ref().ok_or("finite captured frontier")?;
    araphor_query::follow::Cursor::decode(&frontier.cursor)?;
    let mut expected = supplied.clone();
    expected.frontier = Some(frontier.clone());
    assert_eq!(actual, &expected);
    Ok(())
}

async fn guest_failure_persists(target: &str, modes: &[(&str, Code)]) -> TestResult {
    const OUTPUT: usize = 8 * 1024 * 1024;
    for &(mode, code) in modes {
        let limits = araphor_query::execution::Limits {
            global_evaluations: Some(4),
            tenant_evaluations: Some(4),
            output_capacity: Some(OUTPUT),
            evaluate_timeout: Some(Duration::from_secs(10)),
            ..Default::default()
        };
        let fixture = Fixture::new(limits.clone())?;
        let instance = fixture.terminal_target(mode, mode, target).await?;
        let held = fixture.query.memory().input_reserved();
        let input = request("known-failure");
        let error = tokio::time::timeout(
            Duration::from_secs(30),
            instance.run(input.clone(), &AnalysisReadControl::default()),
        )
        .await?
        .err()
        .ok_or("guest failure published")?;
        assert_eq!(
            Subscription::failure(&error),
            ManagedExit::Failed(code),
            "{error:?}"
        );
        let saved = fixture
            .query
            .store()
            .managed_attempt([1; 16], mode, &input.id, &AnalysisReadControl::default())?
            .ok_or("known attempt")?;
        let terminal = saved.terminal().ok_or("known terminal")?.clone();
        assert_eq!(terminal.exit, ManagedExit::Failed(code));
        assert!(!terminal.suspended);
        let status = Instance::read_status(
            Arc::clone(&fixture.query),
            fixture.authority.clone(),
            fixture.grant.clone(),
            mode,
            &AnalysisReadControl::default(),
        )
        .await?;
        assert!(
            matches!(status.readiness, araphor_data::PackageReadinessV1::Failed { code: actual, .. } if actual == code)
        );
        assert_eq!(status.status_progress, 0);
        saved_request(saved.request(), &input)?;
        assert!(saved.receipt().is_none());
        assert!(fixture
            .query
            .store()
            .managed_selected([1; 16], mode, &input.id, &AnalysisReadControl::default())?
            .is_none());
        assert_eq!(fixture.progress(mode)?, 0);
        assert_eq!(fixture.query.memory().input_reserved(), held);
        let permits = (0..4)
            .map(|_| fixture.query.reserve_evaluation([1; 16]))
            .collect::<araphor_query::Result<Vec<_>>>()?;
        assert!(fixture.query.reserve_evaluation([1; 16]).is_err());
        drop(permits);
        drop(fixture.query.memory().reserve_output(OUTPUT)?);
        let before = fixture.query.store().meta()?;
        let error = instance
            .run(input.clone(), &AnalysisReadControl::default())
            .await
            .err()
            .ok_or("known ID executed again")?;
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
        assert_eq!(fixture.query.store().meta()?, before);
        let definition = instance.admitted().spec.definition.clone();
        let Fixture {
            directory,
            query,
            authority,
            grant,
        } = fixture;
        drop(instance);
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
        let saved = fixture
            .query
            .store()
            .managed_attempt([1; 16], mode, &input.id, &AnalysisReadControl::default())?
            .ok_or("recovered known attempt")?;
        assert_eq!(saved.terminal(), Some(&terminal));
        assert!(saved.receipt().is_none());
        saved_request(saved.request(), &input)?;
        assert_eq!(fixture.progress(mode)?, 0);
        let status = fixture.query.store().managed_status(
            &fixture.grant.selection,
            mode,
            &AnalysisReadControl::default(),
        )?;
        assert!(
            matches!(status.readiness, araphor_data::PackageReadinessV1::Failed { code: actual, .. } if actual == code)
        );
        assert_eq!(status.status_progress, 0);
        let instance = Instance::admit(
            Arc::clone(&fixture.query),
            fixture.authority.clone(),
            fixture.grant.clone(),
            mode.into(),
            definition,
            &AnalysisReadControl::default(),
        )
        .await?;
        let before = fixture.query.store().meta()?;
        let error = instance
            .run(input, &AnalysisReadControl::default())
            .await
            .err()
            .ok_or("recovered terminal executed again")?;
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
        assert_eq!(fixture.query.store().meta()?, before);
        let held = fixture.query.memory().input_reserved();
        let retry = request("retry-error");
        let error = instance
            .run(retry.clone(), &AnalysisReadControl::default())
            .await
            .err()
            .ok_or("reopened guest failure published")?;
        assert_eq!(
            Subscription::failure(&error),
            ManagedExit::Failed(code),
            "{error:?}"
        );
        let repeated = fixture
            .query
            .store()
            .managed_attempt([1; 16], mode, &retry.id, &AnalysisReadControl::default())?
            .ok_or("repeated failure attempt")?;
        assert_eq!(
            repeated.terminal().ok_or("repeated terminal")?.exit,
            ManagedExit::Failed(code)
        );
        saved_request(repeated.request(), &retry)?;
        assert!(repeated.receipt().is_none());
        assert!(fixture
            .query
            .store()
            .managed_selected([1; 16], mode, &retry.id, &AnalysisReadControl::default())?
            .is_none());
        assert!(fixture
            .query
            .store()
            .managed_history(
                &fixture.grant.selection,
                mode,
                &AnalysisReadControl::default()
            )?
            .is_empty());
        assert_eq!(fixture.progress(mode)?, 0);
        assert_eq!(fixture.query.memory().input_reserved(), held);
        let permits = (0..4)
            .map(|_| fixture.query.reserve_evaluation([1; 16]))
            .collect::<araphor_query::Result<Vec<_>>>()?;
        assert!(fixture.query.reserve_evaluation([1; 16]).is_err());
        drop(permits);
        drop(fixture.query.memory().reserve_output(OUTPUT)?);
    }
    Ok(())
}

#[tokio::test]
async fn finite_guest_failure_persists() -> TestResult {
    guest_failure_persists(
        "wasm",
        &[
            ("trap", Code::Incomplete),
            ("invalid-evidence", Code::Invalid),
            ("limit", Code::Limit),
        ],
    )
    .await
}

#[tokio::test]
#[ignore = "requires source-built native artifacts in ARAPHOR_NATIVE_DIR"]
async fn native_failures_survive_reopen() -> TestResult {
    guest_failure_persists(
        "native",
        &[
            ("trap", Code::Incomplete),
            ("limit", Code::Limit),
            ("denied", Code::Denied),
            ("invalid-name", Code::Invalid),
            ("invalid-evidence", Code::Invalid),
            ("oversized", Code::Invalid),
        ],
    )
    .await
}

#[tokio::test]
async fn finite_sql_preserves_progress() -> TestResult {
    let fixture = Fixture::new(Default::default())?;
    fixture.context(1)?;
    let instance = fixture.admit("sql-failure", "SELECT CAST(CASE WHEN owner_revision = 1 THEN CAST(owner_revision + 6 AS VARCHAR) ELSE CAST(owner_revision AS VARCHAR) || '-invalid' END AS BIGINT UNSIGNED) AS value FROM context_versions").await?;
    let receipt = instance
        .run(request("success"), &AnalysisReadControl::default())
        .await?;
    assert_eq!(fixture.selected("sql-failure", "success")?, [7]);
    fixture.context(2)?;
    let input = request("invalid-native-value");
    let error = instance
        .run(input.clone(), &AnalysisReadControl::default())
        .await
        .err()
        .ok_or("invalid SQL value published")?;
    assert_eq!(
        Subscription::failure(&error),
        ManagedExit::Failed(Code::Invalid),
        "{error:?}"
    );
    assert!(format!("{error:?}").contains("2-invalid"), "{error:?}");
    let saved = fixture
        .query
        .store()
        .managed_attempt(
            [1; 16],
            "sql-failure",
            &input.id,
            &AnalysisReadControl::default(),
        )?
        .ok_or("SQL failure attempt")?;
    assert_eq!(
        saved.terminal().ok_or("SQL terminal")?.exit,
        ManagedExit::Failed(Code::Invalid)
    );
    assert!(saved.receipt().is_none());
    assert_eq!(fixture.progress("sql-failure")?, receipt.commit_revision);
    let status = Instance::read_status(
        Arc::clone(&fixture.query),
        fixture.authority.clone(),
        fixture.grant.clone(),
        "sql-failure",
        &AnalysisReadControl::default(),
    )
    .await?;
    assert!(matches!(
        status.readiness,
        araphor_data::PackageReadinessV1::Failed {
            code: Code::Invalid,
            ..
        }
    ));
    assert_eq!(status.status_progress, receipt.commit_revision);
    assert_eq!(fixture.selected("sql-failure", "success")?, [7]);
    assert!(fixture
        .query
        .store()
        .managed_selected(
            [1; 16],
            "sql-failure",
            &input.id,
            &AnalysisReadControl::default()
        )?
        .is_none());
    Ok(())
}

#[tokio::test]
async fn failed_publication_rolls_back() -> TestResult {
    for source_changed in [false, true] {
        let code = if source_changed {
            Code::Conflict
        } else {
            Code::Invalid
        };
        let fixture = Fixture::new(Default::default())?;
        let instance = fixture
            .admit("publication", "SELECT CAST(7 AS BIGINT UNSIGNED) AS value")
            .await?;
        let commits = Arc::new(AtomicUsize::new(0));
        let entered = Arc::clone(&commits);
        fixture.query.store().set_commit_hook(
            araphor_data::AnalysisCommitStage::BeforeResultCommit,
            move || {
                entered.fetch_add(1, Ordering::SeqCst);
                if source_changed {
                    Err(araphor_data::Error::AnalysisSourceChanged {
                        location: snafu::location!(),
                    })
                } else {
                    Err(Code::Invalid.error("finite publication fixture"))
                }
            },
        )?;
        let input = request("publication-error");
        let error = instance
            .run(input.clone(), &AnalysisReadControl::default())
            .await
            .err()
            .ok_or("failed commit published")?;
        assert_eq!(Subscription::failure(&error), ManagedExit::Failed(code));
        assert_eq!(commits.load(Ordering::SeqCst), 1);
        let failed = fixture
            .query
            .store()
            .managed_attempt(
                [1; 16],
                "publication",
                &input.id,
                &AnalysisReadControl::default(),
            )?
            .ok_or("publication attempt")?;
        saved_request(failed.request(), &input)?;
        assert_eq!(
            failed.terminal().map(|terminal| terminal.exit),
            Some(ManagedExit::Failed(code))
        );
        assert!(failed.receipt().is_none());
        assert_eq!(fixture.progress("publication")?, 0);
        assert!(fixture
            .query
            .store()
            .managed_selected(
                [1; 16],
                "publication",
                &input.id,
                &AnalysisReadControl::default()
            )?
            .is_none());
        let before = fixture.query.store().meta()?;
        let error = instance
            .run(input, &AnalysisReadControl::default())
            .await
            .err()
            .ok_or("terminated publication replayed")?;
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
        assert_eq!(commits.load(Ordering::SeqCst), 1);
        assert_eq!(fixture.query.store().meta()?, before);
        let receipt = instance
            .run(request("after-rollback"), &AnalysisReadControl::default())
            .await?;
        assert!(receipt.commit_revision > before.commit_revision);
        assert_eq!(fixture.progress("publication")?, receipt.commit_revision);
        let selected = fixture
            .query
            .store()
            .managed_selected(
                [1; 16],
                "publication",
                &receipt.attempt,
                &AnalysisReadControl::default(),
            )?
            .ok_or("healthy publication selected output")?;
        assert_eq!(selected.data.batches.len(), 1);
        let batch = &selected.data.batches[0];
        assert_eq!(batch.num_rows(), 1);
        let values = batch
            .column(0)
            .as_any()
            .downcast_ref::<sdk::arrow_array::UInt64Array>()
            .ok_or("healthy selected value type")?;
        assert_eq!(values.value(0), 7);
        assert_eq!(commits.load(Ordering::SeqCst), 1);
    }
    Ok(())
}

#[tokio::test]
async fn finite_busy_keeps_attempt() -> TestResult {
    const OUTPUT: usize = 1024;
    let fixture = Fixture::new(araphor_query::execution::Limits {
        global_evaluations: Some(1),
        tenant_evaluations: Some(1),
        output_capacity: Some(OUTPUT),
        ..Default::default()
    })?;
    let instance = fixture
        .admit("busy", "SELECT CAST(7 AS BIGINT UNSIGNED) AS value")
        .await?;
    let pressure = fixture
        .query
        .memory()
        .reserve_output(OUTPUT - std::mem::size_of::<u64>())?;
    let input = request("offered-once");
    let error = instance
        .run(input.clone(), &AnalysisReadControl::default())
        .await
        .err()
        .ok_or("full output pool published")?;
    let crate::Error::Query { source } = error else {
        return Err(format!("Busy Query owner absent: {error:?}").into());
    };
    assert_eq!(
        araphor_query::Failure::from(&source),
        araphor_query::Failure::Busy,
        "{source:?}"
    );
    let pending = fixture
        .query
        .store()
        .managed_attempt([1; 16], "busy", &input.id, &AnalysisReadControl::default())?
        .ok_or("Busy attempt was not captured")?;
    saved_request(pending.request(), &input)?;
    assert!(pending.terminal().is_none());
    assert!(pending.receipt().is_none());
    assert_eq!(fixture.progress("busy")?, 0);
    assert!(fixture
        .query
        .store()
        .managed_selected([1; 16], "busy", &input.id, &AnalysisReadControl::default())?
        .is_none());
    drop(pressure);
    drop(fixture.query.reserve_evaluation([1; 16])?);
    drop(fixture.query.memory().reserve_output(OUTPUT)?);
    let before = fixture.query.store().meta()?;
    let error = instance
        .run(input.clone(), &AnalysisReadControl::default())
        .await
        .err()
        .ok_or("Busy cut silently replaced")?;
    assert!(matches!(
        error,
        crate::Error::Data {
            source: araphor_data::Error::Package {
                code: Code::Incomplete,
                field: "managed pending attempt",
                ..
            }
        }
    ));
    let current = fixture
        .query
        .store()
        .managed_attempt([1; 16], "busy", &input.id, &AnalysisReadControl::default())?
        .ok_or("original Busy attempt lost")?;
    assert_eq!(current.request(), pending.request());
    let replacement = request("different-pending-id");
    let error = instance
        .run(replacement.clone(), &AnalysisReadControl::default())
        .await
        .err()
        .ok_or("different ID replaced pending capture")?;
    assert!(matches!(
        error,
        crate::Error::Query {
            source: araphor_query::Error::Data {
                source: araphor_data::Error::Package {
                    code: Code::Incomplete,
                    field: "managed pending attempt",
                    ..
                }
            }
        }
    ));
    assert!(fixture
        .query
        .store()
        .managed_attempt(
            [1; 16],
            "busy",
            &replacement.id,
            &AnalysisReadControl::default()
        )?
        .is_none());
    assert_eq!(fixture.query.store().meta()?, before);
    assert_eq!(fixture.progress("busy")?, 0);
    assert_eq!(current.instance(), pending.instance());
    assert!(current.receipt().is_none());
    assert!(current.terminal().is_none());
    assert_eq!(fixture.query.store().meta()?, before);
    Ok(())
}
