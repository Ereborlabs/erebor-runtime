use std::time::Duration;

use super::*;
use crate::instance::tests::{bundle, Fixture, TestResult};
use araphor_analysis_sdk as sdk;
use araphor_data::ManagedExit;
use araphor_package::PackageImplementationV1;
use futures_util::StreamExt as _;

mod capacity;

impl Fixture {
    pub(in crate::instance) async fn terminal_instance(
        &self,
        id: &str,
        mode: &str,
    ) -> TestResult<Arc<Instance>> {
        let mut image = bundle("wasm")?;
        let model = &mut image.artifacts[0].descriptor.exports[0];
        model.name = "evaluate".into();
        model.inputs.clear();
        model.checkpoint = None;
        model.parameters = sdk::Schema::new(vec![
            sdk::Field::new("mode", sdk::DataType::Utf8, false),
            sdk::Field::new("amount", sdk::DataType::UInt64, false),
        ]);
        let PackageImplementationV1::Wasm { exports, .. } =
            &mut image.artifacts[0].implementations[0]
        else {
            return Err("Wasm terminal fixture absent".into());
        };
        *exports = vec!["evaluate".into()];
        self.install(&image)?;
        self.context(1)?;
        let sql = format!(
            r#"SELECT * FROM "runtime-fixture"."1".evaluate(mode => '{mode}', amount => 0) WHERE EXISTS (SELECT 1 FROM context_versions)"#
        );
        self.admit(id, &sql).await
    }

    async fn terminal_stream(
        &self,
        id: &str,
        mode: &str,
    ) -> TestResult<(Arc<Instance>, Subscription)> {
        let instance = self.terminal_instance(id, mode).await?;
        let lifecycle = self.start(&instance)?;
        let stream = instance.subscribe(
            Arc::new(AnalysisReadControl::default()),
            u64::MAX,
            lifecycle,
        )?;
        Ok((instance, stream))
    }
}

#[test]
fn failure_keeps_package_codes() {
    use datafusion::error::DataFusionError;

    for code in [
        Code::Invalid,
        Code::Limit,
        Code::Denied,
        Code::Unsupported,
        Code::Missing,
        Code::Conflict,
        Code::Incomplete,
    ] {
        let error = crate::Error::from(code.error("direct terminal fixture"));
        assert_eq!(Subscription::failure(&error), ManagedExit::Failed(code));
        let error = crate::Error::from(araphor_query::Error::from(
            code.error("query terminal fixture"),
        ));
        assert_eq!(Subscription::failure(&error), ManagedExit::Failed(code));
        let error = crate::Error::from(araphor_query::Error::Sql {
            source: DataFusionError::External(Box::new(araphor_query::Error::from(
                code.error("wrapped query fixture"),
            ))),
        });
        assert_eq!(Subscription::failure(&error), ManagedExit::Failed(code));
        let source = DataFusionError::Context(
            "native worker".into(),
            Box::new(DataFusionError::External(Box::new(
                code.error("terminal fixture"),
            ))),
        );
        let error = crate::Error::from(araphor_query::Error::Sql { source });
        assert_eq!(Subscription::failure(&error), ManagedExit::Failed(code));
    }
    let denied = || araphor_data::Error::AnalysisReadDenied {
        location: snafu::location!(),
    };
    let error = crate::Error::from(denied());
    assert_eq!(
        Subscription::failure(&error),
        ManagedExit::Failed(Code::Denied)
    );
    assert_eq!(
        error.status_code(),
        erebor_runtime_error::StatusCode::PermissionDenied
    );
    assert_eq!(
        error.retry_hint(),
        erebor_runtime_error::RetryHint::NonRetryable
    );
    for notice in [false, true] {
        for wrapper in 0..3 {
            let source = if notice {
                araphor_query::Error::AuthorityChanged {
                    location: snafu::location!(),
                }
            } else {
                araphor_query::Error::from(denied())
            };
            let source = match wrapper {
                0 => source,
                1 => araphor_query::Error::Sql {
                    source: DataFusionError::External(Box::new(source)),
                },
                _ => araphor_query::Error::Sql {
                    source: DataFusionError::Shared(Arc::new(DataFusionError::Context(
                        "authority origin".into(),
                        Box::new(DataFusionError::External(Box::new(source))),
                    ))),
                },
            };
            assert_eq!(
                araphor_query::Failure::from(&source),
                araphor_query::Failure::Denied
            );
            let error = crate::Error::from(source);
            assert_eq!(
                Subscription::failure(&error),
                if notice {
                    ManagedExit::Cancelled
                } else {
                    ManagedExit::Failed(Code::Denied)
                }
            );
            assert_eq!(
                error.status_code(),
                erebor_runtime_error::StatusCode::PermissionDenied
            );
            assert_eq!(
                error.retry_hint(),
                erebor_runtime_error::RetryHint::NonRetryable
            );
        }
    }
    for resource in ["input capacity", "output capacity"] {
        let error = crate::Error::from(araphor_query::Error::Sql {
            source: DataFusionError::ResourcesExhausted(resource.into()),
        });
        assert_eq!(
            Subscription::failure(&error),
            ManagedExit::Failed(Code::Limit)
        );
    }
    let error = crate::Error::from(araphor_query::Error::Sql {
        source: DataFusionError::External(Box::new(sdk::Error::contract(
            sdk::ErrorCode::Unauthorized,
            "guest denied",
        ))),
    });
    assert_eq!(
        Subscription::failure(&error),
        ManagedExit::Failed(Code::Denied)
    );
}

#[tokio::test]
async fn joined_trap_becomes_durable() -> TestResult {
    let fixture = Fixture::new(araphor_query::execution::Limits {
        global_evaluations: Some(1),
        tenant_evaluations: Some(1),
        ..Default::default()
    })?;
    let (instance, mut stream) = fixture.terminal_stream("known-trap", "trap").await?;
    let error = tokio::time::timeout(Duration::from_secs(30), stream.next())
        .await?
        .ok_or("trap stream ended")?
        .err()
        .ok_or("trapped guest published")?;
    assert_eq!(
        Subscription::failure(&error),
        ManagedExit::Failed(Code::Incomplete)
    );
    assert_eq!(fixture.progress("known-trap")?, 0);
    assert!(fixture
        .query
        .store()
        .managed_resume([1; 16], "known-trap", &AnalysisReadControl::default())
        .is_err());
    let terminal = stream
        .cancel_and_join(&AnalysisReadControl::default())
        .await?
        .ok_or("known terminal absent")?;
    assert_eq!(terminal.exit, ManagedExit::Failed(Code::Incomplete));
    assert!(!terminal.suspended);
    let saved = fixture
        .query
        .store()
        .managed_attempt(
            [1; 16],
            "known-trap",
            &terminal.attempt,
            &AnalysisReadControl::default(),
        )?
        .ok_or("retained terminal absent")?;
    assert_eq!(saved.terminal(), Some(&terminal));
    assert!(saved.receipt().is_none());
    assert!(fixture
        .query
        .store()
        .managed_selected(
            [1; 16],
            "known-trap",
            &terminal.attempt,
            &AnalysisReadControl::default()
        )?
        .is_none());
    let current = fixture
        .query
        .store()
        .managed_instance([1; 16], "known-trap", &AnalysisReadControl::default())?
        .ok_or("trapped instance")?;
    assert_eq!(current.progress, 0);
    assert!(current.running);
    assert!(matches!(
        fixture.query.store().managed_resume(
            [1; 16],
            "known-trap",
            &AnalysisReadControl::default(),
        ),
        Err(araphor_data::Error::Package {
            code: Code::Incomplete,
            field: "managed capacity retry unavailable",
            ..
        })
    ));
    let error = instance
        .run(saved.request().clone(), &AnalysisReadControl::default())
        .await
        .err()
        .ok_or("terminal retry executed")?;
    assert_eq!(
        error.status_code(),
        erebor_runtime_error::StatusCode::AlreadyExists
    );
    drop(fixture.query.reserve_evaluation([1; 16])?);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn revoked_worker_joins_terminal() -> TestResult {
    let fixture = Fixture::new(araphor_query::execution::Limits {
        global_evaluations: Some(1),
        tenant_evaluations: Some(1),
        ..Default::default()
    })?;
    let (_, mut stream) = fixture
        .terminal_stream("joined-revocation", "cancel")
        .await?;
    let control = Arc::clone(&stream.control);
    let state = Arc::clone(&stream.state);
    let (entry, observed) = std::sync::mpsc::channel();
    let (release, waiting) = std::sync::mpsc::channel();
    fixture.query.guest_entry(entry, Some(waiting))?;
    let worker = tokio::spawn(async move {
        let result = stream.next().await;
        (stream, result)
    });
    let entered =
        tokio::task::spawn_blocking(move || observed.recv_timeout(Duration::from_secs(30))).await?;
    if let Err(error) = entered {
        let _released = release.send(());
        let _joined = worker.await?;
        return Err(format!("guest entry failed: {error}").into());
    }
    let attempt = state
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .attempt
        .clone()
        .ok_or("native attempt was not registered")?;
    fixture.authority.set(false);
    tokio::time::timeout(Duration::from_secs(30), control.cancelled()).await?;
    assert!(!worker.is_finished());
    assert!(fixture.query.reserve_evaluation([1; 16]).is_err());
    let pending = fixture
        .query
        .store()
        .managed_attempt(
            [1; 16],
            "joined-revocation",
            &attempt.request().id,
            &AnalysisReadControl::default(),
        )?
        .ok_or("pending worker attempt")?;
    assert!(pending.terminal().is_none());
    assert!(pending.receipt().is_none());
    assert!(
        fixture
            .query
            .store()
            .managed_instance(
                [1; 16],
                "joined-revocation",
                &AnalysisReadControl::default()
            )?
            .ok_or("running instance")?
            .running
    );
    release.send(())?;
    let (stream, result) = tokio::time::timeout(Duration::from_secs(30), worker).await??;
    let error = result
        .ok_or("revoked stream ended")?
        .err()
        .ok_or("revoked guest published")?;
    assert_eq!(
        error.status_code(),
        erebor_runtime_error::StatusCode::PermissionDenied
    );
    assert!(fixture
        .query
        .store()
        .managed_attempt(
            [1; 16],
            "joined-revocation",
            &attempt.request().id,
            &AnalysisReadControl::default()
        )?
        .ok_or("joined pending attempt")?
        .terminal()
        .is_none());
    let terminal = stream
        .cancel_and_join(&AnalysisReadControl::default())
        .await?
        .ok_or("revoked terminal absent")?;
    assert_eq!(terminal.exit, ManagedExit::Failed(Code::Denied));
    assert!(terminal.suspended);
    let araphor_data::ManagedResume {
        instance: current,
        frontier,
        ..
    } = fixture.query.store().managed_resume(
        [1; 16],
        "joined-revocation",
        &AnalysisReadControl::default(),
    )?;
    assert!(!current.running);
    assert_eq!(current.lifecycle, terminal.revision);
    assert_eq!(current.progress, 0);
    assert_eq!(frontier, None);
    drop(fixture.query.reserve_evaluation([1; 16])?);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn valid_notice_keeps_instance() -> TestResult {
    let fixture = Fixture::new(araphor_query::execution::Limits {
        global_evaluations: Some(1),
        tenant_evaluations: Some(1),
        ..Default::default()
    })?;
    let (_, mut stream) = fixture.terminal_stream("valid-notice", "cancel").await?;
    let before = fixture
        .query
        .store()
        .managed_instance([1; 16], "valid-notice", &AnalysisReadControl::default())?
        .ok_or("running instance")?;
    let control = Arc::clone(&stream.control);
    let state = Arc::clone(&stream.state);
    let (entry, observed) = std::sync::mpsc::channel();
    let (release, waiting) = std::sync::mpsc::channel();
    fixture.query.guest_entry(entry, Some(waiting))?;
    let worker = tokio::spawn(async move {
        let result = stream.next().await;
        (stream, result)
    });
    let entered =
        tokio::task::spawn_blocking(move || observed.recv_timeout(Duration::from_secs(30))).await?;
    if let Err(error) = entered {
        let _released = release.send(());
        let _joined = worker.await?;
        return Err(format!("guest entry failed: {error}").into());
    }
    let attempt = state
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .attempt
        .clone()
        .ok_or("native notice attempt")?;
    let registered = fixture.query.store().meta()?;
    fixture.authority.set(true);
    tokio::time::timeout(Duration::from_secs(30), control.cancelled()).await?;
    assert!(!worker.is_finished());
    assert!(fixture.query.reserve_evaluation([1; 16]).is_err());
    let pending = fixture
        .query
        .store()
        .managed_attempt(
            [1; 16],
            "valid-notice",
            &attempt.request().id,
            &AnalysisReadControl::default(),
        )?
        .ok_or("held notice attempt")?;
    assert!(pending.terminal().is_none());
    assert!(pending.receipt().is_none());
    assert_eq!(fixture.query.store().meta()?, registered);
    release.send(())?;
    let (stream, result) = tokio::time::timeout(Duration::from_secs(30), worker).await??;
    let error = result
        .ok_or("notice stream ended")?
        .err()
        .ok_or("notice published")?;
    assert_eq!(Subscription::failure(&error), ManagedExit::Cancelled);
    assert_eq!(fixture.query.store().meta()?, registered);
    let terminal = stream
        .cancel_and_join(&AnalysisReadControl::default())
        .await?
        .ok_or("notice terminal absent")?;
    assert_eq!(terminal.exit, ManagedExit::Cancelled);
    assert!(!terminal.suspended);
    let araphor_data::ManagedResume {
        instance: current,
        frontier,
        ..
    } = fixture.query.store().managed_resume(
        [1; 16],
        "valid-notice",
        &AnalysisReadControl::default(),
    )?;
    assert_eq!(current, before);
    assert!(current.running);
    assert_eq!(current.lifecycle, before.lifecycle);
    assert_eq!(current.progress, 0);
    assert_eq!(frontier, None);
    let saved = fixture
        .query
        .store()
        .managed_attempt(
            [1; 16],
            "valid-notice",
            &attempt.request().id,
            &AnalysisReadControl::default(),
        )?
        .ok_or("notice terminal record")?;
    assert_eq!(saved.terminal(), Some(&terminal));
    assert!(saved.receipt().is_none());
    assert!(fixture
        .query
        .store()
        .managed_selected(
            [1; 16],
            "valid-notice",
            &attempt.request().id,
            &AnalysisReadControl::default()
        )?
        .is_none());
    drop(fixture.query.reserve_evaluation([1; 16])?);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn close_joins_before_terminal() -> TestResult {
    let fixture = Fixture::new(araphor_query::execution::Limits {
        global_evaluations: Some(1),
        tenant_evaluations: Some(1),
        ..Default::default()
    })?;
    let (instance, mut stream) = fixture.terminal_stream("joined-stop", "cancel").await?;
    let control = Arc::clone(&stream.control);
    let state = Arc::clone(&stream.state);
    let (entry, observed) = std::sync::mpsc::channel();
    let (release, waiting) = std::sync::mpsc::channel();
    fixture.query.guest_entry(entry, Some(waiting))?;
    {
        let next = stream.next();
        tokio::pin!(next);
        let entered =
            tokio::task::spawn_blocking(move || observed.recv_timeout(Duration::from_secs(30)));
        tokio::pin!(entered);
        tokio::select! {
            result = &mut entered => result??,
            result = &mut next => {
                let _released = release.send(());
                return Err(format!("guest stream ended before entry: {result:?}").into());
            },
        }
    }
    let attempt = state
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .attempt
        .clone()
        .ok_or("native stop attempt")?;
    let current = fixture
        .query
        .store()
        .managed_instance([1; 16], "joined-stop", &AnalysisReadControl::default())?
        .ok_or("running stop instance")?;
    let stopped = fixture.query.store().set_managed_running(
        [1; 16],
        "joined-stop",
        current.lifecycle,
        false,
        || Ok(()),
    )?;
    let worker = tokio::spawn(async move {
        stream
            .cancel_and_join(&AnalysisReadControl::default())
            .await
    });
    tokio::time::timeout(Duration::from_secs(30), control.cancelled()).await?;
    assert!(!worker.is_finished());
    assert!(fixture.query.reserve_evaluation([1; 16]).is_err());
    assert!(fixture
        .query
        .store()
        .managed_attempt(
            [1; 16],
            "joined-stop",
            &attempt.request().id,
            &AnalysisReadControl::default()
        )?
        .ok_or("pending stop attempt")?
        .terminal()
        .is_none());
    release.send(())?;
    let terminal = tokio::time::timeout(Duration::from_secs(30), worker)
        .await???
        .ok_or("stopped terminal absent")?;
    assert_eq!(terminal.exit, ManagedExit::Cancelled);
    assert!(!terminal.suspended);
    assert_eq!(fixture.progress("joined-stop")?, 0);
    let araphor_data::ManagedResume {
        instance: current, ..
    } = fixture.query.store().managed_resume(
        [1; 16],
        "joined-stop",
        &AnalysisReadControl::default(),
    )?;
    assert_eq!(current, stopped);
    drop(fixture.query.reserve_evaluation([1; 16])?);
    let restarted = fixture.query.store().set_managed_running(
        [1; 16],
        "joined-stop",
        stopped.lifecycle,
        true,
        || Ok(()),
    )?;
    let stream = instance.subscribe(
        Arc::new(AnalysisReadControl::default()),
        u64::MAX,
        restarted.lifecycle,
    )?;
    assert!(stream
        .cancel_and_join(&AnalysisReadControl::default())
        .await?
        .is_none());
    Ok(())
}

#[tokio::test]
async fn diagnostic_cancellation_keeps_pending() -> TestResult {
    let fixture = Fixture::new(Default::default())?;
    let (_, mut stream) = fixture.terminal_stream("diagnostic", "trap").await?;
    assert!(tokio::time::timeout(Duration::from_secs(30), stream.next())
        .await?
        .ok_or("trap stream ended")?
        .is_err());
    let attempt = stream
        .state
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .attempt
        .clone()
        .ok_or("failed attempt")?;
    let before = fixture.query.store().meta()?;
    let diagnostic = AnalysisReadControl::default();
    diagnostic.cancel()?;
    assert!(stream.cancel_and_join(&diagnostic).await.is_err());
    assert_eq!(fixture.query.store().meta()?, before);
    let saved = fixture
        .query
        .store()
        .managed_attempt(
            [1; 16],
            "diagnostic",
            &attempt.request().id,
            &AnalysisReadControl::default(),
        )?
        .ok_or("pending diagnostic attempt")?;
    assert!(saved.terminal().is_none());
    assert!(saved.receipt().is_none());
    assert!(fixture
        .query
        .store()
        .managed_resume([1; 16], "diagnostic", &AnalysisReadControl::default())
        .is_err());
    Ok(())
}

#[tokio::test]
async fn failed_writer_keeps_claim() -> TestResult {
    let fixture = Fixture::new(Default::default())?;
    fixture.context(1)?;
    let instance = fixture.admit("failed-writer", "SELECT CAST(7 AS BIGINT UNSIGNED) AS value WHERE EXISTS (SELECT 1 FROM context_versions)").await?;
    let lifecycle = fixture.start(&instance)?;
    let mut stream = instance.subscribe(
        Arc::new(AnalysisReadControl::default()),
        u64::MAX,
        lifecycle,
    )?;
    fixture.query.store().set_commit_hook(
        araphor_data::AnalysisCommitStage::BeforeResultCommit,
        || Err(Code::Invalid.error("writer fixture rollback")),
    )?;
    let error = tokio::time::timeout(Duration::from_secs(30), stream.next())
        .await?
        .ok_or("writer stream ended")?
        .err()
        .ok_or("failed writer published")?;
    assert_eq!(
        Subscription::failure(&error),
        ManagedExit::Failed(Code::Invalid)
    );
    let attempt = stream
        .state
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .attempt
        .clone()
        .ok_or("writer lost original claim")?;
    assert_eq!(fixture.progress("failed-writer")?, 0);
    assert!(fixture
        .query
        .store()
        .managed_selected(
            [1; 16],
            "failed-writer",
            &attempt.request().id,
            &AnalysisReadControl::default()
        )?
        .is_none());
    let terminal = stream
        .cancel_and_join(&AnalysisReadControl::default())
        .await?
        .ok_or("writer terminal absent")?;
    assert_eq!(terminal.attempt, attempt.request().id);
    assert_eq!(terminal.exit, ManagedExit::Failed(Code::Invalid));
    assert!(!terminal.suspended);
    assert_eq!(fixture.progress("failed-writer")?, 0);
    fixture.query.store().managed_resume(
        [1; 16],
        "failed-writer",
        &AnalysisReadControl::default(),
    )?;
    Ok(())
}

#[tokio::test]
async fn failed_offer_fences_old_stream() -> TestResult {
    let fixture = Fixture::new(araphor_query::execution::Limits {
        global_evaluations: Some(1),
        tenant_evaluations: Some(1),
        ..Default::default()
    })?;
    let mut image = bundle("sql")?;
    let PackageImplementationV1::Sql { program, .. } = &mut image.artifacts[0].implementations[0]
    else {
        return Err("SQL failure fixture".into());
    };
    program.outputs.insert("data".into(), "SELECT CAST(CASE WHEN SUM(value) = 10 THEN 'bad' ELSE '7' END AS BIGINT UNSIGNED) AS value FROM input".into());
    fixture.install(&image)?;
    fixture.context(1)?;
    let instance = fixture.admit("failed-offer", r#"SELECT * FROM "runtime-fixture"."1".accumulate(input => (SELECT CAST(COALESCE(MAX(owner_revision), 0) * 10 AS BIGINT UNSIGNED) AS value FROM context_versions))"#).await?;
    let lifecycle = fixture.start(&instance)?;
    let mut first = instance.subscribe(
        Arc::new(AnalysisReadControl::default()),
        u64::MAX,
        lifecycle,
    )?;
    let mut stale = instance.subscribe(
        Arc::new(AnalysisReadControl::default()),
        u64::MAX,
        lifecycle,
    )?;
    let error = tokio::time::timeout(Duration::from_secs(30), first.next())
        .await?
        .ok_or("failed SQL offer")?
        .err()
        .ok_or("invalid SQL offer published")?;
    assert_eq!(
        Subscription::failure(&error),
        ManagedExit::Failed(Code::Invalid)
    );
    let attempt = first
        .state
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .attempt
        .clone()
        .ok_or("original failed attempt")?;
    let terminal = first
        .cancel_and_join(&AnalysisReadControl::default())
        .await?
        .ok_or("failed SQL terminal")?;
    let control = AnalysisReadControl::default();
    let store = fixture.query.store();
    let resumed = store.managed_resume([1; 16], "failed-offer", &control)?;
    assert_eq!(resumed.instance.progress, 0);
    assert_eq!(resumed.instance.lifecycle, lifecycle);
    assert_eq!(resumed.completed, terminal.revision);
    assert_eq!(
        resumed.frontier.as_ref(),
        attempt.request().frontier.as_ref()
    );
    let before = store.meta()?;
    let error = tokio::time::timeout(Duration::from_secs(30), stale.next())
        .await?
        .ok_or("stale failed-offer result")?
        .err()
        .ok_or("stale failed-offer stream executed")?;
    assert!(
        error
            .to_string()
            .contains("managed subscription completion"),
        "{error:?}"
    );
    assert!(stale.cancel_and_join(&control).await?.is_none());
    assert_eq!(store.meta()?, before);
    assert_eq!(fixture.progress("failed-offer")?, 0);

    let mut stream = instance.subscribe(
        Arc::new(AnalysisReadControl::default()),
        u64::MAX,
        lifecycle,
    )?;
    assert!(futures_util::poll!(stream.next()).is_pending());
    assert_eq!(store.meta()?, before);
    fixture.context(2)?;
    let receipt = tokio::time::timeout(Duration::from_secs(30), stream.next())
        .await?
        .ok_or("changed failed-offer receipt")??;
    assert_eq!(fixture.selected("failed-offer", &receipt.attempt)?, [7]);
    assert_eq!(fixture.progress("failed-offer")?, receipt.commit_revision);
    assert!(receipt.commit_revision > terminal.revision);
    assert_ne!(receipt.attempt, terminal.attempt);
    assert!(stream.cancel_and_join(&control).await?.is_none());
    let retained = store
        .managed_attempt([1; 16], "failed-offer", &terminal.attempt, &control)?
        .ok_or("retained failed offer")?;
    assert_eq!(retained.request(), attempt.request());
    assert_eq!(retained.terminal(), Some(&terminal));
    assert!(retained.receipt().is_none());
    assert!(store
        .managed_selected([1; 16], "failed-offer", &terminal.attempt, &control)?
        .is_none());
    drop(fixture.query.reserve_evaluation([1; 16])?);
    Ok(())
}

#[tokio::test]
async fn postcommit_notice_keeps_receipt() -> TestResult {
    let fixture = Fixture::new(Default::default())?;
    fixture.context(1)?;
    let instance = fixture
        .admit(
            "postcommit-notice",
            "SELECT CAST(COUNT(*) AS BIGINT UNSIGNED) AS value FROM context_versions",
        )
        .await?;
    let lifecycle = fixture.start(&instance)?;
    let mut stream = instance.subscribe(
        Arc::new(AnalysisReadControl::default()),
        u64::MAX,
        lifecycle,
    )?;
    tokio::time::timeout(Duration::from_secs(30), stream.query.next())
        .await?
        .ok_or("native stream ended before commit")??;
    let receipt = stream
        .state
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .receipt
        .clone()
        .ok_or("native publication did not retain receipt")?;
    assert_eq!(
        fixture.progress("postcommit-notice")?,
        receipt.commit_revision
    );
    fixture.authority.set(true);
    let error = tokio::time::timeout(Duration::from_secs(30), stream.next())
        .await?
        .ok_or("notice stream ended")?
        .err()
        .ok_or("committed receipt hid native authority notice")?;
    assert!(matches!(
        &error,
        crate::Error::Query {
            source: araphor_query::Error::AuthorityChanged { .. }
        }
    ));
    assert_eq!(Subscription::failure(&error), ManagedExit::Cancelled);
    assert!(stream
        .cancel_and_join(&AnalysisReadControl::default())
        .await?
        .is_none());
    let saved = fixture
        .query
        .store()
        .managed_attempt(
            [1; 16],
            "postcommit-notice",
            &receipt.attempt,
            &AnalysisReadControl::default(),
        )?
        .ok_or("committed receipt absent")?;
    assert_eq!(saved.receipt(), Some(&receipt));
    assert_eq!(saved.terminal(), None);
    assert_eq!(
        fixture.progress("postcommit-notice")?,
        receipt.commit_revision
    );
    let mut resumed = instance.subscribe(
        Arc::new(AnalysisReadControl::default()),
        u64::MAX,
        lifecycle,
    )?;
    fixture.context(2)?;
    let next = tokio::time::timeout(Duration::from_secs(30), resumed.next())
        .await?
        .ok_or("resumed stream ended")??;
    assert_ne!(next.attempt, receipt.attempt);
    assert!(next.commit_revision > receipt.commit_revision);
    assert!(resumed
        .cancel_and_join(&AnalysisReadControl::default())
        .await?
        .is_none());
    Ok(())
}
