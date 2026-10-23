use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{mpsc, Mutex};
use std::time::Duration;

use crate::instance::tests::{Fixture, TestResult};
use araphor_data::*;
use araphor_query::execution::Limits;
use araphor_query::follow::Clock as _;
use datafusion::catalog::TableProvider as _;
use datafusion::logical_expr::dml::InsertOp;
use datafusion::physical_plan::empty::EmptyExec;
use futures_util::{StreamExt as _, TryStreamExt as _};

use super::*;
use crate::notification::tests::{commit_finding_at, finding, grant, policy, Authority};

struct RoutingNotice {
    armed: AtomicBool,
    entered: tokio::sync::Notify,
}

impl NotificationAuthorization for RoutingNotice {
    fn check(&self, grant: &NotificationGrantV1, now: u64) -> araphor_data::Result<()> {
        Authority.check(grant, now)?;
        if self.armed.swap(false, Ordering::SeqCst) {
            self.entered.notify_one();
        }
        Ok(())
    }
}

struct Sink {
    store: Option<Arc<AnalysisStore>>,
    fail_primary: bool,
    calls: Mutex<Vec<NotificationDeliveryV1>>,
    entered: tokio::sync::Notify,
    release: Mutex<Option<mpsc::Receiver<()>>>,
}

impl NotificationSink for Sink {
    #[allow(
        clippy::expect_used,
        reason = "The test sink must fail on store or gate errors."
    )]
    fn deliver(&self, delivery: &NotificationDeliveryV1) -> NotificationSinkResultV1 {
        if let Some(store) = &self.store {
            store
                .commit_context(&AnalysisContextVersionV1 {
                    key: AnalysisContextKeyV1 {
                        tenant_id: delivery.key.tenant_id,
                        owner_id: "sink-test".into(),
                        entity_key: vec![1],
                        lifetime_key: vec![1],
                        owner_revision: delivery.attempt,
                    },
                    valid_from_utc_ns: None,
                    valid_until_utc_ns: None,
                    sensitivity: ContextSensitivityV1::Tenant,
                    body: vec![1],
                })
                .expect("the sink must not hold a Data writer");
        }
        self.calls
            .lock()
            .expect("sink calls")
            .push(delivery.clone());
        self.entered.notify_one();
        if let Some(release) = self.release.lock().expect("sink gate").take() {
            release
                .recv_timeout(Duration::from_secs(30))
                .expect("sink release");
        }
        if self.fail_primary && delivery.kind == NotificationDeliveryKindV1::Finding {
            NotificationSinkResultV1::Failed {
                reason: NotificationFailureV1::SinkUnavailable,
            }
        } else {
            NotificationSinkResultV1::Accepted {
                receipt: "native-accepted".into(),
            }
        }
    }
}

fn configure(router: &NotificationRouter, now: u64) -> crate::Result<()> {
    let mut approval = grant(NotificationPrincipalV1::Human);
    approval.expires_utc_ns = u64::MAX;
    for name in ["escalation", "primary"] {
        let mut route = policy(name);
        route.acknowledgement_ns = 1_000_000_000_000;
        route.retry_delay_ns = 1_000_000_000_000;
        router.configure(&approval, route, now)?;
    }
    Ok(())
}

#[tokio::test]
async fn notification_host_stop_records() -> TestResult {
    let fixture = Fixture::new(Limits::default())?;
    let store = Arc::clone(fixture.query.store());
    let router = Arc::new(NotificationRouter::new(
        Arc::clone(&store),
        Arc::new(Authority),
    )?);
    let now = araphor_query::follow::SystemClock::default().now_ns()?;
    configure(&router, now)?;
    commit_finding_at(&store, finding(1, FindingSeverityV1::High), 1, now)?;
    let query = Arc::clone(&fixture.query);
    let (release, blocked) = mpsc::channel();
    let sink = Arc::new(Sink {
        store: Some(Arc::clone(&store)),
        fail_primary: false,
        calls: Mutex::default(),
        entered: tokio::sync::Notify::new(),
        release: Mutex::new(Some(blocked)),
    });
    let host = InstanceHost::with_notifications(
        Arc::clone(&query),
        fixture.authority.clone(),
        None,
        Arc::clone(&router),
        sink.clone(),
        true,
    );
    let control = AnalysisReadControl::default();
    let instance = host
        .admit_notifications(fixture.grant.clone(), &control)
        .await?;
    let instance = host
        .start(
            Arc::clone(&instance),
            instance.admitted().lifecycle,
            &control,
        )
        .await?;
    assert!(instance.admitted().spec.definition.images.is_empty());
    assert!(instance.admitted().spec.manifest.calls.is_empty());
    assert!(!store.graph_enabled());
    let (stop, stopped) = tokio::sync::watch::channel(false);
    let serving = tokio::spawn(Arc::clone(&host).serve(stopped, u64::MAX));
    tokio::time::timeout(Duration::from_secs(30), sink.entered.notified()).await?;
    let delivery = sink.calls.lock().map_err(|_| "sink calls")?[0].clone();
    let stopping_host = Arc::clone(&host);
    let stopping_owner = Arc::clone(&instance);
    let mut stopping = tokio::spawn(async move {
        stopping_host
            .stop(
                stopping_owner.clone(),
                stopping_owner.admitted().lifecycle,
                &AnalysisReadControl::default(),
            )
            .await
    });
    assert!(
        tokio::time::timeout(Duration::from_millis(10), &mut stopping)
            .await
            .is_err()
    );
    release.send(())?;
    let stopped = tokio::time::timeout(Duration::from_secs(30), stopping).await???;
    assert!(!stopped.admitted().running);
    let disabled = InstanceHost::with_notifications(
        Arc::clone(&query),
        fixture.authority.clone(),
        None,
        Arc::clone(&router),
        sink.clone(),
        false,
    );
    assert!(disabled
        .admit_notifications(fixture.grant.clone(), &control)
        .await
        .is_err());
    assert!(disabled
        .start(Arc::clone(&stopped), stopped.admitted().lifecycle, &control)
        .await
        .is_err());
    let mut approval = grant(NotificationPrincipalV1::Human);
    approval.expires_utc_ns = u64::MAX;
    let state = router
        .obligations(&approval, now)?
        .into_iter()
        .find(|state| state.key == delivery.key)
        .ok_or("saved obligation")?;
    assert_eq!(state.attempts.len(), 1);
    assert_eq!(state.attempts[0].number, delivery.attempt);
    assert!(
        matches!(&state.attempts[0].result, Some(NotificationSinkResultV1::Accepted { receipt }) if receipt == "native-accepted")
    );
    let resume = store.managed_resume([1; 16], "notifications", &control)?;
    assert_eq!(resume.completed, 0);
    assert_eq!(resume.instance.progress, 0);
    assert!(resume.frontier.is_none());
    assert!(store
        .managed_history(&fixture.grant.clone().selection, "notifications", &control)?
        .is_empty());
    stop.send(true)?;
    tokio::time::timeout(Duration::from_secs(30), serving).await???;
    assert_eq!(sink.calls.lock().map_err(|_| "sink calls")?.len(), 1);
    Ok(())
}

#[tokio::test]
async fn notification_capture_is_bounded() -> TestResult {
    let fixture = Fixture::new(Limits {
        output_rows: 1,
        ..Default::default()
    })?;
    let store = Arc::clone(fixture.query.store());
    let router = Arc::new(NotificationRouter::new(
        Arc::clone(&store),
        Arc::new(Authority),
    )?);
    let now = araphor_query::follow::SystemClock::default().now_ns()?;
    configure(&router, now)?;
    commit_finding_at(&store, finding(1, FindingSeverityV1::High), 1, now)?;
    let query = Arc::clone(&fixture.query);
    let mut approval = grant(NotificationPrincipalV1::Human);
    approval.expires_utc_ns = u64::MAX;
    approval.routes.push("secondary".into());
    let mut second = policy("primary");
    second.route_id = "secondary".into();
    second.acknowledgement_ns = 1_000_000_000_000;
    router.configure(&approval, second, now)?;
    assert_eq!(
        router.route_finding(
            [1; 16],
            &NotificationFindingRefV1 {
                finding_id: "finding:exact-process-key".into(),
                result_id: "graph-test-1".into()
            },
            now
        )?,
        2
    );
    let sink = Arc::new(Sink {
        store: Some(Arc::clone(&store)),
        fail_primary: false,
        calls: Mutex::default(),
        entered: tokio::sync::Notify::new(),
        release: Mutex::default(),
    });
    let host = InstanceHost::with_notifications(
        Arc::clone(&query),
        fixture.authority.clone(),
        None,
        Arc::clone(&router),
        sink.clone(),
        true,
    );
    let control = AnalysisReadControl::default();
    let instance = host
        .admit_notifications(fixture.grant.clone(), &control)
        .await?;
    let instance = host
        .start(
            Arc::clone(&instance),
            instance.admitted().lifecycle,
            &control,
        )
        .await?;
    let child = Arc::new(control.operation()?);
    let mut stream = instance.subscribe_notifications(
        host.notifications.as_ref().ok_or("notification owner")?,
        child,
        instance.admitted().lifecycle,
    )?;
    let error = tokio::time::timeout(Duration::from_secs(30), stream.next())
        .await?
        .ok_or("native sink result")?
        .err()
        .ok_or("bounded capture must fail")?;
    assert_eq!(
        araphor_query::Failure::from(&error),
        araphor_query::Failure::ResultTooLarge
    );
    stream.cancel_and_join().await?;
    control.check()?;
    assert!(sink.calls.lock().map_err(|_| "sink calls")?.is_empty());
    let states = router.obligations(&approval, now)?;
    assert_eq!(states.len(), 2);
    assert!(states.iter().all(|state| state.attempts.is_empty()));
    let mut changes = store.subscribe_revision();
    let (stop, stopped) = tokio::sync::watch::channel(false);
    let serving = tokio::spawn(Arc::clone(&host).serve(stopped, u64::MAX));
    let failed = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            let status =
                store.managed_status(&fixture.grant.selection, "notifications", &control)?;
            if matches!(
                &status.readiness,
                PackageReadinessV1::Failed {
                    code: Code::Limit,
                    ..
                }
            ) {
                break Ok::<_, araphor_data::Error>(status);
            }
            changes
                .changed()
                .await
                .map_err(|_| Code::Incomplete.error("failure notice"))?;
        }
    })
    .await;
    let stopping = stop.send(true);
    let joined = tokio::time::timeout(Duration::from_secs(30), serving).await;
    assert_eq!(failed??.status_progress, 0);
    stopping?;
    joined???;
    assert!(sink.calls.lock().map_err(|_| "sink calls")?.is_empty());
    assert_eq!(
        store
            .managed_resume([1; 16], "notifications", &control)?
            .completed,
        0
    );
    assert!(store
        .managed_history(&fixture.grant.selection, "notifications", &control)?
        .is_empty());
    Ok(())
}

#[tokio::test]
#[allow(
    clippy::panic,
    reason = "The guarded and completed attempts must not reach the sink."
)]
async fn notification_guard_keeps_pending() -> TestResult {
    let fixture = Fixture::new(Limits::default())?;
    let store = Arc::clone(fixture.query.store());
    let router = Arc::new(NotificationRouter::new(
        Arc::clone(&store),
        Arc::new(Authority),
    )?);
    let clock = araphor_query::follow::SystemClock::default();
    let now = clock.now_ns()?;
    configure(&router, now)?;
    let original_finding = finding(1, FindingSeverityV1::High);
    commit_finding_at(&store, original_finding.clone(), 1, now)?;
    router.route_finding(
        [1; 16],
        &NotificationFindingRefV1 {
            finding_id: original_finding.finding_id.clone(),
            result_id: "graph-test-1".into(),
        },
        now,
    )?;
    let mut approval = grant(NotificationPrincipalV1::Human);
    approval.expires_utc_ns = u64::MAX;
    let sink = Arc::new(Sink {
        store: None,
        fail_primary: false,
        calls: Mutex::default(),
        entered: tokio::sync::Notify::new(),
        release: Mutex::default(),
    });
    let host = InstanceHost::with_notifications(
        Arc::clone(&fixture.query),
        fixture.authority.clone(),
        None,
        Arc::clone(&router),
        sink.clone(),
        true,
    );
    let control = AnalysisReadControl::default();
    let instance = host
        .admit_notifications(fixture.grant.clone(), &control)
        .await?;
    let lifecycle = instance.admitted().lifecycle;
    let instance = host.start(instance, lifecycle, &control).await?;
    let running = instance.admitted().clone();
    let checks = AtomicUsize::new(0);
    let error = {
        let session = instance.session.operation(&control, now)?;
        let (snapshot, stream) = session
            .stream(
                &instance.prepared.plan,
                instance.prepared.sources(),
                araphor_query::execution::Read::Snapshot,
            )
            .await?;
        let batches = stream.try_collect::<Vec<_>>().await?;
        assert!(snapshot.page.exhausted);
        assert_eq!(
            batches.iter().map(|batch| batch.num_rows()).sum::<usize>(),
            1
        );
        router
            .consume_rows(
                snapshot.selection.tenant_id,
                snapshot.time_utc_ns(),
                &batches,
                &|| {
                    instance.check_notification(running.lifecycle, &control)?;
                    if checks.fetch_add(1, Ordering::SeqCst) == 1 {
                        return Err(Code::Denied.error("job guard").into());
                    }
                    Ok(())
                },
                &mut |_| panic!("the guard must run before the sink"),
            )
            .err()
            .ok_or("guard denial")?
    };
    assert_eq!(checks.load(Ordering::SeqCst), 2);
    assert!(matches!(
        error,
        crate::Error::Data {
            source: araphor_data::Error::Package {
                code: Code::Denied,
                field: "job guard",
                ..
            }
        }
    ));
    let pending = router.obligations(&approval, now)?.remove(0);
    assert_eq!(pending.attempts.len(), 1);
    assert!(pending.attempts[0].result.is_none());
    assert_eq!(pending.first_seen_utc_ns, now);
    assert_eq!(pending.deadline_utc_ns, Some(now + 1_000_000_000_000));
    let key = pending.key;
    let number = pending.attempts[0].number;
    assert!(sink.calls.lock().map_err(|_| "sink calls")?.is_empty());
    let Fixture {
        directory,
        query,
        authority,
        grant: package_grant,
    } = fixture;
    drop(instance);
    drop(host);
    drop(sink);
    drop(router);
    drop(store);
    drop(query);

    let store = Arc::new(AnalysisStore::open(directory.path().join("data"))?);
    let query = araphor_query::execution::Engine::new(Arc::clone(&store), Limits::default())?;
    let router = Arc::new(NotificationRouter::new(
        Arc::clone(&store),
        Arc::new(Authority),
    )?);
    assert_eq!(
        router.obligations(&approval, clock.now_ns()?)?,
        std::slice::from_ref(&pending)
    );
    let mut updated_route = policy("primary");
    updated_route.revision = 2;
    updated_route.acknowledgement_ns = 2_000_000_000_000;
    updated_route.retry_delay_ns = 1_000_000_000_000;
    router.configure(&approval, updated_route, clock.now_ns()?)?;
    let updated_finding = finding(2, FindingSeverityV1::Critical);
    commit_finding_at(&store, updated_finding.clone(), 2, clock.now_ns()?)?;
    let sink = Arc::new(Sink {
        store: None,
        fail_primary: false,
        calls: Mutex::default(),
        entered: tokio::sync::Notify::new(),
        release: Mutex::default(),
    });
    let host = InstanceHost::with_notifications(
        query,
        authority,
        None,
        Arc::clone(&router),
        sink.clone(),
        false,
    );
    let mut changes = store.subscribe_revision();
    let (stop, stopped) = tokio::sync::watch::channel(false);
    let serving = tokio::spawn(Arc::clone(&host).serve(stopped, u64::MAX));
    let resumed = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            let state = router.obligations(&approval, clock.now_ns()?)?.remove(0);
            if state.attempts.iter().any(|attempt| {
                attempt.number > number
                    && attempt
                        .result
                        .as_ref()
                        .is_some_and(NotificationSinkResultV1::accepted)
            }) {
                break Ok::<_, crate::Error>(state);
            }
            changes
                .changed()
                .await
                .map_err(|_| Code::Incomplete.error("pending notification notice"))?;
        }
    })
    .await;
    let stopping = stop.send(true);
    let joined = tokio::time::timeout(Duration::from_secs(30), serving).await;
    let saved = resumed??;
    stopping?;
    joined???;
    assert_eq!(saved.key, key);
    assert_eq!(saved.first_seen_utc_ns, pending.first_seen_utc_ns);
    assert_eq!(saved.deadline_utc_ns, pending.deadline_utc_ns);
    assert_eq!(saved.route.as_ref().ok_or("updated route")?.revision, 2);
    let calls = sink.calls.lock().map_err(|_| "sink calls")?.clone();
    assert_eq!(calls.len(), 2);
    assert_eq!(calls[0].attempt, number);
    assert_eq!(calls[0].route_revision, 1);
    assert_eq!(
        calls[0]
            .finding
            .as_ref()
            .ok_or("original subject")?
            .revision,
        original_finding.revision
    );
    assert_eq!(calls[1].attempt, number + 1);
    assert_eq!(calls[1].route_revision, 2);
    assert_eq!(
        calls[1].finding.as_ref().ok_or("updated subject")?.revision,
        updated_finding.revision
    );
    assert!(calls.iter().all(|call| {
        call.key == key
            && call.kind == NotificationDeliveryKindV1::Finding
            && call.route_id == "primary"
            && Some(call.deadline_utc_ns) == pending.deadline_utc_ns
    }));
    let mut completed = None;
    for owner_revision in pending.revision..=saved.revision {
        let context = store
            .context_version(&AnalysisContextKeyV1 {
                tenant_id: key.tenant_id,
                owner_id: NOTIFICATION_STATE_OWNER.into(),
                entity_key: key.notification_id.to_vec(),
                lifetime_key: b"obligation".to_vec(),
                owner_revision,
            })?
            .ok_or("retained obligation version")?;
        let state = NotificationObligationV1::try_from(&context)?;
        if let Some(attempt) = state
            .attempts
            .into_iter()
            .find(|attempt| attempt.number == number && attempt.result.is_some())
        {
            completed = Some(attempt);
            break;
        }
    }
    let completed = completed.ok_or("resumed pending outcome")?;
    assert!(completed.completed_utc_ns.is_some());
    let mut expected = pending.attempts[0].clone();
    expected.completed_utc_ns = completed.completed_utc_ns;
    expected.result = Some(NotificationSinkResultV1::Accepted {
        receipt: "native-accepted".into(),
    });
    assert_eq!(completed, expected);
    assert_eq!(
        router.deliver_checked(
            key,
            &mut |_| panic!("an accepted attempt must not be resent"),
            clock.now_ns()?
        )?,
        0
    );
    let resume = store.managed_resume([1; 16], "notifications", &control)?;
    assert_eq!(resume.instance, running);
    assert_eq!(resume.completed, 0);
    assert_eq!(resume.instance.progress, 0);
    assert!(resume.frontier.is_none());
    assert!(store
        .managed_history(&package_grant.selection, "notifications", &control)?
        .is_empty());
    Ok(())
}

#[tokio::test]
async fn notification_host_keeps_deadlines() -> TestResult {
    let fixture = Fixture::new(Limits::default())?;
    let store = Arc::clone(fixture.query.store());
    let router = Arc::new(NotificationRouter::new(
        Arc::clone(&store),
        Arc::new(Authority),
    )?);
    let clock = araphor_query::follow::SystemClock::default();
    let now = clock.now_ns()?;
    let mut approval = grant(NotificationPrincipalV1::Human);
    approval.expires_utc_ns = u64::MAX;
    let mut primary = policy("primary");
    primary.acknowledgement_ns = 5_000_000_000;
    primary.retry_delay_ns = 1_000_000_000;
    primary.retry_limit = 2;
    router.configure(&approval, policy("escalation"), now)?;
    router.configure(&approval, primary.clone(), now)?;
    let subject = finding(1, FindingSeverityV1::High);
    commit_finding_at(&store, subject.clone(), 1, now)?;
    let source = store.source_status(&subject.evidence[0].stream)?;
    let sink = Arc::new(Sink {
        store: None,
        fail_primary: true,
        calls: Mutex::default(),
        entered: tokio::sync::Notify::new(),
        release: Mutex::default(),
    });
    let host = InstanceHost::with_notifications(
        Arc::clone(&fixture.query),
        fixture.authority.clone(),
        None,
        Arc::clone(&router),
        sink.clone(),
        true,
    );
    let control = AnalysisReadControl::default();
    let instance = host
        .admit_notifications(fixture.grant.clone(), &control)
        .await?;
    let instance = host
        .start(
            Arc::clone(&instance),
            instance.admitted().lifecycle,
            &control,
        )
        .await?;
    let mut changes = store.subscribe_revision();
    let (stop, stopped) = tokio::sync::watch::channel(false);
    let serving = tokio::spawn(Arc::clone(&host).serve(stopped, u64::MAX));
    let observed = tokio::time::timeout(Duration::from_secs(30), async {
        let mut before_ack = None;
        loop {
            if let Some(state) = router.obligations(&approval, clock.now_ns()?)?.pop() {
                let acknowledged = state.attempts.iter().any(|attempt| {
                    attempt.kind == NotificationDeliveryKindV1::AcknowledgementEscalation
                        && attempt
                            .result
                            .as_ref()
                            .is_some_and(NotificationSinkResultV1::accepted)
                });
                if state.failure == Some(NotificationFailureV1::RetryExhausted)
                    && !acknowledged
                    && before_ack.is_none()
                {
                    before_ack = Some((state.clone(), clock.now_ns()?));
                }
                if acknowledged {
                    break Ok::<_, crate::Error>((state, before_ack));
                }
            }
            changes
                .changed()
                .await
                .map_err(|_| Code::Incomplete.error("notification deadline notice"))?;
        }
    })
    .await;
    let stopping = stop.send(true);
    let joined = tokio::time::timeout(Duration::from_secs(30), serving).await;
    let (saved, before_ack) = observed??;
    stopping?;
    joined???;
    let (waiting, observed_utc_ns) =
        before_ack.ok_or("retry must finish before acknowledgement deadline")?;
    let deadline = saved.deadline_utc_ns.ok_or("acknowledgement deadline")?;
    assert!(observed_utc_ns < deadline);
    assert_eq!(waiting.first_seen_utc_ns, saved.first_seen_utc_ns);
    assert_eq!(waiting.deadline_utc_ns, Some(deadline));
    assert_eq!(
        deadline,
        saved.first_seen_utc_ns + primary.acknowledgement_ns
    );
    assert_eq!(saved.overdue_since_utc_ns, Some(deadline));
    assert!(saved.human_acknowledgement.is_none());
    let primary_attempts = saved
        .attempts
        .iter()
        .filter(|attempt| attempt.kind == NotificationDeliveryKindV1::Finding)
        .collect::<Vec<_>>();
    assert_eq!(primary_attempts.len(), 2);
    assert!(primary_attempts.iter().all(|attempt| matches!(
        &attempt.result,
        Some(NotificationSinkResultV1::Failed {
            reason: NotificationFailureV1::SinkUnavailable
        })
    )));
    assert!(
        primary_attempts[1].started_utc_ns
            >= primary_attempts[0]
                .completed_utc_ns
                .ok_or("first completion")?
                + primary.retry_delay_ns
    );
    assert!(
        primary_attempts[1]
            .completed_utc_ns
            .ok_or("retry completion")?
            < deadline
    );
    let acknowledgement = saved
        .attempts
        .iter()
        .find(|attempt| attempt.kind == NotificationDeliveryKindV1::AcknowledgementEscalation)
        .ok_or("acknowledgement escalation")?;
    assert!(acknowledgement.started_utc_ns >= deadline);
    let calls = sink.calls.lock().map_err(|_| "sink calls")?.clone();
    assert_eq!(calls.len(), 4);
    assert_eq!(
        calls.iter().map(|call| call.kind).collect::<Vec<_>>(),
        [
            NotificationDeliveryKindV1::Finding,
            NotificationDeliveryKindV1::FailureEscalation,
            NotificationDeliveryKindV1::Finding,
            NotificationDeliveryKindV1::AcknowledgementEscalation,
        ]
    );
    assert!(calls.last().ok_or("overdue delivery")?.overdue);
    assert!(calls.iter().all(|call| call.deadline_utc_ns == deadline
        && call
            .finding
            .as_ref()
            .is_some_and(|finding| finding.revision == subject.revision)));
    assert_eq!(store.source_status(&subject.evidence[0].stream)?, source);
    let resume = store.managed_resume([1; 16], "notifications", &control)?;
    assert_eq!(resume.instance, *instance.admitted());
    assert_eq!(resume.completed, 0);
    assert_eq!(resume.instance.progress, 0);
    assert!(resume.frontier.is_none());
    assert!(store
        .managed_history(&fixture.grant.selection, "notifications", &control)?
        .is_empty());
    Ok(())
}

#[tokio::test]
async fn notification_child_is_independent() -> TestResult {
    let fixture = Fixture::new(Limits::default())?;
    let store = Arc::clone(fixture.query.store());
    let router = Arc::new(NotificationRouter::new(
        Arc::clone(&store),
        Arc::new(Authority),
    )?);
    let sink = Arc::new(Sink {
        store: Some(store),
        fail_primary: false,
        calls: Mutex::default(),
        entered: tokio::sync::Notify::new(),
        release: Mutex::default(),
    });
    let host = InstanceHost::with_notifications(
        Arc::clone(&fixture.query),
        fixture.authority.clone(),
        None,
        router,
        sink.clone(),
        true,
    );
    let parent = AnalysisReadControl::default();
    let instance = host
        .admit_notifications(fixture.grant.clone(), &parent)
        .await?;
    let instance = host
        .start(
            Arc::clone(&instance),
            instance.admitted().lifecycle,
            &parent,
        )
        .await?;
    for _ in 0..2 {
        let child = Arc::new(parent.operation()?);
        let mut stream = instance.subscribe_notifications(
            host.notifications.as_ref().ok_or("notification owner")?,
            child,
            instance.admitted().lifecycle,
        )?;
        let update = tokio::time::timeout(Duration::from_secs(30), stream.next())
            .await?
            .ok_or("empty native result")??;
        assert!(update.exhausted && !update.limited);
        stream.cancel_and_join().await?;
        parent.check()?;
    }
    assert!(sink.calls.lock().map_err(|_| "sink calls")?.is_empty());
    assert_eq!(
        fixture
            .query
            .store()
            .managed_resume([1; 16], "notifications", &parent)?
            .completed,
        0
    );
    Ok(())
}

#[tokio::test]
async fn notification_target_is_sealed() -> TestResult {
    let fixture = Fixture::new(Limits::default())?;
    let store = Arc::clone(fixture.query.store());
    let router = Arc::new(NotificationRouter::new(
        Arc::clone(&store),
        Arc::new(Authority),
    )?);
    let sink = Arc::new(Sink {
        store: Some(store),
        fail_primary: false,
        calls: Mutex::default(),
        entered: tokio::sync::Notify::new(),
        release: Mutex::default(),
    });
    let host = InstanceHost::with_notifications(
        Arc::clone(&fixture.query),
        fixture.authority.clone(),
        None,
        router,
        sink,
        true,
    );
    let control = AnalysisReadControl::default();
    let instance = host
        .admit_notifications(fixture.grant.clone(), &control)
        .await?;
    assert!(instance
        .run(
            crate::instance::tests::request("forged-managed-run"),
            &control
        )
        .await
        .is_err());
    assert!(instance
        .subscribe(
            Arc::new(control.operation()?),
            u64::MAX,
            instance.admitted().lifecycle
        )
        .is_err());
    let mut narrowed = fixture.grant.clone();
    narrowed.selection.nodes.push("node".into());
    assert!(
        Instance::validate_notification(&instance.prepared, &narrowed, "notifications").is_err()
    );
    assert!(
        Instance::validate_notification(&instance.prepared, &fixture.grant, "another-job").is_err()
    );
    let mut altered = instance.prepared.clone();
    altered.plan = LogicalPlanBuilder::from(altered.plan)
        .project([datafusion::logical_expr::lit(1).alias("finding_id")])?
        .build()?;
    assert!(Instance::validate_notification(&altered, &fixture.grant, "notifications").is_err());
    let notifications = host.notifications.as_ref().ok_or("notification owner")?;
    let target = sink::Publication {
        owner: Arc::clone(&instance),
        schema: Arc::clone(instance.prepared.plan.schema().inner()),
        mode: sink::Mode::Notification {
            router: Arc::clone(&notifications.router),
            sink: Arc::clone(&notifications.sink),
            lifecycle: instance.admitted().lifecycle,
        },
    };
    let state = fixture.query.catalog(Default::default())?;
    let mut fields = target
        .schema
        .fields()
        .iter()
        .map(|field| field.as_ref().clone())
        .collect::<Vec<_>>();
    for field in fields.iter_mut().take(2) {
        *field = field
            .clone()
            .with_data_type(DataType::Utf8View)
            .with_metadata(std::collections::HashMap::from([(
                "araphor.owner".into(),
                "araphor-data.AnalysisStore".into(),
            )]));
    }
    let views = Arc::new(araphor_analysis_sdk::Schema::new(fields));
    assert!(target
        .insert_into(
            &state,
            Arc::new(EmptyExec::new(Arc::clone(&views))),
            InsertOp::Append,
        )
        .await
        .is_ok());
    for case in 0..3 {
        let mut fields = views
            .fields()
            .iter()
            .map(|field| field.as_ref().clone())
            .collect::<Vec<_>>();
        match case {
            0 => fields[0] = fields[0].clone().with_name("another_id"),
            1 => fields[0] = fields[0].clone().with_data_type(DataType::Int64),
            _ => {
                let _removed = fields.pop();
            }
        }
        assert!(target
            .insert_into(
                &state,
                Arc::new(EmptyExec::new(Arc::new(araphor_analysis_sdk::Schema::new(
                    fields,
                )))),
                InsertOp::Append,
            )
            .await
            .is_err());
    }
    fixture.install(&crate::instance::tests::bundle("sql")?)?;
    let caller = fixture.admit("foreign-call", r#"SELECT * FROM "runtime-fixture"."1".accumulate(input => (SELECT CAST(11 AS BIGINT UNSIGNED) AS value))"#).await?;
    let mut forged = instance.prepared.clone();
    forged.plan = LogicalPlanBuilder::from(caller.prepared.plan.clone())
        .project([
            datafusion::logical_expr::lit(datafusion::scalar::ScalarValue::Utf8(None))
                .alias("finding_id"),
            datafusion::logical_expr::lit(datafusion::scalar::ScalarValue::Utf8(None))
                .alias("result_id"),
            datafusion::logical_expr::lit(datafusion::scalar::ScalarValue::Binary(None))
                .alias("notification_id"),
        ])?
        .build()?;
    assert!(Instance::validate_notification(&forged, &fixture.grant, "notifications").is_err());
    assert_eq!(
        fixture
            .query
            .store()
            .managed_resume([1; 16], "notifications", &control)?
            .completed,
        0
    );
    Ok(())
}

#[tokio::test]
async fn notification_item_error_keeps_following() -> TestResult {
    let fixture = Fixture::new(Limits::default())?;
    let store = Arc::clone(fixture.query.store());
    let authority = Arc::new(RoutingNotice {
        armed: AtomicBool::new(false),
        entered: tokio::sync::Notify::new(),
    });
    let router = Arc::new(NotificationRouter::new(
        Arc::clone(&store),
        authority.clone(),
    )?);
    let now = araphor_query::follow::SystemClock::default().now_ns()?;
    configure(&router, now)?;
    let mut approval = grant(NotificationPrincipalV1::Human);
    approval.expires_utc_ns = u64::MAX;
    let mut broken = policy("primary");
    broken.revision = 2;
    broken.acknowledgement_ns = u64::MAX;
    router.configure(&approval, broken.clone(), now)?;
    commit_finding_at(&store, finding(1, FindingSeverityV1::High), 1, now)?;
    let sink = Arc::new(Sink {
        store: Some(Arc::clone(&store)),
        fail_primary: false,
        calls: Mutex::default(),
        entered: tokio::sync::Notify::new(),
        release: Mutex::default(),
    });
    let host = InstanceHost::with_notifications(
        Arc::clone(&fixture.query),
        fixture.authority.clone(),
        None,
        Arc::clone(&router),
        sink.clone(),
        true,
    );
    let control = AnalysisReadControl::default();
    let instance = host
        .admit_notifications(fixture.grant.clone(), &control)
        .await?;
    let instance = host
        .start(
            Arc::clone(&instance),
            instance.admitted().lifecycle,
            &control,
        )
        .await?;
    authority.armed.store(true, Ordering::SeqCst);
    let (stop, stopped) = tokio::sync::watch::channel(false);
    let serving = tokio::spawn(Arc::clone(&host).serve(stopped, u64::MAX));
    tokio::time::timeout(Duration::from_secs(30), authority.entered.notified()).await?;
    router.configure(&approval, broken, now)?;
    assert!(router.obligations(&approval, now)?.is_empty());
    assert!(sink.calls.lock().map_err(|_| "sink calls")?.is_empty());
    let mut repaired = policy("primary");
    repaired.revision = 3;
    repaired.acknowledgement_ns = 1_000_000_000_000;
    repaired.retry_delay_ns = 1_000_000_000_000;
    router.configure(&approval, repaired, now)?;
    let delivered = tokio::time::timeout(Duration::from_secs(30), sink.entered.notified()).await;
    let stopping = stop.send(true);
    let joined = tokio::time::timeout(Duration::from_secs(30), serving).await;
    delivered?;
    stopping?;
    joined???;
    let states = router.obligations(&approval, now)?;
    assert_eq!(states.len(), 1);
    assert_eq!(states[0].attempts.len(), 1);
    assert!(states[0].attempts[0]
        .result
        .as_ref()
        .is_some_and(NotificationSinkResultV1::accepted));
    assert_eq!(sink.calls.lock().map_err(|_| "sink calls")?.len(), 1);
    assert_eq!(
        store
            .managed_resume([1; 16], "notifications", &control)?
            .completed,
        0
    );
    assert_eq!(
        store
            .managed_instance([1; 16], "notifications", &control)?
            .ok_or("running job")?
            .lifecycle,
        instance.admitted().lifecycle
    );
    assert!(matches!(
        store
            .managed_status(&fixture.grant.selection, "notifications", &control)?
            .readiness,
        PackageReadinessV1::Ready
    ));
    Ok(())
}
