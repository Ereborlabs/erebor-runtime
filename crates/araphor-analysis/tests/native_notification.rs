#![cfg(feature = "native-store")]

use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};

use araphor_analysis::NotificationRouter;
use araphor_data::{analysis::native::NativeStore, *};

type TestResult<T = ()> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;
const TENANT: [u8; 16] = [1; 16];

#[path = "native_notification/batching.rs"]
mod batching;
#[path = "native_notification/consumption.rs"]
mod consumption;

struct Authority {
    store: Arc<NativeStore>,
    competing: Mutex<Option<(AnalysisContextVersionV1, u64)>>,
    changes: tokio::sync::watch::Sender<u64>,
}

impl NotificationAuthorization for Authority {
    fn check(&self, grant: &NotificationGrantV1, now: u64) -> araphor_data::Result<()> {
        NotificationErrorCodeV1::Denied.require(
            grant.authorization_revision == 1 && now < grant.expires_utc_ns,
            "test grant",
        )?;
        let competing = self
            .competing
            .lock()
            .map_err(|_| {
                NotificationSnafu {
                    code: NotificationErrorCodeV1::Unavailable,
                    field: "test authority lock",
                }
                .build()
            })?
            .take();
        if let Some((context, expected)) = competing {
            self.store.commit_context_checked(&context, expected)?;
        }
        Ok(())
    }
}

struct Fixture {
    directory: tempfile::TempDir,
    store: Arc<NativeStore>,
    authority: Arc<Authority>,
}

impl Fixture {
    fn new() -> TestResult<Self> {
        Self::open(tempfile::tempdir()?)
    }

    fn open(directory: tempfile::TempDir) -> TestResult<Self> {
        let store = Arc::new(NativeStore::open(&directory.path().join("data"))?);
        let authority = Arc::new(Authority {
            store: store.clone(),
            competing: Mutex::new(None),
            changes: tokio::sync::watch::channel(0).0,
        });
        Ok(Self {
            directory,
            store,
            authority,
        })
    }

    fn reopen(self) -> TestResult<Self> {
        let Self {
            directory,
            store,
            authority,
        } = self;
        drop((store, authority));
        Self::open(directory)
    }

    fn router(&self) -> araphor_analysis::Result<NotificationRouter> {
        NotificationRouter::new(self.store.clone(), self.authority.clone())
    }

    fn grant(principal: NotificationPrincipalV1) -> NotificationGrantV1 {
        NotificationGrantV1 {
            tenant_id: TENANT,
            principal_id: [9; 16],
            principal,
            authorization_revision: 1,
            routes: vec!["escalation".into(), "primary".into()],
            operations: vec![
                NotificationOperationV1::Configure,
                NotificationOperationV1::Read,
                NotificationOperationV1::Acknowledge,
                NotificationOperationV1::RecordAgent,
                NotificationOperationV1::SubmitConcern,
            ],
            max_sensitivity: ContextSensitivityV1::HostRestricted,
            expires_utc_ns: 10_000,
        }
    }

    fn policy(route: &str) -> NotificationPolicyV1 {
        NotificationPolicyV1 {
            tenant_id: TENANT,
            route_id: route.into(),
            revision: 1,
            package_ids: vec!["native-package".into()],
            minimum_priority: NotificationPriorityV1::High,
            acknowledgement_ns: 100,
            retry_limit: 4,
            retry_delay_ns: 1,
            escalation_route_id: "escalation".into(),
            max_sensitivity: ContextSensitivityV1::HostRestricted,
            allow_concerns: true,
        }
    }

    fn configure(router: &NotificationRouter) -> TestResult {
        let grant = Self::grant(NotificationPrincipalV1::Human);
        router.configure(&grant, Self::policy("escalation"), 10)?;
        router.configure(&grant, Self::policy("primary"), 10)?;
        Ok(())
    }

    fn concern() -> UnconfirmedNotificationConcernV1 {
        UnconfirmedNotificationConcernV1 {
            concern_id: [7; 16],
            model_label: "possible anomaly".into(),
            summary: "Review the model report".into(),
            context: vec![],
            sensitivity: ContextSensitivityV1::Tenant,
            suggested_priority: NotificationPriorityV1::Warning,
        }
    }

    fn submit(router: &NotificationRouter) -> TestResult<NotificationObligationV1> {
        Ok(router.submit_concern(
            &Self::grant(NotificationPrincipalV1::Agent),
            "primary",
            Self::concern(),
            100,
        )?)
    }

    fn key(state: &NotificationObligationV1) -> AnalysisContextKeyV1 {
        AnalysisContextKeyV1 {
            tenant_id: state.key.tenant_id,
            owner_id: NOTIFICATION_STATE_OWNER.into(),
            entity_key: state.key.notification_id.to_vec(),
            lifetime_key: b"obligation".to_vec(),
            owner_revision: state.revision,
        }
    }

    fn state(store: &NativeStore, key: NotificationKeyV1) -> TestResult<NotificationObligationV1> {
        let context = store
            .context_head(
                key.tenant_id,
                NOTIFICATION_STATE_OWNER,
                &key.notification_id,
                b"obligation",
            )?
            .ok_or("missing obligation")?;
        Ok(NotificationObligationV1::try_from(&context)?)
    }
}

struct Sink {
    store: Arc<NativeStore>,
    calls: Mutex<Vec<NotificationDeliveryV1>>,
    interrupt: AtomicBool,
    fail: AtomicBool,
}

impl Sink {
    fn new(store: Arc<NativeStore>) -> Self {
        Self {
            store,
            calls: Mutex::new(Vec::new()),
            interrupt: AtomicBool::new(false),
            fail: AtomicBool::new(false),
        }
    }

    fn observe(&self, request: &NotificationDeliveryV1) -> TestResult {
        let state = Fixture::state(&self.store, request.key)?;
        let attempt = state
            .attempts
            .iter()
            .find(|attempt| attempt.kind == request.kind && attempt.number == request.attempt)
            .ok_or("missing durable pending attempt")?;
        assert!(attempt.result.is_none());
        assert!(attempt.completed_utc_ns.is_none());
        let mut subject_key = Fixture::key(&state);
        subject_key.owner_revision = attempt.context_revision;
        let context = self
            .store
            .context_version(&subject_key)?
            .ok_or("missing retained subject")?;
        let subject = NotificationObligationV1::try_from(&context)?;
        assert_eq!(subject.unconfirmed_concern, request.unconfirmed_concern);
        let route = subject
            .delivery_route(request.kind)
            .ok_or("missing retained route")?;
        assert_eq!(route.route_id, request.route_id);
        assert_eq!(route.revision, request.route_revision);
        let context = self
            .store
            .context_version(&AnalysisContextKeyV1 {
                tenant_id: request.key.tenant_id,
                owner_id: NOTIFICATION_ROUTE_OWNER.into(),
                entity_key: route.route_id.as_bytes().to_vec(),
                lifetime_key: b"route".to_vec(),
                owner_revision: route.revision,
            })?
            .ok_or("missing approved route version")?;
        let approved = ApprovedNotificationRouteV1::try_from(&context)?;
        assert_eq!(approved.policy.revision, request.route_revision);
        self.calls
            .lock()
            .map_err(|_| "sink lock")?
            .push(request.clone());
        Ok(())
    }
}

impl NotificationSink for Sink {
    fn deliver(&self, request: &NotificationDeliveryV1) -> NotificationSinkResultV1 {
        if let Err(error) = self.observe(request) {
            std::panic::resume_unwind(Box::new(error.to_string()));
        }
        if self.interrupt.swap(false, Ordering::AcqRel) {
            std::panic::resume_unwind(Box::new("interrupt after effect"));
        }
        if self.fail.load(Ordering::Acquire) && request.kind == NotificationDeliveryKindV1::Finding
        {
            NotificationSinkResultV1::Failed {
                reason: NotificationFailureV1::SinkUnavailable,
            }
        } else {
            NotificationSinkResultV1::Accepted {
                receipt: "accepted".into(),
            }
        }
    }
}

struct FixedClock {
    changes: tokio::sync::watch::Sender<u64>,
}

impl araphor_query::follow::Clock for FixedClock {
    fn now_ns(&self) -> araphor_query::Result<u64> {
        Ok(*self.changes.borrow())
    }

    fn changes(&self) -> tokio::sync::watch::Receiver<u64> {
        self.changes.subscribe()
    }
}

impl Fixture {
    async fn update(
        &self,
    ) -> TestResult<(
        araphor_query::follow::Subscription,
        araphor_query::follow::Update,
    )> {
        self.update_at(100).await
    }

    async fn update_at(
        &self,
        now: u64,
    ) -> TestResult<(
        araphor_query::follow::Subscription,
        araphor_query::follow::Update,
    )> {
        use araphor_discovery_definition::{Definition, Program, Source};
        use araphor_query::execution::{Engine, Limits};
        use futures_util::StreamExt as _;

        let engine = Engine::new(self.store.clone(), Limits::default())?;
        let session = engine.session(
            AnalysisSelectionV1::tenant(TENANT),
            &AnalysisReadControl::default(),
            now,
        )?;
        let definition = Definition {
            name: "native-notifications".into(),
            description: String::new(),
            labels: Default::default(),
            program: Program::Sql {
                source: Source::Inline {
                    inline: NotificationRouter::SQL.into(),
                },
            },
        };
        let prepared = session.prepare_definition(&definition, None).await?;
        let plan = Arc::new(prepared.plan().clone());
        let clock = Arc::new(FixedClock {
            changes: tokio::sync::watch::channel(now).0,
        });
        let mut subscription = araphor_query::follow::Subscription::new(
            session,
            plan.clone(),
            prepared.sources().clone(),
            b"native-notifications",
            None,
            clock,
            false,
        )?;
        assert!(Arc::strong_count(&plan) > 1);
        let update = subscription
            .next()
            .await
            .ok_or("native notification update")??;
        Ok((subscription, update))
    }
}

#[tokio::test]
async fn native_notification_sql_delivery() -> TestResult {
    let fixture = Fixture::new()?;
    let router = fixture.router()?;
    Fixture::configure(&router)?;
    let subject = Fixture::submit(&router)?;
    let (subscription, update) = fixture.update().await?;
    assert!(update.exhausted);
    assert!(!update.limited);
    assert!(update.calls.is_empty());
    assert_eq!(update.evaluated_utc_ns, 100);
    assert_eq!(
        update
            .batches
            .as_ref()
            .ok_or("native rows")?
            .iter()
            .map(|batch| batch.num_rows())
            .sum::<usize>(),
        1
    );
    let sink = Sink::new(fixture.store.clone());
    let output = router.consume(&update, &sink)?;
    assert!(output.routed.is_empty());
    assert_eq!(output.delivered.len(), 1);
    assert_eq!(output.delivered[0].0, subject.key);
    assert_eq!(
        *output.delivered[0]
            .1
            .as_ref()
            .map_err(|error| error.to_string())?,
        1
    );
    let calls = sink.calls.lock().map_err(|_| "sink lock")?;
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].key, subject.key);
    assert_eq!(calls[0].unconfirmed_concern, subject.unconfirmed_concern);
    drop(calls);
    let state = Fixture::state(&fixture.store, subject.key)?;
    assert_eq!(state.attempts.len(), 1);
    assert!(state.attempts[0]
        .result
        .as_ref()
        .is_some_and(NotificationSinkResultV1::accepted));
    subscription.cancel_and_join().await?;
    Ok(())
}

#[test]
fn native_router_operations() -> TestResult {
    let fixture = Fixture::new()?;
    let mut changes = fixture.store.subscribe_control();
    let router = fixture.router()?;
    assert!(changes.has_changed()?);
    changes.borrow_and_update();
    assert!(fixture.router().is_err());
    assert!(!changes.has_changed()?);
    assert_eq!(fixture.store.storage_limits(), &StorageLimitsV1::default());
    Fixture::configure(&router)?;
    Fixture::configure(&router)?;
    let state = Fixture::submit(&router)?;
    assert_eq!(state, Fixture::submit(&router)?);
    assert_eq!(state.deadline_utc_ns, Some(200));
    let human = Fixture::grant(NotificationPrincipalV1::Human);
    let (page, next) = router.obligations_page(&human, None, 101)?;
    assert_eq!(page, vec![state.clone()]);
    assert_eq!(next, Some(state.key));
    assert!(router.obligations_page(&human, next, 101)?.0.is_empty());
    let mut hidden = human.clone();
    hidden.routes = vec!["escalation".into()];
    assert!(router.obligations(&hidden, 101)?.is_empty());
    assert!(router
        .acknowledge(&hidden, state.key, 1, [8; 16], 101)
        .is_err());
    assert!(router
        .acknowledge(
            &Fixture::grant(NotificationPrincipalV1::Agent),
            state.key,
            1,
            [8; 16],
            101
        )
        .is_err());
    let advisory = state.advisory.clone();
    assert_eq!(
        router.record_agent(
            &Fixture::grant(NotificationPrincipalV1::Agent),
            state.key,
            [7; 16],
            advisory,
            101
        )?,
        state
    );
    let acknowledged = router.acknowledge(&human, state.key, 1, [8; 16], 101)?;
    assert_eq!(
        router.acknowledge(&human, state.key, 1, [8; 16], 102)?,
        acknowledged
    );
    assert!(router
        .acknowledge(&human, state.key, 1, [6; 16], 102)
        .is_err());
    let sink = Sink::new(fixture.store.clone());
    assert_eq!(router.deliver_obligation(state.key, &sink, 201)?, 0);
    assert!(sink.calls.lock().map_err(|_| "sink lock")?.is_empty());
    let health = router.health(&human, 201)?;
    assert_eq!(health.configured_routes, 2);
    assert_eq!(health.obligations, 1);
    assert_eq!(health.acknowledged, 1);
    changes.borrow_and_update();
    drop(router);
    assert!(changes.has_changed()?);
    drop(fixture.router()?);
    drop((sink, changes));
    let fixture = fixture.reopen()?;
    let router = fixture.router()?;
    assert_eq!(router.obligations(&human, 202)?, vec![acknowledged]);
    assert_eq!(
        fixture
            .store
            .context_heads(TENANT, NOTIFICATION_ROUTE_OWNER, 2)?
            .len(),
        2
    );
    Ok(())
}

#[test]
fn native_pending_attempt_resume() -> TestResult {
    let fixture = Fixture::new()?;
    let router = fixture.router()?;
    Fixture::configure(&router)?;
    let original = Fixture::submit(&router)?;
    let sink = Sink::new(fixture.store.clone());
    sink.interrupt.store(true, Ordering::Release);
    let interrupted = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        router.deliver_obligation(original.key, &sink, 101)
    }));
    assert!(interrupted.is_err());
    let first = sink.calls.lock().map_err(|_| "sink lock")?[0].clone();
    let pending = Fixture::state(&fixture.store, original.key)?;
    assert!(pending.pending(NotificationDeliveryKindV1::Finding));
    assert_eq!(pending.attempts[0].context_revision, original.revision);
    drop((router, sink));
    let fixture = fixture.reopen()?;
    assert_eq!(Fixture::state(&fixture.store, original.key)?, pending);
    let router = fixture.router()?;
    let mut changed = Fixture::policy("primary");
    changed.revision = 2;
    changed.minimum_priority = NotificationPriorityV1::Critical;
    router.configure(
        &Fixture::grant(NotificationPrincipalV1::Human),
        changed,
        102,
    )?;
    let sink = Sink::new(fixture.store.clone());
    assert_eq!(router.deliver_obligation(original.key, &sink, 103)?, 1);
    assert_eq!(sink.calls.lock().map_err(|_| "sink lock")?[0], first);
    let completed = Fixture::state(&fixture.store, original.key)?;
    assert!(!completed.pending(NotificationDeliveryKindV1::Finding));
    assert_eq!(completed.attempts.len(), 1);
    assert_eq!(
        completed.attempts[0].result,
        Some(NotificationSinkResultV1::Accepted {
            receipt: "accepted".into()
        })
    );
    assert_eq!(completed.attempts[0].completed_utc_ns, Some(103));
    drop((router, sink));
    let fixture = fixture.reopen()?;
    assert_eq!(Fixture::state(&fixture.store, original.key)?, completed);
    Ok(())
}

#[test]
fn native_pending_conflict() -> TestResult {
    let fixture = Fixture::new()?;
    let router = fixture.router()?;
    Fixture::configure(&router)?;
    let mut state = Fixture::submit(&router)?;
    let previous = state.revision;
    state.revision += 1;
    state.advisory = None;
    *fixture
        .authority
        .competing
        .lock()
        .map_err(|_| "authority lock")? = Some((
        AnalysisContextVersionV1 {
            key: Fixture::key(&state),
            valid_from_utc_ns: None,
            valid_until_utc_ns: None,
            sensitivity: state.sensitivity,
            body: state.encode()?,
        },
        previous,
    ));
    let sink = Sink::new(fixture.store.clone());
    assert!(router.deliver_obligation(state.key, &sink, 101).is_err());
    assert!(sink.calls.lock().map_err(|_| "sink lock")?.is_empty());
    assert_eq!(Fixture::state(&fixture.store, state.key)?, state);
    assert!(state.attempts.is_empty());
    assert!(fixture
        .store
        .context_version(&AnalysisContextKeyV1 {
            owner_revision: state.revision + 1,
            ..Fixture::key(&state)
        })?
        .is_none());
    drop((router, sink));
    let fixture = fixture.reopen()?;
    assert_eq!(Fixture::state(&fixture.store, state.key)?, state);
    let router = fixture.router()?;
    let sink = Sink::new(fixture.store.clone());
    assert_eq!(router.deliver_obligation(state.key, &sink, 102)?, 1);
    Ok(())
}

#[test]
fn native_failed_attempt_retry() -> TestResult {
    let fixture = Fixture::new()?;
    let router = fixture.router()?;
    Fixture::configure(&router)?;
    let original = Fixture::submit(&router)?;
    let sink = Sink::new(fixture.store.clone());
    sink.fail.store(true, Ordering::Release);
    assert_eq!(router.deliver_obligation(original.key, &sink, 101)?, 2);
    let failed = Fixture::state(&fixture.store, original.key)?;
    assert_eq!(failed.attempts.len(), 2);
    assert_eq!(failed.failure, Some(NotificationFailureV1::SinkUnavailable));
    assert_eq!(
        failed.attempts[0].result,
        Some(NotificationSinkResultV1::Failed {
            reason: NotificationFailureV1::SinkUnavailable
        })
    );
    assert_eq!(failed.attempts[0].number, 1);
    assert_eq!(
        failed.attempts[1].kind,
        NotificationDeliveryKindV1::FailureEscalation
    );
    assert_eq!(failed.attempts[1].number, 2);
    drop((router, sink));
    let fixture = fixture.reopen()?;
    assert_eq!(Fixture::state(&fixture.store, original.key)?, failed);
    let router = fixture.router()?;
    let sink = Sink::new(fixture.store.clone());
    assert_eq!(router.deliver_obligation(original.key, &sink, 102)?, 1);
    let calls = sink.calls.lock().map_err(|_| "sink lock")?;
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].attempt, 3);
    assert_eq!(calls[0].kind, NotificationDeliveryKindV1::Finding);
    let completed = Fixture::state(&fixture.store, original.key)?;
    assert_eq!(completed.attempts[..2], failed.attempts);
    assert_eq!(completed.failure, None);
    assert_eq!(completed.attempts[2].number, 3);
    assert!(completed.attempts[2]
        .result
        .as_ref()
        .is_some_and(NotificationSinkResultV1::accepted));
    drop(calls);
    drop((router, sink));
    let fixture = fixture.reopen()?;
    assert_eq!(Fixture::state(&fixture.store, original.key)?, completed);
    Ok(())
}
