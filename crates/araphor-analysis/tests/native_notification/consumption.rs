use super::*;
use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use araphor_analysis::InstanceHost;
use araphor_discovery_definition::{Definition, Program, Source};
use araphor_package::PackageBundle;
use araphor_query::{
    execution::{Engine, Limits},
    follow::{Subscription, Update},
};
use futures_util::StreamExt as _;
use serde::{Deserialize, Serialize};

impl PackageAuthorization for Authority {
    fn check(&self, grant: &PackageGrantV1, _: PackageActionV1) -> araphor_data::Result<()> {
        grant.remaining().map(|_| ())
    }
    fn admit(&self, _: &PackageGrantV1, _: &PackageBundle) -> araphor_data::Result<()> {
        Ok(())
    }
    fn commit(
        &self,
        grant: &PackageGrantV1,
        action: PackageActionV1,
        bundle: &PackageBundle,
        operation: &mut dyn FnMut() -> araphor_data::Result<()>,
    ) -> araphor_data::Result<()> {
        self.commit_many(&[(grant, action, Some(bundle))], operation)
    }
    fn commit_many(
        &self,
        grants: &[(&PackageGrantV1, PackageActionV1, Option<&PackageBundle>)],
        operation: &mut dyn FnMut() -> araphor_data::Result<()>,
    ) -> araphor_data::Result<()> {
        for (grant, action, _) in grants {
            PackageAuthorization::check(self, *grant, *action)?;
        }
        operation()
    }
    fn changes(&self) -> tokio::sync::watch::Receiver<u64> {
        self.changes.subscribe()
    }
}

#[derive(Deserialize)]
struct Interest {
    selection: AnalysisSelectionV1,
    requests: AnalysisTableRequests,
    owners: Option<BTreeSet<String>>,
}

#[derive(Deserialize)]
struct Consumer {
    completed_through: StorePositionV1,
    interest: Interest,
}

#[derive(Deserialize, Serialize)]
struct Cut {
    revision: u64,
    native: (u64, u64, u64),
    raw: Option<(u64, u64, u64)>,
}

#[derive(Deserialize, Serialize)]
struct Capture {
    owner: u64,
    generation: u64,
    version: u64,
    cut: Cut,
    exhaustive: bool,
}

#[derive(Deserialize, Serialize)]
struct Completion {
    input: Capture,
    lifecycle: u64,
    revision: u64,
    contexts: Vec<AnalysisContextRefV1>,
}

impl Fixture {
    fn consumer(&self) -> TestResult<Consumer> {
        let view = self.store.view()?;
        let (_, value) = view
            .snapshot()
            .prefix(b"\0data/input/")
            .next()
            .ok_or("consumer")??;
        assert_eq!(value[0], 0);
        Ok(rmp_serde::from_slice(&value[1..])?)
    }

    fn configure_cdc(router: &NotificationRouter) -> TestResult {
        for id in ["escalation", "primary"] {
            let mut policy = Self::policy(id);
            policy.acknowledgement_ns = 60_000_000_000;
            router.configure(&Self::grant(NotificationPrincipalV1::Human), policy, 10)?;
        }
        Ok(())
    }

    async fn admission(
        &self,
        router: Arc<NotificationRouter>,
    ) -> TestResult<(Arc<Engine>, ManagedInstance)> {
        let engine = Engine::new(self.store.clone(), Limits::default())?;
        let host = InstanceHost::with_notifications(
            engine.clone(),
            self.authority.clone(),
            None,
            router,
            Arc::new(Sink::new(self.store.clone())),
            true,
        );
        let control = AnalysisReadControl::default();
        let instance = host
            .admit_notifications(
                PackageGrantV1 {
                    principal: "native-notifications".into(),
                    revision: 1,
                    selection: AnalysisSelectionV1::tenant(TENANT),
                    expires_utc_ns: None,
                    authorization_id: Some("native-notifications".into()),
                },
                &control,
            )
            .await?;
        let running = self.store.set_managed_running(
            TENANT,
            "notifications",
            instance.admitted().lifecycle,
            true,
            || Ok(()),
        )?;
        Ok((engine, running))
    }

    async fn following(
        engine: &Arc<Engine>,
        instance: ManagedInstance,
    ) -> TestResult<Subscription> {
        let mut session = engine.session(
            AnalysisSelectionV1::tenant(TENANT),
            &AnalysisReadControl::default(),
            100,
        )?;
        session.bind_consumer(instance)?;
        let definition = Definition {
            name: "native-notifications".into(),
            description: String::new(),
            labels: BTreeMap::new(),
            program: Program::Sql {
                source: Source::Inline {
                    inline: NotificationRouter::SQL.into(),
                },
            },
        };
        let prepared = session.prepare_definition(&definition, None).await?;
        Ok(Subscription::new(
            session,
            Arc::new(prepared.plan().clone()),
            prepared.sources().clone(),
            b"native-notification-consumer",
            None,
            Arc::new(FixedClock {
                changes: tokio::sync::watch::channel(100).0,
            }),
            true,
        )?)
    }

    async fn rows(subscription: &mut Subscription) -> TestResult<Update> {
        tokio::time::timeout(Duration::from_secs(30), async {
            loop {
                let update = subscription.next().await.ok_or("subscription ended")??;
                if update.batches.is_some() {
                    return Ok(update);
                }
            }
        })
        .await?
    }
}

#[tokio::test]
async fn native_notification_consumption() -> TestResult {
    let fixture = Fixture::new()?;
    let router = Arc::new(fixture.router()?);
    Fixture::configure_cdc(&router)?;
    let original = Fixture::submit(&router)?;
    let (engine, instance) = fixture.admission(router.clone()).await?;
    let mut subscription = Fixture::following(&engine, instance.clone()).await?;
    let update = Fixture::rows(&mut subscription).await?;
    assert!(update.snapshot.notification_capture().is_some());
    let anchor = fixture.store.view()?.revision();
    fixture.store.database().inner().flush_memtables()?;
    fixture.store.database().inner().rotate_journal()?;
    assert_eq!(fixture.consumer()?.completed_through.commit_revision, 0);
    let cut = update.cursor.position();
    let mut concern = Fixture::concern();
    concern.concern_id = [8; 16];
    let later = router.submit_concern(
        &Fixture::grant(NotificationPrincipalV1::Agent),
        "primary",
        concern,
        100,
    )?;
    assert!(fixture.store.view()?.revision() > cut.commit_revision);
    let sink = Sink::new(fixture.store.clone());
    let result = router.consume(&update, &sink)?;
    assert_eq!(result.delivered.len(), 1);
    assert_eq!(result.delivered[0].0, original.key);
    assert_eq!(fixture.consumer()?.completed_through, cut);
    assert!(Fixture::state(&fixture.store, later.key)?
        .attempts
        .is_empty());
    let revision = fixture.store.view()?.revision();
    assert_eq!(
        fixture.store.write()?.commit_notifications(
            update.snapshot.notification_capture().ok_or("capture")?,
            &[]
        )?,
        (revision, true)
    );
    assert_eq!(fixture.store.view()?.revision(), revision);
    let next = Fixture::rows(&mut subscription).await?;
    assert!(next.cursor.position() > cut);
    let result = router.consume(&next, &sink)?;
    assert_eq!(result.delivered.len(), 1);
    assert_eq!(result.delivered[0].0, later.key);
    assert_eq!(
        fixture.consumer()?.completed_through,
        next.cursor.position()
    );
    let empty = Fixture::rows(&mut subscription).await?;
    assert_eq!(
        empty
            .batches
            .as_ref()
            .ok_or("empty SQL relation")?
            .iter()
            .map(|batch| batch.num_rows())
            .sum::<usize>(),
        0
    );
    let result = router.consume(&empty, &sink)?;
    assert!(result.delivered.is_empty());
    assert_eq!(
        fixture.consumer()?.completed_through,
        empty.cursor.position()
    );
    let completed = fixture.store.view()?.revision();
    fixture.store.checkpoint_inputs()?;
    fixture.store.checkpoint_inputs()?;
    assert_eq!(fixture.store.view()?.revision(), completed);
    assert_eq!(sink.calls.lock().map_err(|_| "sink lock")?.len(), 2);
    let foreign = AnalysisContextVersionV1 {
        key: AnalysisContextKeyV1 {
            tenant_id: [2; 16],
            owner_id: "unrelated".into(),
            entity_key: vec![1],
            lifetime_key: vec![1],
            owner_revision: 1,
        },
        valid_from_utc_ns: None,
        valid_until_utc_ns: None,
        sensitivity: ContextSensitivityV1::Tenant,
        body: vec![1],
    };
    fixture.store.commit_context(&foreign)?;
    fixture.store.checkpoint_inputs()?;
    let filtered = fixture.store.view()?.revision();
    fixture.store.checkpoint_inputs()?;
    assert_eq!(fixture.store.view()?.revision(), filtered);
    assert_eq!(
        fixture.consumer()?.completed_through,
        empty.cursor.position()
    );
    fixture.store.checkpoint()?;
    assert!(fixture
        .store
        .read_at(anchor)?
        .snapshot()
        .cursor()?
        .is_none());
    let collected = fixture.store.view()?.revision();
    assert_eq!(
        fixture.store.write()?.commit_notifications(
            update.snapshot.notification_capture().ok_or("capture")?,
            &[]
        )?,
        (collected, true)
    );
    assert_eq!(fixture.store.view()?.revision(), collected);
    fixture.store.database().inner().major_compact()?;
    subscription.cancel_and_join().await?;
    drop((update, next, empty, engine, router, sink));
    let fixture = fixture.reopen()?;
    assert!(fixture.consumer()?.completed_through.commit_revision >= cut.commit_revision);
    let router = Arc::new(fixture.router()?);
    let engine = Engine::new(fixture.store.clone(), Limits::default())?;
    let current = fixture
        .store
        .managed_instance(TENANT, "notifications", &AnalysisReadControl::default())?
        .ok_or("instance")?;
    let mut subscription = Fixture::following(&engine, current).await?;
    let update = Fixture::rows(&mut subscription).await?;
    let sink = Sink::new(fixture.store.clone());
    assert!(router.consume(&update, &sink)?.delivered.is_empty());
    assert!(sink.calls.lock().map_err(|_| "sink lock")?.is_empty());
    subscription.cancel_and_join().await?;
    Ok(())
}

#[tokio::test]
async fn native_notification_incomplete() -> TestResult {
    let fixture = Fixture::new()?;
    let router = Arc::new(fixture.router()?);
    Fixture::configure_cdc(&router)?;
    let original = Fixture::submit(&router)?;
    let (engine, instance) = fixture.admission(router.clone()).await?;
    let mut subscription = Fixture::following(&engine, instance.clone()).await?;
    let update = Fixture::rows(&mut subscription).await?;
    let control = AnalysisReadControl::default();
    let memory = araphor_query::memory::Memory::new(None, None);
    let budget = memory.managed_budget(&control, usize::MAX);
    let consumer = fixture.consumer()?;
    let inputs = fixture.store.subscribe_managed_inputs(
        &instance,
        &consumer.interest.selection,
        &consumer.interest.requests,
        consumer.interest.owners.as_ref(),
        &control,
        budget.as_ref(),
    )?;
    let requests =
        AnalysisTableRequests::from([("notifications".into(), Some(BTreeSet::from([0])))]);
    let selection = instance.grant.selection.project(&requests)?;
    let (_, partial) = fixture.store.read_notification_subscribed(
        &inputs,
        &selection,
        &instance,
        AnalysisTableRead {
            requests: &requests,
            event_ranges: None,
            mode: AnalysisReadModeV1::Complete,
            now: 100,
        },
        AnalysisExtractLimits::default(),
        &control,
        None,
    )?;
    assert!(
        !fixture
            .store
            .write()?
            .commit_notifications(&partial, &[])?
            .1
    );
    assert_eq!(fixture.consumer()?.completed_through.commit_revision, 0);
    let capture = update.snapshot.notification_capture().ok_or("capture")?;
    let mut changed = original.clone();
    changed.revision += 1;
    changed.advisory = None;
    let context = AnalysisContextVersionV1 {
        key: Fixture::key(&changed),
        valid_from_utc_ns: None,
        valid_until_utc_ns: None,
        sensitivity: changed.sensitivity,
        body: changed.encode()?,
    };
    let revision = fixture.store.view()?.revision();
    let mut tx = fixture.store.write()?;
    let mut reference = tx.context(&context, Some(original.revision))?;
    reference.commit_revision += 1;
    assert!(tx.commit_notifications(capture, &[reference]).is_err());
    assert_eq!(fixture.store.view()?.revision(), revision);
    assert_eq!(Fixture::state(&fixture.store, original.key)?, original);
    assert_eq!(fixture.consumer()?.completed_through.commit_revision, 0);
    fixture.store.stop_managed(&instance, || Ok(()))?;
    assert!(fixture
        .store
        .write()?
        .commit_notifications(capture, &[])
        .is_err());
    assert_eq!(fixture.consumer()?.completed_through.commit_revision, 0);
    assert!(Fixture::state(&fixture.store, original.key)?
        .attempts
        .is_empty());
    subscription.cancel_and_join().await?;
    Ok(())
}

#[tokio::test]
async fn native_notification_pending_cut() -> TestResult {
    let fixture = Fixture::new()?;
    let router = Arc::new(fixture.router()?);
    Fixture::configure_cdc(&router)?;
    let subjects = Fixture::subjects(&router)?;
    let (engine, instance) = fixture.admission(router.clone()).await?;
    let mut subscription = Fixture::following(&engine, instance).await?;
    let update = Fixture::rows(&mut subscription).await?;
    let sink = Sink::new(fixture.store.clone());
    sink.interrupt.store(true, Ordering::Release);
    assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(
        || router.consume(&update, &sink)
    ))
    .is_err());
    assert_eq!(fixture.consumer()?.completed_through.commit_revision, 0);
    for subject in &subjects {
        assert!(Fixture::state(&fixture.store, subject.key)?
            .pending(NotificationDeliveryKindV1::Finding));
    }
    let request = sink.calls.lock().map_err(|_| "sink lock")?[0].clone();
    subscription.cancel_and_join().await?;
    drop((router, sink, update, engine));
    let fixture = fixture.reopen()?;
    assert_eq!(fixture.consumer()?.completed_through.commit_revision, 0);
    let router = Arc::new(fixture.router()?);
    let engine = Engine::new(fixture.store.clone(), Limits::default())?;
    let instance = fixture
        .store
        .managed_instance(TENANT, "notifications", &AnalysisReadControl::default())?
        .ok_or("instance")?;
    let mut subscription = Fixture::following(&engine, instance).await?;
    let update = Fixture::rows(&mut subscription).await?;
    let sink = Sink::new(fixture.store.clone());
    let result = router.consume(&update, &sink)?;
    assert_eq!(result.delivered.len(), 3);
    assert_eq!(
        fixture.consumer()?.completed_through,
        update.cursor.position()
    );
    assert_eq!(
        sink.calls
            .lock()
            .map_err(|_| "sink lock")?
            .iter()
            .find(|call| call.key == request.key),
        Some(&request)
    );
    subscription.cancel_and_join().await?;
    Ok(())
}

#[tokio::test]
async fn native_notification_host() -> TestResult {
    use araphor_query::follow::{Clock as _, SystemClock};
    let fixture = Fixture::new()?;
    let router = Arc::new(fixture.router()?);
    let mut human = Fixture::grant(NotificationPrincipalV1::Human);
    human.expires_utc_ns = u64::MAX;
    let mut agent = Fixture::grant(NotificationPrincipalV1::Agent);
    agent.expires_utc_ns = u64::MAX;
    for id in ["escalation", "primary"] {
        let mut policy = Fixture::policy(id);
        policy.acknowledgement_ns = 60_000_000_000;
        router.configure(&human, policy, 10)?;
    }
    let now = SystemClock::default().now_ns()?;
    let subject = router.submit_concern(&agent, "primary", Fixture::concern(), now)?;
    let engine = Engine::new(fixture.store.clone(), Limits::default())?;
    let sink = Arc::new(Sink::new(fixture.store.clone()));
    let host = InstanceHost::with_notifications(
        engine.clone(),
        fixture.authority.clone(),
        None,
        router.clone(),
        sink.clone(),
        true,
    );
    let control = AnalysisReadControl::default();
    let instance = host
        .admit_notifications(
            PackageGrantV1 {
                principal: "native-notifications".into(),
                revision: 1,
                selection: AnalysisSelectionV1::tenant(TENANT),
                expires_utc_ns: None,
                authorization_id: Some("native-notifications".into()),
            },
            &control,
        )
        .await?;
    let (stop, stopped) = tokio::sync::watch::channel(false);
    let worker = tokio::spawn(host.clone().serve(stopped, u64::MAX));
    let running = host
        .start(instance.clone(), instance.admitted().lifecycle, &control)
        .await?;
    let mut changes = fixture.store.subscribe_revision();
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            let state = Fixture::state(&fixture.store, subject.key)?;
            if state.attempts.first().is_some_and(|attempt| {
                attempt
                    .result
                    .as_ref()
                    .is_some_and(NotificationSinkResultV1::accepted)
            }) {
                return Ok::<_, Box<dyn std::error::Error + Send + Sync>>(());
            }
            changes.changed().await?;
        }
    })
    .await??;
    assert!(fixture.consumer()?.completed_through.commit_revision > 0);
    assert_eq!(sink.calls.lock().map_err(|_| "sink lock")?.len(), 1);
    let consumed = fixture.consumer()?.completed_through;
    stop.send_replace(true);
    tokio::time::timeout(Duration::from_secs(30), worker).await???;
    let weak_host = Arc::downgrade(&host);
    let weak_engine = Arc::downgrade(&engine);
    drop((host, engine, router, sink, instance, running, changes));
    assert!(
        weak_host.upgrade().is_none(),
        "host remains after joined shutdown"
    );
    assert!(
        weak_engine.upgrade().is_none(),
        "engine remains after joined shutdown; store references {}",
        Arc::strong_count(&fixture.store)
    );
    assert_eq!(
        Arc::strong_count(&fixture.store),
        2,
        "store references after joined shutdown"
    );
    let fixture = fixture.reopen()?;
    assert_eq!(fixture.consumer()?.completed_through, consumed);
    let router = Arc::new(fixture.router()?);
    let engine = Engine::new(fixture.store.clone(), Limits::default())?;
    let sink = Arc::new(Sink::new(fixture.store.clone()));
    let host = InstanceHost::with_notifications(
        engine.clone(),
        fixture.authority.clone(),
        None,
        router.clone(),
        sink.clone(),
        true,
    );
    let (stop, stopped) = tokio::sync::watch::channel(false);
    let worker = tokio::spawn(host.clone().serve(stopped, u64::MAX));
    let mut concern = Fixture::concern();
    concern.concern_id = [8; 16];
    let later =
        router.submit_concern(&agent, "primary", concern, SystemClock::default().now_ns()?)?;
    let mut changes = fixture.store.subscribe_revision();
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            let state = Fixture::state(&fixture.store, later.key)?;
            if state.attempts.first().is_some_and(|attempt| {
                attempt
                    .result
                    .as_ref()
                    .is_some_and(NotificationSinkResultV1::accepted)
            }) {
                return Ok::<_, Box<dyn std::error::Error + Send + Sync>>(());
            }
            changes.changed().await?;
        }
    })
    .await??;
    assert!(fixture.consumer()?.completed_through > consumed);
    let calls = sink.calls.lock().map_err(|_| "sink lock")?;
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].key, later.key);
    drop(calls);
    stop.send_replace(true);
    tokio::time::timeout(Duration::from_secs(30), worker).await???;
    Ok(())
}

#[tokio::test]
async fn native_notification_receipt_recovery() -> TestResult {
    for context in [false, true] {
        let fixture = Fixture::new()?;
        let router = Arc::new(fixture.router()?);
        Fixture::configure_cdc(&router)?;
        Fixture::submit(&router)?;
        let (engine, instance) = fixture.admission(router.clone()).await?;
        let mut subscription = Fixture::following(&engine, instance).await?;
        let update = Fixture::rows(&mut subscription).await?;
        let sink = Sink::new(fixture.store.clone());
        router.consume(&update, &sink)?;
        let mut foreign = Fixture::concern();
        foreign.concern_id = [8; 16];
        router.submit_concern(
            &Fixture::grant(NotificationPrincipalV1::Agent),
            "primary",
            foreign,
            100,
        )?;
        let view = fixture.store.view()?;
        let (key, value) = view
            .snapshot()
            .prefix(b"\0data/notification-completion/")
            .next()
            .ok_or("completion receipt")??;
        assert_eq!(value[0], 0);
        let mut receipt: Completion = rmp_serde::from_slice(&value[1..])?;
        let mut tx = fixture.store.write()?;
        receipt.revision = if context {
            tx.revision()
        } else {
            view.revision()
        };
        if context {
            receipt.contexts[0].commit_revision = update.cursor.position().commit_revision;
        }
        let mut encoded = vec![0];
        encoded.extend(rmp_serde::to_vec_named(&receipt)?);
        tx.native().insert(key, encoded);
        tx.commit([])?;
        subscription.cancel_and_join().await?;
        drop((view, engine, router, sink, update));
        let Fixture {
            directory,
            store,
            authority,
        } = fixture;
        drop((store, authority));
        assert!(
            matches!(NativeStore::open(&directory.path().join("data")),Err(araphor_data::Error::Package {
            code:PackageErrorCodeV1::Invalid,field,..}) if field==if context {"notification completion context"} else {"notification completion commit"})
        );
    }
    Ok(())
}
