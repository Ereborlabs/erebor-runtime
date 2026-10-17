#![cfg(test)]

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

use super::*;

struct TestClock {
    now: AtomicU64,
    started: Option<std::time::Instant>,
    reads: watch::Sender<u64>,
    changes: watch::Sender<u64>,
}

impl TestClock {
    fn new(now: u64) -> Arc<Self> {
        Arc::new(Self {
            now: AtomicU64::new(now),
            started: None,
            reads: watch::channel(0).0,
            changes: watch::channel(0).0,
        })
    }

    fn running(now: u64) -> Arc<Self> {
        Arc::new(Self {
            now: AtomicU64::new(now),
            started: Some(std::time::Instant::now()),
            reads: watch::channel(0).0,
            changes: watch::channel(0).0,
        })
    }

    fn set(&self, now: u64) {
        self.now.store(now, Ordering::SeqCst);
        self.changes.send_replace(now);
    }

    async fn idle(&self, reads: u64) -> TestResult {
        let mut observed = self.reads.subscribe();
        tokio::time::timeout(
            Duration::from_secs(120),
            observed.wait_for(|value| *value >= reads),
        )
        .await??;
        Ok(())
    }
}

impl Clock for TestClock {
    fn now_ns(&self) -> araphor_query::Result<u64> {
        self.reads.send_modify(|reads| *reads += 1);
        Ok(self.now.load(Ordering::SeqCst)
            + self
                .started
                .map_or(0, |start| start.elapsed().as_nanos() as u64))
    }

    fn changes(&self) -> watch::Receiver<u64> {
        self.changes.subscribe()
    }
}

type ContextHook = Box<dyn FnOnce() -> araphor_data::Result<()> + Send>;

struct NoticedContext {
    facts: watch::Sender<u64>,
    reads: watch::Sender<u64>,
    hook: Mutex<Option<ContextHook>>,
}

impl NoticedContext {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            facts: watch::channel(0).0,
            reads: watch::channel(0).0,
            hook: Mutex::new(None),
        })
    }
}

impl DiscoveryContextProvider for NoticedContext {
    fn context(&self, record: &DiscoveryRecordV1) -> araphor_data::Result<DiscoveryContextJoinV1> {
        let hook = self
            .hook
            .lock()
            .map_err(|_| {
                crate::DiscoveryInvalidSnafu {
                    field: "context lock",
                }
                .build()
            })?
            .take();
        if let Some(hook) = hook {
            hook()?;
        }
        MissingContext.context(record)
    }

    fn revision(&self, _source: &EvidenceIntakeIdentityV1) -> araphor_data::Result<u64> {
        self.reads.send_modify(|reads| *reads += 1);
        Ok(*self.facts.borrow())
    }

    fn changes(&self) -> araphor_data::Result<Option<watch::Receiver<u64>>> {
        Ok(Some(self.facts.subscribe()))
    }
}

async fn profile_after(
    owner: &DiscoveryOwner,
    source: &EvidenceIntakeIdentityV1,
    ready: impl Fn(&DiscoveryProfileV1) -> bool,
) -> std::result::Result<DiscoveryProfileV1, Box<dyn std::error::Error>> {
    let mut changes = owner.store.subscribe_revision();
    tokio::time::timeout(Duration::from_secs(120), async {
        loop {
            changes.borrow_and_update();
            if let Some(profile) = owner.profile(source)? {
                if ready(&profile) {
                    return Ok(profile);
                }
            }
            changes.changed().await?;
        }
    })
    .await?
}

#[tokio::test]
async fn discovery_waits_for_events() -> TestResult {
    let fixture = DiscoveryFixture::new(Default::default())?;
    fixture.accept(1)?;
    let provider = NoticedContext::new();
    let mut owner = fixture.owner(Default::default())?;
    owner.provider = provider.clone();
    let owner = Arc::new(owner);
    assert_eq!(owner.process(10)?, 1);
    let initial = owner.profile(&fixture.source)?.ok_or("profile absent")?;
    let clock = TestClock::new(10);
    let (stop, stopped) = watch::channel(false);
    let mut worker = tokio::spawn(owner.clone().run_clock(stopped, clock.clone()));
    clock.idle(2).await?;
    let reads = *provider.reads.borrow();
    let revision = fixture.store.meta()?.commit_revision;
    tokio::select! {
        result = &mut worker => return Err(format!("worker stopped: {result:?}").into()),
        () = tokio::time::sleep(Duration::from_millis(1_100)) => {}
    }
    assert_eq!(*provider.reads.borrow(), reads);
    assert_eq!(fixture.store.meta()?.commit_revision, revision);

    provider.facts.send_replace(1);
    let refreshed = profile_after(&owner, &fixture.source, |profile| {
        profile.facts_revision == 1
    })
    .await?;
    assert_eq!(refreshed.snapshot, initial.snapshot);
    assert_eq!(refreshed.snapshot.accepted_records, 1);
    assert_eq!(
        owner.installed_refs(&refreshed)?,
        owner.installed_refs(&initial)?
    );
    fixture.accept(2)?;
    let updated = profile_after(&owner, &fixture.source, |profile| {
        profile.snapshot.accepted_records == 2
    })
    .await?;
    assert_eq!(updated.interval_id, initial.interval_id);
    assert!(!updated.sealed);
    stop.send_replace(true);
    tokio::time::timeout(Duration::from_secs(120), worker).await???;
    Ok(())
}

#[tokio::test]
async fn discovery_seals_without_intake() -> TestResult {
    let fixture = DiscoveryFixture::new(Default::default())?;
    fixture.accept(1)?;
    let owner = Arc::new(fixture.owner(Default::default())?);
    owner.process(10)?;
    let initial = owner.profile(&fixture.source)?.ok_or("profile absent")?;
    let expiry = initial.created_utc_ns + owner.config.seal_interval_ns;
    let clock = TestClock::new(10);
    let (stop, stopped) = watch::channel(false);
    let worker = tokio::spawn(owner.clone().run_clock(stopped, clock.clone()));
    clock.idle(2).await?;
    clock.set(expiry - 1);
    clock.idle(4).await?;
    assert!(
        !owner
            .profile(&fixture.source)?
            .ok_or("profile absent")?
            .sealed
    );
    clock.set(expiry);
    let sealed = profile_after(&owner, &fixture.source, |profile| profile.sealed).await?;
    assert_eq!(sealed.interval_id, initial.interval_id);
    assert_eq!(sealed.snapshot, initial.snapshot);
    assert_eq!(sealed.updated_utc_ns, expiry);
    stop.send_replace(true);
    tokio::time::timeout(Duration::from_secs(120), worker).await???;
    Ok(())
}

#[tokio::test]
async fn discovery_seal_deadline_wakes() -> TestResult {
    let fixture = DiscoveryFixture::new(Default::default())?;
    fixture.accept(1)?;
    let owner = Arc::new(fixture.owner(DiscoveryConfigV1 {
        seal_interval_ns: 100_000_000,
        ..Default::default()
    })?);
    owner.process(10)?;
    let initial = owner.profile(&fixture.source)?.ok_or("profile absent")?;
    assert!(!initial.sealed);
    let clock = TestClock::running(10);
    let (stop, stopped) = watch::channel(false);
    let worker = tokio::spawn(owner.clone().run_clock(stopped, clock));
    let sealed = profile_after(&owner, &fixture.source, |profile| profile.sealed).await?;
    assert_eq!(sealed.interval_id, initial.interval_id);
    assert_eq!(sealed.snapshot, initial.snapshot);
    assert!(sealed.updated_utc_ns >= initial.created_utc_ns + owner.config.seal_interval_ns);
    stop.send_replace(true);
    tokio::time::timeout(Duration::from_secs(120), worker).await???;
    Ok(())
}

#[tokio::test]
async fn discovery_busy_keeps_deadlines() -> TestResult {
    for sources in [1, 2] {
        let fixture = DiscoveryFixture::new(Default::default())?;
        fixture.accept(1)?;
        let mut busy = fixture.source.clone();
        if sources == 2 {
            busy.source_epoch += 1;
            fixture.store.accept_validated_batch(
                busy.clone(),
                ValidatedEvidenceBatchV1 {
                    cpu_id: 0,
                    first_cursor: 1,
                    last_cursor: 1,
                    intake_utc_ns: 1,
                    framed_records: fixture.frame.clone().into(),
                    frame_ends: vec![fixture.frame.len()],
                },
            )?;
        }
        let owner = Arc::new(fixture.owner(DiscoveryConfigV1 {
            seal_interval_ns: 5_000_000_000,
            ..Default::default()
        })?);
        assert_eq!(owner.process(10)?, sources);
        fixture.store.accept_validated_batch(
            busy.clone(),
            ValidatedEvidenceBatchV1 {
                cpu_id: 0,
                first_cursor: 2,
                last_cursor: 2,
                intake_utc_ns: 2,
                framed_records: fixture.frame.clone().into(),
                frame_ends: vec![fixture.frame.len()],
            },
        )?;
        let query = &owner.execution.owner.query;
        let held = (0..query
            .limits()
            .tenant_evaluations
            .min(query.limits().global_evaluations))
            .map(|_| query.reserve_evaluation(busy.tenant_id))
            .collect::<araphor_query::Result<Vec<_>>>()?;
        let (stop, stopped) = watch::channel(false);
        let worker = tokio::spawn(owner.clone().run_clock(stopped, TestClock::running(10)));
        let sealed = profile_after(&owner, &busy, |profile| profile.sealed).await?;
        assert_eq!(sealed.snapshot.accepted_records, 1);
        assert_eq!(
            owner
                .store
                .processor_health(&sealed.scope)?
                .ok_or("health absent")?
                .consumed_cursor,
            1
        );
        if sources == 2 {
            let first = owner
                .profile(&fixture.source)?
                .ok_or("first profile absent")?;
            assert!(first.sealed);
            assert_eq!(first.snapshot.accepted_records, 1);
        }
        stop.send_replace(true);
        tokio::time::timeout(Duration::from_secs(120), worker).await???;
        drop(held);
    }
    Ok(())
}

#[tokio::test]
async fn discovery_drains_quiet_pages() -> TestResult {
    let fixture = DiscoveryFixture::new(Default::default())?;
    fixture.accept(1)?;
    let provider = NoticedContext::new();
    let mut owner = fixture.owner(DiscoveryConfigV1 {
        sources_per_pass: 1,
        ..Default::default()
    })?;
    owner.provider = provider.clone();
    let owner = Arc::new(owner);
    owner.process(10)?;
    let mut second = fixture.source.clone();
    second.source_epoch += 1;
    fixture.store.accept_validated_batch(
        second.clone(),
        ValidatedEvidenceBatchV1 {
            cpu_id: 0,
            first_cursor: 1,
            last_cursor: 1,
            intake_utc_ns: 1,
            framed_records: fixture.frame.clone().into(),
            frame_ends: vec![fixture.frame.len()],
        },
    )?;
    let store = fixture.store.clone();
    let first = fixture.source.clone();
    let frame = fixture.frame.clone();
    *provider.hook.lock().map_err(|_| "context lock")? = Some(Box::new(move || {
        store.accept_validated_batch(
            first,
            ValidatedEvidenceBatchV1 {
                cpu_id: 0,
                first_cursor: 2,
                last_cursor: 2,
                intake_utc_ns: 2,
                frame_ends: vec![frame.len()],
                framed_records: frame.into(),
            },
        )?;
        Ok(())
    }));
    let (stop, stopped) = watch::channel(false);
    let worker = tokio::spawn(owner.clone().run_clock(stopped, TestClock::new(11)));
    let next = profile_after(&owner, &second, |profile| {
        profile.snapshot.accepted_records == 1
    })
    .await?;
    assert_eq!(next.scope.identity, second);
    let first = profile_after(&owner, &fixture.source, |profile| {
        profile.snapshot.accepted_records == 2
    })
    .await?;
    assert_eq!(first.snapshot.coverage[0].last_cursor, 2);
    assert!(provider.hook.lock().map_err(|_| "context lock")?.is_none());
    stop.send_replace(true);
    tokio::time::timeout(Duration::from_secs(120), worker).await???;
    Ok(())
}

#[tokio::test]
async fn discovery_waits_for_capacity() -> TestResult {
    let fixture = DiscoveryFixture::new(Default::default())?;
    fixture.accept(1)?;
    let provider = NoticedContext::new();
    let mut owner = fixture.owner(Default::default())?;
    owner.provider = provider.clone();
    let owner = Arc::new(owner);
    let epoch = owner.execution.memory.capacity_epoch();
    owner.process(10)?;
    assert_eq!(owner.execution.memory.capacity_epoch(), epoch);
    let packages = owner.execution.testing_owner();
    let held = packages
        .query
        .memory()
        .reserve_input(packages.query.limits().input_capacity)?;
    let revision = fixture.store.meta()?.commit_revision;
    let clock = TestClock::new(10);
    let mut reads = provider.reads.subscribe();
    let (stop, stopped) = watch::channel(false);
    let worker = tokio::spawn(owner.clone().run_clock(stopped, clock.clone()));
    clock.idle(2).await?;
    let clock_reads = *clock.reads.borrow();
    tokio::time::sleep(Duration::from_millis(20)).await;
    assert_eq!(*clock.reads.borrow(), clock_reads);
    reads.borrow_and_update();
    drop(held);
    tokio::time::timeout(Duration::from_secs(120), reads.changed()).await??;
    stop.send_replace(true);
    tokio::time::timeout(Duration::from_secs(120), worker).await???;
    assert_eq!(fixture.store.meta()?.commit_revision, revision);
    assert_eq!(
        owner
            .profile(&fixture.source)?
            .ok_or("profile absent")?
            .snapshot
            .accepted_records,
        1
    );
    Ok(())
}

#[tokio::test]
async fn discovery_stop_joins_work() -> TestResult {
    let fixture = DiscoveryFixture::new(Default::default())?;
    fixture.accept(1)?;
    let provider = NoticedContext::new();
    let (entered, ready) = tokio::sync::oneshot::channel();
    let (release, released) = std::sync::mpsc::sync_channel(0);
    *provider.hook.lock().map_err(|_| "context lock")? = Some(Box::new(move || {
        entered.send(()).map_err(|_| {
            crate::DiscoveryInvalidSnafu {
                field: "entry signal",
            }
            .build()
        })?;
        released.recv().map_err(|_| {
            crate::DiscoveryInvalidSnafu {
                field: "release signal",
            }
            .build()
        })?;
        Ok(())
    }));
    let mut owner = fixture.owner(Default::default())?;
    owner.provider = provider;
    let owner = Arc::new(owner);
    let (stop, stopped) = watch::channel(false);
    let mut worker = tokio::spawn(owner.clone().run_clock(stopped, TestClock::new(10)));
    tokio::time::timeout(Duration::from_secs(120), ready).await??;
    stop.send_replace(true);
    tokio::select! {
        result = &mut worker => return Err(format!("worker did not join: {result:?}").into()),
        () = tokio::time::sleep(Duration::from_millis(20)) => {}
    }
    release.send(())?;
    tokio::time::timeout(Duration::from_secs(120), worker).await???;

    let (stop, stopped) = watch::channel(false);
    drop(stop);
    tokio::time::timeout(
        Duration::from_secs(1),
        owner.run_clock(stopped, TestClock::new(11)),
    )
    .await??;
    Ok(())
}

#[tokio::test]
async fn discovery_notice_pages() -> TestResult {
    let fixture = DiscoveryFixture::new(Default::default())?;
    let provider = NoticedContext::new();
    provider.facts.send_replace(1);
    let facts = provider.facts.clone();
    let owner = Arc::new(DiscoveryOwner::new(
        fixture.store.clone(),
        provider,
        DiscoveryConfigV1 {
            interval_records: 1,
            ..Default::default()
        },
        crate::InstalledAnalysis::testing(Some(fixture.store.clone()), fixture.source.tenant_id)?,
    )?);
    let mut profiles = Vec::new();
    for cursor in 1..=17 {
        fixture.accept(cursor)?;
        assert_eq!(owner.process(cursor + 10)?, 1);
        let profile = owner.profile(&fixture.source)?.ok_or("profile absent")?;
        assert!(profile.sealed);
        assert_eq!(profile.facts_revision, 1);
        assert_eq!(profile.snapshot.accepted_records, 1);
        assert_eq!(profile.snapshot.coverage[0].first_cursor, cursor);
        profiles.push(profile);
    }
    assert_eq!(
        profiles
            .iter()
            .map(|profile| &profile.profile_id)
            .collect::<BTreeSet<_>>()
            .len(),
        17
    );
    let head = profiles.last().cloned().ok_or("head absent")?;
    let coverage = fixture
        .store
        .source_receipt(&fixture.source)?
        .ok_or("receipt absent")?
        .coverage_revision;
    assert!(fixture
        .store
        .profile_notices(&head.scope, 1, coverage)?
        .is_empty());
    assert_eq!(
        fixture
            .store
            .profile_notices(&head.scope, 2, coverage)?
            .len(),
        16
    );

    let mut bundle = crate::AnalysisPackageOwner::required_bundles()
        .into_iter()
        .find(|bundle| bundle.root.package_id == DISCOVERY_PROCESSOR)
        .ok_or("discovery bundle")?;
    bundle.root.revision = "2".into();
    bundle.artifacts[0].descriptor.revision = "2".into();
    owner
        .execution
        .testing_owner()
        .execute(
            crate::PackageGrantV1 {
                principal: "fixture".into(),
                revision: 1,
                selection: crate::AnalysisSelectionV1::tenant(fixture.source.tenant_id),
                expires_utc_ns: None,
                authorization_id: None,
            },
            crate::PackageRequestV1::Update {
                scope_id: crate::AnalysisPackageOwner::DOMAIN_SCOPE.into(),
                bundle,
            },
            Arc::new(AnalysisReadControl::with_timeout(Duration::from_secs(30))?),
        )
        .await?;
    assert_ne!(
        owner.installed_refs(&head)?.ok_or("stored refs absent")?,
        DiscoveryOwner::analysis_refs(&owner.execution.snapshot(fixture.source.tenant_id)?)?
    );
    let changes = fixture.store.subscribe_revision();
    let revision = *changes.borrow();
    let clock = TestClock::new(1_000);
    let mut observed = clock.reads.subscribe();
    let (stop, stopped) = watch::channel(false);
    let run = owner.clone().run_clock(stopped, clock);
    tokio::pin!(run);
    // Each pass reads the clock at its start and before the idle wait.
    for idle in [2, 4] {
        tokio::time::timeout(Duration::from_secs(30), async {
            while *observed.borrow_and_update() < idle {
                tokio::select! {
                    result = &mut run => {
                        result?;
                        return Err("worker stopped before idle".into());
                    }
                    changed = observed.changed() => { changed?; }
                }
            }
            Ok::<(), Box<dyn std::error::Error>>(())
        })
        .await??;
        if idle == 2 {
            facts.send(2)?;
        }
    }
    stop.send(true)?;
    run.await?;

    assert!(fixture
        .store
        .profile_notices(&head.scope, 2, coverage)?
        .is_empty());
    assert_eq!(*changes.borrow(), revision);
    assert_eq!(owner.profile(&fixture.source)?, Some(head.clone()));
    assert_eq!(
        fixture
            .store
            .processor_health(&head.scope)?
            .ok_or("health absent")?
            .consumed_cursor,
        17
    );
    for profile in profiles {
        assert_eq!(
            fixture
                .store
                .read_result(fixture.source.tenant_id, &profile.profile_id)?,
            Some(serde_json::to_vec(&profile)?)
        );
    }
    Ok(())
}
