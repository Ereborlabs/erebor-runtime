use std::collections::BTreeSet;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{mpsc, Mutex};
use std::time::Duration;

use araphor_analysis_sdk as sdk;
use araphor_data::{ManagedInstance, PackageActionV1, PackageBundleRef, PackageGrantV1};

use super::*;
use crate::instance::tests::{bundle, Authority as FixtureAuthority, Fixture, TestResult};

struct Authority {
    inner: Arc<FixtureAuthority>,
    denied: Mutex<BTreeSet<String>>,
    changes: watch::Sender<u64>,
    admissions: AtomicUsize,
    gate: Mutex<Option<(mpsc::Sender<()>, mpsc::Receiver<()>)>>,
    delivery: Mutex<Option<(mpsc::Sender<()>, mpsc::Receiver<()>)>>,
}

impl Authority {
    fn new(fixture: &Fixture) -> Arc<Self> {
        Arc::new(Self {
            inner: Arc::clone(&fixture.authority),
            denied: Mutex::default(),
            changes: watch::channel(0).0,
            admissions: AtomicUsize::new(0),
            gate: Mutex::default(),
            delivery: Mutex::default(),
        })
    }

    fn deny(&self, principal: &str) {
        self.denied
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .insert(principal.into());
        self.changes.send_modify(|revision| *revision += 1);
    }
}

impl PackageAuthorization for Authority {
    fn check(&self, grant: &PackageGrantV1, action: PackageActionV1) -> araphor_data::Result<()> {
        self.inner.check(grant, action)?;
        if self
            .denied
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .contains(&grant.principal)
        {
            return Err(Code::Denied.error("host fixture principal"));
        }
        Ok(())
    }

    fn admit(
        &self,
        grant: &PackageGrantV1,
        image: &PackageBundleRef<'_>,
    ) -> araphor_data::Result<()> {
        let gate = self
            .gate
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .take();
        if let Some((entered, release)) = gate {
            entered
                .send(())
                .map_err(|_| Code::Incomplete.error("host admission entry"))?;
            release
                .recv_timeout(Duration::from_secs(30))
                .map_err(|_| Code::Incomplete.error("host admission release"))?;
        }
        self.admissions.fetch_add(1, Ordering::SeqCst);
        self.inner.admit(grant, image)
    }

    fn commit(
        &self,
        grant: &PackageGrantV1,
        action: PackageActionV1,
        image: &PackageBundleRef<'_>,
        operation: &mut dyn FnMut() -> araphor_data::Result<()>,
    ) -> araphor_data::Result<()> {
        self.commit_many(&[(grant, None), (grant, Some(image))], action, operation)
    }

    fn commit_many(
        &self,
        grants: &[(&PackageGrantV1, Option<&PackageBundleRef<'_>>)],
        action: PackageActionV1,
        operation: &mut dyn FnMut() -> araphor_data::Result<()>,
    ) -> araphor_data::Result<()> {
        let gate = self
            .delivery
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .take();
        if let Some((entered, release)) = gate {
            entered
                .send(())
                .map_err(|_| Code::Incomplete.error("host delivery entry"))?;
            release
                .recv_timeout(Duration::from_secs(30))
                .map_err(|_| Code::Incomplete.error("host delivery release"))?;
        }
        let denied = self
            .denied
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        for (grant, _) in grants {
            if denied.contains(&grant.principal) {
                return Err(Code::Denied.error("host fixture principal"));
            }
        }
        self.inner.commit_many(grants, action, operation)
    }

    fn changes(&self) -> watch::Receiver<u64> {
        self.changes.subscribe()
    }
}

impl Fixture {
    async fn host_progress(&self, id: &str, after: u64) -> TestResult<u64> {
        let mut changes = self.query.store().subscribe_revision();
        tokio::time::timeout(Duration::from_secs(30), async {
            loop {
                let progress = self.progress(id)?;
                if progress > after {
                    return Ok(progress);
                }
                changes.changed().await?;
            }
        })
        .await?
    }

    async fn host_stopped(&self, id: &str) -> TestResult<ManagedInstance> {
        let mut changes = self.query.store().subscribe_activations();
        tokio::time::timeout(Duration::from_secs(30), async {
            loop {
                let current = self
                    .query
                    .store()
                    .managed_instance([1; 16], id, &AnalysisReadControl::default())?
                    .ok_or("host instance absent")?;
                if !current.running {
                    return Ok(current);
                }
                changes.changed().await?;
            }
        })
        .await?
    }
}

#[tokio::test]
async fn host_drives_without_observer() -> TestResult {
    let fixture = Fixture::new(Default::default())?;
    fixture.context(1)?;
    let instance = fixture
        .admit(
            "unobserved",
            "SELECT CAST(COUNT(*) AS BIGINT UNSIGNED) AS value FROM context_versions",
        )
        .await?;
    fixture.start(&instance)?;
    let host = InstanceHost::new(Arc::clone(&fixture.query), fixture.authority.clone());
    let (stop, stopped) = watch::channel(false);
    let worker = tokio::spawn(host.serve(stopped, u64::MAX));
    let first = fixture.host_progress("unobserved", 0).await?;
    fixture.context(2)?;
    let second = fixture.host_progress("unobserved", first).await?;
    assert!(second > first);
    stop.send_replace(true);
    tokio::time::timeout(Duration::from_secs(30), worker).await???;
    drop(fixture.query.store().lease_managed()?);
    Ok(())
}

#[tokio::test]
async fn host_keeps_newer_member() -> TestResult {
    let fixture = Fixture::new(Default::default())?;
    let instance = fixture
        .admit("newer", "SELECT 7::BIGINT UNSIGNED AS value")
        .await?;
    let first = fixture.start(&instance)?;
    let older = fixture
        .query
        .store()
        .managed_instance([1; 16], "newer", &AnalysisReadControl::default())?
        .ok_or("older member absent")?;
    let stopped =
        fixture
            .query
            .store()
            .set_managed_running([1; 16], "newer", first, false, || Ok(()))?;
    let newer = fixture.query.store().set_managed_running(
        [1; 16],
        "newer",
        stopped.lifecycle,
        true,
        || Ok(()),
    )?;
    let host = InstanceHost::new(Arc::clone(&fixture.query), fixture.authority.clone());
    let members = FuturesUnordered::new();
    let current = ManagedMember {
        tenant: newer.spec.tenant,
        id: newer.spec.id.clone(),
        generation: newer.generation,
        lifecycle: newer.lifecycle,
    };
    let memory = host
        .query
        .memory()
        .reserve_input(std::mem::size_of::<ManagedMember>() + current.id.capacity())?;
    members.push(Member::new(Arc::clone(&host), current, memory, u64::MAX));
    host.reconcile(
        &members,
        older.lifecycle,
        Vec::new(),
        host.query.memory().reserve_input(0)?,
        u64::MAX,
    )?;
    let active = vec![ManagedMember {
        tenant: older.spec.tenant,
        id: older.spec.id.clone(),
        generation: older.generation,
        lifecycle: older.lifecycle,
    }];
    let memory = host.query.memory().reserve_input(0)?;
    host.reconcile(&members, newer.lifecycle, active, memory, u64::MAX)?;
    assert_eq!(members.len(), 1);
    for member in members.iter() {
        member.control.check()?;
    }
    let snapshot = fixture.query.store().meta()?.commit_revision;
    host.reconcile(
        &members,
        snapshot,
        Vec::new(),
        host.query.memory().reserve_input(0)?,
        u64::MAX,
    )?;
    assert!(members.iter().all(|member| member.control.check().is_err()));
    Ok(())
}

#[tokio::test]
async fn host_idle_denial_suspends() -> TestResult {
    let fixture = Fixture::new(Default::default())?;
    fixture.context(1)?;
    let instance = fixture
        .admit(
            "denied-idle",
            "SELECT CAST(COUNT(*) AS BIGINT UNSIGNED) AS value FROM context_versions",
        )
        .await?;
    fixture.start(&instance)?;
    let authority = Authority::new(&fixture);
    let host = InstanceHost::new(Arc::clone(&fixture.query), authority.clone());
    let (stop, stopped) = watch::channel(false);
    let worker = tokio::spawn(host.serve(stopped, u64::MAX));
    let progress = fixture.host_progress("denied-idle", 0).await?;
    authority.deny(&instance.admitted.spec.grant.principal);
    let suspended = fixture.host_stopped("denied-idle").await?;
    assert_eq!(suspended.progress, progress);
    assert_eq!(suspended.generation, instance.admitted.generation);
    assert_eq!(suspended.spec, instance.admitted.spec);
    stop.send_replace(true);
    tokio::time::timeout(Duration::from_secs(30), worker).await???;
    Ok(())
}

#[tokio::test]
async fn host_isolates_failure() -> TestResult {
    let fixture = Fixture::new(Default::default())?;
    fixture.context(1)?;
    let failed = fixture.admit("a-failed", "SELECT CAST(CASE WHEN COUNT(*) = 0 THEN '0' ELSE 'wrong' END AS BIGINT UNSIGNED) AS value FROM context_versions").await?;
    let healthy = fixture
        .admit(
            "z-healthy",
            "SELECT CAST(COUNT(*) AS BIGINT UNSIGNED) AS value FROM context_versions",
        )
        .await?;
    fixture.start(&failed)?;
    fixture.start(&healthy)?;
    let host = InstanceHost::new(Arc::clone(&fixture.query), fixture.authority.clone());
    let (stop, stopped) = watch::channel(false);
    let worker = tokio::spawn(host.serve(stopped, u64::MAX));
    let first = fixture.host_progress("z-healthy", 0).await?;
    let mut changes = fixture.query.store().subscribe_revision();
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            if let Ok(resume) = fixture.query.store().managed_resume(
                [1; 16],
                "a-failed",
                &AnalysisReadControl::default(),
            ) {
                if resume.completed > 0 && resume.frontier.is_some() {
                    break;
                }
            }
            changes.changed().await?;
        }
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
    })
    .await??;
    assert_eq!(fixture.progress("a-failed")?, 0);
    fixture.context(2)?;
    fixture.host_progress("z-healthy", first).await?;
    assert_eq!(fixture.progress("a-failed")?, 0);
    stop.send_replace(true);
    tokio::time::timeout(Duration::from_secs(30), worker).await???;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn host_stop_joins_admission() -> TestResult {
    let fixture = Fixture::new(Default::default())?;
    fixture.install(&bundle("sql")?)?;
    fixture.context(1)?;
    let instance = fixture.admit("opening", r#"SELECT * FROM "runtime-fixture"."1".accumulate(input => (SELECT CAST(COUNT(*) AS BIGINT UNSIGNED) AS value FROM context_versions))"#).await?;
    fixture.start(&instance)?;
    let healthy = fixture
        .admit(
            "admission-healthy",
            "SELECT CAST(COUNT(*) AS BIGINT UNSIGNED) AS value FROM context_versions",
        )
        .await?;
    fixture.start(&healthy)?;
    let authority = Authority::new(&fixture);
    let (entry, observed) = mpsc::channel();
    let (release, waiting) = mpsc::channel();
    *authority
        .gate
        .lock()
        .unwrap_or_else(|error| error.into_inner()) = Some((entry, waiting));
    let host = InstanceHost::new(Arc::clone(&fixture.query), authority);
    let (stop, stopped) = watch::channel(false);
    let worker = tokio::spawn(host.serve(stopped, u64::MAX));
    let entered =
        tokio::task::spawn_blocking(move || observed.recv_timeout(Duration::from_secs(30))).await?;
    if let Err(error) = entered {
        let _released = release.send(());
        stop.send_replace(true);
        let _joined = worker.await;
        return Err(format!("admission did not enter: {error}").into());
    }
    let healthy_progress = async {
        let first = fixture.host_progress("admission-healthy", 0).await?;
        fixture.context(2)?;
        fixture.host_progress("admission-healthy", first).await
    }
    .await;
    if let Err(error) = healthy_progress {
        let _released = release.send(());
        stop.send_replace(true);
        let _joined = worker.await;
        return Err(error);
    }
    stop.send_replace(true);
    assert!(!worker.is_finished());
    assert!(fixture.query.store().lease_managed().is_err());
    release.send(())?;
    tokio::time::timeout(Duration::from_secs(30), worker).await???;
    assert_eq!(fixture.progress("opening")?, 0);
    drop(fixture.query.store().lease_managed()?);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn host_stop_joins_guest() -> TestResult {
    let fixture = Fixture::new(araphor_query::execution::Limits {
        global_evaluations: Some(1),
        tenant_evaluations: Some(1),
        ..Default::default()
    })?;
    let instance = fixture.terminal_instance("guest-stop", "cancel").await?;
    fixture.start(&instance)?;
    let (entry, observed) = mpsc::channel();
    let (release, waiting) = mpsc::channel();
    fixture.query.guest_entry(entry, Some(waiting))?;
    let host = InstanceHost::new(Arc::clone(&fixture.query), fixture.authority.clone());
    let (stop, stopped) = watch::channel(false);
    let worker = tokio::spawn(host.serve(stopped, u64::MAX));
    let entered =
        tokio::task::spawn_blocking(move || observed.recv_timeout(Duration::from_secs(30))).await?;
    if let Err(error) = entered {
        let _released = release.send(());
        stop.send_replace(true);
        let _joined = worker.await;
        return Err(format!("guest did not enter: {error}").into());
    }
    stop.send_replace(true);
    assert!(!worker.is_finished());
    assert!(fixture.query.reserve_evaluation([1; 16]).is_err());
    assert!(fixture.query.store().lease_managed().is_err());
    release.send(())?;
    tokio::time::timeout(Duration::from_secs(30), worker).await???;
    assert_eq!(fixture.progress("guest-stop")?, 0);
    let resume = fixture.query.store().managed_resume(
        [1; 16],
        "guest-stop",
        &AnalysisReadControl::default(),
    )?;
    assert!(resume.instance.running);
    assert!(resume.completed > 0);
    assert_eq!(resume.frontier, None);
    drop(fixture.query.reserve_evaluation([1; 16])?);
    drop(fixture.query.store().lease_managed()?);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn host_drop_retains_lease() -> TestResult {
    let fixture = Fixture::new(araphor_query::execution::Limits {
        global_evaluations: Some(1),
        tenant_evaluations: Some(1),
        ..Default::default()
    })?;
    let instance = fixture.terminal_instance("guest-drop", "cancel").await?;
    fixture.start(&instance)?;
    let (entry, observed) = mpsc::channel();
    let (release, waiting) = mpsc::channel();
    fixture.query.guest_entry(entry, Some(waiting))?;
    let host = InstanceHost::new(Arc::clone(&fixture.query), fixture.authority.clone());
    let (stop, stopped) = watch::channel(false);
    let worker = tokio::spawn(host.serve(stopped, u64::MAX));
    let entered =
        tokio::task::spawn_blocking(move || observed.recv_timeout(Duration::from_secs(30))).await?;
    if let Err(error) = entered {
        let _released = release.send(());
        stop.send_replace(true);
        let _joined = worker.await;
        return Err(format!("guest did not enter: {error}").into());
    }
    worker.abort();
    assert!(worker.await.is_err());
    assert!(fixture.query.reserve_evaluation([1; 16]).is_err());
    assert!(fixture.query.store().lease_managed().is_err());
    release.send(())?;
    tokio::time::timeout(Duration::from_secs(30), stop.closed()).await?;
    drop(fixture.query.reserve_evaluation([1; 16])?);
    drop(fixture.query.store().lease_managed()?);
    let resume = fixture.query.store().managed_resume(
        [1; 16],
        "guest-drop",
        &AnalysisReadControl::default(),
    )?;
    assert!(resume.completed > 0);
    assert_eq!(resume.instance.progress, 0);
    Ok(())
}

#[tokio::test]
async fn host_metadata_error_drains() -> TestResult {
    let fixture = Fixture::new(Default::default())?;
    let instance = fixture
        .admit("broken", "SELECT 7::BIGINT UNSIGNED AS value")
        .await?;
    fixture.start(&instance)?;
    fixture
        .query
        .store()
        .fault_write("UPDATE managed_instances SET generation = 0", &[])?;
    let host = InstanceHost::new(Arc::clone(&fixture.query), fixture.authority.clone());
    let (_stop, stopped) = watch::channel(false);
    let result =
        tokio::time::timeout(Duration::from_secs(30), host.serve(stopped, u64::MAX)).await?;
    assert!(result.is_err());
    drop(fixture.query.store().lease_managed()?);
    Ok(())
}

#[tokio::test]
async fn host_replaces_one_lifecycle() -> TestResult {
    let fixture = Fixture::new(Default::default())?;
    fixture.install(&bundle("sql")?)?;
    fixture.context(1)?;
    let sql = r#"SELECT * FROM "runtime-fixture"."1".accumulate(input => (SELECT CAST(COUNT(*) AS BIGINT UNSIGNED) AS value FROM context_versions))"#;
    let first = fixture.admit("first-member", sql).await?;
    let healthy = fixture.admit("healthy-member", sql).await?;
    let lifecycle = fixture.start(&first)?;
    fixture.start(&healthy)?;
    let authority = Authority::new(&fixture);
    let host = InstanceHost::new(Arc::clone(&fixture.query), authority.clone());
    let (stop, stopped) = watch::channel(false);
    let worker = tokio::spawn(host.serve(stopped, u64::MAX));
    let first_progress = fixture.host_progress("first-member", 0).await?;
    let healthy_progress = fixture.host_progress("healthy-member", 0).await?;
    assert_eq!(authority.admissions.load(Ordering::SeqCst), 2);
    let stopped_member = fixture.query.store().set_managed_running(
        [1; 16],
        "first-member",
        lifecycle,
        false,
        || Ok(()),
    )?;
    let restarted = fixture.query.store().set_managed_running(
        [1; 16],
        "first-member",
        stopped_member.lifecycle,
        true,
        || Ok(()),
    )?;
    fixture.context(2)?;
    fixture
        .host_progress("first-member", first_progress)
        .await?;
    fixture
        .host_progress("healthy-member", healthy_progress)
        .await?;
    let current = fixture
        .query
        .store()
        .managed_instance([1; 16], "first-member", &AnalysisReadControl::default())?
        .ok_or("restarted member absent")?;
    assert_eq!(current.lifecycle, restarted.lifecycle);
    assert_eq!(authority.admissions.load(Ordering::SeqCst), 3);
    stop.send_replace(true);
    tokio::time::timeout(Duration::from_secs(30), worker).await???;
    Ok(())
}

#[tokio::test]
async fn host_preserves_pending() -> TestResult {
    let fixture = Fixture::new(Default::default())?;
    fixture.context(1)?;
    let pending = fixture
        .admit(
            "pending-member",
            "SELECT CAST(COUNT(*) AS BIGINT UNSIGNED) AS value FROM context_versions",
        )
        .await?;
    let entered = Arc::new(AtomicBool::new(false));
    let published = Arc::clone(&entered);
    fixture.query.store().set_commit_hook(
        araphor_data::AnalysisCommitStage::BeforeResultCommit,
        move || {
            published.store(true, Ordering::SeqCst);
            Err(Code::Incomplete.error("pending publication fixture"))
        },
    )?;
    let request = araphor_data::ManagedRequest {
        id: "original-pending".into(),
        time_utc_ns: 10,
        seed: None,
        rebuild: false,
        witness_expiry: u64::MAX,
        frontier: None,
    };
    assert!(pending
        .run(request.clone(), &AnalysisReadControl::default())
        .await
        .is_err());
    assert!(entered.load(Ordering::SeqCst));
    let previous = fixture
        .query
        .store()
        .managed_attempt(
            [1; 16],
            "pending-member",
            &request.id,
            &AnalysisReadControl::default(),
        )?
        .ok_or("original pending claim absent")?;
    assert!(previous.receipt().is_none());
    assert!(previous.terminal().is_none());
    fixture.start(&pending)?;
    let healthy = fixture
        .admit(
            "healthy-member",
            "SELECT CAST(COUNT(*) AS BIGINT UNSIGNED) AS value FROM context_versions",
        )
        .await?;
    fixture.start(&healthy)?;
    let host = InstanceHost::new(Arc::clone(&fixture.query), fixture.authority.clone());
    let (stop, stopped) = watch::channel(false);
    let worker = tokio::spawn(host.serve(stopped, u64::MAX));
    let first = fixture.host_progress("healthy-member", 0).await?;
    fixture.context(2)?;
    fixture.host_progress("healthy-member", first).await?;
    stop.send_replace(true);
    tokio::time::timeout(Duration::from_secs(30), worker).await???;
    let retained = fixture
        .query
        .store()
        .managed_attempt(
            [1; 16],
            "pending-member",
            &request.id,
            &AnalysisReadControl::default(),
        )?
        .ok_or("pending claim lost")?;
    assert_eq!(retained.request(), &request);
    assert!(retained.receipt().is_none());
    assert!(retained.terminal().is_none());
    assert_eq!(fixture.progress("pending-member")?, 0);
    Ok(())
}

#[tokio::test]
async fn host_expiry_keeps_healthy() -> TestResult {
    let fixture = Fixture::new(Default::default())?;
    fixture.context(1)?;
    let healthy = fixture
        .admit(
            "healthy-member",
            "SELECT CAST(COUNT(*) AS BIGINT UNSIGNED) AS value FROM context_versions",
        )
        .await?;
    let mut expired = healthy.admitted.spec.clone();
    expired.id = "expired-member".into();
    expired.grant.expires_utc_ns = Some(1);
    let expired = fixture.query.store().admit_managed(&expired, || Ok(()))?;
    fixture.query.store().set_managed_running(
        [1; 16],
        &expired.spec.id,
        expired.lifecycle,
        true,
        || Ok(()),
    )?;
    fixture.start(&healthy)?;
    let host = InstanceHost::new(Arc::clone(&fixture.query), fixture.authority.clone());
    let (stop, stopped) = watch::channel(false);
    let worker = tokio::spawn(host.serve(stopped, u64::MAX));
    let suspended = fixture.host_stopped("expired-member").await?;
    assert_eq!(suspended.generation, expired.generation);
    assert_eq!(suspended.spec, expired.spec);
    assert_eq!(suspended.progress, 0);
    let first = fixture.host_progress("healthy-member", 0).await?;
    fixture.context(2)?;
    fixture.host_progress("healthy-member", first).await?;
    stop.send_replace(true);
    tokio::time::timeout(Duration::from_secs(30), worker).await???;
    Ok(())
}

#[tokio::test]
async fn host_keeps_benign_notice() -> TestResult {
    let fixture = Fixture::new(Default::default())?;
    fixture.context(1)?;
    let instance = fixture
        .admit(
            "benign-idle",
            "SELECT CAST(COUNT(*) AS BIGINT UNSIGNED) AS value FROM context_versions",
        )
        .await?;
    let lifecycle = fixture.start(&instance)?;
    let host = InstanceHost::new(Arc::clone(&fixture.query), fixture.authority.clone());
    let (stop, stopped) = watch::channel(false);
    let worker = tokio::spawn(host.serve(stopped, u64::MAX));
    let first = fixture.host_progress("benign-idle", 0).await?;
    fixture.authority.set(true);
    fixture.context(2)?;
    fixture.host_progress("benign-idle", first).await?;
    let current = fixture
        .query
        .store()
        .managed_instance([1; 16], "benign-idle", &AnalysisReadControl::default())?
        .ok_or("benign member absent")?;
    assert!(current.running);
    assert_eq!(current.lifecycle, lifecycle);
    assert_eq!(current.generation, instance.admitted.generation);
    stop.send_replace(true);
    tokio::time::timeout(Duration::from_secs(30), worker).await???;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn host_guest_keeps_healthy() -> TestResult {
    let fixture = Fixture::new(araphor_query::execution::Limits {
        global_evaluations: Some(2),
        tenant_evaluations: Some(2),
        ..Default::default()
    })?;
    let instance = fixture.terminal_instance("guest-stop", "cancel").await?;
    fixture.start(&instance)?;
    let healthy = fixture
        .admit(
            "guest-healthy",
            "SELECT CAST(COUNT(*) AS BIGINT UNSIGNED) AS value FROM context_versions",
        )
        .await?;
    fixture.start(&healthy)?;
    let (entry, observed) = mpsc::channel();
    let (release, waiting) = mpsc::channel();
    fixture.query.guest_entry(entry, Some(waiting))?;
    let host = InstanceHost::new(Arc::clone(&fixture.query), fixture.authority.clone());
    let (stop, stopped) = watch::channel(false);
    let worker = tokio::spawn(host.serve(stopped, u64::MAX));
    let entered =
        tokio::task::spawn_blocking(move || observed.recv_timeout(Duration::from_secs(30))).await?;
    if let Err(error) = entered {
        let _released = release.send(());
        stop.send_replace(true);
        let _joined = worker.await;
        return Err(format!("guest did not enter: {error}").into());
    }
    let healthy_progress = async {
        let first = fixture.host_progress("guest-healthy", 0).await?;
        fixture.context(2)?;
        fixture.host_progress("guest-healthy", first).await
    }
    .await;
    if let Err(error) = healthy_progress {
        let _released = release.send(());
        stop.send_replace(true);
        let _joined = worker.await;
        return Err(error);
    }
    stop.send_replace(true);
    assert!(!worker.is_finished());
    assert!(fixture.query.store().lease_managed().is_err());
    release.send(())?;
    tokio::time::timeout(Duration::from_secs(30), worker).await???;
    assert_eq!(fixture.progress("guest-stop")?, 0);
    let resume = fixture.query.store().managed_resume(
        [1; 16],
        "guest-stop",
        &AnalysisReadControl::default(),
    )?;
    assert!(resume.instance.running);
    assert!(resume.completed > 0);
    assert_eq!(resume.frontier, None);
    let first = fixture.query.reserve_evaluation([1; 16])?;
    let second = fixture.query.reserve_evaluation([1; 16])?;
    drop((first, second));
    drop(fixture.query.store().lease_managed()?);
    Ok(())
}

#[tokio::test]
async fn host_source_denial_suspends() -> TestResult {
    use araphor_data::{
        TraceBatchV1, TraceBindingV1, TraceFrameKindV1, TraceFrameV1, TraceIdentityV1,
        TraceIntentV1, TraceSourceV1,
    };

    let mut fixture = Fixture::new(Default::default())?;
    fixture.context(1)?;
    let source = TraceSourceV1::new(b"BEGIN { @x = count(); }".to_vec())?;
    let identity = TraceIdentityV1 {
        tenant_id: [1; 16],
        node_id: "host-source".into(),
        node_boot_id: [2; 16],
        request_id: [5; 16],
        execution_id: [9; 16],
        source_sha256: source.sha256,
    };
    let state = fixture.query.store().accept_trace(&TraceIntentV1 {
        tenant_id: identity.tenant_id,
        request_id: identity.request_id,
        source,
        bindings: vec![TraceBindingV1 {
            identity: identity.clone(),
            binding_id: [6; 16],
            namespace_uid: "host-namespace".into(),
        }],
        authority: b"accepted".to_vec(),
        accepted_unix_ns: 100,
        deadline_unix_ns: 10_000,
        host_sensitive: false,
    })?;
    fixture.query.store().append_trace(
        &identity,
        &TraceBatchV1 {
            execution_id: identity.execution_id,
            frames: vec![TraceFrameV1 {
                execution_id: identity.execution_id,
                sequence: 1,
                kind: TraceFrameKindV1::Data,
                bytes: b"trace-input".to_vec(),
            }],
            terminal: None,
        },
        200,
    )?;
    fixture.grant.selection.traces = araphor_data::Selection::Exact(vec![identity.clone()]);
    let denied = fixture
        .admit(
            "source-denied",
            "SELECT CAST(COUNT(*) AS BIGINT UNSIGNED) AS value FROM trace_output",
        )
        .await?;
    fixture.grant.selection.traces = araphor_data::Selection::Exact(Vec::new());
    let healthy = fixture
        .admit(
            "source-healthy",
            "SELECT CAST(COUNT(*) AS BIGINT UNSIGNED) AS value FROM context_versions",
        )
        .await?;
    fixture.start(&denied)?;
    fixture.start(&healthy)?;
    let host = InstanceHost::new(Arc::clone(&fixture.query), fixture.authority.clone());
    let (stop, stopped) = watch::channel(false);
    let worker = tokio::spawn(host.serve(stopped, u64::MAX));
    let progress = fixture.host_progress("source-denied", 0).await?;
    let healthy_progress = fixture.host_progress("source-healthy", 0).await?;
    let prior = fixture.query.store().managed_resume(
        [1; 16],
        "source-denied",
        &AnalysisReadControl::default(),
    )?;
    fixture
        .authority
        .check(&denied.admitted.spec.grant, PackageActionV1::Run)?;
    fixture
        .query
        .store()
        .update_trace(&araphor_data::TraceStateV1 {
            cancel_requested: true,
            read_revoked: true,
            ..state
        })?;
    let suspended = fixture.host_stopped("source-denied").await?;
    fixture
        .authority
        .check(&denied.admitted.spec.grant, PackageActionV1::Run)?;
    assert_eq!(suspended.progress, progress);
    assert_eq!(suspended.generation, denied.admitted.generation);
    fixture.context(2)?;
    let healthy_progress = fixture
        .host_progress("source-healthy", healthy_progress)
        .await?;
    fixture.context(3)?;
    fixture
        .host_progress("source-healthy", healthy_progress)
        .await?;
    let after = fixture.query.store().managed_resume(
        [1; 16],
        "source-denied",
        &AnalysisReadControl::default(),
    )?;
    assert_eq!(after.instance, suspended);
    assert_eq!(after.completed, prior.completed);
    assert_eq!(after.frontier, prior.frontier);
    stop.send_replace(true);
    tokio::time::timeout(Duration::from_secs(30), worker).await???;
    drop(fixture.query.store().lease_managed()?);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn host_crossing_expiry_joins_admission() -> TestResult {
    let mut fixture = Fixture::new(araphor_query::execution::Limits {
        global_evaluations: Some(2),
        tenant_evaluations: Some(2),
        ..Default::default()
    })?;
    fixture.install(&bundle("sql")?)?;
    fixture.context(1)?;
    let healthy = fixture
        .admit(
            "expiry-healthy",
            "SELECT CAST(COUNT(*) AS BIGINT UNSIGNED) AS value FROM context_versions",
        )
        .await?;
    let now = u64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos(),
    )?;
    fixture.grant.expires_utc_ns = Some(now.checked_add(5_000_000_000).ok_or("grant expiry")?);
    let expiring = fixture.admit("crossing-expiry", r#"SELECT * FROM "runtime-fixture"."1".accumulate(input => (SELECT CAST(COUNT(*) AS BIGINT UNSIGNED) AS value FROM context_versions))"#).await?;
    fixture.grant.expires_utc_ns = None;
    let lifecycle = fixture.start(&expiring)?;
    let mut initial = expiring.subscribe(
        Arc::new(AnalysisReadControl::default()),
        u64::MAX,
        lifecycle,
    )?;
    let receipt = tokio::time::timeout(Duration::from_secs(30), initial.next())
        .await?
        .ok_or("initial native stream ended")??;
    assert!(initial
        .cancel_and_join(&AnalysisReadControl::default())
        .await?
        .is_none());
    assert_eq!(receipt.results.len(), 1);
    let result = &receipt
        .results
        .values()
        .next()
        .ok_or("initial call result")?
        .result_id;
    let retained = Instance::read_result(
        Arc::clone(&fixture.query),
        fixture.authority.clone(),
        fixture.grant.clone(),
        "crossing-expiry",
        result,
        &AnalysisReadControl::default(),
    )
    .await?;
    let checkpoint = retained
        .output
        .checkpoint
        .as_ref()
        .ok_or("initial checkpoint")?;
    assert_eq!(checkpoint.datasets.len(), 1);
    assert_eq!(
        checkpoint.datasets[0]
            .batches
            .iter()
            .map(|batch| batch.num_rows())
            .sum::<usize>(),
        1
    );
    fixture.start(&healthy)?;
    let before = fixture.query.store().managed_resume(
        [1; 16],
        "crossing-expiry",
        &AnalysisReadControl::default(),
    )?;
    assert_eq!(before.instance.progress, receipt.commit_revision);
    let deadline = AnalysisReadControl::with_timeout(
        expiring
            .admitted
            .spec
            .grant
            .remaining()?
            .ok_or("finite grant deadline")?,
    )?;
    let authority = Authority::new(&fixture);
    let (entry, observed) = mpsc::channel();
    let (release, waiting) = mpsc::channel();
    *authority
        .gate
        .lock()
        .unwrap_or_else(|error| error.into_inner()) = Some((entry, waiting));
    let host = InstanceHost::new(Arc::clone(&fixture.query), authority);
    let (stop, stopped) = watch::channel(false);
    let worker = tokio::spawn(host.serve(stopped, u64::MAX));
    let entered =
        tokio::task::spawn_blocking(move || observed.recv_timeout(Duration::from_secs(30))).await?;
    if let Err(error) = entered {
        let _released = release.send(());
        stop.send_replace(true);
        let _joined = worker.await;
        return Err(format!("expiring admission did not enter: {error}").into());
    }
    let healthy_progress = fixture.host_progress("expiry-healthy", 0).await;
    if let Err(error) = healthy_progress {
        let _released = release.send(());
        stop.send_replace(true);
        let _joined = worker.await;
        return Err(error);
    }
    deadline.expired().await;
    assert!(matches!(
        expiring.admitted.spec.grant.remaining(),
        Err(araphor_data::Error::Package {
            code: Code::Denied,
            field: "package grant",
            ..
        })
    ));
    assert!(!worker.is_finished());
    assert!(fixture.query.store().lease_managed().is_err());
    let held = fixture
        .query
        .store()
        .managed_instance([1; 16], "crossing-expiry", &AnalysisReadControl::default())?
        .ok_or("held instance")?;
    assert!(held.running);
    assert_eq!(held.progress, before.instance.progress);
    release.send(())?;
    let suspended = fixture.host_stopped("crossing-expiry").await?;
    assert_eq!(suspended.spec, before.instance.spec);
    assert_eq!(suspended.generation, before.instance.generation);
    assert_eq!(suspended.progress, before.instance.progress);
    let after = fixture.query.store().managed_resume(
        [1; 16],
        "crossing-expiry",
        &AnalysisReadControl::default(),
    )?;
    assert_eq!(after.completed, before.completed);
    assert_eq!(after.frontier, before.frontier);
    let historical = Instance::read_result(
        Arc::clone(&fixture.query),
        fixture.authority.clone(),
        fixture.grant.clone(),
        "crossing-expiry",
        result,
        &AnalysisReadControl::default(),
    )
    .await?;
    assert_eq!(historical.commit_revision, retained.commit_revision);
    assert_eq!(
        historical.output.datasets[0].batches,
        retained.output.datasets[0].batches
    );
    let historical = historical
        .output
        .checkpoint
        .as_ref()
        .ok_or("retained checkpoint")?;
    assert_eq!(historical.version, checkpoint.version);
    assert_eq!(
        historical.datasets[0].batches,
        checkpoint.datasets[0].batches
    );
    let healthy_progress = healthy_progress?;
    fixture.context(2)?;
    fixture
        .host_progress("expiry-healthy", healthy_progress)
        .await?;
    stop.send_replace(true);
    tokio::time::timeout(Duration::from_secs(30), worker).await???;
    let first = fixture.query.reserve_evaluation([1; 16])?;
    let second = fixture.query.reserve_evaluation([1; 16])?;
    drop((first, second));
    drop(fixture.query.store().lease_managed()?);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn host_delivery_keeps_healthy() -> TestResult {
    for close in ["stop", "drop"] {
        const INPUT: usize = 2 * 1024 * 1024;
        let fixture = Fixture::new(araphor_query::execution::Limits {
            input_capacity: Some(INPUT),
            global_evaluations: Some(2),
            tenant_evaluations: Some(2),
            ..Default::default()
        })?;
        fixture.install(&bundle("sql")?)?;
        fixture.context(1)?;
        let held = fixture.admit("held-delivery", r#"SELECT * FROM "runtime-fixture"."1".accumulate(input => (SELECT CAST(COUNT(*) AS BIGINT UNSIGNED) AS value FROM context_versions))"#).await?;
        fixture.start(&held)?;
        drop(held);
        let baseline = fixture.query.memory().input_reserved();
        assert_eq!(baseline, 0);
        let authority = Authority::new(&fixture);
        let (entry, observed) = mpsc::channel();
        let (release, waiting) = mpsc::channel();
        let delivery = Arc::clone(&authority);
        fixture.query.store().set_commit_hook(
            araphor_data::AnalysisCommitStage::BeforeResultCommit,
            move || {
                *delivery
                    .delivery
                    .lock()
                    .unwrap_or_else(|error| error.into_inner()) = Some((entry, waiting));
                Ok(())
            },
        )?;
        let host = InstanceHost::new(Arc::clone(&fixture.query), authority);
        let (stop, stopped) = watch::channel(false);
        let mut worker = tokio::spawn(host.serve(stopped, u64::MAX));
        let entered =
            tokio::task::spawn_blocking(move || observed.recv_timeout(Duration::from_secs(30)))
                .await?;
        if let Err(error) = entered {
            let _released = release.send(());
            stop.send_replace(true);
            let _joined = worker.await;
            return Err(format!("final delivery did not enter: {error}").into());
        }
        let committed = fixture.progress("held-delivery")?;
        assert!(committed > 0);
        let healthy = async {
            let healthy = fixture
                .admit(
                    "delivery-healthy",
                    "SELECT CAST(COUNT(*) AS BIGINT UNSIGNED) AS value FROM context_versions",
                )
                .await?;
            fixture.start(&healthy)?;
            drop(healthy);
            let first = fixture.host_progress("delivery-healthy", 0).await?;
            fixture.context(2)?;
            fixture.host_progress("delivery-healthy", first).await
        }
        .await;
        if let Err(error) = healthy {
            let _released = release.send(());
            stop.send_replace(true);
            let _joined = worker.await;
            return Err(error);
        }
        if close == "drop" {
            worker.abort();
            assert!((&mut worker)
                .await
                .err()
                .ok_or("serve caller was not aborted")?
                .is_cancelled());
        } else {
            stop.send_replace(true);
            assert!(!worker.is_finished());
        }
        assert!(fixture.query.store().lease_managed().is_err());
        assert!(fixture.query.memory().input_reserved() > baseline);
        release.send(())?;
        if close == "drop" {
            tokio::time::timeout(Duration::from_secs(30), stop.closed()).await?;
        } else {
            tokio::time::timeout(Duration::from_secs(30), worker).await???;
        }
        assert_eq!(fixture.progress("held-delivery")?, committed);
        assert_eq!(fixture.query.memory().input_reserved(), baseline);
        drop(fixture.query.memory().reserve_input(INPUT)?);
        let first = fixture.query.reserve_evaluation([1; 16])?;
        let second = fixture.query.reserve_evaluation([1; 16])?;
        drop((first, second));
        drop(fixture.query.store().lease_managed()?);
    }
    Ok(())
}

#[tokio::test]
async fn membership_keys_keep_capacity() -> TestResult {
    let capacity = 64 * 1024;
    let fixture = Fixture::new(araphor_query::execution::Limits {
        input_capacity: Some(capacity),
        ..Default::default()
    })?;
    let instance = fixture
        .admit(
            "projected-member",
            "SELECT CAST(7 AS BIGINT UNSIGNED) AS value",
        )
        .await?;
    let lifecycle = fixture.start(&instance)?;
    let expected = ManagedMember {
        tenant: instance.admitted().spec.tenant,
        id: instance.admitted().spec.id.clone(),
        generation: instance.admitted().generation,
        lifecycle: instance.admitted().lifecycle,
    };
    drop(instance);
    assert_eq!(fixture.query.memory().input_reserved(), 0);
    let host = InstanceHost::new(Arc::clone(&fixture.query), fixture.authority.clone());
    let before = fixture.query.store().meta()?;
    let (revision, active) = host
        .membership(Arc::new(AnalysisReadControl::default()))
        .await?;
    assert_eq!(revision, before.commit_revision);
    assert_eq!(active.len(), 1);
    assert_eq!(active[0].tenant, expected.tenant);
    assert_eq!(active[0].id, expected.id);
    assert_eq!(active[0].generation, expected.generation);
    assert_eq!(active[0].lifecycle, lifecycle);
    let bytes = active.capacity() * std::mem::size_of::<ManagedMember>()
        + active
            .iter()
            .map(|member| member.id.capacity())
            .sum::<usize>();
    assert_eq!(fixture.query.memory().input_reserved(), 0);
    let memory = fixture.query.memory().reserve_input(0)?;
    assert!(bytes >= std::mem::size_of::<ManagedMember>() + active[0].id.capacity());
    let retained = std::mem::size_of::<ManagedMember>() + active[0].id.capacity();
    let members = FuturesUnordered::new();
    host.reconcile(&members, revision, active, memory, u64::MAX)?;
    assert_eq!(members.len(), 1);
    assert_eq!(fixture.query.memory().input_reserved(), retained);
    let key = Arc::clone(&members.iter().next().ok_or("projected member")?.key);
    drop(members);
    assert_eq!(fixture.query.memory().input_reserved(), retained);
    assert!(fixture.query.memory().reserve_input(capacity).is_err());
    assert_eq!(fixture.query.store().meta()?, before);
    drop(key);
    assert_eq!(fixture.query.memory().input_reserved(), 0);
    drop(fixture.query.memory().reserve_input(capacity)?);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn replacement_releases_before_admission() -> TestResult {
    use futures_util::FutureExt as _;

    let capacity = 128 * 1024 * 1024;
    let fixture = Fixture::new(araphor_query::execution::Limits {
        input_capacity: Some(capacity),
        output_capacity: Some(32 * 1024 * 1024),
        global_evaluations: Some(2),
        tenant_evaluations: Some(2),
        ..Default::default()
    })?;
    let mut image = bundle("wasm")?;
    let model = &mut image.artifacts[0].descriptor.exports[0];
    model.name = "evaluate".into();
    model.inputs.clear();
    model.checkpoint = None;
    model.parameters = sdk::Schema::new(vec![
        sdk::Field::new("mode", sdk::DataType::Utf8, false),
        sdk::Field::new("amount", sdk::DataType::UInt64, false),
    ]);
    let araphor_package::PackageImplementationV1::Wasm { exports, .. } =
        &mut image.artifacts[0].implementations[0]
    else {
        return Err("replacement Wasm fixture".into());
    };
    *exports = vec!["evaluate".into()];
    let image_bytes = image.allocated_bytes()?;
    fixture.install(&image)?;
    fixture.context(1)?;
    drop(image);
    let instance = fixture.admit("tight-worker", r#"SELECT * FROM "runtime-fixture"."1".evaluate(mode => (SELECT CASE WHEN COUNT(*) = 1 THEN 'cancel' ELSE 'clock' END FROM context_versions), amount => 0)"#).await?;
    let lifecycle = fixture.start(&instance)?;
    let generation = instance.admitted.generation;
    drop(instance);
    let authority = Authority::new(&fixture);
    let host = InstanceHost::new(Arc::clone(&fixture.query), authority.clone());
    let (entered, observed) = mpsc::channel();
    let (release, released) = mpsc::channel();
    fixture.query.guest_entry(entered, Some(released))?;
    let (stop, stopped) = watch::channel(false);
    let mut worker = tokio::spawn(Arc::clone(&host).serve(stopped, u64::MAX));
    tokio::task::spawn_blocking(move || observed.recv_timeout(Duration::from_secs(30))).await??;
    let (_, active) = host
        .membership(Arc::new(AnalysisReadControl::default()))
        .await?;
    assert_eq!(active.len(), 1);
    let headroom = active.capacity() * std::mem::size_of::<ManagedMember>()
        + active
            .iter()
            .map(|member| member.id.capacity())
            .sum::<usize>();
    assert!(headroom < image_bytes);
    drop(active);
    let retained = fixture.query.memory().input_reserved();
    let pressure = fixture.query.memory().reserve_input(
        capacity
            .checked_sub(retained)
            .and_then(|bytes| bytes.checked_sub(headroom))
            .ok_or("replacement capacity")?,
    )?;
    assert_eq!(fixture.query.memory().input_reserved(), capacity - headroom);
    assert!(fixture.query.memory().reserve_input(image_bytes).is_err());
    let stopped = fixture.query.store().set_managed_running(
        [1; 16],
        "tight-worker",
        lifecycle,
        false,
        || Ok(()),
    )?;
    let restarted = fixture.query.store().set_managed_running(
        [1; 16],
        "tight-worker",
        stopped.lifecycle,
        true,
        || Ok(()),
    )?;
    fixture.context(2)?;
    assert_eq!(authority.admissions.load(Ordering::SeqCst), 1);
    assert!(fixture.query.store().lease_managed().is_err());
    assert!((&mut worker).now_or_never().is_none());
    release.send(())?;
    fixture.host_progress("tight-worker", 0).await?;
    assert_eq!(
        authority.admissions.load(Ordering::SeqCst),
        3,
        "Initial, cancellation, and replacement trust checks"
    );
    let current = fixture
        .query
        .store()
        .managed_instance([1; 16], "tight-worker", &AnalysisReadControl::default())?
        .ok_or("replacement instance")?;
    assert_eq!(current.generation, generation);
    assert_eq!(current.lifecycle, restarted.lifecycle);
    assert!(current.running);
    drop(pressure);
    stop.send_replace(true);
    tokio::time::timeout(Duration::from_secs(30), worker).await???;
    drop(host);
    drop(fixture.query.store().lease_managed()?);
    let permits = [
        fixture.query.reserve_evaluation([1; 16])?,
        fixture.query.reserve_evaluation([1; 16])?,
    ];
    drop(permits);
    drop(fixture.query.memory().reserve_input(capacity)?);
    drop(fixture.query.memory().reserve_output(32 * 1024 * 1024)?);
    Ok(())
}

#[tokio::test]
async fn pressure_keeps_stop_reactive() -> TestResult {
    let capacity = 64 * 1024;
    let fixture = Fixture::new(araphor_query::execution::Limits {
        input_capacity: Some(capacity),
        ..Default::default()
    })?;
    let running = fixture
        .admit("pressure-running", "SELECT 1 AS value")
        .await?;
    let pending = fixture
        .admit("pressure-pending", "SELECT 2 AS value")
        .await?;
    let lifecycle = fixture.start(&running)?;
    drop(running);
    let host = InstanceHost::new(Arc::clone(&fixture.query), fixture.authority.clone());
    let control = Arc::new(AnalysisReadControl::default());
    let members = FuturesUnordered::new();
    let (revision, active) = host.membership(Arc::clone(&control)).await?;
    host.reconcile(
        &members,
        revision,
        active,
        fixture.query.memory().reserve_input(0)?,
        u64::MAX,
    )?;
    assert_eq!(members.len(), 1);
    let mut notices = fixture.query.store().subscribe_activations();
    fixture.start(&pending)?;
    drop(pending);
    let pressure = fixture.query.memory().reserve_input(
        capacity
            .checked_sub(fixture.query.memory().input_reserved())
            .ok_or("pressure capacity")?,
    )?;
    assert_eq!(fixture.query.memory().input_reserved(), capacity);
    let (revision, active) = host.membership(Arc::clone(&control)).await?;
    assert_eq!(active.len(), 2);
    assert!(*notices.borrow_and_update() <= revision);
    let memory = fixture.query.memory().scope();
    let epoch = memory.capacity_epoch();
    let error = host
        .reconcile(
            &members,
            revision,
            active,
            memory.reserve_input(0)?,
            u64::MAX,
        )
        .err()
        .ok_or("metadata pressure missing")?;
    assert!(matches!(error, crate::Error::Query { source }
        if araphor_query::Failure::from(&source) == araphor_query::Failure::Busy));
    assert!(members.iter().all(|member| member.control.check().is_ok()));
    let waiting = host.wait_membership(Arc::clone(&control), Arc::clone(&memory), epoch, notices);
    tokio::pin!(waiting);
    assert!(waiting.as_mut().now_or_never().is_none());
    let stopped = fixture.query.store().set_managed_running(
        [1; 16],
        "pressure-running",
        lifecycle,
        false,
        || Ok(()),
    )?;
    let (revision, active) = tokio::time::timeout(Duration::from_secs(30), waiting).await??;
    assert!(revision >= stopped.lifecycle);
    assert_eq!(active.len(), 1);
    assert_eq!(active[0].id, "pressure-pending");
    let error = host
        .reconcile(
            &members,
            revision,
            active,
            memory.reserve_input(0)?,
            u64::MAX,
        )
        .err()
        .ok_or("metadata pressure released early")?;
    assert!(matches!(error, crate::Error::Query { source }
        if araphor_query::Failure::from(&source) == araphor_query::Failure::Busy));
    assert!(members.iter().all(|member| member.control.check().is_err()));
    assert_eq!(fixture.query.memory().input_reserved(), capacity);
    drop(members);
    drop(pressure);
    assert_eq!(fixture.progress("pressure-running")?, 0);
    assert_eq!(fixture.progress("pressure-pending")?, 0);
    drop(fixture.query.memory().reserve_input(capacity)?);
    Ok(())
}

#[tokio::test]
async fn projected_member_keeps_fence() -> TestResult {
    let fixture = Fixture::new(Default::default())?;
    fixture.install(&bundle("sql")?)?;
    let instance = fixture.admit("projected-stale", r#"SELECT * FROM "runtime-fixture"."1".accumulate(input => (SELECT CAST(11 AS BIGINT UNSIGNED) AS value))"#).await?;
    let lifecycle = fixture.start(&instance)?;
    drop(instance);
    let authority = Authority::new(&fixture);
    let host = InstanceHost::new(Arc::clone(&fixture.query), authority.clone());
    let control = Arc::new(AnalysisReadControl::default());
    let (_, mut active) = host.membership(Arc::clone(&control)).await?;
    assert_eq!(active.len(), 1);
    let member = active.pop().ok_or("stale projected member")?;
    let bytes = std::mem::size_of::<ManagedMember>() + member.id.capacity();
    let expected = Arc::new((member, fixture.query.memory().reserve_input(bytes)?));
    let stopped = fixture.query.store().set_managed_running(
        [1; 16],
        "projected-stale",
        lifecycle,
        false,
        || Ok(()),
    )?;
    fixture.query.store().set_managed_running(
        [1; 16],
        "projected-stale",
        stopped.lifecycle,
        true,
        || Ok(()),
    )?;
    let before = fixture.query.store().meta()?;
    let error = host
        .member(&expected, &control, u64::MAX)
        .await
        .err()
        .ok_or("stale projected admission succeeded")?;
    assert!(matches!(
        error,
        crate::Error::Query {
            source: araphor_query::Error::Data {
                source: araphor_data::Error::Package {
                    code: Code::Conflict,
                    field: "managed member fence",
                    ..
                },
            },
        }
    ));
    assert_eq!(authority.admissions.load(Ordering::SeqCst), 0);
    assert_eq!(fixture.query.store().meta()?, before);
    assert_eq!(fixture.progress("projected-stale")?, 0);
    drop(expected);
    assert_eq!(fixture.query.memory().input_reserved(), 0);
    Ok(())
}

#[tokio::test]
async fn host_bad_member_isolates() -> TestResult {
    let fixture = Fixture::new(Default::default())?;
    fixture.install(&bundle("sql")?)?;
    let sql = r#"SELECT * FROM "runtime-fixture"."1".accumulate(input => (SELECT CAST(COUNT(*) AS BIGINT UNSIGNED) AS value FROM context_versions))"#;
    let broken = fixture.admit("broken-spec", sql).await?;
    let healthy = fixture.admit("healthy-spec", sql).await?;
    fixture.start(&broken)?;
    fixture.start(&healthy)?;
    drop(broken);
    drop(healthy);
    fixture.query.store().fault_write(
        "UPDATE managed_instances SET spec = 'invalid'::BLOB WHERE instance_id = 'broken-spec'",
        &[],
    )?;
    let authority = Authority::new(&fixture);
    let host = InstanceHost::new(Arc::clone(&fixture.query), authority.clone());
    let (stop, stopped) = watch::channel(false);
    let worker = tokio::spawn(host.serve(stopped, u64::MAX));
    let first = fixture.host_progress("healthy-spec", 0).await?;
    fixture.context(1)?;
    fixture.host_progress("healthy-spec", first).await?;
    assert!(matches!(
        fixture.query.store().managed_instance(
            [1; 16],
            "broken-spec",
            &AnalysisReadControl::default(),
        ),
        Err(araphor_data::Error::PackageEncoding { .. })
    ));
    assert_eq!(authority.admissions.load(Ordering::SeqCst), 1);
    stop.send_replace(true);
    tokio::time::timeout(Duration::from_secs(30), worker).await???;
    drop(fixture.query.store().lease_managed()?);
    drop(fixture.query.reserve_evaluation([1; 16])?);
    Ok(())
}
