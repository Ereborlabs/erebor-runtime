use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

use super::*;

struct SourceAuthority {
    tenant: [u8; 16],
    denied: AtomicBool,
    inner: Authority,
    opened: Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
    gate: Mutex<
        Option<(
            tokio::sync::oneshot::Sender<()>,
            std::sync::mpsc::Receiver<()>,
        )>,
    >,
}

impl PackageAuthorization for SourceAuthority {
    fn check(&self, grant: &PackageGrantV1, action: PackageActionV1) -> araphor_data::Result<()> {
        if grant.selection.tenant_id == self.tenant && self.denied.load(Ordering::SeqCst) {
            return Err(Code::Denied.error("source fixture revoked tenant"));
        }
        self.inner.check(grant, action)
    }

    fn admit(&self, grant: &PackageGrantV1, bundle: &PackageBundle) -> araphor_data::Result<()> {
        self.inner.admit(grant, bundle)
    }

    fn commit(
        &self,
        grant: &PackageGrantV1,
        action: PackageActionV1,
        bundle: &PackageBundle,
        operation: &mut dyn FnMut() -> araphor_data::Result<()>,
    ) -> araphor_data::Result<()> {
        self.check(grant, action)?;
        if let Some((entered, release)) = self
            .gate
            .lock()
            .map_err(|_| Code::Incomplete.error("source admission gate"))?
            .take()
        {
            entered
                .send(())
                .map_err(|_| Code::Incomplete.error("source admission observer"))?;
            release
                .recv_timeout(Duration::from_secs(30))
                .map_err(|_| Code::Incomplete.error("source admission release"))?;
        }
        self.inner.commit(grant, action, bundle, operation)
    }

    fn commit_many(
        &self,
        grants: &[(&PackageGrantV1, PackageActionV1, Option<&PackageBundle>)],
        operation: &mut dyn FnMut() -> araphor_data::Result<()>,
    ) -> araphor_data::Result<()> {
        for (grant, action, _) in grants {
            self.check(grant, *action)?;
        }
        self.inner.commit_many(grants, operation)
    }

    fn changes(&self) -> watch::Receiver<u64> {
        self.inner.changes()
    }

    fn changes_for(&self, grant: &PackageGrantV1) -> watch::Receiver<u64> {
        let changes = self.inner.changes();
        if grant.selection.tenant_id != self.tenant {
            if let Some(opened) = self
                .opened
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .take()
            {
                let _opened = opened.send(());
            }
        }
        changes
    }
}

#[tokio::test]
async fn denied_program_keeps_sibling() -> TestResult {
    let fixture = Fixture::new(Limits {
        global_streams: Some(2),
        tenant_streams: Some(1),
        ..Default::default()
    })?;
    let tenant = fixture.source.tenant_id;
    let sibling_tenant = [42; 16];
    assert_ne!(sibling_tenant, tenant);
    let (entered, observed) = tokio::sync::oneshot::channel();
    let authority = Arc::new(SourceAuthority {
        tenant,
        denied: AtomicBool::new(false),
        inner: Authority(watch::channel(0).0),
        opened: Mutex::new(Some(entered)),
        gate: Mutex::default(),
    });
    let mut packages = Vec::new();
    for current in [tenant, sibling_tenant] {
        let image = Arc::new(PackageBundle::try_from(Fixture::constant_bundle(
            "SELECT CAST(1 AS BIGINT UNSIGNED) AS value",
        )?)?);
        fixture
            .store
            .install_package_image(current, &image, || Ok(()))?;
        packages.push(Package::new(
            Arc::clone(&fixture.query),
            authority.clone(),
            PackageGrantV1 {
                principal: "fixture".into(),
                revision: 1,
                selection: AnalysisSelectionV1::tenant(current),
                expires_utc_ns: None,
                authorization_id: None,
            },
            image,
            "constant",
            "data",
        )?);
    }
    let host = InstanceHost::new(Arc::clone(&fixture.query), authority.clone());
    let owner = Arc::new(DiscoveryOwner::new(packages, host)?);
    let control = Arc::new(AnalysisReadControl::default());
    let observer = AnalysisReadControl::default();
    let mut feed = Box::pin(owner.feed(Arc::clone(&control)));
    let initial_deadline = tokio::time::sleep(Duration::from_secs(90));
    tokio::pin!(initial_deadline);
    tokio::select! {
        _ = &mut initial_deadline => return Err("source subscription admission stalled".into()),
        result = &mut feed => return Err(format!("source feed ended before subscription admission: {result:?}").into()),
        observed = observed => observed?,
    }
    assert!(matches!(
        fixture.query.reserve_stream(tenant),
        Err(araphor_query::Error::Busy {
            resource: "stream",
            ..
        })
    ));
    authority.denied.store(true, Ordering::SeqCst);
    authority.inner.0.send_replace(1);
    let record = fixture.records.get(&1).ok_or("fixture record")?;
    let sibling = EvidenceIntakeIdentityV1 {
        tenant_id: sibling_tenant,
        ..fixture.source.clone()
    };
    fixture.store.accept_validated_batch(
        sibling.clone(),
        ValidatedEvidenceBatchV1 {
            cpu_id: record.id.cpu_id,
            first_cursor: 1,
            last_cursor: 1,
            intake_utc_ns: 1,
            frame_ends: vec![record.wire_record.len()],
            framed_records: record.wire_record.clone().into(),
        },
    )?;
    fixture.append(1)?;
    let mut notices = fixture.store.subscribe_revision();
    let first_deadline = tokio::time::sleep(Duration::from_secs(90));
    tokio::pin!(first_deadline);
    loop {
        notices.borrow_and_update();
        control.check()?;
        if fixture
            .store
            .managed_instance(
                sibling_tenant,
                &DiscoveryOwner::instance_id(&sibling),
                &observer,
            )?
            .is_some_and(|instance| instance.running)
        {
            break;
        }
        tokio::select! {
            _ = &mut first_deadline => return Err("first sibling admission stalled".into()),
            result = &mut feed => return Err(format!("sibling source feed ended: {result:?}").into()),
            changed = notices.changed() => { changed?; }
        }
    }
    assert!(fixture
        .store
        .managed_instance(
            tenant,
            &DiscoveryOwner::instance_id(&fixture.source),
            &observer
        )?
        .is_none());
    assert!(fixture.store.processor_health(&fixture.scope())?.is_none());
    let second = EvidenceIntakeIdentityV1 {
        source_id: [43; 16],
        ..sibling.clone()
    };
    fixture.store.accept_validated_batch(
        second.clone(),
        ValidatedEvidenceBatchV1 {
            cpu_id: record.id.cpu_id,
            first_cursor: 1,
            last_cursor: 1,
            intake_utc_ns: 2,
            frame_ends: vec![record.wire_record.len()],
            framed_records: record.wire_record.clone().into(),
        },
    )?;
    let second_deadline = tokio::time::sleep(Duration::from_secs(90));
    tokio::pin!(second_deadline);
    loop {
        notices.borrow_and_update();
        control.check()?;
        if fixture
            .store
            .managed_instance(
                sibling_tenant,
                &DiscoveryOwner::instance_id(&second),
                &observer,
            )?
            .is_some_and(|instance| instance.running)
        {
            break;
        }
        tokio::select! {
            _ = &mut second_deadline => return Err("second sibling admission stalled".into()),
            result = &mut feed => return Err(format!("sibling source feed ended after removal: {result:?}").into()),
            changed = notices.changed() => { changed?; }
        }
    }
    control.cancel()?;
    tokio::time::timeout(Duration::from_secs(90), feed)
        .await
        .map_err(|_| "source feed stop stalled")??;
    drop(owner);
    fixture.released()?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn aborted_admission_keeps_owner() -> TestResult {
    let fixture = Fixture::new(Limits::default())?;
    fixture.append(1)?;
    let authority = Arc::new(SourceAuthority {
        tenant: fixture.source.tenant_id,
        denied: AtomicBool::new(false),
        inner: Authority(watch::channel(0).0),
        opened: Mutex::default(),
        gate: Mutex::default(),
    });
    let image = Arc::new(PackageBundle::try_from(Fixture::constant_bundle(
        "SELECT CAST(1 AS BIGINT UNSIGNED) AS value",
    )?)?);
    fixture
        .store
        .install_package_image(fixture.source.tenant_id, &image, || Ok(()))?;
    let host = InstanceHost::new(Arc::clone(&fixture.query), authority.clone());
    let owner = Arc::new(DiscoveryOwner::new(
        vec![Package::new(
            Arc::clone(&fixture.query),
            authority.clone(),
            PackageGrantV1 {
                principal: "fixture".into(),
                revision: 1,
                selection: AnalysisSelectionV1::tenant(fixture.source.tenant_id),
                expires_utc_ns: None,
                authorization_id: None,
            },
            image,
            "constant",
            "data",
        )?],
        host,
    )?);
    let before = fixture.store.meta()?;
    let weak = Arc::downgrade(&owner);
    let (entered, observed) = tokio::sync::oneshot::channel();
    let (release, waiting) = std::sync::mpsc::channel();
    *authority.gate.lock().map_err(|_| "source admission gate")? = Some((entered, waiting));
    let (stop, stopped) = watch::channel(false);
    let worker = tokio::spawn(owner.run(stopped));
    tokio::time::timeout(Duration::from_secs(90), observed).await??;
    worker.abort();
    assert!(worker
        .await
        .err()
        .ok_or("source caller not aborted")?
        .is_cancelled());
    assert!(fixture.store.discovery_enabled());
    assert!(weak.upgrade().is_some());
    assert!(!stop.is_closed());
    assert_eq!(fixture.store.meta()?, before);
    release.send(())?;
    tokio::time::timeout(Duration::from_secs(30), stop.closed()).await?;
    assert!(weak.upgrade().is_none());
    assert!(!fixture.store.discovery_enabled());
    assert_eq!(fixture.store.meta()?, before);
    assert!(fixture.store.processor_health(&fixture.scope())?.is_none());
    assert!(fixture
        .store
        .managed_instance(
            fixture.source.tenant_id,
            &DiscoveryOwner::instance_id(&fixture.source),
            &AnalysisReadControl::default(),
        )?
        .is_none());
    assert!(fixture.profile()?.is_none());
    fixture.released()?;
    Ok(())
}
