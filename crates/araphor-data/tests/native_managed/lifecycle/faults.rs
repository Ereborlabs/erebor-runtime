use super::*;
use araphor_data::{AnalysisCommitStage, AnalysisStoreMetaV1, ManagedMember};

fn efbig(error: &(dyn std::error::Error + 'static)) -> bool {
    let mut current = Some(error);
    while let Some(error) = current {
        if error
            .downcast_ref::<std::io::Error>()
            .is_some_and(|source| {
                source.raw_os_error() == Some(rustix::io::Errno::FBIG.raw_os_error())
            })
        {
            return true;
        }
        current = error.source();
    }
    false
}

fn records(
    view: &araphor_data::analysis::native::DataView,
) -> Result<BTreeMap<Vec<u8>, Vec<u8>>, Box<dyn std::error::Error>> {
    view.snapshot()
        .prefix(b"\0data/")
        .map(|entry| {
            let (key, value) = entry?;
            Ok((key.to_vec(), value.to_vec()))
        })
        .collect()
}

fn closed(
    store: &NativeStore,
    running: &ManagedInstance,
    notices: &araphor_data::analysis::native::ActivationSubscription,
) -> TestResult {
    assert!(matches!(
        store.view(),
        Err(Error::NativeState {
            field: "uncertain commit; reopen required",
            ..
        })
    ));
    assert!(matches!(
        store.write(),
        Err(Error::NativeState {
            field: "uncertain commit; reopen required",
            ..
        })
    ));
    assert!(matches!(
        capture(store, running, None),
        Err(Error::NativeState {
            field: "uncertain commit; reopen required",
            ..
        })
    ));
    assert!(matches!(
        notices.has_changed(),
        Err(Error::NativeState {
            field: "input store requires reopen",
            ..
        })
    ));
    Ok(())
}

async fn reopened(
    store: &NativeStore,
    expected: &ManagedInstance,
    meta: &AnalysisStoreMetaV1,
) -> TestResult {
    let control = AnalysisReadControl::default();
    assert_eq!(&store.view()?.meta(), meta);
    assert_eq!(
        store
            .managed_instance([1; 16], "faults", &control)?
            .as_ref(),
        Some(expected)
    );
    let mut notices = store.subscribe_activations()?;
    assert_eq!(notices.position(), meta.commit_revision);
    let (cut, members) = store.active_managed(&control)?;
    assert_eq!(cut, meta.commit_revision);
    let expected = if expected.running {
        vec![ManagedMember {
            tenant: [1; 16],
            id: "faults".into(),
            generation: expected.generation,
            lifecycle: expected.lifecycle,
        }]
    } else {
        Vec::new()
    };
    assert_eq!(members, expected);
    assert!(!notices.has_changed()?);
    let before = records(store.view()?.as_ref())?;
    store.recover()?;
    store.recover()?;
    assert_eq!(&store.view()?.meta(), meta);
    assert_eq!(records(store.view()?.as_ref())?, before);
    assert!(!notices.has_changed()?);
    super::super::attempts::append(store, 1)?;
    assert!(!notices.has_changed()?);
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(25), notices.changed())
            .await
            .is_err()
    );
    Ok(())
}

#[tokio::test]
async fn journal_failure_requires_reopen() -> TestResult {
    let Some(root) = std::env::var_os("ARAPHOR_WAL_FAULT") else {
        let directory = tempfile::tempdir()?;
        let root = directory.path().join("data");
        let store = NativeStore::open(&root)?;
        let fixture = fixture(&store, "faults")?;
        let admitted = fixture.admit(&store)?;
        let running =
            store.set_managed_running([1; 16], "faults", admitted.lifecycle, true, || Ok(()))?;
        let before = store.view()?;
        let retained = records(&before)?;
        let meta = before.meta();
        let cursor = store.database().inner().journal_head()?;
        drop((before, fixture, store));
        let output = std::process::Command::new(std::env::current_exe()?)
            .args([
                "--exact",
                "lifecycle::faults::journal_failure_requires_reopen",
                "--nocapture",
            ])
            .env("ARAPHOR_WAL_FAULT", &root)
            .output()?;
        assert!(
            output.status.code() == Some(73),
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(stdout.contains("running 1 test"), "{stdout}");
        assert!(stdout.contains("ARAPHOR_WAL_FAULT_CONFIRMED"), "{stdout}");
        let store = NativeStore::open(&root)?;
        assert!(
            records(store.view()?.as_ref())? == retained,
            "changed pre-fault Data records"
        );
        let mut feed = store.database().inner().journal_feed(cursor)?;
        while let Some(batch) = feed.next_batch()? {
            assert!(!batch
                .items
                .iter()
                .any(|item| item.key.starts_with(b"\0data/J")));
        }
        reopened(&store, &running, &meta).await?;
        return Ok(());
    };
    let root = std::path::PathBuf::from(root);
    let store = NativeStore::open(&root)?;
    let running = store
        .managed_instance([1; 16], "faults", &AnalysisReadControl::default())?
        .ok_or("running instance")?;
    assert!(running.running);
    let before = store.view()?;
    let notices = store.subscribe_activations()?;
    let revision = store.subscribe_revision();
    assert_eq!(notices.position(), before.revision());
    assert!(!notices.has_changed()?);
    use rustix::process::{getrlimit, setrlimit, Resource, Rlimit, Signal};
    let _signal = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::from_raw(
        Signal::XFSZ.as_raw(),
    ))?;
    let prior = getrlimit(Resource::Fsize);
    setrlimit(
        Resource::Fsize,
        Rlimit {
            current: Some(0),
            ..prior
        },
    )?;
    let outcome = store.stop_managed(&running, || Ok(()));
    setrlimit(Resource::Fsize, prior)?;
    let error = outcome.err().ok_or("journal write succeeded")?;
    assert!(
        matches!(&error, Error::NativeStorage {operation: "commit Data write", source, ..} if efbig(source)),
        "{error:?}"
    );
    assert!(store.database().inner().is_poisoned());
    assert!(!revision.has_changed()?);
    closed(&store, &running, &notices)?;
    assert!(matches!(
        store.recover(),
        Err(Error::NativeStorage {
            operation: "check recovery engine durability",
            source: fjall::Error::Poisoned,
            ..
        })
    ));
    closed(&store, &running, &notices)?;
    use std::io::Write as _;
    let mut stdout = std::io::stdout().lock();
    writeln!(stdout, "ARAPHOR_WAL_FAULT_CONFIRMED")?;
    stdout.flush()?;
    std::process::exit(73);
}

#[tokio::test]
async fn synced_failure_requires_reopen() -> TestResult {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("data");
    let store = NativeStore::open(&root)?;
    let fixture = fixture(&store, "faults")?;
    let admitted = fixture.admit(&store)?;
    let running =
        store.set_managed_running([1; 16], "faults", admitted.lifecycle, true, || Ok(()))?;
    let before = store.view()?;
    let retained = records(&before)?;
    let cursor = store.database().inner().journal_head()?;
    let notices = store.subscribe_activations()?;
    let revision = store.subscribe_revision();
    assert_eq!(notices.position(), before.revision());
    assert!(!notices.has_changed()?);
    store.set_commit_hook(AnalysisCommitStage::AfterMetadataSync, || {
        Err(Code::Denied.error("post-sync lifecycle fault"))
    })?;
    assert!(matches!(
        store.stop_managed(&running, || Ok(())),
        Err(Error::Package {
            code: Code::Denied,
            field: "post-sync lifecycle fault",
            ..
        })
    ));
    assert!(!store.database().inner().is_poisoned());
    assert!(!revision.has_changed()?);
    closed(&store, &running, &notices)?;
    assert!(matches!(
        store.recover(),
        Err(Error::NativeState {
            field: "changed metadata cut; reopen required",
            ..
        })
    ));
    closed(&store, &running, &notices)?;
    let mut meta = before.meta();
    meta.commit_revision += 1;
    let expected = ManagedInstance {
        running: false,
        lifecycle: meta.commit_revision,
        ..running
    };
    drop((before, notices, revision, store));
    let store = NativeStore::open(&root)?;
    assert_eq!(
        records(&store.read_at(meta.commit_revision - 1)?)?,
        retained
    );
    let mut feed = store.database().inner().journal_feed(cursor)?;
    let mut changes = 0;
    while let Some(batch) = feed.next_batch()? {
        changes += usize::from(
            batch
                .items
                .iter()
                .any(|item| item.key.starts_with(b"\0data/J")),
        );
    }
    assert_eq!(changes, 1);
    reopened(&store, &expected, &meta).await?;
    Ok(())
}
