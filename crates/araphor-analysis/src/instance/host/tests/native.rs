use super::*;
use crate::instance::tests::request;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{UnixListener, UnixStream};

const INPUT: usize = 128 * 1024 * 1024;
const OUTPUT: usize = 4 * 1024 * 1024;

async fn event(peer: &mut UnixStream, expected: u8) -> TestResult {
    let mut actual = [0];
    tokio::time::timeout(Duration::from_secs(30), peer.read_exact(&mut actual)).await??;
    assert_eq!(actual, [expected]);
    Ok(())
}

async fn entered(listener: &UnixListener) -> TestResult<(UnixStream, String)> {
    let (mut peer, _) = tokio::time::timeout(Duration::from_secs(30), listener.accept()).await??;
    event(&mut peer, b'E').await?;
    let mut size = [0; 4];
    tokio::time::timeout(Duration::from_secs(30), peer.read_exact(&mut size)).await??;
    let size = usize::try_from(u32::from_le_bytes(size))?;
    assert!((1..=256).contains(&size));
    let mut id = vec![0; size];
    tokio::time::timeout(Duration::from_secs(30), peer.read_exact(&mut id)).await??;
    Ok((peer, String::from_utf8(id)?))
}

impl Fixture {
    fn native_limits() -> araphor_query::execution::Limits {
        araphor_query::execution::Limits {
            global_evaluations: Some(4),
            tenant_evaluations: Some(4),
            input_capacity: Some(INPUT),
            output_capacity: Some(OUTPUT),
            ..Default::default()
        }
    }

    fn native_slots(&self, available: usize) -> TestResult {
        let permits = (0..available)
            .map(|_| self.query.reserve_evaluation([1; 16]))
            .collect::<araphor_query::Result<Vec<_>>>()?;
        assert!(self.query.reserve_evaluation([1; 16]).is_err());
        drop(permits);
        Ok(())
    }

    fn native_released(&self, retained: usize) -> TestResult {
        self.native_slots(4)?;
        assert_eq!(self.query.memory().input_reserved(), retained);
        drop(self.query.memory().reserve_input(INPUT - retained)?);
        drop(self.query.memory().reserve_output(OUTPUT)?);
        Ok(())
    }

    fn native_empty(&self, id: &str, attempt: Option<&str>) -> TestResult {
        let read = AnalysisReadControl::default();
        let current = self
            .query
            .store()
            .managed_instance([1; 16], id, &read)?
            .ok_or("native instance absent")?;
        assert_eq!(current.progress, 0);
        assert!(self
            .query
            .store()
            .managed_history(&self.grant.selection, id, &read)?
            .is_empty());
        if let Some(attempt) = attempt {
            let captured = self
                .query
                .store()
                .managed_attempt([1; 16], id, attempt, &read)?
                .ok_or("native attempt was not captured")?;
            assert!(captured.receipt().is_none());
            assert!(self
                .query
                .store()
                .managed_selected([1; 16], id, attempt, &read)?
                .is_none());
        }
        Ok(())
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires source-built native artifacts in ARAPHOR_NATIVE_DIR"]
async fn native_control_joins() -> TestResult {
    for cause in ["cancel", "revoke", "expiry"] {
        let mut fixture = Fixture::new(Fixture::native_limits())?;
        if cause == "expiry" {
            fixture.grant.expires_utc_ns = Some(u64::try_from(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)?
                    .as_nanos()
                    + 5_000_000_000,
            )?);
        }
        let deadline = if cause == "expiry" {
            Some(AnalysisReadControl::default().within(fixture.grant.remaining()?)?)
        } else {
            None
        };
        let socket = fixture.directory.path().join("control.sock");
        let listener = UnixListener::bind(&socket)?;
        let mode = format!("cancel:{}", socket.to_str().ok_or("native socket path")?);
        let instance = fixture
            .terminal_target("native-control", &mode, "native")
            .await?;
        assert_eq!(instance.admitted().spec.manifest.calls.len(), 1);
        assert_eq!(
            instance
                .admitted()
                .spec
                .manifest
                .calls
                .values()
                .next()
                .ok_or("native call")?
                .target,
            "native"
        );
        let retained = fixture.query.memory().input_reserved();
        let control = Arc::new(AnalysisReadControl::default());
        let stage = Arc::clone(&control);
        let active = Arc::clone(&instance);
        let worker = tokio::spawn(async move { active.run(request("interrupted"), &stage).await });
        let (mut peer, attempt) = entered(&listener).await?;
        assert_eq!(attempt, "interrupted");
        fixture.native_slots(3)?;
        fixture.native_empty("native-control", Some("interrupted"))?;
        match cause {
            "cancel" => {
                control.cancel()?;
            }
            "revoke" => fixture.authority.set(false),
            "expiry" => {
                tokio::time::timeout(
                    Duration::from_secs(10),
                    deadline.as_ref().ok_or("native expiry wait")?.expired(),
                )
                .await?;
            }
            _ => return Err("native interrupt cause".into()),
        }
        tokio::task::yield_now().await;
        assert!(
            !worker.is_finished(),
            "{cause} returned before Native completion"
        );
        fixture.native_slots(3)?;
        peer.write_all(b"R").await?;
        let error = tokio::time::timeout(Duration::from_secs(5), async {
            event(&mut peer, b'D').await?;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(
                worker.await?.err().ok_or("native interruption published")?,
            )
        })
        .await??;
        if cause == "cancel" {
            assert!(
                matches!(
                    &error,
                    crate::Error::Data {
                        source: araphor_data::Error::AnalysisReadCancelled { .. }
                    }
                ),
                "{cause}: {error:?}"
            );
        } else {
            let field = if cause == "revoke" {
                "managed authority change"
            } else {
                "managed grant expiry"
            };
            assert!(
                matches!(&error, crate::Error::Data {
                source: araphor_data::Error::Package { code: Code::Denied, field: actual, .. }
            } if *actual == field),
                "{cause}: {error:?}"
            );
            control.check()?;
        }
        fixture.native_empty("native-control", Some("interrupted"))?;
        fixture.native_released(retained)?;
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires source-built native artifacts in ARAPHOR_NATIVE_DIR"]
async fn native_stop_joins() -> TestResult {
    let fixture = Fixture::new(Fixture::native_limits())?;
    let socket = fixture.directory.path().join("stop.sock");
    let listener = UnixListener::bind(&socket)?;
    let mode = format!("cancel:{}", socket.to_str().ok_or("native socket path")?);
    let instance = fixture
        .terminal_target("native-stop", &mode, "native")
        .await?;
    let host = InstanceHost::new(Arc::clone(&fixture.query), fixture.authority.clone());
    let (stop, stopped) = watch::channel(false);
    let worker = tokio::spawn(Arc::clone(&host).serve(stopped, u64::MAX));
    host.ready().await?;
    let running = host
        .start(
            Arc::clone(&instance),
            instance.admitted().lifecycle,
            &AnalysisReadControl::default(),
        )
        .await?;
    let (mut peer, attempt) = entered(&listener).await?;
    fixture.native_slots(3)?;
    let owner = Arc::clone(&host);
    let lifecycle = running.admitted().lifecycle;
    let stopping = tokio::spawn(async move {
        owner
            .stop(running, lifecycle, &AnalysisReadControl::default())
            .await
    });
    tokio::task::yield_now().await;
    assert!(!stopping.is_finished());
    fixture.native_slots(3)?;
    peer.write_all(b"R").await?;
    let stopped_instance = tokio::time::timeout(Duration::from_secs(5), async {
        event(&mut peer, b'D').await?;
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(stopping.await??)
    })
    .await??;
    assert!(!stopped_instance.admitted().running);
    fixture.native_empty("native-stop", Some(&attempt))?;
    fixture.native_slots(4)?;
    let resume = fixture.query.store().managed_resume(
        [1; 16],
        "native-stop",
        &AnalysisReadControl::default(),
    )?;
    assert!(resume.completed > 0);
    assert!(resume.frontier.is_none());
    let captured = fixture
        .query
        .store()
        .managed_attempt(
            [1; 16],
            "native-stop",
            &attempt,
            &AnalysisReadControl::default(),
        )?
        .ok_or("native stopped attempt")?;
    let terminal = captured.terminal().ok_or("native stopped terminal")?;
    assert_eq!(terminal.exit, araphor_data::ManagedExit::Cancelled);
    assert_eq!(terminal.revision, resume.completed);
    assert!(!terminal.suspended);
    assert!(captured.receipt().is_none());
    stop.send_replace(true);
    tokio::time::timeout(Duration::from_secs(5), worker).await???;
    drop((stopped_instance, instance, host));
    fixture.native_released(0)?;
    drop(fixture.query.store().lease_managed()?);
    Ok(())
}

#[tokio::test]
#[ignore = "requires source-built native artifacts in ARAPHOR_NATIVE_DIR"]
async fn native_expired_admission() -> TestResult {
    let fixture = Fixture::new(Fixture::native_limits())?;
    let socket = fixture.directory.path().join("expired.sock");
    let listener = UnixListener::bind(&socket)?;
    let mode = format!("cancel:{}", socket.to_str().ok_or("native socket path")?);
    let template = fixture
        .terminal_target("native-template", &mode, "native")
        .await?;
    let mut grant = fixture.grant.clone();
    grant.expires_utc_ns = Some(0);
    let before = fixture.query.store().meta()?;
    let retained = fixture.query.memory().input_reserved();
    let error = Instance::admit(
        Arc::clone(&fixture.query),
        fixture.authority.clone(),
        grant,
        "native-expired".into(),
        template.admitted().spec.definition.clone(),
        &AnalysisReadControl::default(),
    )
    .await
    .err()
    .ok_or("expired Native admission succeeded")?;
    assert!(
        matches!(
            &error,
            crate::Error::Data {
                source: araphor_data::Error::Package {
                    code: Code::Denied,
                    field: "package grant",
                    ..
                }
            }
        ),
        "{error:?}"
    );
    assert_eq!(fixture.query.store().meta()?, before);
    assert!(fixture
        .query
        .store()
        .managed_instance([1; 16], "native-expired", &AnalysisReadControl::default())?
        .is_none());
    assert!(fixture
        .query
        .store()
        .managed_attempt(
            [1; 16],
            "native-expired",
            "interrupted",
            &AnalysisReadControl::default()
        )?
        .is_none());
    assert!(matches!(listener.into_std()?.accept(),
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock
    ));
    fixture.native_released(retained)?;
    Ok(())
}
