use std::sync::{mpsc, Arc};
use std::time::Duration;

use araphor_data::{AnalysisReadControl, AnalysisSelectionV1};
use datafusion::common::DataFusionError;

use super::{execution, Fixture, Limits, PackageImplementationV1, TestResult};

#[tokio::test]
async fn image_capacity_precedes_planning() -> TestResult {
    let mut bundle = Fixture::bundle();
    let PackageImplementationV1::Sql { program, .. } = &mut bundle.artifacts[0].implementations[0]
    else {
        return Err("SQL implementation absent".into());
    };
    program
        .outputs
        .insert("result".into(), "SELECT missing FROM absent".into());
    let fixture = Fixture::limits(Limits {
        input_capacity: Some(1),
        ..Default::default()
    })?;
    fixture.install(&bundle)?;
    let error = fixture
        .prepare(&Fixture::definition())
        .await
        .err()
        .ok_or("image capacity admitted")?;
    assert!(
        matches!(
            error,
            crate::Error::Sql {
                source: DataFusionError::ResourcesExhausted(_)
            }
        ),
        "{error:?}"
    );
    drop(fixture.engine.memory().reserve_input(1)?);
    Ok(())
}

#[tokio::test]
async fn image_capacity_follows_plan() -> TestResult {
    const CAPACITY: usize = 1024 * 1024;
    let fixture = Fixture::limits(Limits {
        input_capacity: Some(CAPACITY),
        ..Default::default()
    })?;
    fixture.install(&Fixture::bundle())?;
    let prepared = fixture.prepare(&Fixture::definition()).await?;
    let calls = Fixture::calls(&prepared.plan)?;
    let call = calls.first().ok_or("package call absent")?;
    let (_, reservation) = prepared.admission.images.first().ok_or("image absent")?;
    assert!(Arc::ptr_eq(reservation, &call._image));
    assert_eq!(
        reservation.size(),
        call.bundle.allocated_bytes()?
            + std::mem::size_of::<(
                Arc<araphor_package::PackageBundle>,
                Arc<datafusion::execution::memory_pool::MemoryReservation>,
            )>()
    );
    assert!(std::ptr::eq(
        call.descriptor(),
        &call.bundle.bundle().artifacts[call.artifact].descriptor
    ));
    let bytes = reservation.size() + call._metadata.size();
    assert!(bytes > 0 && bytes < CAPACITY);
    let image = Arc::downgrade(&call.bundle);
    let charge = Arc::downgrade(reservation);
    let plan = prepared.plan.clone();
    let copy = prepared.clone();
    drop(prepared);
    drop(calls);
    let retained = fixture.engine.memory().input_reserved();
    let pressure = fixture.engine.memory().reserve_input(CAPACITY - retained)?;
    assert!(fixture.engine.memory().reserve_input(1).is_err());
    drop(copy);
    assert!(image.upgrade().is_some());
    assert!(charge.upgrade().is_some());
    let metadata = fixture.engine.memory().reserve_input(retained - bytes)?;
    assert!(fixture.engine.memory().reserve_input(1).is_err());
    drop(plan);
    assert!(image.upgrade().is_none());
    assert!(charge.upgrade().is_none());
    drop((pressure, metadata));
    drop(fixture.engine.memory().reserve_input(CAPACITY)?);
    Ok(())
}

#[tokio::test]
async fn image_capacity_is_shared() -> TestResult {
    let fixture = Fixture::installed(&Fixture::bundle())?;
    let prepared = fixture
        .prepare(&Fixture::sql(format!(
            "{} UNION ALL {}",
            Fixture::definition().program.sql()?,
            Fixture::definition().program.sql()?
        )))
        .await?;
    let calls = Fixture::calls(&prepared.plan)?;
    assert_eq!(calls.len(), 2);
    assert_eq!(prepared.images().count(), 1);
    assert!(Arc::ptr_eq(&calls[0].bundle, &calls[1].bundle));
    assert!(Arc::ptr_eq(&calls[0]._image, &calls[1]._image));
    assert!(!Arc::ptr_eq(&calls[0]._metadata, &calls[1]._metadata));

    let mut second = Fixture::bundle();
    second.root.revision = "r2".into();
    second.artifacts[0].descriptor.revision = "r2".into();
    let images = super::super::package::Packages::new(
        &fixture.engine,
        vec![
            araphor_package::PackageBundle::try_from(second)?,
            araphor_package::PackageBundle::try_from(Fixture::bundle())?,
        ],
        [1; 16],
        Default::default(),
        Arc::clone(fixture.engine.memory()),
    )?;
    assert_eq!(images.bundles[0].0.bundle().root.revision, "r1");
    assert_eq!(images.bundles[1].0.bundle().root.revision, "r2");
    let duplicate = super::super::package::Packages::new(
        &fixture.engine,
        vec![
            araphor_package::PackageBundle::try_from(Fixture::bundle())?,
            araphor_package::PackageBundle::try_from(Fixture::bundle())?,
        ],
        [1; 16],
        Default::default(),
        Arc::clone(fixture.engine.memory()),
    )
    .err()
    .ok_or("duplicate image admitted")?;
    assert!(matches!(
        duplicate,
        crate::Error::Invalid {
            field: "duplicate definition image",
            ..
        }
    ));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn image_capacity_joins_guest() -> TestResult {
    const CAPACITY: usize = 128 * 1024 * 1024;
    let fixture = Fixture::limits(Limits {
        input_capacity: Some(CAPACITY),
        evaluate_timeout: Some(Duration::from_secs(30)),
        global_evaluations: Some(1),
        tenant_evaluations: Some(1),
        ..Default::default()
    })?;
    fixture.install(&execution::component("wasm", "evaluate")?)?;
    let prepared = fixture
        .prepare(&Fixture::sql(
            r#"SELECT * FROM "runtime-fixture"."1".evaluate(mode => 'cancel', amount => 0)"#,
        ))
        .await?;
    let calls = Fixture::calls(&prepared.plan)?;
    let image = Arc::downgrade(&calls[0].bundle);
    let charge = Arc::downgrade(&calls[0]._image);
    let bytes = calls[0]._image.size();
    drop(calls);
    let (entered, observed) = mpsc::channel();
    let (release, waiting) = mpsc::channel();
    fixture.engine.guest_entry(entered, Some(waiting))?;
    let control = araphor_data::AnalysisReadControl::default();
    let session = fixture
        .engine
        .session(AnalysisSelectionV1::tenant([1; 16]), &control, 1)?;
    let worker = tokio::spawn(async move {
        session
            .execute_definition(&prepared, execution::invocation("image-lease"))
            .await
    });
    let entered =
        tokio::task::spawn_blocking(move || observed.recv_timeout(Duration::from_secs(30))).await?;
    if let Err(error) = entered {
        let _released = release.send(());
        return Err(format!("guest entry failed: {error}; {:?}", worker.await?.err()).into());
    }
    control.cancel()?;
    assert!(!worker.is_finished());
    assert!(image.upgrade().is_some());
    assert!(charge.upgrade().is_some());
    assert!(fixture
        .engine
        .memory()
        .reserve_input(CAPACITY - bytes + 1)
        .is_err());
    assert!(fixture.engine.reserve_evaluation([1; 16]).is_err());
    release.send(())?;
    let error = tokio::time::timeout(Duration::from_secs(30), worker)
        .await??
        .err()
        .ok_or("cancelled guest returned output")?;
    assert_eq!(crate::Failure::from(&error), crate::Failure::Cancelled);
    assert!(image.upgrade().is_none());
    assert!(charge.upgrade().is_none());
    drop(fixture.engine.memory().reserve_input(CAPACITY)?);
    drop(fixture.engine.reserve_evaluation([1; 16])?);
    Ok(())
}

#[tokio::test]
async fn failed_preparation_releases_image() -> TestResult {
    const CAPACITY: usize = 1024 * 1024;
    let fixture = Fixture::limits(Limits {
        input_capacity: Some(CAPACITY),
        evaluate_timeout: Some(Duration::from_secs(10)),
        global_evaluations: Some(1),
        tenant_evaluations: Some(1),
        ..Default::default()
    })?;
    let mut bundle = execution::component("wasm", "evaluate")?;
    let PackageImplementationV1::Wasm { artifact, .. } =
        &mut bundle.artifacts[0].implementations[0]
    else {
        return Err("Wasm implementation absent".into());
    };
    // The core function declares i32 but returns i64.
    *artifact = vec![
        0, 97, 115, 109, 13, 0, 1, 0, 1, 27, 0, 97, 115, 109, 1, 0, 0, 0, 1, 5, 1, 96, 0, 1, 127,
        3, 2, 1, 0, 10, 6, 1, 4, 0, 66, 0, 11,
    ];
    fixture.install(&bundle)?;
    let prepared = fixture
        .prepare(&Fixture::sql(
            r#"SELECT * FROM "runtime-fixture"."1".evaluate(mode => 'echo', amount => 0)"#,
        ))
        .await?;
    let calls = Fixture::calls(&prepared.plan)?;
    let image = Arc::downgrade(&calls[0].bundle);
    let charge = Arc::downgrade(&calls[0]._image);
    drop(calls);
    let (entry, observed) = mpsc::channel();
    fixture.engine.guest_entry(entry, None)?;
    let error = fixture
        .execute(&prepared, execution::invocation("bad-image"))
        .await
        .err()
        .ok_or("invalid component prepared")?;
    let mut source: Option<&(dyn std::error::Error + 'static)> = Some(&error);
    let mut wasm = false;
    while let Some(error) = source {
        wasm |= matches!(
            error.downcast_ref::<araphor_package_runtime::Error>(),
            Some(araphor_package_runtime::Error::PackageWasm {
                code: araphor_data::PackageErrorCodeV1::Invalid,
                operation: "component compilation",
                ..
            })
        );
        source = error.source();
    }
    assert!(wasm, "{error:?}");
    assert!(matches!(
        observed.try_recv(),
        Err(mpsc::TryRecvError::Empty)
    ));
    drop(prepared);
    assert!(image.upgrade().is_none());
    assert!(charge.upgrade().is_none());
    drop(fixture.engine.memory().reserve_input(CAPACITY)?);
    drop(fixture.engine.reserve_evaluation([1; 16])?);
    Ok(())
}

#[tokio::test]
async fn image_admission_rejects_short_capacity() -> TestResult {
    let image = Fixture::bundle();
    let measured = Fixture::installed(&image)?;
    let prepared = measured.prepare(&Fixture::definition()).await?;
    let retained = measured.engine.memory().input_reserved();
    assert!(retained > image.allocated_bytes()?);
    drop(prepared);
    assert_eq!(measured.engine.memory().input_reserved(), 0);
    let capacity = retained.checked_sub(1).ok_or("retained image charge")?;
    let fixture = Fixture::limits(Limits {
        input_capacity: Some(capacity),
        ..Default::default()
    })?;
    fixture.install(&image)?;
    let before = fixture.engine.store().meta()?;
    let error = fixture
        .prepare(&Fixture::definition())
        .await
        .err()
        .ok_or("one-byte-short image admission succeeded")?;
    assert!(
        matches!(
            crate::Failure::from(&error),
            crate::Failure::Busy | crate::Failure::InputTooLarge
        ),
        "{error:?}"
    );
    assert_eq!(fixture.engine.store().meta()?, before);
    assert_eq!(fixture.engine.memory().input_reserved(), 0);
    drop(fixture.engine.memory().reserve_input(capacity)?);
    Ok(())
}

#[tokio::test]
async fn metadata_clones_share_capacity() -> TestResult {
    const CAPACITY: usize = 1024 * 1024;
    let fixture = Fixture::limits(Limits {
        input_capacity: Some(CAPACITY),
        ..Default::default()
    })?;
    let mut definition = Fixture::sql("SELECT CAST(7 AS BIGINT UNSIGNED) AS value");
    definition.description = "metadata".repeat(8192);
    let prepared = fixture.prepare(&definition).await?;
    assert_eq!(prepared.images().count(), 0);
    let retained = fixture.engine.memory().input_reserved();
    assert!(retained >= definition.description.len());
    let weak = Arc::downgrade(&prepared.admission);
    let copy = prepared.clone();
    assert!(Arc::ptr_eq(&prepared.admission, &copy.admission));
    assert!(std::ptr::eq(prepared.resolved(), copy.resolved()));
    assert!(std::ptr::eq(prepared.sources(), copy.sources()));
    assert_eq!(fixture.engine.memory().input_reserved(), retained);
    let pressure = fixture.engine.memory().reserve_input(CAPACITY - retained)?;
    assert!(fixture.engine.memory().reserve_input(1).is_err());
    drop(prepared);
    assert!(weak.upgrade().is_some());
    assert!(fixture.engine.memory().reserve_input(1).is_err());
    drop(copy);
    assert!(weak.upgrade().is_none());
    assert_eq!(
        fixture.engine.memory().input_reserved(),
        CAPACITY - retained
    );
    drop(pressure);
    drop(fixture.engine.memory().reserve_input(CAPACITY)?);
    Ok(())
}

#[tokio::test]
async fn metadata_rejects_short_capacity() -> TestResult {
    let measured = Fixture::new()?;
    let mut definition = Fixture::sql("SELECT CAST(7 AS BIGINT UNSIGNED) AS value");
    definition.description = "retained metadata".repeat(4096);
    let prepared = measured.prepare(&definition).await?;
    let retained = measured.engine.memory().input_reserved();
    assert!(retained > definition.description.len());
    drop(prepared);
    assert_eq!(measured.engine.memory().input_reserved(), 0);
    let capacity = retained.checked_sub(1).ok_or("metadata fixture capacity")?;
    let fixture = Fixture::limits(Limits {
        input_capacity: Some(capacity),
        ..Default::default()
    })?;
    let before = fixture.engine.store().meta()?;
    let error = fixture
        .prepare(&definition)
        .await
        .err()
        .ok_or("short metadata capacity admitted")?;
    assert_eq!(
        crate::Failure::from(&error),
        crate::Failure::InputTooLarge,
        "{error:?}"
    );
    assert_eq!(fixture.engine.store().meta()?, before);
    assert_eq!(fixture.engine.memory().input_reserved(), 0);
    drop(fixture.engine.memory().reserve_input(capacity)?);
    Ok(())
}

#[tokio::test]
async fn admission_keeps_memory_scope() -> TestResult {
    let capacity = 128 * 1024;
    let fixture = Fixture::limits(Limits {
        input_capacity: Some(capacity),
        ..Default::default()
    })?;
    fixture.install(&Fixture::bundle())?;
    let control = AnalysisReadControl::default();
    let memory = fixture.engine.memory().scope();
    let observer = fixture.engine.memory().scope();
    let session = fixture.engine.session_on(
        araphor_data::AnalysisSelectionV1::tenant([1; 16]),
        &control,
        0,
        Arc::clone(&memory),
    )?;
    let definition = Fixture::definition();
    let prepared = session.prepare_definition(&definition).await?;
    let retained = fixture.engine.memory().input_reserved();
    assert!(retained > 1);
    drop(prepared);
    assert_eq!(fixture.engine.memory().input_reserved(), 0);
    let pressure = fixture
        .engine
        .memory()
        .reserve_input(capacity - retained + 1)?;
    let epoch = memory.capacity_epoch();
    let observed = observer.capacity_epoch();
    let error = session
        .prepare_definition(&definition)
        .await
        .err()
        .ok_or("scoped admission ignored pressure")?;
    assert_eq!(crate::Failure::from(&error), crate::Failure::Busy);
    assert_eq!(memory.capacity_epoch(), epoch);
    assert_ne!(observer.capacity_epoch(), observed);
    assert_eq!(fixture.engine.memory().input_reserved(), pressure.size());
    let waiting = memory.capacity_changed(epoch);
    tokio::pin!(waiting);
    assert!(futures_util::poll!(waiting.as_mut()).is_pending());
    drop(pressure);
    tokio::time::timeout(std::time::Duration::from_secs(30), waiting).await??;
    let prepared = session.prepare_definition(&definition).await?;
    assert_eq!(fixture.engine.memory().input_reserved(), retained);
    drop(prepared);
    assert_eq!(fixture.engine.memory().input_reserved(), 0);
    drop(fixture.engine.memory().reserve_input(capacity)?);
    Ok(())
}
