use araphor_data::DiscoveryReplayV1;

use super::*;

#[tokio::test]
async fn profile_replay_keeps_capture() -> TestResult {
    let fixture = Fixture::new(Limits::default())?;
    fixture.append(1)?;
    let owner = fixture.owner(AnalysisSelectionV1::tenant(fixture.source.tenant_id))?;
    let control = AnalysisReadControl::default();
    let instance = owner
        .admit(&fixture.source, &control)
        .await?
        .ok_or("Profile instance")?;
    let mut input = Fixture::request("original")?;
    input.seed = Some(17);
    let receipt = instance.run(input.clone(), &control).await?;
    let original = fixture.profile()?.ok_or("original profile")?;
    let producer = owner.installed_refs(&original, &control).await?;
    assert_eq!(producer.result, receipt.results[&producer.call]);
    assert_eq!(producer.generation, instance.admitted().generation);
    assert_eq!(producer.spec, instance.admitted().spec);
    let evaluation = fixture.store.managed_evaluation(
        instance.admitted(),
        &producer.result.result_id,
        &control,
    )?;
    assert_eq!(evaluation.context.id, input.id);
    assert_eq!(evaluation.context.time_utc_ns, input.time_utc_ns as i64);
    assert_eq!(evaluation.context.seed, input.seed);
    let evidence = fixture.store.package_evidence(
        fixture.source.tenant_id,
        std::slice::from_ref(&original.profile_id),
    )?;
    fixture.append(2)?;
    instance.run(Fixture::request("next")?, &control).await?;
    let current = fixture.profile()?.ok_or("current profile")?;
    assert_ne!(current.profile_id, original.profile_id);
    let before = fixture.store.meta()?;
    let health = fixture.store.processor_health(&fixture.scope())?;
    let history = fixture.store.managed_history(
        &instance.admitted().grant.selection,
        &producer.spec.id,
        &control,
    )?;
    assert_eq!(
        owner.replay(&original, &control).await?,
        DiscoveryReplayV1::Available(Box::new(original.snapshot.clone()))
    );
    assert_eq!(fixture.store.meta()?, before);
    assert_eq!(fixture.store.processor_health(&fixture.scope())?, health);
    assert_eq!(fixture.profile()?, Some(current));
    assert_eq!(
        fixture.store.managed_history(
            &instance.admitted().grant.selection,
            &producer.spec.id,
            &control
        )?,
        history
    );
    assert_eq!(
        fixture.store.package_evidence(
            fixture.source.tenant_id,
            std::slice::from_ref(&original.profile_id)
        )?,
        evidence
    );
    let mut changed = original.clone();
    changed.facts_revision += 1;
    assert!(owner.installed_refs(&changed, &control).await.is_err());
    assert!(owner.replay(&changed, &control).await.is_err());
    assert_eq!(fixture.store.meta()?, before);
    drop((evaluation, instance, owner));
    fixture.released()?;
    Ok(())
}

#[tokio::test]
async fn closed_replay_keeps_origin() -> TestResult {
    let fixture = Fixture::new(Limits::default())?;
    fixture.append(1)?;
    let first = fixture
        .managed_image("replay-old", Package::discovery_bundle()?)
        .await?;
    let control = AnalysisReadControl::default();
    let original = first.run(Fixture::request("original")?, &control).await?;
    let previous = fixture.profile()?.ok_or("original profile")?;
    fixture.append(2)?;
    let mut image = Package::discovery_bundle()?;
    image.root.revision = "replay-new".into();
    image.artifacts[0].descriptor.revision = "replay-new".into();
    let next = fixture.managed_image("replay-new", image).await?;
    let close = next.run(Fixture::request("close")?, &control).await?;
    let closed = fixture.profile()?.ok_or("closed profile")?;
    assert!(closed.sealed);
    assert_eq!(closed.snapshot, previous.snapshot);
    let owner = fixture.owner(AnalysisSelectionV1::tenant(fixture.source.tenant_id))?;
    let producer = owner.installed_refs(&closed, &control).await?;
    assert_eq!(producer.spec.id, "replay-old");
    assert_eq!(producer.result, original.results[&producer.call]);
    assert!(!close
        .results
        .values()
        .any(|reference| reference == &producer.result));
    let before = fixture.store.meta()?;
    assert_eq!(
        owner.replay(&closed, &control).await?,
        DiscoveryReplayV1::Available(Box::new(previous.snapshot))
    );
    assert_eq!(fixture.store.meta()?, before);
    drop((first, next, owner));
    fixture.released()?;
    Ok(())
}

#[tokio::test]
async fn replay_survives_raw_retention() -> TestResult {
    let mut fixture = Fixture::new(Limits::default())?;
    fixture.store = Arc::new(AnalysisStore::open_with_limits(
        fixture._directory.path().join("retained"),
        araphor_data::RetentionLimitsV1 {
            raw_max_age_ns: Some(1),
            ..Default::default()
        },
        Default::default(),
    )?);
    fixture.store.install_package_image(
        fixture.source.tenant_id,
        &PackageBundle::try_from(Package::discovery_bundle()?)?,
        || Ok(()),
    )?;
    let mut query = Engine::new(
        Arc::clone(&fixture.store),
        Limits {
            global_streams: Some(2),
            tenant_streams: Some(2),
            ..Default::default()
        },
    )?;
    Arc::get_mut(&mut query)
        .ok_or("retained Query already shared")?
        .register_views(araphor_analysis_builtins::discovery::sql::VIEWS_SQL)?;
    fixture.query = query;
    fixture.append(1)?;
    let owner = fixture.owner(AnalysisSelectionV1::tenant(fixture.source.tenant_id))?;
    let control = AnalysisReadControl::default();
    let instance = owner
        .admit(&fixture.source, &control)
        .await?
        .ok_or("retained Profile instance")?;
    let input = Fixture::request("retained")?;
    instance.run(input.clone(), &control).await?;
    let profile = fixture.profile()?.ok_or("retained profile")?;
    let retained = araphor_data::EvidenceRetentionOwner::new(&fixture.store).retain(
        &fixture.source,
        input
            .witness_expiry
            .checked_add(1)
            .ok_or("retention time")?,
    )?;
    assert_eq!(retained.removed_records, 1);
    let before = fixture.store.meta()?;
    let health = fixture.store.processor_health(&fixture.scope())?;
    assert_eq!(
        owner.replay(&profile, &control).await?,
        DiscoveryReplayV1::Available(Box::new(profile.snapshot.clone()))
    );
    assert_eq!(fixture.store.meta()?, before);
    assert_eq!(fixture.store.processor_health(&fixture.scope())?, health);
    assert_eq!(fixture.profile()?, Some(profile));
    drop((instance, owner));
    fixture.released()?;
    Ok(())
}

#[tokio::test]
async fn replay_distinguishes_missing_inputs() -> TestResult {
    for case in 0..3 {
        let fixture = Fixture::new(Limits::default())?;
        fixture.append(1)?;
        let owner = fixture.owner(AnalysisSelectionV1::tenant(fixture.source.tenant_id))?;
        let control = AnalysisReadControl::default();
        let instance = owner
            .admit(&fixture.source, &control)
            .await?
            .ok_or("missing Profile instance")?;
        let receipt = instance
            .run(Fixture::request("original")?, &control)
            .await?;
        let profile = fixture.profile()?.ok_or("missing replay profile")?;
        let result = &receipt
            .results
            .values()
            .next()
            .ok_or("missing replay call")?
            .result_id;
        match case {
            0 => fixture.store.fault_write("DELETE FROM managed_arrow WHERE result_id = ? AND role = 'input'", &[result])?,
            1 => {
                let image = &instance.admitted().spec.definition.images[0].image;
                fixture.store.fault_write("DELETE FROM package_images WHERE tenant_id = ? AND package_id = ? AND revision = ?", &[&fixture.source.tenant_id.as_slice(), &image.package_id, &image.revision])?;
            }
            _ => fixture.store.fault_write("UPDATE managed_arrow SET ipc = 'invalid'::BLOB WHERE result_id = ? AND role = 'input'", &[result])?,
        }
        let before = fixture.store.meta()?;
        let health = fixture.store.processor_health(&fixture.scope())?;
        let replayed = owner.replay(&profile, &control).await;
        if case == 2 {
            assert!(
                replayed.is_err(),
                "malformed input was treated as unavailable"
            );
        } else {
            assert_eq!(
                replayed?,
                DiscoveryReplayV1::Unavailable {
                    first_cursor: profile
                        .snapshot
                        .coverage
                        .iter()
                        .map(|range| range.first_cursor)
                        .min()
                        .unwrap_or(0),
                    last_cursor: profile
                        .snapshot
                        .coverage
                        .iter()
                        .map(|range| range.last_cursor)
                        .max()
                        .unwrap_or(0),
                    reason: if case == 0 {
                        "FROZEN_INPUT_UNAVAILABLE"
                    } else {
                        "FROZEN_PACKAGES_UNAVAILABLE"
                    }
                    .into(),
                }
            );
        }
        assert_eq!(fixture.store.meta()?, before);
        assert_eq!(fixture.store.processor_health(&fixture.scope())?, health);
        assert_eq!(fixture.profile()?, Some(profile));
        drop((instance, owner));
        fixture.released()?;
    }
    Ok(())
}
