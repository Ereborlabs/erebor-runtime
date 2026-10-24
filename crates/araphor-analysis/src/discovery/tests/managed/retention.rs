use super::*;

use araphor_data::{AnalysisGapV1, EvidenceRetentionOwner, RetentionLimitsV1, Selection};

const RETENTION: RetentionLimitsV1 = RetentionLimitsV1 {
    raw_max_age_ns: Some(50),
    raw_max_bytes: None,
};

impl Fixture {
    fn expire_records(&self, count: u64, expired: &[u64]) -> TestResult<Vec<AnalysisGapV1>> {
        for cursor in 1..=count {
            self.append_at(cursor, if expired.contains(&cursor) { 1 } else { 1000 })?;
            self.store.backup(
                &self
                    ._directory
                    .path()
                    .join(format!("data/backups/before-retention-{cursor}")),
            )?;
        }
        let retained = EvidenceRetentionOwner::new(&self.store).retain(&self.source, 100)?;
        assert_eq!(retained.removed_records as usize, expired.len());
        Ok(expired
            .iter()
            .map(|cursor| AnalysisGapV1 {
                first_cursor: *cursor,
                last_cursor: *cursor,
                commit_revision: retained.commit_revision,
            })
            .collect())
    }

    fn retained_profile(
        &self,
        records: &[u64],
        gaps: &[AnalysisGapV1],
        cursor: u64,
    ) -> TestResult<DiscoveryProfileV1> {
        let profile = self.profile()?.ok_or("the retained profile is absent")?;
        assert_eq!(profile.snapshot.accepted_records, records.len() as u64);
        assert_eq!(
            profile.snapshot.included_records
                + profile.snapshot.unresolved_records
                + profile.snapshot.excluded_records,
            records.len() as u64
        );
        assert_eq!(
            profile.input_bytes,
            records
                .iter()
                .map(|cursor| self.records[cursor].wire_record.len() as u64)
                .sum::<u64>()
        );
        let covered = profile
            .snapshot
            .coverage
            .iter()
            .flat_map(|range| {
                assert_eq!(
                    range.expected_records,
                    range.last_cursor - range.first_cursor + 1
                );
                range.first_cursor..=range.last_cursor
            })
            .collect::<Vec<_>>();
        assert_eq!(covered, records);
        assert_eq!(profile.gaps, gaps);
        assert_eq!(profile.incomplete, !gaps.is_empty());
        assert_eq!(self.store.processor_gaps(&self.scope(), 0)?, gaps);
        let health = self
            .store
            .processor_health(&self.scope())?
            .ok_or("the retained processor is absent")?;
        assert_eq!(health.consumed_cursor, cursor);
        if health.accepted_cursor == cursor {
            assert_eq!(health.incomplete, !gaps.is_empty());
        }
        assert_eq!(
            health.resume_floor,
            gaps.iter().map(|gap| gap.last_cursor).max().unwrap_or(0)
        );
        Ok(profile)
    }

    fn reopen(self) -> TestResult<Self> {
        let Self {
            store,
            query,
            source,
            records,
            _directory,
        } = self;
        let limits = query.limits().clone();
        drop((query, store));
        let store = Arc::new(AnalysisStore::open_with_limits(
            _directory.path().join("data"),
            RETENTION,
            Default::default(),
        )?);
        let mut query = Engine::new(Arc::clone(&store), limits)?;
        Arc::get_mut(&mut query)
            .ok_or("the reopened Query is already shared")?
            .register_views(araphor_analysis_builtins::discovery::sql::VIEWS_SQL)?;
        Ok(Self {
            store,
            query,
            source,
            records,
            _directory,
        })
    }

    fn filtered_image(predicate: &str) -> TestResult<PackageBundleV1> {
        let mut image = Package::discovery_bundle()?;
        image.root.revision = "retained-filter".into();
        image.artifacts[0].descriptor.revision = "retained-filter".into();
        let input = image.artifacts[0].descriptor.exports[0]
            .inputs
            .iter_mut()
            .find(|input| input.port.name == "events")
            .ok_or("the event input is absent")?;
        let columns = input
            .port
            .schema
            .fields()
            .iter()
            .map(|field| field.name().as_str())
            .collect::<Vec<_>>()
            .join(", ");
        input.source =
            sdk::InputSource::Query(format!("SELECT {columns} FROM events WHERE {predicate}"));
        Ok(image)
    }
}

#[tokio::test]
async fn managed_expired_ranges() -> TestResult {
    for (expired, retained) in [
        (vec![1], vec![2, 3]),
        (vec![2], vec![1, 3]),
        (vec![1, 3], vec![2]),
    ] {
        let fixture = Fixture::retention(Limits::default(), RETENTION)?;
        let gaps = fixture.expire_records(3, &expired)?;
        let source = fixture
            .store
            .source_receipt(&fixture.source)?
            .ok_or("the retained source is absent")?;
        assert_eq!(source.contiguous_cursor, 3);
        assert_eq!(source.retained_floor, u64::from(expired.contains(&1)));
        let instance = fixture.managed("retained-ranges").await?;
        assert_eq!(
            instance.admitted().grant.selection.sources,
            Selection::Exact(vec![fixture.source.clone()])
        );
        let control = AnalysisReadControl::default();
        let receipt = instance
            .run(Fixture::request("retained-ranges")?, &control)
            .await?;
        let result = receipt
            .results
            .values()
            .next()
            .ok_or("the retained call is absent")?;
        let evaluation =
            fixture
                .store
                .managed_evaluation(instance.admitted(), &result.result_id, &control)?;
        let events = evaluation
            .inputs
            .iter()
            .find(|input| input.data.name == "events")
            .ok_or("the retained event input is absent")?;
        assert_eq!(events.coverage.state, sdk::CoverageState::Gapped);
        assert!(events
            .coverage
            .limits
            .iter()
            .any(|reason| reason == "SOURCE_GAPS"));
        assert_eq!(
            events
                .data
                .batches
                .iter()
                .map(RecordBatch::num_rows)
                .sum::<usize>(),
            retained.len()
        );
        fixture.retained_profile(&retained, &gaps, 3)?;
        assert_eq!(fixture.store.source_receipt(&fixture.source)?, Some(source));
        drop(evaluation);
        drop(instance);
        fixture.released()?;
    }
    Ok(())
}

#[tokio::test]
async fn managed_expired_bootstrap() -> TestResult {
    let fixture = Fixture::retention(Limits::default(), RETENTION)?;
    let gaps = fixture.expire_records(1, &[1])?;
    let instance = fixture.managed("retained-bootstrap").await?;
    let control = AnalysisReadControl::default();
    instance
        .run(Fixture::request("expired-bootstrap")?, &control)
        .await?;
    let original = fixture.retained_profile(&[], &gaps, 1)?;
    let body = fixture
        .store
        .read_result(fixture.source.tenant_id, &original.profile_id)?
        .ok_or("the bootstrap profile body is absent")?;
    drop(instance);
    fixture.released()?;
    let fixture = fixture.reopen()?;
    assert_eq!(fixture.profile()?, Some(original.clone()));
    assert_eq!(fixture.store.processor_gaps(&fixture.scope(), 0)?, gaps);
    assert_eq!(
        fixture
            .store
            .read_result(fixture.source.tenant_id, &original.profile_id)?,
        Some(body.clone())
    );
    let host = crate::InstanceHost::new(
        Arc::clone(&fixture.query),
        Arc::new(Authority(watch::channel(0).0)),
    );
    let crate::instance::Restored::Present(instance) = host
        .restore(fixture.source.tenant_id, "retained-bootstrap", &control)
        .await?
    else {
        return Err("the bootstrap instance is absent after reopen".into());
    };
    fixture.append(2)?;
    instance
        .run(Fixture::request("retained-after-reopen")?, &control)
        .await?;
    let resumed = fixture.retained_profile(&[2], &gaps, 2)?;
    assert_eq!(resumed.interval_id, original.interval_id);
    assert_eq!(
        fixture
            .store
            .read_result(fixture.source.tenant_id, &original.profile_id)?,
        Some(body)
    );
    let running = host
        .start(
            Arc::clone(&instance),
            instance.admitted().lifecycle,
            &control,
        )
        .await?;
    let mut stream = running.subscribe(
        Arc::new(AnalysisReadControl::default()),
        Fixture::request("retained-witness")?.witness_expiry,
        running.admitted().lifecycle,
    )?;
    assert!(futures_util::poll!(stream.next()).is_pending());
    assert_eq!(fixture.profile()?, Some(resumed));
    fixture.append(3)?;
    tokio::time::timeout(Duration::from_secs(90), async {
        loop {
            let _receipt = stream
                .next()
                .await
                .ok_or("the retained subscription ended")??;
            if fixture
                .store
                .processor_health(&fixture.scope())?
                .is_some_and(|health| health.consumed_cursor == 3)
            {
                return Ok::<_, Box<dyn std::error::Error + Send + Sync>>(());
            }
        }
    })
    .await??;
    fixture.retained_profile(&[2, 3], &gaps, 3)?;
    assert!(futures_util::poll!(stream.next()).is_pending());
    stream.cancel_and_join(&control).await?;
    drop((running, instance, host));
    fixture.released()?;
    Ok(())
}

#[tokio::test]
async fn managed_expired_tail() -> TestResult {
    for sealed in [false, true] {
        let fixture = Fixture::retention(Limits::default(), RETENTION)?;
        fixture.append_at(1, 1)?;
        let control = AnalysisReadControl::default();
        let initial = fixture.managed("retained-tail").await?;
        initial
            .run(Fixture::request("retained-prefix")?, &control)
            .await?;
        let previous = fixture.profile()?.ok_or("the tail prefix is absent")?;
        assert_eq!(previous.snapshot.accepted_records, 1);
        let instance = if sealed {
            let mut image = Package::discovery_bundle()?;
            image.root.revision = "retained-sealed".into();
            image.artifacts[0].descriptor.revision = "retained-sealed".into();
            let next = fixture.managed_image("retained-sealed", image).await?;
            next.run(Fixture::request("retained-seal")?, &control)
                .await?;
            let closed = fixture.profile()?.ok_or("the sealed prefix is absent")?;
            assert!(closed.sealed);
            assert_eq!(closed.snapshot, previous.snapshot);
            assert_eq!(closed.interval_id, previous.interval_id);
            next
        } else {
            Arc::clone(&initial)
        };
        let previous = fixture.profile()?.ok_or("the current prefix is absent")?;
        let body = fixture
            .store
            .read_result(fixture.source.tenant_id, &previous.profile_id)?
            .ok_or("the prefix body is absent")?;
        fixture
            .store
            .backup(&fixture._directory.path().join("data/backups/pinned-prefix"))?;
        fixture.append_at(2, 1)?;
        let expired = EvidenceRetentionOwner::new(&fixture.store).retain(&fixture.source, 100)?;
        assert_eq!(expired.removed_records, 1);
        assert_eq!(expired.retained_floor, 0);
        let retained = fixture.store.read_page(&fixture.source, 1)?;
        assert_eq!(retained.records.len(), 1);
        assert_eq!(retained.records[0].cursor, 1);
        let gaps = [AnalysisGapV1 {
            first_cursor: 2,
            last_cursor: 2,
            commit_revision: expired.commit_revision,
        }];
        instance
            .run(Fixture::request("retained-tail-gap")?, &control)
            .await?;
        let profile = fixture.retained_profile(if sealed { &[] } else { &[1] }, &gaps, 2)?;
        if sealed {
            assert_ne!(profile.interval_id, previous.interval_id);
            assert_eq!(profile.revision, 1);
        } else {
            assert_eq!(profile.interval_id, previous.interval_id);
            assert_eq!(profile.revision, previous.revision + 1);
        }
        assert_eq!(
            fixture
                .store
                .read_result(fixture.source.tenant_id, &previous.profile_id)?,
            Some(body)
        );
        drop((instance, initial));
        fixture.released()?;
    }
    Ok(())
}

#[tokio::test]
async fn managed_expiry_respects_selection() -> TestResult {
    let bin = "date_bin(INTERVAL '2 seconds', CURRENT_TIMESTAMP, TIMESTAMP '1970-01-01')";
    let window = format!("received_at >= {bin} AND received_at < {bin} + INTERVAL '2 seconds'");
    for (predicate, time, cursor) in [
        ("source_cursor <= 2", None, 2),
        ("source_cursor < 1", None, 0),
        (window.as_str(), Some(10_000_000_000), 0),
    ] {
        let fixture = Fixture::retention(Limits::default(), RETENTION)?;
        let expired = fixture.expire_records(3, &[3])?;
        let instance = fixture
            .managed_image("retained-selection", Fixture::filtered_image(predicate)?)
            .await?;
        let mut request = Fixture::request("retained-selection")?;
        if let Some(time) = time {
            request.time_utc_ns = time;
            request.witness_expiry = time + 7 * 24 * 60 * 60 * 1_000_000_000;
        }
        instance
            .run(request, &AnalysisReadControl::default())
            .await?;
        assert!(fixture
            .store
            .processor_gaps(&fixture.scope(), 0)?
            .is_empty());
        assert_eq!(
            fixture
                .store
                .processor_health(&fixture.scope())?
                .ok_or("the selected processor is absent")?
                .consumed_cursor,
            cursor
        );
        if cursor == 2 {
            fixture.retained_profile(&[1, 2], &[], 2)?;
        }
        let health = fixture
            .store
            .processor_health(&fixture.scope())?
            .ok_or("the selected processor is absent")?;
        assert_eq!(
            health.state,
            araphor_data::ProcessorStateV1::ExpiredInput(expired[0])
        );
        assert!(health.incomplete);
        drop(instance);
        fixture.released()?;
    }
    let fixture = Fixture::retention(Limits::default(), RETENTION)?;
    let _expired = fixture.expire_records(3, &[1])?;
    let instance = fixture
        .managed_image(
            "retained-omission",
            Fixture::filtered_image("source_cursor = 3")?,
        )
        .await?;
    let failure = instance
        .run(
            Fixture::request("retained-omission")?,
            &AnalysisReadControl::default(),
        )
        .await
        .err()
        .ok_or("the retained cursor omission was accepted")?;
    assert!(
        format!("{failure:?}").contains("input frontier"),
        "{failure:?}"
    );
    assert!(fixture.profile()?.is_none());
    assert!(fixture
        .store
        .processor_gaps(&fixture.scope(), 0)?
        .is_empty());
    let health = fixture
        .store
        .processor_health(&fixture.scope())?
        .ok_or("the omitted processor is absent")?;
    assert_eq!((health.consumed_cursor, health.resume_floor), (0, 0));
    drop(instance);
    fixture.released()?;
    Ok(())
}
