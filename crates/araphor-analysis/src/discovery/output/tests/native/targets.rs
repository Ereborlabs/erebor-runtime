use super::*;

impl Fixture {
    fn limits() -> TestResult<Limits> {
        let output = usize::try_from(8_u64 * 1024 * 1024 * 1024)?;
        Ok(Limits {
            input_capacity: Some(128 * 1024 * 1024),
            output_capacity: Some(output),
            global_evaluations: Some(1),
            tenant_evaluations: Some(1),
            ..Default::default()
        })
    }

    fn released(&self, before: &AnalysisStoreMetaV1) -> TestResult {
        assert_eq!(self.query.store().meta()?, *before);
        assert!(self
            .query
            .store()
            .active_managed(&araphor_data::AnalysisReadControl::default())?
            .1
            .is_empty());
        assert_eq!(self.query.memory().input_reserved(), 0);
        let permit = self.query.reserve_evaluation(Self::input()?.tenant_id)?;
        assert!(self
            .query
            .reserve_evaluation(Self::input()?.tenant_id)
            .is_err());
        drop(permit);
        let limits = self.query.limits();
        drop(
            self.query
                .memory()
                .reserve_input(limits.input_capacity.ok_or("input capacity")?)?,
        );
        drop(
            self.query
                .memory()
                .reserve_output(limits.output_capacity.ok_or("output capacity")?)?,
        );
        Ok(())
    }
}

#[tokio::test]
#[ignore = "requires source-built native artifacts in ARAPHOR_NATIVE_DIR"]
async fn native_atoms_match_wasm() -> TestResult {
    let wasm = Fixture::target(Target::Wasm, Fixture::limits()?)?;
    let native = Fixture::target(Target::Native, Fixture::limits()?)?;
    let before = [wasm.query.store().meta()?, native.query.store().meta()?];
    let input = Fixture::input()?;
    let mut missing = input.clone();
    missing.contexts.clear();
    let mut reordered = input.clone();
    reordered.records.reverse();
    reordered.contexts.reverse();
    reordered.records.extend(input.records.clone());
    let mut unknown = input.clone();
    unknown.coverage[0].state = DiscoveryCoverageStateV1::Unknown;
    unknown.coverage[0]
        .gap_reasons
        .push("FIXTURE_UNKNOWN".into());
    for manifest in [input, missing, reordered, unknown] {
        let (expected_call, expected) = wasm.atoms(&manifest).await?;
        let (actual_call, actual) = native.atoms(&manifest).await?;
        assert_eq!(
            serde_json::to_value(sdk::wire::Output::encode(
                expected_call.descriptor(),
                expected.evaluation(),
                expected.output()
            )?)?,
            serde_json::to_value(sdk::wire::Output::encode(
                actual_call.descriptor(),
                actual.evaluation(),
                actual.output()
            )?)?
        );
        let expected_result =
            DiscoveryOwner::recorded_result(&manifest, &expected_call, &expected)?;
        let actual_result = DiscoveryOwner::recorded_result(&manifest, &actual_call, &actual)?;
        assert_eq!(actual_result, expected_result);
        assert!(actual_result.snapshot.accepted_records > 0);
        assert!(!actual_result.snapshot.coverage.is_empty());
        assert!(
            !actual_result.snapshot.atoms.is_empty()
                || !actual_result.snapshot.unresolved.is_empty()
        );
        assert!(native
            .query
            .memory()
            .reserve_output(
                native
                    .query
                    .limits()
                    .output_capacity
                    .ok_or("output capacity")?
            )
            .is_err());
        drop(actual);
        drop(actual_call);
        drop(expected);
        drop(expected_call);
        wasm.released(&before[0])?;
        native.released(&before[1])?;
    }
    Ok(())
}

#[tokio::test]
#[ignore = "requires source-built native artifacts in ARAPHOR_NATIVE_DIR"]
async fn native_snapshots_match_wasm() -> TestResult {
    let wasm = Fixture::target(Target::Wasm, Fixture::limits()?)?;
    let native = Fixture::target(Target::Native, Fixture::limits()?)?;
    let before = [wasm.query.store().meta()?, native.query.store().meta()?];
    let manifest = Fixture::input()?;
    let mut first = manifest.clone();
    first.records.retain(|record| record.id.durable_cursor == 1);
    first
        .contexts
        .retain(|context| context.record_id.durable_cursor == 1);
    first.coverage[0].last_cursor = 1;
    first.coverage[0].expected_records = 1;
    let mut second = manifest.clone();
    second
        .records
        .retain(|record| record.id.durable_cursor != 1);
    second
        .contexts
        .retain(|context| context.record_id.durable_cursor != 1);
    second.coverage[0].first_cursor = 2;
    second.coverage[0].expected_records = 2;
    let mut outputs = Vec::new();
    for (fixture, metadata) in [(&wasm, &before[0]), (&native, &before[1])] {
        let first = fixture.recorded(&first).await?.snapshot;
        let second = fixture.recorded(&second).await?.snapshot;
        let merged = fixture.merged(&first, &second).await?;
        let groups = fixture.groups(&merged).await?;
        assert!(!groups.is_empty());
        let baseline = DiscoveryReviewedBaselineV1 {
            reviewer: "operator".into(),
            reviewed_utc_ns: 3000,
            forbidden: vec![merged.atoms[0].key.static_key.clone()],
            snapshot: merged.clone(),
        };
        let mut changed = manifest.clone();
        for context in &mut changed.contexts {
            context.image_digest = "replacement-image".into();
        }
        let changed = fixture.recorded(&changed).await?.snapshot;
        let comparison = fixture.comparison(&changed, &baseline).await?;
        assert!(!comparison.changed_identities.is_empty());
        outputs.push(serde_json::json!({"merged":merged,"groups":groups,"comparison":comparison}));
        fixture.released(metadata)?;
    }
    assert_eq!(outputs[0], outputs[1]);
    Ok(())
}
