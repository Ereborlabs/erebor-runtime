use super::*;

#[tokio::test]
async fn recorded_rejects_forged_proof() -> TestResult {
    let fixture = Fixture::new()?;
    let input = Fixture::input()?;
    let (call, result) = fixture.atoms(&input).await?;
    let recorded = DiscoveryOwner::recorded_result(&input, &call, &result)?;
    let original = result.output().datasets.clone();
    let passthrough = Fixture::passthrough(&call)?;
    let (valid, returned) = passthrough.call("atoms", original.clone()).await?;
    assert_eq!(
        DiscoveryOwner::recorded_result(&input, &valid, &returned)?,
        recorded
    );
    for case in 0..3 {
        let mut outputs = original.clone();
        let (name, data) = match case {
            0 => {
                let mut atoms = recorded.snapshot.atoms.clone();
                atoms[0].key.image_digest.push_str("-invented");
                (
                    "atoms",
                    Rows::encode(&builtin::Discovery::port::<BehaviorAtomV1>("atoms"), &atoms)?,
                )
            }
            1 => {
                let mut lifecycle = recorded.snapshot.lifecycle.clone();
                lifecycle[0].state = DiscoveryLifecycleStateV1::Recorded {
                    records: recorded.snapshot.atoms[0].evidence_sample.clone(),
                };
                (
                    "lifecycle",
                    Rows::encode(
                        &builtin::Discovery::port::<DiscoveryLifecycleEntryV1>("lifecycle"),
                        &lifecycle,
                    )?,
                )
            }
            _ => {
                let mut counts = builtin::Counts {
                    duplicates: recorded.duplicate_deliveries,
                    accepted: recorded.snapshot.accepted_records,
                    included: recorded.snapshot.included_records,
                    unresolved: recorded.snapshot.unresolved_records,
                    excluded: recorded.snapshot.excluded_records,
                };
                counts.duplicates += 1;
                (
                    "counts",
                    Rows::encode(
                        &builtin::Discovery::port::<builtin::Counts>("counts"),
                        &[counts],
                    )?,
                )
            }
        };
        *outputs
            .iter_mut()
            .find(|data| data.name == name)
            .ok_or("output")? = data;
        let (call, result) = passthrough.call("atoms", outputs).await?;
        assert!(
            DiscoveryOwner::recorded_result(&input, &call, &result).is_err(),
            "{case}"
        );
    }
    Ok(())
}

#[tokio::test]
async fn recorded_rejects_coverage_upgrade() -> TestResult {
    let fixture = Fixture::new()?;
    let mut input = Fixture::input()?;
    input.coverage[0].state = DiscoveryCoverageStateV1::Unknown;
    let (call, result) = fixture.atoms(&input).await?;
    let mut recorded = DiscoveryOwner::recorded_result(&input, &call, &result)?;
    let mut outputs = result.output().datasets.clone();
    let passthrough = Fixture::passthrough(&call)?;
    let (valid, returned) = passthrough.call("atoms", outputs.clone()).await?;
    assert_eq!(
        DiscoveryOwner::recorded_result(&input, &valid, &returned)?,
        recorded
    );
    recorded.snapshot.coverage[0].state = DiscoveryCoverageStateV1::Healthy;
    recorded.snapshot.coverage[0].gap_reasons.clear();
    let data = Rows::encode(
        &builtin::Discovery::port::<DiscoveryCoverageV1>("coverage"),
        &recorded.snapshot.coverage,
    )?;
    *outputs
        .iter_mut()
        .find(|data| data.name == "coverage")
        .ok_or("coverage")? = data;
    let (call, result) = passthrough.call("atoms", outputs).await?;
    assert!(DiscoveryOwner::recorded_result(&input, &call, &result).is_err());
    Ok(())
}

#[tokio::test]
async fn results_reject_foreign_attribution() -> TestResult {
    let fixture = Fixture::new()?;
    let input = Fixture::input()?;
    let (call, result) = fixture.atoms(&input).await?;
    let mut foreign = input.clone();
    foreign.tenant_id = [99; 16];
    assert!(matches!(
        DiscoveryOwner::recorded_result(&foreign, &call, &result),
        Err(crate::Error::Data {
            source: araphor_data::Error::Package {
                code: Code::Denied,
                ..
            }
        })
    ));
    let snapshot = DiscoveryOwner::recorded_result(&input, &call, &result)?.snapshot;
    let (other, _) = fixture
        .call(
            "groups",
            vec![
                Fixture::data("groups", "atoms", &snapshot.atoms)?,
                Fixture::data("groups", "coverage", &snapshot.coverage)?,
            ],
        )
        .await?;
    assert!(!result.belongs_to(&other));
    assert!(DiscoveryOwner::recorded_result(&input, &other, &result).is_err());
    Ok(())
}

#[tokio::test]
async fn comparison_requires_trusted_inputs() -> TestResult {
    let fixture = Fixture::new()?;
    let snapshot = fixture.recorded(&Fixture::input()?).await?.snapshot;
    let groups = fixture.groups(&snapshot).await?;
    let states = [
        builtin::MatchState {
            coverage: snapshot.coverage.clone(),
            lifecycle: snapshot.lifecycle.clone(),
        },
        builtin::MatchState {
            coverage: snapshot.coverage.clone(),
            lifecycle: snapshot.lifecycle.clone(),
        },
    ];
    let resources = snapshot
        .atoms
        .iter()
        .map(|atom| atom.key.clone())
        .collect::<Vec<_>>();
    let (call, result) = fixture
        .call(
            "compare",
            vec![
                Fixture::data("compare", "groups", &Fixture::sides([&groups, &groups]))?,
                Fixture::data(
                    "compare",
                    "resources",
                    &Fixture::sides([&resources, &resources]),
                )?,
                Fixture::data::<DiscoveryPolicyKeyV1>("compare", "forbidden", &[])?,
                Fixture::data("compare", "states", &states)?,
            ],
        )
        .await?;
    let baseline = DiscoveryReviewedBaselineV1 {
        snapshot: snapshot.clone(),
        reviewer: "operator".into(),
        reviewed_utc_ns: 3000,
        forbidden: Vec::new(),
    };
    let comparison =
        DiscoveryOwner::comparison_result(&snapshot, &baseline, &groups, &groups, &call, &result)?;
    assert_eq!(comparison, DiscoveryComparisonV1::default());
    let mut forged = groups.clone();
    forged[0].count += 1;
    for (current, prior) in [(&forged, &groups), (&groups, &forged)] {
        assert!(matches!(
            DiscoveryOwner::comparison_result(&snapshot, &baseline, current, prior, &call, &result,),
            Err(crate::Error::Data {
                source: araphor_data::Error::DiscoveryInvalid {
                    field: "analysis group evidence",
                    ..
                }
            })
        ));
    }
    for case in 0..4 {
        let mut invalid = baseline.clone();
        match case {
            0 => invalid.reviewer.clear(),
            1 => invalid.reviewer = "x".repeat(257),
            2 => invalid.reviewed_utc_ns = 0,
            _ => invalid.snapshot.tenant_id = [99; 16],
        }
        assert!(
            DiscoveryOwner::comparison_result(
                &snapshot, &invalid, &groups, &groups, &call, &result
            )
            .is_err(),
            "{case}"
        );
    }
    Ok(())
}
