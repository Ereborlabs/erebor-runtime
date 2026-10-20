use super::*;

use serde::Deserialize;

type TestResult<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

#[derive(Deserialize)]
struct RecordedFixture {
    original: DiscoveryRecordedResultV1,
}
#[derive(Deserialize)]
struct GroupFixture {
    groups: Vec<BehaviorDisplayGroupV1>,
}

fn fixture() -> TestResult<(
    DiscoveryInputManifestV1,
    DiscoveryRecordedResultV1,
    Vec<BehaviorDisplayGroupV1>,
)> {
    let input =
        DiscoveryInputManifestV1::try_from(include_bytes!("tests/fixtures/input.json").as_slice())?;
    let recorded: RecordedFixture =
        serde_json::from_slice(include_bytes!("tests/fixtures/atoms.json"))?;
    let groups: GroupFixture = serde_json::from_slice(include_bytes!("tests/fixtures/merge.json"))?;
    input.validate_result(&recorded.original)?;
    recorded.original.snapshot.validate_groups(&groups.groups)?;
    Ok((input, recorded.original, groups.groups))
}

#[test]
fn recorded_rejects_host_changes() -> TestResult {
    let (input, result, _) = fixture()?;
    let mut identity = result.clone();
    identity.snapshot.atoms[0]
        .key
        .subject_revision
        .push_str("-invented");
    let mut physical = result.clone();
    let key = &mut physical.snapshot.atoms[0].key;
    (
        key.physical_result,
        key.effect.decision,
        key.effect.kernel_result,
    ) = match key.physical_result {
        DiscoveryPhysicalResultV1::Prevented => (DiscoveryPhysicalResultV1::Unknown, 0, 0),
        DiscoveryPhysicalResultV1::Unknown => (DiscoveryPhysicalResultV1::Prevented, 1, -13),
    };
    let mut lifecycle = result.clone();
    lifecycle.snapshot.lifecycle[0].state = DiscoveryLifecycleStateV1::Recorded {
        records: result.snapshot.atoms[0].evidence_sample.clone(),
    };
    for candidate in [identity, physical, lifecycle] {
        candidate.snapshot.validate()?;
        assert!(input.validate_result(&candidate).is_err());
    }
    Ok(())
}

#[test]
fn recorded_rejects_coverage_upgrade() -> TestResult {
    let (mut input, result, _) = fixture()?;
    input.coverage[0].state = DiscoveryCoverageStateV1::Unknown;
    let mut result = result;
    result.snapshot.coverage[0].state = DiscoveryCoverageStateV1::Unknown;
    let unknown = result
        .snapshot
        .coverage
        .iter_mut()
        .find(|range| range.state == DiscoveryCoverageStateV1::Unknown)
        .ok_or("unknown range")?;
    unknown.state = DiscoveryCoverageStateV1::Healthy;
    unknown.gap_reasons.clear();
    result.snapshot.validate()?;
    assert!(matches!(
        input.validate_result(&result),
        Err(crate::Error::DiscoveryInvalid {
            field: "analysis coverage proof",
            ..
        })
    ));
    Ok(())
}

#[test]
fn merge_groups_preserve_attribution() -> TestResult {
    let (_, result, _) = fixture()?;
    let snapshot = result.snapshot;
    let mut candidate = snapshot.clone();
    candidate.atoms[0].key.image_digest.push_str("-invented");
    candidate.validate()?;
    assert!(snapshot.validate_merge(&snapshot, &candidate).is_err());
    let (_, _, mut groups) = fixture()?;
    groups[0].key.image_digest.push_str("-invented");
    assert!(snapshot.validate_groups(&groups).is_err());
    Ok(())
}

#[test]
fn comparison_keeps_source_proof() -> TestResult {
    let (_, result, _) = fixture()?;
    let snapshot = result.snapshot;
    let (_, _, groups) = fixture()?;
    let validate = |value: &DiscoveryComparisonV1| {
        snapshot.validate_comparison(&snapshot, &groups, &groups, value)
    };
    let mut result = DiscoveryComparisonV1::default();
    validate(&result)?;
    result.added.push(groups[0].clone());
    validate(&result)?;
    result.added[0].count += 1;
    assert!(matches!(
        validate(&result),
        Err(crate::Error::DiscoveryInvalid {
            field: "analysis group reference",
            ..
        })
    ));
    result.added.clear();
    result.new_resources.push(snapshot.atoms[0].key.clone());
    validate(&result)?;
    result.new_resources[0].generation += 1;
    assert!(matches!(
        validate(&result),
        Err(crate::Error::DiscoveryInvalid {
            field: "analysis resource reference",
            ..
        })
    ));
    result.new_resources.clear();
    result.coverage_before = snapshot.coverage.clone();
    assert!(matches!(
        validate(&result),
        Err(crate::Error::DiscoveryInvalid {
            field: "analysis comparison proof",
            ..
        })
    ));
    result.coverage_before.clear();
    result.lifecycle_before = snapshot.lifecycle.clone();
    assert!(matches!(
        validate(&result),
        Err(crate::Error::DiscoveryInvalid {
            field: "analysis comparison proof",
            ..
        })
    ));
    Ok(())
}
