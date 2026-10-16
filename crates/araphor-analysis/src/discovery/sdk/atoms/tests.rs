use super::*;

type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;

fn input() -> araphor_data::Result<DiscoveryInputManifestV1> {
    DiscoveryInputManifestV1::try_from(
        include_bytes!("../../../../../mithril-e2e/fixtures/discovery/manifest.json").as_slice(),
    )
}

#[test]
fn duplicate_context_projection() -> TestResult {
    let mut input = input()?;
    input.records.truncate(1);
    input.contexts.truncate(1);
    input.coverage[0].last_cursor = 1;
    input.coverage[0].expected_records = 1;
    let text = "\\\"".repeat(2048);
    input.contexts[0].subject_revision = text.clone();
    input.contexts[0].image_digest = text.clone();
    input.contexts[0].configuration_digest = text.clone();
    input.contexts[0].static_key.object_selector = text;
    let execution = crate::InstalledAnalysis::testing(None, input.tenant_id)?;
    let single = DiscoveryOwner::derive_recorded(&input, &execution)?;
    let record = input.records[0].clone();
    input.records.extend(std::iter::repeat_n(record, 1023));
    let repeated = DiscoveryOwner::derive_recorded(&input, &execution)?;
    assert_eq!(repeated.snapshot, single.snapshot);
    assert_eq!(repeated.duplicate_deliveries, 1023);
    let projected = Adapter::observation(&input, &input.records[0])?;
    assert!(!serde_json::to_string(&projected)?.contains("subject_revision"));
    Ok(())
}

#[test]
fn recorded_pages_match() -> TestResult {
    let mut input = input()?;
    let record = input.records[0].clone();
    let context = input.contexts[0].clone();
    input.records = (1..=129)
        .map(|cursor| {
            let mut record = record.clone();
            record.id.durable_cursor = cursor;
            record
        })
        .collect();
    input.contexts = input.records[..128]
        .iter()
        .map(|record| {
            let mut context = context.clone();
            context.record_id = record.id.clone();
            context
        })
        .collect();
    input.coverage[0].last_cursor = 129;
    input.coverage[0].expected_records = 129;
    input.exclusions = vec![DiscoveryUnresolvedV1 {
        record_id: input.records[127].id.clone(),
        reason: "EXPLICIT_EXCLUSION".into(),
    }];
    input.lifecycle = vec![DiscoveryLifecycleEntryV1 {
        case: DiscoveryLifecycleCaseV1::Startup,
        state: DiscoveryLifecycleStateV1::Recorded {
            records: vec![input.records[0].id.clone(), input.records[128].id.clone()],
        },
    }];
    input.records.extend(input.records.clone());
    input.records.reverse();
    input.contexts.reverse();
    let execution = crate::InstalledAnalysis::testing(None, input.tenant_id)?;
    let control = AnalysisReadControl::with_timeout(std::time::Duration::from_secs(60))?;
    let whole =
        DiscoveryOwner::derive_page(&input, &execution, &Adapter::revision(&input)?, &control)?;
    let paged = DiscoveryOwner::derive_recorded(&input, &execution)?;
    assert_eq!(paged, whole);
    assert_eq!(paged.duplicate_deliveries, 129);
    assert_eq!(paged.snapshot.accepted_records, 129);
    assert_eq!(paged.snapshot.included_records, 127);
    assert_eq!(paged.snapshot.excluded_records, 1);
    assert_eq!(paged.snapshot.unresolved_records, 1);
    assert_eq!(paged.snapshot.coverage, input.coverage);
    assert_eq!(
        paged.snapshot.atoms[0]
            .evidence_sample
            .iter()
            .map(|id| id.durable_cursor)
            .collect::<Vec<_>>(),
        (1..=8).collect::<Vec<_>>()
    );
    assert_eq!(paged.snapshot.lifecycle[0], input.lifecycle[0]);
    Ok(())
}

#[test]
fn discovery_exact_revision() -> TestResult {
    let mut input = input()?;
    let first = Adapter::revision(&input)?;
    let source = input.source_revision.clone();
    input.contexts[0].image_digest.push_str("-replacement");
    assert_eq!(input.source_revision, source);
    assert_ne!(Adapter::revision(&input)?, first);
    Ok(())
}

#[test]
fn recorded_rejects_host_changes() -> TestResult {
    let input = input()?;
    let execution = crate::InstalledAnalysis::testing(None, input.tenant_id)?;
    let result = DiscoveryOwner::derive_recorded(&input, &execution)?;
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
        assert!(Adapter::validate_recorded(&input, &candidate).is_err());
    }
    Ok(())
}

#[test]
fn recorded_rejects_coverage_upgrade() -> TestResult {
    let mut input = input()?;
    input.coverage[0].state = DiscoveryCoverageStateV1::Unknown;
    let execution = crate::InstalledAnalysis::testing(None, input.tenant_id)?;
    let mut result = DiscoveryOwner::derive_recorded(&input, &execution)?;
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
        Adapter::validate_recorded(&input, &result),
        Err(crate::Error::Data {
            source: araphor_data::Error::DiscoveryInvalid {
                field: "analysis coverage proof",
                ..
            }
        })
    ));
    Ok(())
}

#[test]
fn merge_groups_preserve_attribution() -> TestResult {
    let input = input()?;
    let execution = crate::InstalledAnalysis::testing(None, input.tenant_id)?;
    let snapshot = DiscoveryOwner::derive_recorded(&input, &execution)?.snapshot;
    let mut candidate = snapshot.clone();
    candidate.atoms[0].key.image_digest.push_str("-invented");
    candidate.validate()?;
    assert!(Adapter::validate_merge(&snapshot, &snapshot, &candidate).is_err());
    let mut groups = DiscoveryOwner::display_groups(&snapshot, &execution)?;
    groups[0].key.image_digest.push_str("-invented");
    assert!(Adapter::validate_groups(&snapshot, &groups).is_err());
    Ok(())
}

#[test]
fn comparison_keeps_source_proof() -> TestResult {
    let input = input()?;
    let execution = crate::InstalledAnalysis::testing(None, input.tenant_id)?;
    let snapshot = DiscoveryOwner::derive_recorded(&input, &execution)?.snapshot;
    let groups = DiscoveryOwner::display_groups(&snapshot, &execution)?;
    let validate = |value: &DiscoveryComparisonV1| {
        Adapter::validate_comparison(&snapshot, &snapshot, &groups, &groups, value)
    };
    let mut result = DiscoveryComparisonV1::default();
    validate(&result)?;
    result.added.push(groups[0].clone());
    validate(&result)?;
    result.added[0].count += 1;
    assert!(matches!(
        validate(&result),
        Err(crate::Error::Data {
            source: araphor_data::Error::DiscoveryInvalid {
                field: "analysis group reference",
                ..
            }
        })
    ));
    result.added.clear();
    result.new_resources.push(snapshot.atoms[0].key.clone());
    validate(&result)?;
    result.new_resources[0].generation += 1;
    assert!(matches!(
        validate(&result),
        Err(crate::Error::Data {
            source: araphor_data::Error::DiscoveryInvalid {
                field: "analysis resource reference",
                ..
            }
        })
    ));
    result.new_resources.clear();
    result.coverage_before = snapshot.coverage.clone();
    assert!(matches!(
        validate(&result),
        Err(crate::Error::Data {
            source: araphor_data::Error::DiscoveryInvalid {
                field: "analysis comparison proof",
                ..
            }
        })
    ));
    result.coverage_before.clear();
    result.lifecycle_before = snapshot.lifecycle.clone();
    assert!(matches!(
        validate(&result),
        Err(crate::Error::Data {
            source: araphor_data::Error::DiscoveryInvalid {
                field: "analysis comparison proof",
                ..
            }
        })
    ));
    Ok(())
}
