use super::*;

type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;

fn input() -> Result<DiscoveryInputManifestV1> {
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
    let single = DiscoveryOwner::derive_recorded(&input)?;
    let record = input.records[0].clone();
    input.records.extend(std::iter::repeat_n(record, 1023));
    let repeated = DiscoveryOwner::derive_recorded(&input)?;
    assert_eq!(repeated.snapshot, single.snapshot);
    assert_eq!(repeated.duplicate_deliveries, 1023);
    let adapter = Adapter::new(input.records.iter().map(|record| &record.id));
    let projected = adapter.observation(&input, &input.records[0])?;
    assert!(!serde_json::to_string(&projected)?.contains("subject_revision"));
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
