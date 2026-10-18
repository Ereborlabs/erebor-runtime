use std::sync::Arc;

use araphor_data::*;

type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;

fn result_row(store: &AnalysisStore, id: &str) -> araphor_data::Result<(Vec<u8>, Vec<u8>, u64)> {
    store.frozen_result(id)
}

struct NoContext;

impl crate::DiscoveryContextProvider for NoContext {
    fn context(
        &self,
        _: &crate::DiscoveryRecordV1,
    ) -> araphor_data::Result<crate::DiscoveryContextJoinV1> {
        Ok(crate::DiscoveryContextJoinV1::Unresolved(
            crate::DiscoveryContextUnavailableV1::MissingDecisionCatalog,
        ))
    }
}

#[test]
fn discovery_notice_cache() -> TestResult {
    let input = crate::DiscoveryInputManifestV1::try_from(
        include_bytes!("../../../../mithril-e2e/fixtures/discovery/manifest.json").as_slice(),
    )?;
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("analysis");
    let store = Arc::new(AnalysisStore::open(&root)?);
    let record = &input.records[0];
    store.accept_validated_batch(
        record.id.stream.clone(),
        ValidatedEvidenceBatchV1 {
            cpu_id: record.id.cpu_id,
            first_cursor: record.id.durable_cursor,
            last_cursor: record.id.durable_cursor,
            intake_utc_ns: 1,
            framed_records: record.wire_record.clone().into(),
            frame_ends: vec![record.wire_record.len()],
        },
    )?;
    let owner = crate::DiscoveryOwner::new(
        Arc::new(NoContext),
        crate::DiscoveryConfigV1 {
            interval_records: 1,
            ..Default::default()
        },
        crate::InstalledAnalysis::testing(Some(store.clone()), input.tenant_id)?,
    )?;
    owner.process(10)?;
    let profile = owner.profile(&record.id.stream)?.ok_or("profile absent")?;
    assert!(profile.sealed);
    let head = store.processor_result(&profile.scope)?;
    let health = store.processor_health(&profile.scope)?;
    let meta = store.meta()?;
    let frozen = result_row(&store, &profile.profile_id)?;
    let notices = vec![(profile.profile_id.clone(), frozen.2)];
    assert_eq!(store.profile_notices(&profile.scope, 2, 2)?, notices);
    store.mark_notice(&profile, frozen.2, 2, 2)?;
    assert!(store.profile_notices(&profile.scope, 2, 2)?.is_empty());
    store.mark_notice(&profile, frozen.2, 1, 1)?;
    assert!(store.profile_notices(&profile.scope, 2, 2)?.is_empty());
    assert!(store.mark_notice(&profile, frozen.2 + 1, 3, 3).is_err());
    assert_eq!(result_row(&store, &profile.profile_id)?, frozen);
    assert_eq!(store.processor_result(&profile.scope)?, head);
    assert_eq!(store.processor_health(&profile.scope)?, health);
    assert_eq!(store.meta()?, meta);
    drop(owner);
    drop(store);
    let store = AnalysisStore::open(&root)?;
    assert_eq!(result_row(&store, &profile.profile_id)?, frozen);
    assert_eq!(store.processor_result(&profile.scope)?, head);
    assert_eq!(store.processor_health(&profile.scope)?, health);
    assert_eq!(store.meta()?, meta);
    assert!(store.profile_notices(&profile.scope, 2, 2)?.is_empty());
    assert_eq!(store.profile_notices(&profile.scope, 3, 2)?, notices);
    Ok(())
}
