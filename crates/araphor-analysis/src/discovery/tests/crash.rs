use std::path::PathBuf;

use super::super::*;

#[test]
fn discovery_profile_commit_crashes() -> std::result::Result<(), Box<dyn std::error::Error>> {
    use std::sync::Arc;

    use crate::{
        DiscoveryConfigV1, DiscoveryContextJoinV1, DiscoveryContextProvider,
        DiscoveryContextUnavailableV1, DiscoveryInputManifestV1, DiscoveryOwner, DiscoveryRecordV1,
    };

    struct MissingContext;

    impl DiscoveryContextProvider for MissingContext {
        fn context(
            &self,
            _record: &DiscoveryRecordV1,
        ) -> araphor_data::Result<DiscoveryContextJoinV1> {
            Ok(DiscoveryContextJoinV1::Unresolved(
                DiscoveryContextUnavailableV1::MissingDecisionCatalog,
            ))
        }
    }

    let input = DiscoveryInputManifestV1::try_from(
        include_bytes!("../../../../mithril-e2e/fixtures/discovery/manifest.json").as_slice(),
    )?;
    let record = &input.records[0];
    let config = |sealed| DiscoveryConfigV1 {
        interval_records: if sealed { 1 } else { 2 },
        ..Default::default()
    };
    let mut expected = crate::AnalysisPackageOwner::required_bundles()
        .into_iter()
        .map(|bundle| bundle.root)
        .collect::<Vec<_>>();
    expected.sort();
    assert_eq!(expected.len(), 4);
    let check_packages = |installed: &crate::InstalledAnalysis| -> Result<()> {
        let mut roots = installed
            .snapshot(input.tenant_id)?
            .refs()?
            .into_iter()
            .map(|reference| reference.root)
            .collect::<Vec<_>>();
        roots.sort();
        roots.dedup();
        assert_eq!(roots, expected);
        Ok(())
    };
    if let Some(root) = std::env::var_os("ARAPHOR_CRASH_ROOT") {
        let store = Arc::new(AnalysisStore::open(PathBuf::from(root))?);
        let sealed = std::env::var("ARAPHOR_DISCOVERY_SEALED")? == "true";
        let installed = crate::InstalledAnalysis::testing_existing(store.clone(), input.tenant_id)?;
        check_packages(&installed)?;
        let owner = DiscoveryOwner::new(
            store.clone(),
            Arc::new(MissingContext),
            config(sealed),
            installed,
        )?;
        assert_eq!(owner.process(10)?, 1);
        store.crash_at("profile.returned");
        return Err("the requested discovery crash did not occur".into());
    }
    for sealed in [false, true] {
        for point in ["result.before", "result.after", "profile.returned"] {
            let directory = tempfile::tempdir()?;
            let root = directory.path().join("data");
            let store = Arc::new(AnalysisStore::open(&root)?);
            store.accept_validated_batch(
                record.id.stream.clone(),
                ValidatedEvidenceBatchV1 {
                    cpu_id: record.id.cpu_id,
                    first_cursor: 1,
                    last_cursor: 1,
                    intake_utc_ns: 1,
                    framed_records: record.wire_record.clone().into(),
                    frame_ends: vec![record.wire_record.len()],
                },
            )?;
            let receipt = store.source_receipt(&record.id.stream)?;
            let installed =
                crate::InstalledAnalysis::testing(Some(store.clone()), input.tenant_id)?;
            check_packages(&installed)?;
            assert_eq!(store.source_receipt(&record.id.stream)?, receipt);
            drop(installed);
            drop(store);
            let status = std::process::Command::new(std::env::current_exe()?)
                .args([
                    "--exact",
                    "discovery::tests::crash::discovery_profile_commit_crashes",
                ])
                .env("ARAPHOR_CRASH_ROOT", &root)
                .env("ARAPHOR_CRASH_POINT", point)
                .env("ARAPHOR_DISCOVERY_SEALED", sealed.to_string())
                .status()?;
            assert_eq!(status.code(), Some(73), "{point}, sealed={sealed}");
            let store = Arc::new(AnalysisStore::open(&root)?);
            let installed =
                crate::InstalledAnalysis::testing(Some(store.clone()), input.tenant_id)?;
            check_packages(&installed)?;
            let owner = DiscoveryOwner::new(
                store.clone(),
                Arc::new(MissingContext),
                config(sealed),
                installed,
            )?;
            let recovered = owner.profile(&record.id.stream)?;
            let committed = point != "result.before";
            assert_eq!(recovered.is_some(), committed, "{point}, sealed={sealed}");
            let scope = ProcessorScopeV1 {
                processor_id: crate::DISCOVERY_PROCESSOR.into(),
                method_version: u64::from(crate::DISCOVERY_SCHEMA_VERSION),
                identity: record.id.stream.clone(),
            };
            assert_eq!(
                store
                    .processor_health(&scope)?
                    .ok_or("health absent")?
                    .consumed_cursor,
                u64::from(committed),
                "{point}, sealed={sealed}"
            );
            assert_eq!(owner.process(11)?, usize::from(!committed));
            let profile = owner.profile(&record.id.stream)?.ok_or("profile absent")?;
            if let Some(recovered) = recovered {
                assert_eq!(profile, recovered, "{point}, sealed={sealed}");
            }
            assert_eq!(profile.sealed, sealed, "{point}, sealed={sealed}");
            assert_eq!(profile.snapshot.accepted_records, 1);
            assert_eq!(profile.snapshot.unresolved_records, 1);
            assert_eq!(owner.process(12)?, 0);
            assert_eq!(owner.profile(&record.id.stream)?, Some(profile.clone()));
            assert_eq!(store.source_receipt(&record.id.stream)?, receipt);
            assert_eq!(
                store.read_page(&record.id.stream, 1)?.records[0].framed_record,
                record.wire_record
            );
            drop(owner);
            drop(store);
            let store = Arc::new(AnalysisStore::open(&root)?);
            let installed =
                crate::InstalledAnalysis::testing(Some(store.clone()), input.tenant_id)?;
            check_packages(&installed)?;
            let owner = DiscoveryOwner::new(
                store.clone(),
                Arc::new(MissingContext),
                config(sealed),
                installed,
            )?;
            assert_eq!(owner.profile(&record.id.stream)?, Some(profile));
            assert_eq!(owner.process(13)?, 0);
        }
    }
    Ok(())
}
