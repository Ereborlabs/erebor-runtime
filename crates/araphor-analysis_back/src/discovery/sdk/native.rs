use super::*;
use crate::package::tests::{Fixture, TestResult};
use crate::{PackageArtifactV1, PackageBundleV1, PackageImplementationV1, PackageRequestV1};
use araphor_data::native::Qualification;
use std::{path::PathBuf, sync::Arc, time::Duration};

#[tokio::test]
#[ignore = "requires source-built native artifacts in ARAPHOR_NATIVE_DIR"]
async fn native_atoms_match_wasm() -> TestResult {
    let input = DiscoveryInputManifestV1::try_from(
        include_bytes!("../../../../mithril-e2e/fixtures/discovery/manifest.json").as_slice(),
    )?;
    let directory = PathBuf::from(
        std::env::var_os("ARAPHOR_NATIVE_DIR").ok_or("ARAPHOR_NATIVE_DIR is required")?,
    );
    let bytes =
        std::fs::read(directory.join(format!("discovery.{}", std::env::consts::DLL_EXTENSION)))?;
    let package = builtin::Discovery::package();
    let qualification = Qualification::inspect(
        &bytes,
        package
            .exports
            .iter()
            .map(|model| model.name.clone())
            .collect(),
        env!("ARAPHOR_NATIVE_TARGET").into(),
    )?;
    let artifact = PackageArtifactV1 {
        descriptor: package,
        implementations: vec![PackageImplementationV1::Native {
            export: "atoms".into(),
            artifact: bytes,
            qualification: Some(qualification),
        }],
        fixtures: Vec::new(),
    };
    let mut fixture = Fixture::new()?;
    fixture.grant.selection = crate::AnalysisSelectionV1::tenant(input.tenant_id);
    fixture
        .owner
        .execute(
            fixture.grant.clone(),
            PackageRequestV1::Install {
                scope_id: "test".into(),
                bundle: PackageBundleV1 {
                    schema_version: 1,
                    root: artifact.reference(),
                    artifacts: vec![artifact],
                },
                parameters: None,
            },
            Arc::new(crate::AnalysisReadControl::with_timeout(
                Duration::from_secs(30),
            )?),
        )
        .await?;
    let native = crate::InstalledAnalysis::new(fixture.owner.clone(), "test")?;
    let wasm = crate::InstalledAnalysis::testing(None, input.tenant_id)?;
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
        let expected = DiscoveryOwner::derive_recorded(&manifest, &wasm)?;
        let actual = DiscoveryOwner::derive_recorded(&manifest, &native)?;
        assert_eq!(actual, expected);
        assert!(actual.snapshot.accepted_records > 0);
        assert!(!actual.snapshot.coverage.is_empty());
        assert!(!actual.snapshot.atoms.is_empty() || !actual.snapshot.unresolved.is_empty());
    }
    Ok(())
}

#[tokio::test]
#[ignore = "requires source-built native artifacts in ARAPHOR_NATIVE_DIR"]
async fn native_snapshot_exports_match_wasm() -> TestResult {
    let manifest = DiscoveryInputManifestV1::try_from(
        include_bytes!("../../../../mithril-e2e/fixtures/discovery/manifest.json").as_slice(),
    )?;
    let directory = PathBuf::from(
        std::env::var_os("ARAPHOR_NATIVE_DIR").ok_or("ARAPHOR_NATIVE_DIR is required")?,
    );
    let bytes =
        std::fs::read(directory.join(format!("discovery.{}", std::env::consts::DLL_EXTENSION)))?;
    let package = builtin::Discovery::package();
    let qualification = Qualification::inspect(
        &bytes,
        package
            .exports
            .iter()
            .map(|model| model.name.clone())
            .collect(),
        env!("ARAPHOR_NATIVE_TARGET").into(),
    )?;
    let artifact = PackageArtifactV1 {
        descriptor: package,
        implementations: vec![PackageImplementationV1::Native {
            export: "atoms".into(),
            artifact: bytes,
            qualification: Some(qualification),
        }],
        fixtures: Vec::new(),
    };
    let mut fixture = Fixture::new()?;
    fixture.grant.selection = crate::AnalysisSelectionV1::tenant(manifest.tenant_id);
    fixture
        .owner
        .execute(
            fixture.grant.clone(),
            PackageRequestV1::Install {
                scope_id: "test".into(),
                bundle: PackageBundleV1 {
                    schema_version: 1,
                    root: artifact.reference(),
                    artifacts: vec![artifact],
                },
                parameters: None,
            },
            Arc::new(crate::AnalysisReadControl::with_timeout(
                Duration::from_secs(30),
            )?),
        )
        .await?;
    let native = crate::InstalledAnalysis::new(fixture.owner.clone(), "test")?;
    let wasm = crate::InstalledAnalysis::testing(None, manifest.tenant_id)?;
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
    for execution in [&wasm, &native] {
        let first = DiscoveryOwner::derive_recorded(&first, execution)?.snapshot;
        let second = DiscoveryOwner::derive_recorded(&second, execution)?.snapshot;
        let merged = DiscoveryOwner::merge(&first, &second, execution)?;
        let groups = DiscoveryOwner::display_groups(&merged, execution)?;
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
        let changed = DiscoveryOwner::derive_recorded(&changed, execution)?.snapshot;
        let comparison = DiscoveryOwner::compare(&changed, &baseline, execution)?;
        assert!(!comparison.changed_identities.is_empty());
        outputs
            .push(serde_json::json!({ "merged":merged, "groups":groups, "comparison":comparison }));
    }
    assert_eq!(outputs[0], outputs[1]);
    Ok(())
}
