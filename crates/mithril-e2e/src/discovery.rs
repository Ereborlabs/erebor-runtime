use std::{fs, path::Path};

use araphor_data::{
    DiscoveryInputManifestV1, DiscoveryOwner, DiscoveryPhysicalResultV1, DiscoveryProofKindV1,
};
use mithril_control::{
    DiscoveryPreviewOwner, PolicyDocumentV1, SimulatedDispositionV1, SimulatedPhysicalResultV1,
};
use serde::Serialize;
use snafu::{ensure, ResultExt as _};

use crate::{
    error::{DataSnafu, InvalidInputSnafu, IoSnafu, JsonSnafu, PolicySnafu},
    Result,
};

mod data_store;
mod isolation;
mod query_follow;
mod roundtrip;
#[cfg(test)]
mod storage;
mod storage_contract;
pub use data_store::DataStoreQualification;
pub use query_follow::QueryFollowQualification;
pub use roundtrip::DiscoveryQualificationRunner;
pub use storage_contract::run as run_discovery_storage_contract;

pub fn run_discovery_offline(output: &Path) -> Result<()> {
    let input_bytes = include_bytes!("../fixtures/discovery/manifest.json");
    let input = DiscoveryInputManifestV1::try_from(input_bytes.as_slice()).context(DataSnafu)?;
    let result = DiscoveryOwner::derive_recorded(&input).context(DataSnafu)?;
    let snapshot = &result.snapshot;
    ensure!(
        snapshot.proof_kind == DiscoveryProofKindV1::Synthetic
            && snapshot.accepted_records == 3
            && snapshot.included_records == 2
            && snapshot.unresolved_records == 1
            && snapshot.excluded_records == 0
            && result.duplicate_deliveries == 1
            && snapshot.atoms.len() == 1
            && snapshot.atoms[0].count == 2
            && snapshot.atoms[0].key.physical_result == DiscoveryPhysicalResultV1::Prevented,
        InvalidInputSnafu {
            path: output,
            reason: "offline exact counts or proof kind differ"
        }
    );
    let mut replay = input.clone();
    replay.records.reverse();
    replay.contexts.reverse();
    replay.records.extend(input.records.clone());
    ensure!(
        DiscoveryOwner::derive_recorded(&replay)
            .context(DataSnafu)?
            .snapshot
            == *snapshot,
        InvalidInputSnafu {
            path: output,
            reason: "replay changed the sealed snapshot"
        }
    );
    let policy_bytes = include_bytes!("../../mithril-control/tests/fixtures/policy-v1.yaml");
    let policy =
        PolicyDocumentV1::parse(Path::new("policy-v1.yaml"), policy_bytes).context(PolicySnafu)?;
    let preview = DiscoveryPreviewOwner::simulate_recorded(&input, &policy).context(PolicySnafu)?;
    ensure!(
        preview.simulations.len() == 1
            && preview.simulations[0].disposition == SimulatedDispositionV1::WouldDeny
            && preview.simulations[0].physical_result == SimulatedPhysicalResultV1::NotAttempted
            && preview.snapshot == *snapshot,
        InvalidInputSnafu {
            path: output,
            reason: "native preview differs or claims a physical result"
        }
    );
    let pilot: serde_json::Value =
        serde_json::from_slice(include_bytes!("../fixtures/discovery/pilot.json"))
            .context(JsonSnafu { path: output })?;
    let observed_oracle = serde_json::json!({
        "source_revision": input.source_revision,
        "accepted": snapshot.accepted_records,
        "included": snapshot.included_records,
        "unresolved": snapshot.unresolved_records,
        "excluded": snapshot.excluded_records,
        "duplicate_deliveries": result.duplicate_deliveries,
        "coverage_revision": snapshot.coverage[0].coverage_revision,
        "coverage_state": snapshot.coverage[0].state,
        "preview_policy_digest": preview.source_policy_digest,
        "preview_disposition": preview.simulations[0].disposition,
        "preview_physical_result": preview.simulations[0].physical_result,
    });
    ensure!(
        pilot["recorded_oracle"] == observed_oracle,
        InvalidInputSnafu {
            path: output,
            reason: "recorded owner output differs from the frozen fixture oracle"
        }
    );
    fs::create_dir(output).context(IoSnafu { path: output })?;
    write_json(&output.join("input-manifest.json"), &input)?;
    write_json(&output.join("snapshot.json"), snapshot)?;
    write_json(
        &output.join("result.json"),
        &serde_json::json!({
            "schema_version": 1,
            "case": "offline-exact",
            "result": "PASS",
            "asserted_contracts": ["exact-counts", "duplicate-delivery", "missing-context", "replay", "native-static-preview"],
            "preview": preview,
            "recorded_oracle": observed_oracle,
            "production_authority": false,
            "live_lookups": 0
        }),
    )
}

fn write_json(path: &Path, value: &impl Serialize) -> Result<()> {
    let file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .context(IoSnafu { path })?;
    serde_json::to_writer_pretty(&file, value).context(JsonSnafu { path })?;
    file.sync_all().context(IoSnafu { path })
}

#[cfg(test)]
mod tests {
    #[test]
    fn discovery_offline_output_unchanged() -> crate::platform::TestResult<()> {
        let directory = tempfile::tempdir()?;
        let output = directory.path().join("proof");
        super::run_discovery_offline(&output)?;
        let before = std::fs::read(output.join("snapshot.json"))?;
        assert!(super::run_discovery_offline(&output).is_err());
        assert_eq!(std::fs::read(output.join("snapshot.json"))?, before);
        Ok(())
    }
}
