use std::{fs, path::Path};

use mithril_control::{
    DiscoveryInputManifestV1, DiscoveryOwner, DiscoveryPhysicalResultV1, DiscoveryProofKindV1,
    PolicyDocumentV1, SimulatedDispositionV1, SimulatedPhysicalResultV1,
};
use serde::Serialize;
use snafu::{ensure, ResultExt as _};

use crate::{
    error::{InvalidInputSnafu, IoSnafu, JsonSnafu, PolicySnafu},
    Result,
};

mod roundtrip;
#[cfg(test)]
mod storage;
pub use roundtrip::DiscoveryQualificationRunner;

pub fn run_discovery_offline(output: &Path) -> Result<()> {
    let input_bytes = include_bytes!("../fixtures/discovery/manifest.json");
    let input = DiscoveryInputManifestV1::from_json(input_bytes).context(PolicySnafu)?;
    let result = DiscoveryOwner::derive_recorded(&input).context(PolicySnafu)?;
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
            && snapshot.atoms[0].physical_result == DiscoveryPhysicalResultV1::Prevented,
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
            .context(PolicySnafu)?
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
    let preview = DiscoveryOwner::simulate_recorded(&input, &policy).context(PolicySnafu)?;
    ensure!(
        preview.simulations.len() == 1
            && preview.simulations[0].disposition == SimulatedDispositionV1::WouldDeny
            && preview.simulations[0].physical_result == SimulatedPhysicalResultV1::NotAttempted
            && preview.snapshot_digest == snapshot.content_digest,
        InvalidInputSnafu {
            path: output,
            reason: "native preview differs or claims a physical result"
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
            "fixture_digest": crate::DigestV1::of(input_bytes),
            "candidate_bytes_digest": crate::DigestV1::of(policy_bytes),
            "preview": preview,
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
    fn discovery_offline_uses_production_owners_and_preserves_existing_output(
    ) -> crate::platform::TestResult<()> {
        let directory = tempfile::tempdir()?;
        let output = directory.path().join("proof");
        super::run_discovery_offline(&output)?;
        let before = std::fs::read(output.join("snapshot.json"))?;
        assert!(super::run_discovery_offline(&output).is_err());
        assert_eq!(std::fs::read(output.join("snapshot.json"))?, before);
        Ok(())
    }
}
