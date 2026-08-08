use std::fs;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use snafu::{ensure, ResultExt as _};

use crate::error::{InvalidInputSnafu, IoSnafu, JsonSnafu};
use crate::Result;

const INCIDENT_STAGES: [&str; 14] = [
    "HF-008", "HF-009", "HF-010", "HF-011", "HF-012", "HF-013", "HF-014", "HF-015", "HF-016",
    "HF-017", "HF-018", "HF-019", "HF-020", "HF-021",
];

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FixtureV1 {
    schema_version: u32,
    safe_fixture: bool,
    production_authority: bool,
    stages: Vec<StageV1>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct StageV1 {
    incident_event_id: String,
    safe_action: String,
    decision_or_evidence_point: String,
    required_postcondition: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct BaselineV1 {
    schema_version: u32,
    digest_algorithm: String,
    inputs: Vec<String>,
    expected_digest: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PlatformV1 {
    schema_version: u32,
    node_id: String,
    role: String,
    status: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReplayRecordV1 {
    sequence: u64,
    incident_event_id: String,
    event_kind: String,
    synthetic: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct FixtureBaselineRecordV1 {
    pub protected_deployment_digest: String,
    pub input_count: usize,
    pub replay_record_count: usize,
    pub platform_node_ids: Vec<String>,
}

pub struct HuggingFaceFixture {
    root: PathBuf,
}

impl HuggingFaceFixture {
    #[must_use]
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    pub fn verify(&self) -> Result<FixtureBaselineRecordV1> {
        let fixture: FixtureV1 = self.read_json("fixture.json")?;
        ensure!(
            fixture.schema_version == 1 && fixture.safe_fixture && !fixture.production_authority,
            InvalidInputSnafu {
                path: self.root.join("fixture.json"),
                reason: "fixture must be Version 1, safe, and carry no production authority"
            }
        );
        let observed_stages = fixture
            .stages
            .iter()
            .map(|stage| stage.incident_event_id.as_str())
            .collect::<Vec<_>>();
        ensure!(
            observed_stages == INCIDENT_STAGES
                && fixture.stages.iter().all(|stage| {
                    !stage.safe_action.is_empty()
                        && !stage.decision_or_evidence_point.is_empty()
                        && !stage.required_postcondition.is_empty()
                }),
            InvalidInputSnafu {
                path: self.root.join("fixture.json"),
                reason:
                    "incident stages and physical postconditions must exactly cover HF-008..HF-021"
            }
        );

        let mut nodes = [
            self.read_json::<PlatformV1>("platforms/node-a.json")?,
            self.read_json::<PlatformV1>("platforms/node-b.json")?,
        ];
        nodes.sort_by(|left, right| left.node_id.cmp(&right.node_id));
        ensure!(
            nodes.iter().all(|node| {
                node.schema_version == 1
                    && node.status == "MEASURE_AT_RUNTIME"
                    && matches!(node.role.as_str(), "worker" | "isolated-controller")
            }) && nodes[0].node_id != nodes[1].node_id,
            InvalidInputSnafu {
                path: self.root.join("platforms"),
                reason: "two distinct runtime-measured node manifests are required"
            }
        );

        let replay_record_count = self.verify_replay()?;
        let baseline: BaselineV1 = self.read_json("baseline.json")?;
        ensure!(
            baseline.schema_version == 1 && baseline.digest_algorithm == "SHA-256",
            InvalidInputSnafu {
                path: self.root.join("baseline.json"),
                reason: "unsupported baseline schema or digest algorithm"
            }
        );
        ensure!(
            baseline.inputs.windows(2).all(|pair| pair[0] < pair[1]),
            InvalidInputSnafu {
                path: self.root.join("baseline.json"),
                reason: "baseline inputs must be sorted and unique"
            }
        );
        let digest = self.digest_inputs(&baseline.inputs)?;
        ensure!(
            digest == baseline.expected_digest,
            InvalidInputSnafu {
                path: self.root.join("baseline.json"),
                reason: format!(
                    "protected deployment digest is {digest}, expected {}",
                    baseline.expected_digest
                )
            }
        );

        Ok(FixtureBaselineRecordV1 {
            protected_deployment_digest: digest,
            input_count: baseline.inputs.len(),
            replay_record_count,
            platform_node_ids: nodes.into_iter().map(|node| node.node_id).collect(),
        })
    }

    fn verify_replay(&self) -> Result<usize> {
        let path = self.root.join("replay.jsonl");
        let text = fs::read_to_string(&path).context(IoSnafu { path: path.clone() })?;
        let mut count = 0;
        for (index, line) in text.lines().enumerate() {
            let record: ReplayRecordV1 =
                serde_json::from_str(line).context(JsonSnafu { path: path.clone() })?;
            ensure!(
                record.sequence == index as u64 + 1
                    && record.synthetic
                    && INCIDENT_STAGES.contains(&record.incident_event_id.as_str())
                    && !record.event_kind.is_empty(),
                InvalidInputSnafu {
                    path: path.clone(),
                    reason: format!("invalid deterministic replay record at line {}", index + 1)
                }
            );
            count += 1;
        }
        ensure!(
            count == INCIDENT_STAGES.len(),
            InvalidInputSnafu {
                path,
                reason: "replay must contain one ordered synthetic record per incident stage"
            }
        );
        Ok(count)
    }

    fn digest_inputs(&self, inputs: &[String]) -> Result<String> {
        let mut hasher = Sha256::new();
        for relative in inputs {
            let path = self.root.join(relative);
            let bytes = fs::read(&path).context(IoSnafu { path: path.clone() })?;
            hasher.update(relative.as_bytes());
            hasher.update([0]);
            hasher.update((bytes.len() as u64).to_le_bytes());
            hasher.update(bytes);
        }
        Ok(format!("{:x}", hasher.finalize()))
    }

    fn read_json<T>(&self, relative: &str) -> Result<T>
    where
        T: for<'de> Deserialize<'de>,
    {
        let path = self.root.join(relative);
        let bytes = fs::read(&path).context(IoSnafu { path: path.clone() })?;
        serde_json::from_slice(&bytes).context(JsonSnafu { path })
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::HuggingFaceFixture;

    #[test]
    fn safe_fixture_has_exact_stages_replay_nodes_and_unchanged_digest() -> crate::Result<()> {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures/hugging-face");
        let record = HuggingFaceFixture::new(root).verify()?;
        assert_eq!(record.input_count, 5);
        assert_eq!(record.replay_record_count, 14);
        assert_eq!(record.platform_node_ids, ["node-a", "node-b"]);
        Ok(())
    }
}
