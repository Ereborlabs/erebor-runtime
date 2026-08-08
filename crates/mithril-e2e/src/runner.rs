use std::fs;
use std::path::{Path, PathBuf};

use serde::Serialize;
use snafu::ResultExt as _;

use crate::error::{IoSnafu, JsonSnafu};
use crate::{
    ArchitectureClosure, BpfPhase0Loader, BpfPrototypeCompiler, ClosureLedgerV1, CompileRecordV1,
    DigestV1, FixtureBaselineRecordV1, HuggingFaceFixture, OpenBenchmark, OpenBenchmarkRecordV1,
    PhysicalFileOpenProbeV1, PlatformProbe, PlatformProbeV1, ProvenanceVerifier, Result,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum BenchmarkModeV1 {
    Baseline,
    Protected,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct Phase0VerificationBundleV1 {
    pub schema_version: u32,
    pub architecture_closure: ClosureLedgerV1,
    pub fixture_baseline: FixtureBaselineRecordV1,
    pub provenance_dossier_sha256: String,
    pub candidate_contract_digest: String,
    pub abi_state: &'static str,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CapabilityProbeBundleV1 {
    pub schema_version: u32,
    pub platform: PlatformProbeV1,
    pub compile: CompileRecordV1,
    pub physical_probe_state: &'static str,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct PhysicalCapabilityProbeBundleV1 {
    pub schema_version: u32,
    pub platform: PlatformProbeV1,
    pub compile: CompileRecordV1,
    pub file_open: PhysicalFileOpenProbeV1,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct OpenBenchmarkBundleV1 {
    pub schema_version: u32,
    pub mode: BenchmarkModeV1,
    pub target: PathBuf,
    pub records: Vec<OpenBenchmarkRecordV1>,
}

pub struct Phase0Runner {
    repo_root: PathBuf,
}

impl Phase0Runner {
    #[must_use]
    pub fn new(repo_root: impl Into<PathBuf>) -> Self {
        Self {
            repo_root: repo_root.into(),
        }
    }

    pub fn verify(&self) -> Result<Phase0VerificationBundleV1> {
        let closure = ArchitectureClosure::new(self.repo_root.join("spec")).verify()?;
        ProvenanceVerifier::new(&self.repo_root).load_and_verify()?;
        let fixture = HuggingFaceFixture::new(
            self.repo_root
                .join("crates/mithril-e2e/fixtures/hugging-face"),
        )
        .verify()?;
        let provenance_path = self
            .repo_root
            .join("spec/provenance/v1/upstream-adoption.json");
        let provenance = fs::read(&provenance_path).context(IoSnafu {
            path: provenance_path,
        })?;
        let closure_bytes = serde_json::to_vec(&closure).context(JsonSnafu {
            path: PathBuf::from("in-memory architecture closure"),
        })?;
        let mut contract_bytes = Vec::new();
        contract_bytes.extend_from_slice(&closure_bytes);
        contract_bytes.extend_from_slice(&provenance);
        contract_bytes.extend_from_slice(fixture.protected_deployment_digest.as_bytes());
        Ok(Phase0VerificationBundleV1 {
            schema_version: 1,
            architecture_closure: closure,
            fixture_baseline: fixture,
            provenance_dossier_sha256: DigestV1::of(provenance).to_hex(),
            candidate_contract_digest: DigestV1::of(contract_bytes).to_hex(),
            abi_state: "DEFERRED_UNTIL_PHYSICAL_PROBES_PASS",
        })
    }

    pub fn probe(&self, output_directory: &Path) -> Result<CapabilityProbeBundleV1> {
        let platform = PlatformProbe::inspect()?;
        let compile = BpfPrototypeCompiler::new(&self.repo_root).compile(output_directory)?;
        Ok(CapabilityProbeBundleV1 {
            schema_version: 1,
            platform,
            compile,
            physical_probe_state: "REQUIRES_PRIVILEGED_RUNNER_AND_ACTIVE_BPF_LSM",
        })
    }

    pub fn physical_file_open_probe(
        &self,
        output_directory: &Path,
    ) -> Result<PhysicalCapabilityProbeBundleV1> {
        let platform = PlatformProbe::inspect()?;
        let compile = BpfPrototypeCompiler::new(&self.repo_root).compile(output_directory)?;
        let file_open =
            BpfPhase0Loader::new(&compile.object_path).run_file_open_probe(output_directory)?;
        Ok(PhysicalCapabilityProbeBundleV1 {
            schema_version: 1,
            platform,
            compile,
            file_open,
        })
    }

    pub fn benchmark(
        &self,
        mode: BenchmarkModeV1,
        target: &Path,
        warmup_iterations: u64,
        measured_iterations: u64,
    ) -> Result<OpenBenchmarkBundleV1> {
        let records = [1, 32]
            .into_iter()
            .map(|concurrency| {
                OpenBenchmark::run(target, warmup_iterations, measured_iterations, concurrency)
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(OpenBenchmarkBundleV1 {
            schema_version: 1,
            mode,
            target: target.to_path_buf(),
            records,
        })
    }

    pub fn verify_checked_sources(&self) -> Result<()> {
        ProvenanceVerifier::new(&self.repo_root).verify_checked_sources()?;
        Ok(())
    }

    pub fn write_json<T>(&self, output: &Path, value: &T) -> Result<()>
    where
        T: Serialize,
    {
        if let Some(parent) = output.parent() {
            fs::create_dir_all(parent).context(IoSnafu {
                path: parent.to_path_buf(),
            })?;
        }
        let bytes = serde_json::to_vec_pretty(value).context(JsonSnafu {
            path: output.to_path_buf(),
        })?;
        fs::write(output, bytes).context(IoSnafu {
            path: output.to_path_buf(),
        })
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::Phase0Runner;

    #[test]
    fn verification_bundle_stays_candidate_until_physical_probes_pass() -> crate::Result<()> {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
        let bundle = Phase0Runner::new(root).verify()?;
        assert_eq!(bundle.schema_version, 1);
        assert_eq!(bundle.architecture_closure.fixtures.len(), 134);
        assert_eq!(bundle.abi_state, "DEFERRED_UNTIL_PHYSICAL_PROBES_PASS");
        assert_eq!(bundle.candidate_contract_digest.len(), 64);
        Ok(())
    }
}
