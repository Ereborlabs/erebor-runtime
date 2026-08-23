use std::fs;
use std::path::{Path, PathBuf};

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use snafu::{ensure, OptionExt as _, ResultExt as _};

use crate::benchmark::OpenBenchmark;
use crate::capability::BpfPrototypeCompiler;
use crate::capability_matrix::KernelQualificationCapabilityMatrix;
use crate::closure::QualificationRegistry;
use crate::error::{InterceptorSnafu, InvalidInputSnafu, IoSnafu, JsonSnafu};
use crate::fixture::HuggingFaceFixture;
use crate::loader::BpfQualificationLoader;
use crate::physical::ProbeFile;
use crate::provenance::ProvenanceVerifier;
use crate::{
    ClosureLedgerV1, CompileRecordV1, DigestV1, FixtureBaselineRecordV1, OpenBenchmarkRecordV1,
    PhysicalFileOpenProbeV1, PlatformProbeV1, Result,
};
use erebor_interceptor::{KernelHostConfig, KernelHostOwner, KernelObjectManifestV1};
use erebor_interceptor_abi::{CapabilityRecordV1, CapabilityStateV1};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum BenchmarkModeV1 {
    Baseline,
    Protected,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct KernelQualificationBundleV1 {
    pub schema_version: u32,
    pub qualification_registry: ClosureLedgerV1,
    pub fixture_baseline: FixtureBaselineRecordV1,
    pub provenance_dossier_sha256: String,
    pub closed_contract_digest: String,
    pub physical_qualification_sha256: String,
    pub abi_state: &'static str,
    pub capabilities: Vec<CapabilityRecordV1>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RecordedKernelQualificationV1 {
    schema_version: u32,
    platform_architecture: String,
    kernel_release: String,
    active_lsm_order: String,
    runtime_btf_sha256: String,
    abi_header_sha256: String,
    bpf_source_sha256: String,
    bpf_object_sha256: String,
    physical_probe_artifact_sha256: String,
    physical_evidence_sha256: String,
    lsm_program_count: usize,
    map_count: usize,
    file_open_allow_deny_allow: bool,
    supported_capability_ids: Vec<String>,
    unsupported_capability_count: usize,
    benchmark_artifacts: RecordedBenchmarkArtifactsV1,
    benchmarks: Vec<RecordedBenchmarkV1>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RecordedBenchmarkArtifactsV1 {
    baseline_sha256: String,
    protected_sha256: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RecordedBenchmarkV1 {
    mode: String,
    concurrency: u32,
    warmup_iterations: u64,
    measured_iterations: u64,
    elapsed_ns: u64,
    operations_per_second: f64,
    p50_ns: u64,
    p95_ns: u64,
    p99_ns: u64,
    maximum_ns: u64,
    raw_samples_sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CapabilityProbeBundleV1 {
    pub schema_version: u32,
    pub platform: PlatformProbeV1,
    pub compile: CompileRecordV1,
    pub physical_probe_state: &'static str,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PhysicalCapabilityProbeBundleV1 {
    pub schema_version: u32,
    pub probe_binary_sha256: String,
    pub platform: PlatformProbeV1,
    pub compile: CompileRecordV1,
    pub file_open: PhysicalFileOpenProbeV1,
    pub capabilities: Vec<CapabilityRecordV1>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OpenBenchmarkBundleV1 {
    pub schema_version: u32,
    pub mode: BenchmarkModeV1,
    pub target: PathBuf,
    pub records: Vec<OpenBenchmarkRecordV1>,
}

pub struct KernelQualificationRunner {
    repo_root: PathBuf,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct HostLifecycleBundleV1 {
    pub schema_version: u32,
    pub compile: CompileRecordV1,
    pub first_start: KernelObjectManifestV1,
    pub second_owner_rejected: bool,
    pub pins_removed_after_shutdown: bool,
    pub restart: KernelObjectManifestV1,
    pub pins_removed_after_restart: bool,
    pub unchanged_worker_digest_before: String,
    pub unchanged_worker_digest_after: String,
}

pub struct HostLifecycleRunner {
    repo_root: PathBuf,
}

impl KernelQualificationRunner {
    const ABI_HEADER_PATH: &'static str = "bpf/erebor-interceptor/include/erebor_interceptor_abi.h";
    const BPF_SOURCE_PATH: &'static str = "bpf/erebor-interceptor/qualification/feasibility.bpf.c";

    #[must_use]
    pub fn new(repo_root: impl Into<PathBuf>) -> Self {
        Self {
            repo_root: repo_root.into(),
        }
    }

    pub fn verify(&self) -> Result<KernelQualificationBundleV1> {
        let registry = QualificationRegistry::new(self.repo_root.join("spec")).verify()?;
        ProvenanceVerifier::new(&self.repo_root).load_and_verify()?;
        let fixture = HuggingFaceFixture::new(
            self.repo_root
                .join("crates/mithril-e2e/fixtures/hugging-face"),
        )
        .verify()?;
        let provenance = self.read("spec/provenance/v1/upstream-adoption.json")?;
        let qualification_path = self
            .repo_root
            .join("spec/qualification/v1/results/kernel-qualification-x86_64.json");
        let qualification = fs::read(&qualification_path).context(IoSnafu {
            path: &qualification_path,
        })?;
        let recorded: RecordedKernelQualificationV1 = serde_json::from_slice(&qualification)
            .context(JsonSnafu {
                path: &qualification_path,
            })?;
        self.validate_recorded_qualification(&recorded, &qualification_path)?;
        let registry_bytes = serde_json::to_vec(&registry).context(JsonSnafu {
            path: PathBuf::from("in-memory qualification registry"),
        })?;
        let mut contract_bytes = Vec::new();
        let mut parts = vec![registry_bytes, provenance.clone(), qualification.clone()];
        for relative in [
            Self::ABI_HEADER_PATH,
            Self::BPF_SOURCE_PATH,
            "spec/qualification/v1/goldens/cfg-v1.json",
            "spec/qualification/v1/goldens/compiled-profile-v1.json",
            "spec/qualification/v1/goldens/cfg-rollback-v1.json",
            "spec/qualification/v1/goldens/decision-set-v1.hex",
        ] {
            parts.push(self.read(relative)?);
        }
        parts.push(fixture.protected_deployment_digest.as_bytes().to_vec());
        for part in parts {
            contract_bytes.extend_from_slice(&(part.len() as u64).to_le_bytes());
            contract_bytes.extend_from_slice(&part);
        }
        Ok(KernelQualificationBundleV1 {
            schema_version: 1,
            qualification_registry: registry,
            fixture_baseline: fixture,
            provenance_dossier_sha256: DigestV1::of(provenance).to_hex(),
            closed_contract_digest: DigestV1::of(contract_bytes).to_hex(),
            physical_qualification_sha256: DigestV1::of(qualification).to_hex(),
            abi_state: "FROZEN_PROVEN_SURFACES_ONLY",
            capabilities: KernelQualificationCapabilityMatrix::records(Some(
                &recorded.physical_evidence_sha256,
            )),
        })
    }

    fn validate_recorded_qualification(
        &self,
        qualification: &RecordedKernelQualificationV1,
        path: &Path,
    ) -> Result<()> {
        let supported = qualification
            .supported_capability_ids
            .iter()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        let benchmark_keys = qualification
            .benchmarks
            .iter()
            .map(|benchmark| (benchmark.mode.as_str(), benchmark.concurrency))
            .collect::<BTreeSet<_>>();
        ensure!(
            qualification.schema_version == 1
                && qualification.platform_architecture == "x86_64"
                && !qualification.kernel_release.is_empty()
                && qualification
                    .active_lsm_order
                    .split(',')
                    .any(|lsm| lsm == "bpf")
                && qualification.bpf_source_sha256
                    == DigestV1::of(self.read(Self::BPF_SOURCE_PATH)?).to_hex()
                && qualification.abi_header_sha256
                    == DigestV1::of(self.read(Self::ABI_HEADER_PATH)?).to_hex()
                && qualification.lsm_program_count
                    == erebor_interceptor::REQUIRED_QUALIFICATION_LSM_PROGRAMS.len()
                && qualification.map_count == 3
                && qualification.file_open_allow_deny_allow
                && qualification.unsupported_capability_count == 16
                && supported
                    == BTreeSet::from([
                        "BPF_LSM_ATTACH_READBACK",
                        "FILE_OPEN_PRE_EFFECT_DENIAL",
                        "X86_64_PHYSICAL_QUALIFICATION",
                    ])
                && benchmark_keys
                    == BTreeSet::from([
                        ("BASELINE", 1),
                        ("BASELINE", 32),
                        ("PROTECTED", 1),
                        ("PROTECTED", 32),
                    ])
                && [
                    &qualification.runtime_btf_sha256,
                    &qualification.abi_header_sha256,
                    &qualification.bpf_source_sha256,
                    &qualification.bpf_object_sha256,
                    &qualification.physical_probe_artifact_sha256,
                    &qualification.physical_evidence_sha256,
                    &qualification.benchmark_artifacts.baseline_sha256,
                    &qualification.benchmark_artifacts.protected_sha256,
                ]
                .into_iter()
                .all(|digest| is_sha256_hex(digest))
                && qualification.benchmarks.iter().all(|benchmark| {
                    benchmark.warmup_iterations == 100_000
                        && benchmark.measured_iterations == 1_000_000
                        && benchmark.elapsed_ns > 0
                        && benchmark.operations_per_second.is_finite()
                        && benchmark.operations_per_second > 0.0
                        && benchmark.p50_ns <= benchmark.p95_ns
                        && benchmark.p95_ns <= benchmark.p99_ns
                        && benchmark.p99_ns <= benchmark.maximum_ns
                        && is_sha256_hex(&benchmark.raw_samples_sha256)
                }),
            InvalidInputSnafu {
                path,
                reason: "recorded kernel qualification result is incomplete, malformed, or stale",
            }
        );
        Ok(())
    }

    fn read(&self, relative: &str) -> Result<Vec<u8>> {
        let path = self.repo_root.join(relative);
        fs::read(&path).context(IoSnafu { path })
    }

    pub fn probe(&self, output_directory: &Path) -> Result<CapabilityProbeBundleV1> {
        let platform = PlatformProbeV1::inspect()?;
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
        bpf_object: Option<&Path>,
    ) -> Result<PhysicalCapabilityProbeBundleV1> {
        let platform = PlatformProbeV1::inspect()?;
        let compile = match bpf_object {
            Some(object_path) => self.prebuilt_compile_record(object_path)?,
            None => BpfPrototypeCompiler::new(&self.repo_root).compile(output_directory)?,
        };
        let file_open = BpfQualificationLoader::new(&compile.object_path)
            .run_file_open_probe(output_directory)?;
        let evidence = serde_json::to_vec(&file_open).context(JsonSnafu {
            path: PathBuf::from("in-memory physical file-open evidence"),
        })?;
        let evidence_digest = DigestV1::of(evidence).to_hex();
        let probe_binary_path = std::env::current_exe().context(IoSnafu {
            path: PathBuf::from("current qualification executable"),
        })?;
        let probe_binary = fs::read(&probe_binary_path).context(IoSnafu {
            path: &probe_binary_path,
        })?;
        Ok(PhysicalCapabilityProbeBundleV1 {
            schema_version: 1,
            probe_binary_sha256: DigestV1::of(probe_binary).to_hex(),
            platform,
            compile,
            file_open,
            capabilities: KernelQualificationCapabilityMatrix::records(Some(&evidence_digest)),
        })
    }

    fn prebuilt_compile_record(&self, object_path: &Path) -> Result<CompileRecordV1> {
        let source_path = self.repo_root.join(Self::BPF_SOURCE_PATH);
        let source = fs::read(&source_path).context(IoSnafu { path: &source_path })?;
        let object = fs::read(object_path).context(IoSnafu { path: object_path })?;
        Ok(CompileRecordV1 {
            source_sha256: DigestV1::of(source).to_hex(),
            object_sha256: DigestV1::of(object).to_hex(),
            object_path: object_path.to_path_buf(),
            clang_stderr: String::new(),
        })
    }

    pub fn record_physical_qualification(
        &self,
        physical_path: &Path,
        baseline_path: &Path,
        protected_path: &Path,
        probe_binary_path: &Path,
        output: &Path,
    ) -> Result<()> {
        let physical_bytes = fs::read(physical_path).context(IoSnafu {
            path: physical_path,
        })?;
        let physical: PhysicalCapabilityProbeBundleV1 = serde_json::from_slice(&physical_bytes)
            .context(JsonSnafu {
                path: physical_path,
            })?;
        let baseline_bytes = fs::read(baseline_path).context(IoSnafu {
            path: baseline_path,
        })?;
        let baseline: OpenBenchmarkBundleV1 =
            serde_json::from_slice(&baseline_bytes).context(JsonSnafu {
                path: baseline_path,
            })?;
        let protected_bytes = fs::read(protected_path).context(IoSnafu {
            path: protected_path,
        })?;
        let protected: OpenBenchmarkBundleV1 =
            serde_json::from_slice(&protected_bytes).context(JsonSnafu {
                path: protected_path,
            })?;
        ensure!(
            physical.schema_version == 1
                && baseline.schema_version == 1
                && protected.schema_version == 1
                && baseline.mode == BenchmarkModeV1::Baseline
                && protected.mode == BenchmarkModeV1::Protected
                && baseline.target == protected.target
                && baseline.records.len() == 2
                && protected.records.len() == 2,
            InvalidInputSnafu {
                path: output,
                reason: "qualification inputs have incompatible schemas or modes",
            }
        );
        for record in baseline.records.iter().chain(&protected.records) {
            record.validate(output)?;
        }
        let file_open_evidence = serde_json::to_vec(&physical.file_open).context(JsonSnafu {
            path: physical_path,
        })?;
        ensure!(
            physical.capabilities
                == KernelQualificationCapabilityMatrix::records(Some(
                    &DigestV1::of(file_open_evidence).to_hex(),
                )),
            InvalidInputSnafu {
                path: physical_path,
                reason: "physical capability records do not match the file-open evidence",
            }
        );
        let expected_programs = erebor_interceptor::REQUIRED_QUALIFICATION_LSM_PROGRAMS
            .into_iter()
            .collect::<BTreeSet<_>>();
        let object_programs = physical
            .file_open
            .object_layout
            .lsm_programs
            .iter()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        let linked_programs = physical
            .file_open
            .links
            .iter()
            .map(|link| link.program.as_str())
            .collect::<BTreeSet<_>>();
        let expected_attached_programs = erebor_interceptor::REQUIRED_QUALIFICATION_PROGRAMS
            .into_iter()
            .collect::<BTreeSet<_>>();
        ensure!(
            object_programs == expected_programs
                && linked_programs == expected_attached_programs
                && physical.file_open.links.len() == expected_attached_programs.len()
                && physical
                    .file_open
                    .links
                    .iter()
                    .all(|link| link.link_id > 0 && link.program_id > 0),
            InvalidInputSnafu {
                path: physical_path,
                reason: "physical qualification does not contain the exact attached LSM set",
            }
        );
        let mut benchmarks = baseline
            .records
            .iter()
            .map(|record| recorded_benchmark("BASELINE", record))
            .chain(
                protected
                    .records
                    .iter()
                    .map(|record| recorded_benchmark("PROTECTED", record)),
            )
            .collect::<Vec<_>>();
        benchmarks.sort_by(|left, right| {
            left.mode
                .cmp(&right.mode)
                .then(left.concurrency.cmp(&right.concurrency))
        });
        ensure!(
            benchmarks
                .iter()
                .map(|benchmark| (benchmark.mode.as_str(), benchmark.concurrency))
                .collect::<BTreeSet<_>>()
                == BTreeSet::from([
                    ("BASELINE", 1),
                    ("BASELINE", 32),
                    ("PROTECTED", 1),
                    ("PROTECTED", 32),
                ]),
            InvalidInputSnafu {
                path: output,
                reason: "qualification benchmarks must contain concurrency 1 and 32 for both modes",
            }
        );
        let source_path = self.repo_root.join(Self::BPF_SOURCE_PATH);
        let source = fs::read(&source_path).context(IoSnafu { path: &source_path })?;
        ensure!(
            physical.compile.source_sha256 == DigestV1::of(source).to_hex(),
            InvalidInputSnafu {
                path: physical_path,
                reason: "physical qualification was built from a different BPF source",
            }
        );
        let abi_path = self.repo_root.join(Self::ABI_HEADER_PATH);
        let abi = fs::read(&abi_path).context(IoSnafu { path: &abi_path })?;
        let probe_binary = fs::read(probe_binary_path).context(IoSnafu {
            path: probe_binary_path,
        })?;
        ensure!(
            physical.probe_binary_sha256 == DigestV1::of(&probe_binary).to_hex(),
            InvalidInputSnafu {
                path: probe_binary_path,
                reason: "physical evidence was produced by a different probe binary",
            }
        );
        let supported_capability_ids = physical
            .capabilities
            .iter()
            .filter(|capability| capability.state == CapabilityStateV1::Supported)
            .map(|capability| capability.capability_id.clone())
            .collect::<Vec<_>>();
        let unsupported_capability_count = physical
            .capabilities
            .iter()
            .filter(|capability| capability.state == CapabilityStateV1::Unsupported)
            .count();
        let runtime_btf_sha256 =
            physical
                .platform
                .btf_sha256
                .clone()
                .context(InvalidInputSnafu {
                    path: physical_path,
                    reason: "physical qualification has no runtime BTF digest",
                })?;
        let qualification = RecordedKernelQualificationV1 {
            schema_version: 1,
            platform_architecture: physical.platform.architecture,
            kernel_release: physical.platform.kernel_release,
            active_lsm_order: physical.platform.active_lsm_order,
            runtime_btf_sha256,
            abi_header_sha256: DigestV1::of(abi).to_hex(),
            bpf_source_sha256: physical.compile.source_sha256,
            bpf_object_sha256: physical.compile.object_sha256,
            physical_probe_artifact_sha256: DigestV1::of(probe_binary).to_hex(),
            physical_evidence_sha256: DigestV1::of(physical_bytes).to_hex(),
            lsm_program_count: physical.file_open.object_layout.lsm_programs.len(),
            map_count: physical.file_open.object_layout.maps.len(),
            file_open_allow_deny_allow: physical.file_open.allowed_before_target_install
                && physical.file_open.denied_after_target_install
                && physical.file_open.allowed_after_target_clear,
            supported_capability_ids,
            unsupported_capability_count,
            benchmark_artifacts: RecordedBenchmarkArtifactsV1 {
                baseline_sha256: DigestV1::of(baseline_bytes).to_hex(),
                protected_sha256: DigestV1::of(protected_bytes).to_hex(),
            },
            benchmarks,
        };
        self.validate_recorded_qualification(&qualification, output)?;
        write_json(output, &qualification)
    }

    pub fn benchmark(
        &self,
        mode: BenchmarkModeV1,
        target: &Path,
        warmup_iterations: u64,
        measured_iterations: u64,
        bpf_object: Option<&Path>,
    ) -> Result<OpenBenchmarkBundleV1> {
        let run = || {
            [1, 32]
                .into_iter()
                .map(|concurrency| {
                    OpenBenchmark::run(target, warmup_iterations, measured_iterations, concurrency)
                })
                .collect::<Result<Vec<_>>>()
        };
        let records = match mode {
            BenchmarkModeV1::Baseline => run()?,
            BenchmarkModeV1::Protected => {
                let bpf_object = bpf_object.context(InvalidInputSnafu {
                    path: target,
                    reason: "protected benchmark requires --bpf-object",
                })?;
                let loader = BpfQualificationLoader::new(bpf_object);
                let lease_cleanup = ProbeFile::new(&loader.lease_path());
                let attachment = loader.attach()?;
                let records = run()?;
                attachment.shutdown().context(InterceptorSnafu)?;
                lease_cleanup.cleanup()?;
                records
            }
        };
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
        write_json(output, value)
    }
}

fn recorded_benchmark(mode: &str, record: &OpenBenchmarkRecordV1) -> RecordedBenchmarkV1 {
    RecordedBenchmarkV1 {
        mode: mode.to_owned(),
        concurrency: record.concurrency,
        warmup_iterations: record.warmup_iterations,
        measured_iterations: record.measured_iterations,
        elapsed_ns: record.elapsed_ns,
        operations_per_second: record.operations_per_second,
        p50_ns: record.distribution.p50,
        p95_ns: record.distribution.p95,
        p99_ns: record.distribution.p99,
        maximum_ns: record.distribution.maximum,
        raw_samples_sha256: record.distribution.raw_samples_sha256.clone(),
    }
}

impl HostLifecycleRunner {
    #[must_use]
    pub fn new(repo_root: impl Into<PathBuf>) -> Self {
        Self {
            repo_root: repo_root.into(),
        }
    }

    pub fn host_lifecycle(
        &self,
        output_directory: &Path,
        pin_root: &Path,
        lease_path: &Path,
    ) -> Result<HostLifecycleBundleV1> {
        ensure!(
            !pin_root.exists(),
            InvalidInputSnafu {
                path: pin_root,
                reason: "the dedicated lifecycle pin root must not already exist",
            }
        );
        let worker = HuggingFaceFixture::new(
            self.repo_root
                .join("crates/mithril-e2e/fixtures/hugging-face"),
        );
        let unchanged_worker_digest_before = worker.verify()?.protected_deployment_digest;
        let compile = BpfPrototypeCompiler::new(&self.repo_root).compile(output_directory)?;
        let config = KernelHostConfig::qualification(
            &compile.object_path,
            &compile.object_sha256,
            "/sys/kernel/btf/vmlinux",
            lease_path,
            Some(pin_root.to_path_buf()),
            boot_id()?,
            1,
        );
        let first = KernelHostOwner::new(config.clone())
            .start()
            .context(crate::error::InterceptorSnafu)?;
        let first_start = first.manifest().clone();
        ensure!(
            first_start.ready
                && first_start.maps.iter().all(|map| map.pin_path.is_some())
                && first_start.links.iter().all(|link| link.pin_path.is_some()),
            InvalidInputSnafu {
                path: pin_root,
                reason: "the first owner did not read back every pinned map and link",
            }
        );
        let second_owner_rejected = match KernelHostOwner::new(config.clone()).start() {
            Err(erebor_interceptor::Error::LeaseOwned { .. }) => true,
            Err(source) => return Err(crate::Error::from_interceptor(source)),
            Ok(second) => {
                second.shutdown().context(crate::error::InterceptorSnafu)?;
                false
            }
        };
        ensure!(
            second_owner_rejected,
            InvalidInputSnafu {
                path: lease_path,
                reason: "a concurrent Interceptor owner acquired the shared lease",
            }
        );
        first.shutdown().context(crate::error::InterceptorSnafu)?;
        let pins_removed_after_shutdown = !pin_root.exists();
        ensure!(
            pins_removed_after_shutdown,
            InvalidInputSnafu {
                path: pin_root,
                reason: "clean shutdown left pinned Interceptor state",
            }
        );

        let restarted = KernelHostOwner::new(config)
            .start()
            .context(crate::error::InterceptorSnafu)?;
        let restart = restarted.manifest().clone();
        restarted
            .shutdown()
            .context(crate::error::InterceptorSnafu)?;
        let pins_removed_after_restart = !pin_root.exists();
        ensure!(
            restart.ready && pins_removed_after_restart,
            InvalidInputSnafu {
                path: pin_root,
                reason: "the Interceptor did not restart and cleanly release its pin root",
            }
        );
        let unchanged_worker_digest_after = worker.verify()?.protected_deployment_digest;
        ensure!(
            unchanged_worker_digest_before == unchanged_worker_digest_after,
            InvalidInputSnafu {
                path: self
                    .repo_root
                    .join("crates/mithril-e2e/fixtures/hugging-face"),
                reason: "the host lifecycle changed the worker fixture",
            }
        );
        Ok(HostLifecycleBundleV1 {
            schema_version: 1,
            compile,
            first_start,
            second_owner_rejected,
            pins_removed_after_shutdown,
            restart,
            pins_removed_after_restart,
            unchanged_worker_digest_before,
            unchanged_worker_digest_after,
        })
    }

    pub fn write_json<T>(&self, output: &Path, value: &T) -> Result<()>
    where
        T: Serialize,
    {
        write_json(output, value)
    }
}

fn write_json<T>(output: &Path, value: &T) -> Result<()>
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

fn boot_id() -> Result<String> {
    let path = Path::new("/proc/sys/kernel/random/boot_id");
    let value = fs::read_to_string(path).context(IoSnafu { path })?;
    Ok(value.trim().replace('-', ""))
}

fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::KernelQualificationRunner;

    #[test]
    fn verification_bundle_is_frozen_only_for_recorded_physical_surfaces() -> crate::Result<()> {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
        let bundle = KernelQualificationRunner::new(root).verify()?;
        assert_eq!(bundle.schema_version, 1);
        assert_eq!(bundle.abi_state, "FROZEN_PROVEN_SURFACES_ONLY");
        assert_eq!(bundle.closed_contract_digest.len(), 64);
        assert_eq!(bundle.physical_qualification_sha256.len(), 64);
        assert_eq!(
            bundle
                .capabilities
                .iter()
                .filter(|capability| capability.evidence_digest.is_some())
                .count(),
            3
        );
        Ok(())
    }
}
