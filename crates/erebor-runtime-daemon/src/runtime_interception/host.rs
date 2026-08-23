use std::{
    collections::BTreeMap,
    fs::{self, DirBuilder, File, OpenOptions},
    io::{Read as _, Write as _},
    mem::size_of,
    os::unix::fs::{DirBuilderExt as _, MetadataExt as _, OpenOptionsExt as _},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Receiver, Sender},
        Arc, Mutex, MutexGuard,
    },
    thread::{self, JoinHandle},
    time::Duration,
};

use erebor_interceptor::{
    EffectObservationReader, KernelHost, KernelHostConfig, KernelHostOwner, MapInsertResult,
};
use erebor_interceptor_abi::{
    BindingActivationTargetKeyV1, BindingLifecycleStateV1, ControllerSignalAuthorityKeyV1,
    ControllerSignalAuthorityV1, EffectDefaultKeyV1, EffectDefaultScopeV1,
    EffectObservationHealthV1, EntryKindV1, ExecutionSetBindingStateV1, Id128V1,
    IdentityRuntimeConfigV1, InitialRootStateV1, KernelEffectFamilyV1, KernelEffectOperationV1,
    PhysicalDecisionKindV1, PhysicalDecisionV1, PolicyGenerationModeV1, PolicyGenerationStateV1,
    ProfileGenerationDescriptorV1, CONSERVATIVE_PROCESS_STATE_VECTOR_V1,
    CONTROLLER_SIGNAL_ALLOWED_MASK_V1,
};
use erebor_runtime_core::{OutputPlan, SessionSpec};
use erebor_runtime_session::HeldWorkloadBoundary;
use rustix::fs::{flock, fstat, open, openat, FlockOperation, Mode, OFlags};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use snafu::Snafu;
use uuid::Uuid;
use zerocopy::{FromBytes as _, IntoBytes as _, TryFromBytes as _};

use super::{
    evidence::{
        EvidenceCoverageError, EvidenceCoverageInput, EvidenceOwnerSnapshot, EvidenceRouteError,
        EvidenceRouteSnapshot, KernelEvidenceSnapshot, RuntimeEvidenceRouter,
    },
    policy::{PolicyEffectDecision, PortableEffectClass, RuntimePolicyImage},
};
use crate::config::RuntimeInterceptorConfig;

const CGROUP_ROOT: &str = "/sys/fs/cgroup";
const FIRST_EFFECT_ERRNO: i32 = -13;
const DENY_ERRNO: i16 = -13;
const INITIAL_ROLE_ID: u32 = 1;
const EXTERNAL_ROLE_ID: u32 = 2;
const READER_POLL: Duration = Duration::from_millis(25);
const CLEANUP_POLL: Duration = Duration::from_millis(10);
const CLEANUP_ATTEMPTS: usize = 500;
const EVIDENCE_BARRIER_TIMEOUT: Duration = Duration::from_secs(5);
const STATE_SCHEMA_VERSION: u32 = 1;
const OWNER_IDENTITY_FILE: &str = "owner.json";
const OWNER_IDENTITY_LOCK: &str = "owner.lock";

const IDENTITY_CONFIG_MAP: &str = "identity_config";
const DESCRIPTOR_MAP: &str = "profile_generation_descriptors";
const ACTIVE_PROFILE_MAP: &str = "active_profile_generations";
const ACTIVATION_TARGET_MAP: &str = "binding_activation_targets";
const EFFECT_DEFAULT_MAP: &str = "effect_defaults";
const EXECUTION_BINDING_MAP: &str = "execution_set_bindings";
const SIGNAL_AUTHORITY_MAP: &str = "controller_signal_authorities";
const TASK_REFS_MAP: &str = "profile_generation_task_refs";
const ASYNC_REFS_MAP: &str = "profile_generation_async_refs";
const SOCKET_REFS_MAP: &str = "profile_generation_socket_refs";
const EFFECT_HEALTH_MAP: &str = "effect_observation_health";

pub(crate) type Result<T> = std::result::Result<T, RuntimeKernelInterceptionError>;

#[derive(Debug, Snafu)]
pub(crate) enum RuntimeKernelInterceptionError {
    #[snafu(display("{reason}"))]
    InvalidState { reason: String },
    #[snafu(display("{action} `{}`: {source}", path.display()))]
    Io {
        action: &'static str,
        path: PathBuf,
        source: std::io::Error,
    },
    #[snafu(display("kernel Interceptor operation failed: {source}"))]
    Interceptor { source: erebor_interceptor::Error },
    #[snafu(display("evidence route operation failed: {source}"))]
    Evidence { source: EvidenceRouteError },
    #[snafu(display("evidence coverage operation failed: {source}"))]
    EvidenceCoverage { source: EvidenceCoverageError },
    #[snafu(display("durable Runtime Interceptor record `{}` is invalid: {source}", path.display()))]
    DurableRecord {
        path: PathBuf,
        source: serde_json::Error,
    },
    #[snafu(display("activation failed ({activation}); kernel rollback failed ({rollback})"))]
    ActivationRollback {
        activation: String,
        rollback: String,
    },
}

impl From<erebor_interceptor::Error> for RuntimeKernelInterceptionError {
    fn from(source: erebor_interceptor::Error) -> Self {
        Self::Interceptor { source }
    }
}

impl From<EvidenceRouteError> for RuntimeKernelInterceptionError {
    fn from(source: EvidenceRouteError) -> Self {
        Self::Evidence { source }
    }
}

impl From<EvidenceCoverageError> for RuntimeKernelInterceptionError {
    fn from(source: EvidenceCoverageError) -> Self {
        Self::EvidenceCoverage { source }
    }
}

pub(crate) struct RuntimeKernelInterceptionOwner {
    state: Mutex<RuntimeKernelState>,
    evidence: Arc<RuntimeEvidenceRouter>,
    evidence_barriers: Sender<EvidencePollBarrier>,
    stop_reader: Arc<AtomicBool>,
    reader_thread: Option<JoinHandle<()>>,
}

struct RuntimeKernelState {
    host: KernelHost,
    state_directory: PathBuf,
    node_boot_id: Id128V1,
    label_epoch: u64,
    owner_controller_cgroup_id: u64,
    bindings: BTreeMap<(u32, String), LiveBinding>,
}

struct LiveBinding {
    record: DurableBindingRecordV1,
    record_path: PathBuf,
    evidence_owner_start: EvidenceOwnerSnapshot,
    kernel_evidence_start: KernelEvidenceSnapshot,
    recovery: bool,
}

struct RecoveryBinding {
    record: DurableBindingRecordV1,
    path: PathBuf,
    evidence_failure: Option<String>,
}

struct EvidencePollBarrier {
    acknowledged: mpsc::SyncSender<bool>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct DurableHostOwnerIdentityV1 {
    schema_version: u32,
    runtime_btf_path: PathBuf,
    lease_path: PathBuf,
    pin_root: PathBuf,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum DurableBindingStatusV1 {
    Preparing,
    Active,
    Terminating,
    Tombstoned,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct DurableOperationDecisionV1 {
    effect_family: u16,
    operation: u16,
    deny: bool,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct DurableEvidenceCoverageV1 {
    recovery: bool,
    complete: bool,
    route: EvidenceRouteSnapshot,
    owner_start: EvidenceOwnerSnapshot,
    owner_end: EvidenceOwnerSnapshot,
    kernel_start: KernelEvidenceSnapshot,
    kernel_end: KernelEvidenceSnapshot,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct DurableBindingRecordV1 {
    schema_version: u32,
    status: DurableBindingStatusV1,
    owner_uid: u32,
    session_id: String,
    cgroup_path: PathBuf,
    cgroup_id: u64,
    controller_cgroup_id: u64,
    owner_controller_cgroup_id: u64,
    recovery_controller_cgroup_ids: Vec<u64>,
    output: OutputPlan,
    node_boot_id: Id128V1,
    label_epoch: u64,
    binding_id: Id128V1,
    binding_nonce: Id128V1,
    execution_set_id: Id128V1,
    protected_scope_id: Id128V1,
    profile_id: Id128V1,
    root_cgroup_live_interval_id: Id128V1,
    profile_generation_ref_id: u64,
    policy_image_digest: String,
    table_digest: [u8; 32],
    operation_decisions: Vec<DurableOperationDecisionV1>,
    activation_evidence_owner_start: Option<EvidenceOwnerSnapshot>,
    activation_kernel_evidence_start: Option<KernelEvidenceSnapshot>,
    evidence_coverage: Option<DurableEvidenceCoverageV1>,
    failure: Option<String>,
}

#[derive(Clone)]
struct PreparedActivation {
    record: DurableBindingRecordV1,
    binding: ExecutionSetBindingStateV1,
    descriptor: ProfileGenerationDescriptorV1,
    effect_rows: Vec<(EffectDefaultKeyV1, PhysicalDecisionV1)>,
}

trait KernelMaps {
    fn lookup(&self, map: &str, key: &[u8]) -> Result<Option<Vec<u8>>>;
    fn insert(&self, map: &str, key: &[u8], value: &[u8]) -> Result<bool>;
    fn update(&self, map: &str, key: &[u8], value: &[u8]) -> Result<()>;
    fn delete(&self, map: &str, key: &[u8]) -> Result<()>;
}

impl KernelMaps for KernelHost {
    fn lookup(&self, map: &str, key: &[u8]) -> Result<Option<Vec<u8>>> {
        Ok(self.lookup_map(map, key)?)
    }

    fn insert(&self, map: &str, key: &[u8], value: &[u8]) -> Result<bool> {
        Ok(self.insert_map(map, key, value)? == MapInsertResult::Inserted)
    }

    fn update(&self, map: &str, key: &[u8], value: &[u8]) -> Result<()> {
        Ok(self.update_map(map, key, value)?)
    }

    fn delete(&self, map: &str, key: &[u8]) -> Result<()> {
        Ok(self.delete_map_entry(map, key)?)
    }
}

impl RuntimeKernelInterceptionOwner {
    pub(crate) fn start(config: &RuntimeInterceptorConfig, state_root: &Path) -> Result<Self> {
        let state_directory = state_root.join("runtime-interceptor");
        prepare_state_directory(&state_directory)?;
        ensure_host_owner_identity(
            &state_directory,
            config.runtime_btf_path(),
            config.lease_path(),
            config.pin_root(),
        )?;
        let recovered = config.pin_root().join("maps/identity_config").exists();
        let (label_epoch, advance_label_epoch) = label_epoch(&state_directory, recovered)?;
        let (node_boot_id, boot_id) = node_boot_id()?;
        let owner_controller_cgroup_id = current_cgroup_id()?;
        if advance_label_epoch {
            commit_label_epoch(&state_directory, label_epoch)?;
        }
        let host = KernelHostOwner::new(KernelHostConfig::identity(
            config.runtime_btf_path(),
            config.lease_path(),
            Some(config.pin_root().to_path_buf()),
            boot_id,
            label_epoch,
        ))
        .start()?;
        activate_identity_config(&host, node_boot_id, label_epoch, owner_controller_cgroup_id)?;
        install_mount_zero_rows(&host)?;

        let evidence = Arc::new(RuntimeEvidenceRouter::default());
        let mut recovery = load_durable_bindings(&state_directory)?;
        register_recovery_outputs(&evidence, &mut recovery);
        let recovery_evidence_start = evidence.owner_snapshot();
        let recovery_kernel_start = kernel_evidence_health(&host)?;
        let stop_reader = Arc::new(AtomicBool::new(false));
        let (evidence_barriers, barrier_requests) = mpsc::channel();
        let reader = host.effect_observation_reader({
            let evidence = Arc::clone(&evidence);
            move |bytes| {
                evidence.record_bytes(bytes);
                0
            }
        })?;
        let reader_thread = Some(start_evidence_reader(
            reader,
            Arc::clone(&evidence),
            Arc::clone(&stop_reader),
            barrier_requests,
        )?);
        let mut state = RuntimeKernelState {
            host,
            state_directory,
            node_boot_id,
            label_epoch,
            owner_controller_cgroup_id,
            bindings: BTreeMap::new(),
        };
        if let Err(error) = reclaim_durable_bindings(
            &mut state,
            &evidence,
            recovery,
            recovery_evidence_start,
            recovery_kernel_start,
            &evidence_barriers,
        ) {
            stop_reader.store(true, Ordering::Release);
            if let Some(reader_thread) = reader_thread {
                let _result = reader_thread.join();
            }
            return Err(error);
        }
        Ok(Self {
            state: Mutex::new(state),
            evidence,
            evidence_barriers,
            stop_reader,
            reader_thread,
        })
    }

    pub(crate) fn require_disabled_safe(state_root: &Path) -> Result<()> {
        if durable_host_state_present(&state_root.join("runtime-interceptor"))? {
            return invalid(
                "Runtime Interceptor configuration is absent while durable owner state remains",
            );
        }
        Ok(())
    }

    pub(crate) fn activate(
        &self,
        spec: &SessionSpec,
        boundary: &HeldWorkloadBoundary,
        image: &RuntimePolicyImage,
    ) -> Result<()> {
        let mut state = self.lock_state()?;
        state.host.verify_live_manifest()?;
        let owner_uid = spec.owner().uid();
        let session_id = spec.session_id().as_str();
        let owner_key = session_owner_key(owner_uid, session_id);
        require_evidence_reader(self.evidence.owner_snapshot())?;
        if state.bindings.contains_key(&owner_key) {
            return invalid(format!(
                "session `{session_id}` for owner UID {owner_uid} already has a Runtime Interceptor binding"
            ));
        }
        let prepared = prepare_activation(
            &state,
            owner_uid,
            session_id,
            spec.output(),
            boundary,
            image,
        )?;
        let record_path = durable_record_path(&state.state_directory, prepared.record.binding_id);
        write_durable_record(&state.state_directory, &record_path, &prepared.record)?;
        if let Err(error) = self.evidence.register(prepared.record.binding_id, spec) {
            let mut rejected = prepared.record.clone();
            rejected.status = DurableBindingStatusV1::Tombstoned;
            rejected.failure = Some(error.to_string());
            write_durable_record(&state.state_directory, &record_path, &rejected)?;
            return Err(error.into());
        }
        let evidence_owner_start = self.evidence.owner_snapshot();
        let kernel_evidence_start = match kernel_evidence_health(&state.host) {
            Ok(snapshot) => snapshot,
            Err(error) => {
                let mut rejected = prepared.record.clone();
                rejected.status = DurableBindingStatusV1::Tombstoned;
                rejected.failure = Some(error.to_string());
                let write_result =
                    write_durable_record(&state.state_directory, &record_path, &rejected);
                self.evidence.unregister(prepared.record.binding_id);
                if let Err(write_error) = write_result {
                    return invalid(format!(
                        "evidence health read failed ({error}); durable failure recording also failed ({write_error})"
                    ));
                }
                return Err(error);
            }
        };
        let mut preparing = prepared.record.clone();
        preparing.activation_evidence_owner_start = Some(evidence_owner_start);
        preparing.activation_kernel_evidence_start = Some(kernel_evidence_start);
        if let Err(error) = write_durable_record(&state.state_directory, &record_path, &preparing) {
            let mut rejected = preparing;
            rejected.status = DurableBindingStatusV1::Tombstoned;
            rejected.failure = Some(error.to_string());
            let write_result =
                write_durable_record(&state.state_directory, &record_path, &rejected);
            self.evidence.unregister(prepared.record.binding_id);
            if let Err(write_error) = write_result {
                return invalid(format!(
                    "preparing durable publication failed ({error}); durable failure recording also failed ({write_error})"
                ));
            }
            return Err(error);
        }
        if let Err(error) = publish_activation(&state.host, &prepared, || {
            verify_empty_boundary_record(&prepared.record)
        }) {
            let mut rejected = preparing;
            let rollback_incomplete = matches!(
                &error,
                RuntimeKernelInterceptionError::ActivationRollback { .. }
            );
            rejected.status = if rollback_incomplete {
                DurableBindingStatusV1::Terminating
            } else {
                DurableBindingStatusV1::Tombstoned
            };
            rejected.failure = Some(error.to_string());
            if rollback_incomplete {
                let write_result =
                    write_durable_record(&state.state_directory, &record_path, &rejected);
                state.bindings.insert(
                    owner_key,
                    LiveBinding {
                        record: rejected,
                        record_path,
                        evidence_owner_start,
                        kernel_evidence_start,
                        recovery: false,
                    },
                );
                return match write_result {
                    Ok(()) => Err(error),
                    Err(write_error) => invalid(format!(
                        "activation failed ({error}); durable terminating record also failed ({write_error})"
                    )),
                };
            }
            match capture_final_coverage(
                &self.evidence,
                &state.host,
                rejected.binding_id,
                evidence_owner_start,
                kernel_evidence_start,
                false,
                &self.evidence_barriers,
            ) {
                Ok((coverage, coverage_failure)) => {
                    rejected.evidence_coverage = Some(coverage);
                    if let Some(coverage_failure) = coverage_failure {
                        append_failure(&mut rejected.failure, coverage_failure);
                    }
                }
                Err(coverage_error) => append_failure(
                    &mut rejected.failure,
                    format!("final evidence coverage failed: {coverage_error}"),
                ),
            }
            let write_result =
                write_durable_record(&state.state_directory, &record_path, &rejected);
            self.evidence.unregister(prepared.record.binding_id);
            if let Err(write_error) = write_result {
                return invalid(format!(
                    "activation failed ({error}); durable failure recording also failed ({write_error})"
                ));
            }
            return Err(error);
        }
        let mut active = preparing;
        active.status = DurableBindingStatusV1::Active;
        if let Err(commit_error) =
            write_durable_record(&state.state_directory, &record_path, &active)
        {
            let mut rejected = active;
            rejected.failure = Some(format!("active durable publication failed: {commit_error}"));
            if let Err(rollback_error) = rollback_published_activation(&state.host, &prepared) {
                rejected.status = DurableBindingStatusV1::Terminating;
                append_failure(
                    &mut rejected.failure,
                    format!("kernel rollback failed: {rollback_error}"),
                );
                let failure = RuntimeKernelInterceptionError::ActivationRollback {
                    activation: commit_error.to_string(),
                    rollback: rollback_error.to_string(),
                };
                let write_result =
                    write_durable_record(&state.state_directory, &record_path, &rejected);
                state.bindings.insert(
                    owner_key,
                    LiveBinding {
                        record: rejected,
                        record_path,
                        evidence_owner_start,
                        kernel_evidence_start,
                        recovery: false,
                    },
                );
                return match write_result {
                    Ok(()) => Err(failure),
                    Err(write_error) => invalid(format!(
                        "active durable publication failed ({failure}); durable terminating record also failed ({write_error})"
                    )),
                };
            }
            rejected.status = DurableBindingStatusV1::Tombstoned;
            match capture_final_coverage(
                &self.evidence,
                &state.host,
                rejected.binding_id,
                evidence_owner_start,
                kernel_evidence_start,
                false,
                &self.evidence_barriers,
            ) {
                Ok((coverage, coverage_failure)) => {
                    rejected.evidence_coverage = Some(coverage);
                    if let Some(coverage_failure) = coverage_failure {
                        append_failure(&mut rejected.failure, coverage_failure);
                    }
                }
                Err(coverage_error) => append_failure(
                    &mut rejected.failure,
                    format!("final evidence coverage failed: {coverage_error}"),
                ),
            }
            let failure_record =
                write_durable_record(&state.state_directory, &record_path, &rejected);
            self.evidence.unregister(prepared.record.binding_id);
            return match failure_record {
                Ok(()) => Err(commit_error),
                Err(record_error) => invalid(format!(
                    "active durable publication failed ({commit_error}); failure recording also failed ({record_error})"
                )),
            };
        }
        state.bindings.insert(
            owner_key,
            LiveBinding {
                record: active,
                record_path,
                evidence_owner_start,
                kernel_evidence_start,
                recovery: false,
            },
        );
        Ok(())
    }

    pub(crate) fn cleanup(&self, spec: &SessionSpec) -> Result<()> {
        let mut state = self.lock_state()?;
        let session_id = spec.session_id().as_str();
        let owner_key = session_owner_key(spec.owner().uid(), session_id);
        let Some(mut live) = state.bindings.remove(&owner_key) else {
            return Ok(());
        };
        if live.record.owner_uid != spec.owner().uid() || live.record.session_id != session_id {
            state.bindings.insert(owner_key, live);
            return invalid("the live Runtime Interceptor binding has a different session owner");
        }
        if let Err(error) = cleanup_binding(
            &mut state,
            &mut live,
            &self.evidence,
            &self.evidence_barriers,
        ) {
            state.bindings.insert(owner_key, live);
            return Err(error);
        }
        Ok(())
    }

    fn lock_state(&self) -> Result<MutexGuard<'_, RuntimeKernelState>> {
        self.state
            .lock()
            .map_err(|_error| RuntimeKernelInterceptionError::InvalidState {
                reason: "Runtime Interceptor host state lock is poisoned".to_owned(),
            })
    }
}

impl Drop for RuntimeKernelInterceptionOwner {
    fn drop(&mut self) {
        self.stop_reader.store(true, Ordering::Release);
        if let Some(reader_thread) = self.reader_thread.take() {
            let _result = reader_thread.join();
        }
    }
}

fn invalid<T>(reason: impl Into<String>) -> Result<T> {
    Err(RuntimeKernelInterceptionError::InvalidState {
        reason: reason.into(),
    })
}

fn start_evidence_reader(
    reader: EffectObservationReader,
    evidence: Arc<RuntimeEvidenceRouter>,
    stop: Arc<AtomicBool>,
    barrier_requests: Receiver<EvidencePollBarrier>,
) -> Result<JoinHandle<()>> {
    thread::Builder::new()
        .name("erebor-effect-evidence".to_owned())
        .spawn(move || {
            while !stop.load(Ordering::Acquire) {
                if let Ok(barrier) = barrier_requests.try_recv() {
                    let succeeded = reader.poll(READER_POLL).is_ok();
                    if succeeded {
                        evidence.record_poll_success();
                    } else {
                        evidence.record_poll_failure();
                    }
                    let _result = barrier.acknowledged.send(succeeded);
                    if !succeeded {
                        break;
                    }
                    continue;
                }
                if reader.poll(READER_POLL).is_err() {
                    evidence.record_poll_failure();
                    break;
                }
                evidence.record_poll_success();
            }
        })
        .map_err(|source| RuntimeKernelInterceptionError::Io {
            action: "starting the effect evidence reader",
            path: PathBuf::from("<effect-observation-reader>"),
            source,
        })
}

fn prepare_activation(
    state: &RuntimeKernelState,
    owner_uid: u32,
    session_id: &str,
    output: &OutputPlan,
    boundary: &HeldWorkloadBoundary,
    image: &RuntimePolicyImage,
) -> Result<PreparedActivation> {
    let (cgroup_path, cgroup_id, controller_cgroup_id) = match boundary {
        HeldWorkloadBoundary::LinuxCgroup {
            path,
            id,
            controller_id,
        } => (path.clone(), *id, *controller_id),
    };
    verify_boundary(&cgroup_path, cgroup_id, controller_cgroup_id, true)?;
    let binding_id = derived_id(
        b"EREBOR-RUNTIME-BINDING-V1\0",
        owner_uid,
        session_id,
        cgroup_id,
        state.label_epoch,
    );
    let binding_nonce = derived_id(
        b"EREBOR-RUNTIME-BINDING-NONCE-V1\0",
        owner_uid,
        session_id,
        cgroup_id,
        state.label_epoch,
    );
    let execution_set_id = derived_id(
        b"EREBOR-RUNTIME-EXECUTION-SET-V1\0",
        owner_uid,
        session_id,
        cgroup_id,
        state.label_epoch,
    );
    let protected_scope_id = derived_id(
        b"EREBOR-RUNTIME-PROTECTED-SCOPE-V1\0",
        owner_uid,
        session_id,
        cgroup_id,
        state.label_epoch,
    );
    let profile_id = derived_id(
        b"EREBOR-RUNTIME-PROFILE-V1\0",
        owner_uid,
        session_id,
        cgroup_id,
        state.label_epoch,
    );
    let root_cgroup_live_interval_id = derived_id(
        b"EREBOR-RUNTIME-CGROUP-INTERVAL-V1\0",
        owner_uid,
        session_id,
        cgroup_id,
        state.label_epoch,
    );
    let profile_generation_ref_id = derived_generation(
        b"EREBOR-RUNTIME-GENERATION-V1\0",
        owner_uid,
        session_id,
        cgroup_id,
        state.label_epoch,
    );
    let operation_decisions = operation_decisions(image);
    let effect_rows = effect_rows(profile_generation_ref_id, &operation_decisions);
    let table_digest = effect_table_digest(image, &effect_rows);
    let binding = ExecutionSetBindingStateV1 {
        binding_id,
        binding_nonce,
        node_boot_id: state.node_boot_id,
        execution_set_id,
        protected_scope_id,
        profile_id,
        label_epoch: state.label_epoch,
        active_profile_generation_ref_id: profile_generation_ref_id,
        root_cgroup_id: cgroup_id,
        root_cgroup_live_interval_id,
        container_generation: 1,
        lifecycle_generation: 1,
        transition_version: 2,
        initial_role_id: INITIAL_ROLE_ID,
        external_role_id: EXTERNAL_ROLE_ID,
        lifecycle_state: BindingLifecycleStateV1::Active,
        reserved: [0; 7],
        initial_root_state: InitialRootStateV1::Available,
    };
    let descriptor = ProfileGenerationDescriptorV1 {
        node_boot_id: state.node_boot_id,
        profile_id,
        label_epoch: state.label_epoch,
        profile_generation_ref_id,
        owner_generation: 1,
        row_count: 0,
        default_count: u32::try_from(effect_rows.len()).unwrap_or(u32::MAX),
        state: PolicyGenerationStateV1::Active,
        mode: PolicyGenerationModeV1::Protect,
        reserved: [0; 6],
        table_digest,
        transition_version: 3,
    };
    Ok(PreparedActivation {
        record: DurableBindingRecordV1 {
            schema_version: STATE_SCHEMA_VERSION,
            status: DurableBindingStatusV1::Preparing,
            owner_uid,
            session_id: session_id.to_owned(),
            cgroup_path,
            cgroup_id,
            controller_cgroup_id,
            owner_controller_cgroup_id: state.owner_controller_cgroup_id,
            recovery_controller_cgroup_ids: Vec::new(),
            output: output.clone(),
            node_boot_id: state.node_boot_id,
            label_epoch: state.label_epoch,
            binding_id,
            binding_nonce,
            execution_set_id,
            protected_scope_id,
            profile_id,
            root_cgroup_live_interval_id,
            profile_generation_ref_id,
            policy_image_digest: image.digest().as_str().to_owned(),
            table_digest,
            operation_decisions,
            activation_evidence_owner_start: None,
            activation_kernel_evidence_start: None,
            evidence_coverage: None,
            failure: None,
        },
        binding,
        descriptor,
        effect_rows,
    })
}

#[derive(Clone, Copy)]
enum OperationPolicy {
    Allow,
    Deny,
    Portable(PortableEffectClass),
    Compose(PortableEffectClass, PortableEffectClass),
}

use KernelEffectFamilyV1 as Family;
use KernelEffectOperationV1 as Operation;

const OPERATION_MATRIX: [(Family, Operation, OperationPolicy); 39] = [
    (
        Family::Exec,
        Operation::Execute,
        OperationPolicy::Portable(PortableEffectClass::ProcessExec),
    ),
    (
        Family::File,
        Operation::OpenRead,
        OperationPolicy::Compose(PortableEffectClass::FileOpen, PortableEffectClass::FileRead),
    ),
    (
        Family::File,
        Operation::OpenWrite,
        OperationPolicy::Compose(
            PortableEffectClass::FileOpen,
            PortableEffectClass::FileMutation,
        ),
    ),
    (
        Family::File,
        Operation::Read,
        OperationPolicy::Portable(PortableEffectClass::FileRead),
    ),
    (
        Family::File,
        Operation::Write,
        OperationPolicy::Portable(PortableEffectClass::FileMutation),
    ),
    (Family::Device, Operation::Ioctl, OperationPolicy::Allow),
    (
        Family::File,
        Operation::MmapRead,
        OperationPolicy::Portable(PortableEffectClass::FileRead),
    ),
    (
        Family::File,
        Operation::MmapWrite,
        OperationPolicy::Portable(PortableEffectClass::FileMutation),
    ),
    (
        Family::File,
        Operation::MmapExec,
        OperationPolicy::Portable(PortableEffectClass::FileRead),
    ),
    (
        Family::File,
        Operation::Mprotect,
        OperationPolicy::Portable(PortableEffectClass::FileMutation),
    ),
    (Family::Ipc, Operation::IpcAccess, OperationPolicy::Allow),
    (
        Family::Network,
        Operation::Connect,
        OperationPolicy::Portable(PortableEffectClass::SocketConnect),
    ),
    (Family::Network, Operation::Send, OperationPolicy::Allow),
    (Family::Privilege, Operation::Ptrace, OperationPolicy::Deny),
    (Family::Privilege, Operation::Signal, OperationPolicy::Allow),
    (
        Family::File,
        Operation::Unlink,
        OperationPolicy::Portable(PortableEffectClass::FileMutation),
    ),
    (
        Family::File,
        Operation::Link,
        OperationPolicy::Portable(PortableEffectClass::FileMutation),
    ),
    (
        Family::File,
        Operation::Rename,
        OperationPolicy::Portable(PortableEffectClass::FileMutation),
    ),
    (Family::Mount, Operation::Mount, OperationPolicy::Allow),
    (Family::Mount, Operation::Unmount, OperationPolicy::Allow),
    (Family::Mount, Operation::PivotRoot, OperationPolicy::Allow),
    (Family::Mount, Operation::MoveMount, OperationPolicy::Allow),
    (
        Family::Privilege,
        Operation::Capability,
        OperationPolicy::Allow,
    ),
    (Family::Privilege, Operation::Bpf, OperationPolicy::Deny),
    (
        Family::File,
        Operation::Create,
        OperationPolicy::Portable(PortableEffectClass::FileMutation),
    ),
    (
        Family::File,
        Operation::Setattr,
        OperationPolicy::Portable(PortableEffectClass::FileMutation),
    ),
    (
        Family::Privilege,
        Operation::IoUringSetup,
        OperationPolicy::Deny,
    ),
    (
        Family::Privilege,
        Operation::IoUringRegister,
        OperationPolicy::Deny,
    ),
    (
        Family::Privilege,
        Operation::IoUringSqpoll,
        OperationPolicy::Deny,
    ),
    (
        Family::Privilege,
        Operation::IoUringOverrideCreds,
        OperationPolicy::Deny,
    ),
    (
        Family::Privilege,
        Operation::IoUringCommand,
        OperationPolicy::Deny,
    ),
    (
        Family::Network,
        Operation::SocketCreate,
        OperationPolicy::Allow,
    ),
    (Family::Network, Operation::Bind, OperationPolicy::Allow),
    (Family::Network, Operation::Listen, OperationPolicy::Allow),
    (Family::Network, Operation::Accept, OperationPolicy::Allow),
    (Family::Network, Operation::Receive, OperationPolicy::Allow),
    (Family::Network, Operation::Shutdown, OperationPolicy::Allow),
    (
        Family::Network,
        Operation::Setsockopt,
        OperationPolicy::Allow,
    ),
    (
        Family::File,
        Operation::OpenPath,
        OperationPolicy::Portable(PortableEffectClass::FileOpen),
    ),
];

fn operation_decisions(image: &RuntimePolicyImage) -> Vec<DurableOperationDecisionV1> {
    let policy = image
        .decisions()
        .map(|(class, decision)| (class, matches!(decision, PolicyEffectDecision::Deny { .. })))
        .collect::<BTreeMap<_, _>>();
    let deny = |class| policy.get(&class).copied().unwrap_or(true);
    OPERATION_MATRIX
        .iter()
        .map(|&(family, operation, operation_policy)| {
            let deny = match operation_policy {
                OperationPolicy::Allow => false,
                OperationPolicy::Deny => true,
                OperationPolicy::Portable(class) => deny(class),
                OperationPolicy::Compose(left, right) => deny(left) || deny(right),
            };
            row(family, operation, deny)
        })
        .collect()
}

const fn row(
    family: KernelEffectFamilyV1,
    operation: KernelEffectOperationV1,
    deny: bool,
) -> DurableOperationDecisionV1 {
    DurableOperationDecisionV1 {
        effect_family: family as u16,
        operation: operation as u16,
        deny,
    }
}

fn effect_rows(
    generation: u64,
    operations: &[DurableOperationDecisionV1],
) -> Vec<(EffectDefaultKeyV1, PhysicalDecisionV1)> {
    operations
        .iter()
        .map(|operation| {
            (
                EffectDefaultKeyV1 {
                    profile_generation_ref_id: generation,
                    active_role_id: INITIAL_ROLE_ID,
                    entry_kind: EntryKindV1::ContainerStart as u16,
                    effect_family: operation.effect_family,
                    operation: operation.operation,
                    reserved: EffectDefaultScopeV1::Operation as u16,
                    reserved_alignment: [0; 4],
                    composite_atom_id: 0,
                    process_state_vector_id: CONSERVATIVE_PROCESS_STATE_VECTOR_V1,
                    binding_lifecycle_state: BindingLifecycleStateV1::Active,
                    reserved_tail: [0; 3],
                },
                PhysicalDecisionV1 {
                    decision: if operation.deny {
                        PhysicalDecisionKindV1::Deny
                    } else {
                        PhysicalDecisionKindV1::Allow
                    },
                    reserved: 0,
                    errno: if operation.deny { DENY_ERRNO } else { 0 },
                    evidence_class_id: 1,
                    transition_id: 0,
                    exception_numeric_handle: 0,
                },
            )
        })
        .collect()
}

fn effect_table_digest(
    image: &RuntimePolicyImage,
    rows: &[(EffectDefaultKeyV1, PhysicalDecisionV1)],
) -> [u8; 32] {
    effect_table_digest_from(image.digest().as_str(), rows)
}

fn effect_table_digest_from(
    policy_image_digest: &str,
    rows: &[(EffectDefaultKeyV1, PhysicalDecisionV1)],
) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"EREBOR-RUNTIME-EFFECT-TABLE-V1\0");
    digest.update(policy_image_digest.as_bytes());
    for (key, value) in rows {
        digest.update(key.as_bytes());
        digest.update(value.as_bytes());
    }
    digest.finalize().into()
}

fn prepare_state_directory(state_directory: &Path) -> Result<()> {
    let bindings = state_directory.join("bindings");
    for directory in [state_directory, bindings.as_path()] {
        DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(directory)
            .map_err(|source| io_error("creating Runtime Interceptor state", directory, source))?;
        let metadata = fs::symlink_metadata(directory)
            .map_err(|source| io_error("verifying Runtime Interceptor state", directory, source))?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() || metadata.mode() & 0o077 != 0 {
            return invalid(format!(
                "Runtime Interceptor state `{}` is not a private directory",
                directory.display()
            ));
        }
    }
    Ok(())
}

fn ensure_host_owner_identity(
    state_directory: &Path,
    runtime_btf_path: &Path,
    lease_path: &Path,
    pin_root: &Path,
) -> Result<()> {
    let expected = DurableHostOwnerIdentityV1 {
        schema_version: STATE_SCHEMA_VERSION,
        runtime_btf_path: runtime_btf_path.to_path_buf(),
        lease_path: lease_path.to_path_buf(),
        pin_root: pin_root.to_path_buf(),
    };
    let lock_path = state_directory.join(OWNER_IDENTITY_LOCK);
    let lock = open_private_lock(&lock_path)?;
    flock(&lock, FlockOperation::NonBlockingLockExclusive).map_err(|_error| {
        RuntimeKernelInterceptionError::InvalidState {
            reason: "another daemon is publishing the Runtime Interceptor owner identity"
                .to_owned(),
        }
    })?;

    let path = state_directory.join(OWNER_IDENTITY_FILE);
    if let Some(actual) = read_host_owner_identity(&path)? {
        return require_same_host_owner(&expected, &actual);
    }
    let temporary = path.with_extension("next");
    if let Some(actual) = read_host_owner_identity(&temporary)? {
        require_same_host_owner(&expected, &actual)?;
        fs::rename(&temporary, &path)
            .map_err(|source| io_error("recovering the host owner identity", &path, source))?;
        return sync_directory(state_directory, "syncing the host owner identity directory");
    }
    if durable_host_state_present(state_directory)?
        || path_entry_exists(&pin_root.join("maps/identity_config"))?
    {
        return invalid("durable Runtime Interceptor state exists without a host owner identity");
    }

    let mut bytes = serde_json::to_vec(&expected).map_err(|source| {
        RuntimeKernelInterceptionError::DurableRecord {
            path: path.clone(),
            source,
        }
    })?;
    bytes.push(b'\n');
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(&temporary)
        .map_err(|source| io_error("opening the next host owner identity", &temporary, source))?;
    file.write_all(&bytes)
        .map_err(|source| io_error("writing the next host owner identity", &temporary, source))?;
    file.sync_all()
        .map_err(|source| io_error("syncing the next host owner identity", &temporary, source))?;
    fs::rename(&temporary, &path)
        .map_err(|source| io_error("committing the host owner identity", &path, source))?;
    sync_directory(state_directory, "syncing the host owner identity directory")
}

fn open_private_lock(path: &Path) -> Result<File> {
    match open(
        path,
        OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::from(0o600),
    ) {
        Ok(file) => Ok(File::from(file)),
        Err(error) if error == rustix::io::Errno::EXIST => {
            let metadata = fs::symlink_metadata(path)
                .map_err(|source| io_error("verifying the host owner lock", path, source))?;
            if !metadata.is_file()
                || metadata.file_type().is_symlink()
                || metadata.mode() & 0o077 != 0
            {
                return invalid("the Runtime Interceptor host owner lock is not private");
            }
            open(
                path,
                OFlags::RDWR | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                Mode::empty(),
            )
            .map(File::from)
            .map_err(std::io::Error::from)
            .map_err(|source| io_error("opening the host owner lock", path, source))
        }
        Err(source) => Err(io_error(
            "creating the host owner lock",
            path,
            std::io::Error::from(source),
        )),
    }
}

fn read_host_owner_identity(path: &Path) -> Result<Option<DurableHostOwnerIdentityV1>> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(source) => return Err(io_error("verifying the host owner identity", path, source)),
    };
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.mode() & 0o077 != 0 {
        return invalid("the Runtime Interceptor host owner identity is not private");
    }
    let bytes = fs::read(path)
        .map_err(|source| io_error("reading the host owner identity", path, source))?;
    let identity: DurableHostOwnerIdentityV1 =
        serde_json::from_slice(&bytes).map_err(|source| {
            RuntimeKernelInterceptionError::DurableRecord {
                path: path.to_path_buf(),
                source,
            }
        })?;
    if identity.schema_version != STATE_SCHEMA_VERSION
        || !identity.runtime_btf_path.is_absolute()
        || !identity.lease_path.is_absolute()
        || !identity.pin_root.is_absolute()
    {
        return invalid("the Runtime Interceptor host owner identity is invalid");
    }
    Ok(Some(identity))
}

fn require_same_host_owner(
    expected: &DurableHostOwnerIdentityV1,
    actual: &DurableHostOwnerIdentityV1,
) -> Result<()> {
    if expected != actual {
        return invalid(
            "Runtime Interceptor configuration changed its durable host owner identity",
        );
    }
    Ok(())
}

fn durable_host_state_present(state_directory: &Path) -> Result<bool> {
    let metadata = match fs::symlink_metadata(state_directory) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(source) => {
            return Err(io_error(
                "verifying Runtime Interceptor durable state",
                state_directory,
                source,
            ));
        }
    };
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Ok(true);
    }
    let bindings = state_directory.join("bindings");
    for entry in fs::read_dir(state_directory).map_err(|source| {
        io_error(
            "reading Runtime Interceptor durable state",
            state_directory,
            source,
        )
    })? {
        let entry = entry.map_err(|source| {
            io_error(
                "reading a Runtime Interceptor durable state entry",
                state_directory,
                source,
            )
        })?;
        if entry.path() == state_directory.join(OWNER_IDENTITY_LOCK) {
            continue;
        }
        if entry.path() == bindings {
            let file_type = entry.file_type().map_err(|source| {
                io_error("verifying the durable binding directory", &bindings, source)
            })?;
            if !file_type.is_dir()
                || file_type.is_symlink()
                || fs::read_dir(&bindings)
                    .map_err(|source| {
                        io_error("reading the durable binding directory", &bindings, source)
                    })?
                    .next()
                    .is_some()
            {
                return Ok(true);
            }
            continue;
        }
        return Ok(true);
    }
    Ok(false)
}

fn path_entry_exists(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_metadata) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(source) => Err(io_error(
            "verifying Runtime Interceptor pinned state",
            path,
            source,
        )),
    }
}

fn label_epoch(state_directory: &Path, recover: bool) -> Result<(u64, bool)> {
    let path = state_directory.join("label-epoch");
    let current = match fs::read_to_string(&path) {
        Ok(value) => value.trim().parse::<u64>().map_err(|error| {
            RuntimeKernelInterceptionError::InvalidState {
                reason: format!("stored Runtime Interceptor label epoch is invalid: {error}"),
            }
        })?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => 0,
        Err(source) => return Err(io_error("reading the label epoch", &path, source)),
    };
    if recover {
        if current == 0 {
            return invalid("pinned Runtime Interceptor state has no durable label epoch");
        }
        return Ok((current, false));
    }
    let next =
        current
            .checked_add(1)
            .ok_or_else(|| RuntimeKernelInterceptionError::InvalidState {
                reason: "Runtime Interceptor label epoch is exhausted".to_owned(),
            })?;
    Ok((next, true))
}

fn commit_label_epoch(state_directory: &Path, label_epoch: u64) -> Result<()> {
    let path = state_directory.join("label-epoch");
    let temporary = path.with_extension("next");
    let mut file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .mode(0o600)
        .open(&temporary)
        .map_err(|source| io_error("opening the next label epoch", &temporary, source))?;
    file.write_all(format!("{label_epoch}\n").as_bytes())
        .map_err(|source| io_error("writing the next label epoch", &temporary, source))?;
    file.sync_all()
        .map_err(|source| io_error("syncing the next label epoch", &temporary, source))?;
    fs::rename(&temporary, &path)
        .map_err(|source| io_error("committing the label epoch", &path, source))?;
    sync_directory(state_directory, "syncing the label epoch directory")
}

fn node_boot_id() -> Result<(Id128V1, String)> {
    let path = Path::new("/proc/sys/kernel/random/boot_id");
    let value = fs::read_to_string(path)
        .map_err(|source| io_error("reading the kernel boot ID", path, source))?;
    let boot_id = Uuid::parse_str(value.trim()).map_err(|error| {
        RuntimeKernelInterceptionError::InvalidState {
            reason: format!("kernel boot ID is invalid: {error}"),
        }
    })?;
    Ok((Id128V1::from(*boot_id.as_bytes()), boot_id.to_string()))
}

fn current_cgroup_id() -> Result<u64> {
    let proc_path = Path::new("/proc/self/cgroup");
    let value = fs::read_to_string(proc_path)
        .map_err(|source| io_error("reading the daemon cgroup", proc_path, source))?;
    let mut paths = value.lines().filter_map(|line| line.strip_prefix("0::"));
    let relative = paths
        .next()
        .ok_or_else(|| RuntimeKernelInterceptionError::InvalidState {
            reason: "the daemon has no unified cgroup identity".to_owned(),
        })?;
    if paths.next().is_some() {
        return invalid("the daemon has more than one unified cgroup identity");
    }
    let path = Path::new(CGROUP_ROOT).join(relative.trim_start_matches('/'));
    let canonical_root = fs::canonicalize(CGROUP_ROOT).map_err(|source| {
        io_error(
            "resolving the unified cgroup root",
            Path::new(CGROUP_ROOT),
            source,
        )
    })?;
    let canonical = fs::canonicalize(&path)
        .map_err(|source| io_error("resolving the daemon cgroup", &path, source))?;
    if canonical == canonical_root || !canonical.starts_with(&canonical_root) {
        return invalid("the daemon requires a non-root unified cgroup");
    }
    let directory = open(
        &path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map(File::from)
    .map_err(std::io::Error::from)
    .map_err(|source| io_error("opening the daemon cgroup", &path, source))?;
    let descriptor = fstat(&directory)
        .map_err(std::io::Error::from)
        .map_err(|source| io_error("reading the daemon cgroup identity", &path, source))?;
    let metadata = fs::symlink_metadata(&path)
        .map_err(|source| io_error("verifying the daemon cgroup", &path, source))?;
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.ino() != descriptor.st_ino
        || metadata.dev() != descriptor.st_dev
        || descriptor.st_ino == 0
    {
        return invalid("the daemon cgroup identity changed during startup");
    }
    Ok(descriptor.st_ino)
}

fn activate_identity_config(
    host: &impl KernelMaps,
    node_boot_id: Id128V1,
    label_epoch: u64,
    owner_controller_cgroup_id: u64,
) -> Result<()> {
    let key = 0_u32.to_ne_bytes();
    let bytes = host.lookup(IDENTITY_CONFIG_MAP, &key)?.ok_or_else(|| {
        RuntimeKernelInterceptionError::InvalidState {
            reason: "identity config map has no zero-key row".to_owned(),
        }
    })?;
    let mut desired = IdentityRuntimeConfigV1 {
        node_boot_id,
        label_epoch,
        next_id: 1,
        effect_controller_cgroup_id: owner_controller_cgroup_id,
        first_effect_errno: FIRST_EFFECT_ERRNO,
        enabled: 1,
        effect_policy_enabled: 1,
        reserved: [0; 2],
    };
    if bytes.iter().any(|byte| *byte != 0) {
        let existing = IdentityRuntimeConfigV1::read_from_bytes(&bytes).map_err(|error| {
            RuntimeKernelInterceptionError::InvalidState {
                reason: format!("identity config map has an invalid ABI row: {error}"),
            }
        })?;
        if existing.node_boot_id != node_boot_id
            || existing.label_epoch != label_epoch
            || existing.next_id == 0
            || existing.first_effect_errno != FIRST_EFFECT_ERRNO
            || existing.enabled != 1
            || existing.effect_policy_enabled > 1
            || existing.reserved != [0; 2]
        {
            return invalid("recovered identity config belongs to another owner");
        }
        desired.next_id = existing.next_id;
    }
    update_readback(host, IDENTITY_CONFIG_MAP, &key, desired.as_bytes())
}

fn install_mount_zero_rows(host: &impl KernelMaps) -> Result<()> {
    let key = 0_u32.to_ne_bytes();
    for (map, initial) in [
        ("mount_global_mutation_epoch", 1_u64),
        ("mount_global_clean_epoch", 0),
        ("mount_global_pending_mutations", 0),
        ("mount_global_ambiguous_epoch", 1),
    ] {
        if host.lookup(map, &key)?.is_none() {
            host.update(map, &key, &initial.to_ne_bytes())?;
        }
    }
    let mutation = read_u64_map(host, "mount_global_mutation_epoch", &key)?.ok_or_else(|| {
        RuntimeKernelInterceptionError::InvalidState {
            reason: "global mount mutation epoch is absent".to_owned(),
        }
    })?;
    let clean = read_u64_map(host, "mount_global_clean_epoch", &key)?.ok_or_else(|| {
        RuntimeKernelInterceptionError::InvalidState {
            reason: "global mount clean epoch is absent".to_owned(),
        }
    })?;
    let pending = read_u64_map(host, "mount_global_pending_mutations", &key)?.ok_or_else(|| {
        RuntimeKernelInterceptionError::InvalidState {
            reason: "global mount pending count is absent".to_owned(),
        }
    })?;
    let ambiguous = read_u64_map(host, "mount_global_ambiguous_epoch", &key)?.ok_or_else(|| {
        RuntimeKernelInterceptionError::InvalidState {
            reason: "global mount ambiguous epoch is absent".to_owned(),
        }
    })?;
    if mutation == 0 || clean > mutation || pending != 0 || ambiguous == 0 {
        return invalid("global mount security barrier readback is invalid");
    }
    Ok(())
}

fn kernel_evidence_health(host: &impl KernelMaps) -> Result<KernelEvidenceSnapshot> {
    let bytes = host
        .lookup(EFFECT_HEALTH_MAP, &0_u32.to_ne_bytes())?
        .ok_or_else(|| RuntimeKernelInterceptionError::InvalidState {
            reason: "effect evidence health map has no zero-key row".to_owned(),
        })?;
    if bytes.is_empty() || bytes.len() % size_of::<EffectObservationHealthV1>() != 0 {
        return invalid("effect evidence health map has an invalid ABI row");
    }
    let mut snapshot = KernelEvidenceSnapshot::default();
    for bytes in bytes.chunks_exact(size_of::<EffectObservationHealthV1>()) {
        let value = EffectObservationHealthV1::read_from_bytes(bytes).map_err(|error| {
            RuntimeKernelInterceptionError::InvalidState {
                reason: format!("effect evidence health map has an invalid ABI row: {error}"),
            }
        })?;
        snapshot.attempted = snapshot.attempted.saturating_add(value.attempted);
        snapshot.suppressed = snapshot.suppressed.saturating_add(value.suppressed);
        snapshot.requested = snapshot.requested.saturating_add(value.requested);
        snapshot.emitted = snapshot.emitted.saturating_add(value.emitted);
        snapshot.lost = snapshot.lost.saturating_add(value.lost);
        snapshot.classifier_miss_count = snapshot
            .classifier_miss_count
            .saturating_add(value.classifier_miss_count);
        snapshot.unresolved = snapshot.unresolved.saturating_add(value.unresolved);
    }
    Ok(snapshot)
}

fn derived_id(
    domain: &[u8],
    owner_uid: u32,
    session_id: &str,
    cgroup_id: u64,
    label_epoch: u64,
) -> Id128V1 {
    let mut digest = Sha256::new();
    digest.update(domain);
    digest.update(owner_uid.to_be_bytes());
    digest.update((session_id.len() as u64).to_be_bytes());
    digest.update(session_id.as_bytes());
    digest.update(cgroup_id.to_be_bytes());
    digest.update(label_epoch.to_be_bytes());
    let mut id = Id128V1::from(<[u8; 32]>::from(digest.finalize()));
    if id.is_zero() {
        id.low = 1;
    }
    id
}

fn derived_generation(
    domain: &[u8],
    owner_uid: u32,
    session_id: &str,
    cgroup_id: u64,
    label_epoch: u64,
) -> u64 {
    let id = derived_id(domain, owner_uid, session_id, cgroup_id, label_epoch);
    let generation = id.high ^ id.low;
    if generation == 0 {
        1
    } else {
        generation
    }
}

fn session_owner_key(owner_uid: u32, session_id: &str) -> (u32, String) {
    (owner_uid, session_id.to_owned())
}

fn io_error(
    action: &'static str,
    path: impl Into<PathBuf>,
    source: std::io::Error,
) -> RuntimeKernelInterceptionError {
    RuntimeKernelInterceptionError::Io {
        action,
        path: path.into(),
        source,
    }
}

fn sync_directory(directory: &Path, action: &'static str) -> Result<()> {
    File::open(directory)
        .and_then(|directory| directory.sync_all())
        .map_err(|source| io_error(action, directory, source))
}

fn durable_record_path(state_directory: &Path, binding_id: Id128V1) -> PathBuf {
    state_directory
        .join("bindings")
        .join(format!("{}.json", hex::encode(binding_id.to_be_bytes())))
}

fn write_durable_record(
    state_directory: &Path,
    path: &Path,
    record: &DurableBindingRecordV1,
) -> Result<()> {
    let directory = state_directory.join("bindings");
    if path.parent() != Some(directory.as_path()) {
        return invalid("durable binding record escaped its owner directory");
    }
    let mut bytes = serde_json::to_vec(record).map_err(|source| {
        RuntimeKernelInterceptionError::DurableRecord {
            path: path.to_path_buf(),
            source,
        }
    })?;
    bytes.push(b'\n');
    let temporary = path.with_extension("next");
    let mut file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .mode(0o600)
        .open(&temporary)
        .map_err(|source| io_error("opening a durable binding record", &temporary, source))?;
    file.write_all(&bytes)
        .map_err(|source| io_error("writing a durable binding record", &temporary, source))?;
    file.sync_all()
        .map_err(|source| io_error("syncing a durable binding record", &temporary, source))?;
    fs::rename(&temporary, path)
        .map_err(|source| io_error("committing a durable binding record", path, source))?;
    sync_directory(&directory, "syncing the durable binding directory")
}

fn publish_activation(
    maps: &impl KernelMaps,
    prepared: &PreparedActivation,
    recheck_empty: impl FnOnce() -> Result<()>,
) -> Result<()> {
    let mut installed = Vec::new();
    let result = (|| {
        let generation_key = prepared.record.profile_generation_ref_id.to_ne_bytes();
        let mut descriptor = prepared.descriptor;
        descriptor.state = PolicyGenerationStateV1::Preparing;
        descriptor.transition_version = 1;
        install_row(
            maps,
            &mut installed,
            DESCRIPTOR_MAP,
            &generation_key,
            descriptor.as_bytes(),
        )?;
        for map in [TASK_REFS_MAP, ASYNC_REFS_MAP, SOCKET_REFS_MAP] {
            install_row(
                maps,
                &mut installed,
                map,
                &generation_key,
                &0_u64.to_ne_bytes(),
            )?;
        }
        for (key, value) in &prepared.effect_rows {
            install_row(
                maps,
                &mut installed,
                EFFECT_DEFAULT_MAP,
                key.as_bytes(),
                value.as_bytes(),
            )?;
        }
        descriptor.state = PolicyGenerationStateV1::ReadBack;
        descriptor.transition_version = 2;
        update_readback(maps, DESCRIPTOR_MAP, &generation_key, descriptor.as_bytes())?;
        descriptor.state = PolicyGenerationStateV1::Active;
        descriptor.transition_version = 3;
        update_readback(maps, DESCRIPTOR_MAP, &generation_key, descriptor.as_bytes())?;
        install_row(
            maps,
            &mut installed,
            ACTIVE_PROFILE_MAP,
            prepared.record.profile_id.as_bytes(),
            &prepared.record.profile_generation_ref_id.to_ne_bytes(),
        )?;
        let activation_key = BindingActivationTargetKeyV1 {
            binding_id: prepared.record.binding_id,
            profile_generation_ref_id: prepared.record.profile_generation_ref_id,
        };
        install_row(
            maps,
            &mut installed,
            ACTIVATION_TARGET_MAP,
            activation_key.as_bytes(),
            prepared.binding.as_bytes(),
        )?;
        let signal_authority = ControllerSignalAuthorityV1 {
            allowed_signal_mask: CONTROLLER_SIGNAL_ALLOWED_MASK_V1,
        };
        for key in signal_authority_keys(&prepared.record) {
            install_row(
                maps,
                &mut installed,
                SIGNAL_AUTHORITY_MAP,
                key.as_bytes(),
                signal_authority.as_bytes(),
            )?;
        }
        let binding_key = prepared.record.cgroup_id.to_ne_bytes();
        let mut binding = prepared.binding;
        binding.lifecycle_state = BindingLifecycleStateV1::Preparing;
        binding.transition_version = 1;
        install_row(
            maps,
            &mut installed,
            EXECUTION_BINDING_MAP,
            &binding_key,
            binding.as_bytes(),
        )?;
        recheck_empty()?;
        update_readback(
            maps,
            EXECUTION_BINDING_MAP,
            &binding_key,
            prepared.binding.as_bytes(),
        )
    })();
    if let Err(error) = result {
        if let Err(rollback) = rollback_rows(maps, &installed) {
            return Err(RuntimeKernelInterceptionError::ActivationRollback {
                activation: error.to_string(),
                rollback: rollback.to_string(),
            });
        }
        return Err(error);
    }
    Ok(())
}

fn rollback_published_activation(
    maps: &impl KernelMaps,
    prepared: &PreparedActivation,
) -> Result<()> {
    verify_activation_rows(maps, prepared, true)?;
    fence_binding(maps, prepared, true)?;
    wait_for_generation_refs(maps, prepared.record.profile_generation_ref_id, true)?;
    retire_owned_rows(maps, prepared)
}

fn install_row(
    maps: &impl KernelMaps,
    installed: &mut Vec<(&'static str, Vec<u8>)>,
    map: &'static str,
    key: &[u8],
    value: &[u8],
) -> Result<()> {
    if !maps.insert(map, key, value)? {
        return invalid(format!(
            "kernel map `{map}` already contains the activation key"
        ));
    }
    installed.push((map, key.to_vec()));
    verify_readback(maps, map, key, value)
}

fn update_readback(maps: &impl KernelMaps, map: &str, key: &[u8], value: &[u8]) -> Result<()> {
    maps.update(map, key, value)?;
    verify_readback(maps, map, key, value)
}

fn verify_readback(maps: &impl KernelMaps, map: &str, key: &[u8], value: &[u8]) -> Result<()> {
    if maps.lookup(map, key)?.as_deref() != Some(value) {
        return invalid(format!("kernel map `{map}` failed exact readback"));
    }
    Ok(())
}

fn rollback_rows(maps: &impl KernelMaps, installed: &[(&str, Vec<u8>)]) -> Result<()> {
    let mut failures = Vec::new();
    for (map, key) in installed.iter().rev() {
        match maps.lookup(map, key) {
            Ok(Some(_value)) => {
                if let Err(error) = maps.delete(map, key) {
                    failures.push(format!("`{map}` delete failed: {error}"));
                }
            }
            Ok(None) => {}
            Err(error) => failures.push(format!("`{map}` read failed: {error}")),
        }
    }
    if failures.is_empty() {
        Ok(())
    } else {
        invalid(failures.join("; "))
    }
}

fn signal_authority_keys(record: &DurableBindingRecordV1) -> Vec<ControllerSignalAuthorityKeyV1> {
    let mut controller_ids = vec![record.controller_cgroup_id];
    if record.owner_controller_cgroup_id != record.controller_cgroup_id {
        controller_ids.push(record.owner_controller_cgroup_id);
    }
    for &controller_cgroup_id in &record.recovery_controller_cgroup_ids {
        if !controller_ids.contains(&controller_cgroup_id) {
            controller_ids.push(controller_cgroup_id);
        }
    }
    controller_ids
        .into_iter()
        .map(|controller_cgroup_id| ControllerSignalAuthorityKeyV1 {
            controller_cgroup_id,
            target_binding_id: record.binding_id,
            target_binding_nonce: record.binding_nonce,
        })
        .collect()
}

fn prepared_from_record(record: &DurableBindingRecordV1) -> PreparedActivation {
    let effect_rows = effect_rows(
        record.profile_generation_ref_id,
        &record.operation_decisions,
    );
    PreparedActivation {
        record: record.clone(),
        binding: binding_from_record(record),
        descriptor: descriptor_from_record(record),
        effect_rows,
    }
}

fn binding_from_record(record: &DurableBindingRecordV1) -> ExecutionSetBindingStateV1 {
    ExecutionSetBindingStateV1 {
        binding_id: record.binding_id,
        binding_nonce: record.binding_nonce,
        node_boot_id: record.node_boot_id,
        execution_set_id: record.execution_set_id,
        protected_scope_id: record.protected_scope_id,
        profile_id: record.profile_id,
        label_epoch: record.label_epoch,
        active_profile_generation_ref_id: record.profile_generation_ref_id,
        root_cgroup_id: record.cgroup_id,
        root_cgroup_live_interval_id: record.root_cgroup_live_interval_id,
        container_generation: 1,
        lifecycle_generation: 1,
        transition_version: 2,
        initial_role_id: INITIAL_ROLE_ID,
        external_role_id: EXTERNAL_ROLE_ID,
        lifecycle_state: BindingLifecycleStateV1::Active,
        reserved: [0; 7],
        initial_root_state: InitialRootStateV1::Available,
    }
}

fn descriptor_from_record(record: &DurableBindingRecordV1) -> ProfileGenerationDescriptorV1 {
    ProfileGenerationDescriptorV1 {
        node_boot_id: record.node_boot_id,
        profile_id: record.profile_id,
        label_epoch: record.label_epoch,
        profile_generation_ref_id: record.profile_generation_ref_id,
        owner_generation: 1,
        row_count: 0,
        default_count: record.operation_decisions.len() as u32,
        state: PolicyGenerationStateV1::Active,
        mode: PolicyGenerationModeV1::Protect,
        reserved: [0; 6],
        table_digest: record.table_digest,
        transition_version: 3,
    }
}

fn read_u64_map(maps: &impl KernelMaps, map: &str, key: &[u8]) -> Result<Option<u64>> {
    maps.lookup(map, key)?
        .map(|bytes| {
            u64::read_from_bytes(&bytes).map_err(|error| {
                RuntimeKernelInterceptionError::InvalidState {
                    reason: format!("kernel map `{map}` has an invalid u64 row: {error}"),
                }
            })
        })
        .transpose()
}

struct VerifiedCgroup {
    directory: File,
    _controller_directory: File,
    path: PathBuf,
}

impl VerifiedCgroup {
    fn open(path: &Path, id: u64, controller_id: u64) -> Result<Option<Self>> {
        if id == 0 || controller_id == 0 || id == controller_id {
            return invalid("workload and controller cgroups require distinct nonzero identities");
        }
        let canonical_root = fs::canonicalize(CGROUP_ROOT).map_err(|source| {
            io_error(
                "resolving the unified cgroup root",
                Path::new(CGROUP_ROOT),
                source,
            )
        })?;
        let directory = match open(
            path,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        ) {
            Ok(directory) => File::from(directory),
            Err(error) if error == rustix::io::Errno::NOENT => return Ok(None),
            Err(source) => {
                return Err(io_error(
                    "opening the workload cgroup",
                    path,
                    std::io::Error::from(source),
                ));
            }
        };
        let canonical = fs::canonicalize(path)
            .map_err(|source| io_error("resolving the workload cgroup", path, source))?;
        if canonical == canonical_root || !canonical.starts_with(&canonical_root) {
            return invalid(format!(
                "workload cgroup `{}` is outside the unified hierarchy",
                path.display()
            ));
        }
        let parent = path
            .parent()
            .ok_or_else(|| RuntimeKernelInterceptionError::InvalidState {
                reason: format!("workload cgroup `{}` has no controller", path.display()),
            })?;
        let controller_directory = open(
            parent,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .map(File::from)
        .map_err(std::io::Error::from)
        .map_err(|source| io_error("opening the controller cgroup", parent, source))?;
        verify_cgroup_identity(&directory, path, id, "workload")?;
        verify_cgroup_identity(&controller_directory, parent, controller_id, "controller")?;
        Ok(Some(Self {
            directory,
            _controller_directory: controller_directory,
            path: path.to_path_buf(),
        }))
    }

    fn is_empty(&self) -> Result<bool> {
        let mut processes = String::new();
        File::from(
            openat(
                &self.directory,
                "cgroup.procs",
                OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                Mode::empty(),
            )
            .map_err(std::io::Error::from)
            .map_err(|source| {
                io_error("opening the workload cgroup membership", &self.path, source)
            })?,
        )
        .read_to_string(&mut processes)
        .map_err(|source| io_error("reading the workload cgroup membership", &self.path, source))?;
        Ok(processes.trim().is_empty())
    }

    fn terminate_and_wait(&self) -> Result<()> {
        if self.is_empty()? {
            return Ok(());
        }
        let mut kill = match openat(
            &self.directory,
            "cgroup.kill",
            OFlags::WRONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        ) {
            Ok(kill) => File::from(kill),
            Err(error) if error == rustix::io::Errno::NOENT && self.is_empty()? => return Ok(()),
            Err(source) => {
                return Err(io_error(
                    "opening the workload cgroup kill control",
                    &self.path,
                    std::io::Error::from(source),
                ));
            }
        };
        kill.write_all(b"1").map_err(|source| {
            io_error("terminating workload cgroup processes", &self.path, source)
        })?;
        for _attempt in 0..CLEANUP_ATTEMPTS {
            if self.is_empty()? {
                return Ok(());
            }
            thread::sleep(CLEANUP_POLL);
        }
        invalid(format!(
            "workload cgroup `{}` remained populated after termination",
            self.path.display()
        ))
    }
}

fn verify_cgroup_identity(
    directory: &File,
    path: &Path,
    expected_id: u64,
    name: &str,
) -> Result<()> {
    let descriptor = fstat(directory)
        .map_err(std::io::Error::from)
        .map_err(|source| io_error("reading a cgroup identity", path, source))?;
    let metadata = fs::symlink_metadata(path)
        .map_err(|source| io_error("verifying a cgroup identity", path, source))?;
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || descriptor.st_ino != expected_id
        || metadata.ino() != expected_id
        || metadata.dev() != descriptor.st_dev
    {
        return invalid(format!(
            "{name} cgroup `{}` changed identity",
            path.display()
        ));
    }
    Ok(())
}

fn verify_boundary(path: &Path, id: u64, controller_id: u64, require_empty: bool) -> Result<()> {
    let cgroup = VerifiedCgroup::open(path, id, controller_id)?.ok_or_else(|| {
        RuntimeKernelInterceptionError::InvalidState {
            reason: format!("workload cgroup `{}` is absent", path.display()),
        }
    })?;
    if require_empty && !cgroup.is_empty()? {
        return invalid(format!(
            "workload cgroup `{}` is not empty before activation",
            path.display()
        ));
    }
    Ok(())
}

fn verify_empty_boundary_record(record: &DurableBindingRecordV1) -> Result<()> {
    verify_boundary(
        &record.cgroup_path,
        record.cgroup_id,
        record.controller_cgroup_id,
        true,
    )
}

fn cleanup_binding(
    state: &mut RuntimeKernelState,
    live: &mut LiveBinding,
    evidence: &RuntimeEvidenceRouter,
    evidence_barriers: &Sender<EvidencePollBarrier>,
) -> Result<()> {
    if live.record.status == DurableBindingStatusV1::Tombstoned {
        state.host.verify_live_manifest()?;
        write_durable_record(&state.state_directory, &live.record_path, &live.record)?;
        evidence.unregister(live.record.binding_id);
        return Ok(());
    }
    retire_binding_authority(state, live)?;
    live.record.status = DurableBindingStatusV1::Tombstoned;
    match capture_final_coverage(
        evidence,
        &state.host,
        live.record.binding_id,
        live.evidence_owner_start,
        live.kernel_evidence_start,
        live.recovery,
        evidence_barriers,
    ) {
        Ok((coverage, coverage_failure)) => {
            live.record.evidence_coverage = Some(coverage);
            if let Some(coverage_failure) = coverage_failure {
                append_failure(&mut live.record.failure, coverage_failure);
            }
        }
        Err(error) => append_failure(
            &mut live.record.failure,
            format!("final evidence coverage is unavailable: {error}"),
        ),
    }
    write_durable_record(&state.state_directory, &live.record_path, &live.record)?;
    evidence.unregister(live.record.binding_id);
    Ok(())
}

fn retire_binding_authority(state: &mut RuntimeKernelState, live: &mut LiveBinding) -> Result<()> {
    state.host.verify_live_manifest()?;
    let strict = live.record.status == DurableBindingStatusV1::Active
        && live.record.node_boot_id == state.node_boot_id
        && live.record.label_epoch == state.label_epoch;
    live.record.status = DurableBindingStatusV1::Terminating;
    if live.recovery
        && !live
            .record
            .recovery_controller_cgroup_ids
            .contains(&state.owner_controller_cgroup_id)
    {
        live.record
            .recovery_controller_cgroup_ids
            .push(state.owner_controller_cgroup_id);
    }
    write_durable_record(&state.state_directory, &live.record_path, &live.record)?;
    let prepared = prepared_from_record(&live.record);
    verify_activation_rows(&state.host, &prepared, strict)?;
    fence_binding(&state.host, &prepared, strict)?;
    if live.recovery {
        install_recovery_signal_authority(
            &state.host,
            &live.record,
            state.owner_controller_cgroup_id,
        )?;
    }

    let cgroup = VerifiedCgroup::open(
        &live.record.cgroup_path,
        live.record.cgroup_id,
        live.record.controller_cgroup_id,
    )?;
    if live.record.node_boot_id != state.node_boot_id {
        if cgroup.is_some() {
            return invalid(format!(
                "durable binding `{}` names a live cgroup from another boot",
                live.record.session_id
            ));
        }
    } else if let Some(cgroup) = cgroup {
        cgroup.terminate_and_wait()?;
    }
    wait_for_generation_refs(&state.host, live.record.profile_generation_ref_id, strict)?;
    retire_owned_rows(&state.host, &prepared)
}

fn verify_activation_rows(
    maps: &impl KernelMaps,
    prepared: &PreparedActivation,
    strict: bool,
) -> Result<()> {
    let record = &prepared.record;
    let generation_key = record.profile_generation_ref_id.to_ne_bytes();
    match maps.lookup(DESCRIPTOR_MAP, &generation_key)? {
        Some(bytes) => {
            let descriptor =
                ProfileGenerationDescriptorV1::try_read_from_bytes(&bytes).map_err(|error| {
                    RuntimeKernelInterceptionError::InvalidState {
                        reason: format!("profile generation descriptor is invalid: {error}"),
                    }
                })?;
            if !same_descriptor_identity(&prepared.descriptor, &descriptor) {
                return invalid("profile generation descriptor belongs to another owner");
            }
        }
        None if strict => return invalid("active profile generation descriptor is absent"),
        None => {}
    }
    for map in [TASK_REFS_MAP, ASYNC_REFS_MAP, SOCKET_REFS_MAP] {
        if read_u64_map(maps, map, &generation_key)?.is_none() && strict {
            return invalid(format!("active kernel map `{map}` row is absent"));
        }
    }
    for (key, value) in &prepared.effect_rows {
        verify_owned_value(
            maps,
            EFFECT_DEFAULT_MAP,
            key.as_bytes(),
            value.as_bytes(),
            strict,
        )?;
    }
    verify_owned_value(
        maps,
        ACTIVE_PROFILE_MAP,
        record.profile_id.as_bytes(),
        &record.profile_generation_ref_id.to_ne_bytes(),
        strict,
    )?;
    let target_key = BindingActivationTargetKeyV1 {
        binding_id: record.binding_id,
        profile_generation_ref_id: record.profile_generation_ref_id,
    };
    verify_owned_value(
        maps,
        ACTIVATION_TARGET_MAP,
        target_key.as_bytes(),
        prepared.binding.as_bytes(),
        strict,
    )?;
    let signal_authority = ControllerSignalAuthorityV1 {
        allowed_signal_mask: CONTROLLER_SIGNAL_ALLOWED_MASK_V1,
    };
    for key in signal_authority_keys(record) {
        verify_owned_value(
            maps,
            SIGNAL_AUTHORITY_MAP,
            key.as_bytes(),
            signal_authority.as_bytes(),
            strict
                && !record
                    .recovery_controller_cgroup_ids
                    .contains(&key.controller_cgroup_id),
        )?;
    }
    match maps.lookup(EXECUTION_BINDING_MAP, &record.cgroup_id.to_ne_bytes())? {
        Some(bytes) => {
            let binding = read_binding(&bytes)?;
            if !same_binding_identity(&prepared.binding, &binding) {
                return invalid("execution binding belongs to another owner");
            }
        }
        None if strict => return invalid("active execution binding is absent"),
        None => {}
    }
    Ok(())
}

fn fence_binding(
    maps: &impl KernelMaps,
    prepared: &PreparedActivation,
    strict: bool,
) -> Result<()> {
    let key = prepared.record.cgroup_id.to_ne_bytes();
    let Some(bytes) = maps.lookup(EXECUTION_BINDING_MAP, &key)? else {
        return if strict {
            invalid("active execution binding disappeared before termination")
        } else {
            Ok(())
        };
    };
    let mut binding = read_binding(&bytes)?;
    if !same_binding_identity(&prepared.binding, &binding) {
        return invalid("execution binding cannot enter termination");
    }
    if binding.lifecycle_state == BindingLifecycleStateV1::Tombstoned {
        return Ok(());
    }
    if !matches!(
        binding.lifecycle_state,
        BindingLifecycleStateV1::Preparing
            | BindingLifecycleStateV1::Active
            | BindingLifecycleStateV1::Terminating
    ) {
        return invalid("execution binding cannot enter termination");
    }
    if binding.lifecycle_state != BindingLifecycleStateV1::Terminating {
        binding.lifecycle_state = BindingLifecycleStateV1::Terminating;
        binding.initial_root_state = InitialRootStateV1::Consumed;
        binding.transition_version =
            binding.transition_version.checked_add(1).ok_or_else(|| {
                RuntimeKernelInterceptionError::InvalidState {
                    reason: "execution binding transition version is exhausted".to_owned(),
                }
            })?;
        update_readback(maps, EXECUTION_BINDING_MAP, &key, binding.as_bytes())?;
    }
    Ok(())
}

fn install_recovery_signal_authority(
    maps: &impl KernelMaps,
    record: &DurableBindingRecordV1,
    controller_cgroup_id: u64,
) -> Result<()> {
    if !record
        .recovery_controller_cgroup_ids
        .contains(&controller_cgroup_id)
    {
        return invalid("the recovery controller identity is not durable");
    }
    let key = ControllerSignalAuthorityKeyV1 {
        controller_cgroup_id,
        target_binding_id: record.binding_id,
        target_binding_nonce: record.binding_nonce,
    };
    let value = ControllerSignalAuthorityV1 {
        allowed_signal_mask: CONTROLLER_SIGNAL_ALLOWED_MASK_V1,
    };
    match maps.lookup(SIGNAL_AUTHORITY_MAP, key.as_bytes())? {
        Some(existing) if existing == value.as_bytes() => Ok(()),
        Some(_) => invalid("recovery signal authority belongs to another owner"),
        None => {
            if !maps.insert(SIGNAL_AUTHORITY_MAP, key.as_bytes(), value.as_bytes())? {
                return invalid("recovery signal authority changed during publication");
            }
            verify_readback(maps, SIGNAL_AUTHORITY_MAP, key.as_bytes(), value.as_bytes())
        }
    }
}

fn wait_for_generation_refs(maps: &impl KernelMaps, generation: u64, strict: bool) -> Result<()> {
    let key = generation.to_ne_bytes();
    for _attempt in 0..CLEANUP_ATTEMPTS {
        let mut all_zero = true;
        for map in [TASK_REFS_MAP, ASYNC_REFS_MAP, SOCKET_REFS_MAP] {
            match read_u64_map(maps, map, &key)? {
                Some(0) | None if !strict => {}
                Some(0) => {}
                Some(_) => all_zero = false,
                None => return invalid(format!("active kernel map `{map}` row is absent")),
            }
        }
        if all_zero {
            return Ok(());
        }
        thread::sleep(CLEANUP_POLL);
    }
    invalid(format!(
        "profile generation {generation} retained kernel references after termination"
    ))
}

fn retire_owned_rows(maps: &impl KernelMaps, prepared: &PreparedActivation) -> Result<()> {
    let record = &prepared.record;
    let binding_key = record.cgroup_id.to_ne_bytes();
    if let Some(bytes) = maps.lookup(EXECUTION_BINDING_MAP, &binding_key)? {
        let mut binding = read_binding(&bytes)?;
        if !same_binding_identity(&prepared.binding, &binding) {
            return invalid("execution binding changed owner before deletion");
        }
        match binding.lifecycle_state {
            BindingLifecycleStateV1::Preparing
            | BindingLifecycleStateV1::Active
            | BindingLifecycleStateV1::Terminating => {
                binding.lifecycle_state = BindingLifecycleStateV1::Tombstoned;
                binding.initial_root_state = InitialRootStateV1::Consumed;
                binding.transition_version =
                    binding.transition_version.checked_add(1).ok_or_else(|| {
                        RuntimeKernelInterceptionError::InvalidState {
                            reason: "execution binding transition version is exhausted".to_owned(),
                        }
                    })?;
                update_readback(
                    maps,
                    EXECUTION_BINDING_MAP,
                    &binding_key,
                    binding.as_bytes(),
                )?;
            }
            BindingLifecycleStateV1::Tombstoned => {}
            _ => return invalid("execution binding cannot enter retirement"),
        }
    }

    let generation_key = record.profile_generation_ref_id.to_ne_bytes();
    if let Some(bytes) = maps.lookup(DESCRIPTOR_MAP, &generation_key)? {
        let mut descriptor =
            ProfileGenerationDescriptorV1::try_read_from_bytes(&bytes).map_err(|error| {
                RuntimeKernelInterceptionError::InvalidState {
                    reason: format!("profile generation descriptor is invalid: {error}"),
                }
            })?;
        if !same_descriptor_identity(&prepared.descriptor, &descriptor) {
            return invalid("profile generation descriptor changed owner before deletion");
        }
        match descriptor.state {
            PolicyGenerationStateV1::Preparing
            | PolicyGenerationStateV1::ReadBack
            | PolicyGenerationStateV1::Active => {
                descriptor.state = PolicyGenerationStateV1::Retiring;
                descriptor.transition_version = descriptor
                    .transition_version
                    .checked_add(1)
                    .ok_or_else(|| RuntimeKernelInterceptionError::InvalidState {
                        reason: "profile generation transition version is exhausted".to_owned(),
                    })?;
                update_readback(maps, DESCRIPTOR_MAP, &generation_key, descriptor.as_bytes())?;
            }
            PolicyGenerationStateV1::Retiring | PolicyGenerationStateV1::Tombstoned => {}
            _ => return invalid("profile generation descriptor cannot enter retirement"),
        }
        if descriptor.state != PolicyGenerationStateV1::Tombstoned {
            descriptor.state = PolicyGenerationStateV1::Tombstoned;
            descriptor.transition_version = descriptor
                .transition_version
                .checked_add(1)
                .ok_or_else(|| RuntimeKernelInterceptionError::InvalidState {
                    reason: "profile generation transition version is exhausted".to_owned(),
                })?;
            update_readback(maps, DESCRIPTOR_MAP, &generation_key, descriptor.as_bytes())?;
        }
    }

    for (key, value) in &prepared.effect_rows {
        delete_owned_value(maps, EFFECT_DEFAULT_MAP, key.as_bytes(), value.as_bytes())?;
    }
    let target_key = BindingActivationTargetKeyV1 {
        binding_id: record.binding_id,
        profile_generation_ref_id: record.profile_generation_ref_id,
    };
    delete_owned_value(
        maps,
        ACTIVATION_TARGET_MAP,
        target_key.as_bytes(),
        prepared.binding.as_bytes(),
    )?;
    delete_owned_value(
        maps,
        ACTIVE_PROFILE_MAP,
        record.profile_id.as_bytes(),
        &record.profile_generation_ref_id.to_ne_bytes(),
    )?;
    let signal_authority = ControllerSignalAuthorityV1 {
        allowed_signal_mask: CONTROLLER_SIGNAL_ALLOWED_MASK_V1,
    };
    for key in signal_authority_keys(record) {
        delete_owned_value(
            maps,
            SIGNAL_AUTHORITY_MAP,
            key.as_bytes(),
            signal_authority.as_bytes(),
        )?;
    }
    for map in [TASK_REFS_MAP, ASYNC_REFS_MAP, SOCKET_REFS_MAP] {
        delete_owned_value(maps, map, &generation_key, &0_u64.to_ne_bytes())?;
    }
    delete_owned_row(maps, DESCRIPTOR_MAP, &generation_key)?;
    delete_owned_row(maps, EXECUTION_BINDING_MAP, &binding_key)
}

fn verify_owned_value(
    maps: &impl KernelMaps,
    map: &str,
    key: &[u8],
    expected: &[u8],
    required: bool,
) -> Result<()> {
    match maps.lookup(map, key)? {
        Some(value) if value == expected => Ok(()),
        Some(_) => invalid(format!("kernel map `{map}` row belongs to another owner")),
        None if required => invalid(format!("owned kernel map `{map}` row is absent")),
        None => Ok(()),
    }
}

fn delete_owned_value(
    maps: &impl KernelMaps,
    map: &str,
    key: &[u8],
    expected: &[u8],
) -> Result<()> {
    let Some(value) = maps.lookup(map, key)? else {
        return Ok(());
    };
    if value != expected {
        return invalid(format!(
            "kernel map `{map}` row changed owner before deletion"
        ));
    }
    delete_owned_row(maps, map, key)
}

fn delete_owned_row(maps: &impl KernelMaps, map: &str, key: &[u8]) -> Result<()> {
    if maps.lookup(map, key)?.is_none() {
        return Ok(());
    }
    maps.delete(map, key)?;
    if maps.lookup(map, key)?.is_some() {
        return invalid(format!("kernel map `{map}` row survived deletion"));
    }
    Ok(())
}

fn read_binding(bytes: &[u8]) -> Result<ExecutionSetBindingStateV1> {
    ExecutionSetBindingStateV1::try_read_from_bytes(bytes).map_err(|error| {
        RuntimeKernelInterceptionError::InvalidState {
            reason: format!("execution binding has an invalid ABI row: {error}"),
        }
    })
}

fn same_binding_identity(
    expected: &ExecutionSetBindingStateV1,
    actual: &ExecutionSetBindingStateV1,
) -> bool {
    expected.binding_id == actual.binding_id
        && expected.binding_nonce == actual.binding_nonce
        && expected.node_boot_id == actual.node_boot_id
        && expected.execution_set_id == actual.execution_set_id
        && expected.protected_scope_id == actual.protected_scope_id
        && expected.profile_id == actual.profile_id
        && expected.label_epoch == actual.label_epoch
        && expected.active_profile_generation_ref_id == actual.active_profile_generation_ref_id
        && expected.root_cgroup_id == actual.root_cgroup_id
        && expected.root_cgroup_live_interval_id == actual.root_cgroup_live_interval_id
        && expected.container_generation == actual.container_generation
        && expected.lifecycle_generation == actual.lifecycle_generation
        && expected.initial_role_id == actual.initial_role_id
        && expected.external_role_id == actual.external_role_id
        && expected.reserved == actual.reserved
}

fn same_descriptor_identity(
    expected: &ProfileGenerationDescriptorV1,
    actual: &ProfileGenerationDescriptorV1,
) -> bool {
    expected.node_boot_id == actual.node_boot_id
        && expected.profile_id == actual.profile_id
        && expected.label_epoch == actual.label_epoch
        && expected.profile_generation_ref_id == actual.profile_generation_ref_id
        && expected.owner_generation == actual.owner_generation
        && expected.row_count == actual.row_count
        && expected.default_count == actual.default_count
        && expected.mode == actual.mode
        && expected.reserved == actual.reserved
        && expected.table_digest == actual.table_digest
}

fn capture_final_coverage(
    evidence: &RuntimeEvidenceRouter,
    host: &KernelHost,
    binding_id: Id128V1,
    owner_start: EvidenceOwnerSnapshot,
    kernel_start: KernelEvidenceSnapshot,
    recovery: bool,
    evidence_barriers: &Sender<EvidencePollBarrier>,
) -> Result<(DurableEvidenceCoverageV1, Option<String>)> {
    let mut failure = request_evidence_barrier(evidence_barriers);
    let route = evidence.route_snapshot(binding_id).ok_or_else(|| {
        RuntimeKernelInterceptionError::InvalidState {
            reason: format!(
                "evidence binding `{}` is not registered",
                hex::encode(binding_id.to_be_bytes())
            ),
        }
    })?;
    let owner_end = evidence.owner_snapshot();
    if let Err(error) = host.verify_live_manifest() {
        append_failure(
            &mut failure,
            format!("live kernel ownership verification failed: {error}"),
        );
    }
    let kernel_end = kernel_evidence_health(host)?;
    if let Some(coverage_failure) = coverage_failure(
        recovery,
        route,
        owner_start,
        owner_end,
        kernel_start,
        kernel_end,
    ) {
        append_failure(&mut failure, coverage_failure);
    }
    let complete = failure.is_none();
    if let Err(error) = evidence.append_final_coverage(
        binding_id,
        EvidenceCoverageInput {
            recovery,
            complete,
            route,
            owner_start,
            owner_end,
            kernel_start,
            kernel_end,
        },
    ) {
        append_failure(
            &mut failure,
            format!("final evidence coverage append failed: {error}"),
        );
    }
    Ok((
        DurableEvidenceCoverageV1 {
            recovery,
            complete: failure.is_none(),
            route,
            owner_start,
            owner_end,
            kernel_start,
            kernel_end,
        },
        failure,
    ))
}

fn request_evidence_barrier(evidence_barriers: &Sender<EvidencePollBarrier>) -> Option<String> {
    let (acknowledged, acknowledgement) = mpsc::sync_channel(1);
    if evidence_barriers
        .send(EvidencePollBarrier { acknowledged })
        .is_err()
    {
        return Some("effect evidence reader is unavailable for the drain barrier".to_owned());
    }
    match acknowledgement.recv_timeout(EVIDENCE_BARRIER_TIMEOUT) {
        Ok(true) => None,
        Ok(false) => Some("effect evidence polling failed at the drain barrier".to_owned()),
        Err(mpsc::RecvTimeoutError::Timeout) => {
            Some("effect evidence reader did not acknowledge the drain barrier".to_owned())
        }
        Err(mpsc::RecvTimeoutError::Disconnected) => {
            Some("effect evidence reader disconnected before the drain barrier".to_owned())
        }
    }
}

fn coverage_failure(
    recovery: bool,
    route: EvidenceRouteSnapshot,
    owner_start: EvidenceOwnerSnapshot,
    owner_end: EvidenceOwnerSnapshot,
    kernel_start: KernelEvidenceSnapshot,
    kernel_end: KernelEvidenceSnapshot,
) -> Option<String> {
    let mut reasons = Vec::new();
    if recovery {
        reasons.push("daemon recovery cannot prove continuous process-local evidence routing");
    }
    if owner_counters_regressed(owner_start, owner_end) {
        reasons.push("owner evidence counters regressed");
    }
    if kernel_counters_regressed(kernel_start, kernel_end) {
        reasons.push("kernel evidence counters regressed");
    }
    if !kernel_counters_are_valid(kernel_start) || !kernel_counters_are_valid(kernel_end) {
        reasons.push("kernel evidence accounting is invalid");
    }
    if let (Some(emitted), Some(processed), Some(parse_failures), Some(unknown_bindings)) = (
        kernel_end.emitted.checked_sub(kernel_start.emitted),
        owner_end.processed.checked_sub(owner_start.processed),
        owner_end
            .parse_failures
            .checked_sub(owner_start.parse_failures),
        owner_end
            .unknown_bindings
            .checked_sub(owner_start.unknown_bindings),
    ) {
        if processed
            .checked_add(parse_failures)
            .and_then(|observed| observed.checked_add(unknown_bindings))
            != Some(emitted)
        {
            reasons.push("kernel emitted count differs from reader outcomes");
        }
    }
    if route.processed != route.persisted {
        reasons.push("route persistence count differs from its processed count");
    }
    if route.parse_failures != 0 {
        reasons.push("route parse failures are nonzero");
    }
    if route.write_failures != 0 {
        reasons.push("route write failures are nonzero");
    }
    if counter_increased(owner_start.parse_failures, owner_end.parse_failures)
        || counter_increased(
            owner_start.unattributed_parse_failures,
            owner_end.unattributed_parse_failures,
        )
    {
        reasons.push("owner parse failures increased");
    }
    if counter_increased(owner_start.write_failures, owner_end.write_failures) {
        reasons.push("owner write failures increased");
    }
    if counter_increased(owner_start.unknown_bindings, owner_end.unknown_bindings) {
        reasons.push("unknown evidence bindings increased");
    }
    if owner_end.poll_failures != 0 {
        reasons.push("effect evidence polling failed");
    }
    if counter_increased(kernel_start.lost, kernel_end.lost) {
        reasons.push("kernel evidence loss increased");
    }
    if counter_increased(kernel_start.suppressed, kernel_end.suppressed) {
        reasons.push("kernel evidence suppression increased");
    }
    if counter_increased(
        kernel_start.classifier_miss_count,
        kernel_end.classifier_miss_count,
    ) {
        reasons.push("kernel classifier misses increased");
    }
    if counter_increased(kernel_start.unresolved, kernel_end.unresolved) {
        reasons.push("unresolved kernel evidence increased");
    }
    (!reasons.is_empty()).then(|| reasons.join("; "))
}

fn require_evidence_reader(snapshot: EvidenceOwnerSnapshot) -> Result<()> {
    if snapshot.poll_failures != 0 {
        return invalid("the effect evidence reader stopped after a poll failure");
    }
    Ok(())
}

const fn counter_increased(start: u64, end: u64) -> bool {
    end > start
}

fn owner_counters_regressed(start: EvidenceOwnerSnapshot, end: EvidenceOwnerSnapshot) -> bool {
    [
        (start.processed, end.processed),
        (start.persisted, end.persisted),
        (start.parse_failures, end.parse_failures),
        (start.write_failures, end.write_failures),
        (
            start.unattributed_parse_failures,
            end.unattributed_parse_failures,
        ),
        (start.unknown_bindings, end.unknown_bindings),
        (start.successful_polls, end.successful_polls),
        (start.poll_failures, end.poll_failures),
    ]
    .into_iter()
    .any(|(opening, closing)| closing < opening)
}

fn kernel_counters_regressed(start: KernelEvidenceSnapshot, end: KernelEvidenceSnapshot) -> bool {
    [
        (start.attempted, end.attempted),
        (start.suppressed, end.suppressed),
        (start.requested, end.requested),
        (start.emitted, end.emitted),
        (start.lost, end.lost),
        (start.classifier_miss_count, end.classifier_miss_count),
        (start.unresolved, end.unresolved),
    ]
    .into_iter()
    .any(|(opening, closing)| closing < opening)
}

fn kernel_counters_are_valid(counters: KernelEvidenceSnapshot) -> bool {
    counters
        .suppressed
        .checked_add(counters.requested)
        .is_some_and(|total| total == counters.attempted)
        && counters
            .emitted
            .checked_add(counters.lost)
            .is_some_and(|total| total == counters.requested)
}

fn append_failure(failure: &mut Option<String>, reason: String) {
    match failure {
        Some(existing) => {
            existing.push_str("; ");
            existing.push_str(&reason);
        }
        None => *failure = Some(reason),
    }
}

fn load_durable_bindings(state_directory: &Path) -> Result<Vec<RecoveryBinding>> {
    let directory = state_directory.join("bindings");
    let mut paths = fs::read_dir(&directory)
        .map_err(|source| io_error("reading durable binding records", &directory, source))?
        .map(|entry| {
            entry
                .map(|entry| entry.path())
                .map_err(|source| io_error("reading a durable binding entry", &directory, source))
        })
        .collect::<Result<Vec<_>>>()?;
    paths.sort();
    let mut binding_ids = BTreeMap::new();
    let mut session_owners = BTreeMap::new();
    let mut recovery = Vec::new();
    for path in paths {
        if path.extension().and_then(|value| value.to_str()) != Some("json") {
            continue;
        }
        let metadata = fs::symlink_metadata(&path)
            .map_err(|source| io_error("verifying a durable binding record", &path, source))?;
        if !metadata.is_file() || metadata.file_type().is_symlink() {
            return invalid(format!(
                "durable binding record `{}` is not a regular file",
                path.display()
            ));
        }
        let bytes = fs::read(&path)
            .map_err(|source| io_error("reading a durable binding record", &path, source))?;
        let record: DurableBindingRecordV1 = serde_json::from_slice(&bytes).map_err(|source| {
            RuntimeKernelInterceptionError::DurableRecord {
                path: path.clone(),
                source,
            }
        })?;
        validate_durable_record(&record, &path)?;
        if durable_record_path(state_directory, record.binding_id) != path {
            return invalid(format!(
                "durable binding record `{}` has the wrong owner name",
                path.display()
            ));
        }
        if let Some(previous) = binding_ids.insert(record.binding_id, path.clone()) {
            return invalid(format!(
                "durable binding records `{}` and `{}` repeat one binding ID",
                previous.display(),
                path.display()
            ));
        }
        let owner_key = session_owner_key(record.owner_uid, &record.session_id);
        if let Some(previous) = session_owners.insert(owner_key, path.clone()) {
            return invalid(format!(
                "durable binding records `{}` and `{}` repeat one session owner identity",
                previous.display(),
                path.display()
            ));
        }
        if record.status == DurableBindingStatusV1::Tombstoned {
            continue;
        }
        recovery.push(RecoveryBinding {
            record,
            path,
            evidence_failure: None,
        });
    }
    Ok(recovery)
}

fn register_recovery_outputs(evidence: &RuntimeEvidenceRouter, recovery: &mut [RecoveryBinding]) {
    for binding in recovery {
        if let Err(error) =
            evidence.register_output(binding.record.binding_id, &binding.record.output)
        {
            binding.evidence_failure = Some(error.to_string());
        }
    }
}

fn reclaim_durable_bindings(
    state: &mut RuntimeKernelState,
    evidence: &RuntimeEvidenceRouter,
    recovery: Vec<RecoveryBinding>,
    evidence_owner_start: EvidenceOwnerSnapshot,
    kernel_evidence_start: KernelEvidenceSnapshot,
    evidence_barriers: &Sender<EvidencePollBarrier>,
) -> Result<()> {
    state.host.verify_live_manifest()?;
    let mut failures = Vec::new();
    for binding in recovery {
        let evidence_failure = binding.evidence_failure;
        let mut live = LiveBinding {
            record: binding.record,
            record_path: binding.path,
            evidence_owner_start,
            kernel_evidence_start,
            recovery: true,
        };
        let cleanup = match evidence_failure.as_deref() {
            Some(error) => cleanup_recovery_without_evidence(state, &mut live, error),
            None => cleanup_binding(state, &mut live, evidence, evidence_barriers),
        };
        if let Err(error) = cleanup {
            if live.record.status != DurableBindingStatusV1::Tombstoned {
                live.record.status = DurableBindingStatusV1::Terminating;
            }
            append_failure(&mut live.record.failure, error.to_string());
            if let Err(write_error) =
                write_durable_record(&state.state_directory, &live.record_path, &live.record)
            {
                failures.push(format!(
                    "{error}; durable failure recording also failed: {write_error}"
                ));
            } else {
                failures.push(error.to_string());
            }
        } else if let Some(error) = evidence_failure {
            failures.push(format!(
                "binding {} had no required recovery evidence route: {error}",
                hex::encode(live.record.binding_id.to_be_bytes())
            ));
        }
    }
    if !failures.is_empty() {
        return invalid(format!(
            "Runtime Interceptor startup reclamation was incomplete: {}",
            failures.join("; ")
        ));
    }
    Ok(())
}

fn cleanup_recovery_without_evidence(
    state: &mut RuntimeKernelState,
    live: &mut LiveBinding,
    evidence_failure: &str,
) -> Result<()> {
    live.record.evidence_coverage = None;
    append_failure(
        &mut live.record.failure,
        format!(
            "required Evidence stream was unavailable during recovery: {evidence_failure}; final evidence coverage is incomplete"
        ),
    );
    retire_binding_authority(state, live)?;
    live.record.status = DurableBindingStatusV1::Tombstoned;
    write_durable_record(&state.state_directory, &live.record_path, &live.record)
}

fn validate_durable_record(record: &DurableBindingRecordV1, path: &Path) -> Result<()> {
    if record.schema_version != STATE_SCHEMA_VERSION
        || record.session_id.is_empty()
        || record.cgroup_id == 0
        || record.controller_cgroup_id == 0
        || record.owner_controller_cgroup_id == 0
        || record
            .recovery_controller_cgroup_ids
            .iter()
            .enumerate()
            .any(|(index, controller)| {
                *controller == 0
                    || record.recovery_controller_cgroup_ids[..index].contains(controller)
            })
        || record.cgroup_id == record.controller_cgroup_id
        || record.node_boot_id.is_zero()
        || record.label_epoch == 0
        || record.binding_id.is_zero()
        || record.binding_nonce.is_zero()
        || record.execution_set_id.is_zero()
        || record.protected_scope_id.is_zero()
        || record.profile_id.is_zero()
        || record.root_cgroup_live_interval_id.is_zero()
        || record.profile_generation_ref_id == 0
        || record.policy_image_digest.is_empty()
        || record.operation_decisions.len() != KernelEffectOperationV1::OpenPath as usize
    {
        return invalid(format!(
            "durable binding record `{}` has an incomplete owner identity",
            path.display()
        ));
    }
    record
        .output
        .validate()
        .map_err(|error| RuntimeKernelInterceptionError::InvalidState {
            reason: format!(
                "durable binding record `{}` has an invalid output plan: {error}",
                path.display()
            ),
        })?;
    let expected_ids = [
        (b"EREBOR-RUNTIME-BINDING-V1\0".as_slice(), record.binding_id),
        (
            b"EREBOR-RUNTIME-BINDING-NONCE-V1\0".as_slice(),
            record.binding_nonce,
        ),
        (
            b"EREBOR-RUNTIME-EXECUTION-SET-V1\0".as_slice(),
            record.execution_set_id,
        ),
        (
            b"EREBOR-RUNTIME-PROTECTED-SCOPE-V1\0".as_slice(),
            record.protected_scope_id,
        ),
        (b"EREBOR-RUNTIME-PROFILE-V1\0".as_slice(), record.profile_id),
        (
            b"EREBOR-RUNTIME-CGROUP-INTERVAL-V1\0".as_slice(),
            record.root_cgroup_live_interval_id,
        ),
    ];
    if expected_ids.iter().any(|(domain, expected)| {
        derived_id(
            domain,
            record.owner_uid,
            &record.session_id,
            record.cgroup_id,
            record.label_epoch,
        ) != *expected
    }) || derived_generation(
        b"EREBOR-RUNTIME-GENERATION-V1\0",
        record.owner_uid,
        &record.session_id,
        record.cgroup_id,
        record.label_epoch,
    ) != record.profile_generation_ref_id
    {
        return invalid(format!(
            "durable binding record `{}` has non-derived owner identities",
            path.display()
        ));
    }
    let operation_keys = record
        .operation_decisions
        .iter()
        .map(|row| (row.effect_family, row.operation))
        .collect::<Vec<_>>();
    let expected_operation_keys = OPERATION_MATRIX
        .iter()
        .map(|(family, operation, _policy)| (*family as u16, *operation as u16))
        .collect::<Vec<_>>();
    if operation_keys != expected_operation_keys {
        return invalid(format!(
            "durable binding record `{}` has a different operation authority matrix",
            path.display()
        ));
    }
    let rows = effect_rows(
        record.profile_generation_ref_id,
        &record.operation_decisions,
    );
    if effect_table_digest_from(&record.policy_image_digest, &rows) != record.table_digest {
        return invalid(format!(
            "durable binding record `{}` has a different effect table digest",
            path.display()
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{
        cell::{Cell, RefCell},
        collections::BTreeMap,
        path::{Path, PathBuf},
        sync::mpsc,
        thread,
    };

    use erebor_interceptor_abi::{
        BindingLifecycleStateV1, ControllerSignalAuthorityV1, ExecutionSetBindingStateV1,
        KernelEffectFamilyV1, KernelEffectOperationV1, PolicyGenerationStateV1,
        ProfileGenerationDescriptorV1, CONTROLLER_SIGNAL_ALLOWED_MASK_V1,
    };
    use erebor_runtime_core::{OutputPlan, OutputStreamRequirements};
    use erebor_runtime_packages::PolicyPackageRevision;
    use tempfile::TempDir;
    use zerocopy::{IntoBytes as _, TryFromBytes as _};

    use super::{
        binding_from_record, coverage_failure, derived_generation, derived_id, durable_record_path,
        effect_rows, effect_table_digest, effect_table_digest_from, ensure_host_owner_identity,
        invalid, operation_decisions, prepare_state_directory, prepared_from_record,
        publish_activation, register_recovery_outputs, request_evidence_barrier,
        require_evidence_reader, retire_owned_rows, rollback_published_activation,
        session_owner_key, validate_durable_record, DurableBindingRecordV1, DurableBindingStatusV1,
        EvidencePollBarrier, KernelMaps, PreparedActivation, RecoveryBinding, Result,
        RuntimeKernelInterceptionOwner, ACTIVATION_TARGET_MAP, ACTIVE_PROFILE_MAP, DESCRIPTOR_MAP,
        EFFECT_DEFAULT_MAP, EXECUTION_BINDING_MAP, SIGNAL_AUTHORITY_MAP, STATE_SCHEMA_VERSION,
    };
    use crate::runtime_interception::evidence::{
        EvidenceOwnerSnapshot, EvidenceRouteSnapshot, KernelEvidenceSnapshot, RuntimeEvidenceRouter,
    };
    use crate::runtime_interception::policy::RuntimePolicyImage;

    const POLICY: &str = r#"{
        "rules": [
            {"id":"exec","match":{"surface":"terminal","action":"process_exec"},"decision":"allow"},
            {"id":"open","match":{"surface":"filesystem","action":"file_open"},"decision":"allow"},
            {"id":"read","match":{"surface":"filesystem","action":"file_read"},"decision":"deny","reason":"deny reads"},
            {"id":"mutation","match":{"surface":"filesystem","action":"file_mutation"},"decision":"allow"},
            {"id":"connect","match":{"surface":"network","action":"network_request"},"decision":"allow"}
        ]
    }"#;

    type FakeMapKey = (String, Vec<u8>);
    type FakeMapRows = BTreeMap<FakeMapKey, Vec<u8>>;

    #[derive(Default)]
    struct FakeMaps {
        rows: RefCell<FakeMapRows>,
        mutations: Cell<usize>,
        fail_at: RefCell<Vec<usize>>,
    }

    impl FakeMaps {
        fn fail_at(&self, mutation: usize) {
            self.fail_at.borrow_mut().push(mutation);
        }

        fn fail_at_many(&self, mutations: &[usize]) {
            self.fail_at.borrow_mut().extend_from_slice(mutations);
        }

        fn mutate(&self) -> Result<()> {
            let mutation = self.mutations.get() + 1;
            self.mutations.set(mutation);
            let failure = self
                .fail_at
                .borrow()
                .iter()
                .position(|candidate| *candidate == mutation);
            if let Some(index) = failure {
                self.fail_at.borrow_mut().remove(index);
                return invalid(format!("injected map mutation {mutation} failure"));
            }
            Ok(())
        }

        fn len(&self) -> usize {
            self.rows.borrow().len()
        }

        fn map_len(&self, map: &str) -> usize {
            self.rows
                .borrow()
                .keys()
                .filter(|(name, _key)| name == map)
                .count()
        }
    }

    impl KernelMaps for FakeMaps {
        fn lookup(&self, map: &str, key: &[u8]) -> Result<Option<Vec<u8>>> {
            Ok(self
                .rows
                .borrow()
                .get(&(map.to_owned(), key.to_vec()))
                .cloned())
        }

        fn insert(&self, map: &str, key: &[u8], value: &[u8]) -> Result<bool> {
            self.mutate()?;
            let mut rows = self.rows.borrow_mut();
            let key = (map.to_owned(), key.to_vec());
            if rows.contains_key(&key) {
                return Ok(false);
            }
            rows.insert(key, value.to_vec());
            Ok(true)
        }

        fn update(&self, map: &str, key: &[u8], value: &[u8]) -> Result<()> {
            self.mutate()?;
            self.rows
                .borrow_mut()
                .insert((map.to_owned(), key.to_vec()), value.to_vec());
            Ok(())
        }

        fn delete(&self, map: &str, key: &[u8]) -> Result<()> {
            self.mutate()?;
            self.rows
                .borrow_mut()
                .remove(&(map.to_owned(), key.to_vec()));
            Ok(())
        }
    }

    fn policy_image() -> std::result::Result<RuntimePolicyImage, Box<dyn std::error::Error>> {
        let revision = PolicyPackageRevision::new(
            "host",
            b"name = \"host\"\n".to_vec(),
            BTreeMap::from([(String::from("effects.json"), POLICY.as_bytes().to_vec())]),
            BTreeMap::new(),
            BTreeMap::from([(String::from("effects.json"), b"{}".to_vec())]),
            b"# host\n".to_vec(),
        )?;
        Ok(RuntimePolicyImage::compile("policy-set-1", vec![revision])?)
    }

    fn output_plan(root: PathBuf) -> std::result::Result<OutputPlan, Box<dyn std::error::Error>> {
        Ok(OutputPlan::new(
            root,
            100_000,
            10_000,
            16,
            OutputStreamRequirements::optional(),
        )?)
    }

    fn prepared(
        temporary: &TempDir,
    ) -> std::result::Result<PreparedActivation, Box<dyn std::error::Error>> {
        let image = policy_image()?;
        let session_id = "session-host-test";
        let owner_uid = 1000;
        let cgroup_id = 41;
        let label_epoch = 7;
        let operation_decisions = operation_decisions(&image);
        let generation = derived_generation(
            b"EREBOR-RUNTIME-GENERATION-V1\0",
            owner_uid,
            session_id,
            cgroup_id,
            label_epoch,
        );
        let rows = effect_rows(generation, &operation_decisions);
        let record = DurableBindingRecordV1 {
            schema_version: STATE_SCHEMA_VERSION,
            status: DurableBindingStatusV1::Preparing,
            owner_uid,
            session_id: session_id.to_owned(),
            cgroup_path: PathBuf::from("/sys/fs/cgroup/controller/erebor-workload"),
            cgroup_id,
            controller_cgroup_id: 40,
            owner_controller_cgroup_id: 39,
            recovery_controller_cgroup_ids: Vec::new(),
            output: output_plan(temporary.path().join("output"))?,
            node_boot_id: erebor_interceptor_abi::Id128V1::new(1, 2),
            label_epoch,
            binding_id: derived_id(
                b"EREBOR-RUNTIME-BINDING-V1\0",
                owner_uid,
                session_id,
                cgroup_id,
                label_epoch,
            ),
            binding_nonce: derived_id(
                b"EREBOR-RUNTIME-BINDING-NONCE-V1\0",
                owner_uid,
                session_id,
                cgroup_id,
                label_epoch,
            ),
            execution_set_id: derived_id(
                b"EREBOR-RUNTIME-EXECUTION-SET-V1\0",
                owner_uid,
                session_id,
                cgroup_id,
                label_epoch,
            ),
            protected_scope_id: derived_id(
                b"EREBOR-RUNTIME-PROTECTED-SCOPE-V1\0",
                owner_uid,
                session_id,
                cgroup_id,
                label_epoch,
            ),
            profile_id: derived_id(
                b"EREBOR-RUNTIME-PROFILE-V1\0",
                owner_uid,
                session_id,
                cgroup_id,
                label_epoch,
            ),
            root_cgroup_live_interval_id: derived_id(
                b"EREBOR-RUNTIME-CGROUP-INTERVAL-V1\0",
                owner_uid,
                session_id,
                cgroup_id,
                label_epoch,
            ),
            profile_generation_ref_id: generation,
            policy_image_digest: image.digest().as_str().to_owned(),
            table_digest: effect_table_digest(&image, &rows),
            operation_decisions,
            activation_evidence_owner_start: None,
            activation_kernel_evidence_start: None,
            evidence_coverage: None,
            failure: None,
        };
        Ok(prepared_from_record(&record))
    }

    fn deny(
        prepared: &PreparedActivation,
        operation: KernelEffectOperationV1,
    ) -> std::result::Result<bool, Box<dyn std::error::Error>> {
        Ok(prepared
            .record
            .operation_decisions
            .iter()
            .find(|row| row.operation == operation as u16)
            .ok_or("operation row is absent")?
            .deny)
    }

    #[test]
    fn lowers_every_operation_with_exact_runtime_defaults(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let temporary = TempDir::new()?;
        let prepared = prepared(&temporary)?;

        assert_eq!(prepared.effect_rows.len(), 39);
        for operation in 1_u16..=KernelEffectOperationV1::OpenPath as u16 {
            assert_eq!(
                prepared
                    .record
                    .operation_decisions
                    .iter()
                    .filter(|row| row.operation == operation)
                    .count(),
                1
            );
        }
        assert!(deny(&prepared, KernelEffectOperationV1::OpenRead)?);
        assert!(!deny(&prepared, KernelEffectOperationV1::OpenWrite)?);
        assert!(!deny(&prepared, KernelEffectOperationV1::Mprotect)?);
        assert!(deny(&prepared, KernelEffectOperationV1::Ptrace)?);
        assert!(!deny(&prepared, KernelEffectOperationV1::Signal)?);
        for operation in [
            KernelEffectOperationV1::Bpf,
            KernelEffectOperationV1::IoUringSetup,
            KernelEffectOperationV1::IoUringRegister,
            KernelEffectOperationV1::IoUringSqpoll,
            KernelEffectOperationV1::IoUringOverrideCreds,
            KernelEffectOperationV1::IoUringCommand,
        ] {
            assert!(deny(&prepared, operation)?);
        }
        let mprotect = prepared
            .record
            .operation_decisions
            .iter()
            .find(|row| row.operation == KernelEffectOperationV1::Mprotect as u16)
            .ok_or("mprotect row is absent")?;
        assert_eq!(mprotect.effect_family, KernelEffectFamilyV1::File as u16);
        Ok(())
    }

    #[test]
    fn publishes_exact_rows_and_retires_the_owned_transaction(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let temporary = TempDir::new()?;
        let prepared = prepared(&temporary)?;
        let maps = FakeMaps::default();
        let checked = Cell::new(false);

        publish_activation(&maps, &prepared, || {
            checked.set(true);
            Ok(())
        })?;

        assert!(checked.get());
        assert_eq!(maps.len(), 48);
        assert_eq!(maps.map_len(EFFECT_DEFAULT_MAP), 39);
        assert_eq!(maps.map_len(SIGNAL_AUTHORITY_MAP), 2);
        assert_eq!(maps.map_len(ACTIVATION_TARGET_MAP), 1);
        assert_eq!(maps.map_len(ACTIVE_PROFILE_MAP), 1);
        let binding = maps
            .lookup(
                EXECUTION_BINDING_MAP,
                &prepared.record.cgroup_id.to_ne_bytes(),
            )?
            .ok_or("execution binding is absent")?;
        let binding = ExecutionSetBindingStateV1::try_read_from_bytes(&binding)
            .map_err(|error| error.to_string())?;
        assert_eq!(binding.lifecycle_state, BindingLifecycleStateV1::Active);
        let descriptor = maps
            .lookup(
                DESCRIPTOR_MAP,
                &prepared.record.profile_generation_ref_id.to_ne_bytes(),
            )?
            .ok_or("profile descriptor is absent")?;
        let descriptor = ProfileGenerationDescriptorV1::try_read_from_bytes(&descriptor)
            .map_err(|error| error.to_string())?;
        assert_eq!(descriptor.state, PolicyGenerationStateV1::Active);
        assert!(maps.rows.borrow().iter().any(|((map, _key), value)| {
            map == SIGNAL_AUTHORITY_MAP
                && ControllerSignalAuthorityV1::try_read_from_bytes(value)
                    .is_ok_and(|row| row.allowed_signal_mask == CONTROLLER_SIGNAL_ALLOWED_MASK_V1)
        }));

        rollback_published_activation(&maps, &prepared)?;
        assert_eq!(maps.len(), 0);
        Ok(())
    }

    #[test]
    fn retires_after_the_kernel_tombstones_an_exited_cgroup(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let temporary = TempDir::new()?;
        let prepared = prepared(&temporary)?;
        let maps = FakeMaps::default();
        publish_activation(&maps, &prepared, || Ok(()))?;

        let binding_key = prepared.record.cgroup_id.to_ne_bytes();
        let bytes = maps
            .lookup(EXECUTION_BINDING_MAP, &binding_key)?
            .ok_or("execution binding is absent")?;
        let mut binding = ExecutionSetBindingStateV1::try_read_from_bytes(&bytes)
            .map_err(|error| error.to_string())?;
        binding.lifecycle_state = BindingLifecycleStateV1::Tombstoned;
        maps.update(EXECUTION_BINDING_MAP, &binding_key, binding.as_bytes())?;

        super::fence_binding(&maps, &prepared, true)?;
        retire_owned_rows(&maps, &prepared)?;
        assert_eq!(maps.len(), 0);
        Ok(())
    }

    #[test]
    fn resumes_retirement_after_binding_tombstone_publication(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let temporary = TempDir::new()?;
        let prepared = prepared(&temporary)?;
        let maps = FakeMaps::default();
        publish_activation(&maps, &prepared, || Ok(()))?;
        super::fence_binding(&maps, &prepared, true)?;
        maps.fail_at(maps.mutations.get() + 2);

        assert!(retire_owned_rows(&maps, &prepared).is_err());
        let binding = maps
            .lookup(
                EXECUTION_BINDING_MAP,
                &prepared.record.cgroup_id.to_ne_bytes(),
            )?
            .ok_or("execution binding is absent")?;
        let binding = ExecutionSetBindingStateV1::try_read_from_bytes(&binding)
            .map_err(|error| error.to_string())?;
        assert_eq!(binding.lifecycle_state, BindingLifecycleStateV1::Tombstoned);

        super::fence_binding(&maps, &prepared, false)?;
        retire_owned_rows(&maps, &prepared)?;
        assert_eq!(maps.len(), 0);
        Ok(())
    }

    #[test]
    fn rolls_back_a_final_binding_publication_failure(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let temporary = TempDir::new()?;
        let prepared = prepared(&temporary)?;
        let maps = FakeMaps::default();
        maps.fail_at(51);

        assert!(publish_activation(&maps, &prepared, || Ok(())).is_err());
        assert_eq!(maps.len(), 0);
        Ok(())
    }

    #[test]
    fn reports_incomplete_rollback_and_attempts_every_delete(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let temporary = TempDir::new()?;
        let prepared = prepared(&temporary)?;
        let maps = FakeMaps::default();
        maps.fail_at_many(&[51, 52]);

        let error = publish_activation(&maps, &prepared, || Ok(()))
            .err()
            .ok_or("publication unexpectedly succeeded")?;
        assert!(matches!(
            error,
            super::RuntimeKernelInterceptionError::ActivationRollback { .. }
        ));
        assert_eq!(maps.len(), 1);
        assert_eq!(maps.map_len(EXECUTION_BINDING_MAP), 1);
        Ok(())
    }

    #[test]
    fn rolls_back_when_the_empty_boundary_recheck_fails(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let temporary = TempDir::new()?;
        let prepared = prepared(&temporary)?;
        let maps = FakeMaps::default();

        assert!(publish_activation(&maps, &prepared, || {
            invalid("the held boundary became populated")
        })
        .is_err());
        assert_eq!(maps.len(), 0);
        Ok(())
    }

    #[test]
    fn durable_owner_identities_are_deterministic_and_validated(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let temporary = TempDir::new()?;
        let prepared = prepared(&temporary)?;
        let state = temporary.path().join("runtime-interceptor");
        let path = durable_record_path(&state, prepared.record.binding_id);

        validate_durable_record(&prepared.record, &path)?;
        assert!(!prepared.record.binding_id.is_zero());
        assert_eq!(
            prepared.record.binding_id,
            derived_id(
                b"EREBOR-RUNTIME-BINDING-V1\0",
                prepared.record.owner_uid,
                &prepared.record.session_id,
                prepared.record.cgroup_id,
                prepared.record.label_epoch,
            )
        );
        assert_ne!(prepared.record.binding_id, prepared.record.binding_nonce);

        let mut changed = prepared.record.clone();
        changed.binding_id = erebor_interceptor_abi::Id128V1::new(90, 91);
        assert!(validate_durable_record(&changed, Path::new("changed.json")).is_err());

        let mut changed = prepared.record.clone();
        changed.owner_uid = changed.owner_uid.saturating_add(1);
        assert!(validate_durable_record(&changed, Path::new("changed.json")).is_err());

        let mut changed = prepared.record.clone();
        changed.recovery_controller_cgroup_ids = vec![90, 90];
        assert!(validate_durable_record(&changed, Path::new("changed.json")).is_err());

        let mut changed = prepared.record.clone();
        changed.operation_decisions[0].effect_family = KernelEffectFamilyV1::Unknown as u16;
        let rows = effect_rows(
            changed.profile_generation_ref_id,
            &changed.operation_decisions,
        );
        changed.table_digest = effect_table_digest_from(&changed.policy_image_digest, &rows);
        assert!(validate_durable_record(&changed, Path::new("changed.json")).is_err());
        assert_eq!(
            binding_from_record(&prepared.record).binding_id,
            prepared.record.binding_id
        );
        Ok(())
    }

    #[test]
    fn same_session_id_is_isolated_by_owner_uid(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let temporary = TempDir::new()?;
        let prepared = prepared(&temporary)?;
        let mut bindings = BTreeMap::new();
        bindings.insert(session_owner_key(1000, "same-session"), 1_u8);
        bindings.insert(session_owner_key(1001, "same-session"), 2_u8);

        assert_eq!(bindings.len(), 2);
        assert_eq!(
            bindings.get(&session_owner_key(1000, "same-session")),
            Some(&1)
        );
        assert_eq!(
            bindings.get(&session_owner_key(1001, "same-session")),
            Some(&2)
        );
        assert_ne!(
            derived_id(
                b"EREBOR-RUNTIME-BINDING-V1\0",
                1000,
                "same-session",
                prepared.record.cgroup_id,
                prepared.record.label_epoch,
            ),
            derived_id(
                b"EREBOR-RUNTIME-BINDING-V1\0",
                1001,
                "same-session",
                prepared.record.cgroup_id,
                prepared.record.label_epoch,
            )
        );
        Ok(())
    }

    #[test]
    fn durable_host_owner_retries_exact_config_and_rejects_disabled_or_changed_config(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let temporary = TempDir::new()?;
        let state_directory = temporary.path().join("runtime-interceptor");
        let btf = temporary.path().join("vmlinux");
        let lease = temporary.path().join("interceptor.lock");
        let pins = temporary.path().join("pins");

        assert!(RuntimeKernelInterceptionOwner::require_disabled_safe(temporary.path()).is_ok());
        prepare_state_directory(&state_directory)?;
        ensure_host_owner_identity(&state_directory, &btf, &lease, &pins)?;
        ensure_host_owner_identity(&state_directory, &btf, &lease, &pins)?;
        assert!(RuntimeKernelInterceptionOwner::require_disabled_safe(temporary.path()).is_err());
        assert!(ensure_host_owner_identity(
            &state_directory,
            &btf,
            &temporary.path().join("changed.lock"),
            &pins,
        )
        .is_err());
        assert!(ensure_host_owner_identity(
            &state_directory,
            &btf,
            &lease,
            &temporary.path().join("changed-pins"),
        )
        .is_err());
        assert!(ensure_host_owner_identity(
            &state_directory,
            &temporary.path().join("changed-vmlinux"),
            &lease,
            &pins,
        )
        .is_err());
        Ok(())
    }

    #[test]
    fn recovery_output_failure_does_not_gate_owned_row_retirement(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let temporary = TempDir::new()?;
        let prepared = prepared(&temporary)?;
        let blocked_output = temporary.path().join("blocked-output");
        std::fs::write(&blocked_output, b"not a directory")?;

        let mut good = prepared.record.clone();
        good.binding_id = erebor_interceptor_abi::Id128V1::new(80, 81);
        good.output = output_plan(temporary.path().join("good-output"))?;
        let mut blocked = prepared.record.clone();
        blocked.binding_id = erebor_interceptor_abi::Id128V1::new(82, 83);
        blocked.output = output_plan(blocked_output)?;
        let mut recovery = vec![
            RecoveryBinding {
                record: good,
                path: PathBuf::from("good.json"),
                evidence_failure: None,
            },
            RecoveryBinding {
                record: blocked,
                path: PathBuf::from("blocked.json"),
                evidence_failure: None,
            },
        ];
        let evidence = RuntimeEvidenceRouter::default();
        register_recovery_outputs(&evidence, &mut recovery);

        assert!(recovery[0].evidence_failure.is_none());
        assert!(evidence
            .route_snapshot(recovery[0].record.binding_id)
            .is_some());
        assert!(recovery[1].evidence_failure.is_some());
        assert!(evidence
            .route_snapshot(recovery[1].record.binding_id)
            .is_none());

        let maps = FakeMaps::default();
        publish_activation(&maps, &prepared, || Ok(()))?;
        super::fence_binding(&maps, &prepared, true)?;
        retire_owned_rows(&maps, &prepared)?;
        assert_eq!(maps.len(), 0);
        Ok(())
    }

    #[test]
    fn preexisting_poll_failure_rejects_activation_and_marks_coverage_incomplete() {
        let failed = EvidenceOwnerSnapshot {
            poll_failures: 1,
            ..EvidenceOwnerSnapshot::default()
        };

        assert!(require_evidence_reader(failed).is_err());
        assert!(coverage_failure(
            false,
            EvidenceRouteSnapshot::default(),
            failed,
            failed,
            KernelEvidenceSnapshot::default(),
            KernelEvidenceSnapshot::default(),
        )
        .is_some());
        assert!(coverage_failure(
            true,
            EvidenceRouteSnapshot::default(),
            EvidenceOwnerSnapshot::default(),
            EvidenceOwnerSnapshot::default(),
            KernelEvidenceSnapshot::default(),
            KernelEvidenceSnapshot::default(),
        )
        .is_some());
    }

    #[test]
    fn evidence_coverage_rejects_counter_regression_and_reader_mismatch() {
        assert_eq!(
            coverage_failure(
                false,
                EvidenceRouteSnapshot::default(),
                EvidenceOwnerSnapshot::default(),
                EvidenceOwnerSnapshot::default(),
                KernelEvidenceSnapshot::default(),
                KernelEvidenceSnapshot::default(),
            ),
            None
        );
        let healthy_start = KernelEvidenceSnapshot {
            attempted: 1,
            requested: 1,
            emitted: 1,
            ..KernelEvidenceSnapshot::default()
        };
        assert!(coverage_failure(
            false,
            EvidenceRouteSnapshot::default(),
            EvidenceOwnerSnapshot::default(),
            EvidenceOwnerSnapshot::default(),
            healthy_start,
            KernelEvidenceSnapshot::default(),
        )
        .is_some());

        let one_emitted = KernelEvidenceSnapshot {
            attempted: 1,
            requested: 1,
            emitted: 1,
            ..KernelEvidenceSnapshot::default()
        };
        assert!(coverage_failure(
            false,
            EvidenceRouteSnapshot::default(),
            EvidenceOwnerSnapshot::default(),
            EvidenceOwnerSnapshot::default(),
            KernelEvidenceSnapshot::default(),
            one_emitted,
        )
        .is_some());
    }

    #[test]
    fn drain_barrier_requires_an_explicit_reader_acknowledgement() -> std::result::Result<(), String>
    {
        let (requests, reader_requests) = mpsc::channel::<EvidencePollBarrier>();
        let reader = thread::spawn(move || {
            let request = reader_requests.recv().map_err(|error| error.to_string())?;
            request
                .acknowledged
                .send(true)
                .map_err(|error| error.to_string())
        });

        assert_eq!(request_evidence_barrier(&requests), None);
        reader
            .join()
            .map_err(|_panic| "reader task panicked".to_owned())??;

        let (unavailable, reader_requests) = mpsc::channel::<EvidencePollBarrier>();
        drop(reader_requests);
        assert!(request_evidence_barrier(&unavailable).is_some());
        Ok(())
    }
}
