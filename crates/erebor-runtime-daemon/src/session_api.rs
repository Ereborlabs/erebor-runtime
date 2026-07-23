mod admission;
mod policy_router;
mod response;

use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use erebor_runtime_core::{
    ActiveSessionSignal, EndpointProjection, FilesystemProjection, ImmutableIdentity,
    SafePathBinding, SafePathKind, SessionLifecycleState, SessionOwner, SessionSpec,
};
use erebor_runtime_ipc::v1::{
    AgentInstallResponse, CodexAppServerAttachResponse, CodexAppServerInputCloseResponse,
    CodexAppServerInputResponse, CodexRunRequest, PolicyPackageRecord, PolicySetAliasRecord,
    PolicySetRecord, SessionAliasListResponse, SessionAliasRecord, SessionAttachResponse,
    SessionCreateRequest, SessionCreateResponse, SessionInputLeaseResponse, SessionInputResponse,
    SessionListResponse, SessionPruneResponse, SessionRecord,
    KIND_CODEX_APP_SERVER_ATTACH_RESPONSE, KIND_POLICY_PACKAGE_RECORD,
    KIND_POLICY_SET_ALIAS_RECORD, KIND_POLICY_SET_RECORD, KIND_SESSION_ALIAS_RECORD,
    KIND_SESSION_ATTACH_RESPONSE, KIND_SESSION_CREATE_RESPONSE, KIND_SESSION_INPUT_LEASE_RESPONSE,
    KIND_SESSION_PRUNE_RESPONSE, KIND_SESSION_RECORD,
};
use erebor_runtime_packages::{ContentDigest, LocalArtifactProvider, VerifiedLocalArtifact};
use erebor_runtime_session::{
    AgentAdapterRegistry, CodexAppServerService, CodexHookService, DurableSessionRecord,
    RunnerAdmissionRequest, RunnerRegistry, SessionManager, SessionManagerError, SessionRepository,
    SessionRepositoryError, SessionRuntimeResources, StreamKind, ValidatedStartConstraints,
};
use prost::Message;
use snafu::ResultExt;
use uuid::Uuid;

use crate::{
    config::DaemonConfig,
    error::SessionSnafu,
    idempotency::{MutationIntent, MutationResponse},
    local_store::DaemonLocalStore,
    path_broker::DescriptorBroker,
    DaemonPaths, Result,
};

use self::{
    admission::{admit, parse_request, AdmissionContext},
    policy_router::StoredPolicyInterceptionRouterFactory,
    response::session_record,
};

pub(crate) struct DaemonSessionApi {
    manager: Arc<SessionManager>,
    state_root: PathBuf,
    runtime_root: PathBuf,
    retry_horizon: Duration,
    descriptor_broker: Arc<DescriptorBroker>,
    local_store: Arc<DaemonLocalStore>,
    adapters: AgentAdapterRegistry,
    codex_hook_service: Arc<CodexHookService>,
    codex_app_server_service: Arc<CodexAppServerService>,
    codex_app_server_output_monitors: Arc<Mutex<BTreeSet<String>>>,
}

pub(crate) struct VerifiedCodexInstallation {
    package_digest: String,
    artifact: VerifiedLocalArtifact,
}

impl VerifiedCodexInstallation {
    pub(crate) fn package_digest(&self) -> &str {
        &self.package_digest
    }

    pub(crate) const fn artifact(&self) -> &VerifiedLocalArtifact {
        &self.artifact
    }
}

impl DaemonSessionApi {
    pub(crate) fn installed(paths: &DaemonPaths, config: &DaemonConfig) -> Result<Self> {
        Self::new(
            paths,
            config,
            RunnerRegistry::compiled_linux_host(config.linux_runner().install_config())
                .context(SessionSnafu)?,
        )
    }

    pub(crate) fn new(
        paths: &DaemonPaths,
        config: &DaemonConfig,
        runners: RunnerRegistry,
    ) -> Result<Self> {
        let state_root = paths.session_state_path();
        let runtime_root = paths.session_runtime_path();
        let descriptor_broker = Arc::new(
            config
                .linux_runner()
                .descriptor_broker_path()
                .map(PathBuf::from)
                .map(DescriptorBroker::new)
                .unwrap_or_else(DescriptorBroker::installed),
        );
        let local_store = Arc::new(DaemonLocalStore::installed(paths)?);
        let adapters = AgentAdapterRegistry::compiled().map_err(|error| {
            crate::error::InvalidRequestSnafu {
                reason: format!("compiling built-in adapter registry failed: {error}"),
            }
            .build()
        })?;
        local_store.seed_builtin_generic_content()?;
        local_store.seed_root_curated(config.root_curated_admissions())?;
        local_store.seed_root_curated_codex_packages(config.root_curated_codex_packages())?;
        let codex_hook_service = Arc::new(CodexHookService::start(runtime_root.clone()).map_err(
            |error| {
                crate::error::InvalidRequestSnafu {
                    reason: format!("starting the daemon-owned Codex hook service failed: {error}"),
                }
                .build()
            },
        )?);
        let codex_app_server_service = Arc::new(CodexAppServerService::default());
        let runtime = SessionRuntimeResources::new(
            state_root.clone(),
            runtime_root.clone(),
            Arc::clone(&descriptor_broker) as Arc<dyn erebor_runtime_session::SessionPathResolver>,
            Arc::new(StoredPolicyInterceptionRouterFactory::new(
                Arc::clone(&local_store),
                Arc::clone(&codex_hook_service),
                Arc::clone(&codex_app_server_service),
            )),
        )
        .context(SessionSnafu)?;
        Ok(Self {
            manager: Arc::new(SessionManager::new(
                SessionRepository::new(&state_root),
                runners,
                runtime,
            )),
            state_root,
            runtime_root,
            retry_horizon: Duration::from_secs(config.session_retry_horizon_seconds),
            descriptor_broker,
            local_store,
            adapters,
            codex_hook_service,
            codex_app_server_service,
            codex_app_server_output_monitors: Arc::new(Mutex::new(BTreeSet::new())),
        })
    }

    pub(crate) fn admit_request(
        &self,
        request: SessionCreateRequest,
        owner_uid: u32,
        owner_gid: u32,
        configuration_generation: u64,
        config: &DaemonConfig,
    ) -> Result<SessionSpec> {
        self.admit_request_with_adapter(
            request,
            owner_uid,
            owner_gid,
            configuration_generation,
            config,
            false,
        )
    }

    fn admit_request_with_adapter(
        &self,
        mut request: SessionCreateRequest,
        owner_uid: u32,
        owner_gid: u32,
        configuration_generation: u64,
        config: &DaemonConfig,
        allow_codex_adapter: bool,
    ) -> Result<SessionSpec> {
        let session_id = format!("session-{}", Uuid::new_v4());
        let identity_fields = [
            &request.package_digest,
            &request.installation_digest,
            &request.adapter_digest,
            &request.policy_set_digest,
        ];
        if identity_fields.iter().all(|value| value.is_empty()) {
            let builtin = self.local_store.ensure_builtin_admission(owner_uid)?;
            request.package_digest = builtin.package_digest().to_owned();
            request.installation_digest = builtin.installation_digest().to_owned();
            request.adapter_digest = builtin.adapter_digest().to_owned();
            request.policy_set_digest = builtin.policy_set_digest().to_owned();
        } else if identity_fields.iter().any(|value| value.is_empty()) {
            return crate::error::InvalidRequestSnafu {
                reason: String::from(
                    "package, installation, adapter, and policy-set identities must be supplied together",
                ),
            }
            .fail();
        }
        let request = parse_request(request)?;
        self.enforce_session_quota(owner_uid, config)?;
        let runner = request.runner().clone();
        let executable_search_path = request
            .environment()
            .iter()
            .find(|(key, _value)| key == "PATH")
            .map(|(_key, value)| value.as_str());
        let capability = self.manager.inspect_runner(&runner).context(SessionSnafu)?;
        let owner = SessionOwner::new(owner_uid, owner_gid);
        let mut runner_admission = self
            .manager
            .admit_runner(
                &runner,
                RunnerAdmissionRequest::new(
                    &session_id,
                    &owner,
                    request.command(),
                    executable_search_path,
                    request.workspace(),
                    request.container_image_sha256(),
                    &self.runtime_root.join("runtime-interception.sock"),
                ),
                self.descriptor_broker.as_ref(),
            )
            .context(SessionSnafu)?;
        let additional_filesystem_projections = if allow_codex_adapter {
            let package_digest = request.package_sha256().ok_or_else(|| {
                crate::error::InvalidRequestSnafu {
                    reason: String::from("Codex admission requires a package digest"),
                }
                .build()
            })?;
            let projections =
                self.codex_filesystem_projections(owner_uid, owner_gid, package_digest, config)?;
            runner_admission.endpoint_projections.push(
                EndpointProjection::new(
                    "codex-hook",
                    self.codex_hook_service.endpoint().to_path_buf(),
                    PathBuf::from(CodexHookService::session_endpoint()),
                )
                .map_err(|error| {
                    crate::error::InvalidRequestSnafu {
                        reason: error.to_string(),
                    }
                    .build()
                })?,
            );
            projections
        } else {
            Vec::new()
        };
        let spec = admit(
            request,
            AdmissionContext {
                owner,
                session_id: &session_id,
                root_configuration_generation: configuration_generation,
                state_root: &self.state_root,
                capability,
                runner_admission,
                adapters: &self.adapters,
                local_store: self.local_store.as_ref(),
                config,
                allow_codex_adapter,
                additional_filesystem_projections,
            },
        )?;
        self.manager
            .validate_admission(&spec)
            .context(SessionSnafu)?;
        Ok(spec)
    }

    pub(crate) fn seed_root_curated(&self, config: &DaemonConfig) -> Result<()> {
        self.local_store
            .seed_root_curated(config.root_curated_admissions())?;
        self.local_store
            .seed_root_curated_codex_packages(config.root_curated_codex_packages())
    }

    pub(crate) fn verify_codex_installation(
        &self,
        package_reference: &str,
        source_path: &Path,
        owner_uid: u32,
        owner_gid: u32,
    ) -> Result<VerifiedCodexInstallation> {
        let package = self
            .local_store
            .resolve_codex_package_reference(package_reference)?;
        let resolved = self.descriptor_broker.resolve(
            owner_uid,
            owner_gid,
            source_path,
            SafePathKind::Executable,
        )?;
        let binding = resolved.binding();
        let sha256 = binding.content_sha256().ok_or_else(|| {
            crate::error::InvalidRequestSnafu {
                reason: String::from("descriptor broker did not hash the held Codex executable"),
            }
            .build()
        })?;
        let artifact = VerifiedLocalArtifact::new(
            binding.requested_path().to_path_buf(),
            binding.device(),
            binding.inode(),
            binding.mount_id(),
            binding.owner_uid(),
            binding.owner_gid(),
            resolved.mode()?,
            ContentDigest::new(sha256).map_err(|error| {
                crate::error::InvalidRequestSnafu {
                    reason: format!(
                        "descriptor broker returned an invalid executable digest: {error}"
                    ),
                }
                .build()
            })?,
            LocalArtifactProvider::CallerDescriptor,
        )
        .map_err(|error| {
            crate::error::InvalidRequestSnafu {
                reason: format!("Codex installation artifact is invalid: {error}"),
            }
            .build()
        })?;
        if artifact.owner_uid() != owner_uid {
            return crate::error::InvalidRequestSnafu {
                reason: String::from(
                    "a caller-enrolled Codex executable must remain owned by the calling UID",
                ),
            }
            .fail();
        }
        if artifact.sha256() != package.definition().executable_sha256() {
            return crate::error::InvalidRequestSnafu {
                reason: String::from(
                    "the held Codex executable does not match the root-curated release hash",
                ),
            }
            .fail();
        }
        Ok(VerifiedCodexInstallation {
            package_digest: package.package_digest().to_owned(),
            artifact,
        })
    }

    pub(crate) fn admit_codex_run(
        &self,
        request: CodexRunRequest,
        owner_uid: u32,
        owner_gid: u32,
        configuration_generation: u64,
        config: &DaemonConfig,
    ) -> Result<SessionSpec> {
        let installation = self
            .local_store
            .resolve_codex_alias(owner_uid, &request.alias)?;
        let artifact = installation
            .installation()
            .local_artifact()
            .ok_or_else(|| {
                crate::error::InvalidRequestSnafu {
                    reason: String::from("Codex alias has no descriptor-verified local artifact"),
                }
                .build()
            })?;
        let executable = self.reverify_codex_artifact(owner_uid, owner_gid, artifact)?;
        let entrypoint = installation
            .package()
            .definition()
            .entrypoint(installation.entrypoint())
            .ok_or_else(|| {
                crate::error::InvalidRequestSnafu {
                    reason: String::from(
                        "Codex alias does not name a certified package entrypoint",
                    ),
                }
                .build()
            })?;
        if entrypoint.app_server_stdio() && request.tty {
            return crate::error::InvalidRequestSnafu {
                reason: String::from(
                    "the certified Codex App Server entrypoint must not use a TTY",
                ),
            }
            .fail();
        }
        if !entrypoint.app_server_stdio() && !request.tty {
            return crate::error::InvalidRequestSnafu {
                reason: String::from(
                    "the certified interactive Codex entrypoint requires a daemon-owned TTY",
                ),
            }
            .fail();
        }
        let mut command = vec![artifact.path().display().to_string()];
        command.extend(entrypoint.argv_suffix().iter().cloned());
        let policy_set_digest = self
            .local_store
            .resolve_policy_set_reference(owner_uid, &request.policy_set_reference)?;
        let spec = self.admit_request_with_adapter(
            SessionCreateRequest {
                runner_id: String::from("linux-host"),
                command,
                workspace: request.workspace,
                policy_set_digest: policy_set_digest.as_str().to_owned(),
                package_digest: installation.package().package_digest().to_owned(),
                installation_digest: installation.installation_digest().to_owned(),
                adapter_digest: installation
                    .package()
                    .package()
                    .adapter_digest()
                    .as_str()
                    .to_owned(),
                daemon_failure_mode: request.daemon_failure_mode,
                requested_loss_grace_seconds: request.requested_loss_grace_seconds,
                environment: Vec::new(),
                secret_references: Vec::new(),
                container_image_digest: String::new(),
                tty: request.tty,
                detached: request.detached,
            },
            owner_uid,
            owner_gid,
            configuration_generation,
            config,
            true,
        )?;
        if spec.executable() != Some(&executable) {
            return crate::error::InvalidRequestSnafu {
                reason: String::from(
                    "Codex executable changed between alias revalidation and runner admission",
                ),
            }
            .fail();
        }
        Ok(spec)
    }

    pub(crate) fn install_verified_codex(
        &self,
        owner_uid: u32,
        package_digest: &str,
        artifact: VerifiedLocalArtifact,
        installed_at_unix_ms: u64,
    ) -> Result<AgentInstallResponse> {
        let installation = self.local_store.store_codex_installation(
            owner_uid,
            package_digest,
            installed_at_unix_ms,
            artifact,
        )?;
        let definition = installation.package().definition();
        let aliases = ["codex", "codex-app-server"]
            .into_iter()
            .filter(|alias| {
                definition
                    .entrypoint(alias)
                    .is_some_and(|entrypoint| *alias == "codex" || entrypoint.app_server_stdio())
            })
            .map(str::to_owned)
            .collect();
        Ok(AgentInstallResponse {
            package_digest: installation.package().package_digest().to_owned(),
            installation_digest: installation.installation_digest().to_owned(),
            aliases,
        })
    }

    pub(crate) fn installation_time() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(1, |duration| duration.as_millis() as u64)
    }

    fn reverify_codex_artifact(
        &self,
        owner_uid: u32,
        owner_gid: u32,
        artifact: &VerifiedLocalArtifact,
    ) -> Result<SafePathBinding> {
        let resolved = self.descriptor_broker.resolve(
            owner_uid,
            owner_gid,
            artifact.path(),
            SafePathKind::Executable,
        )?;
        let binding = resolved.binding();
        let matches = binding.requested_path() == artifact.path()
            && binding.device() == artifact.device()
            && binding.inode() == artifact.inode()
            && binding.mount_id() == artifact.mount_id()
            && binding.owner_uid() == artifact.owner_uid()
            && binding.owner_gid() == artifact.owner_gid()
            && binding.content_sha256() == Some(artifact.sha256().as_str())
            && resolved.mode()? == artifact.mode();
        if !matches {
            return crate::error::InvalidRequestSnafu {
                reason: String::from(
                    "Codex installation artifact identity, owner, mode, or content changed after enrollment",
                ),
            }
            .fail();
        }
        Ok(binding.clone())
    }

    fn codex_filesystem_projections(
        &self,
        owner_uid: u32,
        owner_gid: u32,
        package_digest: &str,
        config: &DaemonConfig,
    ) -> Result<Vec<FilesystemProjection>> {
        let package = config
            .root_curated_codex_package(package_digest)
            .ok_or_else(|| {
                crate::error::InvalidRequestSnafu {
                reason: String::from(
                    "Codex package is not present in the active root-curated daemon configuration",
                ),
            }
            .build()
            })?;
        let artifacts = package.definition().managed_artifacts();
        let mut sources = vec![
            (
                artifacts.requirements_source(),
                artifacts.requirements_path(),
            ),
            (
                artifacts.managed_hook_source(),
                artifacts.managed_hook_path(),
            ),
            (
                artifacts.shell_startup_source(),
                artifacts.shell_startup_path(),
            ),
        ];
        if let (Some(source), Some(target)) = (
            artifacts.sandbox_launcher(),
            artifacts.sandbox_launcher_path(),
        ) {
            sources.push((source, target));
        }
        sources
            .into_iter()
            .map(|(artifact, target)| {
                if !artifact.path().starts_with(package.trust_root()) {
                    return crate::error::InvalidRequestSnafu {
                        reason: String::from(
                            "Codex package artifact is outside its root-curated trust root",
                        ),
                    }
                    .fail();
                }
                let resolved = self.descriptor_broker.resolve(
                    owner_uid,
                    owner_gid,
                    artifact.path(),
                    SafePathKind::File,
                )?;
                let binding = resolved.binding();
                if binding.owner_uid() != 0
                    || resolved.mode()? & 0o022 != 0
                    || binding.content_sha256() != Some(artifact.sha256().as_str())
                {
                    return crate::error::InvalidRequestSnafu {
                        reason: format!(
                            "Codex root-managed artifact `{}` has an unexpected owner, mode, or digest",
                            artifact.path().display(),
                        ),
                    }
                    .fail();
                }
                FilesystemProjection::new(binding.clone(), target.to_path_buf(), true).map_err(
                    |error| crate::error::InvalidRequestSnafu {
                        reason: error.to_string(),
                    }
                    .build(),
                )
            })
            .collect()
    }

    pub(crate) fn runner_reports(
        &self,
    ) -> Result<Vec<erebor_runtime_session::RunnerCapabilityReport>> {
        self.manager.runner_reports().context(SessionSnafu)
    }

    pub(crate) fn runner_report(
        &self,
        runner_id: &str,
    ) -> Result<erebor_runtime_session::RunnerCapabilityReport> {
        let runner = erebor_runtime_core::RunnerId::new(runner_id).map_err(|error| {
            crate::error::InvalidRequestSnafu {
                reason: error.to_string(),
            }
            .build()
        })?;
        self.manager.runner_report(&runner).context(SessionSnafu)
    }

    fn enforce_session_quota(&self, owner_uid: u32, config: &DaemonConfig) -> Result<()> {
        let sessions = self.manager.list(owner_uid).context(SessionSnafu)?;
        let active = sessions
            .iter()
            .filter(|record| !record.state().is_terminal())
            .count();
        if active >= config.max_concurrent_sessions_per_uid() as usize {
            return crate::error::InvalidRequestSnafu {
                reason: format!(
                    "owner UID {owner_uid} has reached the {} concurrent-session limit",
                    config.max_concurrent_sessions_per_uid()
                ),
            }
            .fail();
        }
        let retained_output = sessions
            .iter()
            .filter(|record| record.retains_content())
            .fold(0_u64, |total, record| {
                total.saturating_add(record.spec().output().maximum_bytes())
            });
        let requested_output = config.max_session_output_bytes;
        if retained_output.saturating_add(requested_output)
            > config.max_retained_session_output_bytes_per_uid()
        {
            return crate::error::InvalidRequestSnafu {
                reason: format!(
                    "owner UID {owner_uid} would exceed the {}-byte retained output/evidence limit",
                    config.max_retained_session_output_bytes_per_uid(),
                ),
            }
            .fail();
        }
        Ok(())
    }

    pub(crate) fn apply(&self, intent: &MutationIntent) -> Result<MutationResponse> {
        match intent {
            MutationIntent::SessionCreate { spec } => self.create((**spec).clone()),
            MutationIntent::SessionStart { .. } => {
                unreachable!("session start requires validated root constraints")
            }
            MutationIntent::SessionStop {
                uid,
                session_id,
                grace_period_seconds,
            } => self.stop(*uid, session_id, *grace_period_seconds),
            MutationIntent::SessionKill {
                uid,
                session_id,
                signal,
            } => self.kill(*uid, session_id, *signal),
            MutationIntent::SessionRemove {
                uid,
                session_id,
                force,
            } => self.remove(*uid, session_id, *force),
            MutationIntent::SessionAttach {
                uid,
                session_id,
                request_input_lease,
                client_instance_id,
            } => self.attach(*uid, session_id, *request_input_lease, client_instance_id),
            MutationIntent::CodexAppServerAttach {
                uid,
                session_id,
                client_instance_id,
            } => self.attach_codex_app_server(*uid, session_id, client_instance_id),
            MutationIntent::SessionInputLeaseRenew {
                uid,
                session_id,
                lease_id,
                client_instance_id,
            } => self.renew_lease(*uid, session_id, lease_id, client_instance_id),
            MutationIntent::SessionInputLeaseRelease {
                uid,
                session_id,
                lease_id,
                client_instance_id,
            } => self.release_lease(*uid, session_id, lease_id, client_instance_id),
            MutationIntent::SessionPrune {
                uid,
                terminal_before_unix_ms,
                maximum_sessions,
            } => self.prune(*uid, *terminal_before_unix_ms, *maximum_sessions),
            MutationIntent::SessionAliasSet {
                uid,
                alias,
                session_id,
            } => self.set_alias(*uid, alias, session_id),
            MutationIntent::SessionAliasRemove { uid, alias } => self.remove_alias(*uid, alias),
            MutationIntent::SessionSetRetentionHold {
                uid,
                session_id,
                retention_hold,
            } => self.set_retention_hold(*uid, session_id, *retention_hold),
            MutationIntent::PolicyPackageApply {
                uid,
                policy,
                maximum_stored_bytes,
            } => self.store_policy_package(*uid, policy, *maximum_stored_bytes),
            MutationIntent::PolicySetCreate {
                uid,
                root_minimum_digest,
                package_minimum_digests,
                local_override_digest,
            } => self.create_policy_set(
                *uid,
                root_minimum_digest,
                package_minimum_digests,
                local_override_digest.as_deref(),
            ),
            MutationIntent::PolicySetAliasSet {
                uid,
                alias,
                policy_set_digest,
            } => self.set_policy_set_alias(*uid, alias, policy_set_digest),
            MutationIntent::Reload { .. }
            | MutationIntent::Stop
            | MutationIntent::AgentInstall { .. }
            | MutationIntent::ApprovalApprove { .. }
            | MutationIntent::ApprovalDeny { .. } => {
                unreachable!("daemon-only mutation reached session service")
            }
        }
    }

    pub(crate) fn read_policy_package(
        &self,
        owner_uid: u32,
        owner_gid: u32,
        path: &std::path::Path,
        maximum_bytes: u64,
    ) -> Result<erebor_runtime_packages::PolicyPackageRevision> {
        self.descriptor_broker
            .read_policy_package(owner_uid, owner_gid, path, maximum_bytes)
    }

    pub(crate) fn list_policy_packages(&self, owner_uid: u32) -> Result<Vec<PolicyPackageRecord>> {
        self.local_store
            .list_policy_packages(owner_uid)
            .map(|packages| {
                packages
                    .into_iter()
                    .map(|package| PolicyPackageRecord {
                        digest: package.digest().to_owned(),
                        name: package.name().to_owned(),
                    })
                    .collect()
            })
    }

    pub(crate) fn inspect_policy_package(
        &self,
        owner_uid: u32,
        digest: &str,
    ) -> Result<PolicyPackageRecord> {
        self.local_store
            .inspect_policy_package(owner_uid, digest)
            .map(|package| PolicyPackageRecord {
                digest: package.digest().to_owned(),
                name: package.name().to_owned(),
            })
    }

    pub(crate) fn list_policy_sets(&self, owner_uid: u32) -> Result<Vec<PolicySetRecord>> {
        self.local_store
            .list_policy_sets(owner_uid)
            .map(|policy_sets| {
                policy_sets
                    .into_iter()
                    .map(|policy_set| PolicySetRecord {
                        digest: policy_set.digest().to_owned(),
                    })
                    .collect()
            })
    }

    pub(crate) fn inspect_policy_set(
        &self,
        owner_uid: u32,
        digest: &str,
    ) -> Result<PolicySetRecord> {
        self.local_store
            .inspect_policy_set(owner_uid, digest)
            .map(|policy_set| PolicySetRecord {
                digest: policy_set.digest().to_owned(),
            })
    }

    fn store_policy_package(
        &self,
        owner_uid: u32,
        policy: &erebor_runtime_packages::PolicyPackageRevision,
        maximum_stored_bytes: u64,
    ) -> Result<MutationResponse> {
        let digest =
            self.local_store
                .store_user_policy_package(owner_uid, policy, maximum_stored_bytes)?;
        message(
            KIND_POLICY_PACKAGE_RECORD,
            &PolicyPackageRecord {
                digest: digest.as_str().to_owned(),
                name: policy.manifest().name().to_owned(),
            },
        )
    }

    fn create_policy_set(
        &self,
        owner_uid: u32,
        root_minimum_digest: &str,
        package_minimum_digests: &[String],
        local_override_digest: Option<&str>,
    ) -> Result<MutationResponse> {
        let digest = self.local_store.create_user_policy_set(
            owner_uid,
            root_minimum_digest,
            package_minimum_digests,
            local_override_digest,
        )?;
        message(
            KIND_POLICY_SET_RECORD,
            &PolicySetRecord {
                digest: digest.as_str().to_owned(),
            },
        )
    }

    fn set_policy_set_alias(
        &self,
        owner_uid: u32,
        alias: &str,
        policy_set_digest: &str,
    ) -> Result<MutationResponse> {
        let alias = self
            .local_store
            .set_policy_set_alias(owner_uid, alias, policy_set_digest)?;
        message(
            KIND_POLICY_SET_ALIAS_RECORD,
            &PolicySetAliasRecord {
                alias: alias.name().to_owned(),
                policy_set_digest: alias.digest().as_str().to_owned(),
            },
        )
    }

    pub(crate) fn inspect(&self, uid: u32, session_id: &str) -> Result<SessionRecord> {
        let session_id = self.resolve_session_reference(uid, session_id)?;
        let record = self
            .manager
            .inspect(uid, &session_id)
            .context(SessionSnafu)?;
        Ok(self.record(&record))
    }

    pub(crate) fn list(&self, uid: u32) -> Result<SessionListResponse> {
        let sessions = self
            .manager
            .list(uid)
            .context(SessionSnafu)?
            .iter()
            .map(|record| self.record(record))
            .collect();
        Ok(SessionListResponse { sessions })
    }

    pub(crate) fn aliases(&self, uid: u32) -> Result<SessionAliasListResponse> {
        let aliases = self
            .manager
            .aliases(uid)
            .context(SessionSnafu)?
            .into_iter()
            .map(|alias| SessionAliasRecord {
                alias: alias.alias().to_owned(),
                session_id: alias.session_id().to_owned(),
            })
            .collect();
        Ok(SessionAliasListResponse { aliases })
    }

    pub(crate) fn list_all(&self) -> Result<SessionListResponse> {
        let sessions = self
            .manager
            .list_all()
            .context(SessionSnafu)?
            .iter()
            .map(|record| self.record(record))
            .collect();
        Ok(SessionListResponse { sessions })
    }

    pub(crate) fn wait(&self, uid: u32, session_id: &str) -> Result<SessionRecord> {
        let session_id = self.resolve_session_reference(uid, session_id)?;
        let record = self.manager.wait(uid, &session_id).context(SessionSnafu)?;
        Ok(self.record(&record))
    }

    pub(crate) fn stream(
        &self,
        uid: u32,
        session_id: &str,
        kind: StreamKind,
        after_sequence: u64,
        maximum_records: usize,
    ) -> Result<erebor_runtime_session::DurableStreamCursor> {
        let session_id = self.resolve_session_reference(uid, session_id)?;
        let page = self
            .manager
            .stream(uid, &session_id, kind, after_sequence, maximum_records)
            .context(SessionSnafu)?;
        if kind == StreamKind::Stdout && self.is_codex_app_server(uid, &session_id)? {
            for record in page.records() {
                self.codex_app_server_service
                    .observe_output_chunk(&session_id, record.sequence(), record.data())
                    .map_err(|error| {
                        crate::error::InvalidRequestSnafu {
                            reason: format!("Codex App Server output is invalid: {error}"),
                        }
                        .build()
                    })?;
            }
        }
        Ok(page)
    }

    pub(crate) fn has_unresolved_sessions(&self) -> Result<bool> {
        self.manager.has_unresolved_sessions().context(SessionSnafu)
    }

    pub(crate) fn validate_start(
        &self,
        uid: u32,
        session_id: &str,
        configuration_generation: u64,
        config: &DaemonConfig,
    ) -> Result<ValidatedStartConstraints> {
        let session_id = self.resolve_session_reference(uid, session_id)?;
        let record = self
            .manager
            .inspect(uid, &session_id)
            .context(SessionSnafu)?;
        if record.state() != SessionLifecycleState::Created {
            return Ok(ValidatedStartConstraints::new(
                uid,
                &session_id,
                configuration_generation,
            ));
        }
        self.manager
            .validate_admission(record.spec())
            .context(SessionSnafu)?;
        let output = record.spec().output();
        if record.spec().loss_grace_seconds() > config.max_daemon_loss_grace_seconds
            || output.maximum_bytes() > config.max_session_output_bytes
            || output.rotation_bytes() > config.session_output_rotation_bytes
        {
            return crate::error::InvalidRequestSnafu {
                reason: String::from(
                    "session no longer satisfies the active root start constraints",
                ),
            }
            .fail();
        }
        let admission = self.local_store.validate_session_spec(record.spec())?;
        if admission.package().adapter_id() == "codex-v1" {
            let installation = self.local_store.resolve_codex_installation(
                uid,
                admission.package_digest(),
                admission.installation_digest(),
                None,
            )?;
            let artifact = installation
                .installation()
                .local_artifact()
                .ok_or_else(|| {
                    crate::error::InvalidRequestSnafu {
                        reason: String::from(
                            "Codex session installation no longer has a verified local artifact",
                        ),
                    }
                    .build()
                })?;
            let current =
                self.reverify_codex_artifact(uid, record.spec().owner().gid(), artifact)?;
            if record.spec().executable() != Some(&current) {
                return crate::error::InvalidRequestSnafu {
                    reason: String::from(
                        "Codex session executable no longer matches its enrolled artifact",
                    ),
                }
                .fail();
            }
        }
        self.adapters
            .prepare(
                admission.package(),
                env!("CARGO_PKG_VERSION"),
                record.spec().command(),
            )
            .map_err(|error| {
                crate::error::InvalidRequestSnafu {
                    reason: format!("session adapter no longer validates: {error}"),
                }
                .build()
            })?;
        if !admission
            .policy_input_digests()
            .iter()
            .map(String::as_str)
            .eq(record
                .spec()
                .policy_inputs()
                .iter()
                .map(ImmutableIdentity::sha256))
        {
            return crate::error::InvalidRequestSnafu {
                reason: String::from(
                    "session policy identities no longer match the daemon-owned policy set",
                ),
            }
            .fail();
        }
        Ok(ValidatedStartConstraints::new(
            uid,
            &session_id,
            configuration_generation,
        ))
    }

    pub(crate) fn reconcile(&self) -> Result<Vec<DurableSessionRecord>> {
        let records = self.manager.reconcile().context(SessionSnafu)?;
        for record in &records {
            if !record.state().is_terminal() {
                self.monitor_codex_app_server_output(
                    record.spec().owner().uid(),
                    record.spec().session_id().as_str(),
                )?;
            }
        }
        Ok(records)
    }

    fn create(&self, spec: SessionSpec) -> Result<MutationResponse> {
        let record = match self.manager.create(spec.clone()) {
            Ok(record) => record,
            Err(SessionManagerError::Repository {
                source: SessionRepositoryError::AlreadyExists { .. },
                ..
            }) => self
                .manager
                .inspect(spec.owner().uid(), spec.session_id().as_str())
                .context(SessionSnafu)?,
            Err(source) => return Err(source).context(SessionSnafu),
        };
        self.local_store.record_session_lease(record.spec())?;
        message(
            KIND_SESSION_CREATE_RESPONSE,
            &SessionCreateResponse {
                session_id: record.spec().session_id().as_str().to_owned(),
                state: record.state().as_str().to_owned(),
                generation: record.generation(),
                retry_guarantee_expires_unix_ms: self.retry_expiration(&record),
            },
        )
    }

    pub(crate) fn start(
        &self,
        uid: u32,
        session_id: &str,
        constraints: &ValidatedStartConstraints,
        resume_pending: bool,
    ) -> Result<MutationResponse> {
        let session_id = self.resolve_session_reference(uid, session_id)?;
        let record = self
            .manager
            .start(uid, &session_id, constraints, resume_pending)
            .context(SessionSnafu)?;
        self.monitor_codex_app_server_output(uid, &session_id)?;
        message(KIND_SESSION_RECORD, &self.record(&record))
    }

    fn stop(
        &self,
        uid: u32,
        session_id: &str,
        grace_period_seconds: u64,
    ) -> Result<MutationResponse> {
        let session_id = self.resolve_session_reference(uid, session_id)?;
        let record = self
            .manager
            .stop(
                uid,
                &session_id,
                Duration::from_secs(grace_period_seconds.max(1)),
            )
            .context(SessionSnafu)?;
        message(KIND_SESSION_RECORD, &self.record(&record))
    }

    fn kill(
        &self,
        uid: u32,
        session_id: &str,
        signal: ActiveSessionSignal,
    ) -> Result<MutationResponse> {
        let session_id = self.resolve_session_reference(uid, session_id)?;
        let record = self
            .manager
            .kill(uid, &session_id, signal)
            .context(SessionSnafu)?;
        message(KIND_SESSION_RECORD, &self.record(&record))
    }

    fn remove(&self, uid: u32, session_id: &str, force: bool) -> Result<MutationResponse> {
        let session_id = self.resolve_session_reference(uid, session_id)?;
        let record = self
            .manager
            .remove(uid, &session_id, force)
            .context(SessionSnafu)?;
        self.codex_app_server_service
            .unregister(&session_id)
            .map_err(|error| {
                crate::error::InvalidRequestSnafu {
                    reason: format!("removing the Codex App Server output ledger failed: {error}"),
                }
                .build()
            })?;
        message(KIND_SESSION_RECORD, &self.record(&record))
    }

    fn attach(
        &self,
        uid: u32,
        session_id: &str,
        request_input_lease: bool,
        client_instance_id: &str,
    ) -> Result<MutationResponse> {
        let session_id = self.resolve_session_reference(uid, session_id)?;
        let outcome = self
            .manager
            .attach(uid, &session_id, request_input_lease, client_instance_id)
            .context(SessionSnafu)?;
        let lease = outcome.lease();
        message(
            KIND_SESSION_ATTACH_RESPONSE,
            &SessionAttachResponse {
                session_id,
                read_only: lease.is_none(),
                input_lease_id: lease
                    .as_ref()
                    .map_or_else(String::new, |value| value.lease_id().to_owned()),
                input_lease_expires_unix_ms: lease
                    .as_ref()
                    .map_or(0, |value| value.expires_unix_ms()),
            },
        )
    }

    fn attach_codex_app_server(
        &self,
        uid: u32,
        session_id: &str,
        client_instance_id: &str,
    ) -> Result<MutationResponse> {
        let session_id = self.resolve_session_reference(uid, session_id)?;
        self.require_codex_app_server(uid, &session_id)?;
        let outcome = self
            .manager
            .attach_structured_input(uid, &session_id, client_instance_id)
            .context(SessionSnafu)?;
        let lease = outcome.lease();
        message(
            KIND_CODEX_APP_SERVER_ATTACH_RESPONSE,
            &CodexAppServerAttachResponse {
                session_id,
                read_only: lease.is_none(),
                input_lease_id: lease
                    .as_ref()
                    .map_or_else(String::new, |value| value.lease_id().to_owned()),
                input_lease_expires_unix_ms: lease
                    .as_ref()
                    .map_or(0, |value| value.expires_unix_ms()),
            },
        )
    }

    fn renew_lease(
        &self,
        uid: u32,
        session_id: &str,
        lease_id: &str,
        client_instance_id: &str,
    ) -> Result<MutationResponse> {
        let session_id = self.resolve_session_reference(uid, session_id)?;
        let lease = self
            .manager
            .renew_input_lease(uid, &session_id, lease_id, client_instance_id)
            .context(SessionSnafu)?;
        message(
            KIND_SESSION_INPUT_LEASE_RESPONSE,
            &SessionInputLeaseResponse {
                session_id,
                input_lease_id: lease.lease_id().to_owned(),
                expires_unix_ms: lease.expires_unix_ms(),
                released: false,
            },
        )
    }

    fn release_lease(
        &self,
        uid: u32,
        session_id: &str,
        lease_id: &str,
        client_instance_id: &str,
    ) -> Result<MutationResponse> {
        let session_id = self.resolve_session_reference(uid, session_id)?;
        self.manager
            .release_input_lease(uid, &session_id, lease_id, client_instance_id)
            .context(SessionSnafu)?;
        message(
            KIND_SESSION_INPUT_LEASE_RESPONSE,
            &SessionInputLeaseResponse {
                session_id,
                input_lease_id: lease_id.to_owned(),
                expires_unix_ms: 0,
                released: true,
            },
        )
    }

    pub(crate) fn input(
        &self,
        uid: u32,
        session_id: &str,
        lease_id: &str,
        client_instance_id: &str,
        data: &[u8],
    ) -> Result<SessionInputResponse> {
        let session_id = self.resolve_session_reference(uid, session_id)?;
        self.manager
            .write_input(uid, &session_id, lease_id, client_instance_id, data)
            .context(SessionSnafu)?;
        Ok(SessionInputResponse {
            session_id,
            accepted_bytes: u32::try_from(data.len()).map_err(|_error| {
                crate::error::InvalidRequestSnafu {
                    reason: String::from("interactive input chunk length is invalid"),
                }
                .build()
            })?,
        })
    }

    pub(crate) fn codex_app_server_input(
        &self,
        uid: u32,
        session_id: &str,
        lease_id: &str,
        client_instance_id: &str,
        frame: &[u8],
    ) -> Result<CodexAppServerInputResponse> {
        let session_id = self.resolve_session_reference(uid, session_id)?;
        self.require_codex_app_server(uid, &session_id)?;
        let input = self
            .codex_app_server_service
            .accept_input(&session_id, frame)
            .map_err(|error| {
                crate::error::InvalidRequestSnafu {
                    reason: format!("Codex App Server request is invalid: {error}"),
                }
                .build()
            })?;
        match input {
            erebor_runtime_session::CodexAppServerInput::Forward(frame) => {
                if let Err(error) = self.manager.write_structured_input(
                    uid,
                    &session_id,
                    lease_id,
                    client_instance_id,
                    &frame,
                ) {
                    let _result = self
                        .codex_app_server_service
                        .abort_input(&session_id, &frame);
                    return Err(error).context(SessionSnafu);
                }
                Ok(CodexAppServerInputResponse {
                    session_id,
                    accepted_bytes: u32::try_from(frame.len()).map_err(|_error| {
                        crate::error::InvalidRequestSnafu {
                            reason: String::from("Codex App Server frame length is invalid"),
                        }
                        .build()
                    })?,
                    synthetic_jsonl_response: Vec::new(),
                })
            }
            erebor_runtime_session::CodexAppServerInput::Deny(response) => {
                Ok(CodexAppServerInputResponse {
                    session_id,
                    accepted_bytes: 0,
                    synthetic_jsonl_response: response,
                })
            }
        }
    }

    pub(crate) fn close_codex_app_server_input(
        &self,
        uid: u32,
        session_id: &str,
        lease_id: &str,
        client_instance_id: &str,
    ) -> Result<CodexAppServerInputCloseResponse> {
        let session_id = self.resolve_session_reference(uid, session_id)?;
        self.require_codex_app_server(uid, &session_id)?;
        self.manager
            .close_structured_input(uid, &session_id, lease_id, client_instance_id)
            .context(SessionSnafu)?;
        Ok(CodexAppServerInputCloseResponse {
            session_id,
            closed: true,
        })
    }

    fn require_codex_app_server(&self, uid: u32, session_id: &str) -> Result<()> {
        let record = self
            .manager
            .inspect(uid, session_id)
            .context(SessionSnafu)?;
        if record.spec().tty() {
            return crate::error::InvalidRequestSnafu {
                reason: String::from("Codex App Server structured stdio cannot use a TTY session"),
            }
            .fail();
        }
        let admission = self.local_store.validate_session_spec(record.spec())?;
        if admission.package().adapter_id() != "codex-v1" {
            return crate::error::InvalidRequestSnafu {
                reason: String::from("session is not admitted through the Codex adapter"),
            }
            .fail();
        }
        let installation = self.local_store.resolve_codex_installation(
            uid,
            admission.package_digest(),
            admission.installation_digest(),
            Some("codex-app-server"),
        )?;
        let entrypoint = installation
            .package()
            .definition()
            .entrypoint(installation.entrypoint())
            .filter(|entrypoint| entrypoint.app_server_stdio())
            .ok_or_else(|| {
                crate::error::InvalidRequestSnafu {
                    reason: String::from(
                        "session installation does not certify Codex App Server stdio",
                    ),
                }
                .build()
            })?;
        let artifact = installation
            .installation()
            .local_artifact()
            .ok_or_else(|| {
                crate::error::InvalidRequestSnafu {
                    reason: String::from("Codex App Server installation has no local executable"),
                }
                .build()
            })?;
        let current = self.reverify_codex_artifact(uid, record.spec().owner().gid(), artifact)?;
        if record.spec().executable() != Some(&current) {
            return crate::error::InvalidRequestSnafu {
                reason: String::from(
                    "Codex App Server executable no longer matches its enrolled artifact",
                ),
            }
            .fail();
        }
        let mut expected_command = vec![artifact.path().display().to_string()];
        expected_command.extend(entrypoint.argv_suffix().iter().cloned());
        if record.spec().command() != expected_command {
            return crate::error::InvalidRequestSnafu {
                reason: String::from(
                    "session command does not match the certified Codex App Server entrypoint",
                ),
            }
            .fail();
        }
        Ok(())
    }

    fn is_codex_app_server(&self, uid: u32, session_id: &str) -> Result<bool> {
        let record = self
            .manager
            .inspect(uid, session_id)
            .context(SessionSnafu)?;
        if record.spec().tty() || record.spec().package().is_none() {
            return Ok(false);
        }
        let admission = self.local_store.validate_session_spec(record.spec())?;
        if admission.package().adapter_id() != "codex-v1" {
            return Ok(false);
        }
        let installation = self.local_store.resolve_codex_installation(
            uid,
            admission.package_digest(),
            admission.installation_digest(),
            Some("codex-app-server"),
        )?;
        let Some(entrypoint) = installation
            .package()
            .definition()
            .entrypoint(installation.entrypoint())
        else {
            return Ok(false);
        };
        if !entrypoint.app_server_stdio() {
            return Ok(false);
        }
        let artifact = installation
            .installation()
            .local_artifact()
            .ok_or_else(|| {
                crate::error::InvalidRequestSnafu {
                    reason: String::from("Codex App Server installation has no local executable"),
                }
                .build()
            })?;
        let mut expected_command = vec![artifact.path().display().to_string()];
        expected_command.extend(entrypoint.argv_suffix().iter().cloned());
        Ok(record.spec().command() == expected_command)
    }

    fn monitor_codex_app_server_output(&self, uid: u32, session_id: &str) -> Result<()> {
        if !self.is_codex_app_server(uid, session_id)? {
            return Ok(());
        }
        let monitor_key = format!("{uid}:{session_id}");
        let mut monitors = self
            .codex_app_server_output_monitors
            .lock()
            .map_err(|_error| crate::error::StateLockSnafu.build())?;
        if !monitors.insert(monitor_key.clone()) {
            return Ok(());
        }
        drop(monitors);
        let manager = Arc::clone(&self.manager);
        let service = Arc::clone(&self.codex_app_server_service);
        let monitors = Arc::clone(&self.codex_app_server_output_monitors);
        let session_id = session_id.to_owned();
        thread::Builder::new()
            .name(format!("erebor-codex-app-server-{session_id}"))
            .spawn(move || {
                let mut after_sequence = 0;
                loop {
                    let page = match manager.stream(
                        uid,
                        &session_id,
                        StreamKind::Stdout,
                        after_sequence,
                        256,
                    ) {
                        Ok(page) => page,
                        Err(_) => break,
                    };
                    let invalid_output = page.records().iter().any(|record| {
                        after_sequence = after_sequence.max(record.sequence());
                        service
                            .observe_output_chunk(&session_id, record.sequence(), record.data())
                            .is_err()
                    });
                    if invalid_output {
                        let _result = manager.kill(uid, &session_id, ActiveSessionSignal::Kill);
                        break;
                    }
                    match manager.inspect(uid, &session_id) {
                        Ok(record) if record.state().is_terminal() => break,
                        Ok(_) => thread::sleep(Duration::from_millis(50)),
                        Err(_) => break,
                    }
                }
                if let Ok(mut monitors) = monitors.lock() {
                    monitors.remove(&monitor_key);
                }
            })
            .map_err(|source| {
                crate::error::InvalidRequestSnafu {
                    reason: format!("starting Codex App Server output monitor failed: {source}"),
                }
                .build()
            })?;
        Ok(())
    }

    fn prune(
        &self,
        uid: u32,
        terminal_before_unix_ms: u64,
        maximum_sessions: u32,
    ) -> Result<MutationResponse> {
        let result = self
            .manager
            .prune(
                uid,
                terminal_before_unix_ms,
                maximum_sessions.max(1) as usize,
            )
            .context(SessionSnafu)?;
        for session_id in &result.pruned_session_ids {
            self.codex_app_server_service
                .unregister(session_id)
                .map_err(|error| crate::error::InvalidRequestSnafu {
                    reason: format!(
                        "pruning the Codex App Server output ledger for `{session_id}` failed: {error}"
                    ),
                }
                .build())?;
        }
        for record in self.manager.list(uid).context(SessionSnafu)? {
            if record.state() == SessionLifecycleState::Removed && !record.retains_content() {
                self.local_store
                    .release_session_lease(uid, record.spec().session_id().as_str())?;
            }
        }
        message(
            KIND_SESSION_PRUNE_RESPONSE,
            &SessionPruneResponse {
                pruned_sessions: result.pruned as u32,
                retained_session_ids: result.retained_session_ids,
            },
        )
    }

    fn set_alias(&self, uid: u32, alias: &str, session_id: &str) -> Result<MutationResponse> {
        let session_id = self.resolve_session_reference(uid, session_id)?;
        let alias = self
            .manager
            .set_alias(uid, alias, &session_id)
            .context(SessionSnafu)?;
        message(
            KIND_SESSION_ALIAS_RECORD,
            &SessionAliasRecord {
                alias: alias.alias().to_owned(),
                session_id: alias.session_id().to_owned(),
            },
        )
    }

    fn remove_alias(&self, uid: u32, alias: &str) -> Result<MutationResponse> {
        let alias = self
            .manager
            .remove_alias(uid, alias)
            .context(SessionSnafu)?;
        message(
            KIND_SESSION_ALIAS_RECORD,
            &SessionAliasRecord {
                alias: alias.alias().to_owned(),
                session_id: alias.session_id().to_owned(),
            },
        )
    }

    fn set_retention_hold(
        &self,
        uid: u32,
        session_id: &str,
        retention_hold: bool,
    ) -> Result<MutationResponse> {
        let session_id = self.resolve_session_reference(uid, session_id)?;
        let record = self
            .manager
            .set_retention_hold(uid, &session_id, retention_hold)
            .context(SessionSnafu)?;
        message(KIND_SESSION_RECORD, &self.record(&record))
    }

    fn record(&self, record: &DurableSessionRecord) -> SessionRecord {
        session_record(record, self.retry_expiration(record))
    }

    pub(crate) fn resolve_session_reference(&self, uid: u32, reference: &str) -> Result<String> {
        if reference.trim().is_empty() {
            return crate::error::InvalidRequestSnafu {
                reason: String::from("session reference must not be empty"),
            }
            .fail();
        }
        let sessions = self.manager.list(uid).context(SessionSnafu)?;
        if sessions
            .iter()
            .any(|record| record.spec().session_id().as_str() == reference)
        {
            return Ok(reference.to_owned());
        }
        if let Some(session_id) = self
            .manager
            .resolve_alias(uid, reference)
            .context(SessionSnafu)?
        {
            if sessions
                .iter()
                .any(|record| record.spec().session_id().as_str() == session_id)
            {
                return Ok(session_id);
            }
            return crate::error::InvalidRequestSnafu {
                reason: format!("session alias `{reference}` does not name a session"),
            }
            .fail();
        }
        Self::choose_session_id(
            reference,
            sessions
                .iter()
                .map(|record| record.spec().session_id().as_str()),
        )
    }

    fn choose_session_id<'a>(
        reference: &str,
        candidates: impl Iterator<Item = &'a str>,
    ) -> Result<String> {
        let candidates = candidates.collect::<Vec<_>>();
        if let Some(session_id) = candidates
            .iter()
            .find(|session_id| **session_id == reference)
        {
            return Ok((*session_id).to_owned());
        }
        let matches = candidates
            .into_iter()
            .filter(|session_id| session_id.starts_with(reference))
            .collect::<Vec<_>>();
        match matches.as_slice() {
            [session_id] => Ok((*session_id).to_owned()),
            [] => crate::error::InvalidRequestSnafu {
                reason: format!("no session owned by this UID matches `{reference}`"),
            }
            .fail(),
            _ => crate::error::InvalidRequestSnafu {
                reason: format!("session reference `{reference}` is ambiguous"),
            }
            .fail(),
        }
    }

    fn retry_expiration(&self, record: &DurableSessionRecord) -> u64 {
        if record.state() == erebor_runtime_core::SessionLifecycleState::Removed {
            record
                .updated_at_unix_ms()
                .saturating_add(self.retry_horizon.as_millis() as u64)
        } else {
            u64::MAX
        }
    }
}

fn message(kind: &str, value: &impl Message) -> Result<MutationResponse> {
    let mut payload = Vec::with_capacity(value.encoded_len());
    value
        .encode(&mut payload)
        .map_err(|source| crate::DaemonError::Ipc {
            source: erebor_runtime_ipc::IpcProtocolError::EncodePayload {
                source,
                location: snafu::Location::default(),
            },
            location: snafu::Location::default(),
        })?;
    Ok(MutationResponse {
        message_kind: kind.to_owned(),
        payload,
    })
}

#[cfg(test)]
mod tests {
    use super::DaemonSessionApi;

    #[test]
    fn session_reference_requires_an_exact_or_unique_owner_scoped_prefix(
    ) -> Result<(), crate::DaemonError> {
        let sessions = ["session-a111", "session-b222"];
        assert_eq!(
            DaemonSessionApi::choose_session_id("session-a", sessions.into_iter())?,
            "session-a111"
        );
        assert_eq!(
            DaemonSessionApi::choose_session_id("session-b222", sessions.into_iter())?,
            "session-b222"
        );
        assert!(DaemonSessionApi::choose_session_id("session", sessions.into_iter()).is_err());
        assert!(DaemonSessionApi::choose_session_id("session-z", sessions.into_iter()).is_err());
        Ok(())
    }
}
