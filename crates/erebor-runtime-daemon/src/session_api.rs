mod admission;
mod policy_router;
mod response;

use std::{path::PathBuf, sync::Arc, time::Duration};

use erebor_runtime_core::{
    ActiveSessionSignal, ImmutableIdentity, SessionLifecycleState, SessionOwner, SessionSpec,
};
use erebor_runtime_ipc::v1::{
    PolicyPackageRecord, PolicySetRecord, SessionAliasListResponse, SessionAliasRecord,
    SessionAttachResponse, SessionCreateRequest, SessionCreateResponse, SessionInputLeaseResponse,
    SessionListResponse, SessionPruneResponse, SessionRecord, KIND_POLICY_PACKAGE_RECORD,
    KIND_POLICY_SET_RECORD, KIND_SESSION_ALIAS_RECORD, KIND_SESSION_ATTACH_RESPONSE,
    KIND_SESSION_CREATE_RESPONSE, KIND_SESSION_INPUT_LEASE_RESPONSE, KIND_SESSION_PRUNE_RESPONSE,
    KIND_SESSION_RECORD,
};
use erebor_runtime_session::{
    AgentAdapterRegistry, DurableSessionRecord, RunnerAdmissionRequest, RunnerInstallConfig,
    RunnerRegistry, SessionManager, SessionManagerError, SessionRepository, SessionRepositoryError,
    SessionRuntimeResources, StreamKind, ValidatedStartConstraints,
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
}

impl DaemonSessionApi {
    pub(crate) fn installed(paths: &DaemonPaths, config: &DaemonConfig) -> Result<Self> {
        Self::new(
            paths,
            config,
            RunnerRegistry::compiled_linux_host(RunnerInstallConfig::default())
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
        let descriptor_broker = Arc::new(DescriptorBroker::installed());
        let local_store = Arc::new(DaemonLocalStore::installed(paths)?);
        let adapters = AgentAdapterRegistry::compiled().map_err(|error| {
            crate::error::InvalidRequestSnafu {
                reason: format!("compiling built-in adapter registry failed: {error}"),
            }
            .build()
        })?;
        local_store.seed_builtin_generic_content()?;
        local_store.seed_root_curated(config.root_curated_admissions())?;
        let runtime = SessionRuntimeResources::new(
            state_root.clone(),
            runtime_root.clone(),
            Arc::clone(&descriptor_broker) as Arc<dyn erebor_runtime_session::SessionPathResolver>,
            Arc::new(StoredPolicyInterceptionRouterFactory::new(Arc::clone(
                &local_store,
            ))),
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
        })
    }

    pub(crate) fn admit_request(
        &self,
        mut request: SessionCreateRequest,
        owner_uid: u32,
        owner_gid: u32,
        configuration_generation: u64,
        config: &DaemonConfig,
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
        let runner_admission = self
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
            },
        )?;
        self.manager
            .validate_admission(&spec)
            .context(SessionSnafu)?;
        Ok(spec)
    }

    pub(crate) fn seed_root_curated(&self, config: &DaemonConfig) -> Result<()> {
        self.local_store
            .seed_root_curated(config.root_curated_admissions())
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
        let active = self
            .manager
            .list(owner_uid)
            .context(SessionSnafu)?
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
            MutationIntent::PolicyPackageApply { uid, policy } => {
                self.store_policy_package(*uid, policy)
            }
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
            MutationIntent::Reload { .. }
            | MutationIntent::Stop
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

    fn store_policy_package(
        &self,
        owner_uid: u32,
        policy: &erebor_runtime_packages::PolicyPackageRevision,
    ) -> Result<MutationResponse> {
        let digest = self
            .local_store
            .store_user_policy_package(owner_uid, policy)?;
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
        self.manager
            .stream(uid, &session_id, kind, after_sequence, maximum_records)
            .context(SessionSnafu)
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
        self.manager.reconcile().context(SessionSnafu)
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
