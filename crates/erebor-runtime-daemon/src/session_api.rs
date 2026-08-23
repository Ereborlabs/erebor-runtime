mod admission;
mod filesystem;
mod policy_router;
mod response;

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use erebor_runtime_core::{
    ActiveSessionSignal, CallerHomeFilesystemSource, CallerHomeFilesystemSourceAccess,
    CallerHomeFilesystemSourceKind, CallerHomeFilesystemSourceView, EndpointProjection,
    FilesystemProjection, ImmutableIdentity, SafePathBinding, SafePathKind, SessionLifecycleState,
    SessionOwner, SessionResourceAssociation, SessionSpec, TerminalSize,
};
use erebor_runtime_ipc::v1::{
    AgentInstallResponse, CallerHomeFilesystemSource as IpcCallerHomeFilesystemSource,
    CodexAppServerAttachResponse, CodexAppServerInputCloseResponse, CodexAppServerInputResponse,
    CodexRunRequest, PolicyPackageRecord, PolicySetRecord, SessionAliasListResponse,
    SessionAliasRecord, SessionAttachResponse, SessionCreateRequest, SessionCreateResponse,
    SessionEnvironmentEntry, SessionInputLeaseResponse, SessionInputResponse, SessionListResponse,
    SessionPruneResponse, SessionRecord, SessionTerminalResizeResponse, SurfaceListResponse,
    SurfaceRecord,
};
use erebor_runtime_packages::{
    CodexHookContract, ContentDigest, LocalArtifactProvider, VerifiedLocalArtifact,
};
use erebor_runtime_session::{
    AgentAdapterRegistry, ChildContextDelivery, ChildContextDeliveryDispatcher,
    ChildContextDeliveryHandler, CodexAppServerService, CodexHookService, ContextAgentControl,
    ContextAgentControlDispatcher, ContextAgentControlHandler, ContextAgentControlResult,
    ContextOperationAdmission, ContextOperationAdmissionDispatcher,
    ContextOperationAdmissionHandler, DurableSessionRecord, RunnerAdmissionRequest, RunnerRegistry,
    SessionManager, SessionManagerError, SessionRepository, SessionRepositoryError,
    SessionRuntimeResources, StreamKind, ValidatedStartConstraints,
};
use prost::Message;
use sha2::{Digest, Sha256};
use snafu::ResultExt;
use users::os::unix::UserExt;
use uuid::Uuid;

use crate::{
    config::DaemonConfig,
    context_dag::{
        delivery::{
            ContextDeliveryKind, ContextDeliveryMode, ContextDeliveryPublication,
            ContextDeliveryReceipt, ContextDeliveryRecord,
        },
        ContextChildForkRequest, ContextDagCoordinator, ContextExecutionBinding,
        ContextScopeGraphActivity, ContextScopeGraphNode, SessionContextResolver,
    },
    error::SessionSnafu,
    idempotency::{MutationIntent, MutationResponse, MutationResponseType},
    local_store::{DaemonLocalStore, StaticSessionAdmission, StoredStaticSession},
    path_broker::DescriptorBroker,
    runtime_interception::host::RuntimeKernelInterceptionOwner,
    DaemonPaths, Result,
};

use self::{
    admission::{admit, parse_request, AdmissionContext, AdmissionIdentity},
    policy_router::StoredPolicyInterceptionRouterFactory,
    response::session_record,
};

pub(crate) struct DaemonSessionApi {
    manager: Arc<SessionManager>,
    state_root: PathBuf,
    retry_horizon: Duration,
    descriptor_broker: Arc<DescriptorBroker>,
    local_store: Arc<DaemonLocalStore>,
    adapters: AgentAdapterRegistry,
    codex_hook_service: Arc<CodexHookService>,
    codex_app_server_service: Arc<CodexAppServerService>,
    child_deliveries: Arc<ChildContextDeliveryDispatcher>,
    agent_controls: Arc<ContextAgentControlDispatcher>,
    operation_admissions: Arc<ContextOperationAdmissionDispatcher>,
    context_resolver: Arc<SessionContextResolver>,
    context_coordinators: Arc<Mutex<BTreeMap<String, Arc<ContextDagCoordinator>>>>,
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
        let kernel_interception = match config.linux_runner().interceptor() {
            Some(interceptor) => Some(Arc::new(
                RuntimeKernelInterceptionOwner::start(interceptor, &state_root).map_err(
                    |error| {
                        crate::error::InvalidRequestSnafu {
                            reason: format!(
                                "starting the daemon-owned Runtime Interceptor failed: {error}"
                            ),
                        }
                        .build()
                    },
                )?,
            )),
            None => {
                RuntimeKernelInterceptionOwner::require_disabled_safe(&state_root).map_err(
                    |error| {
                        crate::error::InvalidRequestSnafu {
                            reason: format!(
                                "the daemon-owned Runtime Interceptor cannot remain disabled: {error}"
                            ),
                        }
                        .build()
                    },
                )?;
                None
            }
        };
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
        let child_deliveries = Arc::new(ChildContextDeliveryDispatcher::default());
        let agent_controls = Arc::new(ContextAgentControlDispatcher::default());
        let operation_admissions = Arc::new(ContextOperationAdmissionDispatcher::default());
        let context_resolver = Arc::new(SessionContextResolver::new(state_root.clone()));
        let runtime = SessionRuntimeResources::new(
            state_root.clone(),
            runtime_root.clone(),
            Arc::clone(&descriptor_broker) as Arc<dyn erebor_runtime_session::SessionPathResolver>,
            Arc::new(
                StoredPolicyInterceptionRouterFactory::new(
                    Arc::clone(&local_store),
                    Arc::clone(&codex_hook_service),
                    Arc::clone(&codex_app_server_service),
                    Arc::clone(&context_resolver),
                    Arc::clone(&child_deliveries) as Arc<dyn ChildContextDeliveryHandler>,
                    Arc::clone(&agent_controls) as Arc<dyn ContextAgentControlHandler>,
                    Arc::clone(&operation_admissions) as Arc<dyn ContextOperationAdmissionHandler>,
                )
                .with_kernel_interception(kernel_interception),
            ),
        )
        .context(SessionSnafu)?;
        Ok(Self {
            manager: Arc::new(SessionManager::new(
                SessionRepository::new(&state_root),
                runners,
                runtime,
            )),
            state_root,
            retry_horizon: Duration::from_secs(config.session_retry_horizon_seconds),
            descriptor_broker,
            local_store,
            adapters,
            codex_hook_service,
            codex_app_server_service,
            child_deliveries,
            agent_controls,
            operation_admissions,
            context_resolver,
            context_coordinators: Arc::new(Mutex::new(BTreeMap::new())),
            codex_app_server_output_monitors: Arc::new(Mutex::new(BTreeSet::new())),
        })
    }

    pub(crate) fn shutdown(&self) -> Result<()> {
        self.manager.shutdown().context(SessionSnafu)
    }

    pub(crate) fn bind_child_delivery_handler(
        &self,
        handler: Arc<dyn ChildContextDeliveryHandler>,
    ) -> Result<()> {
        self.child_deliveries.install(handler).map_err(|reason| {
            crate::error::InvalidRequestSnafu {
                reason: format!("binding daemon child delivery handler failed: {reason}"),
            }
            .build()
        })
    }

    pub(crate) fn bind_agent_control_handler(
        &self,
        handler: Arc<dyn ContextAgentControlHandler>,
    ) -> Result<()> {
        self.agent_controls.install(handler).map_err(|reason| {
            crate::error::InvalidRequestSnafu {
                reason: format!("binding daemon context-agent-control handler failed: {reason}"),
            }
            .build()
        })
    }

    pub(crate) fn bind_operation_admission_handler(
        &self,
        handler: Arc<dyn ContextOperationAdmissionHandler>,
    ) -> Result<()> {
        self.operation_admissions
            .install(handler)
            .map_err(|reason| {
                crate::error::InvalidRequestSnafu {
                    reason: format!("binding daemon context-operation handler failed: {reason}"),
                }
                .build()
            })
    }

    pub(crate) fn publish_child_delivery(&self, delivery: ChildContextDelivery) -> Result<()> {
        let record = self
            .manager
            .list_all()
            .context(SessionSnafu)?
            .into_iter()
            .find(|record| record.spec().session_id().as_str() == delivery.source_session_id())
            .ok_or_else(|| {
                crate::error::InvalidRequestSnafu {
                    reason: String::from("child delivery session no longer exists"),
                }
                .build()
            })?;
        if record.state() != SessionLifecycleState::Running {
            return crate::error::InvalidRequestSnafu {
                reason: String::from("authenticated child delivery requires a running session"),
            }
            .fail();
        }
        let child_spec = record.spec();
        let child_scope = delivery
            .source_scope()
            .cloned()
            .map_or_else(
                || erebor_runtime_context::ScopeRef::root(child_spec.session_id().as_str()),
                Ok,
            )
            .map_err(|error| {
                crate::error::InvalidRequestSnafu {
                    reason: format!("could not resolve child delivery scope: {error}"),
                }
                .build()
            })?;
        if child_scope.session_id() != child_spec.session_id().as_str() {
            return crate::error::InvalidRequestSnafu {
                reason: String::from(
                    "authenticated delivery source scope does not belong to its session",
                ),
            }
            .fail();
        }
        let kind = match delivery.kind() {
            "message" => ContextDeliveryKind::Message,
            "result" => ContextDeliveryKind::Result,
            "failure" => ContextDeliveryKind::Failure,
            "cancelled" => ContextDeliveryKind::Cancelled,
            _ => {
                return crate::error::InvalidRequestSnafu {
                    reason: String::from("child delivery kind is not supported"),
                }
                .fail()
            }
        };
        let mode = match delivery.mode() {
            "queue" => ContextDeliveryMode::Queue,
            "follow-up" => ContextDeliveryMode::FollowUp,
            _ => {
                return crate::error::InvalidRequestSnafu {
                    reason: String::from("child delivery mode is not supported"),
                }
                .fail()
            }
        };
        let publication = ContextDeliveryPublication::new(
            child_scope,
            delivery.sequence(),
            kind,
            mode,
            delivery.selected_bytes().to_vec(),
        )?;
        self.context_coordinator(child_spec)?
            .publish_delivery(publication)?;
        Ok(())
    }

    pub(crate) fn handle_agent_control(
        &self,
        control: ContextAgentControl,
    ) -> Result<ContextAgentControlResult> {
        let record = self
            .manager
            .list_all()
            .context(SessionSnafu)?
            .into_iter()
            .find(|record| record.spec().session_id().as_str() == control.session_id())
            .ok_or_else(|| {
                crate::error::InvalidRequestSnafu {
                    reason: String::from("context agent control session no longer exists"),
                }
                .build()
            })?;
        if record.state() != SessionLifecycleState::Running {
            return crate::error::InvalidRequestSnafu {
                reason: String::from(
                    "authenticated context agent control requires a running session",
                ),
            }
            .fail();
        }
        let spec = record.spec();
        if self
            .local_store
            .validate_session_spec(spec)?
            .package()
            .adapter_id()
            != "codex-v1"
        {
            return crate::error::InvalidRequestSnafu {
                reason: String::from("only a certified Codex session may use context controls"),
            }
            .fail();
        }
        self.context_coordinator(spec)?
            .authorize_agent_control(control)
    }

    pub(crate) fn admit_context_operation(
        &self,
        admission: ContextOperationAdmission,
    ) -> Result<erebor_runtime_context::ScopeRef> {
        let parent = self
            .manager
            .list_all()
            .context(SessionSnafu)?
            .into_iter()
            .find(|record| record.spec().session_id().as_str() == admission.session_id())
            .ok_or_else(|| {
                crate::error::InvalidRequestSnafu {
                    reason: String::from("context operation session no longer exists"),
                }
                .build()
            })?;
        if parent.state() != SessionLifecycleState::Running {
            return crate::error::InvalidRequestSnafu {
                reason: String::from("authenticated context operation requires a running session"),
            }
            .fail();
        }
        let parent_spec = parent.spec();
        let parent_admission = self.local_store.validate_session_spec(parent_spec)?;
        if parent_admission.package().adapter_id() != "codex-v1" {
            return crate::error::InvalidRequestSnafu {
                reason: String::from("only a certified Codex session may admit an operation"),
            }
            .fail();
        }
        let key = admission.operation_key();
        if key.is_empty()
            || key.len() > 128
            || !key
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        {
            return crate::error::InvalidRequestSnafu {
                reason: String::from("context operation key must be a bounded ASCII identifier"),
            }
            .fail();
        }
        let parent_scope = admission.parent_context().scope().map_err(|error| {
            crate::error::InvalidRequestSnafu {
                reason: format!("context operation parent scope is invalid: {error}"),
            }
            .build()
        })?;
        if parent_scope.session_id() != parent_spec.session_id().as_str() {
            return crate::error::InvalidRequestSnafu {
                reason: String::from(
                    "context operation parent pin does not belong to its authenticated session",
                ),
            }
            .fail();
        }
        let digest = format!("{:x}", Sha256::digest(key.as_bytes()));
        let child_scope = erebor_runtime_context::ScopeRef::scope(
            parent_spec.session_id().as_str(),
            format!("codex-operation-{}", &digest[..20]),
        )
        .map_err(|error| {
            crate::error::InvalidRequestSnafu {
                reason: format!("could not construct context operation scope: {error}"),
            }
            .build()
        })?;
        let mut context_fork = ContextChildForkRequest::new(
            admission.parent_context().clone(),
            child_scope.clone(),
            ContextExecutionBinding::NativeLogical,
            Some(if admission.selects_parent_context() {
                format!("codex-v1:logical-fork:{key}")
            } else {
                format!("codex-v1:operation:{key}")
            }),
            admission.source_tool_use_id().map(ToOwned::to_owned),
        )?;
        if admission.selects_parent_context() {
            context_fork.select_parent_context();
        }
        self.context_coordinator(parent_spec)?
            .admit_child(context_fork)?;
        Ok(child_scope)
    }

    pub(crate) fn context_delivery_inbox(
        &self,
        owner_uid: u32,
        parent_session_id: &str,
    ) -> Result<Vec<ContextDeliveryRecord>> {
        let parent_session_id = self.resolve_session_reference(owner_uid, parent_session_id)?;
        let parent = self
            .manager
            .inspect(owner_uid, &parent_session_id)
            .context(SessionSnafu)?;
        self.context_coordinator(parent.spec())?
            .inbox_for_session(parent.spec().session_id().as_str())
    }

    pub(crate) fn context_graph(
        &self,
        owner_uid: u32,
        session_id: &str,
    ) -> Result<(
        erebor_runtime_context::ScopeRef,
        Vec<ContextScopeGraphNode>,
        Vec<ContextScopeGraphActivity>,
    )> {
        let session_id = self.resolve_session_reference(owner_uid, session_id)?;
        let session = self
            .manager
            .inspect(owner_uid, &session_id)
            .context(SessionSnafu)?;
        let coordinator = self.context_coordinator(session.spec())?;
        let root_scope = coordinator.root_scope.clone();
        let (nodes, activities) = coordinator.graph()?;
        Ok((root_scope, nodes, activities))
    }

    pub(crate) fn receive_context_delivery(
        &self,
        owner_uid: u32,
        parent_session_id: &str,
        delivery_path: &str,
        delivery_commit: &str,
        expected_parent_head: &str,
    ) -> Result<ContextDeliveryReceipt> {
        self.decide_context_delivery(
            owner_uid,
            parent_session_id,
            delivery_path,
            delivery_commit,
            expected_parent_head,
            None,
        )
    }

    pub(crate) fn reject_context_delivery(
        &self,
        owner_uid: u32,
        parent_session_id: &str,
        delivery_path: &str,
        delivery_commit: &str,
        expected_parent_head: &str,
        reason: &str,
    ) -> Result<ContextDeliveryReceipt> {
        self.decide_context_delivery(
            owner_uid,
            parent_session_id,
            delivery_path,
            delivery_commit,
            expected_parent_head,
            Some(reason),
        )
    }

    fn decide_context_delivery(
        &self,
        owner_uid: u32,
        parent_session_id: &str,
        delivery_path: &str,
        delivery_commit: &str,
        expected_parent_head: &str,
        rejection_reason: Option<&str>,
    ) -> Result<ContextDeliveryReceipt> {
        use std::str::FromStr;

        let parent_session_id = self.resolve_session_reference(owner_uid, parent_session_id)?;
        let parent = self
            .manager
            .inspect(owner_uid, &parent_session_id)
            .context(SessionSnafu)?;
        let coordinator = self.context_coordinator(parent.spec())?;
        let delivery_commit = erebor_runtime_context::ContextObjectId::from_str(delivery_commit)
            .map_err(|error| {
                crate::error::InvalidRequestSnafu {
                    reason: format!("delivery commit is invalid: {error}"),
                }
                .build()
            })?;
        let expected_parent_head = erebor_runtime_context::ContextObjectId::from_str(
            expected_parent_head,
        )
        .map_err(|error| {
            crate::error::InvalidRequestSnafu {
                reason: format!("expected parent head is invalid: {error}"),
            }
            .build()
        })?;
        let receiver = coordinator.delivery_receiver(delivery_path, delivery_commit)?;
        if receiver.session_id() != parent.spec().session_id().as_str() {
            return crate::error::InvalidRequestSnafu {
                reason: String::from("only the delivery's direct parent session may decide it"),
            }
            .fail();
        }
        rejection_reason.map_or_else(
            || {
                coordinator.receive_delivery(
                    &receiver,
                    delivery_path,
                    delivery_commit,
                    expected_parent_head,
                )
            },
            |reason| {
                coordinator.reject_delivery(
                    &receiver,
                    delivery_path,
                    delivery_commit,
                    expected_parent_head,
                    reason,
                )
            },
        )
    }

    pub(crate) fn admit_request(
        &self,
        request: SessionCreateRequest,
        owner_uid: u32,
        owner_gid: u32,
        configuration_generation: u64,
        config: &DaemonConfig,
    ) -> Result<SessionSpec> {
        let builtin = self.local_store.ensure_builtin_admission(owner_uid)?;
        self.admit_request_with_adapter(
            request,
            AdmissionIdentity {
                package_digest: builtin.package_digest().to_owned(),
                installation_digest: builtin.installation_digest().to_owned(),
                adapter_digest: builtin.adapter_digest().to_owned(),
                policy_set_digest: builtin.policy_set_digest().to_owned(),
            },
            owner_uid,
            owner_gid,
            configuration_generation,
            config,
            false,
            false,
        )
    }

    pub(crate) fn admits_static_association(request: &SessionCreateRequest) -> bool {
        !request.agent_name.is_empty()
            || !request.policy_set_name.is_empty()
            || !request.surface_names.is_empty()
    }

    pub(crate) fn admit_static_session(
        &self,
        request: SessionCreateRequest,
        owner_uid: u32,
    ) -> Result<StaticSessionAdmission> {
        if !Self::admits_static_association(&request) {
            return crate::error::InvalidRequestSnafu {
                reason: String::from("Session static admission requires an Agent and PolicySet"),
            }
            .fail();
        }
        if !request.runner_id.is_empty()
            || !request.command.is_empty()
            || !request.workspace.is_empty()
            || !request.daemon_failure_mode.is_empty()
            || request.requested_loss_grace_seconds != 0
            || !request.environment.is_empty()
            || !request.secret_references.is_empty()
            || request.tty
            || request.detached
            || request.terminal_rows != 0
            || request.terminal_columns != 0
            || !request.caller_home_sources.is_empty()
        {
            return crate::error::InvalidRequestSnafu {
                reason: String::from(
                    "Session static admission accepts only Agent, PolicySet, and named Surface references",
                ),
            }
            .fail();
        }
        let session_name = format!("session-{}", Uuid::new_v4());
        let admission = self.local_store.prepare_static_session_admission(
            owner_uid,
            &session_name,
            &request.agent_name,
            &request.policy_set_name,
            &request.surface_names,
        )?;
        if self
            .adapters
            .descriptor(admission.agent_adapter())
            .is_none()
        {
            return crate::error::InvalidRequestSnafu {
                reason: format!(
                    "Agent `{}` selects unknown compiled adapter `{}`",
                    request.agent_name,
                    admission.agent_adapter()
                ),
            }
            .fail();
        }
        Ok(admission)
    }

    #[allow(clippy::too_many_arguments)]
    fn admit_request_with_adapter(
        &self,
        request: SessionCreateRequest,
        identity: AdmissionIdentity,
        owner_uid: u32,
        owner_gid: u32,
        configuration_generation: u64,
        config: &DaemonConfig,
        allow_codex_adapter: bool,
        private_state_projection: bool,
    ) -> Result<SessionSpec> {
        self.admit_request_with_adapter_and_parent(
            request,
            identity,
            owner_uid,
            owner_gid,
            configuration_generation,
            config,
            allow_codex_adapter,
            private_state_projection,
            None,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn admit_request_with_adapter_and_parent(
        &self,
        request: SessionCreateRequest,
        identity: AdmissionIdentity,
        owner_uid: u32,
        owner_gid: u32,
        configuration_generation: u64,
        config: &DaemonConfig,
        allow_codex_adapter: bool,
        private_state_projection: bool,
        parent_context: Option<erebor_runtime_context::ContextPin>,
    ) -> Result<SessionSpec> {
        let session_id = format!("session-{}", Uuid::new_v4());
        let resource_association = match (
            request.agent_name.is_empty(),
            request.policy_set_name.is_empty(),
        ) {
            (true, true) if request.surface_names.is_empty() => None,
            (false, false) => Some(
                SessionResourceAssociation::new(
                    request.agent_name.clone(),
                    request.policy_set_name.clone(),
                    request.surface_names.clone(),
                )
                .map_err(|error: erebor_runtime_core::SessionSpecError| {
                    crate::error::InvalidRequestSnafu {
                        reason: error.to_string(),
                    }
                    .build()
                })?,
            ),
            _ => {
                return crate::error::InvalidRequestSnafu {
                    reason: String::from(
                        "runtime Session association requires both Agent and PolicySet names",
                    ),
                }
                .fail()
            }
        };
        let source_view = Self::caller_home_source_view(&request.caller_home_sources)?;
        let request = parse_request(request, identity)?;
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
                ),
                self.descriptor_broker.as_ref(),
            )
            .context(SessionSnafu)?;
        let mut additional_filesystem_projections = self.caller_home_source_projections(
            owner_uid,
            owner_gid,
            source_view.as_ref(),
            request.workspace(),
        )?;
        if allow_codex_adapter {
            let package_digest = request.package_sha256().ok_or_else(|| {
                crate::error::InvalidRequestSnafu {
                    reason: String::from("Codex admission requires a package digest"),
                }
                .build()
            })?;
            let projections = self.codex_managed_artifact_projections(
                owner_uid,
                owner_gid,
                package_digest,
                config,
            )?;
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
            additional_filesystem_projections.extend(projections);
        }
        let spec = admit(
            request,
            AdmissionContext {
                owner,
                session_id: &session_id,
                parent_context,
                root_configuration_generation: configuration_generation,
                state_root: &self.state_root,
                capability,
                runner_admission,
                adapters: &self.adapters,
                local_store: self.local_store.as_ref(),
                config,
                allow_codex_adapter,
                private_state_projection,
                resource_association,
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
        package_name: &str,
        adapter: &str,
        source_path: &Path,
        owner_uid: u32,
        owner_gid: u32,
    ) -> Result<VerifiedCodexInstallation> {
        let package = self.local_store.resolve_codex_package_name(package_name)?;
        if package.package().adapter_id() != adapter {
            return crate::error::InvalidRequestSnafu {
                reason: String::from(
                    "the requested Agent adapter does not match the selected root-curated package",
                ),
            }
            .fail();
        }
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
        let installation = self.local_store.resolve_codex_agent(
            owner_uid,
            &request.agent_name,
            if request.app_server {
                "codex-app-server"
            } else {
                "codex"
            },
        )?;
        let definition = installation.package().definition();
        let source_view = Self::caller_home_source_view(&request.caller_home_sources)?;
        let environment = Self::codex_session_environment(
            definition.hook_contract(),
            source_view.as_ref(),
            owner_uid,
            &request.environment,
        )?;
        let artifact = installation
            .installation()
            .local_artifact()
            .ok_or_else(|| {
                crate::error::InvalidRequestSnafu {
                    reason: String::from(
                        "named Codex Agent has no descriptor-verified local artifact",
                    ),
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
                        "named Codex Agent does not certify the requested entrypoint",
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
            .resolve_policy_set_name(owner_uid, &request.policy_set_name)?;
        let spec = self.admit_request_with_adapter(
            SessionCreateRequest {
                runner_id: String::from("linux-host"),
                command,
                workspace: request.workspace,
                daemon_failure_mode: request.daemon_failure_mode,
                requested_loss_grace_seconds: request.requested_loss_grace_seconds,
                environment,
                secret_references: Vec::new(),
                tty: request.tty,
                detached: request.detached,
                terminal_rows: request.terminal_rows,
                terminal_columns: request.terminal_columns,
                agent_name: request.agent_name,
                policy_set_name: request.policy_set_name,
                surface_names: Vec::new(),
                caller_home_sources: request.caller_home_sources,
            },
            AdmissionIdentity {
                package_digest: installation.package().package_digest().to_owned(),
                installation_digest: installation.installation_digest().to_owned(),
                adapter_digest: installation
                    .package()
                    .package()
                    .adapter_digest()
                    .as_str()
                    .to_owned(),
                policy_set_digest: policy_set_digest.as_str().to_owned(),
            },
            owner_uid,
            owner_gid,
            configuration_generation,
            config,
            true,
            source_view.is_none(),
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
        agent_name: &str,
        package_digest: &str,
        artifact: VerifiedLocalArtifact,
        installed_at_unix_ms: u64,
    ) -> Result<AgentInstallResponse> {
        let _installation = self.local_store.store_codex_installation(
            owner_uid,
            agent_name,
            package_digest,
            installed_at_unix_ms,
            artifact,
        )?;
        Ok(AgentInstallResponse {
            name: agent_name.to_owned(),
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

    fn codex_managed_artifact_projections(
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
        let artifacts = sources
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
                Self::codex_artifact_projection(binding.clone(), target)
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(artifacts)
    }

    fn caller_home_source_projections(
        &self,
        owner_uid: u32,
        owner_gid: u32,
        source_view: Option<&CallerHomeFilesystemSourceView>,
        workspace: &Path,
    ) -> Result<Vec<FilesystemProjection>> {
        let Some(source_view) = source_view else {
            return Ok(Vec::new());
        };
        let home = Self::caller_home(owner_uid)?;
        let workspace_is_declared = source_view.sources().iter().any(|source| {
            source.kind() == CallerHomeFilesystemSourceKind::Directory
                && !source.access().read_only()
                && workspace.starts_with(home.join(source.relative_path()))
        });
        if !workspace_is_declared {
            return crate::error::InvalidRequestSnafu {
                reason: format!(
                    "workspace `{}` is not inside a declared writable caller-home source",
                    workspace.display()
                ),
            }
            .fail();
        }
        source_view
            .sources()
            .iter()
            .map(|source| {
                let source_path = home.join(source.relative_path());
                let kind = match source.kind() {
                    CallerHomeFilesystemSourceKind::File => SafePathKind::File,
                    CallerHomeFilesystemSourceKind::Directory => SafePathKind::Directory,
                };
                let resolved =
                    self.descriptor_broker
                        .resolve(owner_uid, owner_gid, &source_path, kind)?;
                let binding = resolved.binding();
                if binding.owner_uid() != owner_uid {
                    return crate::error::InvalidRequestSnafu {
                        reason: format!(
                            "caller-home source `{}` is not owned by the calling UID",
                            source_path.display()
                        ),
                    }
                    .fail();
                }
                FilesystemProjection::session_view(
                    binding.clone(),
                    source_path,
                    source.access().read_only(),
                    home.clone(),
                )
                .map_err(|error| {
                    crate::error::InvalidRequestSnafu {
                        reason: error.to_string(),
                    }
                    .build()
                })
            })
            .collect()
    }

    fn caller_home(owner_uid: u32) -> Result<PathBuf> {
        let home = users::get_user_by_uid(owner_uid)
            .map(|user| user.home_dir().to_path_buf())
            .ok_or_else(|| {
                crate::error::InvalidRequestSnafu {
                    reason: format!("could not resolve a home directory for UID {owner_uid}"),
                }
                .build()
            })?;
        let metadata = fs::symlink_metadata(&home).context(crate::error::IoSnafu {
            action: "checking caller home source root",
            path: home.clone(),
        })?;
        if !home.is_absolute() || metadata.file_type().is_symlink() || !metadata.is_dir() {
            return crate::error::InvalidRequestSnafu {
                reason: format!(
                    "caller home must be a non-symlink directory, found `{}`",
                    home.display()
                ),
            }
            .fail();
        }
        Ok(home)
    }

    fn codex_artifact_projection(
        source: SafePathBinding,
        target: &Path,
    ) -> Result<FilesystemProjection> {
        let projection = match target {
            path if path == Path::new("/etc/codex/requirements.toml") => {
                FilesystemProjection::session_overlay(
                    source,
                    target.to_path_buf(),
                    true,
                    PathBuf::from("/etc"),
                )
            }
            path if path == Path::new("/usr/lib/erebor/codex-hooks/erebor-codex-hook")
                || path == Path::new("/usr/lib/erebor/codex-hooks/shell-startup") =>
            {
                FilesystemProjection::session_overlay(
                    source,
                    target.to_path_buf(),
                    true,
                    PathBuf::from("/usr/lib"),
                )
            }
            path if path.starts_with("/run/erebor") => {
                FilesystemProjection::new(source, target.to_path_buf(), true)
            }
            _path => {
                return crate::error::InvalidRequestSnafu {
                    reason: format!(
                        "Codex managed artifact target `{}` is not an admitted private-runtime or session-overlay target",
                        target.display()
                    ),
                }
                .fail();
            }
        };
        projection.map_err(|error| {
            crate::error::InvalidRequestSnafu {
                reason: error.to_string(),
            }
            .build()
        })
    }

    fn codex_hook_shell_environment(contract: &CodexHookContract) -> Vec<SessionEnvironmentEntry> {
        contract.shell_executable().map_or_else(Vec::new, |shell| {
            vec![SessionEnvironmentEntry {
                key: String::from("SHELL"),
                value: shell.display().to_string(),
            }]
        })
    }

    fn codex_session_environment(
        contract: &CodexHookContract,
        source_view: Option<&CallerHomeFilesystemSourceView>,
        owner_uid: u32,
        client_environment: &[SessionEnvironmentEntry],
    ) -> Result<Vec<SessionEnvironmentEntry>> {
        let mut environment = Self::codex_hook_shell_environment(contract);
        let Some(source_view) = source_view else {
            return Ok(environment);
        };
        let path = Self::codex_client_path(client_environment)?;
        let home = Self::caller_home(owner_uid)?;
        environment.extend([
            SessionEnvironmentEntry {
                key: String::from("HOME"),
                value: home.display().to_string(),
            },
            SessionEnvironmentEntry {
                key: String::from("PATH"),
                value: path,
            },
        ]);
        if source_view.includes_file(Path::new(".bashrc")) {
            environment.push(SessionEnvironmentEntry {
                key: String::from("BASH_ENV"),
                value: home.join(".bashrc").display().to_string(),
            });
        }
        Ok(environment)
    }

    fn caller_home_source_view(
        sources: &[IpcCallerHomeFilesystemSource],
    ) -> Result<Option<CallerHomeFilesystemSourceView>> {
        if sources.is_empty() {
            return Ok(None);
        }
        let sources = sources
            .iter()
            .map(|source| {
                let kind = match source.kind.as_str() {
                    "file" => CallerHomeFilesystemSourceKind::File,
                    "directory" => CallerHomeFilesystemSourceKind::Directory,
                    _ => {
                        return crate::error::InvalidRequestSnafu {
                            reason: format!(
                                "caller-home source `{}` has unsupported kind `{}`",
                                source.relative_path, source.kind
                            ),
                        }
                        .fail()
                    }
                };
                let access = match source.access.as_str() {
                    "read_only" => CallerHomeFilesystemSourceAccess::ReadOnly,
                    "read_write" => CallerHomeFilesystemSourceAccess::ReadWrite,
                    _ => {
                        return crate::error::InvalidRequestSnafu {
                            reason: format!(
                                "caller-home source `{}` has unsupported access `{}`",
                                source.relative_path, source.access
                            ),
                        }
                        .fail()
                    }
                };
                CallerHomeFilesystemSource::new(PathBuf::from(&source.relative_path), kind, access)
                    .map_err(|error| {
                        crate::error::InvalidRequestSnafu {
                            reason: format!("invalid caller-home source: {error}"),
                        }
                        .build()
                    })
            })
            .collect::<Result<Vec<_>>>()?;
        CallerHomeFilesystemSourceView::new(sources)
            .map(Some)
            .map_err(|error| {
                crate::error::InvalidRequestSnafu {
                    reason: format!("invalid caller-home source view: {error}"),
                }
                .build()
            })
    }

    fn codex_client_path(client_environment: &[SessionEnvironmentEntry]) -> Result<String> {
        let Some(entry) = client_environment.first() else {
            return crate::error::InvalidRequestSnafu {
                reason: String::from(
                    "a caller-home Codex source view requires the client's non-empty PATH",
                ),
            }
            .fail();
        };
        if client_environment.len() != 1
            || entry.key != "PATH"
            || entry.value.is_empty()
            || entry.value.contains('\0')
        {
            return crate::error::InvalidRequestSnafu {
                reason: String::from(
                    "Codex accepts only one non-empty PATH environment entry from the client",
                ),
            }
            .fail();
        }
        Ok(entry.value.clone())
    }

    fn context_coordinator(&self, parent: &SessionSpec) -> Result<Arc<ContextDagCoordinator>> {
        let root_scope = self.root_context_scope(parent)?;
        let root_session_id = root_scope.session_id().to_owned();
        let mut coordinators = self.context_coordinators.lock().map_err(|_error| {
            crate::error::InvalidRequestSnafu {
                reason: String::from("context DAG coordinator state is unavailable"),
            }
            .build()
        })?;
        if let Some(coordinator) = coordinators.get(&root_session_id) {
            return Ok(Arc::clone(coordinator));
        }
        let coordinator = Arc::new(ContextDagCoordinator::new(
            self.context_resolver.resolve(parent)?,
            root_scope,
        )?);
        coordinators.insert(root_session_id, Arc::clone(&coordinator));
        Ok(coordinator)
    }

    fn root_context_scope(&self, parent: &SessionSpec) -> Result<erebor_runtime_context::ScopeRef> {
        let mut current = parent.clone();
        let mut visited = BTreeSet::new();
        loop {
            let current_id = current.session_id().as_str().to_owned();
            if !visited.insert(current_id.clone()) {
                return crate::error::InvalidRequestSnafu {
                    reason: format!("context parent chain contains session `{current_id}` twice"),
                }
                .fail();
            }
            let Some(parent_context) = current.parent_context() else {
                return erebor_runtime_context::ScopeRef::root(current.session_id().as_str())
                    .map_err(|error| {
                        crate::error::InvalidRequestSnafu {
                            reason: format!("could not resolve root context scope: {error}"),
                        }
                        .build()
                    });
            };
            let parent_scope = parent_context.scope().map_err(|error| {
                crate::error::InvalidRequestSnafu {
                    reason: format!("session context parent scope is invalid: {error}"),
                }
                .build()
            })?;
            let record = self
                .manager
                .inspect(current.owner().uid(), parent_scope.session_id())
                .context(SessionSnafu)?;
            if record.spec().owner().uid() != current.owner().uid() {
                return crate::error::InvalidRequestSnafu {
                    reason: String::from("context parent crosses session owner identities"),
                }
                .fail();
            }
            current = record.spec().clone();
        }
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
            MutationIntent::StaticSessionCreate { uid, admission } => {
                self.create_static_session(*uid, admission)
            }
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
            MutationIntent::FilesystemMutation {
                uid,
                session_id,
                operation,
                target,
                name,
                output_format,
            } => self
                .filesystem_mutation(*uid, session_id, *operation, target, name, output_format)
                .and_then(|response| {
                    message(MutationResponseType::FilesystemOperationResponse, &response)
                }),
            MutationIntent::PolicyPackageApply {
                uid,
                policy,
                maximum_stored_bytes,
            } => self.store_policy_package(*uid, policy, *maximum_stored_bytes),
            MutationIntent::PolicySetCreate {
                uid,
                name,
                package_names,
            } => self.create_policy_set(*uid, name, package_names),
            MutationIntent::SurfaceCreate {
                uid,
                name,
                surface_type,
            } => self.create_surface(*uid, name, surface_type),
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
        name: &str,
        maximum_bytes: u64,
    ) -> Result<erebor_runtime_packages::PolicyPackageRevision> {
        self.descriptor_broker
            .read_policy_package(owner_uid, owner_gid, path, name, maximum_bytes)
    }

    pub(crate) fn list_policy_packages(&self, owner_uid: u32) -> Result<Vec<PolicyPackageRecord>> {
        self.local_store
            .list_policy_packages(owner_uid)
            .map(|packages| {
                packages
                    .into_iter()
                    .map(|package| PolicyPackageRecord {
                        name: package.name().to_owned(),
                    })
                    .collect()
            })
    }

    pub(crate) fn inspect_policy_package(
        &self,
        owner_uid: u32,
        name: &str,
    ) -> Result<PolicyPackageRecord> {
        self.local_store
            .inspect_policy_package(owner_uid, name)
            .map(|package| PolicyPackageRecord {
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
                        name: policy_set.name().to_owned(),
                    })
                    .collect()
            })
    }

    pub(crate) fn inspect_policy_set(&self, owner_uid: u32, name: &str) -> Result<PolicySetRecord> {
        self.local_store
            .inspect_policy_set(owner_uid, name)
            .map(|policy_set| PolicySetRecord {
                name: policy_set.name().to_owned(),
            })
    }

    pub(crate) fn list_surfaces(&self, owner_uid: u32) -> Result<SurfaceListResponse> {
        self.local_store
            .list_surfaces(owner_uid)
            .map(|surfaces| SurfaceListResponse {
                surfaces: surfaces
                    .into_iter()
                    .map(|surface| SurfaceRecord {
                        name: surface.name().to_owned(),
                        surface_type: surface.surface_type().to_owned(),
                    })
                    .collect(),
            })
    }

    pub(crate) fn inspect_surface(&self, owner_uid: u32, name: &str) -> Result<SurfaceRecord> {
        self.local_store
            .inspect_surface(owner_uid, name)
            .map(|surface| SurfaceRecord {
                name: surface.name().to_owned(),
                surface_type: surface.surface_type().to_owned(),
            })
    }

    fn store_policy_package(
        &self,
        owner_uid: u32,
        policy: &erebor_runtime_packages::PolicyPackageRevision,
        maximum_stored_bytes: u64,
    ) -> Result<MutationResponse> {
        self.local_store
            .store_user_policy_package(owner_uid, policy, maximum_stored_bytes)?;
        message(
            MutationResponseType::PolicyPackageRecord,
            &PolicyPackageRecord {
                name: policy.manifest().name().to_owned(),
            },
        )
    }

    fn create_policy_set(
        &self,
        owner_uid: u32,
        name: &str,
        package_names: &[String],
    ) -> Result<MutationResponse> {
        let policy_set = self
            .local_store
            .create_user_policy_set(owner_uid, name, package_names)?;
        message(
            MutationResponseType::PolicySetRecord,
            &PolicySetRecord {
                name: policy_set.name().to_owned(),
            },
        )
    }

    fn create_surface(
        &self,
        owner_uid: u32,
        name: &str,
        surface_type: &str,
    ) -> Result<MutationResponse> {
        let surface = self
            .local_store
            .create_user_surface(owner_uid, name, surface_type)?;
        message(
            MutationResponseType::SurfaceRecord,
            &SurfaceRecord {
                name: surface.name().to_owned(),
                surface_type: surface.surface_type().to_owned(),
            },
        )
    }

    pub(crate) fn inspect(&self, uid: u32, session_id: &str) -> Result<SessionRecord> {
        if let Some(session) = self.local_store.inspect_static_session(uid, session_id)? {
            return Ok(Self::static_session_record(uid, &session));
        }
        let session_id = self.resolve_session_reference(uid, session_id)?;
        let record = self
            .manager
            .inspect(uid, &session_id)
            .context(SessionSnafu)?;
        Ok(self.record(&record))
    }

    pub(crate) fn list(&self, uid: u32) -> Result<SessionListResponse> {
        let mut sessions = self
            .manager
            .list(uid)
            .context(SessionSnafu)?
            .iter()
            .map(|record| self.record(record))
            .collect::<Vec<_>>();
        sessions.extend(
            self.local_store
                .list_static_sessions(uid)?
                .iter()
                .map(|session| Self::static_session_record(uid, session)),
        );
        sessions.sort_by(|left, right| left.session_id.cmp(&right.session_id));
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
        if self
            .local_store
            .inspect_static_session(uid, session_id)?
            .is_some()
        {
            return crate::error::InvalidRequestSnafu {
                reason: String::from(
                    "Session has static admission only; runtime activation is not available in Phase 5.2",
                ),
            }
            .fail();
        }
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
            MutationResponseType::SessionCreateResponse,
            &SessionCreateResponse {
                session_id: record.spec().session_id().as_str().to_owned(),
                state: record.state().as_str().to_owned(),
                generation: record.generation(),
                retry_guarantee_expires_unix_ms: self.retry_expiration(&record),
            },
        )
    }

    fn create_static_session(
        &self,
        owner_uid: u32,
        admission: &StaticSessionAdmission,
    ) -> Result<MutationResponse> {
        let session = self
            .local_store
            .create_static_session(owner_uid, admission)?;
        message(
            MutationResponseType::SessionCreateResponse,
            &SessionCreateResponse {
                session_id: session.name().to_owned(),
                state: String::from("admitted"),
                generation: 0,
                retry_guarantee_expires_unix_ms: 0,
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
        message(MutationResponseType::SessionRecord, &self.record(&record))
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
        message(MutationResponseType::SessionRecord, &self.record(&record))
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
        message(MutationResponseType::SessionRecord, &self.record(&record))
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
        message(MutationResponseType::SessionRecord, &self.record(&record))
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
            MutationResponseType::SessionAttachResponse,
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
            MutationResponseType::CodexAppServerAttachResponse,
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
            MutationResponseType::SessionInputLeaseResponse,
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
            MutationResponseType::SessionInputLeaseResponse,
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

    pub(crate) fn resize_terminal(
        &self,
        uid: u32,
        session_id: &str,
        lease_id: &str,
        client_instance_id: &str,
        rows: u32,
        columns: u32,
    ) -> Result<SessionTerminalResizeResponse> {
        let rows = u16::try_from(rows).map_err(|_error| {
            crate::error::InvalidRequestSnafu {
                reason: String::from("terminal rows must fit in a Linux terminal size"),
            }
            .build()
        })?;
        let columns = u16::try_from(columns).map_err(|_error| {
            crate::error::InvalidRequestSnafu {
                reason: String::from("terminal columns must fit in a Linux terminal size"),
            }
            .build()
        })?;
        let terminal_size = TerminalSize::new(rows, columns).map_err(|error| {
            crate::error::InvalidRequestSnafu {
                reason: error.to_string(),
            }
            .build()
        })?;
        let session_id = self.resolve_session_reference(uid, session_id)?;
        self.manager
            .resize_terminal(
                uid,
                &session_id,
                lease_id,
                client_instance_id,
                terminal_size,
            )
            .context(SessionSnafu)?;
        Ok(SessionTerminalResizeResponse {
            session_id,
            rows: u32::from(rows),
            columns: u32::from(columns),
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
            MutationResponseType::SessionPruneResponse,
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
            MutationResponseType::SessionAliasRecord,
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
            MutationResponseType::SessionAliasRecord,
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
        message(MutationResponseType::SessionRecord, &self.record(&record))
    }

    fn record(&self, record: &DurableSessionRecord) -> SessionRecord {
        session_record(record, self.retry_expiration(record))
    }

    fn static_session_record(owner_uid: u32, session: &StoredStaticSession) -> SessionRecord {
        SessionRecord {
            session_id: session.name().to_owned(),
            state: String::from("admitted"),
            generation: 0,
            owner_uid,
            runner_id: String::new(),
            runner_recovery: String::new(),
            failure: String::new(),
            retry_guarantee_expires_unix_ms: 0,
            retention_hold: false,
            api_version: String::from("erebor.dev/v1"),
            kind: String::from("Session"),
            agent_name: session.agent_name().to_owned(),
            policy_set_name: session.policy_set_name().to_owned(),
            surface_names: session.surface_names().to_vec(),
            state_projection: None,
        }
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
            .filter(|session_id| {
                session_id.starts_with(reference)
                    || session_id
                        .strip_prefix("session-")
                        .is_some_and(|short| short.starts_with(reference))
            })
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

fn message(response_type: MutationResponseType, value: &impl Message) -> Result<MutationResponse> {
    Ok(MutationResponse::new(response_type, value.encode_to_vec()))
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use erebor_runtime_core::{FilesystemProjectionTarget, SafePathBinding, SafePathKind};
    use erebor_runtime_ipc::v1::{CallerHomeFilesystemSource, SessionEnvironmentEntry};
    use erebor_runtime_packages::{
        CodexHookContract, CodexHookEventName, CodexHookExec, CodexHookShell,
    };

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

    #[test]
    fn codex_managed_profile_artifacts_use_session_overlay_targets(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let source = SafePathBinding::new(
            PathBuf::from("/var/lib/erebor/requirements.toml"),
            1,
            2,
            3,
            0,
            0,
            SafePathKind::File,
        )?;

        let requirements = DaemonSessionApi::codex_artifact_projection(
            source.clone(),
            Path::new("/etc/codex/requirements.toml"),
        )?;
        let hook = DaemonSessionApi::codex_artifact_projection(
            source.clone(),
            Path::new("/usr/lib/erebor/codex-hooks/erebor-codex-hook"),
        )?;
        let private_runtime = DaemonSessionApi::codex_artifact_projection(
            source,
            Path::new("/run/erebor/codex/requirements.toml"),
        )?;

        assert_eq!(
            requirements.target().session_overlay_root(),
            Some(Path::new("/etc"))
        );
        assert_eq!(
            hook.target().session_overlay_root(),
            Some(Path::new("/usr/lib"))
        );
        assert!(matches!(
            private_runtime.target(),
            FilesystemProjectionTarget::Preinstalled
        ));
        Ok(())
    }

    #[test]
    fn codex_session_pins_the_declared_hook_shell_environment(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let direct = CodexHookContract::new(
            CodexHookShell::Direct,
            vec![
                CodexHookExec::InstalledExecutable,
                CodexHookExec::ManagedHook,
            ],
            vec![CodexHookEventName::SessionStart],
            None,
        )?;
        let bash = CodexHookContract::new(
            CodexHookShell::Bash,
            vec![
                CodexHookExec::InstalledExecutable,
                CodexHookExec::AbsolutePath(PathBuf::from("/usr/bin/bash")),
                CodexHookExec::ManagedHook,
            ],
            vec![CodexHookEventName::SessionStart],
            None,
        )?;

        assert!(DaemonSessionApi::codex_hook_shell_environment(&direct).is_empty());
        assert_eq!(
            DaemonSessionApi::codex_hook_shell_environment(&bash),
            vec![erebor_runtime_ipc::v1::SessionEnvironmentEntry {
                key: String::from("SHELL"),
                value: String::from("/usr/bin/bash"),
            }]
        );
        Ok(())
    }

    #[test]
    fn caller_source_view_accepts_only_the_client_path_environment(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let path = vec![SessionEnvironmentEntry {
            key: String::from("PATH"),
            value: String::from("/home/navid/.local/bin:/usr/bin:/bin"),
        }];
        assert_eq!(
            DaemonSessionApi::codex_client_path(&path)?,
            "/home/navid/.local/bin:/usr/bin:/bin"
        );
        assert!(DaemonSessionApi::codex_client_path(&[]).is_err());
        assert!(DaemonSessionApi::codex_client_path(&[
            SessionEnvironmentEntry {
                key: String::from("PATH"),
                value: String::from("/usr/bin"),
            },
            SessionEnvironmentEntry {
                key: String::from("HOME"),
                value: String::from("/home/navid"),
            },
        ])
        .is_err());
        Ok(())
    }

    #[test]
    fn caller_home_sources_are_a_generic_session_input() -> Result<(), Box<dyn std::error::Error>> {
        let view = DaemonSessionApi::caller_home_source_view(&[
            CallerHomeFilesystemSource {
                relative_path: String::from(".bashrc"),
                kind: String::from("file"),
                access: String::from("read_only"),
            },
            CallerHomeFilesystemSource {
                relative_path: String::from("workspace"),
                kind: String::from("directory"),
                access: String::from("read_write"),
            },
        ])?
        .ok_or("source view must be present")?;
        assert_eq!(view.sources().len(), 2);
        assert!(DaemonSessionApi::caller_home_source_view(&[
            CallerHomeFilesystemSource {
                relative_path: String::from("workspace"),
                kind: String::from("directory"),
                access: String::from("read_write"),
            },
            CallerHomeFilesystemSource {
                relative_path: String::from("workspace/file"),
                kind: String::from("file"),
                access: String::from("read_only"),
            },
        ])
        .is_err());
        Ok(())
    }
}
