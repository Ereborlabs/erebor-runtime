use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    path::{Component, Path, PathBuf},
};

use erebor_runtime_events::SessionId;
use serde::{Deserialize, Serialize};
use snafu::ensure;

use crate::{error::session_spec::InvalidSnafu, SessionSpecError};

pub const SESSION_SPEC_SCHEMA_VERSION: u32 = 5;
pub const RUNNER_CAPABILITY_SCHEMA_VERSION: u32 = 2;
pub const RUNNER_RECOVERY_SCHEMA_VERSION: u32 = 1;

/// Immutable initial geometry for an admitted daemon-owned terminal.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct TerminalSize {
    rows: u16,
    columns: u16,
}

impl TerminalSize {
    #[must_use]
    pub const fn default_tty() -> Self {
        Self {
            rows: 24,
            columns: 80,
        }
    }

    pub fn new(rows: u16, columns: u16) -> Result<Self, SessionSpecError> {
        let value = Self { rows, columns };
        value.validate()?;
        Ok(value)
    }

    pub fn validate(&self) -> Result<(), SessionSpecError> {
        ensure!(
            self.rows > 0 && self.columns > 0,
            InvalidSnafu {
                field: "terminal_size",
                reason: String::from("rows and columns must be positive"),
            }
        );
        Ok(())
    }

    #[must_use]
    pub const fn rows(&self) -> u16 {
        self.rows
    }

    #[must_use]
    pub const fn columns(&self) -> u16 {
        self.columns
    }
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct RunnerId(String);

impl RunnerId {
    pub fn new(value: impl Into<String>) -> Result<Self, SessionSpecError> {
        let value = Self(value.into());
        value.validate()?;
        Ok(value)
    }

    pub fn validate(&self) -> Result<(), SessionSpecError> {
        let bytes = self.0.as_bytes();
        ensure!(
            !bytes.is_empty()
                && bytes.len() <= 64
                && bytes.first().is_some_and(u8::is_ascii_lowercase)
                && bytes.last().is_some_and(u8::is_ascii_alphanumeric)
                && bytes.iter().all(|byte| byte.is_ascii_lowercase()
                    || byte.is_ascii_digit()
                    || *byte == b'-'),
            InvalidSnafu {
                field: "runner_id",
                reason: String::from(
                    "must be 1-64 lowercase ASCII letters, digits, or interior hyphens",
                ),
            }
        );
        Ok(())
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for RunnerId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl TryFrom<String> for RunnerId {
    type Error = SessionSpecError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<RunnerId> for String {
    fn from(value: RunnerId) -> Self {
        value.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SessionOwner {
    uid: u32,
    gid: u32,
}

impl SessionOwner {
    #[must_use]
    pub const fn new(uid: u32, gid: u32) -> Self {
        Self { uid, gid }
    }

    #[must_use]
    pub const fn uid(&self) -> u32 {
        self.uid
    }

    #[must_use]
    pub const fn gid(&self) -> u32 {
        self.gid
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct WorkloadPrivilegePlan {
    supplementary_groups: Vec<u32>,
    umask: u32,
    maximum_open_files: u64,
    maximum_processes: u64,
    maximum_core_bytes: u64,
}

impl WorkloadPrivilegePlan {
    pub fn new(
        supplementary_groups: Vec<u32>,
        umask: u32,
        maximum_open_files: u64,
        maximum_processes: u64,
        maximum_core_bytes: u64,
    ) -> Result<Self, SessionSpecError> {
        let value = Self {
            supplementary_groups,
            umask,
            maximum_open_files,
            maximum_processes,
            maximum_core_bytes,
        };
        value.validate()?;
        Ok(value)
    }

    pub fn validate(&self) -> Result<(), SessionSpecError> {
        ensure!(
            self.umask <= 0o777
                && self.maximum_open_files >= 16
                && self.maximum_processes > 0
                && self
                    .supplementary_groups
                    .iter()
                    .collect::<BTreeSet<_>>()
                    .len()
                    == self.supplementary_groups.len(),
            InvalidSnafu {
                field: "workload_privilege_plan",
                reason: String::from(
                    "umask, resource limits, and unique supplementary groups are required",
                ),
            }
        );
        Ok(())
    }

    #[must_use]
    pub fn supplementary_groups(&self) -> &[u32] {
        &self.supplementary_groups
    }

    #[must_use]
    pub const fn umask(&self) -> u32 {
        self.umask
    }

    #[must_use]
    pub const fn maximum_open_files(&self) -> u64 {
        self.maximum_open_files
    }

    #[must_use]
    pub const fn maximum_processes(&self) -> u64 {
        self.maximum_processes
    }

    #[must_use]
    pub const fn maximum_core_bytes(&self) -> u64 {
        self.maximum_core_bytes
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DaemonFailureMode {
    Terminate,
    Continue,
    ContinueIfEnforced,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActiveSessionSignalKind {
    Terminate,
    Kill,
    Interrupt,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RunnerCapabilityDocument {
    schema_version: u32,
    runner: RunnerId,
    implementation_id: String,
    implementation_version: String,
    host_os: String,
    host_architecture: String,
    filesystem_isolation: bool,
    physical_interception: bool,
    stream_kinds: BTreeSet<String>,
    supported_signals: BTreeSet<ActiveSessionSignalKind>,
    tty_supported: bool,
    attach_supported: bool,
    supported_failure_modes: BTreeSet<DaemonFailureMode>,
    admission_constraints: BTreeMap<String, String>,
}

impl RunnerCapabilityDocument {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        runner: RunnerId,
        implementation_id: impl Into<String>,
        implementation_version: impl Into<String>,
        host_os: impl Into<String>,
        host_architecture: impl Into<String>,
        filesystem_isolation: bool,
        physical_interception: bool,
        stream_kinds: BTreeSet<String>,
        supported_signals: BTreeSet<ActiveSessionSignalKind>,
        tty_supported: bool,
        attach_supported: bool,
        supported_failure_modes: BTreeSet<DaemonFailureMode>,
        admission_constraints: BTreeMap<String, String>,
    ) -> Result<Self, SessionSpecError> {
        let value = Self {
            schema_version: RUNNER_CAPABILITY_SCHEMA_VERSION,
            runner,
            implementation_id: implementation_id.into(),
            implementation_version: implementation_version.into(),
            host_os: host_os.into(),
            host_architecture: host_architecture.into(),
            filesystem_isolation,
            physical_interception,
            stream_kinds,
            supported_signals,
            tty_supported,
            attach_supported,
            supported_failure_modes,
            admission_constraints,
        };
        value.validate()?;
        Ok(value)
    }

    pub fn validate(&self) -> Result<(), SessionSpecError> {
        ensure!(
            self.schema_version == RUNNER_CAPABILITY_SCHEMA_VERSION,
            InvalidSnafu {
                field: "runner_capability.schema_version",
                reason: format!("unsupported version {}", self.schema_version),
            }
        );
        self.runner.validate()?;
        for (field, value) in [
            (
                "runner_capability.implementation_id",
                &self.implementation_id,
            ),
            (
                "runner_capability.implementation_version",
                &self.implementation_version,
            ),
            ("runner_capability.host_os", &self.host_os),
            (
                "runner_capability.host_architecture",
                &self.host_architecture,
            ),
        ] {
            ensure!(
                !value.trim().is_empty(),
                InvalidSnafu {
                    field,
                    reason: String::from("must not be empty"),
                }
            );
        }
        ensure!(
            self.stream_kinds.contains("stdout") && self.stream_kinds.contains("stderr"),
            InvalidSnafu {
                field: "runner_capability.stream_kinds",
                reason: String::from("stdout and stderr are required"),
            }
        );
        ensure!(
            !self.supported_failure_modes.is_empty()
                && !self
                    .supported_failure_modes
                    .contains(&DaemonFailureMode::ContinueIfEnforced),
            InvalidSnafu {
                field: "runner_capability.supported_failure_modes",
                reason: String::from(
                    "at least one Phase 2 mode is required and continue_if_enforced is unavailable",
                ),
            }
        );
        Ok(())
    }

    #[must_use]
    pub const fn runner(&self) -> &RunnerId {
        &self.runner
    }

    #[must_use]
    pub fn implementation_id(&self) -> &str {
        &self.implementation_id
    }

    #[must_use]
    pub fn implementation_version(&self) -> &str {
        &self.implementation_version
    }

    #[must_use]
    pub fn host_os(&self) -> &str {
        &self.host_os
    }

    #[must_use]
    pub fn host_architecture(&self) -> &str {
        &self.host_architecture
    }

    #[must_use]
    pub const fn filesystem_isolation(&self) -> bool {
        self.filesystem_isolation
    }

    #[must_use]
    pub const fn tty_supported(&self) -> bool {
        self.tty_supported
    }

    #[must_use]
    pub const fn attach_supported(&self) -> bool {
        self.attach_supported
    }

    #[must_use]
    pub fn supports_signal(&self, signal: ActiveSessionSignalKind) -> bool {
        self.supported_signals.contains(&signal)
    }

    #[must_use]
    pub fn supports_failure_mode(&self, mode: DaemonFailureMode) -> bool {
        self.supported_failure_modes.contains(&mode)
    }

    #[must_use]
    pub fn admission_constraint(&self, key: &str) -> Option<&str> {
        self.admission_constraints.get(key).map(String::as_str)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RunnerBinding {
    runner: RunnerId,
    implementation_id: String,
    recovery: RunnerRecovery,
    observed_at_unix_ms: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RunnerRecovery {
    schema_version: u32,
    format_version: u32,
    payload: String,
}

impl RunnerRecovery {
    pub fn new(format_version: u32, payload: impl Into<String>) -> Result<Self, SessionSpecError> {
        let value = Self {
            schema_version: RUNNER_RECOVERY_SCHEMA_VERSION,
            format_version,
            payload: payload.into(),
        };
        value.validate()?;
        Ok(value)
    }

    pub fn validate(&self) -> Result<(), SessionSpecError> {
        ensure!(
            self.schema_version == RUNNER_RECOVERY_SCHEMA_VERSION
                && self.format_version > 0
                && !self.payload.trim().is_empty()
                && self.payload.len() <= 64 * 1024,
            InvalidSnafu {
                field: "runner_recovery",
                reason: String::from(
                    "supported schema, positive format version, and a bounded payload are required",
                ),
            }
        );
        Ok(())
    }

    #[must_use]
    pub const fn format_version(&self) -> u32 {
        self.format_version
    }

    #[must_use]
    pub fn payload(&self) -> &str {
        &self.payload
    }
}

impl RunnerBinding {
    pub fn new(
        runner: RunnerId,
        implementation_id: impl Into<String>,
        recovery: RunnerRecovery,
        observed_at_unix_ms: u64,
    ) -> Result<Self, SessionSpecError> {
        let value = Self {
            runner,
            implementation_id: implementation_id.into(),
            recovery,
            observed_at_unix_ms,
        };
        value.validate()?;
        Ok(value)
    }

    pub fn validate(&self) -> Result<(), SessionSpecError> {
        ensure!(
            !self.implementation_id.trim().is_empty() && self.observed_at_unix_ms > 0,
            InvalidSnafu {
                field: "runner_binding",
                reason: String::from(
                    "implementation, recovery value, and observation time are required",
                ),
            }
        );
        self.runner.validate()?;
        self.recovery.validate()?;
        Ok(())
    }

    #[must_use]
    pub const fn runner(&self) -> &RunnerId {
        &self.runner
    }

    #[must_use]
    pub fn implementation_id(&self) -> &str {
        &self.implementation_id
    }

    #[must_use]
    pub const fn recovery(&self) -> &RunnerRecovery {
        &self.recovery
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SafePathKind {
    Directory,
    Executable,
    File,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SafePathBinding {
    requested_path: PathBuf,
    device: u64,
    inode: u64,
    mount_id: u64,
    owner_uid: u32,
    owner_gid: u32,
    kind: SafePathKind,
    #[serde(default)]
    content_sha256: Option<String>,
}

impl SafePathBinding {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        requested_path: PathBuf,
        device: u64,
        inode: u64,
        mount_id: u64,
        owner_uid: u32,
        owner_gid: u32,
        kind: SafePathKind,
    ) -> Result<Self, SessionSpecError> {
        let value = Self {
            requested_path,
            device,
            inode,
            mount_id,
            owner_uid,
            owner_gid,
            kind,
            content_sha256: None,
        };
        value.validate()?;
        Ok(value)
    }

    pub fn validate(&self) -> Result<(), SessionSpecError> {
        ensure!(
            is_normalized_absolute(&self.requested_path)
                && self.device != 0
                && self.inode != 0
                && self.mount_id != 0,
            InvalidSnafu {
                field: "safe_path",
                reason: String::from(
                    "absolute path and nonzero device, inode, and mount id are required",
                ),
            }
        );
        if let Some(digest) = &self.content_sha256 {
            ensure!(
                digest.len() == 64
                    && digest
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f')),
                InvalidSnafu {
                    field: "safe_path.content_sha256",
                    reason: String::from("must be a lower-case SHA-256 digest when present"),
                }
            );
        }
        Ok(())
    }

    pub fn with_content_sha256(
        mut self,
        digest: impl Into<String>,
    ) -> Result<Self, SessionSpecError> {
        self.content_sha256 = Some(digest.into());
        self.validate()?;
        Ok(self)
    }

    #[must_use]
    pub fn requested_path(&self) -> &Path {
        &self.requested_path
    }

    #[must_use]
    pub const fn device(&self) -> u64 {
        self.device
    }

    #[must_use]
    pub const fn inode(&self) -> u64 {
        self.inode
    }

    #[must_use]
    pub const fn mount_id(&self) -> u64 {
        self.mount_id
    }

    #[must_use]
    pub const fn owner_uid(&self) -> u32 {
        self.owner_uid
    }

    #[must_use]
    pub const fn owner_gid(&self) -> u32 {
        self.owner_gid
    }

    #[must_use]
    pub const fn kind(&self) -> SafePathKind {
        self.kind
    }

    #[must_use]
    pub fn content_sha256(&self) -> Option<&str> {
        self.content_sha256.as_deref()
    }
}

/// An interpreter selected from a script shebang during admission. Its
/// executable identity and arguments are part of the immutable session record.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ScriptInterpreterBinding {
    executable: SafePathBinding,
    arguments: Vec<String>,
}

impl ScriptInterpreterBinding {
    pub fn new(
        executable: SafePathBinding,
        arguments: Vec<String>,
    ) -> Result<Self, SessionSpecError> {
        let value = Self {
            executable,
            arguments,
        };
        value.validate()?;
        Ok(value)
    }

    pub fn validate(&self) -> Result<(), SessionSpecError> {
        self.executable.validate()?;
        ensure!(
            self.executable.kind() == SafePathKind::Executable
                && self.executable.content_sha256().is_some()
                && self
                    .arguments
                    .iter()
                    .all(|argument| !argument.is_empty() && !argument.contains('\0')),
            InvalidSnafu {
                field: "script_interpreter",
                reason: String::from(
                    "a script interpreter must be a hash-pinned executable with safe arguments",
                ),
            }
        );
        Ok(())
    }

    #[must_use]
    pub const fn executable(&self) -> &SafePathBinding {
        &self.executable
    }

    #[must_use]
    pub fn arguments(&self) -> &[String] {
        &self.arguments
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ImmutableIdentity {
    kind: String,
    sha256: String,
}

impl ImmutableIdentity {
    pub fn new(
        kind: impl Into<String>,
        sha256: impl Into<String>,
    ) -> Result<Self, SessionSpecError> {
        let value = Self {
            kind: kind.into(),
            sha256: sha256.into().to_ascii_lowercase(),
        };
        value.validate()?;
        Ok(value)
    }

    pub fn validate(&self) -> Result<(), SessionSpecError> {
        ensure!(
            is_safe_name(&self.kind)
                && self.sha256.len() == 64
                && self
                    .sha256
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f')),
            InvalidSnafu {
                field: "immutable_identity",
                reason: String::from("safe kind and SHA-256 digest are required"),
            }
        );
        Ok(())
    }

    #[must_use]
    pub fn kind(&self) -> &str {
        &self.kind
    }

    #[must_use]
    pub fn sha256(&self) -> &str {
        &self.sha256
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct FilesystemProjection {
    source: SafePathBinding,
    workload_path: PathBuf,
    read_only: bool,
}

impl FilesystemProjection {
    pub fn new(
        source: SafePathBinding,
        workload_path: PathBuf,
        read_only: bool,
    ) -> Result<Self, SessionSpecError> {
        let value = Self {
            source,
            workload_path,
            read_only,
        };
        value.validate()?;
        Ok(value)
    }

    pub fn validate(&self) -> Result<(), SessionSpecError> {
        self.source.validate()?;
        ensure!(
            is_normalized_absolute(&self.workload_path),
            InvalidSnafu {
                field: "filesystem_projection.workload_path",
                reason: String::from("must be absolute"),
            }
        );
        Ok(())
    }

    #[must_use]
    pub const fn source(&self) -> &SafePathBinding {
        &self.source
    }

    #[must_use]
    pub fn workload_path(&self) -> &Path {
        &self.workload_path
    }

    #[must_use]
    pub const fn read_only(&self) -> bool {
        self.read_only
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct EndpointProjection {
    service: String,
    host_path: PathBuf,
    workload_path: PathBuf,
}

impl EndpointProjection {
    pub fn new(
        service: impl Into<String>,
        host_path: PathBuf,
        workload_path: PathBuf,
    ) -> Result<Self, SessionSpecError> {
        let value = Self {
            service: service.into(),
            host_path,
            workload_path,
        };
        value.validate()?;
        Ok(value)
    }

    pub fn validate(&self) -> Result<(), SessionSpecError> {
        ensure!(
            is_safe_name(&self.service)
                && self.service != "daemon-control"
                && is_normalized_absolute(&self.host_path)
                && is_normalized_absolute(&self.workload_path),
            InvalidSnafu {
                field: "endpoint_projection",
                reason: String::from("safe non-control service and absolute paths are required",),
            }
        );
        Ok(())
    }

    #[must_use]
    pub fn service(&self) -> &str {
        &self.service
    }

    #[must_use]
    pub fn host_path(&self) -> &Path {
        &self.host_path
    }

    #[must_use]
    pub fn workload_path(&self) -> &Path {
        &self.workload_path
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct EvidenceRequirement {
    kind: String,
    required: bool,
}

impl EvidenceRequirement {
    pub fn new(kind: impl Into<String>, required: bool) -> Result<Self, SessionSpecError> {
        let value = Self {
            kind: kind.into(),
            required,
        };
        value.validate()?;
        Ok(value)
    }

    pub fn validate(&self) -> Result<(), SessionSpecError> {
        ensure!(
            is_safe_name(&self.kind),
            InvalidSnafu {
                field: "evidence_requirement.kind",
                reason: String::from("must be a safe non-empty name"),
            }
        );
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct OutputPlan {
    root: PathBuf,
    maximum_bytes: u64,
    rotation_bytes: u64,
    maximum_records_per_read: u32,
    requirements: OutputStreamRequirements,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct OutputStreamRequirements {
    stdout: bool,
    stderr: bool,
}

impl OutputStreamRequirements {
    #[must_use]
    pub const fn required() -> Self {
        Self {
            stdout: true,
            stderr: true,
        }
    }

    #[must_use]
    pub const fn optional() -> Self {
        Self {
            stdout: false,
            stderr: false,
        }
    }

    #[must_use]
    pub const fn stdout_required(self) -> bool {
        self.stdout
    }

    #[must_use]
    pub const fn stderr_required(self) -> bool {
        self.stderr
    }
}

impl OutputPlan {
    pub fn new(
        root: PathBuf,
        maximum_bytes: u64,
        rotation_bytes: u64,
        maximum_records_per_read: u32,
        requirements: OutputStreamRequirements,
    ) -> Result<Self, SessionSpecError> {
        let value = Self {
            root,
            maximum_bytes,
            rotation_bytes,
            maximum_records_per_read,
            requirements,
        };
        value.validate()?;
        Ok(value)
    }

    pub fn validate(&self) -> Result<(), SessionSpecError> {
        ensure!(
            is_normalized_absolute(&self.root)
                && self.maximum_bytes > 0
                && self.rotation_bytes > 0
                && self.rotation_bytes <= self.maximum_bytes
                && self.maximum_records_per_read > 0,
            InvalidSnafu {
                field: "output_plan",
                reason: String::from("requires an absolute root and bounded rotation/read limits"),
            }
        );
        Ok(())
    }

    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    #[must_use]
    pub const fn maximum_bytes(&self) -> u64 {
        self.maximum_bytes
    }

    #[must_use]
    pub const fn rotation_bytes(&self) -> u64 {
        self.rotation_bytes
    }

    #[must_use]
    pub const fn maximum_records_per_read(&self) -> u32 {
        self.maximum_records_per_read
    }

    #[must_use]
    pub const fn requirements(&self) -> OutputStreamRequirements {
        self.requirements
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RunRequest {
    runner: RunnerId,
    command: Vec<String>,
    workspace: PathBuf,
    policy_set_sha256: String,
    package_sha256: Option<String>,
    installation_sha256: Option<String>,
    adapter_sha256: Option<String>,
    container_image_sha256: Option<String>,
    environment: Vec<(String, String)>,
    secret_references: Vec<String>,
    tty: bool,
    terminal_size: Option<TerminalSize>,
    detached: bool,
    daemon_failure_mode: DaemonFailureMode,
    requested_loss_grace_seconds: u64,
}

impl RunRequest {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        runner: RunnerId,
        command: Vec<String>,
        workspace: PathBuf,
        policy_set_sha256: impl Into<String>,
        package_sha256: Option<String>,
        installation_sha256: Option<String>,
        adapter_sha256: Option<String>,
        container_image_sha256: Option<String>,
        environment: Vec<(String, String)>,
        secret_references: Vec<String>,
        tty: bool,
        terminal_size: Option<TerminalSize>,
        detached: bool,
        daemon_failure_mode: DaemonFailureMode,
        requested_loss_grace_seconds: u64,
    ) -> Result<Self, SessionSpecError> {
        let value = Self {
            runner,
            command,
            workspace,
            policy_set_sha256: policy_set_sha256.into(),
            package_sha256,
            installation_sha256,
            adapter_sha256,
            container_image_sha256,
            environment,
            secret_references,
            tty,
            terminal_size,
            detached,
            daemon_failure_mode,
            requested_loss_grace_seconds,
        };
        value.validate()?;
        Ok(value)
    }

    fn validate(&self) -> Result<(), SessionSpecError> {
        ensure!(
            !self.command.is_empty()
                && self.command.iter().all(|argument| !argument.contains('\0'))
                && is_normalized_absolute(&self.workspace)
                && self.requested_loss_grace_seconds > 0,
            InvalidSnafu {
                field: "run_request",
                reason: String::from(
                    "command, absolute workspace, and positive loss grace are required",
                ),
            }
        );
        self.runner.validate()?;
        ImmutableIdentity::new("policy-set", &self.policy_set_sha256)?;
        for (kind, digest) in [
            ("agent-package", self.package_sha256.as_deref()),
            ("installation", self.installation_sha256.as_deref()),
            ("adapter", self.adapter_sha256.as_deref()),
            ("container-image", self.container_image_sha256.as_deref()),
        ] {
            if let Some(digest) = digest {
                ImmutableIdentity::new(kind, digest)?;
            }
        }
        validate_environment(&self.environment)?;
        validate_secret_references(&self.secret_references)?;
        ensure!(
            self.tty == self.terminal_size.is_some(),
            InvalidSnafu {
                field: "run_request.terminal_size",
                reason: String::from(
                    "TTY sessions require terminal geometry and non-TTY sessions must not have it"
                ),
            }
        );
        Ok(())
    }

    #[must_use]
    pub const fn runner(&self) -> &RunnerId {
        &self.runner
    }

    #[must_use]
    pub fn command(&self) -> &[String] {
        &self.command
    }

    #[must_use]
    pub fn workspace(&self) -> &Path {
        &self.workspace
    }

    #[must_use]
    pub fn policy_set_sha256(&self) -> &str {
        &self.policy_set_sha256
    }

    #[must_use]
    pub fn package_sha256(&self) -> Option<&str> {
        self.package_sha256.as_deref()
    }

    #[must_use]
    pub fn installation_sha256(&self) -> Option<&str> {
        self.installation_sha256.as_deref()
    }

    #[must_use]
    pub fn adapter_sha256(&self) -> Option<&str> {
        self.adapter_sha256.as_deref()
    }

    #[must_use]
    pub fn container_image_sha256(&self) -> Option<&str> {
        self.container_image_sha256.as_deref()
    }

    #[must_use]
    pub fn environment(&self) -> &[(String, String)] {
        &self.environment
    }

    #[must_use]
    pub fn secret_references(&self) -> &[String] {
        &self.secret_references
    }

    #[must_use]
    pub const fn tty(&self) -> bool {
        self.tty
    }

    #[must_use]
    pub const fn terminal_size(&self) -> Option<TerminalSize> {
        self.terminal_size
    }

    #[must_use]
    pub const fn detached(&self) -> bool {
        self.detached
    }

    #[must_use]
    pub const fn daemon_failure_mode(&self) -> DaemonFailureMode {
        self.daemon_failure_mode
    }

    #[must_use]
    pub const fn requested_loss_grace_seconds(&self) -> u64 {
        self.requested_loss_grace_seconds
    }
}

fn validate_secret_references(secret_references: &[String]) -> Result<(), SessionSpecError> {
    ensure!(
        secret_references
            .iter()
            .all(|reference| !reference.trim().is_empty() && !reference.contains('\0')),
        InvalidSnafu {
            field: "run_request.secret_references",
            reason: String::from("contains an empty or unsafe secret reference"),
        }
    );
    Ok(())
}

#[derive(Clone, Debug)]
pub struct SessionAdmission {
    pub session_id: SessionId,
    pub owner: SessionOwner,
    pub workload_privileges: WorkloadPrivilegePlan,
    pub command: Vec<String>,
    pub package: Option<ImmutableIdentity>,
    pub package_configuration: Option<ImmutableIdentity>,
    pub installation: Option<ImmutableIdentity>,
    pub adapter: Option<ImmutableIdentity>,
    pub policy_inputs: Vec<ImmutableIdentity>,
    pub policy_set: ImmutableIdentity,
    pub runner_capability: RunnerCapabilityDocument,
    pub workspace: SafePathBinding,
    pub executable: Option<SafePathBinding>,
    pub script_interpreters: Vec<ScriptInterpreterBinding>,
    pub container_image: Option<ImmutableIdentity>,
    pub environment: Vec<(String, String)>,
    pub secret_references: Vec<String>,
    pub filesystem_projections: Vec<FilesystemProjection>,
    pub endpoint_projections: Vec<EndpointProjection>,
    pub output: OutputPlan,
    pub evidence_requirements: Vec<EvidenceRequirement>,
    pub tty: bool,
    pub terminal_size: Option<TerminalSize>,
    pub detached: bool,
    pub daemon_failure_mode: DaemonFailureMode,
    pub loss_grace_seconds: u64,
    pub root_configuration_generation: u64,
    pub created_at_unix_ms: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SessionSpec {
    schema_version: u32,
    session_id: SessionId,
    owner: SessionOwner,
    workload_privileges: WorkloadPrivilegePlan,
    command: Vec<String>,
    package: Option<ImmutableIdentity>,
    package_configuration: Option<ImmutableIdentity>,
    installation: Option<ImmutableIdentity>,
    adapter: Option<ImmutableIdentity>,
    policy_inputs: Vec<ImmutableIdentity>,
    policy_set: ImmutableIdentity,
    runner_capability: RunnerCapabilityDocument,
    workspace: SafePathBinding,
    executable: Option<SafePathBinding>,
    script_interpreters: Vec<ScriptInterpreterBinding>,
    container_image: Option<ImmutableIdentity>,
    environment: Vec<(String, String)>,
    secret_references: Vec<String>,
    filesystem_projections: Vec<FilesystemProjection>,
    endpoint_projections: Vec<EndpointProjection>,
    output: OutputPlan,
    evidence_requirements: Vec<EvidenceRequirement>,
    tty: bool,
    terminal_size: Option<TerminalSize>,
    detached: bool,
    daemon_failure_mode: DaemonFailureMode,
    loss_grace_seconds: u64,
    root_configuration_generation: u64,
    created_at_unix_ms: u64,
}

impl SessionSpec {
    pub fn new(admission: SessionAdmission) -> Result<Self, SessionSpecError> {
        let value = Self {
            schema_version: SESSION_SPEC_SCHEMA_VERSION,
            session_id: admission.session_id,
            owner: admission.owner,
            workload_privileges: admission.workload_privileges,
            command: admission.command,
            package: admission.package,
            package_configuration: admission.package_configuration,
            installation: admission.installation,
            adapter: admission.adapter,
            policy_inputs: admission.policy_inputs,
            policy_set: admission.policy_set,
            runner_capability: admission.runner_capability,
            workspace: admission.workspace,
            executable: admission.executable,
            script_interpreters: admission.script_interpreters,
            container_image: admission.container_image,
            environment: admission.environment,
            secret_references: admission.secret_references,
            filesystem_projections: admission.filesystem_projections,
            endpoint_projections: admission.endpoint_projections,
            output: admission.output,
            evidence_requirements: admission.evidence_requirements,
            tty: admission.tty,
            terminal_size: admission.terminal_size,
            detached: admission.detached,
            daemon_failure_mode: admission.daemon_failure_mode,
            loss_grace_seconds: admission.loss_grace_seconds,
            root_configuration_generation: admission.root_configuration_generation,
            created_at_unix_ms: admission.created_at_unix_ms,
        };
        value.validate()?;
        Ok(value)
    }

    pub fn validate(&self) -> Result<(), SessionSpecError> {
        ensure!(
            self.schema_version == SESSION_SPEC_SCHEMA_VERSION,
            InvalidSnafu {
                field: "session_spec.schema_version",
                reason: format!("unsupported version {}", self.schema_version),
            }
        );
        ensure!(
            is_safe_component(self.session_id.as_str())
                && !self.command.is_empty()
                && self.command.iter().all(|value| !value.contains('\0')),
            InvalidSnafu {
                field: "session_spec.command",
                reason: String::from("safe session id and command are required"),
            }
        );
        self.runner_capability.validate()?;
        self.workload_privileges.validate()?;
        self.workspace.validate()?;
        self.executable
            .iter()
            .try_for_each(SafePathBinding::validate)?;
        self.script_interpreters
            .iter()
            .try_for_each(ScriptInterpreterBinding::validate)?;
        ensure!(
            self.executable
                .as_ref()
                .is_none_or(|binding| binding.content_sha256().is_some()),
            InvalidSnafu {
                field: "session_spec.executable.content_sha256",
                reason: String::from("an admitted executable must retain its held content digest"),
            }
        );
        self.package
            .iter()
            .chain(self.package_configuration.iter())
            .chain(self.installation.iter())
            .chain(self.adapter.iter())
            .chain(self.policy_inputs.iter())
            .chain(std::iter::once(&self.policy_set))
            .chain(self.container_image.iter())
            .try_for_each(ImmutableIdentity::validate)?;
        self.filesystem_projections
            .iter()
            .try_for_each(FilesystemProjection::validate)?;
        ensure!(
            self.filesystem_projections.iter().all(|projection| {
                projection.source().kind() == SafePathKind::Directory
                    || projection.source().content_sha256().is_some()
            }),
            InvalidSnafu {
                field: "session_spec.filesystem_projections",
                reason: String::from(
                    "file and executable projections must retain their held content digest",
                ),
            }
        );
        self.endpoint_projections
            .iter()
            .try_for_each(EndpointProjection::validate)?;
        self.output.validate()?;
        self.evidence_requirements
            .iter()
            .try_for_each(EvidenceRequirement::validate)?;
        let package_identity_is_complete = self.package.is_some()
            && self.package_configuration.is_some()
            && self.installation.is_some()
            && self.adapter.is_some();
        let package_identity_is_absent = self.package.is_none()
            && self.package_configuration.is_none()
            && self.installation.is_none()
            && self.adapter.is_none();
        ensure!(
            (package_identity_is_complete || package_identity_is_absent)
                && !self.policy_inputs.is_empty()
                && self
                    .package
                    .as_ref()
                    .is_none_or(|identity| identity.kind() == "agent-package")
                && self
                    .package_configuration
                    .as_ref()
                    .is_none_or(|identity| identity.kind() == "agent-package-config")
                && self
                    .installation
                    .as_ref()
                    .is_none_or(|identity| identity.kind() == "installation")
                && self
                    .adapter
                    .as_ref()
                    .is_none_or(|identity| identity.kind() == "adapter")
                && self.policy_set.kind() == "policy-set",
            InvalidSnafu {
                field: "session_spec.immutable_identities",
                reason: String::from(
                    "package identities must be complete or absent and policy inputs/set are required",
                ),
            }
        );
        ensure!(
            self.runner_capability
                .supports_failure_mode(self.daemon_failure_mode),
            InvalidSnafu {
                field: "session_spec.daemon_failure_mode",
                reason: String::from("is not supported by the admitted runner capability"),
            }
        );
        ensure!(
            !self.tty || self.runner_capability.tty_supported(),
            InvalidSnafu {
                field: "session_spec.tty",
                reason: String::from("is not supported by the admitted runner"),
            }
        );
        ensure!(
            self.tty == self.terminal_size.is_some(),
            InvalidSnafu {
                field: "session_spec.terminal_size",
                reason: String::from(
                    "TTY sessions require terminal geometry and non-TTY sessions must not have it"
                ),
            }
        );
        self.terminal_size
            .iter()
            .try_for_each(TerminalSize::validate)?;
        ensure!(
            self.loss_grace_seconds > 0
                && self.root_configuration_generation > 0
                && self.created_at_unix_ms > 0,
            InvalidSnafu {
                field: "session_spec.lifecycle",
                reason: String::from("loss grace, root generation, and creation time are required",),
            }
        );
        validate_environment(&self.environment)?;
        validate_secret_references(&self.secret_references)?;
        ensure!(
            self.workspace.kind() == SafePathKind::Directory
                && self
                    .executable
                    .as_ref()
                    .is_none_or(|binding| binding.kind() == SafePathKind::Executable)
                && (self.script_interpreters.is_empty() || self.executable.is_some())
                && self
                    .container_image
                    .as_ref()
                    .is_none_or(|identity| identity.kind() == "container-image"),
            InvalidSnafu {
                field: "session_spec.execution_identity",
                reason: String::from(
                    "workspace, optional executable, and optional image identities are malformed",
                ),
            }
        );
        Ok(())
    }

    #[must_use]
    pub fn session_id(&self) -> &SessionId {
        &self.session_id
    }

    #[must_use]
    pub const fn owner(&self) -> &SessionOwner {
        &self.owner
    }

    #[must_use]
    pub const fn workload_privileges(&self) -> &WorkloadPrivilegePlan {
        &self.workload_privileges
    }

    #[must_use]
    pub fn runner_capability(&self) -> &RunnerCapabilityDocument {
        &self.runner_capability
    }

    #[must_use]
    pub fn command(&self) -> &[String] {
        &self.command
    }

    #[must_use]
    pub const fn package(&self) -> Option<&ImmutableIdentity> {
        self.package.as_ref()
    }

    #[must_use]
    pub const fn package_configuration(&self) -> Option<&ImmutableIdentity> {
        self.package_configuration.as_ref()
    }

    #[must_use]
    pub const fn installation(&self) -> Option<&ImmutableIdentity> {
        self.installation.as_ref()
    }

    #[must_use]
    pub const fn adapter(&self) -> Option<&ImmutableIdentity> {
        self.adapter.as_ref()
    }

    #[must_use]
    pub fn policy_inputs(&self) -> &[ImmutableIdentity] {
        &self.policy_inputs
    }

    #[must_use]
    pub const fn policy_set(&self) -> &ImmutableIdentity {
        &self.policy_set
    }

    #[must_use]
    pub const fn workspace(&self) -> &SafePathBinding {
        &self.workspace
    }

    #[must_use]
    pub fn executable(&self) -> Option<&SafePathBinding> {
        self.executable.as_ref()
    }

    #[must_use]
    pub fn script_interpreters(&self) -> &[ScriptInterpreterBinding] {
        &self.script_interpreters
    }

    #[must_use]
    pub fn container_image(&self) -> Option<&ImmutableIdentity> {
        self.container_image.as_ref()
    }

    #[must_use]
    pub fn environment(&self) -> &[(String, String)] {
        &self.environment
    }

    #[must_use]
    pub fn secret_references(&self) -> &[String] {
        &self.secret_references
    }

    #[must_use]
    pub fn filesystem_projections(&self) -> &[FilesystemProjection] {
        &self.filesystem_projections
    }

    #[must_use]
    pub fn endpoint_projections(&self) -> &[EndpointProjection] {
        &self.endpoint_projections
    }

    #[must_use]
    pub const fn output(&self) -> &OutputPlan {
        &self.output
    }

    #[must_use]
    pub const fn tty(&self) -> bool {
        self.tty
    }

    #[must_use]
    pub const fn terminal_size(&self) -> Option<TerminalSize> {
        self.terminal_size
    }

    #[must_use]
    pub const fn detached(&self) -> bool {
        self.detached
    }

    #[must_use]
    pub const fn daemon_failure_mode(&self) -> DaemonFailureMode {
        self.daemon_failure_mode
    }

    #[must_use]
    pub const fn loss_grace_seconds(&self) -> u64 {
        self.loss_grace_seconds
    }

    #[must_use]
    pub const fn root_configuration_generation(&self) -> u64 {
        self.root_configuration_generation
    }

    #[must_use]
    pub const fn created_at_unix_ms(&self) -> u64 {
        self.created_at_unix_ms
    }
}

fn validate_environment(environment: &[(String, String)]) -> Result<(), SessionSpecError> {
    let mut keys = BTreeSet::new();
    for (key, value) in environment {
        ensure!(
            !key.is_empty()
                && !key.starts_with('=')
                && key
                    .bytes()
                    .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
                && !value.contains('\0')
                && keys.insert(key.as_str()),
            InvalidSnafu {
                field: "session_spec.environment",
                reason: String::from("contains an unsafe or duplicate environment entry"),
            }
        );
    }
    Ok(())
}

fn is_safe_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn is_safe_component(value: &str) -> bool {
    is_safe_name(value) && value != "." && value != ".."
}

fn is_normalized_absolute(path: &Path) -> bool {
    let mut components = path.components();
    matches!(components.next(), Some(Component::RootDir))
        && components.all(|component| matches!(component, Component::Normal(_)))
}

#[cfg(test)]
mod tests {
    use std::{
        collections::{BTreeMap, BTreeSet},
        path::PathBuf,
    };

    use erebor_runtime_events::SessionId;

    use super::{
        ActiveSessionSignalKind, DaemonFailureMode, EvidenceRequirement, ImmutableIdentity,
        OutputPlan, OutputStreamRequirements, RunnerBinding, RunnerCapabilityDocument, RunnerId,
        RunnerRecovery, SafePathBinding, SafePathKind, SessionAdmission, SessionOwner, SessionSpec,
        WorkloadPrivilegePlan,
    };

    fn digest() -> String {
        String::from("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
    }

    fn capability() -> Result<RunnerCapabilityDocument, Box<dyn std::error::Error>> {
        RunnerCapabilityDocument::new(
            RunnerId::new("linux-host")?,
            "linux-host-v1",
            "1",
            "linux",
            "x86_64",
            true,
            true,
            BTreeSet::from([String::from("stdout"), String::from("stderr")]),
            BTreeSet::from([
                ActiveSessionSignalKind::Terminate,
                ActiveSessionSignalKind::Kill,
            ]),
            false,
            true,
            BTreeSet::from([DaemonFailureMode::Terminate, DaemonFailureMode::Continue]),
            BTreeMap::new(),
        )
        .map_err(Into::into)
    }

    fn path(
        value: &str,
        inode: u64,
        kind: SafePathKind,
    ) -> Result<SafePathBinding, Box<dyn std::error::Error>> {
        let binding = SafePathBinding::new(PathBuf::from(value), 1, inode, 1, 1000, 1000, kind)?;
        if kind == SafePathKind::Executable {
            return binding.with_content_sha256(digest()).map_err(Into::into);
        }
        Ok(binding)
    }

    fn admission(mode: DaemonFailureMode) -> Result<SessionAdmission, Box<dyn std::error::Error>> {
        Ok(SessionAdmission {
            session_id: SessionId::new("session-9f7b7f6e"),
            owner: SessionOwner::new(1000, 1000),
            workload_privileges: WorkloadPrivilegePlan::new(Vec::new(), 0o077, 1024, 512, 0)?,
            command: vec![String::from("/usr/bin/agent"), String::from("run")],
            package: Some(ImmutableIdentity::new("agent-package", digest())?),
            package_configuration: Some(ImmutableIdentity::new("agent-package-config", digest())?),
            installation: Some(ImmutableIdentity::new("installation", digest())?),
            adapter: Some(ImmutableIdentity::new("adapter", digest())?),
            policy_inputs: vec![ImmutableIdentity::new("root-policy", digest())?],
            policy_set: ImmutableIdentity::new("policy-set", digest())?,
            runner_capability: capability()?,
            workspace: path("/workspace", 2, SafePathKind::Directory)?,
            executable: Some(path("/usr/bin/agent", 3, SafePathKind::Executable)?),
            script_interpreters: Vec::new(),
            container_image: None,
            environment: vec![(String::from("LANG"), String::from("C"))],
            secret_references: vec![String::from("vault://session-token")],
            filesystem_projections: Vec::new(),
            endpoint_projections: Vec::new(),
            output: OutputPlan::new(
                PathBuf::from("/var/lib/erebor/users/1000/sessions/session-9f7b7f6e/output"),
                1024,
                512,
                64,
                OutputStreamRequirements::required(),
            )?,
            evidence_requirements: vec![EvidenceRequirement::new("audit", true)?],
            tty: false,
            terminal_size: None,
            detached: true,
            daemon_failure_mode: mode,
            loss_grace_seconds: 10,
            root_configuration_generation: 1,
            created_at_unix_ms: 1,
        })
    }

    #[test]
    fn session_spec_pins_immutable_admission_inputs() -> Result<(), Box<dyn std::error::Error>> {
        let spec = SessionSpec::new(admission(DaemonFailureMode::Terminate)?)?;

        assert_eq!(spec.session_id().as_str(), "session-9f7b7f6e");
        assert_eq!(spec.owner().uid(), 1000);
        assert!(spec
            .runner_capability()
            .supports_failure_mode(DaemonFailureMode::Continue));
        Ok(())
    }

    #[test]
    fn session_spec_rejects_unadmitted_daemon_failure_mode(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut admission = admission(DaemonFailureMode::Terminate)?;
        admission.daemon_failure_mode = DaemonFailureMode::ContinueIfEnforced;
        let result = SessionSpec::new(admission);

        assert!(result.is_err_and(|error| error.to_string().contains("not supported")));
        Ok(())
    }

    #[test]
    fn runner_binding_requires_an_opaque_versioned_recovery_value(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let binding = RunnerBinding::new(
            RunnerId::new("test-runner")?,
            "test-runner-v1",
            RunnerRecovery::new(3, r#"{"object":"runner-owned"}"#)?,
            1,
        )?;
        let round_trip: RunnerBinding = serde_json::from_str(&serde_json::to_string(&binding)?)?;

        assert_eq!(round_trip, binding);
        assert_eq!(round_trip.recovery().format_version(), 3);
        assert!(RunnerId::new("Invalid_Runner").is_err());
        assert!(RunnerRecovery::new(0, "payload").is_err());
        Ok(())
    }

    #[test]
    fn deserialized_session_spec_revalidates_nested_identity_and_path_owners(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let spec = SessionSpec::new(admission(DaemonFailureMode::Terminate)?)?;
        let mut encoded = serde_json::to_value(spec)?;
        encoded["workspace"]["requested_path"] = serde_json::json!("relative/workspace");
        encoded["policy_set"]["sha256"] =
            serde_json::json!("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
        encoded["workload_privileges"]["umask"] = serde_json::json!(1024);
        let decoded: SessionSpec = serde_json::from_value(encoded)?;

        assert!(decoded.validate().is_err());
        Ok(())
    }

    #[test]
    fn executable_binding_keeps_its_content_digest() -> Result<(), Box<dyn std::error::Error>> {
        let expected = digest();
        let binding =
            path("/usr/bin/agent", 3, SafePathKind::Executable)?.with_content_sha256(&expected)?;
        assert_eq!(binding.content_sha256(), Some(expected.as_str()));
        assert!(path("/usr/bin/agent", 3, SafePathKind::Executable)?
            .with_content_sha256("not-a-digest")
            .is_err());
        Ok(())
    }
}
