use erebor_runtime_core::{AgentAdapterDescriptor, AgentAdapterInvocationShape, SessionSpecError};
use erebor_runtime_packages::AgentPackageManifest;

use crate::agents::{AgentAdapter, PreparedAgentInvocation};

/// The compiled Codex adapter accepts only a package-selected entrypoint.
/// Daemon admission supplies that command after it resolves the local alias,
/// verified installation, and immutable release definition; raw session argv
/// never reaches this adapter for `codex-v1`.
pub(crate) struct CodexV1Adapter {
    descriptor: AgentAdapterDescriptor,
}

impl CodexV1Adapter {
    pub(crate) fn new() -> Result<Self, SessionSpecError> {
        Ok(Self {
            descriptor: AgentAdapterDescriptor::codex_v1()?,
        })
    }
}

impl AgentAdapter for CodexV1Adapter {
    fn descriptor(&self) -> &AgentAdapterDescriptor {
        &self.descriptor
    }

    fn validate_package(
        &self,
        package: &AgentPackageManifest,
        _daemon_version: &str,
    ) -> Result<(), SessionSpecError> {
        package
            .validate()
            .map_err(|error| SessionSpecError::invalid("agent_package", error.to_string()))?;
        if package.adapter_id() != self.descriptor.id()
            || package.adapter_digest().as_str() != self.descriptor.sha256()?
            || package.entrypoint() != ["codex", "codex-app-server"]
            || self.descriptor.invocation_shape() != AgentAdapterInvocationShape::PackageEntrypoint
        {
            return Err(SessionSpecError::invalid(
                "agent_package",
                "codex-v1 requires the compiled descriptor and its two certified package entrypoints",
            ));
        }
        Ok(())
    }

    fn prepare_invocation(
        &self,
        _package: &AgentPackageManifest,
        command: &[String],
    ) -> Result<PreparedAgentInvocation, SessionSpecError> {
        if command.is_empty()
            || command
                .iter()
                .any(|argument| argument.is_empty() || argument.contains('\0'))
        {
            return Err(SessionSpecError::invalid(
                "agent_adapter_invocation",
                "codex-v1 requires an exact non-empty daemon-selected argv",
            ));
        }
        Ok(PreparedAgentInvocation::exact(command.to_vec()))
    }
}
