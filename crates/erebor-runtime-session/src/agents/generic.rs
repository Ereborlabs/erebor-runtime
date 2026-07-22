use std::{collections::BTreeMap, sync::Arc};

use erebor_runtime_core::{AgentAdapterDescriptor, AgentAdapterInvocationShape, SessionSpecError};
use erebor_runtime_packages::AgentPackageManifest;

/// The narrow compiled-adapter seam used by daemon admission.
///
/// An adapter is selected from Erebor's compiled registry. It receives only
/// immutable package data and argv, so a package cannot load code or create a
/// daemon-side plugin process.
pub trait AgentAdapter: Send + Sync {
    fn descriptor(&self) -> &AgentAdapterDescriptor;

    fn validate_package(
        &self,
        package: &AgentPackageManifest,
        daemon_version: &str,
    ) -> Result<(), SessionSpecError>;

    fn prepare_invocation(
        &self,
        package: &AgentPackageManifest,
        command: &[String],
    ) -> Result<PreparedAgentInvocation, SessionSpecError>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreparedAgentInvocation {
    command: Vec<String>,
}

impl PreparedAgentInvocation {
    pub(crate) fn exact(command: Vec<String>) -> Self {
        Self { command }
    }

    #[must_use]
    pub fn command(&self) -> &[String] {
        &self.command
    }
}

/// The daemon-owned lookup table for adapter implementations compiled into
/// this binary.
pub struct AgentAdapterRegistry {
    adapters: BTreeMap<String, Arc<dyn AgentAdapter>>,
}

impl AgentAdapterRegistry {
    pub fn compiled() -> Result<Self, SessionSpecError> {
        let generic = GenericProcessAdapter::new()?;
        let codex = super::codex::CodexV1Adapter::new()?;
        Ok(Self {
            adapters: BTreeMap::from([
                (
                    generic.descriptor().id().to_owned(),
                    Arc::new(generic) as Arc<dyn AgentAdapter>,
                ),
                (
                    codex.descriptor().id().to_owned(),
                    Arc::new(codex) as Arc<dyn AgentAdapter>,
                ),
            ]),
        })
    }

    pub fn prepare(
        &self,
        package: &AgentPackageManifest,
        daemon_version: &str,
        command: &[String],
    ) -> Result<PreparedAgentInvocation, SessionSpecError> {
        let adapter = self.adapters.get(package.adapter_id()).ok_or_else(|| {
            SessionSpecError::invalid(
                "agent_adapter",
                format!(
                    "package selects unknown compiled adapter `{}`",
                    package.adapter_id()
                ),
            )
        })?;
        adapter.validate_package(package, daemon_version)?;
        adapter.prepare_invocation(package, command)
    }

    pub fn descriptor(&self, id: &str) -> Option<&AgentAdapterDescriptor> {
        self.adapters.get(id).map(|adapter| adapter.descriptor())
    }
}

struct GenericProcessAdapter {
    descriptor: AgentAdapterDescriptor,
}

impl GenericProcessAdapter {
    fn new() -> Result<Self, SessionSpecError> {
        Ok(Self {
            descriptor: AgentAdapterDescriptor::generic_process_v1()?,
        })
    }

    fn daemon_version_is_compatible(
        &self,
        package: &AgentPackageManifest,
        daemon_version: &str,
    ) -> Result<bool, SessionSpecError> {
        Ok(Self::parse_version(daemon_version, "daemon version")?
            >= Self::parse_version(package.minimum_daemon_version(), "package minimum")?)
    }

    fn parse_version(value: &str, field: &'static str) -> Result<[u64; 3], SessionSpecError> {
        let components = value.split('.').collect::<Vec<_>>();
        if components.len() != 3 {
            return Err(SessionSpecError::invalid(
                "agent_adapter_version",
                format!("{field} `{value}` must be a three-component numeric version"),
            ));
        }
        let mut parsed = [0_u64; 3];
        for (slot, component) in parsed.iter_mut().zip(components) {
            *slot = component.parse().map_err(|_error| {
                SessionSpecError::invalid(
                    "agent_adapter_version",
                    format!("{field} `{value}` must be a three-component numeric version"),
                )
            })?;
        }
        Ok(parsed)
    }
}

impl AgentAdapter for GenericProcessAdapter {
    fn descriptor(&self) -> &AgentAdapterDescriptor {
        &self.descriptor
    }

    fn validate_package(
        &self,
        package: &AgentPackageManifest,
        daemon_version: &str,
    ) -> Result<(), SessionSpecError> {
        package
            .validate()
            .map_err(|error| SessionSpecError::invalid("agent_package", error.to_string()))?;
        let arbitrary_argv = package.entrypoint().len() == 1
            && package
                .entrypoint()
                .first()
                .is_some_and(|entrypoint| entrypoint == "<argv>");
        if package.adapter_id() != self.descriptor.id()
            || package.adapter_digest().as_str() != self.descriptor.sha256()?
            || !arbitrary_argv
            || !package.support_layer_digests().is_empty()
            || !self.daemon_version_is_compatible(package, daemon_version)?
        {
            return Err(SessionSpecError::invalid(
                "agent_package",
                "generic-process-v1 requires its compiled descriptor, an arbitrary-argv entrypoint, no support layers, and a compatible daemon version",
            ));
        }
        Ok(())
    }

    fn prepare_invocation(
        &self,
        package: &AgentPackageManifest,
        command: &[String],
    ) -> Result<PreparedAgentInvocation, SessionSpecError> {
        let arbitrary_argv = package.entrypoint().len() == 1
            && package
                .entrypoint()
                .first()
                .is_some_and(|entrypoint| entrypoint == "<argv>");
        if self.descriptor.invocation_shape() != AgentAdapterInvocationShape::ArbitraryInitialArgv
            || !arbitrary_argv
            || command.is_empty()
            || command.iter().any(|argument| argument.contains('\0'))
        {
            return Err(SessionSpecError::invalid(
                "agent_adapter_invocation",
                "generic-process-v1 requires one non-empty initial argv",
            ));
        }
        Ok(PreparedAgentInvocation::exact(command.to_vec()))
    }
}

#[cfg(test)]
mod tests {
    use erebor_runtime_core::AgentAdapterDescriptor;
    use erebor_runtime_packages::{AgentPackageManifest, ContentDigest};

    use super::AgentAdapterRegistry;

    fn package() -> Result<AgentPackageManifest, Box<dyn std::error::Error>> {
        let descriptor = AgentAdapterDescriptor::generic_process_v1()?;
        Ok(AgentPackageManifest::new(
            "generic-process",
            "generic-process-v1",
            "0.1.0",
            vec![String::from("<argv>")],
            ContentDigest::new(descriptor.sha256()?)?,
            Vec::new(),
        )?)
    }

    #[test]
    fn compiled_registry_only_admits_its_immutable_generic_descriptor(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let registry = AgentAdapterRegistry::compiled()?;
        let package = package()?;
        assert_eq!(
            registry
                .prepare(&package, "0.1.0", &[String::from("id")])?
                .command(),
            &[String::from("id")]
        );
        assert!(registry
            .prepare(&package, "0.0.9", &[String::from("id")])
            .is_err());
        Ok(())
    }
}
