use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use snafu::ensure;

use crate::{error::session_spec::InvalidSnafu, SessionSpecError};

pub const AGENT_ADAPTER_DESCRIPTOR_SCHEMA_VERSION: u32 = 1;

/// Immutable facts about an adapter compiled into Erebor.
///
/// This descriptor is deliberately data-only: a package selects an already
/// compiled implementation by digest and cannot name code for `erebord` to
/// load or execute.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentAdapterDescriptor {
    schema_version: u32,
    id: String,
    invocation_shape: AgentAdapterInvocationShape,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentAdapterInvocationShape {
    ArbitraryInitialArgv,
}

impl AgentAdapterDescriptor {
    pub fn new(
        id: impl Into<String>,
        invocation_shape: AgentAdapterInvocationShape,
    ) -> Result<Self, SessionSpecError> {
        let descriptor = Self {
            schema_version: AGENT_ADAPTER_DESCRIPTOR_SCHEMA_VERSION,
            id: id.into(),
            invocation_shape,
        };
        descriptor.validate()?;
        Ok(descriptor)
    }

    pub fn generic_process_v1() -> Result<Self, SessionSpecError> {
        Self::new(
            "generic-process-v1",
            AgentAdapterInvocationShape::ArbitraryInitialArgv,
        )
    }

    pub fn validate(&self) -> Result<(), SessionSpecError> {
        ensure!(
            self.schema_version == AGENT_ADAPTER_DESCRIPTOR_SCHEMA_VERSION
                && Self::is_identifier(&self.id),
            InvalidSnafu {
                field: "agent_adapter_descriptor",
                reason: String::from("has an unsupported schema version or unsafe identifier"),
            }
        );
        Ok(())
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, SessionSpecError> {
        serde_json::to_vec(self).map_err(|error| {
            InvalidSnafu {
                field: "agent_adapter_descriptor",
                reason: format!("cannot encode canonical descriptor: {error}"),
            }
            .build()
        })
    }

    pub fn sha256(&self) -> Result<String, SessionSpecError> {
        Ok(format!("{:x}", Sha256::digest(self.canonical_bytes()?)))
    }

    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    #[must_use]
    pub const fn invocation_shape(&self) -> AgentAdapterInvocationShape {
        self.invocation_shape
    }

    fn is_identifier(value: &str) -> bool {
        !value.is_empty()
            && value.bytes().all(|byte| {
                byte.is_ascii_lowercase()
                    || byte.is_ascii_digit()
                    || matches!(byte, b'.' | b'-' | b'_')
            })
    }
}

#[cfg(test)]
mod tests {
    use super::{AgentAdapterDescriptor, AgentAdapterInvocationShape};

    #[test]
    fn generic_adapter_descriptor_has_a_stable_identity() -> Result<(), Box<dyn std::error::Error>>
    {
        let descriptor = AgentAdapterDescriptor::new(
            "generic-process-v1",
            AgentAdapterInvocationShape::ArbitraryInitialArgv,
        )?;
        assert_eq!(descriptor.sha256()?, descriptor.sha256()?);
        assert!(AgentAdapterDescriptor::new(
            "invalid adapter",
            AgentAdapterInvocationShape::ArbitraryInitialArgv,
        )
        .is_err());
        Ok(())
    }
}
