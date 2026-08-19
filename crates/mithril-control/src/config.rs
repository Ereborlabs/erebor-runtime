use std::collections::BTreeSet;
use std::fs;
use std::net::SocketAddr;
use std::path::Path;
use std::path::PathBuf;

use serde::Deserialize;
use snafu::{ensure, ResultExt as _};

use crate::error::{InvalidConfigurationSnafu, IoSnafu, JsonSnafu};
use crate::{
    AdministrativeHttpConfigV1, AllowedNodeIdentity, ControlPlane, ControlServerTls, Result,
    TrustGenerationV1,
};

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControlConfig {
    pub listen: SocketAddr,
    pub tls: ControlServerTls,
    pub allowed_nodes: Vec<AllowedNodeIdentity>,
    pub trust: TrustGenerationV1,
    pub administrative_exec: Option<AdministrativeHttpConfigV1>,
    pub evidence_directory: PathBuf,
}

impl ControlConfig {
    pub fn load(path: &Path) -> Result<Self> {
        let bytes = fs::read(path).context(IoSnafu { path })?;
        let config: Self = serde_json::from_slice(&bytes).context(JsonSnafu { path })?;
        config.validate()?;
        Ok(config)
    }

    pub fn into_parts(
        self,
    ) -> Result<(
        SocketAddr,
        ControlServerTls,
        ControlPlane,
        Option<AdministrativeHttpConfigV1>,
    )> {
        let control = ControlPlane::with_evidence_directory(
            self.allowed_nodes,
            self.trust,
            self.evidence_directory,
        )?;
        Ok((self.listen, self.tls, control, self.administrative_exec))
    }

    fn validate(&self) -> Result<()> {
        ensure!(
            !self.allowed_nodes.is_empty(),
            InvalidConfigurationSnafu {
                reason: "allowed_nodes must not be empty",
            }
        );
        ensure!(
            self.evidence_directory.is_absolute(),
            InvalidConfigurationSnafu {
                reason: "evidence_directory must be absolute",
            }
        );
        ensure!(
            self.trust.generation > 0 && is_sha256_hex(&self.trust.bundle_digest),
            InvalidConfigurationSnafu {
                reason: "trust generation must be nonzero and its digest must be SHA-256 hex",
            }
        );
        let mut node_ids = BTreeSet::new();
        for identity in &self.allowed_nodes {
            ensure!(
                !identity.node_id.is_empty()
                    && !identity.node_id.chars().any(char::is_whitespace)
                    && is_sha256_hex(&identity.certificate_sha256)
                    && node_ids.insert(identity.node_id.as_str()),
                InvalidConfigurationSnafu {
                    reason: "every node needs a unique clean ID and lowercase certificate SHA-256 digest",
                }
            );
        }
        if let Some(config) = &self.administrative_exec {
            config.validate()?;
        }
        Ok(())
    }
}

fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}
