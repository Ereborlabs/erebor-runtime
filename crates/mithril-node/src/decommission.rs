use std::fs::{self, File, OpenOptions};
use std::io::Write as _;
use std::path::{Path, PathBuf};

use ed25519_dalek::VerifyingKey;
use erebor_interceptor_abi::Id128V1;
use minicbor::{Decoder, Encoder};
use sha2::{Digest as _, Sha256};
use snafu::ResultExt as _;

use crate::error::{AuthorizationSnafu, IoSnafu};
use crate::{NodeDecommissionConfig, Result};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NodeDecommissionAcceptanceV1 {
    Accepted,
    ResumeCleanup,
    Completed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DurableDecommissionStateV1 {
    Accepted,
    Completed,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct DurableDecommissionV1 {
    node_id: String,
    nonce: [u8; 16],
    artifact_sha256: [u8; 32],
    state: DurableDecommissionStateV1,
}

pub struct NodeDecommissionOwner {
    path: PathBuf,
    node_id: String,
    node_boot_id: [u8; 16],
    cluster_uid: [u8; 16],
    signing_key_id: String,
    verifying_key: VerifyingKey,
    durable: Option<DurableDecommissionV1>,
}

impl NodeDecommissionOwner {
    pub fn durable_completion(state_directory: &Path) -> Result<bool> {
        let path = state_directory.join("node-decommission-v1.cbor");
        match fs::read(&path) {
            Ok(bytes) => Ok(DurableDecommissionV1::decode(&bytes)?.state
                == DurableDecommissionStateV1::Completed),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(source) => Err(crate::Error::Io {
                path,
                source,
                location: snafu::Location::default(),
            }),
        }
    }

    pub fn load(
        config: &NodeDecommissionConfig,
        state_directory: &Path,
        node_id: String,
        node_boot_id: Id128V1,
    ) -> Result<Self> {
        fs::create_dir_all(state_directory).context(IoSnafu {
            path: state_directory,
        })?;
        let path = state_directory.join("node-decommission-v1.cbor");
        let durable = match fs::read(&path) {
            Ok(bytes) => Some(DurableDecommissionV1::decode(&bytes)?),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(source) => {
                return Err(crate::Error::Io {
                    path,
                    source,
                    location: snafu::Location::default(),
                })
            }
        };
        if durable
            .as_ref()
            .is_some_and(|state| state.node_id != node_id)
        {
            return AuthorizationSnafu {
                reason: "decommission state belongs to another stable node",
            }
            .fail();
        }
        let cluster_uid = canonical_uuid(&config.cluster_uid, "cluster UID")?;
        let verifying_key = VerifyingKey::from_bytes(&read_key(&config.public_key_path)?)
            .map_err(|error| authorization_error(format!("decommission public key: {error}")))?;
        Ok(Self {
            path,
            node_id,
            node_boot_id: node_boot_id.to_be_bytes(),
            cluster_uid,
            signing_key_id: config.signing_key_id.clone(),
            verifying_key,
            durable,
        })
    }

    pub fn accept(
        &mut self,
        artifact: &[u8],
        live_runtime_bindings: usize,
        now_utc_ns: i64,
    ) -> Result<NodeDecommissionAcceptanceV1> {
        let (envelope, authorization) = mithril_control::SignedNodeDecommissionV1::parse(artifact)
            .map_err(|error| authorization_error(error.to_string()))?;
        if envelope.signing_key_id != self.signing_key_id {
            return AuthorizationSnafu {
                reason: "decommission artifact names an untrusted key",
            }
            .fail();
        }
        let verified = envelope
            .verify(&self.verifying_key)
            .map_err(|error| authorization_error(error.to_string()))?;
        if verified != authorization
            || authorization.cluster_uid != self.cluster_uid
            || authorization.node_id != self.node_id
            || authorization.node_boot_id != self.node_boot_id
            || now_utc_ns < 0
            || now_utc_ns >= authorization.expires_at_utc_ns
        {
            return AuthorizationSnafu {
                reason: "decommission artifact target or expiry does not match this node boot",
            }
            .fail();
        }
        let artifact_sha256: [u8; 32] = Sha256::digest(artifact).into();
        if let Some(durable) = &self.durable {
            if durable.nonce != authorization.nonce || durable.artifact_sha256 != artifact_sha256 {
                return AuthorizationSnafu {
                    reason: "decommission nonce was already consumed by another artifact",
                }
                .fail();
            }
            if durable.state == DurableDecommissionStateV1::Accepted && live_runtime_bindings != 0 {
                return AuthorizationSnafu {
                    reason: "decommission is blocked by a live protected runtime binding",
                }
                .fail();
            }
            return Ok(match durable.state {
                DurableDecommissionStateV1::Accepted => NodeDecommissionAcceptanceV1::ResumeCleanup,
                DurableDecommissionStateV1::Completed => NodeDecommissionAcceptanceV1::Completed,
            });
        }
        if live_runtime_bindings != 0 {
            return AuthorizationSnafu {
                reason: "decommission is blocked by a live protected runtime binding",
            }
            .fail();
        }
        let durable = DurableDecommissionV1 {
            node_id: self.node_id.clone(),
            nonce: authorization.nonce,
            artifact_sha256,
            state: DurableDecommissionStateV1::Accepted,
        };
        self.replace(&durable)?;
        self.durable = Some(durable);
        Ok(NodeDecommissionAcceptanceV1::Accepted)
    }

    pub fn complete(&mut self, artifact: &[u8]) -> Result<()> {
        let artifact_sha256: [u8; 32] = Sha256::digest(artifact).into();
        let mut durable = self.durable.clone().ok_or_else(|| {
            AuthorizationSnafu {
                reason: "decommission cleanup has no durable accepted authorization".to_owned(),
            }
            .build()
        })?;
        if durable.artifact_sha256 != artifact_sha256 {
            return AuthorizationSnafu {
                reason: "decommission completion names another artifact",
            }
            .fail();
        }
        if durable.state == DurableDecommissionStateV1::Completed {
            return Ok(());
        }
        durable.state = DurableDecommissionStateV1::Completed;
        self.replace(&durable)?;
        self.durable = Some(durable);
        Ok(())
    }

    #[must_use]
    pub fn completed(&self) -> bool {
        self.durable
            .as_ref()
            .is_some_and(|state| state.state == DurableDecommissionStateV1::Completed)
    }

    #[must_use]
    pub fn accepted_artifact_sha256(&self) -> Option<[u8; 32]> {
        self.durable.as_ref().map(|state| state.artifact_sha256)
    }

    fn replace(&self, state: &DurableDecommissionV1) -> Result<()> {
        use std::os::unix::fs::OpenOptionsExt as _;

        let bytes = state.encode()?;
        let temporary = self.path.with_extension("tmp");
        let mut file = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .mode(0o600)
            .open(&temporary)
            .context(IoSnafu { path: &temporary })?;
        file.write_all(&bytes)
            .and_then(|()| file.sync_all())
            .context(IoSnafu { path: &temporary })?;
        fs::rename(&temporary, &self.path).context(IoSnafu { path: &self.path })?;
        File::open(self.path.parent().ok_or_else(|| {
            authorization_error("decommission state has no parent directory".to_owned())
        })?)
        .and_then(|directory| directory.sync_all())
        .context(IoSnafu { path: &self.path })
    }
}

impl DurableDecommissionV1 {
    fn encode(&self) -> Result<Vec<u8>> {
        let mut bytes = Vec::with_capacity(96);
        Encoder::new(&mut bytes)
            .array(5)
            .and_then(|encoder| encoder.u8(1))
            .and_then(|encoder| encoder.str(&self.node_id))
            .and_then(|encoder| encoder.bytes(&self.nonce))
            .and_then(|encoder| encoder.bytes(&self.artifact_sha256))
            .and_then(|encoder| {
                encoder.u8(match self.state {
                    DurableDecommissionStateV1::Accepted => 1,
                    DurableDecommissionStateV1::Completed => 2,
                })
            })
            .map_err(|error| authorization_error(format!("encode decommission state: {error}")))?;
        Ok(bytes)
    }

    fn decode(bytes: &[u8]) -> Result<Self> {
        let mut decoder = Decoder::new(bytes);
        let count = decoder
            .array()
            .map_err(|error| authorization_error(format!("decode state array: {error}")))?;
        let version = decoder
            .u8()
            .map_err(|error| authorization_error(format!("decode state version: {error}")))?;
        if count != Some(5) || version != 1 {
            return AuthorizationSnafu {
                reason: "decommission state schema is invalid",
            }
            .fail();
        }
        let state = Self {
            node_id: decoder
                .str()
                .map_err(|error| authorization_error(format!("decode state node: {error}")))?
                .to_owned(),
            nonce: exact_bytes(&mut decoder, "state nonce")?,
            artifact_sha256: exact_bytes(&mut decoder, "state artifact digest")?,
            state: match decoder
                .u8()
                .map_err(|error| authorization_error(format!("decode state value: {error}")))?
            {
                1 => DurableDecommissionStateV1::Accepted,
                2 => DurableDecommissionStateV1::Completed,
                _ => {
                    return AuthorizationSnafu {
                        reason: "decommission durable state is invalid",
                    }
                    .fail()
                }
            },
        };
        if decoder.position() != bytes.len()
            || !mithril_control::node_id_is_valid(&state.node_id)
            || state.nonce == [0; 16]
            || state.artifact_sha256 == [0; 32]
            || state.encode()? != bytes
        {
            return AuthorizationSnafu {
                reason: "decommission state is not canonical",
            }
            .fail();
        }
        Ok(state)
    }
}

fn exact_bytes<const N: usize>(decoder: &mut Decoder<'_>, name: &str) -> Result<[u8; N]> {
    decoder
        .bytes()
        .map_err(|error| authorization_error(format!("decode {name}: {error}")))?
        .try_into()
        .map_err(|_| authorization_error(format!("{name} is not {N} bytes")))
}

fn read_key(path: &Path) -> Result<[u8; 32]> {
    let bytes = fs::read(path).context(IoSnafu { path })?;
    if bytes.len() == 32 {
        return bytes
            .try_into()
            .map_err(|_| authorization_error("decommission key is not 32 bytes".to_owned()));
    }
    let text = std::str::from_utf8(&bytes)
        .map_err(|error| authorization_error(format!("decommission key is not UTF-8: {error}")))?
        .trim();
    let decoded = hex::decode(text)
        .map_err(|error| authorization_error(format!("decommission key is not hex: {error}")))?;
    decoded
        .try_into()
        .map_err(|_| authorization_error("decommission key is not 32 bytes".to_owned()))
}

fn canonical_uuid(value: &str, name: &str) -> Result<[u8; 16]> {
    let uuid = uuid::Uuid::parse_str(value)
        .map_err(|error| authorization_error(format!("{name} is invalid: {error}")))?;
    if uuid.hyphenated().to_string() != value || uuid.is_nil() {
        return AuthorizationSnafu {
            reason: format!("{name} is not a canonical nonzero UUID"),
        }
        .fail();
    }
    Ok(*uuid.as_bytes())
}

fn authorization_error(reason: String) -> crate::Error {
    AuthorizationSnafu { reason }.build()
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::SigningKey;
    use erebor_interceptor_abi::Id128V1;
    use tempfile::TempDir;

    use super::{NodeDecommissionAcceptanceV1, NodeDecommissionOwner};
    use crate::NodeDecommissionConfig;

    const CLUSTER: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
    const BOOT: &str = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
    const NONCE: &str = "cccccccc-cccc-4ccc-8ccc-cccccccccccc";

    fn config(directory: &TempDir, key: &SigningKey) -> crate::Result<NodeDecommissionConfig> {
        let public_key_path = directory.path().join("public-key");
        std::fs::write(&public_key_path, key.verifying_key().to_bytes()).map_err(|source| {
            crate::Error::Io {
                path: public_key_path.clone(),
                source,
                location: snafu::Location::default(),
            }
        })?;
        Ok(NodeDecommissionConfig {
            cluster_uid: CLUSTER.to_owned(),
            signing_key_id: "offline-decommission-v1".to_owned(),
            public_key_path,
            runtime_integration_owner: "mithril-system/mithril".to_owned(),
            runtime_hook_directory: directory.path().join("hooks"),
            containerd_config_directory: directory.path().join("containerd"),
            containerd_drop_in_directory: "conf.d".to_owned(),
            runtime_services: vec!["containerd".to_owned()],
        })
    }

    fn artifact(
        key: &SigningKey,
        cluster: &str,
        node: &str,
        boot: &str,
        expiry: i64,
        nonce: &str,
    ) -> crate::Result<Vec<u8>> {
        let authorization = mithril_control::NodeDecommissionAuthorizationV1::new(
            cluster,
            node.to_owned(),
            boot,
            expiry,
            nonce,
        )
        .map_err(|error| super::authorization_error(error.to_string()))?;
        mithril_control::SignedNodeDecommissionV1::sign(
            &authorization,
            "offline-decommission-v1".to_owned(),
            key,
        )
        .and_then(|artifact| artifact.to_bytes())
        .map_err(|error| super::authorization_error(error.to_string()))
    }

    fn boot_id() -> Id128V1 {
        let value = uuid::Uuid::parse_str(BOOT).map_or(0, |uuid| uuid.as_u128());
        Id128V1::new((value >> 64) as u64, value as u64)
    }

    #[test]
    fn exact_authorization_is_durable_and_resumes_after_restart() -> crate::Result<()> {
        let directory = TempDir::new().map_err(|source| crate::Error::Io {
            path: "temporary decommission directory".into(),
            source,
            location: snafu::Location::default(),
        })?;
        let key = SigningKey::from_bytes(&[7; 32]);
        let config = config(&directory, &key)?;
        let artifact = artifact(&key, CLUSTER, "node-a", BOOT, 20, NONCE)?;
        let mut owner =
            NodeDecommissionOwner::load(&config, directory.path(), "node-a".to_owned(), boot_id())?;
        assert_eq!(
            owner.accept(&artifact, 0, 10)?,
            NodeDecommissionAcceptanceV1::Accepted
        );
        assert!(!NodeDecommissionOwner::durable_completion(
            directory.path()
        )?);
        let mut restarted =
            NodeDecommissionOwner::load(&config, directory.path(), "node-a".to_owned(), boot_id())?;
        assert!(restarted.accept(&artifact, 1, 10).is_err());
        assert_eq!(
            restarted.accept(&artifact, 0, 10)?,
            NodeDecommissionAcceptanceV1::ResumeCleanup
        );
        restarted.complete(&artifact)?;
        assert!(restarted.completed());
        assert!(NodeDecommissionOwner::durable_completion(directory.path())?);
        assert_eq!(
            restarted.accept(&artifact, 0, 10)?,
            NodeDecommissionAcceptanceV1::Completed
        );
        Ok(())
    }

    #[test]
    fn wrong_target_expiry_nonce_key_and_live_binding_are_rejected() -> crate::Result<()> {
        let cases = [
            (
                "wrong_cluster",
                "dddddddd-dddd-4ddd-8ddd-dddddddddddd",
                "node-a",
                BOOT,
                20,
                NONCE,
                0,
            ),
            ("wrong_node", CLUSTER, "node-b", BOOT, 20, NONCE, 0),
            (
                "wrong_boot",
                CLUSTER,
                "node-a",
                "dddddddd-dddd-4ddd-8ddd-dddddddddddd",
                20,
                NONCE,
                0,
            ),
            ("expired", CLUSTER, "node-a", BOOT, 10, NONCE, 0),
            ("live_binding", CLUSTER, "node-a", BOOT, 20, NONCE, 1),
        ];
        for (name, cluster, node, boot, expiry, nonce, bindings) in cases {
            let directory = TempDir::new().map_err(|source| crate::Error::Io {
                path: format!("temporary decommission directory for {name}").into(),
                source,
                location: snafu::Location::default(),
            })?;
            let key = SigningKey::from_bytes(&[7; 32]);
            let config = config(&directory, &key)?;
            let mut owner = NodeDecommissionOwner::load(
                &config,
                directory.path(),
                "node-a".to_owned(),
                boot_id(),
            )?;
            assert!(
                owner
                    .accept(
                        &artifact(&key, cluster, node, boot, expiry, nonce)?,
                        bindings,
                        10,
                    )
                    .is_err(),
                "{name}"
            );
        }

        let directory = TempDir::new().map_err(|source| crate::Error::Io {
            path: "temporary wrong-key directory".into(),
            source,
            location: snafu::Location::default(),
        })?;
        let trusted = SigningKey::from_bytes(&[7; 32]);
        let config = config(&directory, &trusted)?;
        let mut owner =
            NodeDecommissionOwner::load(&config, directory.path(), "node-a".to_owned(), boot_id())?;
        assert!(owner
            .accept(
                &artifact(
                    &SigningKey::from_bytes(&[8; 32]),
                    CLUSTER,
                    "node-a",
                    BOOT,
                    20,
                    NONCE,
                )?,
                0,
                10,
            )
            .is_err());
        Ok(())
    }

    #[test]
    fn consumed_nonce_cannot_name_another_signed_artifact() -> crate::Result<()> {
        let directory = TempDir::new().map_err(|source| crate::Error::Io {
            path: "temporary nonce directory".into(),
            source,
            location: snafu::Location::default(),
        })?;
        let key = SigningKey::from_bytes(&[7; 32]);
        let config = config(&directory, &key)?;
        let mut owner =
            NodeDecommissionOwner::load(&config, directory.path(), "node-a".to_owned(), boot_id())?;
        owner.accept(&artifact(&key, CLUSTER, "node-a", BOOT, 20, NONCE)?, 0, 10)?;
        assert!(owner
            .accept(&artifact(&key, CLUSTER, "node-a", BOOT, 30, NONCE)?, 0, 10)
            .is_err());
        Ok(())
    }
}
