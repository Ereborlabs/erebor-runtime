use crate::error::DecommissionSnafu;
use crate::{Result, SignatureAlgorithmV1};
use ed25519_dalek::{Signature, Signer as _, SigningKey, Verifier as _, VerifyingKey};
use minicbor::{Decoder, Encoder};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

const DECOMMISSION_SIGNATURE_DOMAIN: &[u8] = b"MITHRIL-NODE-DECOMMISSION-V1\0";
pub const MAX_DECOMMISSION_ARTIFACT_BYTES: usize = 4_096;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeDecommissionAuthorizationV1 {
    pub cluster_uid: [u8; 16],
    pub node_id: String,
    pub node_boot_id: [u8; 16],
    pub expires_at_utc_ns: i64,
    pub nonce: [u8; 16],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedNodeDecommissionV1 {
    pub schema_version: u32,
    pub signing_key_id: String,
    pub algorithm: SignatureAlgorithmV1,
    pub canonical_payload: Vec<u8>,
    pub signature: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum NodeDecommissionStateV1 {
    Submitted,
    Accepted,
    Quarantined,
    Completed,
    Rejected,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct StoredNodeDecommissionV1 {
    pub(crate) artifact: Vec<u8>,
    pub(crate) state: NodeDecommissionStateV1,
    pub(crate) reason_code: String,
}

impl StoredNodeDecommissionV1 {
    pub(crate) fn digest(&self) -> [u8; 32] {
        Sha256::digest(&self.artifact).into()
    }

    pub(crate) fn authorization(&self) -> Result<NodeDecommissionAuthorizationV1> {
        SignedNodeDecommissionV1::parse(&self.artifact)
            .map(|(_envelope, authorization)| authorization)
    }
}

impl NodeDecommissionAuthorizationV1 {
    pub fn new(
        cluster_uid: &str,
        node_id: String,
        node_boot_id: &str,
        expires_at_utc_ns: i64,
        nonce: &str,
    ) -> Result<Self> {
        let authorization = Self {
            cluster_uid: canonical_uuid(cluster_uid, "cluster UID")?,
            node_id,
            node_boot_id: canonical_uuid(node_boot_id, "node boot ID")?,
            expires_at_utc_ns,
            nonce: canonical_uuid(nonce, "nonce")?,
        };
        authorization.validate()?;
        Ok(authorization)
    }

    pub fn canonical_payload(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let mut bytes = Vec::with_capacity(96);
        let mut encoder = Encoder::new(&mut bytes);
        encoder
            .array(5)
            .and_then(|encoder| encoder.bytes(&self.cluster_uid))
            .and_then(|encoder| encoder.str(&self.node_id))
            .and_then(|encoder| encoder.bytes(&self.node_boot_id))
            .and_then(|encoder| encoder.i64(self.expires_at_utc_ns))
            .and_then(|encoder| encoder.bytes(&self.nonce))
            .map_err(|error| decommission_error(format!("encode canonical payload: {error}")))?;
        Ok(bytes)
    }

    fn decode(bytes: &[u8]) -> Result<Self> {
        let mut decoder = Decoder::new(bytes);
        if decoder
            .array()
            .map_err(|error| decommission_error(format!("decode payload array: {error}")))?
            != Some(5)
        {
            return DecommissionSnafu {
                reason: "canonical payload must contain five fields",
            }
            .fail();
        }
        let authorization = Self {
            cluster_uid: exact_id(&mut decoder, "cluster UID")?,
            node_id: decoder
                .str()
                .map_err(|error| decommission_error(format!("decode node ID: {error}")))?
                .to_owned(),
            node_boot_id: exact_id(&mut decoder, "node boot ID")?,
            expires_at_utc_ns: decoder
                .i64()
                .map_err(|error| decommission_error(format!("decode expiry: {error}")))?,
            nonce: exact_id(&mut decoder, "nonce")?,
        };
        if decoder.position() != bytes.len() || authorization.canonical_payload()? != bytes {
            return DecommissionSnafu {
                reason: "decommission payload is not canonical",
            }
            .fail();
        }
        Ok(authorization)
    }

    fn validate(&self) -> Result<()> {
        if self.cluster_uid == [0; 16]
            || self.node_boot_id == [0; 16]
            || self.nonce == [0; 16]
            || !crate::node_id_is_valid(&self.node_id)
            || self.expires_at_utc_ns <= 0
        {
            return DecommissionSnafu {
                reason: "decommission target, expiry, or nonce is invalid",
            }
            .fail();
        }
        Ok(())
    }
}

impl SignedNodeDecommissionV1 {
    pub fn sign(
        authorization: &NodeDecommissionAuthorizationV1,
        signing_key_id: String,
        key: &SigningKey,
    ) -> Result<Self> {
        if signing_key_id.is_empty() || signing_key_id.len() > 128 {
            return DecommissionSnafu {
                reason: "decommission signing key ID is invalid",
            }
            .fail();
        }
        let canonical_payload = authorization.canonical_payload()?;
        Ok(Self {
            schema_version: 1,
            signing_key_id,
            algorithm: SignatureAlgorithmV1::Ed25519,
            signature: key
                .sign(&signature_input(&canonical_payload))
                .to_bytes()
                .to_vec(),
            canonical_payload,
        })
    }

    pub fn parse(artifact: &[u8]) -> Result<(Self, NodeDecommissionAuthorizationV1)> {
        if artifact.is_empty() || artifact.len() > MAX_DECOMMISSION_ARTIFACT_BYTES {
            return DecommissionSnafu {
                reason: "decommission artifact exceeds its byte limit",
            }
            .fail();
        }
        let mut decoder = Decoder::new(artifact);
        if decoder
            .array()
            .map_err(|error| decommission_error(format!("decode envelope array: {error}")))?
            != Some(5)
        {
            return DecommissionSnafu {
                reason: "decommission envelope must contain five fields",
            }
            .fail();
        }
        let schema_version = decoder
            .u32()
            .map_err(|error| decommission_error(format!("decode schema version: {error}")))?;
        let signing_key_id = decoder
            .str()
            .map_err(|error| decommission_error(format!("decode signing key ID: {error}")))?
            .to_owned();
        let algorithm = match decoder
            .u8()
            .map_err(|error| decommission_error(format!("decode signature algorithm: {error}")))?
        {
            1 => SignatureAlgorithmV1::Ed25519,
            _ => {
                return DecommissionSnafu {
                    reason: "decommission signature algorithm is invalid",
                }
                .fail()
            }
        };
        let canonical_payload = decoder
            .bytes()
            .map_err(|error| decommission_error(format!("decode canonical payload: {error}")))?
            .to_vec();
        let signature = decoder
            .bytes()
            .map_err(|error| decommission_error(format!("decode signature: {error}")))?
            .to_vec();
        let envelope = Self {
            schema_version,
            signing_key_id,
            algorithm,
            canonical_payload,
            signature,
        };
        if envelope.schema_version != 1
            || envelope.algorithm != SignatureAlgorithmV1::Ed25519
            || envelope.signing_key_id.is_empty()
            || envelope.signing_key_id.len() > 128
            || envelope.signature.len() != 64
            || envelope.canonical_payload.len() > 512
            || decoder.position() != artifact.len()
            || envelope.to_bytes()? != artifact
        {
            return DecommissionSnafu {
                reason: "decommission envelope is invalid or outside its bounds",
            }
            .fail();
        }
        let authorization = NodeDecommissionAuthorizationV1::decode(&envelope.canonical_payload)?;
        Ok((envelope, authorization))
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut artifact = Vec::with_capacity(256);
        Encoder::new(&mut artifact)
            .array(5)
            .and_then(|encoder| encoder.u32(self.schema_version))
            .and_then(|encoder| encoder.str(&self.signing_key_id))
            .and_then(|encoder| encoder.u8(1))
            .and_then(|encoder| encoder.bytes(&self.canonical_payload))
            .and_then(|encoder| encoder.bytes(&self.signature))
            .map_err(|error| decommission_error(format!("encode artifact: {error}")))?;
        Ok(artifact)
    }

    pub fn verify(&self, key: &VerifyingKey) -> Result<NodeDecommissionAuthorizationV1> {
        let authorization = NodeDecommissionAuthorizationV1::decode(&self.canonical_payload)?;
        let signature = Signature::from_slice(&self.signature)
            .map_err(|error| decommission_error(format!("decode signature: {error}")))?;
        key.verify(&signature_input(&self.canonical_payload), &signature)
            .map_err(|error| decommission_error(format!("verify signature: {error}")))?;
        Ok(authorization)
    }
}

fn signature_input(payload: &[u8]) -> Vec<u8> {
    let mut input = Vec::with_capacity(DECOMMISSION_SIGNATURE_DOMAIN.len() + payload.len());
    input.extend_from_slice(DECOMMISSION_SIGNATURE_DOMAIN);
    input.extend_from_slice(payload);
    input
}

fn exact_id(decoder: &mut Decoder<'_>, name: &str) -> Result<[u8; 16]> {
    decoder
        .bytes()
        .map_err(|error| decommission_error(format!("decode {name}: {error}")))?
        .try_into()
        .map_err(|_| decommission_error(format!("{name} is not 16 bytes")))
}

fn canonical_uuid(value: &str, name: &str) -> Result<[u8; 16]> {
    let uuid = uuid::Uuid::parse_str(value)
        .map_err(|error| decommission_error(format!("{name} is invalid: {error}")))?;
    if uuid.hyphenated().to_string() != value || uuid.is_nil() {
        return DecommissionSnafu {
            reason: format!("{name} is not a canonical nonzero UUID"),
        }
        .fail();
    }
    Ok(*uuid.as_bytes())
}

fn decommission_error(reason: String) -> crate::Error {
    DecommissionSnafu { reason }.build()
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::SigningKey;

    use super::{NodeDecommissionAuthorizationV1, SignedNodeDecommissionV1};

    fn authorization() -> crate::Result<NodeDecommissionAuthorizationV1> {
        NodeDecommissionAuthorizationV1::new(
            "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
            "node-a".to_owned(),
            "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
            9_000_000_000,
            "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
        )
    }

    #[test]
    fn signed_decommission_round_trips_the_five_canonical_fields() -> crate::Result<()> {
        let key = SigningKey::from_bytes(&[7; 32]);
        let signed = SignedNodeDecommissionV1::sign(
            &authorization()?,
            "offline-decommission-v1".to_owned(),
            &key,
        )?;
        let artifact = signed.to_bytes()?;
        let (parsed, target) = SignedNodeDecommissionV1::parse(&artifact)?;
        assert_eq!(target, authorization()?);
        assert_eq!(parsed.verify(&key.verifying_key())?, target);
        Ok(())
    }

    #[test]
    fn changed_payload_or_wrong_key_is_rejected() -> crate::Result<()> {
        let key = SigningKey::from_bytes(&[7; 32]);
        let mut signed = SignedNodeDecommissionV1::sign(
            &authorization()?,
            "offline-decommission-v1".to_owned(),
            &key,
        )?;
        signed.canonical_payload[1] ^= 1;
        assert!(signed.verify(&key.verifying_key()).is_err());

        let signed = SignedNodeDecommissionV1::sign(
            &authorization()?,
            "offline-decommission-v1".to_owned(),
            &key,
        )?;
        assert!(signed
            .verify(&SigningKey::from_bytes(&[8; 32]).verifying_key())
            .is_err());
        Ok(())
    }
}
