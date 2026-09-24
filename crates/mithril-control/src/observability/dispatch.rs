use ed25519_dalek::{Signature, Signer as _, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::{DiscoveryDigestV1, Result, TraceAcceptedV1, TraceErrorCodeV1};

pub const MAX_TRACE_GRPC_MESSAGE_BYTES: usize = 8 * 1024 * 1024;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TraceResolveV1 {
    pub resolve_id: [u8; 16],
    pub facts: Vec<crate::WorkloadTargetFactV1>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum TraceParticipantStateV1 {
    Resolved,
    Denied,
    Disappeared,
    Unsupported,
    Failed,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TraceParticipantV1 {
    pub fact_digest: DiscoveryDigestV1,
    pub state: TraceParticipantStateV1,
    pub target: Option<crate::TraceTargetV1>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TraceResolvedV1 {
    pub resolve_id: [u8; 16],
    pub participants: Vec<TraceParticipantV1>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TraceUploadV1 {
    pub request_id: [u8; 16],
    pub target_index: u16,
    pub original_node_boot_id: [u8; 16],
    pub batch: crate::TraceBatchV1,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TraceAcknowledgementV1 {
    pub execution_id: [u8; 16],
    pub last_sequence: u64,
    pub terminal: Option<crate::TraceTerminalV1>,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TraceExchangeV1 {
    pub retained: Vec<[u8; 16]>,
    pub resolved: Option<TraceResolvedV1>,
    pub output: Option<TraceUploadV1>,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TraceExchangeReplyV1 {
    pub resolve: Option<TraceResolveV1>,
    pub dispatch: Option<TraceDispatchV1>,
    pub cancel: Vec<[u8; 16]>,
    pub acknowledgement: Option<TraceAcknowledgementV1>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TraceDispatchV1 {
    pub accepted: TraceAcceptedV1,
    pub target_index: u16,
    pub signing_key_id: String,
    pub issuer_epoch: u64,
    pub signature: Vec<u8>,
}

impl TraceDispatchV1 {
    pub fn sign(
        accepted: TraceAcceptedV1,
        target_index: u16,
        signing_key_id: String,
        issuer_epoch: u64,
        key: &SigningKey,
    ) -> Result<Self> {
        let mut dispatch = Self {
            accepted,
            target_index,
            signing_key_id,
            issuer_epoch,
            signature: Vec::new(),
        };
        dispatch.signature = key.sign(&dispatch.input()?.0).to_bytes().to_vec();
        Ok(dispatch)
    }

    fn input(&self) -> Result<DiscoveryDigestV1> {
        self.accepted.validate()?;
        self.accepted.execution_id(self.target_index)?;
        TraceErrorCodeV1::Invalid.require(
            !self.signing_key_id.is_empty()
                && self.signing_key_id.len() <= 128
                && self.issuer_epoch != 0,
            "trace signer identity is invalid",
        )?;
        DiscoveryDigestV1::of(&(
            "ARAPHOR-TRACE-DISPATCH-V1",
            &self.accepted,
            self.target_index,
            &self.signing_key_id,
            self.issuer_epoch,
        ))
    }

    pub fn verify(
        &self,
        key: &VerifyingKey,
        tenant: [u8; 16],
        node: &str,
        boot: [u8; 16],
        now: u64,
    ) -> Result<()> {
        let input = self.input()?;
        let target = &self.accepted.request.targets[self.target_index as usize];
        TraceErrorCodeV1::Denied.require(
            self.accepted.request.tenant_id == tenant
                && target.fact.node_id == node
                && target.node_boot_id == boot,
            "trace dispatch names another node lifetime",
        )?;
        TraceErrorCodeV1::Expired.require(
            now >= self.accepted.accepted_unix_ns && now < self.accepted.deadline_unix_ns,
            "trace execution lease is not current",
        )?;
        TraceErrorCodeV1::Denied.require(
            Signature::from_slice(&self.signature)
                .is_ok_and(|signature| key.verify_strict(&input.0, &signature).is_ok()),
            "trace execution signature is invalid",
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn observability_target_signed_lease_binds_complete_request_and_node(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let key = SigningKey::from_bytes(&[23; 32]);
        let accepted = TraceAcceptedV1 {
            request: super::super::owner::tests::request()?,
            grant: super::super::owner::tests::grant()?,
            approval: None,
            accepted_unix_ns: 1,
            deadline_unix_ns: 16_000_000_001,
            recipe: Some(crate::TraceRecipeV1::SyscallErrors),
        };
        let dispatch = TraceDispatchV1::sign(accepted, 0, "key".into(), 1, &key)?;
        dispatch.verify(&key.verifying_key(), [1; 16], "node-a", [2; 16], 2)?;
        assert!(dispatch
            .verify(&key.verifying_key(), [9; 16], "node-a", [2; 16], 2)
            .is_err());
        assert!(dispatch
            .verify(&key.verifying_key(), [1; 16], "node-a", [9; 16], 2)
            .is_err());
        assert!(dispatch
            .verify(
                &key.verifying_key(),
                [1; 16],
                "node-a",
                [2; 16],
                16_000_000_001
            )
            .is_err());
        let mut changed = dispatch;
        changed.accepted.request.targets[0].cgroup_id += 1;
        assert!(changed
            .verify(&key.verifying_key(), [1; 16], "node-a", [2; 16], 2)
            .is_err());
        Ok(())
    }
}
