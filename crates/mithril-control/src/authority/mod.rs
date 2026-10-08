mod model;
mod proof;

pub use model::*;
pub use proof::*;

use ed25519_dalek::VerifyingKey;

use crate::{AdministrativeApprovalOwner, ControlStore, Result};

pub struct AuthorityLeaseOwner {
    store: ControlStore,
}

impl AuthorityLeaseOwner {
    pub fn new(store: ControlStore, trust: AuthorityTrustV1) -> Result<Self> {
        trust.validate()?;
        store.update_authority(|state| {
            if state.trust.as_ref() == Some(&trust) {
                return Ok(false);
            }
            AuthorityErrorCodeV1::Conflict.require(
                state.trust.as_ref().is_none_or(|prior| {
                    prior.trust_domain_id == trust.trust_domain_id
                        && prior.revision < trust.revision
                }),
                "authority trust revision",
            )?;
            if let Some(prior) = &state.trust {
                AuthorityErrorCodeV1::Denied.require(
                    prior.issuers.iter().all(|old| {
                        trust
                            .issuers
                            .iter()
                            .filter(|new| {
                                new.issuer_id == old.issuer_id
                                    && new.sequence_epoch == old.sequence_epoch
                            })
                            .all(|new| new.key_id == old.key_id && new.public_key == old.public_key)
                    }),
                    "authority signing key epoch",
                )?;
            }
            state.trust = Some(trust);
            Ok(true)
        })?;
        Ok(Self { store })
    }

    pub fn request(&self, request: AuthorityLeaseRequestV1) -> Result<()> {
        request.validate()?;
        self.store.update_authority(|state| {
            if let Some(prior) = state.requests.get(&request.request_id) {
                AuthorityErrorCodeV1::Conflict
                    .require(prior == &request, "authority request retry")?;
                return Ok(false);
            }
            AuthorityErrorCodeV1::Unavailable.require(
                state.requests.len() < MAX_AUTHORITY_RECORDS,
                "authority request capacity",
            )?;
            state.requests.insert(request.request_id, request);
            Ok(true)
        })
    }

    /// The caller must authenticate the approver before this call.
    pub fn approve(
        &self,
        signer: &AdministrativeApprovalOwner,
        tenant: [u8; 16],
        request_id: [u8; 16],
        approver: [u8; 16],
        now: i64,
    ) -> Result<AuthorityApprovalV1> {
        let request = self.request_record(tenant, request_id)?;
        let state = self.store.authority_state()?;
        let trust = state
            .trust
            .as_ref()
            .ok_or_else(|| AuthorityErrorCodeV1::Unavailable.error("authority trust"))?;
        AuthorityErrorCodeV1::Denied
            .require(trust.approvers.contains(&approver), "authority approver")?;
        let signed = signer.sign_authority(&request, trust, now)?;
        self.accept(tenant, request_id, approver, &signed, now)
    }

    /// The caller must authenticate the approver before this call.
    pub fn accept(
        &self,
        tenant: [u8; 16],
        request_id: [u8; 16],
        approver: [u8; 16],
        signed: &[u8],
        now: i64,
    ) -> Result<AuthorityApprovalV1> {
        let envelope = SignedIntentEnvelopeV1::try_from(signed)?;
        let intent = AuthorityIntentPayloadV1::try_from(envelope.payload.as_slice())?;
        let mut result = None;
        self.store.update_authority(|state| {
            let request = state
                .requests
                .get(&request_id)
                .ok_or_else(|| AuthorityErrorCodeV1::Denied.error("authority request scope"))?;
            AuthorityErrorCodeV1::Denied.require(
                request.tenant_id == tenant
                    && intent.tenant_id == tenant
                    && request.body == intent.body.lease
                    && now >= request.requested_utc_ns
                    && intent.issued_utc_ns >= request.requested_utc_ns,
                "authority intent binding",
            )?;
            let trust = state
                .trust
                .as_ref()
                .ok_or_else(|| AuthorityErrorCodeV1::Unavailable.error("authority trust"))?;
            AuthorityErrorCodeV1::Denied
                .require(trust.approvers.contains(&approver), "authority approver")?;
            let issuer = trust.verify(&envelope, &intent, now)?;
            AuthorityErrorCodeV1::Replay.require(
                !state.approvals.contains_key(&request_id)
                    && !state.proofs.contains(&intent.proof_id)
                    && !state.slots.contains(&*intent.slots[0]),
                "authority proof or slot replay",
            )?;
            AuthorityErrorCodeV1::Unavailable.require(
                state.proofs.len() < MAX_AUTHORITY_RECORDS
                    && state.slots.len() < MAX_AUTHORITY_RECORDS
                    && state.windows.len() < 256,
                "authority replay capacity",
            )?;
            let replay = AuthorityReplayKeyV1 {
                trust_domain_id: intent.trust_domain_id,
                issuer_id: intent.issuer_id,
                key_id: issuer.key_id.clone(),
                sequence_epoch: intent.sequence_epoch,
            };
            state
                .windows
                .entry(replay)
                .or_default()
                .accept(intent.sequence)?;
            let approval = AuthorityApprovalV1 {
                request_id,
                tenant_id: tenant,
                approver_principal_id: approver,
                trust_revision: trust.revision,
                proof_id: intent.proof_id,
                claim_slot_id: *intent.slots[0],
                accepted_utc_ns: now,
                expires_utc_ns: intent.expires_utc_ns,
                signed_intent: signed.to_vec(),
                state: AuthorityIntentStateV1::Pending,
            };
            state.proofs.insert(intent.proof_id);
            state.slots.insert(*intent.slots[0]);
            state.approvals.insert(request_id, approval.clone());
            result = Some(approval);
            Ok(true)
        })?;
        result.ok_or_else(|| AuthorityErrorCodeV1::Unavailable.error("authority acceptance result"))
    }

    pub fn record_lease(&self, lease: CredentialLeaseV1, now: i64) -> Result<()> {
        lease.validate()?;
        self.store.update_authority(|state| {
            let request = state
                .requests
                .get(&lease.request_id)
                .ok_or_else(|| AuthorityErrorCodeV1::Denied.error("authority lease request"))?;
            let approval = state
                .approvals
                .get(&lease.request_id)
                .ok_or_else(|| AuthorityErrorCodeV1::Denied.error("authority lease approval"))?;
            state.current_approval(approval, now)?;
            AuthorityErrorCodeV1::Denied.require(
                lease.tenant_id == request.tenant_id
                    && lease.provider == request.body.provider
                    && lease.account == request.body.account
                    && lease.audience == request.body.audience
                    && lease.request_nonce == request.body.request_nonce
                    && lease
                        .permission_ids
                        .iter()
                        .all(|value| request.body.permission_ids.contains(value))
                    && lease
                        .resources
                        .iter()
                        .all(|value| request.body.resources.contains(value))
                    && lease.issued_utc_ns >= approval.accepted_utc_ns
                    && lease.expires_utc_ns <= approval.expires_utc_ns
                    && lease
                        .expires_utc_ns
                        .checked_sub(lease.issued_utc_ns)
                        .is_some_and(|ttl| {
                            u64::try_from(ttl).is_ok_and(|ttl| ttl <= request.body.maximum_ttl_ns)
                        }),
                "authority lease binding",
            )?;
            if let Some(prior) = state.leases.get(&lease.lease_id) {
                AuthorityErrorCodeV1::Conflict.require(prior == &lease, "authority lease retry")?;
                return Ok(false);
            }
            AuthorityErrorCodeV1::Unavailable.require(
                state.leases.len() < MAX_AUTHORITY_RECORDS,
                "authority lease capacity",
            )?;
            state.leases.insert(lease.lease_id, lease.clone());
            Ok(true)
        })
    }

    pub fn record_audit_handle(&self, handle: AuthorityAuditHandleV1) -> Result<()> {
        handle.validate()?;
        self.store.update_authority(|state| {
            let lease = state
                .leases
                .get(&handle.lease_id)
                .ok_or_else(|| AuthorityErrorCodeV1::Denied.error("authority audit lease"))?;
            AuthorityErrorCodeV1::Denied.require(
                lease.tenant_id == handle.tenant_id && lease.provider == handle.provider,
                "authority audit binding",
            )?;
            if let Some(prior) = state.handles.get(&handle.handle_id) {
                AuthorityErrorCodeV1::Conflict
                    .require(prior == &handle, "authority audit retry")?;
                return Ok(false);
            }
            AuthorityErrorCodeV1::Unavailable.require(
                state.handles.len() < MAX_AUTHORITY_RECORDS,
                "authority audit capacity",
            )?;
            state.handles.insert(handle.handle_id, handle);
            Ok(true)
        })
    }

    pub fn request_record(
        &self,
        tenant: [u8; 16],
        request_id: [u8; 16],
    ) -> Result<AuthorityLeaseRequestV1> {
        self.store
            .authority_state()?
            .requests
            .get(&request_id)
            .filter(|request| request.tenant_id == tenant)
            .cloned()
            .ok_or_else(|| AuthorityErrorCodeV1::Denied.error("authority request tenant"))
    }

    pub fn approval(
        &self,
        tenant: [u8; 16],
        request_id: [u8; 16],
        now: i64,
    ) -> Result<AuthorityApprovalV1> {
        let state = self.store.authority_state()?;
        let mut approval = state
            .approvals
            .get(&request_id)
            .filter(|approval| approval.tenant_id == tenant)
            .cloned()
            .ok_or_else(|| AuthorityErrorCodeV1::Denied.error("authority approval tenant"))?;
        if now >= approval.expires_utc_ns {
            approval.state = AuthorityIntentStateV1::Expired;
        }
        Ok(approval)
    }

    pub fn lease(
        &self,
        tenant: [u8; 16],
        lease_id: [u8; 16],
        now: i64,
    ) -> Result<CredentialLeaseV1> {
        let state = self.store.authority_state()?;
        let mut lease = state
            .leases
            .get(&lease_id)
            .filter(|lease| lease.tenant_id == tenant)
            .cloned()
            .ok_or_else(|| AuthorityErrorCodeV1::Denied.error("authority lease tenant"))?;
        if now >= lease.expires_utc_ns {
            lease.state = CredentialLeaseStateV1::Expired;
        }
        Ok(lease)
    }

    pub fn audit_handle(
        &self,
        tenant: [u8; 16],
        handle_id: [u8; 16],
    ) -> Result<AuthorityAuditHandleV1> {
        self.store
            .authority_state()?
            .handles
            .get(&handle_id)
            .filter(|handle| handle.tenant_id == tenant)
            .cloned()
            .ok_or_else(|| AuthorityErrorCodeV1::Denied.error("authority audit tenant"))
    }
}

impl AuthorityTrustV1 {
    pub fn validate(&self) -> Result<()> {
        AuthorityErrorCodeV1::Invalid.require(
            self.trust_domain_id != [0; 16]
                && self.revision > 0
                && (0..=300_000_000_000).contains(&self.maximum_clock_skew_ns)
                && (1..=256).contains(&self.issuers.len())
                && (1..=256).contains(&self.approvers.len())
                && self.approvers.iter().all(|id| *id != [0; 16])
                && self.approvers.windows(2).all(|pair| pair[0] < pair[1]),
            "authority trust",
        )?;
        let mut keys = std::collections::BTreeSet::new();
        for issuer in &self.issuers {
            AuthorityErrorCodeV1::Invalid.require(
                issuer.issuer_id != [0; 16]
                    && (1..=128).contains(&issuer.key_id.len())
                    && issuer.sequence_epoch > 0
                    && issuer.valid_from_utc_ns > 0
                    && issuer.valid_until_utc_ns > issuer.valid_from_utc_ns
                    && (1..=128).contains(&issuer.scopes.len())
                    && keys.insert((issuer.issuer_id, issuer.sequence_epoch)),
                "authority issuer",
            )?;
            VerifyingKey::from_bytes(&issuer.public_key)
                .map_err(|_| AuthorityErrorCodeV1::Invalid.error("authority issuer key"))?;
            for scope in &issuer.scopes {
                AuthorityErrorCodeV1::Invalid
                    .require(scope.tenant_id != [0; 16], "authority issuer tenant")?;
                AuthorityLeaseBodyV1 {
                    subject: scope.subject.clone(),
                    provider: scope.provider,
                    account: scope.account.clone(),
                    audience: scope.audience.clone(),
                    permission_ids: scope.permission_ids.clone(),
                    resources: scope.resources.clone(),
                    maximum_ttl_ns: scope.maximum_ttl_ns,
                    issuer_subject: scope.issuer_subject.clone(),
                    request_nonce: [1; 16],
                }
                .validate()?;
            }
        }
        Ok(())
    }

    fn verify<'a>(
        &'a self,
        envelope: &SignedIntentEnvelopeV1,
        intent: &AuthorityIntentPayloadV1,
        now: i64,
    ) -> Result<&'a AuthorityIssuerV1> {
        let issuer = self
            .issuers
            .iter()
            .find(|issuer| {
                issuer.issuer_id == intent.issuer_id
                    && issuer.key_id == envelope.key_id
                    && issuer.sequence_epoch == intent.sequence_epoch
            })
            .ok_or_else(|| AuthorityErrorCodeV1::Denied.error("authority trusted issuer"))?;
        AuthorityErrorCodeV1::Denied.require(
            !issuer.revoked
                && self.trust_domain_id == intent.trust_domain_id
                && issuer.sequence_epoch == intent.sequence_epoch
                && issuer
                    .scopes
                    .iter()
                    .any(|scope| scope.permits(intent.tenant_id, &intent.body.lease)),
            "authority issuer scope",
        )?;
        AuthorityErrorCodeV1::Expired.require(
            now > 0
                && now >= issuer.valid_from_utc_ns
                && now < issuer.valid_until_utc_ns
                && now < intent.expires_utc_ns
                && now
                    .checked_add(self.maximum_clock_skew_ns)
                    .is_some_and(|time| {
                        time >= intent.issued_utc_ns && time >= intent.not_before_utc_ns
                    }),
            "authority validity window",
        )?;
        let key = VerifyingKey::from_bytes(&issuer.public_key)
            .map_err(|_| AuthorityErrorCodeV1::Invalid.error("authority issuer key"))?;
        envelope.verify(&key)?;
        Ok(issuer)
    }
}

impl AuthorityStateV1 {
    fn current_approval(&self, approval: &AuthorityApprovalV1, now: i64) -> Result<()> {
        let trust = self
            .trust
            .as_ref()
            .ok_or_else(|| AuthorityErrorCodeV1::Unavailable.error("authority trust"))?;
        let envelope = SignedIntentEnvelopeV1::try_from(approval.signed_intent.as_slice())?;
        let intent = AuthorityIntentPayloadV1::try_from(envelope.payload.as_slice())?;
        trust.verify(&envelope, &intent, now)?;
        AuthorityErrorCodeV1::Denied.require(
            approval.trust_revision == trust.revision
                && trust.approvers.contains(&approval.approver_principal_id),
            "authority approval revision",
        )
    }
}

#[cfg(test)]
mod tests;
