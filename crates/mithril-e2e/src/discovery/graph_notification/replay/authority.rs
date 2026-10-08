use super::*;
use ed25519_dalek::SigningKey;
use mithril_control::{
    AdministrativeApprovalConfigV1, AdministrativeApprovalOwner, AuthorityAuditHandleV1,
    AuthorityErrorCodeV1, AuthorityIntentStateV1, AuthorityIssuerV1, AuthorityLeaseBodyV1,
    AuthorityLeaseOwner, AuthorityLeaseRequestV1, AuthorityResourceDigestV1, AuthorityResourceV1,
    AuthorityScopeV1, AuthorityTrustV1, ControlPlane, CredentialLeaseStateV1, CredentialLeaseV1,
    Error as ControlError, LocalAuthoritySubjectV1, ProviderAuthorityProofV1, ProviderV1,
    TrustGenerationV1,
};

pub(super) fn run(now: u64) -> std::result::Result<serde_json::Value, Box<dyn StdError>> {
    let root = tempfile::tempdir()?;
    let target_path = root.path().join("target-control");
    let now = i64::try_from(now)?;
    let body = AuthorityLeaseBodyV1 {
        subject: LocalAuthoritySubjectV1::Process {
            node_boot_id: [1; 16],
            execution_set_id: [2; 16],
            process_lineage_id: [3; 16],
        },
        provider: ProviderV1::Aws,
        account: b"recorded-account".to_vec(),
        audience: b"recorded-audience".to_vec(),
        permission_ids: vec![1, 2],
        resources: vec![AuthorityResourceV1 {
            resource_kind_id: 1,
            canonical_resource: b"recorded-resource".to_vec(),
            immutable_revision: Some(AuthorityResourceDigestV1 {
                algorithm: 1,
                sha256: [26; 32],
            }),
        }],
        maximum_ttl_ns: 1000,
        issuer_subject: b"recorded-broker".to_vec(),
        request_nonce: [4; 16],
    };
    let trust = AuthorityTrustV1 {
        trust_domain_id: [7; 16],
        revision: 1,
        maximum_clock_skew_ns: 0,
        approvers: vec![[8; 16]],
        issuers: vec![AuthorityIssuerV1 {
            issuer_id: [9; 16],
            key_id: b"key".to_vec(),
            public_key: SigningKey::from_bytes(&[10; 32]).verifying_key().to_bytes(),
            sequence_epoch: 1,
            valid_from_utc_ns: now - 100,
            valid_until_utc_ns: now + 10_000,
            revoked: false,
            scopes: vec![AuthorityScopeV1 {
                tenant_id: [5; 16],
                subject: body.subject.clone(),
                provider: body.provider,
                account: body.account.clone(),
                audience: body.audience.clone(),
                permission_ids: body.permission_ids.clone(),
                resources: body.resources.clone(),
                maximum_ttl_ns: body.maximum_ttl_ns,
                issuer_subject: body.issuer_subject.clone(),
            }],
        }],
    };
    let issuer = AuthorityLeaseOwner::new(
        ControlStore::open(root.path().join("issuer-control"))?,
        trust.clone(),
    )?;
    let owner = AuthorityLeaseOwner::new(ControlStore::open(&target_path)?, trust.clone())?;
    let request = AuthorityLeaseRequestV1 {
        schema_version: 1,
        request_id: [13; 16],
        tenant_id: [5; 16],
        requester_principal_id: [6; 16],
        requested_utc_ns: now - 10,
        body: body.clone(),
    };
    let key = root.path().join("key");
    fs::write(&key, "0a".repeat(32))?;
    let config = AdministrativeApprovalConfigV1 {
        state_directory: root.path().join("signer"),
        tenant_id: uuid::Uuid::from_bytes([5; 16]).to_string(),
        cluster_uid: uuid::Uuid::from_bytes([25; 16]).to_string(),
        trust_domain_id: uuid::Uuid::from_bytes([7; 16]).to_string(),
        issuer_id: uuid::Uuid::from_bytes([9; 16]).to_string(),
        key_id: "key".into(),
        private_key_path: key,
        sequence_epoch: 1,
        authorization_lifetime_seconds: 1,
    };
    let control = ControlPlane::new(
        vec![],
        TrustGenerationV1 {
            generation: 1,
            bundle_digest: "recorded-trust".into(),
            policy_issuer_sequence_epoch: 1,
            policy_signers: vec![],
        },
    );
    let signer = AdministrativeApprovalOwner::load(&config, control.clone())?;
    issuer.request(request.clone())?;
    let signed = issuer.approve(&signer, [5; 16], request.request_id, [8; 16], now)?;
    owner.request(request.clone())?;
    let approval = owner.accept(
        [5; 16],
        request.request_id,
        [8; 16],
        &signed.signed_intent,
        now,
    )?;
    assert_eq!(approval.state, AuthorityIntentStateV1::Pending);
    assert!(matches!(
        owner.accept(
            [5; 16],
            request.request_id,
            [8; 16],
            &approval.signed_intent,
            now
        ),
        Err(ControlError::Authority {
            code: AuthorityErrorCodeV1::Replay,
            ..
        })
    ));
    let mut variants = Vec::new();
    for (index, name) in [
        "foreign-tenant",
        "audience-retarget",
        "resource-retarget",
        "reboot",
        "expiry",
        "unapproved-principal",
        "signature-tamper",
    ]
    .into_iter()
    .enumerate()
    {
        let id = u8::try_from(30 + index)?;
        let mut issued_request = request.clone();
        issued_request.request_id = [id; 16];
        issued_request.body.request_nonce = [id; 16];
        issuer.request(issued_request.clone())?;
        let fresh = issuer.approve(&signer, [5; 16], issued_request.request_id, [8; 16], now)?;
        assert_ne!(fresh.proof_id, approval.proof_id);
        assert_ne!(fresh.claim_slot_id, approval.claim_slot_id);
        let mut changed = issued_request;
        match name {
            "audience-retarget" => changed.body.audience = b"other-audience".to_vec(),
            "resource-retarget" => {
                changed.body.resources[0].immutable_revision = Some(AuthorityResourceDigestV1 {
                    algorithm: 1,
                    sha256: [27; 32],
                })
            }
            "reboot" => {
                changed.body.subject = LocalAuthoritySubjectV1::Process {
                    node_boot_id: [27; 16],
                    execution_set_id: [2; 16],
                    process_lineage_id: [3; 16],
                }
            }
            _ => {}
        }
        owner.request(changed.clone())?;
        let mut signed = fresh.signed_intent;
        if name == "signature-tamper" {
            let byte = signed.last_mut().ok_or("signed envelope is absent")?;
            *byte ^= 1;
        }
        let expected = if name == "expiry" {
            AuthorityErrorCodeV1::Expired
        } else {
            AuthorityErrorCodeV1::Denied
        };
        let rejected = owner.accept(
            if name == "foreign-tenant" {
                [99; 16]
            } else {
                [5; 16]
            },
            changed.request_id,
            if name == "unapproved-principal" {
                [99; 16]
            } else {
                [8; 16]
            },
            &signed,
            if name == "expiry" { now + 1000 } else { now },
        );
        assert!(
            matches!(rejected, Err(ControlError::Authority { code, .. }) if code == expected),
            "{name}"
        );
        variants.push(
            json!({"input": name, "result": "REJECTED", "error_code": expected,
            "fresh_proof": fresh.proof_id, "provider_issuance": "UNQUALIFIED"}),
        );
    }
    owner.record_lease(
        CredentialLeaseV1 {
            schema_version: 1,
            lease_id: [23; 16],
            request_id: request.request_id,
            tenant_id: [5; 16],
            provider: body.provider,
            account: body.account.clone(),
            audience: body.audience.clone(),
            provider_principal: b"recorded-principal".to_vec(),
            public_session_id: b"recorded-session".to_vec(),
            permission_ids: vec![1],
            resources: body.resources.clone(),
            request_nonce: body.request_nonce,
            issued_utc_ns: now,
            expires_utc_ns: now + 500,
            provider_proof: ProviderAuthorityProofV1::Missing,
            state: CredentialLeaseStateV1::Unknown,
        },
        now + 1,
    )?;
    owner.record_audit_handle(AuthorityAuditHandleV1 {
        schema_version: 1,
        handle_id: [24; 16],
        lease_id: [23; 16],
        tenant_id: [5; 16],
        provider: body.provider,
        provider_request_id: b"recorded-provider-request".to_vec(),
        provider_result_id: b"recorded-provider-result".to_vec(),
        public_audit_id: b"recorded-public-audit".to_vec(),
    })?;
    assert_eq!(
        owner.lease([5; 16], [23; 16], now + 1)?.state,
        CredentialLeaseStateV1::Unknown
    );
    assert_eq!(
        owner.approval([5; 16], request.request_id, now + 1)?.state,
        AuthorityIntentStateV1::Pending
    );
    drop(owner);
    drop(signer);
    let owner = AuthorityLeaseOwner::new(ControlStore::open(&target_path)?, trust)?;
    assert!(matches!(
        owner.accept(
            [5; 16],
            request.request_id,
            [8; 16],
            &approval.signed_intent,
            now + 1
        ),
        Err(ControlError::Authority {
            code: AuthorityErrorCodeV1::Replay,
            ..
        })
    ));
    assert_eq!(owner.audit_handle([5; 16], [24; 16])?.lease_id, [23; 16]);
    let signer = AdministrativeApprovalOwner::load(&config, control)?;
    let mut next = request;
    next.request_id = [40; 16];
    next.body.request_nonce = [41; 16];
    issuer.request(next.clone())?;
    let signed = issuer.approve(&signer, [5; 16], next.request_id, [8; 16], now + 1)?;
    owner.request(next.clone())?;
    let after = owner.accept(
        [5; 16],
        next.request_id,
        [8; 16],
        &signed.signed_intent,
        now + 1,
    )?;
    assert_ne!(approval.proof_id, after.proof_id);
    assert_eq!(
        owner
            .approval([5; 16], approval.request_id, now + 1000)?
            .state,
        AuthorityIntentStateV1::Expired
    );
    Ok(
        json!({"result": "PASS", "signed_approval": approval, "restart_approval": after,
        "variants": variants, "control_store_reopened": true, "replay_rejected_after_restart": true,
        "lease_state": "UNKNOWN", "provider_issuance": "UNQUALIFIED", "local_kernel_grant": false}),
    )
}
