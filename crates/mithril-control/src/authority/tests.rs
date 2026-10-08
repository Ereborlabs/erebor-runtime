use ed25519_dalek::SigningKey;

use super::*;

mod replay;

type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;

fn body() -> AuthorityLeaseBodyV1 {
    AuthorityLeaseBodyV1 {
        subject: LocalAuthoritySubjectV1::Process {
            node_boot_id: [1; 16],
            execution_set_id: [2; 16],
            process_lineage_id: [3; 16],
        },
        provider: crate::ProviderV1::Aws,
        account: b"account".to_vec(),
        audience: b"audience".to_vec(),
        permission_ids: vec![1, 2],
        resources: vec![AuthorityResourceV1 {
            resource_kind_id: 1,
            canonical_resource: b"resource".to_vec(),
            immutable_revision: None,
        }],
        maximum_ttl_ns: 1000,
        issuer_subject: b"broker".to_vec(),
        request_nonce: [4; 16],
    }
}
fn request(id: u8) -> AuthorityLeaseRequestV1 {
    AuthorityLeaseRequestV1 {
        schema_version: 1,
        request_id: [id; 16],
        tenant_id: [5; 16],
        requester_principal_id: [6; 16],
        requested_utc_ns: 10,
        body: body(),
    }
}
fn trust() -> AuthorityTrustV1 {
    let body = body();
    AuthorityTrustV1 {
        trust_domain_id: [7; 16],
        revision: 1,
        maximum_clock_skew_ns: 0,
        approvers: vec![[8; 16]],
        issuers: vec![AuthorityIssuerV1 {
            issuer_id: [9; 16],
            key_id: b"key".to_vec(),
            public_key: SigningKey::from_bytes(&[10; 32]).verifying_key().to_bytes(),
            sequence_epoch: 1,
            valid_from_utc_ns: 1,
            valid_until_utc_ns: 10_000,
            revoked: false,
            scopes: vec![AuthorityScopeV1 {
                tenant_id: [5; 16],
                subject: body.subject,
                provider: body.provider,
                account: body.account,
                audience: body.audience,
                permission_ids: body.permission_ids,
                resources: body.resources,
                maximum_ttl_ns: 1000,
                issuer_subject: body.issuer_subject,
            }],
        }],
    }
}
fn payload(sequence: u64) -> AuthorityIntentPayloadV1 {
    AuthorityIntentPayloadV1 {
        version: 1,
        kind: 3,
        proof_id: [11; 16],
        tenant_id: [5; 16],
        trust_domain_id: [7; 16],
        issuer_id: [9; 16],
        sequence_epoch: 1,
        sequence,
        issued_utc_ns: 100,
        not_before_utc_ns: 100,
        expires_utc_ns: 1000,
        slots: vec![minicbor::bytes::ByteArray::from([12; 16])],
        body: AuthorityIntentBodyV1 {
            tag: 3,
            lease: body(),
        },
        parent: None,
        triggers: None,
    }
}
fn signed(payload: &AuthorityIntentPayloadV1) -> Result<Vec<u8>> {
    SignedIntentEnvelopeV1::sign(
        &payload.bytes()?,
        b"key",
        &SigningKey::from_bytes(&[10; 32]),
    )
}

#[test]
fn control_authority_exact_signed_scope_and_approver_are_required() -> TestResult {
    let dir = tempfile::tempdir()?;
    let store = ControlStore::open(dir.path())?;
    let owner = AuthorityLeaseOwner::new(store.clone(), trust())?;
    owner.request(request(13))?;
    let before = store.commit_index();
    assert!(owner
        .accept([6; 16], [13; 16], [8; 16], &signed(&payload(1))?, 100)
        .is_err());
    assert!(owner
        .accept([5; 16], [13; 16], [14; 16], &signed(&payload(1))?, 100)
        .is_err());
    let mut wrong = payload(1);
    wrong.body.lease.audience = b"other".to_vec();
    assert!(owner
        .accept([5; 16], [13; 16], [8; 16], &signed(&wrong)?, 100)
        .is_err());
    wrong = payload(1);
    wrong.issuer_id = [14; 16];
    assert!(owner
        .accept([5; 16], [13; 16], [8; 16], &signed(&wrong)?, 100)
        .is_err());
    wrong = payload(1);
    wrong.sequence_epoch = 2;
    assert!(owner
        .accept([5; 16], [13; 16], [8; 16], &signed(&wrong)?, 100)
        .is_err());
    for field in 0..6 {
        wrong = payload(1);
        match field {
            0 => wrong.body.lease.account = b"other account".to_vec(),
            1 => {
                wrong.body.lease.subject = LocalAuthoritySubjectV1::Process {
                    node_boot_id: [2; 16],
                    execution_set_id: [2; 16],
                    process_lineage_id: [3; 16],
                }
            }
            2 => wrong.body.lease.permission_ids = vec![1, 3],
            3 => wrong.body.lease.resources[0].canonical_resource = b"other resource".to_vec(),
            4 => wrong.body.lease.maximum_ttl_ns = 1001,
            _ => wrong.body.lease.request_nonce = [26; 16],
        }
        assert!(owner
            .accept([5; 16], [13; 16], [8; 16], &signed(&wrong)?, 100)
            .is_err());
    }
    wrong = payload(1);
    wrong.issued_utc_ns = 9;
    wrong.not_before_utc_ns = 9;
    assert!(owner
        .accept([5; 16], [13; 16], [8; 16], &signed(&wrong)?, 100)
        .is_err());
    let other_key = SignedIntentEnvelopeV1::sign(
        &payload(1).bytes()?,
        b"other",
        &SigningKey::from_bytes(&[10; 32]),
    )?;
    assert!(owner
        .accept([5; 16], [13; 16], [8; 16], &other_key, 100)
        .is_err());
    let wrong_signature = SignedIntentEnvelopeV1::sign(
        &payload(1).bytes()?,
        b"key",
        &SigningKey::from_bytes(&[15; 32]),
    )?;
    assert!(owner
        .accept([5; 16], [13; 16], [8; 16], &wrong_signature, 100)
        .is_err());
    assert!(owner
        .accept([5; 16], [13; 16], [8; 16], &signed(&payload(1))?, 1000)
        .is_err());
    assert_eq!(store.commit_index(), before);
    let accepted = owner.accept([5; 16], [13; 16], [8; 16], &signed(&payload(1))?, 100)?;
    assert_eq!(accepted.state, AuthorityIntentStateV1::Pending);
    assert_eq!(accepted.trust_revision, 1);
    assert!(owner.approval([6; 16], [13; 16], 101).is_err());
    assert_eq!(
        owner.approval([5; 16], [13; 16], 1000)?.state,
        AuthorityIntentStateV1::Expired
    );
    Ok(())
}

#[test]
fn control_authority_proof_slot_and_sequence_replay_survive_restart() -> TestResult {
    let dir = tempfile::tempdir()?;
    {
        let store = ControlStore::open(dir.path())?;
        let owner = AuthorityLeaseOwner::new(store, trust())?;
        owner.request(request(13))?;
        owner.accept([5; 16], [13; 16], [8; 16], &signed(&payload(100))?, 100)?;
    }
    let store = ControlStore::open(dir.path())?;
    let owner = AuthorityLeaseOwner::new(store.clone(), trust())?;
    for id in [14, 15, 16, 17] {
        owner.request(request(id))?;
    }
    assert!(owner
        .accept([5; 16], [14; 16], [8; 16], &signed(&payload(101))?, 100)
        .is_err());
    let mut replay = payload(101);
    replay.proof_id = [18; 16];
    assert!(owner
        .accept([5; 16], [15; 16], [8; 16], &signed(&replay)?, 100)
        .is_err());
    replay.slots = vec![minicbor::bytes::ByteArray::from([19; 16])];
    replay.sequence = 100;
    assert!(owner
        .accept([5; 16], [16; 16], [8; 16], &signed(&replay)?, 100)
        .is_err());
    replay.sequence = 99;
    owner.accept([5; 16], [17; 16], [8; 16], &signed(&replay)?, 100)?;
    let mut revoked = trust();
    revoked.revision = 2;
    revoked.issuers[0].revoked = true;
    let revoked = AuthorityLeaseOwner::new(store.clone(), revoked)?;
    revoked.request(request(20))?;
    replay.proof_id = [21; 16];
    replay.slots = vec![minicbor::bytes::ByteArray::from([22; 16])];
    replay.sequence = 102;
    assert!(revoked
        .accept([5; 16], [20; 16], [8; 16], &signed(&replay)?, 100)
        .is_err());
    assert!(AuthorityLeaseOwner::new(store, trust()).is_err());
    Ok(())
}

#[test]
fn control_authority_unknown_lease_has_no_provider_issuance_or_execution_grant() -> TestResult {
    let dir = tempfile::tempdir()?;
    let owner = AuthorityLeaseOwner::new(ControlStore::open(dir.path())?, trust())?;
    owner.request(request(13))?;
    owner.accept([5; 16], [13; 16], [8; 16], &signed(&payload(1))?, 100)?;
    let mut lease = CredentialLeaseV1 {
        schema_version: 1,
        lease_id: [23; 16],
        request_id: [13; 16],
        tenant_id: [5; 16],
        provider: crate::ProviderV1::Aws,
        account: b"account".to_vec(),
        audience: b"audience".to_vec(),
        provider_principal: b"principal".to_vec(),
        public_session_id: b"public session".to_vec(),
        permission_ids: vec![1],
        resources: body().resources,
        request_nonce: [4; 16],
        issued_utc_ns: 100,
        expires_utc_ns: 500,
        provider_proof: ProviderAuthorityProofV1::Missing,
        state: CredentialLeaseStateV1::Unknown,
    };
    let mut unbound = lease.clone();
    unbound.audience = b"other".to_vec();
    assert!(owner.record_lease(unbound, 101).is_err());
    lease.state = CredentialLeaseStateV1::Active;
    assert!(owner.record_lease(lease.clone(), 101).is_err());
    lease.state = CredentialLeaseStateV1::Unknown;
    owner.record_lease(lease, 101)?;
    assert_eq!(
        owner.approval([5; 16], [13; 16], 101)?.state,
        AuthorityIntentStateV1::Pending
    );
    assert_eq!(
        owner.lease([5; 16], [23; 16], 101)?.provider_proof,
        ProviderAuthorityProofV1::Missing
    );
    assert_eq!(
        owner.lease([5; 16], [23; 16], 500)?.state,
        CredentialLeaseStateV1::Expired
    );
    let handle = AuthorityAuditHandleV1 {
        schema_version: 1,
        handle_id: [24; 16],
        lease_id: [23; 16],
        tenant_id: [5; 16],
        provider: crate::ProviderV1::Aws,
        provider_request_id: b"request".to_vec(),
        provider_result_id: b"result".to_vec(),
        public_audit_id: b"public audit".to_vec(),
    };
    owner.record_audit_handle(handle.clone())?;
    assert_eq!(owner.audit_handle([5; 16], [24; 16])?, handle);
    assert!(owner.audit_handle([6; 16], [24; 16]).is_err());
    Ok(())
}

#[test]
fn control_authority_administrative_sequence_owner_signs_neutral_records() -> TestResult {
    let dir = tempfile::tempdir()?;
    let key_path = dir.path().join("key");
    std::fs::write(&key_path, hex::encode([10; 32]))?;
    let config = crate::AdministrativeApprovalConfigV1 {
        state_directory: dir.path().join("signer"),
        tenant_id: uuid::Uuid::from_bytes([5; 16]).to_string(),
        cluster_uid: uuid::Uuid::from_bytes([25; 16]).to_string(),
        trust_domain_id: uuid::Uuid::from_bytes([7; 16]).to_string(),
        issuer_id: uuid::Uuid::from_bytes([9; 16]).to_string(),
        key_id: "key".into(),
        private_key_path: key_path,
        sequence_epoch: 1,
        authorization_lifetime_seconds: 1,
    };
    let control = crate::ControlPlane::new(
        vec![],
        crate::TrustGenerationV1 {
            generation: 1,
            bundle_digest: "test".into(),
            policy_issuer_sequence_epoch: 1,
            policy_signers: vec![],
        },
    );
    let first = crate::AdministrativeApprovalOwner::load(&config, control.clone())?;
    let signed = first.sign_authority(&request(13), &trust(), 100)?;
    let envelope = SignedIntentEnvelopeV1::try_from(signed.as_slice())?;
    assert_eq!(
        AuthorityIntentPayloadV1::try_from(envelope.payload.as_slice())?.sequence,
        1
    );
    drop(first);
    let second = crate::AdministrativeApprovalOwner::load(&config, control)?;
    let signed = second.sign_authority(&request(14), &trust(), 101)?;
    let envelope = SignedIntentEnvelopeV1::try_from(signed.as_slice())?;
    assert_eq!(
        AuthorityIntentPayloadV1::try_from(envelope.payload.as_slice())?.sequence,
        2
    );
    Ok(())
}

#[test]
fn control_authority_key_rotation_requires_a_new_sequence_epoch() -> TestResult {
    let dir = tempfile::tempdir()?;
    let store = ControlStore::open(dir.path())?;
    let owner = AuthorityLeaseOwner::new(store.clone(), trust())?;
    owner.request(request(13))?;
    owner.accept([5; 16], [13; 16], [8; 16], &signed(&payload(1))?, 100)?;
    let mut rotated = trust();
    rotated.revision = 2;
    rotated.issuers[0].key_id = b"rotated".to_vec();
    rotated.issuers[0].public_key = SigningKey::from_bytes(&[27; 32]).verifying_key().to_bytes();
    assert!(AuthorityLeaseOwner::new(store.clone(), rotated.clone()).is_err());
    rotated.issuers[0].sequence_epoch = 2;
    let rotated = AuthorityLeaseOwner::new(store, rotated)?;
    rotated.request(request(14))?;
    let mut next = payload(1);
    next.sequence_epoch = 2;
    next.proof_id = [28; 16];
    next.slots = vec![minicbor::bytes::ByteArray::from([29; 16])];
    let signed = SignedIntentEnvelopeV1::sign(
        &next.bytes()?,
        b"rotated",
        &SigningKey::from_bytes(&[27; 32]),
    )?;
    rotated.accept([5; 16], [14; 16], [8; 16], &signed, 100)?;
    Ok(())
}
