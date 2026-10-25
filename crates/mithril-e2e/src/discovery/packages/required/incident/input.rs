use erebor_interceptor_abi::{
    EffectObservationReasonV1, EffectObservationV1, EffectPhysicalResultV1,
};

pub(super) fn events(mut denied: EffectObservationV1) -> [EffectObservationV1; 2] {
    denied.observed_boottime_ns = 101;
    denied.source_sequence = 1;
    denied.source_cpu_id = 3;
    denied.task_cookie = 7;
    denied.process_instance_id = [8; 16].into();
    denied.entry_instance_id = [9; 16].into();
    denied.reason = EffectObservationReasonV1::ExactPolicyDeny as u8;
    denied.physical_result = EffectPhysicalResultV1::DeniedBeforeEffect as u8;
    denied.configured_errno = -(libc::EACCES as i16);
    denied.kernel_result = -libc::EACCES;
    let mut allowed = denied;
    allowed.observed_boottime_ns = 102;
    allowed.source_cpu_id = 2;
    allowed.reason = EffectObservationReasonV1::ApplicationDefaultAllow as u8;
    allowed.physical_result = EffectPhysicalResultV1::UnknownAfterPreEffect as u8;
    allowed.configured_errno = 0;
    allowed.kernel_result = 0;
    allowed.exact_object_key_id = 0;
    allowed.composite_atom_id = 0;
    [denied, allowed]
}

pub(super) async fn fetch_policy(
    node: &mut mithril_node::ControlConnection,
    expected: &mithril_control::PolicyBundleV1,
) -> super::Result<mithril_control::PolicyBundleV1> {
    use sha2::{Digest as _, Sha256};

    let offer = node.policy_inventory(None, Vec::new()).await?;
    assert!(offer.candidate_available && offer.desired_inventory_complete);
    assert_eq!(
        offer.candidate_content_id,
        expected.candidate.candidate_content_id
    );
    assert_eq!(offer.bundle_digest, expected.bundle_digest);
    let mut bytes = Vec::new();
    for index in 0..offer.chunk_count {
        let chunk = node
            .fetch_policy_chunk(
                offer.candidate_content_id.clone(),
                offer.bundle_digest.clone(),
                index,
            )
            .await?;
        assert_eq!(chunk.chunk_index, index);
        assert_eq!(chunk.chunk_count, offer.chunk_count);
        assert_eq!(chunk.bundle_digest, offer.bundle_digest);
        assert_eq!(
            chunk.chunk_sha256,
            hex::encode(Sha256::digest(&chunk.payload))
        );
        bytes.extend_from_slice(&chunk.payload);
    }
    assert_eq!(u64::try_from(bytes.len())?, offer.bundle_bytes);
    let delivered = serde_json::from_slice(&bytes)?;
    assert_eq!(&delivered, expected);
    Ok(delivered)
}

pub(super) fn policy_config(
    config: &mut mithril_control::ControlConfig,
    root: &std::path::Path,
) -> super::Result<()> {
    use crate::control_fixture::{OUTAGE_CLUSTER_UID, OUTAGE_TENANT_ID};

    let baseline: mithril_control::ControlConfig =
        serde_json::from_slice(include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/fixtures/kubernetes/pid-reuse-control-v1.json"
        )))?;
    let mut policy = baseline
        .kubernetes_policy
        .ok_or("fixture policy configuration")?;
    let key = root.join("paired-policy-key.hex");
    std::fs::write(
        &key,
        include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/fixtures/mithril-policy/test-signing-key.hex"
        )),
    )?;
    let seal = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/fixtures/mithril-policy/observe-profile-seal-request.json"
    ));
    let seal_path = root.join("paired-seal.json");
    std::fs::write(&seal_path, seal)?;
    let request: mithril_control::ProfileSealRequestV1 = serde_json::from_slice(seal)?;
    assert_eq!(request.signing_key_id, policy.signer.signing_key_id);
    policy.tenant_id = OUTAGE_TENANT_ID.into();
    policy.cluster_uid = OUTAGE_CLUSTER_UID.into();
    policy.signer.signing_key_path = key;
    policy.signer.seal_request_path = seal_path;
    config.trust.policy_issuer_sequence_epoch = request.sequence_epoch;
    config.trust.policy_signers = vec![mithril_control::PolicySignerTrustV1 {
        signing_key_id: policy.signer.signing_key_id.clone(),
        ed25519_public_key_hex: include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/fixtures/mithril-policy/test-public-key.hex"
        ))
        .trim()
        .into(),
        revoked: false,
    }];
    config.trust.bundle_digest = config.trust.computed_bundle_digest();
    config.kubernetes_policy = Some(policy);
    Ok(())
}
