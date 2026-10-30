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

fn background_record(cursor: u64, denied: bool) -> EffectObservationV1 {
    let mut record = super::super::input::event(cursor, denied);
    record.source_cpu_id = 1;
    record.task_cookie = 8;
    record.process_instance_id = [18; 16].into();
    record.entry_instance_id = [19; 16].into();
    if !denied {
        record.exact_object_key_id = 0;
        record.composite_atom_id = 0;
    }
    record
}

pub(super) async fn background(
    tls: &crate::control_fixture::MtlsFixture,
    node: &mut mithril_node::ControlConnection,
) -> super::Result<araphor_data::EvidenceIntakeIdentityV1> {
    use super::super::input::{upload_on, wal};
    use zerocopy::IntoBytes as _;

    let input = wal(tls, "paired-background", 3)?;
    let count = u64::try_from(araphor_data::AnalysisExtractLimits::default().page_rows + 1)?;
    for cursor in 1..=count {
        input.record_bytes(background_record(cursor, false).as_bytes());
    }
    assert_eq!(input.pending_evidence_records(), count);
    let (source, _) = upload_on(tls, node, &input).await?;
    Ok(source)
}

pub(super) async fn backlog(
    tls: &crate::control_fixture::MtlsFixture,
    node: &mut mithril_node::ControlConnection,
) -> super::Result<(
    mithril_node::EffectObservationStore,
    araphor_data::EvidenceIntakeIdentityV1,
)> {
    use super::super::input::wal;

    let input = wal(tls, "paired-backlog", 3)?;
    let mut source = None;
    for (first, last) in [(1, 256), (257, 512), (513, 768), (769, 940)] {
        let actual = upload_range(tls, node, &input, first..=last, 1, 0).await?;
        if let Some(expected) = &source {
            assert_eq!(&actual, expected);
        } else {
            source = Some(actual);
        }
    }
    Ok((input, source.ok_or("backlog source")?))
}

pub(super) async fn busy_backlog(
    tls: &crate::control_fixture::MtlsFixture,
    node: &mut mithril_node::ControlConnection,
) -> super::Result<(
    mithril_node::EffectObservationStore,
    araphor_data::EvidenceIntakeIdentityV1,
)> {
    let input = super::super::input::wal(tls, "paired-busy", 3)?;
    let mut source = None;
    for (first, last) in [(1, 256), (257, 512), (513, 639)] {
        let actual = upload_range(tls, node, &input, first..=last, 0, 138).await?;
        if let Some(expected) = &source {
            assert_eq!(&actual, expected);
        } else {
            source = Some(actual);
        }
    }
    Ok((input, source.ok_or("background source")?))
}

async fn upload_range(
    tls: &crate::control_fixture::MtlsFixture,
    node: &mut mithril_node::ControlConnection,
    input: &mithril_node::EffectObservationStore,
    range: std::ops::RangeInclusive<u64>,
    cpu: u32,
    denied: u64,
) -> super::Result<araphor_data::EvidenceIntakeIdentityV1> {
    use zerocopy::IntoBytes as _;
    let (first, last) = (*range.start(), *range.end());
    for cursor in range {
        let mut record = background_record(cursor, cursor <= denied);
        record.source_cpu_id = cpu;
        input.record_bytes(record.as_bytes());
    }
    assert_eq!(input.pending_evidence_records(), last - first + 1);
    let batch = input.next_evidence_batch().ok_or("range batch")?;
    assert_eq!((batch.first_cursor, batch.last_cursor), (first, last));
    let (source, _) = super::super::input::upload_on(tls, node, input).await?;
    Ok(source)
}

pub(super) fn check_runtime(
    bytes: &[u8],
    container: &str,
    binding: mithril_control::EvidenceIdV1,
) -> super::Result<()> {
    let denied = mithril_control::EvidenceRecord::try_from(bytes)?;
    let context = denied.decision_context.as_ref().ok_or("runtime context")?;
    let catalog = mithril_control::EvidenceDecisionCatalogV1::from_context(context)?
        .ok_or("runtime catalog")?;
    let proof = catalog.runtime_binding.as_ref().ok_or("runtime proof")?;
    assert_eq!(
        (proof.container_id.as_str(), catalog.binding_id),
        (container, binding)
    );
    Ok(())
}

pub(super) async fn append_reads(
    tls: &crate::control_fixture::MtlsFixture,
    node: &mut mithril_node::ControlConnection,
    input: &mithril_node::EffectObservationStore,
    source: &araphor_data::EvidenceIntakeIdentityV1,
    raw: EffectObservationV1,
    background: &mithril_node::EffectObservationStore,
    background_source: &araphor_data::EvidenceIntakeIdentityV1,
) -> super::Result<[Vec<u8>; 2]> {
    use super::super::input::upload_on;
    use zerocopy::IntoBytes as _;

    let [mut denied, mut allowed] = events(raw);
    for (record, cursor) in [(&mut denied, 941), (&mut allowed, 950)] {
        record.source_cpu_id = 1;
        record.source_sequence = cursor;
        record.observed_boottime_ns = 100 + cursor;
    }
    input.record_bytes(denied.as_bytes());
    assert_eq!(input.pending_evidence_records(), 1);
    let batch = input.next_evidence_batch().ok_or("backlog denial batch")?;
    assert_eq!((batch.first_cursor, batch.last_cursor), (941, 941));
    let (actual, denied) = upload_on(tls, node, input).await?;
    assert_eq!(&actual, source);
    assert_eq!(
        &upload_range(tls, node, background, 640..=640, 0, 0).await?,
        background_source
    );
    for cursor in 942..950 {
        input.record_bytes(background_record(cursor, false).as_bytes());
    }
    assert_eq!(input.pending_evidence_records(), 8);
    let batch = input.next_evidence_batch().ok_or("backlog gap batch")?;
    assert_eq!((batch.first_cursor, batch.last_cursor), (942, 949));
    let (actual, _) = upload_on(tls, node, input).await?;
    assert_eq!(&actual, source);
    assert_eq!(
        &upload_range(tls, node, background, 641..=641, 0, 0).await?,
        background_source
    );
    input.record_bytes(allowed.as_bytes());
    assert_eq!(input.pending_evidence_records(), 1);
    let batch = input.next_evidence_batch().ok_or("backlog benign batch")?;
    assert_eq!((batch.first_cursor, batch.last_cursor), (950, 950));
    let (actual, allowed) = upload_on(tls, node, input).await?;
    assert_eq!(&actual, source);
    assert_eq!(
        &upload_range(tls, node, background, 642..=642, 0, 0).await?,
        background_source
    );
    Ok([denied, allowed])
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
