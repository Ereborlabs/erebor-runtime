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

fn background_record(cursor: u64) -> EffectObservationV1 {
    let mut record = super::super::input::event(cursor, false);
    record.source_cpu_id = 1;
    record.task_cookie = 8;
    record.process_instance_id = [18; 16].into();
    record.entry_instance_id = [19; 16].into();
    record.exact_object_key_id = 0;
    record.composite_atom_id = 0;
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
        input.record_bytes(background_record(cursor).as_bytes());
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
    use super::super::input::{upload_on, wal};
    use zerocopy::IntoBytes as _;

    let input = wal(tls, "paired-backlog", 3)?;
    let mut source = None;
    for (first, last) in [(1, 256), (257, 512), (513, 768), (769, 940)] {
        for cursor in first..=last {
            input.record_bytes(background_record(cursor).as_bytes());
        }
        assert_eq!(input.pending_evidence_records(), last - first + 1);
        let batch = input.next_evidence_batch().ok_or("backlog prefix batch")?;
        assert_eq!((batch.first_cursor, batch.last_cursor), (first, last));
        let (actual, _) = upload_on(tls, node, &input).await?;
        if let Some(expected) = &source {
            assert_eq!(&actual, expected);
        } else {
            source = Some(actual);
        }
    }
    Ok((input, source.ok_or("backlog source")?))
}

pub(super) async fn append_reads(
    tls: &crate::control_fixture::MtlsFixture,
    node: &mut mithril_node::ControlConnection,
    input: &mithril_node::EffectObservationStore,
    source: &araphor_data::EvidenceIntakeIdentityV1,
    raw: EffectObservationV1,
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
    for cursor in 942..950 {
        input.record_bytes(background_record(cursor).as_bytes());
    }
    assert_eq!(input.pending_evidence_records(), 8);
    let batch = input.next_evidence_batch().ok_or("backlog gap batch")?;
    assert_eq!((batch.first_cursor, batch.last_cursor), (942, 949));
    let (actual, _) = upload_on(tls, node, input).await?;
    assert_eq!(&actual, source);
    input.record_bytes(allowed.as_bytes());
    assert_eq!(input.pending_evidence_records(), 1);
    let batch = input.next_evidence_batch().ok_or("backlog benign batch")?;
    assert_eq!((batch.first_cursor, batch.last_cursor), (950, 950));
    let (actual, allowed) = upload_on(tls, node, input).await?;
    assert_eq!(&actual, source);
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

pub(super) fn progress(
    fixture: &super::super::super::Fixture,
    background: &araphor_data::EvidenceIntakeIdentityV1,
    selected: &[(araphor_data::EvidenceIntakeIdentityV1, Vec<u8>)],
) -> super::Result<serde_json::Value> {
    use araphor_data::{
        AnalysisReadControl, AnalysisSelectionV1, ManagedGraphOperation, ProcessorScopeV1,
    };

    let data = super::super::observed::store(fixture)?;
    let control = AnalysisReadControl::default().within(std::time::Duration::from_secs(5))?;
    let mut values = Vec::new();
    for source in std::iter::once(background).chain(selected.iter().map(|(source, _)| source)) {
        let scope = ProcessorScopeV1 {
            processor_id: araphor_data::GRAPH_PROCESSOR.into(),
            method_version: u64::from(araphor_data::GRAPH_SCHEMA_VERSION),
            identity: source.clone(),
        };
        let selection = AnalysisSelectionV1::tenant(source.tenant_id);
        let instances = [ManagedGraphOperation::Evaluate, ManagedGraphOperation::Expire].map(|operation| {
            let id = operation.instance_id(source);
            let status = data.managed_status(&selection, &id, &control).map(|status| {
                (status.readiness, status.instance.running, status.instance.progress, status.instance.generation)
            });
            let history = data.managed_history(&selection, &id, &control).map(|history| {
                history.into_iter().rev().take(3).map(|receipt| {
                    (receipt.attempt, receipt.commit_revision, receipt.selected.result_id)
                }).collect::<Vec<_>>()
            });
            serde_json::json!({"id": id, "status": format!("{status:?}"), "history": format!("{history:?}")})
        });
        let health = data.processor_health(&scope);
        let head = data
            .processor_result(&scope)
            .map(|head| head.map(|head| (head.result_id, head.commit_revision)));
        values.push(
            serde_json::json!({"source": source, "health": format!("{health:?}"),
            "head": format!("{head:?}"), "instances": instances}),
        );
    }
    Ok(serde_json::Value::Array(values))
}
