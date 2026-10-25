use std::time::{Duration, SystemTime, UNIX_EPOCH};

use araphor_data::{
    ContextSensitivityV1, EvidenceIntakeIdentityV1, NotificationGrantV1, NotificationOperationV1,
    NotificationPolicyV1, NotificationPrincipalV1, NotificationPriorityV1,
};
use erebor_interceptor_abi::{
    EffectObservationHealthV1, EffectObservationReasonV1, EffectObservationV1,
    EffectPhysicalResultV1, KernelEffectFamilyV1, KernelEffectOperationV1,
};
use mithril_control::{ControlConfig, EvidenceIdV1};
use mithril_node::{
    ControlConnection, EffectObservationStore, EvidenceWalLimits, NodeControlMessage,
    ObservationCanonicalizer, TrustCache,
};
use zerocopy::IntoBytes as _;

use super::super::*;
use crate::control_fixture::{ControlServerFixture, OutagePolicyFixture};

pub(super) fn now() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)?
        .as_nanos()
        .try_into()?)
}

pub(super) fn event(cursor: u64, denied: bool) -> EffectObservationV1 {
    EffectObservationV1 {
        observed_boottime_ns: 100 + cursor,
        source_sequence: cursor,
        source_cpu_id: 3,
        task_cookie: 7,
        process_instance_id: [8; 16].into(),
        entry_instance_id: [9; 16].into(),
        binding_id: [10; 16].into(),
        execution_set_id: [11; 16].into(),
        authority_domain_id: [12; 16].into(),
        profile_generation_ref_id: 1,
        active_role_id: 1,
        process_state_vector_id: 1,
        admitted_entry_rule_id: 1,
        exact_object_key_id: if denied { 20 } else { 21 },
        composite_atom_id: if denied { 22 } else { 23 },
        reason: if denied {
            EffectObservationReasonV1::ExactPolicyDeny as u8
        } else {
            EffectObservationReasonV1::ApplicationDefaultAllow as u8
        },
        physical_result: if denied {
            EffectPhysicalResultV1::DeniedBeforeEffect as u8
        } else {
            EffectPhysicalResultV1::UnknownAfterPreEffect as u8
        },
        effect_family: KernelEffectFamilyV1::File as u16,
        operation: KernelEffectOperationV1::OpenRead as u16,
        configured_errno: if denied { -(libc::EACCES as i16) } else { 0 },
        kernel_result: if denied { -libc::EACCES } else { 0 },
        ..Default::default()
    }
}

pub(super) fn wal(tls: &MtlsFixture, name: &str, seed: u8) -> Result<EffectObservationStore> {
    let root = tls.path().join(name);
    fs::create_dir(&root)?;
    let store = EffectObservationStore::durable(
        8,
        root.join("wal"),
        EvidenceWalLimits::default(),
        ObservationCanonicalizer::new(
            EvidenceIdV1::new(1, 2),
            [seed; 16].into(),
            1,
            [7; 16].into(),
        )?,
    )?;
    store.sample_coverage_health([EffectObservationHealthV1::default(); 4].as_bytes())?;
    Ok(store)
}

pub(super) async fn upload(
    tls: &MtlsFixture,
    server: &ControlServerFixture,
    wal: &EffectObservationStore,
) -> Result<(EvidenceIntakeIdentityV1, Vec<u8>)> {
    let mut trust = TrustCache::load(&tls.path().join("required-trust"))?;
    let mut registration = OutagePolicyFixture::registration([7; 16], false);
    registration.effect_prevention_claims_enabled = false;
    let mut connection: ControlConnection = tls
        .connector(server, "node-a", [7; 16])
        .connect(registration, false, &mut trust)
        .await?;
    let batch = wal.next_evidence_batch().ok_or("required WAL batch")?;
    let wire: mithril_control::EvidenceBatch = batch.clone().into();
    let source = tls.identity(wire.source_id.as_slice().try_into()?);
    connection.send_evidence_batch(batch.clone()).await?;
    let ack = tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            if let NodeControlMessage::EvidenceAck(ack) = connection.next_message().await? {
                return Ok::<_, mithril_node::Error>(ack);
            }
        }
    })
    .await??;
    assert_eq!(ack.contiguous_cursor, batch.last_cursor);
    wal.acknowledge_evidence(ack)?;
    assert_eq!(wal.pending_evidence_records(), 0);
    let mut health = [EffectObservationHealthV1::default(); 4];
    health[3] = EffectObservationHealthV1 {
        attempted: batch.last_cursor,
        requested: batch.last_cursor,
        emitted: batch.last_cursor,
        next_sequence: batch.last_cursor,
        ..Default::default()
    };
    wal.sample_coverage_health(health.as_bytes())?;
    let snapshot = wal
        .coverage_snapshot()
        .ok_or("required coverage snapshot")?;
    let current = snapshot
        .current_intervals()
        .into_iter()
        .find(|interval| interval.cpu_id == 3)
        .ok_or("required coverage interval")?;
    assert_eq!(current.source_id.to_be_bytes(), source.source_id);
    assert!(current.supports_negative_claim());
    assert_eq!(current.last_sequence, Some(batch.last_cursor));
    let expected = connection.send_coverage_report(&snapshot, &current).await?;
    let actual = tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            if let NodeControlMessage::CoverageAck(ack) = connection.next_message().await? {
                return Ok::<_, mithril_node::Error>(ack);
            }
        }
    })
    .await??;
    assert_eq!(actual, expected);
    Ok((source, wire.framed_records.to_vec()))
}

pub(super) async fn configuration(
    tls: &MtlsFixture,
    oidc: &OidcFixture,
) -> Result<(ControlConfig, NotificationGrantV1, Arc<ClientAuth>)> {
    let tenant = EvidenceIdV1::new(1, 2).to_be_bytes();
    let auth = oidc.auth(
        "https://localhost:44444",
        Some(tenant),
        tls.files.ca.clone(),
    );
    let mut config = lifecycle::configuration(tls, &auth)?;
    config.graph_enabled = true;
    config.discovery = false;
    config.data_retention.raw_max_age_ns = Some(1);
    let grant = NotificationGrantV1 {
        tenant_id: tenant,
        principal_id: [9; 16],
        principal: NotificationPrincipalV1::Agent,
        authorization_revision: 1,
        routes: vec!["escalation".into(), "primary".into()],
        operations: vec![
            NotificationOperationV1::Configure,
            NotificationOperationV1::Read,
        ],
        max_sensitivity: ContextSensitivityV1::HostRestricted,
        expires_utc_ns: u64::MAX,
    };
    config.notifications = mithril_control::NotificationControlConfigV1 {
        grants: vec![grant.clone()],
        routes: ["escalation", "primary"]
            .into_iter()
            .map(|route| NotificationPolicyV1 {
                tenant_id: tenant,
                route_id: route.into(),
                revision: 1,
                package_ids: vec![if route == "primary" {
                    "HF-PROC-001".into()
                } else {
                    "HF-XNODE-001".into()
                }],
                minimum_priority: NotificationPriorityV1::Info,
                acknowledgement_ns: 3_600_000_000_000,
                retry_limit: 4,
                retry_delay_ns: 3_600_000_000_000,
                escalation_route_id: "escalation".into(),
                max_sensitivity: ContextSensitivityV1::HostRestricted,
                allow_concerns: false,
            })
            .collect(),
        ..Default::default()
    };
    Ok((config, grant, Arc::new(ClientAuth::load(&auth).await?)))
}
