use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use ed25519_dalek::SigningKey;
use mithril_control::{
    canonical_policy_spec_digest, ContainerKindV1, ControlPlane, ControlStore,
    PolicyActivationAcknowledgementV1, PolicyActivationStateV1, PolicyBundleV1,
    PolicyConditionKindV1, PolicyDeliveryOperationV1, PolicyDesiredStateConfigV1,
    PolicyDesiredStateOwner, PolicyDocumentV1, PolicySignerConfigV1, ProfileSealRequestV1,
    RegistryDigestsV1, TrustGenerationV1, WorkloadProtectionProfile, WorkloadTargetFactV1,
    POLICY_API_VERSION, POLICY_KIND, SUBMITTED_SPEC_DIGEST_ANNOTATION,
};
use serde_json::json;
use tempfile::TempDir;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const POLICY: &str = include_str!("fixtures/policy-v1.yaml");
const TENANT_ID: &str = "10000000-0000-4000-8000-000000000001";
const CLUSTER_UID: &str = "55555555-5555-4555-8555-555555555555";
const NAMESPACE_UID: &str = "66666666-6666-4666-8666-666666666666";
const OBJECT_UID: &str = "30000000-0000-4000-8000-000000000001";
const NOW: i64 = 1_800_000_000_000_000_000;

fn policy() -> TestResult<PolicyDocumentV1> {
    Ok(PolicyDocumentV1::parse(
        Path::new("policy-v1.yaml"),
        POLICY.as_bytes(),
    )?)
}

fn resource(
    document: &PolicyDocumentV1,
    name: &str,
    uid: &str,
    generation: u64,
    deleting: bool,
) -> TestResult<WorkloadProtectionProfile> {
    let digest = canonical_policy_spec_digest(document)?;
    let resource_version = if deleting {
        format!("opaque-{generation}-deleting")
    } else {
        format!("opaque-{generation}")
    };
    let mut metadata = json!({
        "name": name,
        "namespace": "tenant-a",
        "uid": uid,
        "generation": generation,
        "resourceVersion": resource_version,
        "annotations": {SUBMITTED_SPEC_DIGEST_ANNOTATION: digest},
    });
    if deleting {
        metadata["deletionTimestamp"] = json!("2027-01-15T00:00:00Z");
    }
    Ok(serde_json::from_value(json!({
        "apiVersion": POLICY_API_VERSION,
        "kind": POLICY_KIND,
        "metadata": metadata,
        "spec": document,
    }))?)
}

fn make_owner(store: ControlStore) -> PolicyDesiredStateOwner {
    PolicyDesiredStateOwner::new(
        PolicyDesiredStateConfigV1 {
            tenant_id: TENANT_ID.to_owned(),
            cluster_uid: CLUSTER_UID.to_owned(),
            signer: PolicySignerConfigV1 {
                signing_key_id: "policy-key-a".to_owned(),
                signing_key_path: PathBuf::from("/unused/policy-key"),
                seal_request_path: PathBuf::from("/unused/seal-request"),
                distribution_sequence_epoch: 9,
                candidate_validity_ns: 60_000_000_000,
            },
        },
        store,
        SigningKey::from_bytes(&[7; 32]),
        seal_request(),
    )
}

fn seal_request() -> ProfileSealRequestV1 {
    let digest = "0".repeat(64);
    ProfileSealRequestV1 {
        signing_key_id: "policy-key-a".to_owned(),
        issuer_id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".to_owned(),
        sequence_epoch: 4,
        issuer_sequence: 0,
        rollback_authorization_id: None,
        registry_digests: RegistryDigestsV1 {
            provider_numeric_registry_bundle_digest: digest.clone(),
            required_capability_schema_digest: digest.clone(),
            source_selector_registry_digest: digest.clone(),
            object_classifier_registry_digest: digest.clone(),
            reason_code_registry_digest: digest.clone(),
            correlation_package_registry_digest: digest.clone(),
            provider_vocabulary_registry_digest: digest,
        },
    }
}

fn inventory(binding_digest: &str) -> Vec<WorkloadTargetFactV1> {
    vec![WorkloadTargetFactV1 {
        node_id: "node-a".to_owned(),
        workload_binding_generation_digest: binding_digest.to_owned(),
        execution_set_id: "44444444-4444-4444-8444-444444444444".to_owned(),
        cluster_uid: CLUSTER_UID.to_owned(),
        namespace_uid: NAMESPACE_UID.to_owned(),
        controller_uid: "88888888-8888-4888-8888-888888888888".to_owned(),
        service_account_uid: "77777777-7777-4777-8777-777777777777".to_owned(),
        pod_uid: "99999999-9999-4999-8999-999999999999".to_owned(),
        container_id: "containerd://converter".to_owned(),
        container_name: "converter".to_owned(),
        container_kind: ContainerKindV1::Application,
        image_digest: "sha256:converter".to_owned(),
        pod_labels: BTreeMap::new(),
        kubernetes: None,
    }]
}

fn two_node_inventory() -> Vec<WorkloadTargetFactV1> {
    let node_a = inventory(&"1".repeat(64)).remove(0);
    let mut node_b = node_a.clone();
    node_b.node_id = "node-b".to_owned();
    node_b.workload_binding_generation_digest = "2".repeat(64);
    node_b.execution_set_id = "44444444-4444-4444-8444-444444444445".to_owned();
    node_b.pod_uid = "99999999-9999-4999-8999-999999999998".to_owned();
    node_b.container_id = "containerd://converter-b".to_owned();
    vec![node_a, node_b]
}

fn acknowledgement(
    bundle: &PolicyBundleV1,
    state: PolicyActivationStateV1,
    observed_utc_ns: i64,
) -> TestResult<PolicyActivationAcknowledgementV1> {
    let active = state == PolicyActivationStateV1::Active;
    Ok(PolicyActivationAcknowledgementV1 {
        acknowledgement_content_id: String::new(),
        tenant_id: TENANT_ID.to_owned(),
        node_id: bundle.candidate.exact_target.node_id.clone(),
        node_boot_id: vec![1; 16],
        label_epoch: 1,
        candidate_content_id: bundle.candidate.candidate_content_id.clone(),
        policy_source_revision_id: bundle.candidate.policy_source_revision_id.clone(),
        target_snapshot_digest: bundle.candidate.target_snapshot_digest.clone(),
        state,
        node_bound_generation_digest: active.then(|| "1".repeat(64)),
        profile_generation_ref_id: active.then_some(1),
        readback_digest: active.then(|| "2".repeat(64)),
        probe_result_digest: active.then(|| "3".repeat(64)),
        reason_code: (!active).then(|| "CANDIDATE_REJECTED".to_owned()),
        observed_utc_ns,
        authenticated_channel_receipt_digest: "4".repeat(64),
    }
    .finalize()?)
}

#[test]
fn create_update_duplicate_and_restart_preserve_one_monotonic_rollout() -> TestResult {
    let directory = TempDir::new()?;
    let store = ControlStore::open(directory.path())?;
    let owner = make_owner(store.clone());
    let first_policy = policy()?;
    let first = owner.reconcile(
        &resource(&first_policy, "profile", OBJECT_UID, 1, false)?,
        NAMESPACE_UID,
        &inventory(&"1".repeat(64)),
        NOW,
    )?;
    assert_eq!(first.bundles.len(), 1);
    assert_eq!(
        first.bundles[0].candidate.operation,
        PolicyDeliveryOperationV1::Activate
    );
    assert_eq!(first.bundles[0].candidate.distribution_sequence, 1);
    assert_eq!(first.bundles[0].profile_artifact.header.issuer_sequence, 1);

    let first_commit = store.commit_index();
    let duplicate = owner.reconcile(
        &resource(&first_policy, "profile", OBJECT_UID, 1, false)?,
        NAMESPACE_UID,
        &inventory(&"1".repeat(64)),
        NOW,
    )?;
    assert_eq!(duplicate, first);
    assert_eq!(store.commit_index(), first_commit);

    let mut second_policy = first_policy;
    second_policy.metadata.profile_version = 2;
    second_policy.rollout.rollout_generation = 2;
    let second = owner.reconcile(
        &resource(&second_policy, "profile", OBJECT_UID, 2, false)?,
        NAMESPACE_UID,
        &inventory(&"1".repeat(64)),
        NOW + 1,
    )?;
    assert_eq!(
        second.bundles[0].candidate.operation,
        PolicyDeliveryOperationV1::Replace
    );
    assert_eq!(second.bundles[0].candidate.distribution_sequence, 2);
    assert_eq!(second.bundles[0].profile_artifact.header.issuer_sequence, 2);
    assert_eq!(
        second.bundles[0]
            .candidate
            .predecessor_candidate_content_id
            .as_deref(),
        Some(first.bundles[0].candidate.candidate_content_id.as_str())
    );

    let stale = owner.reconcile(
        &resource(&second_policy, "profile", OBJECT_UID, 1, false)?,
        NAMESPACE_UID,
        &inventory(&"1".repeat(64)),
        NOW + 2,
    );
    assert!(stale.is_err());

    drop(owner);
    drop(store);
    let reopened = ControlStore::open(directory.path())?;
    let restarted = make_owner(reopened.clone()).reconcile(
        &resource(&second_policy, "profile", OBJECT_UID, 2, false)?,
        NAMESPACE_UID,
        &inventory(&"1".repeat(64)),
        NOW + 3,
    )?;
    assert_eq!(restarted.bundles, second.bundles);
    assert_eq!(reopened.commit_index(), 6);
    Ok(())
}

#[test]
fn bound_inventory_change_reconciles_without_a_policy_source_change() -> TestResult {
    let directory = TempDir::new()?;
    let store = ControlStore::open(directory.path())?;
    let owner = make_owner(store);
    let policy = policy()?;
    let resource = resource(&policy, "profile", OBJECT_UID, 1, false)?;
    let first = owner.reconcile(&resource, NAMESPACE_UID, &inventory(&"1".repeat(64)), NOW)?;
    let second = owner.reconcile(&resource, NAMESPACE_UID, &two_node_inventory(), NOW + 1)?;

    assert_eq!(
        first.source_revision.policy_source_revision_id,
        second.source_revision.policy_source_revision_id
    );
    assert_ne!(
        first.target_snapshot.target_snapshot_digest,
        second.target_snapshot.target_snapshot_digest
    );
    assert_eq!(second.bundles.len(), 2);
    let node_a = second
        .bundles
        .iter()
        .find(|bundle| bundle.candidate.exact_target.node_id == "node-a")
        .ok_or("updated snapshot has no node-a bundle")?;
    let node_b = second
        .bundles
        .iter()
        .find(|bundle| bundle.candidate.exact_target.node_id == "node-b")
        .ok_or("updated snapshot has no node-b bundle")?;
    assert_eq!(
        node_a.candidate.operation,
        PolicyDeliveryOperationV1::Replace
    );
    assert_eq!(
        node_b.candidate.operation,
        PolicyDeliveryOperationV1::Activate
    );
    Ok(())
}

#[test]
fn health_snapshot_exposes_bounded_operational_counts_without_payloads() -> TestResult {
    let directory = TempDir::new()?;
    let store = ControlStore::open(directory.path())?;
    let owner = make_owner(store);
    let before = owner.health()?;
    assert_eq!(before.configured_namespaces, 1);
    assert_eq!(before.watched_namespaces, 0);
    assert_eq!(before.reconcile_in_flight, 0);

    owner.reconcile(
        &resource(&policy()?, "profile", OBJECT_UID, 1, false)?,
        NAMESPACE_UID,
        &inventory(&"1".repeat(64)),
        NOW,
    )?;
    let control = ControlPlane::new(
        Vec::new(),
        TrustGenerationV1 {
            generation: 1,
            bundle_digest: "0".repeat(64),
            policy_issuer_sequence_epoch: 0,
            policy_signers: Vec::new(),
        },
    )
    .with_policy_desired_state(owner);
    let health = control.convergence_health()?;
    assert!(health.queue_healthy);
    assert!(health.storage_healthy);
    assert!(!health.watch_healthy);
    assert_eq!(health.successful_reconciles, 1);
    assert_eq!(health.successful_compiles, 1);
    assert_eq!(health.target_snapshots, 1);
    assert_eq!(health.rollout_targets, 1);
    assert_eq!(health.unsettled_rollout_targets, 1);
    assert_eq!(health.pending_evidence_records, 0);
    Ok(())
}

#[test]
fn duplicate_profile_and_exact_workload_claims_do_not_replace_valid_rollout() -> TestResult {
    let directory = TempDir::new()?;
    let store = ControlStore::open(directory.path())?;
    let owner = make_owner(store.clone());
    let first_policy = policy()?;
    let first = owner.reconcile(
        &resource(&first_policy, "one", OBJECT_UID, 1, false)?,
        NAMESPACE_UID,
        &inventory(&"1".repeat(64)),
        NOW,
    )?;

    let duplicate_profile = owner.reconcile(
        &resource(
            &first_policy,
            "two",
            "30000000-0000-4000-8000-000000000002",
            1,
            false,
        )?,
        NAMESPACE_UID,
        &inventory(&"2".repeat(64)),
        NOW + 1,
    );
    let Err(duplicate_profile) = duplicate_profile else {
        return Err("a duplicate profile owner must fail".into());
    };
    assert!(duplicate_profile
        .to_string()
        .contains("CFG_DUPLICATE_PROFILE_OWNER"));

    let mut overlapping = first_policy;
    overlapping.metadata.profile_id = "11111111-1111-4111-8111-111111111112".to_owned();
    let overlap = owner.reconcile(
        &resource(
            &overlapping,
            "three",
            "30000000-0000-4000-8000-000000000003",
            1,
            false,
        )?,
        NAMESPACE_UID,
        &inventory(&"1".repeat(64)),
        NOW + 2,
    );
    let Err(overlap) = overlap else {
        return Err("an exact workload overlap must fail".into());
    };
    assert!(overlap
        .to_string()
        .contains("CFG_OVERLAPPING_WORKLOAD_OWNER"));
    assert_eq!(
        store.bundle_for_node("node-a")?,
        Some(first.bundles[0].clone())
    );
    Ok(())
}

#[test]
fn status_refreshes_from_durable_node_rollout_state() -> TestResult {
    let directory = TempDir::new()?;
    let store = ControlStore::open(directory.path())?;
    let owner = make_owner(store.clone());
    let policy = policy()?;
    let resource = resource(&policy, "profile", OBJECT_UID, 1, false)?;
    let first = owner.reconcile(&resource, NAMESPACE_UID, &inventory(&"1".repeat(64)), NOW)?;
    let bundle = &first.bundles[0];
    owner.rollout_owner().acknowledge(
        PolicyActivationAcknowledgementV1 {
            acknowledgement_content_id: String::new(),
            tenant_id: TENANT_ID.to_owned(),
            node_id: "node-a".to_owned(),
            node_boot_id: vec![1; 16],
            label_epoch: 1,
            candidate_content_id: bundle.candidate.candidate_content_id.clone(),
            policy_source_revision_id: bundle.candidate.policy_source_revision_id.clone(),
            target_snapshot_digest: bundle.candidate.target_snapshot_digest.clone(),
            state: PolicyActivationStateV1::Active,
            node_bound_generation_digest: Some("1".repeat(64)),
            profile_generation_ref_id: Some(1),
            readback_digest: Some("2".repeat(64)),
            probe_result_digest: Some("3".repeat(64)),
            reason_code: None,
            observed_utc_ns: NOW + 1,
            authenticated_channel_receipt_digest: "4".repeat(64),
        }
        .finalize()?,
    )?;

    let refreshed = owner.reconcile(
        &resource,
        NAMESPACE_UID,
        &inventory(&"1".repeat(64)),
        NOW + 2,
    )?;
    assert_eq!(refreshed.status.rollout_counts.active, 1);
    assert_eq!(refreshed.status.rollout_counts.total(), 1);
    assert_eq!(refreshed.status.conditions.len(), 6);
    assert!(refreshed.status.conditions.iter().any(|condition| {
        condition.condition == PolicyConditionKindV1::Available && condition.status
    }));
    assert!(store
        .next_bundle_for_node(
            "node-a",
            &bundle.candidate.candidate_content_id,
            std::slice::from_ref(&bundle.bundle_digest),
        )?
        .is_none());
    assert_eq!(store.commit_index(), 4);
    Ok(())
}

#[test]
fn rejected_candidate_stops_redelivery_and_projects_degraded_status() -> TestResult {
    let directory = TempDir::new()?;
    let store = ControlStore::open(directory.path())?;
    let owner = make_owner(store.clone());
    let policy = policy()?;
    let resource = resource(&policy, "profile", OBJECT_UID, 1, false)?;
    let first = owner.reconcile(&resource, NAMESPACE_UID, &inventory(&"1".repeat(64)), NOW)?;
    let bundle = &first.bundles[0];
    assert_eq!(
        store.next_bundle_for_node("node-a", "", &[])?,
        Some(bundle.clone())
    );
    owner.rollout_owner().acknowledge(
        PolicyActivationAcknowledgementV1 {
            acknowledgement_content_id: String::new(),
            tenant_id: TENANT_ID.to_owned(),
            node_id: "node-a".to_owned(),
            node_boot_id: vec![1; 16],
            label_epoch: 1,
            candidate_content_id: bundle.candidate.candidate_content_id.clone(),
            policy_source_revision_id: bundle.candidate.policy_source_revision_id.clone(),
            target_snapshot_digest: bundle.candidate.target_snapshot_digest.clone(),
            state: PolicyActivationStateV1::Rejected,
            node_bound_generation_digest: None,
            profile_generation_ref_id: None,
            readback_digest: None,
            probe_result_digest: None,
            reason_code: Some("CAPABILITY_REJECTED".to_owned()),
            observed_utc_ns: NOW + 1,
            authenticated_channel_receipt_digest: "4".repeat(64),
        }
        .finalize()?,
    )?;

    assert!(store.next_bundle_for_node("node-a", "", &[])?.is_none());
    let refreshed = owner.reconcile(
        &resource,
        NAMESPACE_UID,
        &inventory(&"1".repeat(64)),
        NOW + 2,
    )?;
    assert_eq!(refreshed.status.rollout_counts.rejected, 1);
    assert!(refreshed.status.conditions.iter().any(|condition| {
        condition.condition == PolicyConditionKindV1::Degraded && condition.status
    }));
    Ok(())
}

#[test]
fn deletion_names_exact_predecessor_and_recreate_gets_a_new_source_identity() -> TestResult {
    let directory = TempDir::new()?;
    let store = ControlStore::open(directory.path())?;
    let owner = make_owner(store);
    let policy = policy()?;
    let first = owner.reconcile(
        &resource(&policy, "profile", OBJECT_UID, 1, false)?,
        NAMESPACE_UID,
        &inventory(&"1".repeat(64)),
        NOW,
    )?;
    let retiring = owner.reconcile(
        &resource(&policy, "profile", OBJECT_UID, 1, true)?,
        NAMESPACE_UID,
        &[],
        NOW + 1,
    )?;
    assert_eq!(retiring.bundles.len(), 1);
    assert_eq!(
        retiring.bundles[0].candidate.operation,
        PolicyDeliveryOperationV1::RetireToRestrictiveTerminal
    );
    assert_eq!(
        retiring.bundles[0]
            .candidate
            .predecessor_candidate_content_id
            .as_deref(),
        Some(first.bundles[0].candidate.candidate_content_id.as_str())
    );
    assert!(owner
        .reconcile(
            &resource(&policy, "profile", OBJECT_UID, 1, false)?,
            NAMESPACE_UID,
            &inventory(&"1".repeat(64)),
            NOW + 2,
        )
        .is_err());

    let recreated = owner.reconcile(
        &resource(
            &policy,
            "profile",
            "30000000-0000-4000-8000-000000000004",
            1,
            false,
        )?,
        NAMESPACE_UID,
        &inventory(&"1".repeat(64)),
        NOW + 3,
    )?;
    assert_ne!(
        recreated.source_revision.policy_source_revision_id,
        first.source_revision.policy_source_revision_id
    );
    assert_eq!(
        recreated.bundles[0].candidate.operation,
        PolicyDeliveryOperationV1::Replace
    );
    assert_eq!(
        recreated.bundles[0]
            .candidate
            .predecessor_candidate_content_id
            .as_deref(),
        Some(retiring.bundles[0].candidate.candidate_content_id.as_str())
    );
    assert!(
        recreated.bundles[0].candidate.distribution_sequence
            > retiring.bundles[0].candidate.distribution_sequence
    );
    Ok(())
}

#[test]
fn completed_relist_retires_a_source_that_is_absent_from_the_snapshot() -> TestResult {
    let directory = TempDir::new()?;
    let store = ControlStore::open(directory.path())?;
    let owner = make_owner(store);
    let accepted = owner.reconcile(
        &resource(&policy()?, "profile", OBJECT_UID, 1, false)?,
        NAMESPACE_UID,
        &inventory(&"1".repeat(64)),
        NOW,
    )?;

    let retired = owner.retire_missing_sources(&BTreeSet::new(), &[], NOW + 1)?;
    assert_eq!(retired.len(), 1);
    assert_eq!(
        retired[0].bundles[0].candidate.operation,
        PolicyDeliveryOperationV1::RetireToRestrictiveTerminal
    );
    assert_eq!(
        retired[0].bundles[0]
            .candidate
            .predecessor_candidate_content_id
            .as_deref(),
        Some(accepted.bundles[0].candidate.candidate_content_id.as_str())
    );
    assert!(owner
        .retire_missing_sources(&BTreeSet::new(), &[], NOW + 2)?
        .is_empty());
    Ok(())
}

#[test]
fn two_node_create_update_restart_delete_and_recreate_preserve_provenance() -> TestResult {
    let directory = TempDir::new()?;
    let store = ControlStore::open(directory.path())?;
    let owner = make_owner(store.clone());
    let inventory = two_node_inventory();
    let mut first_policy = policy()?;
    let first_resource = resource(&first_policy, "profile", OBJECT_UID, 1, false)?;
    let first = owner.reconcile(&first_resource, NAMESPACE_UID, &inventory, NOW)?;
    assert_eq!(first.bundles.len(), 2);
    assert_eq!(
        first.source_revision.canonical_spec_digest,
        canonical_policy_spec_digest(&first_policy)?
    );
    let first_by_node = first
        .bundles
        .iter()
        .map(|bundle| (bundle.candidate.exact_target.node_id.as_str(), bundle))
        .collect::<BTreeMap<_, _>>();
    let node_a_first = first_by_node
        .get("node-a")
        .ok_or("node-a has no first bundle")?;
    let node_b_first = first_by_node
        .get("node-b")
        .ok_or("node-b has no first bundle")?;
    owner.rollout_owner().acknowledge(acknowledgement(
        node_a_first,
        PolicyActivationStateV1::Active,
        NOW + 1,
    )?)?;
    owner.rollout_owner().acknowledge(acknowledgement(
        node_b_first,
        PolicyActivationStateV1::Rejected,
        NOW + 1,
    )?)?;
    let first_status = owner
        .reconcile(&first_resource, NAMESPACE_UID, &inventory, NOW + 2)?
        .status;
    assert_eq!(first_status.rollout_counts.active, 1);
    assert_eq!(first_status.rollout_counts.rejected, 1);

    first_policy.metadata.profile_version = 2;
    first_policy.rollout.rollout_generation = 2;
    let second_resource = resource(&first_policy, "profile", OBJECT_UID, 2, false)?;
    let second = owner.reconcile(&second_resource, NAMESPACE_UID, &inventory, NOW + 3)?;
    let second_by_node = second
        .bundles
        .iter()
        .map(|bundle| (bundle.candidate.exact_target.node_id.as_str(), bundle))
        .collect::<BTreeMap<_, _>>();
    for node_id in ["node-a", "node-b"] {
        let prior = first_by_node
            .get(node_id)
            .ok_or("node has no first bundle")?;
        let current = second_by_node
            .get(node_id)
            .ok_or("node has no updated bundle")?;
        assert_eq!(
            current.candidate.operation,
            PolicyDeliveryOperationV1::Replace
        );
        assert_eq!(
            current
                .candidate
                .predecessor_candidate_content_id
                .as_deref(),
            Some(prior.candidate.candidate_content_id.as_str())
        );
        assert!(current.candidate.distribution_sequence > prior.candidate.distribution_sequence);
    }
    assert!(owner
        .rollout_owner()
        .acknowledge(acknowledgement(
            node_a_first,
            PolicyActivationStateV1::Active,
            NOW + 4,
        )?)
        .is_err());
    owner.rollout_owner().acknowledge(acknowledgement(
        second_by_node
            .get("node-a")
            .ok_or("node-a has no updated bundle")?,
        PolicyActivationStateV1::Active,
        NOW + 4,
    )?)?;
    let mixed = owner.reconcile(&second_resource, NAMESPACE_UID, &inventory, NOW + 5)?;
    assert_eq!(mixed.status.rollout_counts.active, 1);
    assert_eq!(mixed.status.rollout_counts.pending, 1);
    assert!(mixed.status.conditions.iter().any(|condition| {
        condition.condition == PolicyConditionKindV1::Progressing && condition.status
    }));

    drop(owner);
    drop(store);
    let reopened = ControlStore::open(directory.path())?;
    let restarted_owner = make_owner(reopened.clone());
    let restarted =
        restarted_owner.reconcile(&second_resource, NAMESPACE_UID, &inventory, NOW + 6)?;
    assert_eq!(restarted.bundles, second.bundles);
    assert_eq!(restarted.status.rollout_counts.active, 1);
    assert_eq!(restarted.status.rollout_counts.pending, 1);

    let deleting_resource = resource(&first_policy, "profile", OBJECT_UID, 2, true)?;
    let retiring = restarted_owner.reconcile(&deleting_resource, NAMESPACE_UID, &[], NOW + 7)?;
    assert_eq!(retiring.bundles.len(), 2);
    assert!(retiring.bundles.iter().all(|bundle| {
        bundle.candidate.operation == PolicyDeliveryOperationV1::RetireToRestrictiveTerminal
    }));
    let retiring_by_node = retiring
        .bundles
        .iter()
        .map(|bundle| (bundle.candidate.exact_target.node_id.as_str(), bundle))
        .collect::<BTreeMap<_, _>>();
    for node_id in ["node-a", "node-b"] {
        assert_eq!(
            retiring_by_node
                .get(node_id)
                .and_then(|bundle| bundle.candidate.predecessor_candidate_content_id.as_deref()),
            second_by_node
                .get(node_id)
                .map(|bundle| bundle.candidate.candidate_content_id.as_str())
        );
    }

    let recreated_resource = resource(
        &first_policy,
        "profile",
        "30000000-0000-4000-8000-000000000009",
        1,
        false,
    )?;
    let recreated =
        restarted_owner.reconcile(&recreated_resource, NAMESPACE_UID, &inventory, NOW + 8)?;
    assert_eq!(recreated.bundles.len(), 2);
    for bundle in &recreated.bundles {
        let terminal = retiring_by_node
            .get(bundle.candidate.exact_target.node_id.as_str())
            .ok_or("recreated target has no terminal predecessor")?;
        assert_eq!(
            bundle.candidate.operation,
            PolicyDeliveryOperationV1::Replace
        );
        assert_eq!(
            bundle.candidate.predecessor_candidate_content_id.as_deref(),
            Some(terminal.candidate.candidate_content_id.as_str())
        );
        assert!(bundle.candidate.distribution_sequence > terminal.candidate.distribution_sequence);
    }
    assert_ne!(
        recreated.source_revision.policy_source_revision_id,
        retiring.source_revision.policy_source_revision_id
    );
    Ok(())
}

#[test]
fn corrupt_or_incompatible_commit_chain_blocks_store_recovery() -> TestResult {
    let directory = TempDir::new()?;
    let store = ControlStore::open(directory.path())?;
    make_owner(store.clone()).reconcile(
        &resource(&policy()?, "profile", OBJECT_UID, 1, false)?,
        NAMESPACE_UID,
        &inventory(&"1".repeat(64)),
        NOW,
    )?;
    drop(store);

    let first_commit = directory.path().join("commits/00000000000000000001.json");
    let bytes = std::fs::read_to_string(&first_commit)?;
    let incompatible = bytes.replacen("\"schema_version\":1", "\"schema_version\":2", 1);
    std::fs::write(&first_commit, incompatible)?;
    assert!(ControlStore::open(directory.path()).is_err());
    Ok(())
}
