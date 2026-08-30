use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use ed25519_dalek::{SigningKey, VerifyingKey};
use mithril_control::{
    canonical_kubernetes_policy_spec_digest, lower_kubernetes_policy, workload_target_fact_digest,
    ContainerKindV1, ControlPlane, ControlStore, ExceptionActivationAcknowledgementV1,
    ExceptionActivationStateV1, ExceptionDeliveryOperationV1, ExceptionReconcileResultV1,
    ExceptionSourceStateV1, KubernetesConditionStatusV1, KubernetesWorkloadIdentityV1,
    PolicyActivationAcknowledgementV1, PolicyActivationStateV1, PolicyBundleV1,
    PolicyDeliveryOperationV1, PolicyDesiredStateConfigV1, PolicyDesiredStateOwner,
    PolicySignerConfigV1, PolicySourceRevisionV1, PolicySourceStateV1, ProfileSealRequestV1,
    RegistryDigestsV1, TrustGenerationV1, WorkloadProtectionException,
    WorkloadProtectionExceptionStateV1, WorkloadProtectionPolicy, WorkloadProtectionPolicySpec,
    WorkloadTargetFactV1, EXCEPTION_KIND, POLICY_API_VERSION, POLICY_KIND,
};
use serde_json::json;
use tempfile::TempDir;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const POLICY: &str = include_str!("fixtures/kubernetes-policy-v1.yaml");
const ENTRY_ROLES_POLICY: &str = include_str!("fixtures/kubernetes-entry-roles-v1.yaml");
const TENANT_ID: &str = "10000000-0000-4000-8000-000000000001";
const CLUSTER_UID: &str = "55555555-5555-4555-8555-555555555555";
const NAMESPACE_UID: &str = "66666666-6666-4666-8666-666666666666";
const OBJECT_UID: &str = "30000000-0000-4000-8000-000000000001";
const EXCEPTION_UID: &str = "30000000-0000-4000-8000-000000000002";
const NOW: i64 = 1_800_000_000_000_000_000;

fn policy() -> TestResult<WorkloadProtectionPolicySpec> {
    Ok(WorkloadProtectionPolicySpec::parse(
        Path::new("kubernetes-policy-v1.yaml"),
        POLICY.as_bytes(),
    )?)
}

fn resource(
    spec: &WorkloadProtectionPolicySpec,
    name: &str,
    uid: &str,
    generation: u64,
    deleting: bool,
) -> TestResult<WorkloadProtectionPolicy> {
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
    });
    if deleting {
        metadata["deletionTimestamp"] = json!("2027-01-15T00:00:00Z");
    }
    Ok(serde_json::from_value(json!({
        "apiVersion": POLICY_API_VERSION,
        "kind": POLICY_KIND,
        "metadata": metadata,
        "spec": spec,
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

fn inventory(seed: &str) -> TestResult<Vec<WorkloadTargetFactV1>> {
    let spec = policy()?;
    let resource = resource(&spec, "profile", OBJECT_UID, 1, false)?;
    inventory_for_resource(&resource, seed)
}

fn inventory_for_resource(
    resource: &WorkloadProtectionPolicy,
    seed: &str,
) -> TestResult<Vec<WorkloadTargetFactV1>> {
    let policy = lower_kubernetes_policy(resource, TENANT_ID, CLUSTER_UID, NAMESPACE_UID)?;
    let source = PolicySourceRevisionV1::from_resource(
        resource,
        &policy,
        TENANT_ID,
        CLUSTER_UID,
        NAMESPACE_UID,
        if resource.metadata.deletion_timestamp.is_some() {
            PolicySourceStateV1::DeletionRequested
        } else {
            PolicySourceStateV1::Accepted
        },
    )?;
    let mut target = WorkloadTargetFactV1 {
        node_id: "node-a".to_owned(),
        workload_binding_generation_digest: String::new(),
        execution_set_id: "44444444-4444-4444-8444-444444444444".to_owned(),
        cluster_uid: CLUSTER_UID.to_owned(),
        namespace_uid: NAMESPACE_UID.to_owned(),
        controller_uid: "88888888-8888-4888-8888-888888888888".to_owned(),
        service_account_uid: "77777777-7777-4777-8777-777777777777".to_owned(),
        pod_uid: "99999999-9999-4999-8999-999999999999".to_owned(),
        container_id: format!("scheduled:{seed}"),
        container_name: "converter".to_owned(),
        container_kind: ContainerKindV1::Application,
        image_digest: concat!(
            "sha256:",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        )
        .to_owned(),
        pod_labels: BTreeMap::from([("app".to_owned(), "converter".to_owned())]),
        kubernetes: Some(KubernetesWorkloadIdentityV1 {
            namespace_name: "tenant-a".to_owned(),
            pod_name: "converter-pod".to_owned(),
            profile_id: policy.profile_id().to_owned(),
            policy_source_revision_id: source.policy_source_revision_id,
            binding_id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".to_owned(),
            protected_scope_id: policy.protected_universe.protected_scope_ids[0].clone(),
            workload_selector_id: policy.workload_selectors[0].workload_selector_id.clone(),
            kubernetes_node_name: "worker-a".to_owned(),
            kubernetes_node_uid: "dddddddd-dddd-4ddd-8ddd-dddddddddddd".to_owned(),
            node_boot_id: "01".repeat(16),
            label_epoch: 1,
        }),
    };
    target.workload_binding_generation_digest = workload_target_fact_digest(&target)?;
    Ok(vec![target])
}

fn two_node_inventory() -> TestResult<Vec<WorkloadTargetFactV1>> {
    let spec = policy()?;
    let resource = resource(&spec, "profile", OBJECT_UID, 1, false)?;
    two_node_inventory_for_resource(&resource)
}

fn two_node_inventory_for_resource(
    resource: &WorkloadProtectionPolicy,
) -> TestResult<Vec<WorkloadTargetFactV1>> {
    let node_a = inventory_for_resource(resource, &"1".repeat(64))?.remove(0);
    let mut node_b = node_a.clone();
    node_b.node_id = "node-b".to_owned();
    node_b.execution_set_id = "44444444-4444-4444-8444-444444444445".to_owned();
    node_b.pod_uid = "99999999-9999-4999-8999-999999999998".to_owned();
    node_b.container_id = "containerd://converter-b".to_owned();
    if let Some(identity) = node_b.kubernetes.as_mut() {
        identity.pod_name = "converter-pod-b".to_owned();
        identity.binding_id = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaab".to_owned();
        identity.kubernetes_node_name = "worker-b".to_owned();
        identity.kubernetes_node_uid = "dddddddd-dddd-4ddd-8ddd-ddddddddddde".to_owned();
    }
    node_b.workload_binding_generation_digest = workload_target_fact_digest(&node_b)?;
    Ok(vec![node_a, node_b])
}

fn two_workload_inventory_for_resource(
    resource: &WorkloadProtectionPolicy,
) -> TestResult<Vec<WorkloadTargetFactV1>> {
    let first = inventory_for_resource(resource, &"1".repeat(64))?.remove(0);
    let mut second = first.clone();
    second.execution_set_id = "44444444-4444-4444-8444-444444444445".to_owned();
    second.pod_uid = "99999999-9999-4999-8999-999999999998".to_owned();
    second.container_id = "containerd://converter-b".to_owned();
    if let Some(identity) = second.kubernetes.as_mut() {
        identity.pod_name = "converter-pod-b".to_owned();
        identity.binding_id = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaab".to_owned();
    }
    second.workload_binding_generation_digest = workload_target_fact_digest(&second)?;
    Ok(vec![first, second])
}

fn acknowledgement(
    bundle: &PolicyBundleV1,
    state: PolicyActivationStateV1,
    observed_utc_ns: i64,
) -> TestResult<PolicyActivationAcknowledgementV1> {
    let active = state == PolicyActivationStateV1::Active;
    let target = bundle
        .candidate
        .exact_target
        .workload_targets
        .first()
        .ok_or("the policy bundle has no workload target")?;
    let identity = target
        .kubernetes
        .as_ref()
        .ok_or("the policy target has no Kubernetes identity")?;
    Ok(PolicyActivationAcknowledgementV1 {
        acknowledgement_content_id: String::new(),
        tenant_id: TENANT_ID.to_owned(),
        node_id: bundle.candidate.exact_target.node_id.clone(),
        node_boot_id: hex::decode(&identity.node_boot_id)?,
        label_epoch: identity.label_epoch,
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

fn kubernetes_inventory(
    policy_source_revision_id: &str,
    profile_id: &str,
) -> TestResult<Vec<WorkloadTargetFactV1>> {
    let mut target = inventory("")?.remove(0);
    let identity = target
        .kubernetes
        .as_mut()
        .ok_or("the Kubernetes target fixture has no provenance")?;
    identity.profile_id = profile_id.to_owned();
    identity.policy_source_revision_id = policy_source_revision_id.to_owned();
    target.workload_binding_generation_digest = workload_target_fact_digest(&target)?;
    Ok(vec![target])
}

fn exception_resource(uid: &str, deleting: bool) -> TestResult<WorkloadProtectionException> {
    let mut metadata = json!({
        "name": "temporary-file-access",
        "namespace": "tenant-a",
        "uid": uid,
        "generation": 1,
        "resourceVersion": if deleting { "exception-deleting" } else { "exception-active" },
    });
    if deleting {
        metadata["deletionTimestamp"] = json!("2027-01-15T00:00:00Z");
    }
    Ok(serde_json::from_value(json!({
        "apiVersion": POLICY_API_VERSION,
        "kind": EXCEPTION_KIND,
        "metadata": metadata,
        "spec": {
            "policyRef": { "name": "profile" },
            "grant": "temporary-file-access",
            "target": {
                "pod": {
                    "name": "converter-pod",
                    "uid": "99999999-9999-4999-8999-999999999999"
                },
                "containerName": "converter"
            },
            "requestedDuration": "30s",
            "requestedUses": 1
        }
    }))?)
}

fn exception_acknowledgement(
    candidate: &mithril_control::ExceptionDeliveryCandidateV1,
    state: ExceptionActivationStateV1,
    transition_version: u64,
    observed_utc_ns: i64,
) -> TestResult<ExceptionActivationAcknowledgementV1> {
    let rejected = matches!(
        state,
        ExceptionActivationStateV1::Rejected | ExceptionActivationStateV1::Stale
    );
    let identity = candidate
        .exact_target
        .kubernetes
        .as_ref()
        .ok_or("the exception target has no Kubernetes identity")?;
    Ok(ExceptionActivationAcknowledgementV1 {
        acknowledgement_content_id: String::new(),
        tenant_id: TENANT_ID.to_owned(),
        node_id: candidate.exact_target.node_id.clone(),
        node_boot_id: hex::decode(&identity.node_boot_id)?,
        label_epoch: identity.label_epoch,
        candidate_content_id: candidate.candidate_content_id.clone(),
        exception_source_revision_id: candidate.exception_source_revision_id.clone(),
        state,
        consumed_uses: if state == ExceptionActivationStateV1::Consumed {
            candidate.maximum_uses
        } else {
            0
        },
        transition_version,
        observed_utc_ns,
        reason_code: rejected.then(|| "EXCEPTION_REJECTED".to_owned()),
        authenticated_channel_receipt_digest: "5".repeat(64),
    }
    .finalize()?)
}

struct PreparedException {
    owner: PolicyDesiredStateOwner,
    policy_resource: WorkloadProtectionPolicy,
    inventory: Vec<WorkloadTargetFactV1>,
    resource: WorkloadProtectionException,
    activation: ExceptionReconcileResultV1,
}

fn prepare_exception(store: &ControlStore) -> TestResult<PreparedException> {
    let owner = make_owner(store.clone());
    let policy_resource = resource(&policy()?, "profile", OBJECT_UID, 1, false)?;
    let initial = owner.reconcile(
        &policy_resource,
        NAMESPACE_UID,
        &inventory(&"1".repeat(64))?,
        NOW,
    )?;
    let profile_id = &initial.bundles[0]
        .profile_artifact
        .policy_document
        .metadata
        .profile_id;
    let inventory = kubernetes_inventory(
        &initial.source_revision.policy_source_revision_id,
        profile_id,
    )?;
    let bound = owner.reconcile(&policy_resource, NAMESPACE_UID, &inventory, NOW + 1)?;
    owner.rollout_owner().acknowledge(acknowledgement(
        &bound.bundles[0],
        PolicyActivationStateV1::Active,
        NOW + 2,
    )?)?;
    let resource = exception_resource(EXCEPTION_UID, false)?;
    let activation = owner.reconcile_exception(&resource, NAMESPACE_UID, &inventory, NOW + 3)?;
    Ok(PreparedException {
        owner,
        policy_resource,
        inventory,
        resource,
        activation,
    })
}

#[test]
fn kubernetes_outage_exception_uses_current_policy_with_admission_provenance() -> TestResult {
    let directory = TempDir::new()?;
    let owner = make_owner(ControlStore::open(directory.path())?);
    let policy = policy()?;
    let policy_v1 = resource(&policy, "profile", OBJECT_UID, 1, false)?;
    let initial = owner.reconcile(&policy_v1, NAMESPACE_UID, &inventory(&"1".repeat(64))?, NOW)?;
    let admitted_source_revision_id = initial.source_revision.policy_source_revision_id;
    let profile_id = initial.bundles[0]
        .profile_artifact
        .policy_document
        .metadata
        .profile_id
        .clone();
    let inventory = kubernetes_inventory(&admitted_source_revision_id, &profile_id)?;
    let bound_v1 = owner.reconcile(&policy_v1, NAMESPACE_UID, &inventory, NOW + 1)?;
    owner.rollout_owner().acknowledge(acknowledgement(
        &bound_v1.bundles[0],
        PolicyActivationStateV1::Active,
        NOW + 2,
    )?)?;

    let policy_v2 = resource(&policy, "profile", OBJECT_UID, 2, false)?;
    let bound_v2 = owner.reconcile(&policy_v2, NAMESPACE_UID, &inventory, NOW + 3)?;
    let current_source_revision_id = bound_v2.source_revision.policy_source_revision_id.clone();
    assert_ne!(current_source_revision_id, admitted_source_revision_id);
    owner.rollout_owner().acknowledge(acknowledgement(
        &bound_v2.bundles[0],
        PolicyActivationStateV1::Active,
        NOW + 4,
    )?)?;

    let activated = owner.reconcile_exception(
        &exception_resource(EXCEPTION_UID, false)?,
        NAMESPACE_UID,
        &inventory,
        NOW + 5,
    )?;
    assert_eq!(
        activated.candidate.base_policy_source_revision_id,
        current_source_revision_id
    );
    assert_eq!(
        activated
            .candidate
            .exact_target
            .kubernetes
            .as_ref()
            .map(|identity| identity.policy_source_revision_id.as_str()),
        Some(admitted_source_revision_id.as_str())
    );
    Ok(())
}

#[test]
fn exception_is_bounded_to_one_active_container_and_replays_revocation() -> TestResult {
    let directory = TempDir::new()?;
    let store = ControlStore::open(directory.path())?;
    let owner = make_owner(store.clone());
    let policy = policy()?;
    let policy_resource = resource(&policy, "profile", OBJECT_UID, 1, false)?;
    let policy_resource_v2 = resource(&policy, "profile", OBJECT_UID, 2, false)?;
    let initial = owner.reconcile(
        &policy_resource,
        NAMESPACE_UID,
        &inventory(&"1".repeat(64))?,
        NOW,
    )?;
    let profile_id = &initial.bundles[0]
        .profile_artifact
        .policy_document
        .metadata
        .profile_id;
    let inventory = kubernetes_inventory(
        &initial.source_revision.policy_source_revision_id,
        profile_id,
    )?;
    let bound = owner.reconcile(&policy_resource, NAMESPACE_UID, &inventory, NOW + 1)?;
    owner.rollout_owner().acknowledge(acknowledgement(
        &bound.bundles[0],
        PolicyActivationStateV1::Active,
        NOW + 2,
    )?)?;

    let resource = exception_resource(EXCEPTION_UID, false)?;
    let activated = owner.reconcile_exception(&resource, NAMESPACE_UID, &inventory, NOW + 3)?;
    assert_eq!(
        activated.candidate.operation,
        ExceptionDeliveryOperationV1::Activate
    );
    assert_eq!(activated.candidate.maximum_uses, 1);
    assert_eq!(
        activated
            .candidate
            .exact_target
            .workload_binding_generation_digest,
        inventory[0].workload_binding_generation_digest
    );
    assert!(store
        .next_exception_candidate_for_node("node-b", &[])?
        .is_none());
    assert_eq!(
        store
            .next_exception_candidate_for_node("node-a", &[])?
            .map(|candidate| candidate.candidate_content_id),
        Some(activated.candidate.candidate_content_id.clone())
    );
    assert!(store
        .next_exception_candidate_for_node(
            "node-a",
            std::slice::from_ref(&activated.candidate.candidate_content_id),
        )?
        .is_none());
    let pending_health = store.health()?;
    assert_eq!(pending_health.exception_candidates, 1);
    assert_eq!(pending_health.unsettled_exception_candidates, 1);
    let commit_index = store.commit_index();
    let duplicate = owner.reconcile_exception(&resource, NAMESPACE_UID, &inventory, NOW + 4)?;
    assert_eq!(duplicate.source_revision, activated.source_revision);
    assert_eq!(duplicate.candidate, activated.candidate);
    assert_eq!(duplicate.rollout_state, activated.rollout_state);
    assert_eq!(store.commit_index(), commit_index);

    owner
        .rollout_owner()
        .acknowledge_exception(exception_acknowledgement(
            &activated.candidate,
            ExceptionActivationStateV1::Active,
            1,
            NOW + 5,
        )?)?;
    assert_eq!(store.health()?.unsettled_exception_candidates, 0);
    let mut overlapping = exception_resource("30000000-0000-4000-8000-000000000003", false)?;
    overlapping.metadata.name = Some("temporary-file-access-overlap".to_owned());
    assert!(owner
        .reconcile_exception(&overlapping, NAMESPACE_UID, &inventory, NOW + 6)
        .is_err());

    drop(owner);
    drop(store);
    let reopened = ControlStore::open(directory.path())?;
    let restarted = make_owner(reopened.clone());
    let restored = restarted.reconcile_exception(&resource, NAMESPACE_UID, &inventory, NOW + 7)?;
    assert_eq!(restored.candidate, activated.candidate);
    assert_eq!(
        restored.status.state,
        mithril_control::WorkloadProtectionExceptionStateV1::Active
    );

    // Revocation remains deliverable after the short-lived exception authority expires.
    let deleting = exception_resource(EXCEPTION_UID, true)?;
    let revoked =
        restarted.reconcile_exception(&deleting, NAMESPACE_UID, &[], NOW + 120_000_000_000)?;
    assert_eq!(reopened.health()?.exception_candidates, 2);
    assert_eq!(reopened.health()?.unsettled_exception_candidates, 1);
    assert_eq!(
        revoked.candidate.operation,
        ExceptionDeliveryOperationV1::Revoke
    );
    assert_eq!(
        revoked
            .candidate
            .predecessor_candidate_content_id
            .as_deref(),
        Some(activated.candidate.candidate_content_id.as_str())
    );
    revoked.candidate.verify(
        &SigningKey::from_bytes(&[7; 32]).verifying_key(),
        "node-a",
        NOW + 120_000_000_001,
    )?;
    restarted
        .rollout_owner()
        .acknowledge_exception(exception_acknowledgement(
            &revoked.candidate,
            ExceptionActivationStateV1::Revoked,
            1,
            NOW + 120_000_000_002,
        )?)?;
    assert_eq!(reopened.health()?.unsettled_exception_candidates, 0);

    let policy_v2_inventory = inventory_for_resource(&policy_resource_v2, "")?;
    let policy_v2 = restarted.reconcile(
        &policy_resource_v2,
        NAMESPACE_UID,
        &policy_v2_inventory,
        NOW + 120_000_000_003,
    )?;
    restarted.rollout_owner().acknowledge(acknowledgement(
        &policy_v2.bundles[0],
        PolicyActivationStateV1::Active,
        NOW + 120_000_000_004,
    )?)?;

    let mut replacement_inventory = policy_v2_inventory;
    replacement_inventory[0].execution_set_id = "44444444-4444-4444-8444-444444444445".to_owned();
    replacement_inventory[0].pod_uid = "99999999-9999-4999-8999-999999999998".to_owned();
    replacement_inventory[0].container_id = "containerd://converter-recreated".to_owned();
    if let Some(identity) = replacement_inventory[0].kubernetes.as_mut() {
        identity.binding_id = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaab".to_owned();
        identity.node_boot_id = "02".repeat(16);
        identity.label_epoch = 2;
    }
    replacement_inventory[0].workload_binding_generation_digest =
        workload_target_fact_digest(&replacement_inventory[0])?;
    let replacement = restarted.reconcile(
        &policy_resource_v2,
        NAMESPACE_UID,
        &replacement_inventory,
        NOW + 120_000_000_005,
    )?;
    restarted.rollout_owner().acknowledge(acknowledgement(
        &replacement.bundles[0],
        PolicyActivationStateV1::Active,
        NOW + 120_000_000_006,
    )?)?;
    drop(restarted);
    drop(reopened);
    let recovered_store = ControlStore::open(directory.path())?;
    let recovered_owner = make_owner(recovered_store.clone());
    let empty = recovered_owner.reconcile(
        &policy_resource_v2,
        NAMESPACE_UID,
        &[],
        NOW + 120_000_000_007,
    )?;
    assert!(empty.bundles.is_empty());
    let recovered = recovered_owner.reconcile(
        &policy_resource_v2,
        NAMESPACE_UID,
        &replacement_inventory,
        NOW + 120_000_000_008,
    )?;
    assert_ne!(
        recovered.bundles[0].candidate.candidate_content_id,
        replacement.bundles[0].candidate.candidate_content_id
    );
    let mut recreated_resource = exception_resource("30000000-0000-4000-8000-000000000009", false)?;
    recreated_resource.spec.target.pod.uid = replacement_inventory[0].pod_uid.clone();
    assert!(recovered_owner
        .reconcile_exception(
            &recreated_resource,
            NAMESPACE_UID,
            &replacement_inventory,
            NOW + 120_000_000_009,
        )
        .is_err());
    recovered_owner
        .rollout_owner()
        .acknowledge(acknowledgement(
            &recovered.bundles[0],
            PolicyActivationStateV1::Active,
            NOW + 120_000_000_010,
        )?)?;
    drop(recovered_owner);
    drop(recovered_store);
    let restarted = make_owner(ControlStore::open(directory.path())?);

    let recreated = restarted.reconcile_exception(
        &recreated_resource,
        NAMESPACE_UID,
        &replacement_inventory,
        NOW + 120_000_000_011,
    )?;
    assert_eq!(recreated.candidate.exact_target, replacement_inventory[0]);
    let retired_policy_target = restarted.reconcile(
        &policy_resource_v2,
        NAMESPACE_UID,
        &[],
        NOW + 120_000_000_012,
    )?;
    assert!(retired_policy_target.bundles.is_empty());
    let target_retirement = restarted.reconcile_exception(
        &recreated_resource,
        NAMESPACE_UID,
        &[],
        NOW + 120_000_000_013,
    )?;
    assert_eq!(
        target_retirement
            .candidate
            .predecessor_candidate_content_id
            .as_deref(),
        Some(recreated.candidate.candidate_content_id.as_str())
    );
    drop(restarted);
    assert!(ControlStore::open(directory.path()).is_ok());
    Ok(())
}

#[test]
fn exception_acknowledgement_reuses_a_durable_transition_after_response_loss() -> TestResult {
    let directory = TempDir::new()?;
    let store = ControlStore::open(directory.path())?;
    let prepared = prepare_exception(&store)?;
    let acknowledgement = exception_acknowledgement(
        &prepared.activation.candidate,
        ExceptionActivationStateV1::Active,
        1,
        NOW + 4,
    )?;
    let accepted = prepared
        .owner
        .rollout_owner()
        .acknowledge_exception(acknowledgement.clone())?;
    let committed = store.commit_index();
    let replay = ExceptionActivationAcknowledgementV1 {
        acknowledgement_content_id: String::new(),
        authenticated_channel_receipt_digest: "6".repeat(64),
        ..acknowledgement.clone()
    }
    .finalize()?;

    assert_ne!(
        replay.acknowledgement_content_id,
        accepted
            .latest_acknowledgement_content_id
            .clone()
            .unwrap_or_default()
    );
    assert_eq!(
        prepared
            .owner
            .rollout_owner()
            .acknowledge_exception(replay)?,
        accepted
    );
    assert_eq!(store.commit_index(), committed);
    let conflicting_replay = ExceptionActivationAcknowledgementV1 {
        acknowledgement_content_id: String::new(),
        authenticated_channel_receipt_digest: "7".repeat(64),
        observed_utc_ns: NOW + 5,
        ..acknowledgement
    }
    .finalize()?;
    assert!(prepared
        .owner
        .rollout_owner()
        .acknowledge_exception(conflicting_replay)
        .is_err());
    assert_eq!(store.commit_index(), committed);
    Ok(())
}

#[test]
fn missing_exact_target_revokes_the_accepted_exception_once() -> TestResult {
    let directory = TempDir::new()?;
    let store = ControlStore::open(directory.path())?;
    let mut prepared = prepare_exception(&store)?;
    prepared
        .owner
        .rollout_owner()
        .acknowledge_exception(exception_acknowledgement(
            &prepared.activation.candidate,
            ExceptionActivationStateV1::Active,
            1,
            NOW + 4,
        )?)?;

    let commit_before_status_update = store.commit_index();
    prepared.resource.metadata.resource_version = Some("exception-status-update".to_owned());
    let status_update = prepared.owner.reconcile_exception(
        &prepared.resource,
        NAMESPACE_UID,
        &prepared.inventory,
        NOW + 5,
    )?;
    assert_eq!(status_update.candidate, prepared.activation.candidate);
    assert_eq!(store.commit_index(), commit_before_status_update);

    let commit_before_incomplete_inventory = store.commit_index();
    assert!(prepared
        .owner
        .reconcile_exception(&prepared.resource, NAMESPACE_UID, &[], NOW + 6)
        .is_err());
    assert_eq!(store.commit_index(), commit_before_incomplete_inventory);

    let mut replacement_inventory = prepared.inventory.clone();
    replacement_inventory[0].pod_uid = "99999999-9999-4999-8999-999999999998".to_owned();
    replacement_inventory[0].workload_binding_generation_digest =
        workload_target_fact_digest(&replacement_inventory[0])?;
    prepared.owner.reconcile(
        &prepared.policy_resource,
        NAMESPACE_UID,
        &replacement_inventory,
        NOW + 7,
    )?;
    let retired = prepared.owner.reconcile_exception(
        &prepared.resource,
        NAMESPACE_UID,
        &replacement_inventory,
        NOW + 8,
    )?;

    assert_eq!(retired.source_revision, prepared.activation.source_revision);
    assert_eq!(
        retired.source_revision.state,
        ExceptionSourceStateV1::Accepted
    );
    assert_eq!(
        retired.candidate.operation,
        ExceptionDeliveryOperationV1::Revoke
    );
    assert_eq!(
        retired.candidate.exact_target,
        prepared.activation.candidate.exact_target
    );
    assert_eq!(
        retired.candidate.maximum_uses,
        prepared.activation.candidate.maximum_uses
    );
    assert_eq!(
        retired.candidate.valid_until_utc_ns,
        prepared.activation.candidate.valid_until_utc_ns
    );
    assert_eq!(
        retired
            .candidate
            .predecessor_candidate_content_id
            .as_deref(),
        Some(prepared.activation.candidate.candidate_content_id.as_str())
    );
    assert!(retired.candidate.expires_utc_ns >= retired.candidate.valid_until_utc_ns);
    assert!(retired
        .status
        .conditions
        .iter()
        .any(|condition| condition.reason == "TargetRetirementPending"));
    assert_eq!(
        store
            .next_exception_candidate_for_node("node-a", &[])?
            .map(|candidate| candidate.candidate_content_id),
        Some(retired.candidate.candidate_content_id.clone())
    );

    let retirement_commit = store.commit_index();
    let duplicate = prepared.owner.reconcile_exception(
        &prepared.resource,
        NAMESPACE_UID,
        &replacement_inventory,
        NOW + 9,
    )?;
    assert_eq!(duplicate.candidate, retired.candidate);
    assert_eq!(store.commit_index(), retirement_commit);

    drop(prepared.owner);
    drop(store);
    let reopened = ControlStore::open(directory.path())?;
    let restarted = make_owner(reopened.clone());
    let replayed = restarted.reconcile_exception(
        &prepared.resource,
        NAMESPACE_UID,
        &replacement_inventory,
        NOW + 10,
    )?;
    assert_eq!(replayed.candidate, retired.candidate);
    assert_eq!(reopened.commit_index(), retirement_commit);
    restarted
        .rollout_owner()
        .acknowledge_exception(exception_acknowledgement(
            &retired.candidate,
            ExceptionActivationStateV1::Revoked,
            1,
            NOW + 11,
        )?)?;

    let reappeared = restarted.reconcile_exception(
        &prepared.resource,
        NAMESPACE_UID,
        &prepared.inventory,
        NOW + 12,
    )?;
    assert_eq!(reappeared.candidate, retired.candidate);
    assert_eq!(
        reappeared.status.state,
        WorkloadProtectionExceptionStateV1::Revoked
    );
    Ok(())
}

#[test]
fn pending_activation_settles_before_target_retirement() -> TestResult {
    let directory = TempDir::new()?;
    let store = ControlStore::open(directory.path())?;
    let prepared = prepare_exception(&store)?;
    prepared
        .owner
        .reconcile(&prepared.policy_resource, NAMESPACE_UID, &[], NOW + 4)?;
    let retired =
        prepared
            .owner
            .reconcile_exception(&prepared.resource, NAMESPACE_UID, &[], NOW + 5)?;

    let first = store
        .next_exception_candidate_for_node("node-a", &[])?
        .ok_or("the pending activation is not deliverable")?;
    assert_eq!(first, prepared.activation.candidate);
    prepared
        .owner
        .rollout_owner()
        .acknowledge_exception(exception_acknowledgement(
            &prepared.activation.candidate,
            ExceptionActivationStateV1::Expired,
            1,
            NOW + 6,
        )?)?;
    let second = store
        .next_exception_candidate_for_node("node-a", &[])?
        .ok_or("the target retirement is not deliverable")?;
    assert_eq!(second, retired.candidate);
    assert_eq!(
        retired
            .candidate
            .predecessor_candidate_content_id
            .as_deref(),
        Some(prepared.activation.candidate.candidate_content_id.as_str())
    );
    Ok(())
}

#[test]
fn exception_activation_precedes_revocation_when_delete_arrives_before_poll() -> TestResult {
    let directory = TempDir::new()?;
    let store = ControlStore::open(directory.path())?;
    let owner = make_owner(store.clone());
    let policy = policy()?;
    let policy_resource = resource(&policy, "profile", OBJECT_UID, 1, false)?;
    let initial = owner.reconcile(
        &policy_resource,
        NAMESPACE_UID,
        &inventory(&"1".repeat(64))?,
        NOW,
    )?;
    let profile_id = initial.bundles[0]
        .profile_artifact
        .policy_document
        .metadata
        .profile_id
        .clone();
    let inventory = kubernetes_inventory(
        &initial.source_revision.policy_source_revision_id,
        &profile_id,
    )?;
    let bound = owner.reconcile(&policy_resource, NAMESPACE_UID, &inventory, NOW + 1)?;
    owner.rollout_owner().acknowledge(acknowledgement(
        &bound.bundles[0],
        PolicyActivationStateV1::Active,
        NOW + 2,
    )?)?;

    let activated = owner.reconcile_exception(
        &exception_resource(EXCEPTION_UID, false)?,
        NAMESPACE_UID,
        &inventory,
        NOW + 3,
    )?;
    let revoked = owner.reconcile_exception(
        &exception_resource(EXCEPTION_UID, true)?,
        NAMESPACE_UID,
        &[],
        NOW + 4,
    )?;

    let first = store
        .next_exception_candidate_for_node("node-a", &[])?
        .ok_or("the exception activation is not deliverable")?;
    assert_eq!(first, activated.candidate);
    assert!(store
        .next_exception_candidate_for_node(
            "node-a",
            std::slice::from_ref(&activated.candidate.candidate_content_id),
        )?
        .is_none());

    owner
        .rollout_owner()
        .acknowledge_exception(exception_acknowledgement(
            &activated.candidate,
            ExceptionActivationStateV1::Active,
            1,
            NOW + 5,
        )?)?;
    let second = store
        .next_exception_candidate_for_node("node-a", &[])?
        .ok_or("the exception revocation is not deliverable")?;
    assert_eq!(second, revoked.candidate);
    Ok(())
}

#[test]
fn terminal_exception_does_not_block_a_new_bounded_instance() -> TestResult {
    let directory = TempDir::new()?;
    let store = ControlStore::open(directory.path())?;
    let owner = make_owner(store);
    let policy = policy()?;
    let policy_resource = resource(&policy, "profile", OBJECT_UID, 1, false)?;
    let initial = owner.reconcile(
        &policy_resource,
        NAMESPACE_UID,
        &inventory(&"1".repeat(64))?,
        NOW,
    )?;
    let profile_id = &initial.bundles[0]
        .profile_artifact
        .policy_document
        .metadata
        .profile_id;
    let inventory = kubernetes_inventory(
        &initial.source_revision.policy_source_revision_id,
        profile_id,
    )?;
    let bound = owner.reconcile(&policy_resource, NAMESPACE_UID, &inventory, NOW + 1)?;
    owner.rollout_owner().acknowledge(acknowledgement(
        &bound.bundles[0],
        PolicyActivationStateV1::Active,
        NOW + 2,
    )?)?;

    let first = owner.reconcile_exception(
        &exception_resource(EXCEPTION_UID, false)?,
        NAMESPACE_UID,
        &inventory,
        NOW + 3,
    )?;
    owner
        .rollout_owner()
        .acknowledge_exception(exception_acknowledgement(
            &first.candidate,
            ExceptionActivationStateV1::Consumed,
            1,
            NOW + 4,
        )?)?;

    let mut next_resource = exception_resource("30000000-0000-4000-8000-000000000003", false)?;
    next_resource.metadata.name = Some("temporary-file-access-next".to_owned());
    let next = owner.reconcile_exception(&next_resource, NAMESPACE_UID, &inventory, NOW + 5)?;
    assert_eq!(
        next.rollout_state.state,
        mithril_control::WorkloadProtectionExceptionStateV1::Pending
    );
    assert_ne!(
        next.candidate.exception_instance_id,
        first.candidate.exception_instance_id
    );
    Ok(())
}

#[test]
fn activation_delivery_covers_the_complete_bounded_authority_window() -> TestResult {
    let directory = TempDir::new()?;
    let store = ControlStore::open(directory.path())?;
    let owner = make_owner(store);
    let policy = policy()?;
    let policy_resource = resource(&policy, "profile", OBJECT_UID, 1, false)?;
    let initial = owner.reconcile(
        &policy_resource,
        NAMESPACE_UID,
        &inventory(&"1".repeat(64))?,
        NOW,
    )?;
    let profile_id = initial.bundles[0]
        .profile_artifact
        .policy_document
        .metadata
        .profile_id
        .clone();
    let inventory = kubernetes_inventory(
        &initial.source_revision.policy_source_revision_id,
        &profile_id,
    )?;
    let bound = owner.reconcile(&policy_resource, NAMESPACE_UID, &inventory, NOW + 1)?;
    owner.rollout_owner().acknowledge(acknowledgement(
        &bound.bundles[0],
        PolicyActivationStateV1::Active,
        NOW + 2,
    )?)?;
    let mut exception = exception_resource(EXCEPTION_UID, false)?;
    exception.spec.requested_duration = "2m".to_owned();
    let activated = owner.reconcile_exception(&exception, NAMESPACE_UID, &inventory, NOW + 3)?;

    assert_eq!(
        activated.candidate.expires_utc_ns,
        activated.candidate.valid_until_utc_ns
    );
    activated.candidate.verify(
        &SigningKey::from_bytes(&[7; 32]).verifying_key(),
        "node-a",
        NOW + 90_000_000_000,
    )?;
    Ok(())
}

#[test]
fn create_update_duplicate_and_restart_preserve_one_monotonic_rollout() -> TestResult {
    let directory = TempDir::new()?;
    let store = ControlStore::open(directory.path())?;
    let owner = make_owner(store.clone());
    let first_policy = policy()?;
    let first_resource = resource(&first_policy, "profile", OBJECT_UID, 1, false)?;
    let first_inventory = inventory_for_resource(&first_resource, &"1".repeat(64))?;
    let first = owner.reconcile(&first_resource, NAMESPACE_UID, &first_inventory, NOW)?;
    assert_eq!(first.bundles.len(), 1);
    assert_eq!(
        first.bundles[0].candidate.operation,
        PolicyDeliveryOperationV1::Activate
    );
    assert_eq!(first.bundles[0].candidate.distribution_sequence, 1);
    assert_eq!(first.bundles[0].profile_artifact.header.issuer_sequence, 1);

    let first_commit = store.commit_index();
    let duplicate = owner.reconcile(&first_resource, NAMESPACE_UID, &first_inventory, NOW)?;
    assert_eq!(duplicate, first);
    assert_eq!(store.commit_index(), first_commit);

    let mut second_policy = first_policy;
    second_policy.roles[0].files[0].operations.reverse();
    let second_resource = resource(&second_policy, "profile", OBJECT_UID, 2, false)?;
    let second_inventory = first_inventory.clone();
    let second = owner.reconcile(&second_resource, NAMESPACE_UID, &second_inventory, NOW + 1)?;
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
        &second_inventory,
        NOW + 2,
    );
    assert!(stale.is_err());

    drop(owner);
    drop(store);
    let reopened = ControlStore::open(directory.path())?;
    let restarted = make_owner(reopened.clone()).reconcile(
        &second_resource,
        NAMESPACE_UID,
        &second_inventory,
        NOW + 3,
    )?;
    assert_eq!(restarted.bundles, second.bundles);
    assert_eq!(reopened.commit_index(), 4);
    Ok(())
}

#[test]
fn kubernetes_outage_partial_two_node_update_survives_control_restart() -> TestResult {
    let directory = TempDir::new()?;
    let store = ControlStore::open(directory.path())?;
    let owner = make_owner(store.clone());

    let first_policy = policy()?;
    let first_resource = resource(&first_policy, "profile", OBJECT_UID, 1, false)?;
    let first_inventory = two_node_inventory_for_resource(&first_resource)?;
    let first = owner.reconcile(&first_resource, NAMESPACE_UID, &first_inventory, NOW)?;
    for bundle in &first.bundles {
        owner.rollout_owner().acknowledge(acknowledgement(
            bundle,
            PolicyActivationStateV1::Active,
            NOW + 1,
        )?)?;
    }

    let mut second_policy = first_policy;
    second_policy.roles[0].files[0].operations.reverse();
    let second_resource = resource(&second_policy, "profile", OBJECT_UID, 2, false)?;
    let second_inventory = two_node_inventory_for_resource(&second_resource)?;
    let second = owner.reconcile(&second_resource, NAMESPACE_UID, &second_inventory, NOW + 2)?;
    let node_a = second
        .bundles
        .iter()
        .find(|bundle| bundle.candidate.exact_target.node_id == "node-a")
        .ok_or("the replacement rollout has no node-a bundle")?;
    let node_b = second
        .bundles
        .iter()
        .find(|bundle| bundle.candidate.exact_target.node_id == "node-b")
        .ok_or("the replacement rollout has no node-b bundle")?;
    assert_eq!(
        node_a.candidate.operation,
        PolicyDeliveryOperationV1::Replace
    );
    assert_eq!(
        node_b.candidate.operation,
        PolicyDeliveryOperationV1::Replace
    );

    owner.rollout_owner().acknowledge(acknowledgement(
        node_a,
        PolicyActivationStateV1::Active,
        NOW + 3,
    )?)?;
    let mixed = owner.reconcile(&second_resource, NAMESPACE_UID, &second_inventory, NOW + 4)?;
    assert_eq!(mixed.status.rollout.desired, 2);
    assert_eq!(mixed.status.rollout.active, 1);
    assert_eq!(mixed.status.rollout.updating, 1);
    assert_eq!(mixed.status.rollout.failed, 0);

    let first_node_b = first
        .bundles
        .iter()
        .find(|bundle| bundle.candidate.exact_target.node_id == "node-b")
        .ok_or("the initial rollout has no node-b bundle")?;
    assert_eq!(
        store.next_bundle_for_node("node-b", std::slice::from_ref(&first_node_b.bundle_digest),)?,
        Some(node_b.clone())
    );

    drop(owner);
    drop(store);
    let reopened = ControlStore::open(directory.path())?;
    let recovered = make_owner(reopened).reconcile(
        &second_resource,
        NAMESPACE_UID,
        &second_inventory,
        NOW + 5,
    )?;
    assert_eq!(recovered.status.rollout, mixed.status.rollout);
    assert_eq!(recovered.bundles, second.bundles);
    Ok(())
}

#[test]
fn kubernetes_outage_candidate_accepts_bounded_clock_skew() -> TestResult {
    let directory = TempDir::new()?;
    let owner = make_owner(ControlStore::open(directory.path())?);
    let resource = resource(&policy()?, "profile", OBJECT_UID, 1, false)?;
    let inventory = inventory_for_resource(&resource, &"1".repeat(64))?;
    let reconciled = owner.reconcile(&resource, NAMESPACE_UID, &inventory, NOW)?;
    let bundle = reconciled
        .bundles
        .first()
        .ok_or("the rollout has no policy bundle")?;
    let key_bytes: [u8; 32] = bundle.profile_signing_public_key.as_slice().try_into()?;
    let key = VerifyingKey::from_bytes(&key_bytes)?;
    let before_issue = bundle.candidate.issued_utc_ns - 1;

    assert!(bundle
        .verify(&key, &bundle.candidate.exact_target.node_id, before_issue)
        .is_err());
    bundle.verify_with_clock_skew(
        &key,
        &bundle.candidate.exact_target.node_id,
        before_issue,
        1,
    )?;
    assert!(bundle
        .verify_with_clock_skew(
            &key,
            &bundle.candidate.exact_target.node_id,
            before_issue,
            300_000_000_001,
        )
        .is_err());
    Ok(())
}

#[test]
fn policy_delivery_skips_superseded_candidates_before_node_poll() -> TestResult {
    let directory = TempDir::new()?;
    let store = ControlStore::open(directory.path())?;
    let owner = make_owner(store.clone());

    let first_policy = policy()?;
    let first_resource = resource(&first_policy, "profile", OBJECT_UID, 1, false)?;
    let first_inventory = inventory_for_resource(&first_resource, &"1".repeat(64))?;
    let first = owner.reconcile(&first_resource, NAMESPACE_UID, &first_inventory, NOW)?;
    owner.rollout_owner().acknowledge(acknowledgement(
        &first.bundles[0],
        PolicyActivationStateV1::Active,
        NOW + 1,
    )?)?;

    let mut second_policy = first_policy;
    second_policy.roles[0].files[0].operations.reverse();
    let second_resource = resource(&second_policy, "profile", OBJECT_UID, 2, false)?;
    let second_inventory = inventory_for_resource(&second_resource, &"1".repeat(64))?;
    let second = owner.reconcile(&second_resource, NAMESPACE_UID, &second_inventory, NOW + 2)?;

    second_policy.roles[0].files[0].operations.rotate_left(1);
    let third_resource = resource(&second_policy, "profile", OBJECT_UID, 3, false)?;
    let third_inventory = inventory_for_resource(&third_resource, &"1".repeat(64))?;
    let third = owner.reconcile(&third_resource, NAMESPACE_UID, &third_inventory, NOW + 3)?;

    let first_bundle = &first.bundles[0];
    let second_bundle = &second.bundles[0];
    let third_bundle = &third.bundles[0];
    assert_eq!(
        second_bundle
            .candidate
            .predecessor_candidate_content_id
            .as_deref(),
        Some(first_bundle.candidate.candidate_content_id.as_str())
    );
    assert_eq!(
        third_bundle
            .candidate
            .predecessor_candidate_content_id
            .as_deref(),
        Some(second_bundle.candidate.candidate_content_id.as_str())
    );

    let current = store
        .next_bundle_for_node("node-a", &[])?
        .ok_or("the current desired candidate is not recoverable")?;
    assert_eq!(current, *third_bundle);
    let next = store
        .next_bundle_for_node("node-a", std::slice::from_ref(&first_bundle.bundle_digest))?
        .ok_or("the current desired replacement is not deliverable")?;
    assert_eq!(next, *third_bundle);

    owner.rollout_owner().acknowledge(acknowledgement(
        third_bundle,
        PolicyActivationStateV1::Active,
        NOW + 4,
    )?)?;
    assert!(owner
        .rollout_owner()
        .acknowledge(acknowledgement(
            first_bundle,
            PolicyActivationStateV1::Active,
            NOW + 5,
        )?)
        .is_err());
    assert!(store
        .next_bundle_for_node("node-a", std::slice::from_ref(&third_bundle.bundle_digest))?
        .is_none());
    Ok(())
}

#[test]
fn bound_inventory_change_reconciles_without_a_policy_source_change() -> TestResult {
    let directory = TempDir::new()?;
    let store = ControlStore::open(directory.path())?;
    let owner = make_owner(store);
    let policy = policy()?;
    let resource = resource(&policy, "profile", OBJECT_UID, 1, false)?;
    let first = owner.reconcile(&resource, NAMESPACE_UID, &inventory(&"1".repeat(64))?, NOW)?;
    let second = owner.reconcile(&resource, NAMESPACE_UID, &two_node_inventory()?, NOW + 1)?;

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
fn kubernetes_node_uid_rebind_keeps_the_exact_physical_predecessor() -> TestResult {
    let directory = TempDir::new()?;
    let store = ControlStore::open(directory.path())?;
    let owner = make_owner(store.clone());
    let policy = policy()?;
    let resource = resource(&policy, "profile", OBJECT_UID, 1, false)?;
    let first_inventory = inventory_for_resource(&resource, &"1".repeat(64))?;
    let first = owner.reconcile(&resource, NAMESPACE_UID, &first_inventory, NOW)?;
    let first_bundle = first.bundles[0].clone();
    let active_acknowledgement =
        acknowledgement(&first_bundle, PolicyActivationStateV1::Active, NOW + 1)?;

    let mut rebound_inventory = first_inventory;
    let identity = rebound_inventory[0]
        .kubernetes
        .as_mut()
        .ok_or("the rebound target has no Kubernetes identity")?;
    identity.kubernetes_node_uid = "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee".to_owned();
    rebound_inventory[0].workload_binding_generation_digest =
        workload_target_fact_digest(&rebound_inventory[0])?;
    let rebound = owner.reconcile(&resource, NAMESPACE_UID, &rebound_inventory, NOW + 2)?;
    let rebound_bundle = &rebound.bundles[0];

    assert_eq!(
        rebound_bundle.candidate.operation,
        PolicyDeliveryOperationV1::Replace
    );
    assert_eq!(
        rebound_bundle
            .candidate
            .predecessor_candidate_content_id
            .as_deref(),
        Some(first_bundle.candidate.candidate_content_id.as_str())
    );
    assert_eq!(
        rebound_bundle.candidate.exact_target.workload_targets[0]
            .kubernetes
            .as_ref()
            .map(|identity| identity.kubernetes_node_uid.as_str()),
        Some("eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee")
    );
    // The old UID does not invalidate a delayed ACK from the same physical epoch.
    owner.rollout_owner().acknowledge(active_acknowledgement)?;

    let committed = store.commit_index();
    drop(owner);
    drop(store);
    let replayed = ControlStore::open(directory.path())?;
    let result = make_owner(replayed.clone()).reconcile(
        &resource,
        NAMESPACE_UID,
        &rebound_inventory,
        NOW + 3,
    )?;
    assert_eq!(result.bundles, rebound.bundles);
    assert_eq!(replayed.commit_index(), committed);
    Ok(())
}

#[test]
fn removed_node_is_withdrawn_without_a_terminal_candidate() -> TestResult {
    let directory = TempDir::new()?;
    let store = ControlStore::open(directory.path())?;
    let owner = make_owner(store.clone());
    let policy = policy()?;
    let resource = resource(&policy, "profile", OBJECT_UID, 1, false)?;
    let inventory = two_node_inventory_for_resource(&resource)?;
    let first = owner.reconcile(&resource, NAMESPACE_UID, &inventory, NOW)?;
    let removed = first
        .bundles
        .iter()
        .find(|bundle| bundle.candidate.exact_target.node_id == "node-b")
        .ok_or("the initial rollout has no node-b bundle")?
        .clone();

    let shrunk = owner.reconcile(
        &resource,
        NAMESPACE_UID,
        std::slice::from_ref(&inventory[0]),
        NOW + 1,
    )?;

    assert_eq!(shrunk.target_snapshot.targets.len(), 1);
    assert_eq!(shrunk.bundles.len(), 1);
    assert!(shrunk.retirement_bundles.is_empty());
    assert!(shrunk.retirement_rollout_states.is_empty());
    assert!(store
        .next_bundle_for_node("node-b", std::slice::from_ref(&removed.bundle_digest))?
        .is_none());
    assert!(store.next_bundle_for_node("node-b", &[])?.is_none());
    Ok(())
}

#[test]
fn removed_declared_entry_target_is_withdrawn_without_recompilation() -> TestResult {
    let directory = TempDir::new()?;
    let store = ControlStore::open(directory.path())?;
    let owner = make_owner(store.clone());
    let policy = WorkloadProtectionPolicySpec::parse(
        Path::new("kubernetes-entry-roles-v1.yaml"),
        ENTRY_ROLES_POLICY.as_bytes(),
    )?;
    let resource = resource(&policy, "profile", OBJECT_UID, 1, false)?;
    let mut target = inventory_for_resource(&resource, &"1".repeat(64))?.remove(0);
    target.container_name = "worker".to_owned();
    target.image_digest = format!("sha256:{}", "b".repeat(64));
    target.pod_labels = BTreeMap::from([("app".to_owned(), "worker".to_owned())]);
    target.workload_binding_generation_digest = workload_target_fact_digest(&target)?;

    let active = owner.reconcile(&resource, NAMESPACE_UID, &[target], NOW)?;
    let active_bundle = active.bundles[0].clone();
    let withdrawn = owner.reconcile(&resource, NAMESPACE_UID, &[], NOW + 1)?;

    assert!(withdrawn.bundles.is_empty());
    assert!(withdrawn.retirement_bundles.is_empty());
    assert_eq!(
        owner
            .store()
            .compiled_artifact(&withdrawn.source_revision.policy_source_revision_id)?
            .ok_or("the accepted source has no compiled artifact")?
            .policy_document,
        active_bundle.profile_artifact.policy_document
    );
    assert!(store
        .next_bundle_for_node("node-a", std::slice::from_ref(&active_bundle.bundle_digest),)?
        .is_none());
    Ok(())
}

#[test]
fn same_node_partial_removal_uses_one_exact_replacement() -> TestResult {
    let directory = TempDir::new()?;
    let store = ControlStore::open(directory.path())?;
    let owner = make_owner(store);
    let policy = policy()?;
    let resource = resource(&policy, "profile", OBJECT_UID, 1, false)?;
    let inventory = two_workload_inventory_for_resource(&resource)?;
    let first = owner.reconcile(&resource, NAMESPACE_UID, &inventory, NOW)?;
    assert_eq!(
        first.bundles[0]
            .candidate
            .exact_target
            .workload_targets
            .len(),
        2
    );

    let shrunk = owner.reconcile(
        &resource,
        NAMESPACE_UID,
        std::slice::from_ref(&inventory[0]),
        NOW + 1,
    )?;

    assert!(shrunk.retirement_bundles.is_empty());
    assert_eq!(shrunk.bundles.len(), 1);
    assert_eq!(
        shrunk.bundles[0].candidate.operation,
        PolicyDeliveryOperationV1::Replace
    );
    assert_eq!(
        shrunk.bundles[0]
            .candidate
            .exact_target
            .workload_binding_generation_digests,
        vec![inventory[0].workload_binding_generation_digest.clone()]
    );
    assert!(
        shrunk.bundles[0].profile_artifact.header.issuer_sequence
            > first.bundles[0].profile_artifact.header.issuer_sequence
    );
    Ok(())
}

#[test]
fn empty_desired_inventory_replays_and_readd_accepts_present_or_absent_predecessor() -> TestResult {
    let directory = TempDir::new()?;
    let store = ControlStore::open(directory.path())?;
    let owner = make_owner(store.clone());
    let policy = policy()?;
    let resource = resource(&policy, "profile", OBJECT_UID, 1, false)?;
    let inventory = inventory_for_resource(&resource, &"1".repeat(64))?;
    let first = owner.reconcile(&resource, NAMESPACE_UID, &inventory, NOW)?;
    let first_bundle = first.bundles[0].clone();

    let emptied = owner.reconcile(&resource, NAMESPACE_UID, &[], NOW + 1)?;
    assert!(emptied.target_snapshot.targets.is_empty());
    assert!(emptied.bundles.is_empty());
    assert!(emptied.retirement_bundles.is_empty());
    assert!(store
        .next_bundle_for_node("node-a", std::slice::from_ref(&first_bundle.bundle_digest),)?
        .is_none());
    let committed = store.commit_index();
    drop(owner);
    drop(store);

    let reopened = ControlStore::open(directory.path())?;
    let restarted = make_owner(reopened.clone());
    let replayed = restarted.reconcile(&resource, NAMESPACE_UID, &[], NOW + 2)?;
    assert_eq!(reopened.commit_index(), committed);
    assert_eq!(replayed.target_snapshot, emptied.target_snapshot);

    let readded = restarted.reconcile(&resource, NAMESPACE_UID, &inventory, NOW + 3)?;
    let replacement = readded.bundles[0].clone();
    assert_eq!(
        replacement.candidate.operation,
        PolicyDeliveryOperationV1::Replace
    );
    assert_eq!(
        replacement
            .candidate
            .predecessor_candidate_content_id
            .as_deref(),
        Some(first_bundle.candidate.candidate_content_id.as_str())
    );
    assert_eq!(
        reopened
            .next_bundle_for_node("node-a", std::slice::from_ref(&first_bundle.bundle_digest),)?,
        Some(replacement.clone())
    );
    assert_eq!(
        reopened.next_bundle_for_node("node-a", &[])?,
        Some(replacement)
    );
    Ok(())
}

#[test]
fn deletion_withdraws_the_profile_after_a_rejected_successor() -> TestResult {
    let directory = TempDir::new()?;
    let store = ControlStore::open(directory.path())?;
    let owner = make_owner(store.clone());
    let first_policy = policy()?;
    let first_resource = resource(&first_policy, "profile", OBJECT_UID, 1, false)?;
    let first_inventory = inventory_for_resource(&first_resource, &"1".repeat(64))?;
    let first = owner.reconcile(&first_resource, NAMESPACE_UID, &first_inventory, NOW)?;
    let active = first.bundles[0].clone();
    owner.rollout_owner().acknowledge(acknowledgement(
        &active,
        PolicyActivationStateV1::Active,
        NOW + 1,
    )?)?;

    let mut second_policy = first_policy;
    second_policy.roles[0].files[0].operations.reverse();
    let second_resource = resource(&second_policy, "profile", OBJECT_UID, 2, false)?;
    let second_inventory = inventory_for_resource(&second_resource, &"1".repeat(64))?;
    let second = owner.reconcile(&second_resource, NAMESPACE_UID, &second_inventory, NOW + 2)?;
    let rejected = second.bundles[0].clone();
    owner.rollout_owner().acknowledge(acknowledgement(
        &rejected,
        PolicyActivationStateV1::Rejected,
        NOW + 3,
    )?)?;

    let deleting = resource(&second_policy, "profile", OBJECT_UID, 2, true)?;
    let withdrawn = owner.reconcile(&deleting, NAMESPACE_UID, &[], NOW + 4)?;
    assert!(withdrawn.bundles.is_empty());
    assert!(withdrawn.retirement_bundles.is_empty());
    assert!(store
        .next_bundle_for_node("node-a", std::slice::from_ref(&active.bundle_digest))?
        .is_none());
    assert!(store
        .next_bundle_for_node("node-a", std::slice::from_ref(&rejected.bundle_digest))?
        .is_none());
    Ok(())
}

#[test]
fn health_snapshot_exposes_bounded_operational_counts_without_payloads() -> TestResult {
    let directory = TempDir::new()?;
    let store = ControlStore::open(directory.path())?;
    let owner = make_owner(store);
    let before = owner.health()?;
    assert_eq!(before.reconcile_queue_limit, 1);
    assert_eq!(before.configured_watches, 2);
    assert_eq!(before.connected_watches, 0);
    assert_eq!(before.reconcile_in_flight, 0);

    owner.reconcile(
        &resource(&policy()?, "profile", OBJECT_UID, 1, false)?,
        NAMESPACE_UID,
        &inventory(&"1".repeat(64))?,
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
    assert_eq!(health.exception_candidates, 0);
    assert_eq!(health.unsettled_exception_candidates, 0);
    assert_eq!(health.pending_evidence_records, 0);
    Ok(())
}

#[test]
fn rejected_source_metadata_is_counted_as_a_reconcile_failure() -> TestResult {
    let directory = TempDir::new()?;
    let owner = make_owner(ControlStore::open(directory.path())?);
    let mut invalid = resource(&policy()?, "profile", OBJECT_UID, 1, false)?;
    invalid.metadata.uid = None;
    assert!(owner
        .reconcile(&invalid, NAMESPACE_UID, &inventory(&"1".repeat(64))?, NOW,)
        .is_err());
    let health = owner.health()?;
    assert_eq!(health.successful_reconciles, 0);
    assert_eq!(health.rejected_reconciles, 1);
    assert_eq!(health.reconcile_in_flight, 0);
    Ok(())
}

#[test]
fn node_reported_target_cannot_enter_a_crd_rollout() -> TestResult {
    let directory = TempDir::new()?;
    let store = ControlStore::open(directory.path())?;
    let owner = make_owner(store);
    let policy = policy()?;
    let resource = resource(&policy, "profile", OBJECT_UID, 1, false)?;
    let mut reported = inventory_for_resource(&resource, &"1".repeat(64))?.remove(0);
    reported.kubernetes = None;
    reported.workload_binding_generation_digest = workload_target_fact_digest(&reported)?;

    let result = owner.reconcile(&resource, NAMESPACE_UID, &[reported], NOW)?;

    assert!(result.target_snapshot.targets.is_empty());
    assert!(result.bundles.is_empty());
    Ok(())
}

#[test]
fn status_refreshes_from_durable_node_rollout_state() -> TestResult {
    let directory = TempDir::new()?;
    let store = ControlStore::open(directory.path())?;
    let owner = make_owner(store.clone());
    let policy = policy()?;
    let resource = resource(&policy, "profile", OBJECT_UID, 1, false)?;
    let first = owner.reconcile(&resource, NAMESPACE_UID, &inventory(&"1".repeat(64))?, NOW)?;
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
        &inventory(&"1".repeat(64))?,
        NOW + 2,
    )?;
    assert_eq!(refreshed.status.rollout.active, 1);
    assert_eq!(refreshed.status.rollout.total(), 1);
    assert_eq!(refreshed.status.conditions.len(), 6);
    assert!(refreshed.status.conditions.iter().any(|condition| {
        condition.condition_type == "Available"
            && condition.status == KubernetesConditionStatusV1::True
    }));
    assert!(store
        .next_bundle_for_node("node-a", std::slice::from_ref(&bundle.bundle_digest),)?
        .is_none());
    assert_eq!(store.commit_index(), 3);
    Ok(())
}

#[test]
fn rejected_candidate_stops_redelivery_and_projects_degraded_status() -> TestResult {
    let directory = TempDir::new()?;
    let store = ControlStore::open(directory.path())?;
    let owner = make_owner(store.clone());
    let policy = policy()?;
    let resource = resource(&policy, "profile", OBJECT_UID, 1, false)?;
    let first = owner.reconcile(&resource, NAMESPACE_UID, &inventory(&"1".repeat(64))?, NOW)?;
    let bundle = &first.bundles[0];
    assert_eq!(
        store.next_bundle_for_node("node-a", &[])?,
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

    assert!(store.next_bundle_for_node("node-a", &[])?.is_none());
    let refreshed = owner.reconcile(
        &resource,
        NAMESPACE_UID,
        &inventory(&"1".repeat(64))?,
        NOW + 2,
    )?;
    assert_eq!(refreshed.status.rollout.failed, 1);
    assert!(refreshed.status.conditions.iter().any(|condition| {
        condition.condition_type == "Degraded"
            && condition.status == KubernetesConditionStatusV1::True
    }));
    Ok(())
}

#[test]
fn deletion_withdraws_desired_policy_and_recreate_gets_a_new_source_identity() -> TestResult {
    let directory = TempDir::new()?;
    let store = ControlStore::open(directory.path())?;
    let owner = make_owner(store);
    let policy = policy()?;
    let first = owner.reconcile(
        &resource(&policy, "profile", OBJECT_UID, 1, false)?,
        NAMESPACE_UID,
        &inventory(&"1".repeat(64))?,
        NOW,
    )?;
    let retiring = owner.reconcile(
        &resource(&policy, "profile", OBJECT_UID, 1, true)?,
        NAMESPACE_UID,
        &[],
        NOW + 1,
    )?;
    assert!(retiring.bundles.is_empty());
    assert!(retiring.retirement_bundles.is_empty());
    assert!(owner
        .reconcile(
            &resource(&policy, "profile", OBJECT_UID, 1, false)?,
            NAMESPACE_UID,
            &inventory(&"1".repeat(64))?,
            NOW + 2,
        )
        .is_err());

    let recreated_resource = resource(
        &policy,
        "profile",
        "30000000-0000-4000-8000-000000000004",
        1,
        false,
    )?;
    let recreated_inventory = inventory_for_resource(&recreated_resource, &"1".repeat(64))?;
    let recreated = owner.reconcile(
        &recreated_resource,
        NAMESPACE_UID,
        &recreated_inventory,
        NOW + 3,
    )?;
    assert_ne!(
        recreated.source_revision.policy_source_revision_id,
        first.source_revision.policy_source_revision_id
    );
    assert_eq!(
        recreated.bundles[0].candidate.operation,
        PolicyDeliveryOperationV1::Activate
    );
    assert!(recreated.bundles[0]
        .candidate
        .predecessor_candidate_content_id
        .is_none());
    assert_eq!(recreated.bundles[0].candidate.distribution_sequence, 1);
    Ok(())
}

#[test]
fn active_recreated_source_retires_when_its_workload_disappears() -> TestResult {
    let directory = TempDir::new()?;
    let store = ControlStore::open(directory.path())?;
    let owner = make_owner(store.clone());
    let policy = policy()?;
    let first_resource = resource(&policy, "profile", OBJECT_UID, 1, false)?;
    owner.reconcile(
        &first_resource,
        NAMESPACE_UID,
        &inventory_for_resource(&first_resource, &"1".repeat(64))?,
        NOW,
    )?;
    owner.reconcile(
        &resource(&policy, "profile", OBJECT_UID, 1, true)?,
        NAMESPACE_UID,
        &[],
        NOW + 1,
    )?;
    drop(owner);
    drop(store);

    let reopened = ControlStore::open(directory.path())?;
    let restarted = make_owner(reopened.clone());
    let recreated_resource = resource(
        &policy,
        "profile",
        "30000000-0000-4000-8000-000000000004",
        1,
        false,
    )?;
    let recreated_inventory = inventory_for_resource(&recreated_resource, &"2".repeat(64))?;
    let activated = restarted.reconcile(
        &recreated_resource,
        NAMESPACE_UID,
        &recreated_inventory,
        NOW + 2,
    )?;
    restarted.rollout_owner().acknowledge(acknowledgement(
        &activated.bundles[0],
        PolicyActivationStateV1::Active,
        NOW + 3,
    )?)?;
    let active_bundle_digest = activated.bundles[0].bundle_digest.clone();
    let commit_before_retirement = reopened.commit_index();

    let retired = restarted.reconcile(&recreated_resource, NAMESPACE_UID, &[], NOW + 4)?;

    assert!(retired.target_snapshot.targets.is_empty());
    assert!(retired.bundles.is_empty());
    assert!(reopened.commit_index() > commit_before_retirement);
    assert!(reopened
        .next_bundle_for_node("node-a", &[active_bundle_digest])?
        .is_none());
    Ok(())
}

#[test]
fn invalid_update_does_not_replace_or_block_retirement_of_the_last_compiled_source() -> TestResult {
    let directory = TempDir::new()?;
    let store = ControlStore::open(directory.path())?;
    let owner = make_owner(store.clone());
    let first_policy = policy()?;
    let first_resource = resource(&first_policy, "profile", OBJECT_UID, 1, false)?;
    let first_inventory = inventory_for_resource(&first_resource, &"1".repeat(64))?;
    let first = owner.reconcile(&first_resource, NAMESPACE_UID, &first_inventory, NOW)?;

    let mut invalid_policy = first_policy;
    let mut conflicting_rule = invalid_policy.roles[0].files[0].clone();
    conflicting_rule.name = "deny-python-read".to_owned();
    conflicting_rule.action = mithril_control::KubernetesRuleActionV1::Deny;
    invalid_policy.roles[0].files.push(conflicting_rule);
    let invalid_resource = resource(&invalid_policy, "profile", OBJECT_UID, 2, false)?;
    assert!(owner
        .reconcile(&invalid_resource, NAMESPACE_UID, &first_inventory, NOW + 1,)
        .is_err());
    assert_eq!(
        store
            .latest_source(TENANT_ID, NAMESPACE_UID, "profile")?
            .ok_or("the accepted source is missing")?
            .policy_source_revision_id,
        first.source_revision.policy_source_revision_id
    );

    let deleting_invalid = resource(&invalid_policy, "profile", OBJECT_UID, 2, true)?;
    let retired = owner.reconcile(&deleting_invalid, NAMESPACE_UID, &[], NOW + 2)?;
    assert_eq!(retired.source_revision.object_generation, 1);
    assert!(retired.bundles.is_empty());
    assert!(retired.retirement_bundles.is_empty());
    assert_eq!(
        store
            .compiled_artifact(&retired.source_revision.policy_source_revision_id)?
            .ok_or("the deleted source has no retained artifact")?
            .policy_document,
        first.bundles[0].profile_artifact.policy_document
    );
    Ok(())
}

#[test]
fn completed_relist_retires_a_source_that_is_absent_from_the_snapshot() -> TestResult {
    let directory = TempDir::new()?;
    let store = ControlStore::open(directory.path())?;
    let owner = make_owner(store);
    owner.reconcile(
        &resource(&policy()?, "profile", OBJECT_UID, 1, false)?,
        NAMESPACE_UID,
        &inventory(&"1".repeat(64))?,
        NOW,
    )?;

    let retired = owner.retire_missing_sources(&BTreeSet::new(), &[], NOW + 1)?;
    assert_eq!(retired.len(), 1);
    assert!(retired[0].bundles.is_empty());
    assert!(retired[0].retirement_bundles.is_empty());
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
    let mut first_policy = policy()?;
    let first_resource = resource(&first_policy, "profile", OBJECT_UID, 1, false)?;
    let first_inventory = two_node_inventory_for_resource(&first_resource)?;
    let first = owner.reconcile(&first_resource, NAMESPACE_UID, &first_inventory, NOW)?;
    assert_eq!(first.bundles.len(), 2);
    assert_eq!(
        first.source_revision.canonical_spec_digest,
        canonical_kubernetes_policy_spec_digest(&first_policy)?
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
    // Preserve mixed per-node results before a new source revision supersedes both candidates.
    let first_status = owner
        .reconcile(&first_resource, NAMESPACE_UID, &first_inventory, NOW + 2)?
        .status;
    assert_eq!(first_status.rollout.active, 1);
    assert_eq!(first_status.rollout.failed, 1);

    first_policy.roles[0].files[0].operations.reverse();
    let second_resource = resource(&first_policy, "profile", OBJECT_UID, 2, false)?;
    let second_inventory = first_inventory.clone();
    let second = owner.reconcile(&second_resource, NAMESPACE_UID, &second_inventory, NOW + 3)?;
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
        if node_id == "node-a" {
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
        } else {
            // The rejected root cannot become a physical predecessor for later authority.
            assert_eq!(
                current.candidate.operation,
                PolicyDeliveryOperationV1::Activate
            );
            assert!(current.candidate.predecessor_candidate_content_id.is_none());
        }
        assert!(current.candidate.distribution_sequence > prior.candidate.distribution_sequence);
    }
    // A late predecessor ACK remains valid until its successor becomes active.
    owner.rollout_owner().acknowledge(acknowledgement(
        node_a_first,
        PolicyActivationStateV1::Active,
        NOW + 4,
    )?)?;
    owner.rollout_owner().acknowledge(acknowledgement(
        second_by_node
            .get("node-a")
            .ok_or("node-a has no updated bundle")?,
        PolicyActivationStateV1::Active,
        NOW + 4,
    )?)?;
    let mixed = owner.reconcile(&second_resource, NAMESPACE_UID, &second_inventory, NOW + 5)?;
    assert_eq!(mixed.status.rollout.active, 1);
    assert_eq!(mixed.status.rollout.updating, 1);
    assert!(mixed.status.conditions.iter().any(|condition| {
        condition.condition_type == "Progressing"
            && condition.status == KubernetesConditionStatusV1::True
    }));

    // Restart recovery must reproduce the exact candidates and mixed rollout state.
    drop(owner);
    drop(store);
    let reopened = ControlStore::open(directory.path())?;
    let restarted_owner = make_owner(reopened.clone());
    let restarted =
        restarted_owner.reconcile(&second_resource, NAMESPACE_UID, &second_inventory, NOW + 6)?;
    assert_eq!(restarted.bundles, second.bundles);
    assert_eq!(restarted.status.rollout.active, 1);
    assert_eq!(restarted.status.rollout.updating, 1);

    let deleting_resource = resource(&first_policy, "profile", OBJECT_UID, 2, true)?;
    let retiring = restarted_owner.reconcile(&deleting_resource, NAMESPACE_UID, &[], NOW + 7)?;
    assert!(retiring.bundles.is_empty());
    assert!(retiring.retirement_bundles.is_empty());

    // A new Kubernetes object UID starts a separate source and cannot reuse old authority.
    let recreated_resource = resource(
        &first_policy,
        "profile",
        "30000000-0000-4000-8000-000000000009",
        1,
        false,
    )?;
    let recreated_inventory = two_node_inventory_for_resource(&recreated_resource)?;
    let recreated = restarted_owner.reconcile(
        &recreated_resource,
        NAMESPACE_UID,
        &recreated_inventory,
        NOW + 8,
    )?;
    assert_eq!(recreated.bundles.len(), 2);
    for bundle in &recreated.bundles {
        assert_eq!(
            bundle.candidate.operation,
            PolicyDeliveryOperationV1::Activate
        );
        assert!(bundle.candidate.predecessor_candidate_content_id.is_none());
        assert_eq!(bundle.candidate.distribution_sequence, 1);
    }
    assert_ne!(
        recreated.source_revision.policy_source_revision_id,
        retiring.source_revision.policy_source_revision_id
    );
    Ok(())
}

#[test]
fn new_physical_node_epoch_starts_a_new_activation_chain() -> TestResult {
    let directory = TempDir::new()?;
    let owner = make_owner(ControlStore::open(directory.path())?);
    let policy_resource = resource(&policy()?, "profile", OBJECT_UID, 1, false)?;
    let first_inventory = inventory_for_resource(&policy_resource, &"1".repeat(64))?;
    let first = owner.reconcile(&policy_resource, NAMESPACE_UID, &first_inventory, NOW)?;
    assert_eq!(first.bundles.len(), 1);
    assert_eq!(
        first.bundles[0].candidate.operation,
        PolicyDeliveryOperationV1::Activate
    );

    let mut next_inventory = first_inventory;
    let target = &mut next_inventory[0];
    target.execution_set_id = "44444444-4444-4444-8444-444444444446".to_owned();
    target.pod_uid = "99999999-9999-4999-8999-999999999997".to_owned();
    target.container_id = "containerd://converter-after-reboot".to_owned();
    let identity = target
        .kubernetes
        .as_mut()
        .ok_or("the Kubernetes target fixture has no provenance")?;
    identity.binding_id = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaac".to_owned();
    identity.node_boot_id = "02".repeat(16);
    identity.label_epoch = 2;
    target.workload_binding_generation_digest = workload_target_fact_digest(target)?;

    let next = owner.reconcile(&policy_resource, NAMESPACE_UID, &next_inventory, NOW + 1)?;
    assert_eq!(next.bundles.len(), 1);
    assert_eq!(
        next.bundles[0].candidate.operation,
        PolicyDeliveryOperationV1::Activate
    );
    assert!(next.bundles[0]
        .candidate
        .predecessor_candidate_content_id
        .is_none());
    assert!(
        next.bundles[0].candidate.distribution_sequence
            > first.bundles[0].candidate.distribution_sequence
    );
    Ok(())
}

#[test]
fn corrupt_current_state_blocks_store_recovery() -> TestResult {
    let directory = TempDir::new()?;
    let store = ControlStore::open(directory.path())?;
    make_owner(store.clone()).reconcile(
        &resource(&policy()?, "profile", OBJECT_UID, 1, false)?,
        NAMESPACE_UID,
        &inventory(&"1".repeat(64))?,
        NOW,
    )?;
    drop(store);

    let state = directory.path().join("state.bin");
    let mut bytes = std::fs::read(&state)?;
    let last = bytes.last_mut().ok_or("the current state is empty")?;
    *last ^= 1;
    std::fs::write(&state, bytes)?;
    assert!(ControlStore::open(directory.path()).is_err());
    Ok(())
}
