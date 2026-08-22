use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use ed25519_dalek::SigningKey;
use mithril_control::{
    canonical_policy_spec_digest, ContainerKindV1, ControlStore, PolicyDeliveryOperationV1,
    PolicyDesiredStateConfigV1, PolicyDesiredStateOwner, PolicyDocumentV1, PolicySignerConfigV1,
    ProfileSealRequestV1, RegistryDigestsV1, WorkloadProtectionProfile, WorkloadTargetFactV1,
    POLICY_API_VERSION, POLICY_KIND, SUBMITTED_SPEC_DIGEST_ANNOTATION,
};
use serde_json::json;
use tempfile::TempDir;

const POLICY: &str = include_str!("fixtures/policy-v1.yaml");
const TENANT_ID: &str = "10000000-0000-4000-8000-000000000001";
const CLUSTER_UID: &str = "55555555-5555-4555-8555-555555555555";
const NAMESPACE_UID: &str = "66666666-6666-4666-8666-666666666666";
const OBJECT_UID: &str = "30000000-0000-4000-8000-000000000001";
const NOW: i64 = 1_800_000_000_000_000_000;

fn policy() -> PolicyDocumentV1 {
    PolicyDocumentV1::parse(Path::new("policy-v1.yaml"), POLICY.as_bytes())
        .expect("the policy fixture must parse")
}

fn resource(
    document: &PolicyDocumentV1,
    name: &str,
    uid: &str,
    generation: u64,
    deleting: bool,
) -> WorkloadProtectionProfile {
    let digest = canonical_policy_spec_digest(document).expect("the policy must canonicalize");
    let mut metadata = json!({
        "name": name,
        "namespace": "tenant-a",
        "uid": uid,
        "generation": generation,
        "resourceVersion": format!("opaque-{generation}"),
        "annotations": {SUBMITTED_SPEC_DIGEST_ANNOTATION: digest},
    });
    if deleting {
        metadata["deletionTimestamp"] = json!("2027-01-15T00:00:00Z");
    }
    serde_json::from_value(json!({
        "apiVersion": POLICY_API_VERSION,
        "kind": POLICY_KIND,
        "metadata": metadata,
        "spec": document,
    }))
    .expect("the policy resource must decode")
}

fn make_owner(store: ControlStore) -> PolicyDesiredStateOwner {
    PolicyDesiredStateOwner::new(
        PolicyDesiredStateConfigV1 {
            tenant_id: TENANT_ID.to_owned(),
            cluster_uid: CLUSTER_UID.to_owned(),
            namespace_uids: BTreeMap::from([("tenant-a".to_owned(), NAMESPACE_UID.to_owned())]),
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
    }]
}

#[test]
fn create_update_duplicate_and_restart_preserve_one_monotonic_rollout() {
    let directory = TempDir::new().expect("a temporary directory is required");
    let store = ControlStore::open(directory.path()).expect("the store must open");
    let owner = make_owner(store.clone());
    let first_policy = policy();
    let first = owner
        .reconcile(
            &resource(&first_policy, "profile", OBJECT_UID, 1, false),
            &inventory(&"1".repeat(64)),
            NOW,
        )
        .expect("the first revision must reconcile");
    assert_eq!(first.bundles.len(), 1);
    assert_eq!(
        first.bundles[0].candidate.operation,
        PolicyDeliveryOperationV1::Activate
    );
    assert_eq!(first.bundles[0].candidate.distribution_sequence, 1);
    assert_eq!(first.bundles[0].profile_artifact.header.issuer_sequence, 1);

    let first_commit = store.commit_index();
    let duplicate = owner
        .reconcile(
            &resource(&first_policy, "profile", OBJECT_UID, 1, false),
            &inventory(&"1".repeat(64)),
            NOW,
        )
        .expect("a duplicate watch event must be idempotent");
    assert_eq!(duplicate, first);
    assert_eq!(store.commit_index(), first_commit);

    let mut second_policy = first_policy;
    second_policy.metadata.profile_version = 2;
    second_policy.rollout.rollout_generation = 2;
    let second = owner
        .reconcile(
            &resource(&second_policy, "profile", OBJECT_UID, 2, false),
            &inventory(&"1".repeat(64)),
            NOW + 1,
        )
        .expect("the update must reconcile");
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
        &resource(&second_policy, "profile", OBJECT_UID, 1, false),
        &inventory(&"1".repeat(64)),
        NOW + 2,
    );
    assert!(stale.is_err());

    drop(owner);
    drop(store);
    let reopened = ControlStore::open(directory.path()).expect("the store must replay");
    let restarted = make_owner(reopened.clone())
        .reconcile(
            &resource(&second_policy, "profile", OBJECT_UID, 2, false),
            &inventory(&"1".repeat(64)),
            NOW + 3,
        )
        .expect("restart reconciliation must be idempotent");
    assert_eq!(restarted.bundles, second.bundles);
    assert_eq!(reopened.commit_index(), 6);
}

#[test]
fn duplicate_profile_and_exact_workload_claims_do_not_replace_valid_rollout() {
    let directory = TempDir::new().expect("a temporary directory is required");
    let store = ControlStore::open(directory.path()).expect("the store must open");
    let owner = make_owner(store.clone());
    let first_policy = policy();
    let first = owner
        .reconcile(
            &resource(&first_policy, "one", OBJECT_UID, 1, false),
            &inventory(&"1".repeat(64)),
            NOW,
        )
        .expect("the first profile must reconcile");

    let duplicate_profile = owner.reconcile(
        &resource(
            &first_policy,
            "two",
            "30000000-0000-4000-8000-000000000002",
            1,
            false,
        ),
        &inventory(&"2".repeat(64)),
        NOW + 1,
    );
    assert!(duplicate_profile
        .expect_err("a duplicate profile owner must fail")
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
        ),
        &inventory(&"1".repeat(64)),
        NOW + 2,
    );
    assert!(overlap
        .expect_err("an exact workload overlap must fail")
        .to_string()
        .contains("CFG_OVERLAPPING_WORKLOAD_OWNER"));
    assert_eq!(
        store
            .bundle_for_node("node-a")
            .expect("the bundle query must succeed"),
        Some(first.bundles[0].clone())
    );
}

#[test]
fn deletion_names_exact_predecessor_and_recreate_gets_a_new_source_identity() {
    let directory = TempDir::new().expect("a temporary directory is required");
    let store = ControlStore::open(directory.path()).expect("the store must open");
    let owner = make_owner(store);
    let policy = policy();
    let first = owner
        .reconcile(
            &resource(&policy, "profile", OBJECT_UID, 1, false),
            &inventory(&"1".repeat(64)),
            NOW,
        )
        .expect("the first profile must reconcile");
    let retiring = owner
        .reconcile(
            &resource(&policy, "profile", OBJECT_UID, 2, true),
            &[],
            NOW + 1,
        )
        .expect("deletion must create a retirement candidate");
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

    let recreated = owner
        .reconcile(
            &resource(
                &policy,
                "profile",
                "30000000-0000-4000-8000-000000000004",
                1,
                false,
            ),
            &inventory(&"1".repeat(64)),
            NOW + 2,
        )
        .expect("a recreate after retirement input must reconcile");
    assert_ne!(
        recreated.source_revision.policy_source_revision_id,
        first.source_revision.policy_source_revision_id
    );
    assert_eq!(
        recreated.bundles[0].candidate.operation,
        PolicyDeliveryOperationV1::Activate
    );
}

#[test]
fn corrupt_or_incompatible_commit_chain_blocks_store_recovery() {
    let directory = TempDir::new().expect("a temporary directory is required");
    let store = ControlStore::open(directory.path()).expect("the store must open");
    make_owner(store.clone())
        .reconcile(
            &resource(&policy(), "profile", OBJECT_UID, 1, false),
            &inventory(&"1".repeat(64)),
            NOW,
        )
        .expect("the policy must reconcile");
    drop(store);

    let first_commit = directory.path().join("commits/00000000000000000001.json");
    let bytes = std::fs::read_to_string(&first_commit).expect("the commit must be readable");
    let incompatible = bytes.replacen("\"schema_version\":1", "\"schema_version\":2", 1);
    std::fs::write(&first_commit, incompatible).expect("the temporary commit must be writable");
    assert!(ControlStore::open(directory.path()).is_err());
}
