use std::path::Path;

use k8s_openapi::apiextensions_apiserver::pkg::apis::apiextensions::v1::CustomResourceDefinition;
use mithril_control::{
    canonical_policy_document_bytes, canonical_policy_spec_digest,
    policy_custom_resource_definition, PolicyDocumentV1, PolicySourceRevisionV1,
    PolicySourceStateV1, WorkloadProtectionProfile, POLICY_API_VERSION, POLICY_KIND,
    SUBMITTED_SPEC_DIGEST_ANNOTATION,
};
use serde_json::{json, Value};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const POLICY: &str = include_str!("fixtures/policy-v1.yaml");
const CRD: &str = include_str!(
    "../../../packaging/mithril/helm/crds/mithril.erebor.dev_workloadprotectionprofiles.yaml"
);
const CONTROL_RBAC: &str =
    include_str!("../../../packaging/mithril/helm/templates/control-rbac.yaml");

fn policy() -> TestResult<PolicyDocumentV1> {
    Ok(PolicyDocumentV1::parse(
        Path::new("policy-v1.yaml"),
        POLICY.as_bytes(),
    )?)
}

fn resource(document: &PolicyDocumentV1) -> TestResult<WorkloadProtectionProfile> {
    let digest = canonical_policy_spec_digest(document)?;
    Ok(serde_json::from_value(json!({
        "apiVersion": POLICY_API_VERSION,
        "kind": POLICY_KIND,
        "metadata": {
            "name": "hugging-face-runtime",
            "namespace": "tenant-a",
            "uid": "30000000-0000-4000-8000-000000000001",
            "generation": 7,
            "resourceVersion": "opaque/watch/97",
            "annotations": {
                SUBMITTED_SPEC_DIGEST_ANNOTATION: digest,
            },
        },
        "spec": serde_json::to_value(document)?,
    }))?)
}

#[test]
fn generated_crd_has_one_closed_bounded_namespaced_storage_version() -> TestResult {
    let generated = policy_custom_resource_definition()?;
    assert_eq!(generated.spec.group, "mithril.erebor.dev");
    assert_eq!(generated.spec.scope, "Namespaced");
    assert_eq!(generated.spec.names.kind, POLICY_KIND);
    assert_eq!(generated.spec.names.plural, "workloadprotectionprofiles");
    assert_eq!(generated.spec.versions.len(), 1);
    let version = &generated.spec.versions[0];
    assert_eq!(version.name, "v1alpha1");
    assert!(version.served);
    assert!(version.storage);

    let value = serde_json::to_value(version.schema.as_ref().ok_or("schema is required")?)?;
    assert_closed_and_bounded(&value);
    Ok(())
}

#[test]
fn committed_crd_is_the_generated_contract() -> TestResult {
    let committed: CustomResourceDefinition = serde_json::from_str(CRD)?;
    assert_eq!(
        serde_json::to_value(committed)?,
        serde_json::to_value(policy_custom_resource_definition()?)?
    );
    Ok(())
}

#[test]
fn crd_spec_and_offline_yaml_have_identical_canonical_bytes() -> TestResult {
    let offline = policy()?;
    let resource = resource(&offline)?;
    assert_eq!(
        canonical_policy_document_bytes(&offline)?,
        canonical_policy_document_bytes(&resource.spec.policy)?
    );
    let revision = PolicySourceRevisionV1::from_resource(
        &resource,
        "10000000-0000-4000-8000-000000000001",
        "10000000-0000-4000-8000-000000000002",
        "10000000-0000-4000-8000-000000000003",
        PolicySourceStateV1::Accepted,
    )?;
    assert_eq!(
        revision.canonical_spec_digest,
        canonical_policy_spec_digest(&offline)?
    );
    assert_eq!(revision.opaque_resource_version, b"opaque/watch/97");
    Ok(())
}

#[test]
fn strict_resource_decode_and_submitted_digest_reject_unknown_or_pruned_input() -> TestResult {
    let document = policy()?;
    let mut value = serde_json::to_value(resource(&document)?)?;
    value["spec"]["unknown_authority"] = json!(true);
    assert!(serde_json::from_value::<WorkloadProtectionProfile>(value).is_err());

    let mut pruned = resource(&document)?;
    pruned.spec.policy.metadata.profile_version += 1;
    let Err(error) = PolicySourceRevisionV1::from_resource(
        &pruned,
        "10000000-0000-4000-8000-000000000001",
        "10000000-0000-4000-8000-000000000002",
        "10000000-0000-4000-8000-000000000003",
        PolicySourceStateV1::Accepted,
    ) else {
        return Err("a stored spec that differs from the submitted digest must fail".into());
    };
    assert!(error.to_string().contains("CFG_CRD_SILENT_PRUNE"));
    Ok(())
}

#[test]
fn status_uses_bounded_informational_fields_and_rbac_cannot_write_policy_spec() -> TestResult {
    let status = mithril_control::WorkloadProtectionProfileStatusV1::default();
    let value = serde_json::to_value(status)?;
    assert!(value.get("observedGeneration").is_some());
    assert!(value.get("rolloutCounts").is_some());
    assert!(value.get("observed_generation").is_none());

    assert!(CONTROL_RBAC.contains("workloadprotectionprofiles/status"));
    assert!(CONTROL_RBAC.contains("workloadprotectionprofiles/finalizers"));
    assert!(CONTROL_RBAC.contains("verbs: [\"get\", \"list\", \"watch\"]"));
    assert!(!CONTROL_RBAC.contains("\"create\""));
    assert!(!CONTROL_RBAC.contains("\"delete\""));
    assert!(!CONTROL_RBAC.contains("resources: [\"secrets\"]"));
    Ok(())
}

fn assert_closed_and_bounded(value: &Value) {
    match value {
        Value::Array(values) => {
            for value in values {
                assert_closed_and_bounded(value);
            }
        }
        Value::Object(object) => {
            match object.get("type").and_then(Value::as_str) {
                Some("string") => assert!(object.get("maxLength").is_some()),
                Some("array") => assert!(object.get("maxItems").is_some()),
                Some("object") => {
                    assert!(object.get("maxProperties").is_some());
                    if object.contains_key("properties") {
                        assert_eq!(
                            object.get("additionalProperties"),
                            Some(&Value::Bool(false))
                        );
                    }
                }
                _ => {}
            }
            for nested in object.values() {
                assert_closed_and_bounded(nested);
            }
        }
        _ => {}
    }
}
