use std::path::Path;

use mithril_control::{
    canonical_policy_document_bytes, canonical_policy_spec_digest, policy_custom_resource,
    policy_custom_resource_definition, PolicyDocumentV1, PolicySourceRevisionV1,
    PolicySourceStateV1, WorkloadProtectionProfile, POLICY_KIND,
};
use serde_json::{json, Value};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const POLICY: &str = include_str!("fixtures/policy-v1.yaml");

fn policy() -> TestResult<PolicyDocumentV1> {
    Ok(PolicyDocumentV1::parse(
        Path::new("policy-v1.yaml"),
        POLICY.as_bytes(),
    )?)
}

fn resource(document: &PolicyDocumentV1) -> TestResult<WorkloadProtectionProfile> {
    let mut resource =
        policy_custom_resource("hugging-face-runtime", "tenant-a", document.clone())?;
    resource.metadata.uid = Some("30000000-0000-4000-8000-000000000001".to_owned());
    resource.metadata.generation = Some(7);
    resource.metadata.resource_version = Some("opaque/watch/97".to_owned());
    Ok(resource)
}

#[test]
fn generated_crd_has_one_structural_bounded_namespaced_storage_version() -> TestResult {
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

    let value = serde_json::to_value(
        version
            .schema
            .as_ref()
            .and_then(|validation| validation.open_api_v3_schema.as_ref())
            .ok_or("schema is required")?,
    )?;
    assert_structural_and_bounded(&value, true);
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
fn status_serializes_with_the_kubernetes_api_contract() -> TestResult {
    let status = mithril_control::WorkloadProtectionProfileStatusV1::default();
    let value = serde_json::to_value(status)?;
    assert!(value.get("observedGeneration").is_some());
    assert!(value.get("rolloutCounts").is_some());
    assert!(value.get("observed_generation").is_none());
    Ok(())
}

fn assert_structural_and_bounded(value: &Value, resource_root: bool) {
    match value {
        Value::Array(values) => {
            for value in values {
                assert_structural_and_bounded(value, false);
            }
        }
        Value::Object(object) => {
            if object.get("nullable") == Some(&Value::Bool(true)) {
                assert!(object.get("enum").is_none());
            }
            match object.get("type").and_then(Value::as_str) {
                Some("string") => assert!(object.get("maxLength").is_some()),
                Some("array") => assert!(object.get("maxItems").is_some()),
                Some("object") => {
                    if !resource_root {
                        assert!(object.get("maxProperties").is_some());
                    }
                    if object.contains_key("properties") {
                        // Kubernetes rejects schemas that combine named and additional properties.
                        assert!(object.get("additionalProperties").is_none());
                    }
                }
                _ => {}
            }
            for nested in object.values() {
                assert_structural_and_bounded(nested, false);
            }
        }
        _ => {}
    }
}
