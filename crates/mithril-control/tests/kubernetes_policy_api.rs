use std::path::Path;

use mithril_control::{
    canonical_kubernetes_policy_spec_bytes, exception_custom_resource_definition,
    lower_kubernetes_policy, policy_custom_resource, policy_custom_resource_definition,
    CompiledPhysicalResultV1, KubernetesRuleActionV1, PolicyCompiler, PolicySourceRevisionV1,
    PolicySourceStateV1, ProfileModeV1, WorkloadProtectionException,
    WorkloadProtectionExceptionSpec, WorkloadProtectionPolicy, WorkloadProtectionPolicySpec,
    EXCEPTION_KIND, POLICY_KIND,
};
use serde_json::{json, Value};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const POLICY: &str = include_str!("fixtures/kubernetes-policy-v1.yaml");
const TENANT_ID: &str = "10000000-0000-4000-8000-000000000001";
const CLUSTER_UID: &str = "10000000-0000-4000-8000-000000000002";
const NAMESPACE_UID: &str = "10000000-0000-4000-8000-000000000003";
const OBJECT_UID: &str = "30000000-0000-4000-8000-000000000001";

fn spec() -> TestResult<WorkloadProtectionPolicySpec> {
    Ok(WorkloadProtectionPolicySpec::parse(
        Path::new("kubernetes-policy-v1.yaml"),
        POLICY.as_bytes(),
    )?)
}

fn resource() -> TestResult<WorkloadProtectionPolicy> {
    let mut resource = policy_custom_resource("converter", "tenant-a", spec()?)?;
    resource.metadata.uid = Some(OBJECT_UID.to_owned());
    resource.metadata.generation = Some(7);
    resource.metadata.resource_version = Some("opaque/watch/97".to_owned());
    Ok(resource)
}

#[test]
fn generated_crds_are_namespaced_structural_and_keep_authority_out_of_status() -> TestResult {
    let policy = policy_custom_resource_definition()?;
    assert_eq!(policy.spec.group, "mithril.erebor.dev");
    assert_eq!(policy.spec.scope, "Namespaced");
    assert_eq!(policy.spec.names.kind, POLICY_KIND);
    assert_eq!(policy.spec.names.plural, "workloadprotectionpolicies");
    assert_eq!(policy.spec.versions.len(), 1);
    assert!(policy.spec.versions[0].served);
    assert!(policy.spec.versions[0].storage);
    let policy_json = serde_json::to_value(policy)?;
    assert_bounded_schema(
        policy_json
            .pointer("/spec/versions/0/schema/openAPIV3Schema/properties/spec")
            .ok_or("policy spec schema is absent")?,
    );
    let policy_status = policy_json
        .pointer("/spec/versions/0/schema/openAPIV3Schema/properties/status/properties")
        .and_then(Value::as_object)
        .ok_or("policy status schema is absent")?;
    assert_eq!(
        policy_status.keys().cloned().collect::<Vec<_>>(),
        ["conditions", "observedGeneration", "rollout"]
    );
    for forbidden in ["digest", "signature", "receipt", "candidate", "node"] {
        assert!(!serde_json::to_string(policy_status)?.contains(forbidden));
    }

    let exception = exception_custom_resource_definition()?;
    assert_eq!(exception.spec.scope, "Namespaced");
    assert_eq!(exception.spec.names.kind, EXCEPTION_KIND);
    assert_eq!(exception.spec.names.plural, "workloadprotectionexceptions");
    let exception_json = serde_json::to_value(exception)?;
    assert_bounded_schema(
        exception_json
            .pointer("/spec/versions/0/schema/openAPIV3Schema/properties/spec")
            .ok_or("exception spec schema is absent")?,
    );
    assert_eq!(
        exception_json
            .pointer("/spec/versions/0/schema/openAPIV3Schema/properties/spec/x-kubernetes-validations/0/rule"),
        Some(&json!("self == oldSelf"))
    );
    assert_eq!(
        exception_json
            .pointer(
                "/spec/versions/0/schema/openAPIV3Schema/properties/spec/properties/requestedUses/minimum",
            )
            .and_then(Value::as_f64),
        Some(1.0)
    );
    assert_eq!(
        policy_json
            .pointer(
                "/spec/versions/0/schema/openAPIV3Schema/properties/spec/properties/exceptionGrants/items/properties/maximumUses/minimum",
            )
            .and_then(Value::as_f64),
        Some(1.0)
    );
    Ok(())
}

#[test]
fn stored_and_offline_policy_specs_lower_to_the_same_compilable_policy() -> TestResult {
    let offline = spec()?;
    let resource = resource()?;
    assert_eq!(
        canonical_kubernetes_policy_spec_bytes(&offline)?,
        canonical_kubernetes_policy_spec_bytes(&resource.spec)?
    );
    let lowered = lower_kubernetes_policy(&resource, TENANT_ID, CLUSTER_UID, NAMESPACE_UID)?;
    let compiled = PolicyCompiler.compile(&lowered)?;
    assert_eq!(lowered.metadata.profile_id, OBJECT_UID);
    assert_eq!(lowered.metadata.profile_version, 7);
    assert_eq!(lowered.rollout.desired_profile_mode, ProfileModeV1::Protect);
    assert!(!compiled.compiled_cells.is_empty());
    assert!(lowered.exceptions.is_empty());
    assert_eq!(lowered.file_exception_grants.len(), 1);
    let python_selectors = lowered
        .path_selectors
        .iter()
        .filter(|selector| selector.path_expression() == "/usr/bin/python")
        .collect::<Vec<_>>();
    assert_eq!(python_selectors.len(), 1);
    assert!(!python_selectors[0].requires_exact_object());
    assert!(lowered
        .path_selectors
        .iter()
        .all(|selector| !selector.requires_exact_object()));
    let grant_cells = compiled
        .compiled_cells
        .iter()
        .filter(|cell| cell.consuming_exception_id.as_deref() == Some("temporary-file-access"))
        .collect::<Vec<_>>();
    assert!(!grant_cells.is_empty());
    assert!(grant_cells.iter().all(|cell| {
        cell.key.operation_id == "OPEN_READ"
            && cell.physical_result == CompiledPhysicalResultV1::AllowEffect
            && cell.errno.is_none()
    }));
    Ok(())
}

#[test]
fn source_revision_binds_stored_spec_and_lowered_policy_without_submitted_authority() -> TestResult
{
    let resource = resource()?;
    assert!(resource.metadata.annotations.is_none());
    let lowered = lower_kubernetes_policy(&resource, TENANT_ID, CLUSTER_UID, NAMESPACE_UID)?;
    let revision = PolicySourceRevisionV1::from_resource(
        &resource,
        &lowered,
        TENANT_ID,
        CLUSTER_UID,
        NAMESPACE_UID,
        PolicySourceStateV1::Accepted,
    )?;
    assert_eq!(revision.object_generation, 7);
    assert_eq!(revision.opaque_resource_version, b"opaque/watch/97");
    assert_ne!(
        revision.canonical_spec_digest,
        revision.policy_document_digest
    );
    assert!(!revision.policy_source_revision_id.is_empty());
    Ok(())
}

#[test]
fn public_resources_reject_unknown_and_internal_authority_fields() -> TestResult {
    let mut policy = serde_json::to_value(resource()?)?;
    policy["spec"]["roles"][0]["nativeTransitionRules"] = json!([]);
    assert!(serde_json::from_value::<WorkloadProtectionPolicy>(policy).is_err());

    let exception = json!({
        "apiVersion": "mithril.erebor.dev/v1alpha1",
        "kind": "WorkloadProtectionException",
        "metadata": {"name": "temporary", "namespace": "tenant-a"},
        "spec": {
            "policyRef": {"name": "converter"},
            "grant": "temporary-file-access",
            "target": {
                "pod": {"name": "converter-1", "uid": OBJECT_UID},
                "containerName": "converter"
            },
            "requestedDuration": "2m",
            "requestedUses": 1,
            "nodeTarget": "worker-a"
        }
    });
    assert!(serde_json::from_value::<WorkloadProtectionException>(exception).is_err());
    Ok(())
}

#[test]
fn exception_request_requires_an_exact_bounded_target() -> TestResult {
    let valid = json!({
        "policyRef": {"name": "converter"},
        "grant": "temporary-file-access",
        "target": {
            "pod": {"name": "converter-1", "uid": OBJECT_UID},
            "containerName": "converter"
        },
        "requestedDuration": "2m",
        "requestedUses": 1
    });
    let request = serde_json::from_value::<WorkloadProtectionExceptionSpec>(valid.clone())?;
    request.validate_request("temporary")?;

    for invalid in [
        ("/requestedUses", json!(0)),
        ("/requestedDuration", json!("forever")),
        ("/target/pod/uid", json!("pod-by-name-only")),
        ("/target/containerName", json!("")),
    ] {
        let mut candidate = valid.clone();
        *candidate
            .pointer_mut(invalid.0)
            .ok_or("invalid exception test pointer")? = invalid.1;
        let request = serde_json::from_value::<WorkloadProtectionExceptionSpec>(candidate)?;
        assert!(request.validate_request("temporary").is_err());
    }
    Ok(())
}

#[test]
fn policy_lowering_rejects_unqualified_or_ambiguous_authority() -> TestResult {
    let mut recursive_allow = resource()?;
    recursive_allow.spec.roles[0].files[0].recursive = true;
    assert!(
        lower_kubernetes_policy(&recursive_allow, TENANT_ID, CLUSTER_UID, NAMESPACE_UID).is_err()
    );

    let mut mutable_image = resource()?;
    mutable_image.spec.containers[0].images[0] = "registry.example/converter:latest".to_owned();
    assert!(
        lower_kubernetes_policy(&mutable_image, TENANT_ID, CLUSTER_UID, NAMESPACE_UID).is_err()
    );

    let mut positive_ptrace = resource()?;
    let mithril_control::ProcessControlRuleV1::Ptrace { action, .. } =
        &mut positive_ptrace.spec.roles[0].process_control[1]
    else {
        return Err("fixture lost its ptrace rule".into());
    };
    *action = KubernetesRuleActionV1::Allow;
    assert!(
        lower_kubernetes_policy(&positive_ptrace, TENANT_ID, CLUSTER_UID, NAMESPACE_UID).is_err()
    );

    let mut allow_exception = resource()?;
    allow_exception.spec.exception_grants[0].file_rules = vec!["allow-python-read".to_owned()];
    assert!(
        lower_kubernetes_policy(&allow_exception, TENANT_ID, CLUSTER_UID, NAMESPACE_UID).is_err()
    );
    Ok(())
}

fn assert_bounded_schema(schema: &Value) {
    match schema {
        Value::Array(values) => {
            for value in values {
                assert_bounded_schema(value);
            }
        }
        Value::Object(object) => {
            match object.get("type").and_then(Value::as_str) {
                Some("string") => assert!(object.contains_key("maxLength")),
                Some("array") => assert!(object.contains_key("maxItems")),
                Some("object") => assert!(object.contains_key("maxProperties")),
                _ => {}
            }
            for value in object.values() {
                assert_bounded_schema(value);
            }
        }
        _ => {}
    }
}
