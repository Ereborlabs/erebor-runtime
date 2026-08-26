use std::collections::BTreeSet;
use std::path::Path;

use mithril_control::{
    canonical_kubernetes_policy_spec_bytes, exception_custom_resource_definition,
    lower_kubernetes_policy, policy_custom_resource, policy_custom_resource_definition,
    CompiledPhysicalResultV1, EffectFamilyV1, EntryKindV1, KubernetesExecutionOperationV1,
    KubernetesRuleActionV1, PolicyCompiler, PolicySourceRevisionV1, PolicySourceStateV1,
    ProfileModeV1, RootClassificationV1, WorkloadProtectionException,
    WorkloadProtectionExceptionSpec, WorkloadProtectionPolicy, WorkloadProtectionPolicySpec,
    EXCEPTION_KIND, POLICY_KIND,
};
use serde_json::{json, Value};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const POLICY: &str = include_str!("fixtures/kubernetes-policy-v1.yaml");
const ENTRY_ROLES_POLICY: &str = include_str!("fixtures/kubernetes-entry-roles-v1.yaml");
const CONVERGENCE_POLICY: &[u8] =
    include_bytes!("../../mithril-e2e/fixtures/convergence/policy-v1.yaml");
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

fn entry_roles_resource() -> TestResult<WorkloadProtectionPolicy> {
    let spec = WorkloadProtectionPolicySpec::parse(
        Path::new("kubernetes-entry-roles-v1.yaml"),
        ENTRY_ROLES_POLICY.as_bytes(),
    )?;
    let mut resource = policy_custom_resource("worker", "tenant-a", spec)?;
    resource.metadata.uid = Some(OBJECT_UID.to_owned());
    resource.metadata.generation = Some(7);
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
    let container_properties = policy_json
        .pointer(
            "/spec/versions/0/schema/openAPIV3Schema/properties/spec/properties/containers/items/properties",
        )
        .and_then(Value::as_object)
        .ok_or("container policy schema is absent")?;
    assert_eq!(
        container_properties
            .keys()
            .cloned()
            .collect::<BTreeSet<_>>(),
        BTreeSet::from([
            "additionalEntries".to_owned(),
            "administrativeEntry".to_owned(),
            "applicationEntry".to_owned(),
            "externalRole".to_owned(),
            "images".to_owned(),
            "kinds".to_owned(),
            "names".to_owned(),
        ])
    );
    assert!(!container_properties.contains_key("initialRole"));
    assert_eq!(
        policy_json.pointer(
            "/spec/versions/0/schema/openAPIV3Schema/properties/spec/properties/containers/items/properties/additionalEntries/items/properties/kind/enum",
        ),
        Some(&json!([
            "PostStart",
            "PreStop",
            "StartupProbe",
            "ReadinessProbe",
            "LivenessProbe"
        ]))
    );

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
    assert_eq!(lowered.effect_family_defaults.len(), 2);
    assert!(lowered.effect_family_defaults.iter().all(|default| {
        default.effect_family == EffectFamilyV1::Network
            && matches!(
                default.operations.as_slice(),
                [operation] if operation == "SOCKET_CREATE" || operation == "SHUTDOWN"
            )
    }));
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
    let path_object_classes = lowered
        .path_selectors
        .iter()
        .map(|selector| selector.object_class_id.as_str())
        .collect::<BTreeSet<_>>();
    assert_eq!(path_object_classes.len(), lowered.path_selectors.len());
    assert_eq!(
        path_object_classes,
        lowered
            .protected_universe
            .object_class_ids
            .iter()
            .map(String::as_str)
            .collect()
    );
    assert!(lowered.path_selectors.iter().all(|selector| {
        lowered.classifier_bindings.iter().any(|binding| {
            binding.object_class_id == selector.object_class_id
                && binding.classifier_binding_id
                    == format!("kubernetes-{}", selector.path_selector_id)
                && binding.required_capability_ids.is_empty()
        })
    }));
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
fn independent_entry_roles_lower_without_application_role_inheritance() -> TestResult {
    let resource = entry_roles_resource()?;
    let lowered = lower_kubernetes_policy(&resource, TENANT_ID, CLUSTER_UID, NAMESPACE_UID)?;
    let compiled = PolicyCompiler.compile(&lowered)?;

    assert_eq!(lowered.entry_role_assignments.len(), 8);
    let expected = [
        (
            "container-0-application",
            EntryKindV1::ContainerStart,
            RootClassificationV1::ExactInitial,
            "application",
            Some("application-entry"),
            false,
        ),
        (
            "container-0-additional-initialize-cache",
            EntryKindV1::DeclaredPostStart,
            RootClassificationV1::DeclaredAdditionalEntry,
            "cache-initializer",
            Some("initialize-cache-entry"),
            false,
        ),
        (
            "container-0-additional-graceful-drain",
            EntryKindV1::DeclaredPreStop,
            RootClassificationV1::DeclaredAdditionalEntry,
            "connection-drainer",
            Some("graceful-drain-entry"),
            false,
        ),
        (
            "container-0-additional-startup-check",
            EntryKindV1::DeclaredStartupProbe,
            RootClassificationV1::DeclaredAdditionalEntry,
            "startup-probe",
            Some("startup-probe-entry"),
            false,
        ),
        (
            "container-0-additional-readiness-check",
            EntryKindV1::DeclaredReadinessProbe,
            RootClassificationV1::DeclaredAdditionalEntry,
            "readiness-probe",
            Some("readiness-probe-entry"),
            false,
        ),
        (
            "container-0-additional-liveness-check",
            EntryKindV1::DeclaredLivenessProbe,
            RootClassificationV1::DeclaredAdditionalEntry,
            "liveness-probe",
            Some("liveness-probe-entry"),
            false,
        ),
        (
            "container-0-administrative",
            EntryKindV1::ApprovedAdministrativeExec,
            RootClassificationV1::ApprovedAdministrativeNextMatch,
            "administrator",
            None,
            true,
        ),
        (
            "container-0-external",
            EntryKindV1::ExternalRuntimeUnknown,
            RootClassificationV1::ConservativeExternalUnknown,
            "runtime-external",
            None,
            false,
        ),
    ];
    for (id, kind, classification, role, execution_rule, administrative) in expected {
        let assignment = lowered
            .entry_role_assignments
            .iter()
            .find(|assignment| assignment.assignment_id == id)
            .ok_or_else(|| format!("missing assignment `{id}`"))?;
        assert_eq!(assignment.entry_kinds, [kind]);
        assert_eq!(assignment.accepted_classifications, [classification]);
        assert_eq!(assignment.resulting_role_id, role);
        assert_eq!(
            assignment.admission_execution_rule_id.as_deref(),
            execution_rule
        );
        assert_eq!(
            assignment.required_administrative_exec_approval,
            administrative
        );
    }

    for role in &lowered.roles {
        assert_eq!(role.permitted_entry_kinds.len(), 1, "{}", role.role_id);
    }
    assert!(compiled.compiled_cells.iter().all(|cell| {
        lowered.roles.iter().any(|role| {
            role.role_id == cell.key.role_id
                && role.permitted_entry_kinds.contains(&cell.key.entry_kind)
        })
    }));

    let mut cross_role = lowered.clone();
    cross_role
        .entry_role_assignments
        .iter_mut()
        .find(|assignment| assignment.assignment_id == "container-0-application")
        .ok_or("application assignment is absent")?
        .admission_execution_rule_id = Some("initialize-cache-entry".to_owned());
    assert!(PolicyCompiler.compile(&cross_role).is_err());

    let mut denied_entry = lowered;
    denied_entry
        .rules
        .iter_mut()
        .find(|rule| rule.rule_id == "application-entry")
        .ok_or("application entry rule is absent")?
        .requested_disposition = mithril_control::PolicyDispositionV1::Deny;
    assert!(PolicyCompiler.compile(&denied_entry).is_err());
    Ok(())
}

#[test]
fn entry_execution_references_reject_invalid_or_ambiguous_admission() -> TestResult {
    let valid = entry_roles_resource()?;
    let mutations: [fn(&mut WorkloadProtectionPolicy); 7] = [
        |resource| {
            resource.spec.containers[0].application_entry.execution_rule =
                "missing-entry".to_owned();
        },
        |resource| {
            resource.spec.containers[0].application_entry.role = "cache-initializer".to_owned();
        },
        |resource| {
            resource.spec.roles[0].execution[0].action = KubernetesRuleActionV1::Deny;
        },
        |resource| {
            resource.spec.roles[0].execution[0].recursive = true;
        },
        |resource| {
            resource.spec.roles[0].execution[0].operations =
                vec![KubernetesExecutionOperationV1::MmapExecute];
        },
        |resource| {
            resource.spec.roles[1].execution[0].path = "/bin/sh".to_owned();
        },
        |resource| {
            resource.spec.containers[0].additional_entries[0].role = "application".to_owned();
            resource.spec.containers[0].additional_entries[0].execution_rule =
                "application-entry".to_owned();
        },
    ];
    for mutate in mutations {
        let mut invalid = valid.clone();
        mutate(&mut invalid);
        assert!(lower_kubernetes_policy(&invalid, TENANT_ID, CLUSTER_UID, NAMESPACE_UID).is_err());
    }

    let unsupported = ENTRY_ROLES_POLICY.replacen("kind: PostStart", "kind: Exec", 1);
    assert!(WorkloadProtectionPolicySpec::parse(
        Path::new("kubernetes-entry-roles-v1.yaml"),
        unsupported.as_bytes(),
    )
    .is_err());
    Ok(())
}

#[test]
fn application_policy_lowering_does_not_create_implicit_denials() -> TestResult {
    let mut resource = resource()?;
    resource.spec.roles[0].network.socket_controls.clear();
    let lowered = lower_kubernetes_policy(&resource, TENANT_ID, CLUSTER_UID, NAMESPACE_UID)?;
    assert!(lowered.effect_family_defaults.is_empty());
    assert!(lowered
        .rules
        .iter()
        .any(|rule| rule.rule_id == "deny-service-account-files"));
    Ok(())
}

#[test]
fn convergence_policy_has_only_declared_entry_and_explicit_deny_paths() -> TestResult {
    let mut resource: WorkloadProtectionPolicy = serde_saphyr::from_slice(CONVERGENCE_POLICY)?;
    resource.metadata.namespace = Some("mithril-convergence".to_owned());
    resource.metadata.uid = Some(OBJECT_UID.to_owned());
    resource.metadata.generation = Some(1);
    let lowered = lower_kubernetes_policy(&resource, TENANT_ID, CLUSTER_UID, NAMESPACE_UID)?;
    PolicyCompiler.compile(&lowered)?;

    let paths = lowered
        .path_selectors
        .iter()
        .map(|selector| selector.path_expression())
        .collect::<BTreeSet<_>>();
    assert_eq!(lowered.path_selectors.len(), 12);
    assert_eq!(
        paths,
        BTreeSet::from([
            "/bin/sh",
            "/bin/cat",
            "/bin/cp",
            "/bin/dd",
            "/bin/grep",
            "/bin/wc",
            "/var/lib/mithril-convergence/liveness-probe.denied",
            "/var/lib/mithril-convergence/poststart.denied",
            "/var/lib/mithril-convergence/prestop.denied",
            "/var/lib/mithril-convergence/protected.exception-target",
            "/var/lib/mithril-convergence/readiness-probe.denied",
            "/var/lib/mithril-convergence/startup-probe.denied",
        ])
    );
    assert!(!paths.contains("/bin/busybox"));
    assert!(lowered.effect_family_defaults.is_empty());
    assert!(lowered
        .path_selectors
        .iter()
        .all(|selector| !selector.requires_exact_object()));
    assert!(lowered
        .rules
        .iter()
        .any(|rule| rule.rule_id == "deny-exception-target-open"));
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
