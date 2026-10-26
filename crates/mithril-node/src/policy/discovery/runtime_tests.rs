use super::*;
use crate::ScheduledRuntimeBindingV1;

#[test]
fn runtime_catalog_metadata() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let (artifact, binding) = super::super::tests::entry_roles_artifact()?;
    let objects = super::super::tests::entry_role_objects(&artifact, &binding)?;
    let boot = Id128V1::new(1, 2);
    let authority =
        ScheduledRuntimeBindingV1::authority_binding_id(&binding.pod_uid, &binding.container_name);
    let scheduled = WorkloadBindingConfig {
        binding_id: authority.clone(),
        scheduled_binding_authority_id: Some(authority.clone()),
        scheduled_target_digest: Some("d".repeat(64)),
        container_id: format!("scheduled:{}", "a".repeat(64)),
        ..binding
    };
    let container_id = "a".repeat(64);
    let runtime = WorkloadBindingConfig {
        binding_id: ScheduledRuntimeBindingV1::runtime_binding_id(&authority, &container_id),
        container_id: container_id.clone(),
        ..scheduled.clone()
    };
    let build = |binding: &WorkloadBindingConfig| {
        let mut catalog = NodeDiscoveryContextCatalog::default();
        catalog.add_verified_binding(&artifact, binding, &objects, boot);
        catalog
    };
    for (binding, expected) in [
        (&scheduled, None),
        (
            &runtime,
            Some(EvidenceRuntimeBindingV1 {
                container_id,
                signed_target_digest: "d".repeat(64),
            }),
        ),
    ] {
        let catalog = build(binding);
        assert!(catalog.unavailable.is_none());
        let bytes = catalog
            .entries
            .values()
            .find_map(|value| value.as_ref().ok())
            .ok_or("no signed catalog entry")?;
        let sealed: EvidenceDecisionCatalogV1 = serde_json::from_slice(bytes)?;
        assert_eq!(sealed.runtime_binding, expected);
        assert_eq!(sealed.digest, sealed.content_digest()?);
        assert_eq!(
            sealed.binding_id.to_be_bytes(),
            uuid::Uuid::parse_str(&binding.binding_id)?.into_bytes()
        );
    }

    for invalid in [
        WorkloadBindingConfig {
            scheduled_binding_authority_id: None,
            ..runtime.clone()
        },
        WorkloadBindingConfig {
            scheduled_target_digest: None,
            ..runtime.clone()
        },
        WorkloadBindingConfig {
            scheduled_target_digest: Some("A".repeat(64)),
            ..runtime.clone()
        },
        WorkloadBindingConfig {
            scheduled_binding_authority_id: Some("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".into()),
            ..runtime.clone()
        },
        WorkloadBindingConfig {
            binding_id: authority,
            ..runtime.clone()
        },
        WorkloadBindingConfig {
            container_id: "b".repeat(64),
            ..runtime.clone()
        },
        WorkloadBindingConfig {
            container_id: "invalid/container".into(),
            ..runtime.clone()
        },
        WorkloadBindingConfig {
            binding_id: runtime.binding_id.clone(),
            ..scheduled
        },
    ] {
        let mut catalog = build(&runtime);
        assert!(!catalog.entries.is_empty());
        catalog.add_verified_binding(&artifact, &invalid, &objects, boot);
        assert!(catalog.entries.is_empty());
        assert_eq!(catalog.unavailable, Some("MISSING_CATALOG"));
    }
    Ok(())
}
