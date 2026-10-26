use super::*;

#[test]
fn runtime_binding_keeps_authority() -> TestResult {
    let directory = tempfile::tempdir()?;
    let (store, mut record, bundle, mut rollout) = fixture(&directory.path().join("control"))?;
    let workload = &bundle.candidate.exact_target.workload_targets[0];
    let identity = workload.kubernetes.as_ref().ok_or("identity")?;
    assert!(workload.container_id.starts_with("scheduled:"));
    let proof = crate::EvidenceRuntimeBindingV1 {
        container_id: "oci-container1".into(),
        signed_target_digest: workload.workload_binding_generation_digest.clone(),
    };
    let runtime = araphor_data::KubernetesWorkloadIdentityV1::runtime_binding_id(
        &identity.binding_id,
        &proof.container_id,
    );
    assert_ne!(runtime, identity.binding_id);
    let mut wire = record.decode()?;
    let context = wire.decision_context.as_mut().ok_or("context")?;
    let mut catalog = crate::EvidenceDecisionCatalogV1::from_context(context)?.ok_or("catalog")?;
    catalog.binding_id = uuid::Uuid::parse_str(&runtime)?.into_bytes().into();
    catalog.runtime_binding = Some(proof);
    context.binding_id = catalog.binding_id.to_be_bytes().to_vec();
    context.catalog_json = catalog.clone().seal()?;
    record.wire_record = Vec::<u8>::try_from(&wire)?;
    let data = Arc::new(AnalysisStore::open(directory.path().join("data"))?);
    let mut copy = owner(&store, Arc::clone(&data), record.id.stream.tenant_id)?;
    acknowledge(
        &store,
        &bundle,
        &mut rollout,
        PolicyActivationStateV1::Active,
        Some(7),
        '4',
    )?;
    assert!(policies(&facts(&mut copy, &data, &record)?)?
        .iter()
        .all(|policy| policy.state != PolicyProvenanceStateV1::Exact));
    acknowledge(
        &store,
        &bundle,
        &mut rollout,
        PolicyActivationStateV1::Active,
        Some(8),
        '4',
    )?;
    let selected = policies(&facts(&mut copy, &data, &record)?)?;
    assert_eq!(selected.len(), 1);
    assert_eq!(selected[0].state, PolicyProvenanceStateV1::Exact);
    let retained = GraphContext::new(&capture(&data, record.id.stream.tenant_id)?.1)?;
    for scenario in ["container", "target", "binding", "fallback", "node", "boot"] {
        let mut changed = record.clone();
        let mut changed_wire = wire.clone();
        let context = changed_wire.decision_context.as_mut().ok_or("context")?;
        let mut changed_catalog = catalog.clone();
        match scenario {
            "container" => {
                changed_catalog
                    .runtime_binding
                    .as_mut()
                    .ok_or("proof")?
                    .container_id = "other-container".into();
            }
            "target" => {
                changed_catalog
                    .runtime_binding
                    .as_mut()
                    .ok_or("proof")?
                    .signed_target_digest = "f".repeat(64);
            }
            "binding" => changed_catalog.binding_id = [9; 16].into(),
            "fallback" => {
                changed_catalog.binding_id = uuid::Uuid::parse_str(&identity.binding_id)?
                    .into_bytes()
                    .into();
            }
            "node" => changed.id.stream.node_id = "other-node".into(),
            "boot" => {
                changed.id.stream.node_boot_id = [99; 16];
                changed_catalog.node_boot_id = [99; 16].into();
            }
            _ => unreachable!(),
        }
        context.binding_id = changed_catalog.binding_id.to_be_bytes().to_vec();
        context.catalog_json = changed_catalog.seal()?;
        changed.wire_record = Vec::<u8>::try_from(&changed_wire)?;
        assert!(retained.facts(&changed)?.is_empty(), "accepted {scenario}");
    }
    Ok(())
}
