use super::*;

#[test]
fn graph_native_baseline() -> TestResult {
    let mut denied = wire(1, DeniedBeforeEffect, 2, 2, [20; 16]);
    let original = input(vec![record(1, &denied)?]);
    let protected = GraphAndFindingOwner::derive(&original)?;
    let mut gapped = original;
    gapped.coverage[0].state = DiscoveryCoverageStateV1::Gapped;
    gapped.coverage[0].gap_reasons.push("GAP".into());
    gapped.coverage_keys[0].state = DiscoveryCoverageStateV1::Gapped;
    gapped.coverage_keys[0].gap_reasons.push("GAP".into());
    let gapped = GraphAndFindingOwner::derive(&gapped)?;
    denied.task_cookie = 0;
    denied
        .decision_context
        .as_mut()
        .ok_or("context")?
        .process_instance_id = vec![0; 16];
    let missing = GraphAndFindingOwner::derive(&input(vec![record(1, &denied)?]))?;
    let actual = serde_json::json!({"protected": protected, "gapped": gapped, "missing": missing});
    assert_eq!(
        actual,
        serde_json::from_slice::<serde_json::Value>(include_bytes!("baseline/native.json"))?
    );
    Ok(())
}

#[test]
fn graph_credential_baseline() -> TestResult {
    let mut input = credential_input()?;
    let direct = GraphAndFindingOwner::derive(&input)?;
    let mut use_fact = GraphFactV1::try_from(&input.facts[5])?;
    if let GraphFactValueV1::AuthorityUse {
        process_instance_id,
        task_cookie,
        credential_object_id,
        socket_object_id,
        ..
    } = &mut use_fact.value
    {
        *process_instance_id = Some([22; 16]);
        *task_cookie = Some(22);
        *credential_object_id = None;
        *socket_object_id = None;
    }
    input.facts[5].body = serde_json::to_vec(&use_fact)?;
    let contextual = GraphAndFindingOwner::derive(&input)?;
    input.facts.remove(5);
    let missing = GraphAndFindingOwner::derive(&input)?;
    let actual =
        serde_json::json!({"direct": direct, "contextual": contextual, "missing": missing});
    assert_eq!(
        actual,
        serde_json::from_slice::<serde_json::Value>(include_bytes!("baseline/credential.json"))?
    );
    Ok(())
}

#[test]
fn graph_kubernetes_baseline() -> TestResult {
    let mut input = input(vec![record(
        1,
        &wire(1, UnknownAfterPreEffect, 3, 13, [20; 16]),
    )?]);
    let mut stage = KubernetesStageProofV1 {
        cluster_id: "cluster".into(),
        carried_request_id: None,
        audit_id: None,
        object_uid: None,
        resource_version: None,
        owner_uid: None,
        pod_uid: None,
        node_id: None,
        full_container_id: None,
        remote_admission_id: None,
        proof_quality: authority_proof(),
    };
    let mut outputs = Vec::new();
    for index in 0..6 {
        match index {
            1 => stage.carried_request_id = Some("request".into()),
            2 => stage.audit_id = Some("audit".into()),
            3 => {
                stage.object_uid = Some("object".into());
                stage.resource_version = Some("version".into());
            }
            4 => {
                stage.owner_uid = Some("owner".into());
                stage.pod_uid = Some("pod".into());
                stage.node_id = Some("remote-node".into());
            }
            5 => {
                stage.full_container_id = Some("container".into());
                stage.remote_admission_id = Some("admission".into());
            }
            _ => {}
        }
        input.facts = vec![fact(
            &input.records[0],
            1,
            GraphFactValueV1::Kubernetes(stage.clone()),
        )?];
        outputs.push(GraphAndFindingOwner::derive(&input)?);
    }
    let actual = serde_json::to_value(outputs)?;
    assert_eq!(
        actual,
        serde_json::from_slice::<serde_json::Value>(include_bytes!("baseline/kubernetes.json"))?
    );
    Ok(())
}
