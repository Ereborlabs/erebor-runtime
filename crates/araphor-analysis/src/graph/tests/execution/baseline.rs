use super::super::{baseline::historical_snapshot, fixture::*};
use super::*;
use araphor_data::KubernetesStageProofV1;
use EffectPhysicalResultV1::{DeniedBeforeEffect, UnknownAfterPreEffect};

#[tokio::test]
#[ignore = "requires source-built native artifacts in ARAPHOR_NATIVE_DIR"]
async fn native_process_baseline() -> TestResult {
    let mut denied = wire(1, DeniedBeforeEffect, 2, 2, [20; 16]);
    let original = input(vec![record(1, &denied)?]);
    let fixtures = fixtures(&original)?;
    let protected = snapshot(&original, &fixtures).await?;
    let mut gapped = original;
    gapped.coverage[0].state = DiscoveryCoverageStateV1::Gapped;
    gapped.coverage[0].gap_reasons.push("GAP".into());
    gapped.coverage_keys[0].state = DiscoveryCoverageStateV1::Gapped;
    gapped.coverage_keys[0].gap_reasons.push("GAP".into());
    let gapped = snapshot(&gapped, &fixtures).await?;
    denied.task_cookie = 0;
    denied
        .decision_context
        .as_mut()
        .ok_or("context")?
        .process_instance_id = vec![0; 16];
    let missing = snapshot(&input(vec![record(1, &denied)?]), &fixtures).await?;
    let actual = serde_json::json!({"protected": protected, "gapped": gapped, "missing": missing});
    assert_eq!(
        actual,
        serde_json::from_slice::<serde_json::Value>(include_bytes!("../baseline/native.json"))?
    );
    Ok(())
}

#[tokio::test]
#[ignore = "requires source-built native artifacts in ARAPHOR_NATIVE_DIR"]
async fn native_credential_baseline() -> TestResult {
    let mut input = credential_input()?;
    let fixtures = fixtures(&input)?;
    let direct = snapshot(&input, &fixtures).await?;
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
    input.facts[5].body = use_fact.encode_context()?;
    let contextual = snapshot(&input, &fixtures).await?;
    input.facts.remove(5);
    let missing = snapshot(&input, &fixtures).await?;
    let actual =
        serde_json::json!({"direct": direct, "contextual": contextual, "missing": missing});
    assert_eq!(
        actual,
        serde_json::from_slice::<serde_json::Value>(include_bytes!("../baseline/credential.json"))?
    );
    Ok(())
}

#[tokio::test]
#[ignore = "requires source-built native artifacts in ARAPHOR_NATIVE_DIR"]
async fn native_kubernetes_baseline() -> TestResult {
    let mut input = input(vec![record(
        1,
        &wire(1, UnknownAfterPreEffect, 3, 13, [20; 16]),
    )?]);
    let fixtures = fixtures(&input)?;
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
        outputs.push(snapshot(&input, &fixtures).await?);
    }
    let actual = serde_json::to_value(outputs)?;
    assert_eq!(
        actual,
        serde_json::from_slice::<serde_json::Value>(include_bytes!("../baseline/kubernetes.json"))?
    );
    Ok(())
}

fn fixtures(input: &GraphReplayInputV1) -> TestResult<Vec<(algorithm::Detector, Fixture)>> {
    let input = input.normalized()?;
    detectors()
        .into_iter()
        .map(|detector| {
            let evaluation = evaluation(&input, detector)?;
            let expected = detector.evaluate(&evaluation)?;
            Ok((
                detector,
                Fixture::new(detector, Target::Native, &evaluation, &expected, None)?,
            ))
        })
        .collect()
}

async fn snapshot(
    input: &GraphReplayInputV1,
    fixtures: &[(algorithm::Detector, Fixture)],
) -> TestResult<GraphSnapshotV1> {
    let input = input.normalized()?;
    let mut graph = Graph::new(&input)?;
    for (detector, fixture) in fixtures {
        let evaluation = evaluation(&input, *detector)?;
        let expected = detector.evaluate(&evaluation)?;
        let (call, returned) = fixture.run(&evaluation).await?;
        let result = returned.calls.get(&call.id()).ok_or("baseline call")?;
        fixture.compare(&evaluation, &expected, result)?;
        graph = graph.apply(&call, result)?;
        drop(returned);
        drop(call);
        fixture.released()?;
    }
    Ok(historical_snapshot(graph.finish()?))
}
