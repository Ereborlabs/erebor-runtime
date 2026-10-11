use super::*;
use crate::Rows;

mod fixture;
use fixture::*;

type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;

#[test]
fn process_replay_checkpoint() -> TestResult {
    let detector = Detector::Process;
    let mut fixture = fixture(detector, &[record()], &[])?;
    let (first, output) = findings(detector, &fixture)?;
    assert_eq!(first.len(), 1);
    assert_eq!(first[0].reason, "UNEXPECTED_EFFECT");
    assert!(first[0].confirmed);
    assert_eq!(first[0].evidence, [0]);
    fixture.evaluation.inputs.reverse();
    fixture.evaluation.checkpoint = output.checkpoint;
    let (replay, _) = findings(detector, &fixture)?;
    assert_eq!(serde_json::to_value(first)?, serde_json::to_value(replay)?);
    Ok(())
}

#[test]
fn process_context_classifications() -> TestResult {
    let detector = Detector::Process;
    for (classification, reason) in [
        (ContextClass::OutsideAuthority, "OUTSIDE_AUTHORITY"),
        (ContextClass::InMemory, "IN_MEMORY_ONLY"),
        (ContextClass::PayloadUnobservable, "PAYLOAD_UNOBSERVABLE"),
    ] {
        let fixture = fixture(
            detector,
            &[record()],
            &[fact(0, FactValue::Context { classification })],
        )?;
        let (rows, _) = findings(detector, &fixture)?;
        assert_eq!(rows[1].reason, reason);
        assert!(!rows[1].confirmed);
        assert_eq!(rows[1].context, Some(0));
    }
    Ok(())
}

#[test]
fn fact_reference_is_exact() -> TestResult {
    let fixture = fixture(
        Detector::Process,
        &[record()],
        &[fact(
            u64::from(u32::MAX) + 1,
            FactValue::Context {
                classification: ContextClass::InMemory,
            },
        )],
    )?;
    assert!(Detector::Process.evaluate(&fixture.evaluation).is_err());
    Ok(())
}

#[test]
fn kubernetes_retains_missing_proof() -> TestResult {
    let detector = Detector::Kubernetes;
    let stage = Kubernetes {
        qualified: true,
        request: true,
        audit: true,
        object: true,
        version: true,
        owner: true,
        pod: true,
        node: true,
        container: true,
        admission: true,
    };
    let fixture = fixture(
        detector,
        &[record()],
        &[fact(0, FactValue::Kubernetes(stage))],
    )?;
    let (rows, output) = findings(detector, &fixture)?;
    assert_eq!(rows[0].limits, ["CROSS_NODE_CAUSALITY_UNQUALIFIED"]);
    assert!(!rows[0].confirmed);
    let state = output.checkpoint.ok_or("checkpoint")?;
    let rows: Vec<State> = Rows::decode(
        &detector.descriptor().exports[0]
            .checkpoint
            .as_ref()
            .ok_or("checkpoint descriptor")?
            .datasets[0],
        &state.datasets[0],
        sdk::Limits::default(),
    )?;
    assert_eq!(rows[0].value, "REMOTE_ADMISSION");
    Ok(())
}

#[test]
fn credential_exact_and_missing() -> TestResult {
    let detector = Detector::Credentials;
    let mut read = record();
    read.admitted = true;
    read.denied = false;
    read.physical = Physical::Unknown;
    let mut channel = read.clone();
    channel.network = true;
    channel.object = vec![7; 16];
    channel.boottime = 11;
    let mut remote = read.clone();
    remote.boottime = 12;
    let credential = Credential {
        object: [6; 16],
        expected: false,
        reviewed: true,
        successful: true,
        completion: Some(Completion {
            owner: "node".into(),
            id: "read".into(),
            task: 3,
            process: [4; 16],
            object: [6; 16],
            file_description: "fd".into(),
            path: ReadPath::Read,
            result: 8,
            bytes: 8,
            lease: Some("lease".into()),
            principal: Some("principal".into()),
        }),
        principal: Some("principal".into()),
    };
    let channel_fact = Channel {
        task: 3,
        process: [4; 16],
        socket: [7; 16],
        authority: "provider".into(),
        request: "request".into(),
        lease: "lease".into(),
        principal: "principal".into(),
        operation: "write".into(),
        successful: true,
    };
    let authority = Authority {
        id: "provider".into(),
        process: Some([4; 16]),
        task: Some(3),
        credential: Some([6; 16]),
        socket: Some([7; 16]),
        request: Some("request".into()),
        lease: Some("lease".into()),
        principal: "principal".into(),
        operation: "write".into(),
        outside: true,
        workload: Some(vec![5; 16]),
        contextual: true,
        direct: true,
        result: ResultAuthority::Succeeded,
    };
    let facts = vec![
        fact(0, FactValue::Credential(credential)),
        fact(1, FactValue::Channel(channel_fact)),
        fact(2, FactValue::Authority(authority)),
    ];
    let mut complete = fixture(detector, &[read, channel, remote], &facts)?;
    let batch = complete.evaluation.inputs[0].data.batches.remove(0);
    complete.evaluation.inputs[0].data.batches = vec![batch.slice(0, 1), batch.slice(1, 2)];
    let (rows, output) = findings(detector, &complete)?;
    assert_eq!(rows[0].reason, "CREDENTIAL_PIVOT");
    assert!(rows[0].confirmed);
    assert_eq!(rows[0].evidence, [0, 1, 2]);
    assert_eq!(output.evidence.len(), 3);
    authority_identity_order(&complete, &facts)?;
    let mut missing = complete;
    let model = detector.descriptor();
    missing.evaluation.inputs[1].data = Rows::encode(
        &model.exports[0].inputs[1],
        &facts[..1],
        missing.evaluation.context.limits,
    )?;
    let (rows, _) = findings(detector, &missing)?;
    assert_eq!(rows[0].reason, "MISSING_AUTHORITY_PROOF");
    assert!(!rows[0].confirmed);
    Ok(())
}

fn authority_identity_order(complete: &sdk::Fixture, facts: &[Fact]) -> TestResult {
    let detector = Detector::Credentials;
    let package = detector.descriptor();
    let model = &package.exports[0];
    let records: Vec<Observation> = Rows::decode(
        &model.inputs[0],
        &complete.evaluation.inputs[0].data,
        complete.evaluation.context.limits,
    )?;
    let mut blocked = records[1].clone();
    blocked.admitted = false;
    let mut records = vec![
        records[0].clone(),
        blocked,
        records[1].clone(),
        records[2].clone(),
        records[2].clone(),
        records[2].clone(),
    ];
    let mut carried = facts[1].clone();
    carried.record = 2;
    let mut first = facts[2].clone();
    first.identity = 50;
    first.record = 4;
    let FactValue::Authority(authority) = &mut first.value else {
        return Err("authority fixture".into());
    };
    authority.direct = false;
    let mut earlier = facts[2].clone();
    earlier.identity = 90;
    earlier.record = 3;
    let mut duplicate = facts[2].clone();
    duplicate.identity = 50;
    duplicate.record = 5;
    let mut later = facts[2].clone();
    later.identity = 1;
    later.record = 3;
    let facts = vec![facts[0].clone(), carried, first, earlier, duplicate, later];
    for network in [true, false] {
        records[1].network = network;
        records[2].network = network;
        let fixture = fixture(detector, &records, &facts)?;
        let (findings, output) = findings(detector, &fixture)?;
        let edges: Vec<Relationship> = Rows::decode(
            &model.outputs[1],
            &output.datasets[1],
            fixture.evaluation.context.limits,
        )?;
        assert_eq!(findings.len(), 1);
        assert_eq!(edges.len(), 3);
        assert_eq!(
            edges.iter().map(|edge| edge.fact).collect::<Vec<_>>(),
            [Some(3), Some(5), Some(2)]
        );
        let (reason, evidence, prefix) = if network {
            (
                "CREDENTIAL_PIVOT",
                vec![0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 4],
                9,
            )
        } else {
            ("CONTEXTUAL_CREDENTIAL_PIVOT", vec![0, 3, 3, 4], 1)
        };
        for (index, edge) in edges.iter().enumerate() {
            assert_eq!(edge.record, 0);
            assert!(matches!(edge.kind, EdgeKind::Authority));
            assert!(matches!(
                (network, edge.cause),
                (true, Cause::Direct) | (false, Cause::Contextual)
            ));
            assert_eq!(edge.evidence, evidence[..prefix + index + 1]);
        }
        assert_eq!(findings[0].reason, reason);
        assert_eq!(findings[0].confirmed, network);
        assert_eq!(findings[0].evidence, evidence);
        assert_eq!(
            output
                .evidence
                .iter()
                .map(|link| link.input.row)
                .collect::<Vec<_>>(),
            if network {
                vec![0, 1, 2, 3, 4]
            } else {
                vec![0, 3, 4]
            }
        );
    }
    Ok(())
}
