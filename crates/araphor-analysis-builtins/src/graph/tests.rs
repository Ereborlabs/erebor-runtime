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
