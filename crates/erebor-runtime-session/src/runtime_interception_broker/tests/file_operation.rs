use erebor_runtime_ipc::v1::{DecisionKind, FileOperationKind, InterceptionOperation};

use super::{
    super::SessionInterceptionRouter,
    fixtures::{BrokerFixture, InterceptionRequestFixture, TestFileHandler},
};

#[test]
fn broker_routes_file_operation_to_registered_surface_handler(
) -> Result<(), Box<dyn std::error::Error>> {
    let fixture = BrokerFixture::new("routes-file-operation");
    let router = SessionInterceptionRouter::new().with_file_operation_handler(TestFileHandler);
    let broker = fixture.register(router)?;

    let decision = fixture.request_decision(
        &broker,
        InterceptionRequestFixture::file(FileOperationKind::Read, "/workspace/secret.txt"),
    )?;

    assert_eq!(decision.decision, DecisionKind::Deny as i32);
    assert_eq!(decision.rule_id, "filesystem-file-read-visible");
    assert_eq!(decision.reason, "/workspace/secret.txt@/workspace:100");
    Ok(())
}

#[test]
fn broker_fails_closed_for_mismatched_file_operation_payload(
) -> Result<(), Box<dyn std::error::Error>> {
    let fixture = BrokerFixture::new("mismatched-file-operation");
    let router = SessionInterceptionRouter::new().with_file_operation_handler(TestFileHandler);
    let broker = fixture.register(router)?;
    let mut request =
        InterceptionRequestFixture::file(FileOperationKind::Read, "/workspace/secret.txt");
    request.operation = InterceptionOperation::FileOpen as i32;

    let decision = fixture.request_decision(&broker, request)?;

    assert_eq!(decision.decision, DecisionKind::Deny as i32);
    assert_eq!(
        decision.rule_id,
        "erebor-runtime-interception-broker-invalid-operation-payload"
    );
    assert!(decision.reason.contains("file.kind"));
    Ok(())
}
