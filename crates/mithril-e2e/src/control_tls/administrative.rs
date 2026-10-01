use mithril_control::{
    AdministrativeExecArmResult, AdministrativeExecResolution, ArmAdministrativeExec as Arm,
    ResolveAdministrativeExec as Resolve,
};
use mithril_node::{AdministrativeControlRequest as Request, Error, TrustCache};
use tokio::time::{timeout, Duration};

use super::registration;
use crate::control_fixture::MtlsFixture;
use crate::platform::TestResult;

#[tokio::test]
async fn admin_services_keep_requests() -> TestResult<()> {
    let fixture = MtlsFixture::new(false)?;
    let path = fixture.path();
    let control = fixture.control(1)?;
    let server = fixture.start(control.clone()).await?;
    let connector = fixture.connector(&server, "node-a", [7; 16]);
    let mut trust = TrustCache::load(path)?;
    let mut connection = connector.connect(registration(), true, &mut trust).await?;
    let wait = Duration::from_secs(1);

    let mut request = Resolve {
        request_id: vec![1; 16],
        ..Resolve::default()
    };
    let call = control.resolve_administrative_exec("node-a", request.clone());
    let answer = async {
        let Request::Resolve(received) = connection.next_administrative_request().await? else {
            return Err("resolve request reached the wrong service".into());
        };
        assert_eq!(received.request_id, vec![1; 16]);
        let response = AdministrativeExecResolution {
            request_id: received.request_id,
            resolved: true,
            ..AdministrativeExecResolution::default()
        };
        connection.send_resolution(response.clone()).await?;
        TestResult::Ok(response)
    };
    let (reply, sent) = timeout(wait, async { tokio::join!(call, answer) })
        .await
        .map_err(|error| format!("resolve exchange at {path:?}: {error}"))?;
    let mut resolution = sent?;
    assert_eq!(reply?, resolution);

    let arm = Arm {
        request_id: vec![2; 16],
        ..Arm::default()
    };
    let call = control.arm_administrative_exec("node-a", arm);
    let answer = async {
        let Request::Arm(received) = connection.next_administrative_request().await? else {
            return Err("arm request reached the wrong service".into());
        };
        assert_eq!(received.request_id, vec![2; 16]);
        let response = AdministrativeExecArmResult {
            request_id: received.request_id,
            armed: true,
            ..AdministrativeExecArmResult::default()
        };
        connection.send_arm_result(response.clone()).await?;
        TestResult::Ok(response)
    };
    let (reply, sent) = timeout(wait, async { tokio::join!(call, answer) })
        .await
        .map_err(|error| format!("arm exchange at {path:?}: {error}"))?;
    assert_eq!(reply?, sent?);

    request.request_id = vec![3; 16];
    let message = tokio::select! {
        reply = control.resolve_administrative_exec("node-a", request) => {
            return Err(format!("cancelled request completed before Node received it: {reply:?}").into());
        }
        message = timeout(wait, connection.next_administrative_request()) => {
            message.map_err(|error| format!("cancel resolve receive at {path:?}: {error}"))??
        }
    };
    let Request::Resolve(received) = message else {
        return Err("cancelled resolve reached the wrong service".into());
    };
    assert_eq!(received.request_id, vec![3; 16]);
    resolution.request_id = received.request_id;
    connection.send_resolution(resolution).await?;
    let error = timeout(wait, connection.next_message())
        .await
        .map_err(|error| format!("cancelled response at {path:?}: {error}"))?
        .err()
        .ok_or("late response was accepted")?;
    let Error::ControlRpc { source, .. } = error else {
        return Err(format!("late response failed for an unrelated reason: {error}").into());
    };
    assert_eq!(source.code(), tonic::Code::Cancelled);
    assert_eq!(source.message(), "administrative requester stopped waiting");

    drop(connection);
    server.shutdown().await?;
    Ok(())
}
