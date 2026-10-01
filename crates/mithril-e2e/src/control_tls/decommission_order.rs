use std::time::Duration;

use mithril_control::NodeDecommissionStateV1 as State;
use mithril_node::{
    NodeControlMessage as Message, NodeDecommissionAcceptanceV1 as Acceptance,
    NodeDecommissionOwner, TrustCache,
};
use sha2::{Digest as _, Sha256};

use super::registration;
use crate::control_fixture::MtlsFixture;
use crate::physical::wait_for_async;
use crate::platform::TestResult;

#[tokio::test]
async fn decommission_keeps_durable_order() -> TestResult<()> {
    let tls = MtlsFixture::new(false)?;
    let control = tls.control(4)?;
    let server = tls.start(control.clone()).await?;
    let connector = tls.connector(&server, "node-a", [7; 16]);
    let mut trust = TrustCache::load(tls.path())?;
    let mut node = registration();
    node.kubernetes_node_name = "worker-a.example".to_owned();
    let mut connection = connector.connect(node, true, &mut trust).await?;
    control
        .bind_kubernetes_node_session("worker-a.example", "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")?;
    let wait = Duration::from_secs(2);
    let ready = || control.ready_kubernetes_node_sessions(wait);
    let sessions = ready();
    assert_eq!(sessions.len(), 1);
    let (config, artifact) = tls.decommission([7; 16])?;
    let path = tls.path().join("node-state");
    let mut owner =
        NodeDecommissionOwner::load(&config, &path, "node-a".to_owned(), [7; 16].into())?;
    let submission = control.submit_node_decommission(artifact.clone()).await?;
    let hash = &submission.artifact_sha256;
    let digest: [u8; 32] = Sha256::digest(&artifact).into();

    for (state, execute, acceptance) in [
        (State::Accepted, false, Acceptance::Accepted),
        (State::Completed, true, Acceptance::ResumeCleanup),
    ] {
        if execute {
            control
                .confirm_node_decommission_quarantine_for_test(&sessions[0])
                .await?;
        }
        let message = tokio::time::timeout(wait, connection.next_message())
            .await
            .map_err(|error| format!("decommission {state:?} command: {error}"))??;
        let Message::Decommission(command) = message else {
            return Err(format!("Control returned no {state:?} command").into());
        };
        assert_eq!(command.execute, execute);
        assert_eq!(command.artifact, artifact);
        assert_eq!(owner.accept(&command.artifact, 0, 1)?, acceptance);
        if execute {
            owner.complete(&command.artifact)?;
        }
        let result = if execute { "COMPLETED" } else { "ACCEPTED" };
        connection
            .send_decommission_result(digest, result, String::new())
            .await?;
        wait_for_async(
            &path,
            &format!("Control decommission {state:?}"),
            wait,
            || {
                Ok(control
                    .node_decommission_status(hash)
                    .is_ok_and(|status| status.state == state)
                    .then_some(()))
            },
            || format!("last status: {:?}", control.node_decommission_status(hash)),
        )
        .await?;
        if !execute {
            wait_for_async(
                &path,
                "accepted Node leaves ready sessions",
                wait,
                || Ok(ready().is_empty().then_some(())),
                || format!("last ready sessions: {:?}", ready()),
            )
            .await?;
        }
    }
    assert!(owner.completed());
    assert!(NodeDecommissionOwner::durable_completion(&path)?);

    drop(connection);
    server.shutdown().await?;
    Ok(())
}
