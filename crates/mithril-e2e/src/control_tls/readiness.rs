use std::time::Duration;

use mithril_node::TrustCache;

use super::registration;
use crate::control_fixture::MtlsFixture;
use crate::platform::TestResult;

#[tokio::test]
async fn readiness_keeps_session() -> TestResult<()> {
    let fixture = MtlsFixture::new(false)?;
    let control = fixture.control(4)?;
    let server = fixture.start(control.clone()).await?;
    let connector = fixture.connector(&server, "node-a", [7; 16]);
    let mut trust = TrustCache::load(fixture.path())?;
    let mut node = registration();
    node.kubernetes_node_name = "worker-a.example".to_owned();
    let connection = connector.connect(node, true, &mut trust).await?;
    control
        .bind_kubernetes_node_session("worker-a.example", "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")?;
    let nonce = trust.installed().control_connection_nonce.clone();
    let age = Duration::from_secs(2);
    let initial = control.ready_kubernetes_node_sessions(age);
    assert_eq!(initial.len(), 1);
    assert_eq!(initial[0].kubernetes_node_name, "worker-a.example");
    assert_eq!(control.registered_nonce_count(), 1);

    // The initial report is older than this lease. Only renewal keeps it ready.
    tokio::time::sleep(Duration::from_millis(2_300)).await;
    let renewed = control.ready_kubernetes_node_sessions(Duration::from_millis(1_500));
    assert_eq!(renewed, initial);
    assert_eq!(control.registered_nonce_count(), 1);
    assert_eq!(trust.installed().control_connection_nonce, nonce);

    for ready in [false, true] {
        connection.report_readiness(true, ready).await?;
        let sessions = control.ready_kubernetes_node_sessions(age);
        if ready {
            assert_eq!(sessions, initial);
        } else {
            assert!(sessions.is_empty());
        }
        assert_eq!(control.registered_nonce_count(), 1);
        assert_eq!(trust.installed().control_connection_nonce, nonce);
    }

    drop(connection);
    server.shutdown().await?;
    Ok(())
}
