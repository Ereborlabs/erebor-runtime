use erebor_runtime_ipc::v1::DecisionKind;

use super::{
    super::SessionInterceptionRouter,
    fixtures::{BrokerFixture, InterceptionRequestFixture, TestSocketConnectHandler},
};

#[test]
fn broker_fails_closed_for_unrouted_socket_connect() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = BrokerFixture::new("unrouted-socket-connect");
    let broker = fixture.register(SessionInterceptionRouter::new())?;

    let decision = fixture.request_decision(
        &broker,
        InterceptionRequestFixture::socket_connect("api.example.test", 443),
    )?;

    assert_eq!(decision.decision, DecisionKind::Deny as i32);
    assert_eq!(
        decision.rule_id,
        "erebor-runtime-interception-broker-unrouted-operation"
    );
    assert!(decision.reason.contains("socket_connect"));
    Ok(())
}

#[test]
fn broker_routes_socket_connect_to_registered_surface_handler(
) -> Result<(), Box<dyn std::error::Error>> {
    let fixture = BrokerFixture::new("routes-socket-connect");
    let router =
        SessionInterceptionRouter::new().with_socket_connect_handler(TestSocketConnectHandler);
    let broker = fixture.register(router)?;

    let decision = fixture.request_decision(
        &broker,
        InterceptionRequestFixture::socket_connect("api.example.test", 443),
    )?;

    assert_eq!(decision.decision, DecisionKind::Deny as i32);
    assert_eq!(decision.rule_id, "network-socket-connect-visible");
    assert_eq!(decision.reason, "tcp://api.example.test:443");
    Ok(())
}
