use std::fs;

use erebor_runtime_ipc::v1::PROTOCOL_VERSION;

use super::{
    super::{
        InterceptionBrokerClient, RuntimeInterceptionBroker, RuntimeInterceptionBrokerError,
        RuntimeInterceptionEndpoint, SessionInterceptionRouter,
    },
    fixtures::BrokerFixture,
};

#[test]
fn broker_accepts_guard_hello_with_interception_token() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = BrokerFixture::new("accepts-hello");
    let broker = fixture.register(SessionInterceptionRouter::new())?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        assert_eq!(
            fs::metadata(broker.endpoint().directory())?
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        assert_eq!(
            fs::metadata(broker.endpoint().path())?.permissions().mode() & 0o777,
            0o600
        );
    }

    let ack = InterceptionBrokerClient::send_hello(broker.endpoint(), fixture.hello())?;

    assert!(ack.accepted);
    assert_eq!(ack.protocol_version, PROTOCOL_VERSION);
    assert!(ack.broker_id.contains(fixture.session_id()));

    Ok(())
}

#[test]
fn broker_rejects_guard_hello_with_bad_interception_token() -> Result<(), Box<dyn std::error::Error>>
{
    let fixture = BrokerFixture::new("rejects-token");
    let broker = fixture.register(SessionInterceptionRouter::new())?;
    let bad_endpoint = broker.endpoint().with_path(broker.endpoint().path());
    let bad_endpoint = RuntimeInterceptionEndpoint::unix(bad_endpoint.path(), "wrong-token", 25);

    let ack = InterceptionBrokerClient::send_hello(&bad_endpoint, fixture.hello())?;

    assert!(!ack.accepted);
    assert_eq!(ack.reason, "invalid interception token");

    Ok(())
}

#[test]
fn broker_accepts_multiple_sessions_on_one_server() -> Result<(), Box<dyn std::error::Error>> {
    let first_fixture = BrokerFixture::new("first");
    let second_fixture = BrokerFixture::new("second");
    let first = first_fixture.register(SessionInterceptionRouter::new())?;
    let second = RuntimeInterceptionBroker::register_session(
        second_fixture.session_id(),
        "codex",
        SessionInterceptionRouter::new(),
    )?;

    assert_eq!(first.endpoint().path(), second.endpoint().path());
    assert_ne!(first.endpoint().token(), second.endpoint().token());

    let first_ack = InterceptionBrokerClient::send_hello(first.endpoint(), first_fixture.hello())?;
    let second_ack =
        InterceptionBrokerClient::send_hello(second.endpoint(), second_fixture.hello())?;
    let crossed_endpoint =
        RuntimeInterceptionEndpoint::unix(first.endpoint().path(), second.endpoint().token(), 25);
    let crossed_ack =
        InterceptionBrokerClient::send_hello(&crossed_endpoint, first_fixture.hello())?;

    assert!(first_ack.accepted);
    assert!(second_ack.accepted);
    assert!(!crossed_ack.accepted);
    assert_eq!(crossed_ack.reason, "invalid interception token");
    Ok(())
}

#[test]
fn broker_unregisters_session_when_registration_drops() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = BrokerFixture::new("drop-unregisters");
    let broker = fixture.register(SessionInterceptionRouter::new())?;
    let endpoint = broker.endpoint().clone();
    drop(broker);

    let ack = InterceptionBrokerClient::send_hello(&endpoint, fixture.hello())?;

    assert!(!ack.accepted);
    assert_eq!(ack.reason, "unknown session");
    Ok(())
}

#[test]
fn broker_rejects_duplicate_session_registration() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = BrokerFixture::new("duplicate");
    let _broker = fixture.register(SessionInterceptionRouter::new())?;
    let error = match RuntimeInterceptionBroker::register_session(
        fixture.session_id(),
        "codex",
        SessionInterceptionRouter::new(),
    ) {
        Ok(_registration) => return Err("duplicate session id should be rejected".into()),
        Err(error) => error,
    };

    assert!(matches!(
        error,
        RuntimeInterceptionBrokerError::SessionAlreadyRegistered { .. }
    ));
    Ok(())
}
