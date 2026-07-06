use super::{
    super::{InterceptionBrokerClient, RuntimeInterceptionEndpoint},
    fixtures::{BrokerFixture, TempDirectoryFixture},
};

#[test]
fn client_fails_closed_when_broker_is_unavailable() -> Result<(), Box<dyn std::error::Error>> {
    let directory = TempDirectoryFixture::new("unavailable")?;
    let broker = BrokerFixture::new("missing-session");
    let endpoint =
        RuntimeInterceptionEndpoint::unix(directory.path().join("missing.sock"), "token", 25);

    let error = InterceptionBrokerClient::send_hello(&endpoint, broker.hello());

    assert!(error.is_err());
    Ok(())
}
