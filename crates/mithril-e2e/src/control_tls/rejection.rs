use super::*;

#[tokio::test]
async fn mtls_rejects_wrong_node() -> Result<(), Box<dyn StdError>> {
    let fixture = MtlsFixture::new(false)?;
    let control = fixture.control(1)?;
    let server = fixture.start(control.clone()).await?;
    let connector = fixture.connector(&server, "node-b", [7; 16]);
    let mut trust = TrustCache::load(fixture.path())?;

    let error = connector
        .connect(registration(), true, &mut trust)
        .await
        .err()
        .ok_or("Control accepted a mismatched Node ID")?;
    assert!(
        error
            .to_string()
            .contains("node identity does not match its mTLS certificate"),
        "{error}"
    );
    assert_eq!(control.registered_nonce_count(), 0);
    server.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn mtls_rejects_expired_cert() -> Result<(), Box<dyn StdError>> {
    let fixture = MtlsFixture::new(true)?;
    let control = fixture.control(1)?;
    let server = fixture.start(control.clone()).await?;
    let connector = fixture.connector(&server, "node-a", [7; 16]);
    let mut trust = TrustCache::load(fixture.path())?;

    assert!(connector
        .connect(registration(), true, &mut trust)
        .await
        .is_err());
    assert_eq!(control.registered_nonce_count(), 0);
    server.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn mtls_rejects_wrong_ca() -> Result<(), Box<dyn StdError>> {
    let fixture = MtlsFixture::new(false)?;
    let wrong_dir = fixture.path().join("wrong-ca");
    fs::create_dir(&wrong_dir)?;
    let wrong_ca = Certificates::issue(false)?.write(&wrong_dir)?;
    let control = fixture.control(1)?;
    let server = fixture.start(control.clone()).await?;
    let mut config = fixture.node_config(server.address());
    config.ca_path = wrong_ca.ca;
    let connector = NodeControlConnector::new(config, "node-a".to_owned(), [7; 16]);
    let mut trust = TrustCache::load(fixture.path())?;

    assert!(connector
        .connect(registration(), true, &mut trust)
        .await
        .is_err());
    assert_eq!(control.registered_nonce_count(), 0);
    server.shutdown().await?;
    Ok(())
}
