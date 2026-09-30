use std::error::Error as StdError;

use mithril_control::TrustGenerationV1;
use mithril_node::TrustCache;

use super::registration;
use crate::control_fixture::MtlsFixture;

#[tokio::test]
async fn registration_renews_nonce() -> Result<(), Box<dyn StdError>> {
    let fixture = MtlsFixture::new(false)?;
    let control = fixture.control(4)?;
    let server = fixture.start(control.clone()).await?;
    let connector = fixture.connector(&server, "node-a", [7; 16]);
    let mut trust = TrustCache::load(fixture.path())?;

    let first = connector.connect(registration(), true, &mut trust).await?;
    assert_eq!(trust.installed().generation, 4);
    let nonce = trust.installed().control_connection_nonce.clone();
    drop(first);
    let second = connector.connect(registration(), true, &mut trust).await?;
    assert_ne!(trust.installed().control_connection_nonce, nonce);

    assert_eq!(control.registered_nonce_count(), 2);
    assert_eq!(
        control.acknowledged_trust("node-a"),
        Some(TrustGenerationV1 {
            generation: 4,
            bundle_digest: "d".repeat(64),
            policy_issuer_sequence_epoch: 0,
            policy_signers: Vec::new(),
        })
    );

    drop(second);
    server.shutdown().await?;
    Ok(())
}
