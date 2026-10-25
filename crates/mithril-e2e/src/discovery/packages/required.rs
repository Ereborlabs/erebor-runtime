use araphor_data::EvidenceRetentionOwner;
use zerocopy::IntoBytes as _;

use super::*;

mod input;
mod observed;

use input::{event, now, upload, wal};
use observed::{store, Saved};

#[tokio::test]
async fn required_detector_recovers() -> Result<()> {
    let tls = MtlsFixture::new(false)?;
    let oidc = OidcFixture::start(&tls.files, "required-operator").await?;
    let outcome: Result<()> = async {
        let (mut config, grant, authority) = input::configuration(&tls, &oidc).await?;
        let first = wal(&tls, "required-first", 3)?;
        let pending = wal(&tls, "required-pending", 4)?;
        let fixture = Fixture::configured(config.clone(), authority.clone())?;
        let (fixture, server) = fixture.listening(&tls).await?;
        let captured: Result<_> = async {
            assert!(!store(&fixture)?.discovery_enabled());
            first.record_bytes(event(1, true).as_bytes());
            first.record_bytes(event(2, false).as_bytes());
            let (source, _) = upload(&tls, &server, &first).await?;
            Saved::initial(&fixture, source, &grant).await
        }
        .await;
        let network = server.shutdown().await;
        let stopped = fixture.shutdown().await;
        network?;
        stopped?;
        let saved = captured?;
        let mut capped = config.clone();
        capped
            .client
            .as_mut()
            .and_then(|client| client.investigation.as_mut())
            .ok_or("required query configuration")?
            .query
            .package
            .wasm
            .fuel = Some(1);
        let fixture = Fixture::configured(capped, authority.clone())?;
        let (fixture, server) = fixture.listening(&tls).await?;
        let failed: Result<_> = async {
            pending.record_bytes(event(1, true).as_bytes());
            pending.record_bytes(event(2, false).as_bytes());
            let (blocked, frames) = upload(&tls, &server, &pending).await?;
            assert_ne!(saved.source.source_id, blocked.source_id);
            saved.failed(&fixture, &blocked).await?;
            let data = store(&fixture)?;
            let retention = EvidenceRetentionOwner::new(&data);
            assert!(retention.enabled());
            retention.step(now()?)?;
            saved.retained(&fixture, &blocked, &frames, &grant)?;
            Ok((blocked, frames))
        }
        .await;
        let network = server.shutdown().await;
        let stopped = fixture.shutdown().await;
        network?;
        stopped?;
        let (blocked, frames) = failed?;
        config.data_retention.raw_max_age_ns = None;
        let fixture = Fixture::configured(config, authority)?;
        let (fixture, server) = fixture.listening(&tls).await?;
        let recovered: Result<()> = async {
            pending.record_bytes(event(3, false).as_bytes());
            let (current, _) = upload(&tls, &server, &pending).await?;
            assert_eq!(current, blocked);
            saved.recovered(&fixture, &blocked, &frames, &grant).await
        }
        .await;
        let network = server.shutdown().await;
        let stopped = fixture.shutdown().await;
        network?;
        stopped?;
        recovered
    }
    .await;
    oidc.shutdown().await?;
    outcome
}
