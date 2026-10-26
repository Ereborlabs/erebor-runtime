use mithril_control::EvidenceIdV1;
use mithril_node::{ControlConnection, TrustCache};
use zerocopy::IntoBytes as _;

use super::super::super::*;
use super::super::input::{configuration, now, upload_on, wal};
use super::{input, Incident};
use crate::control_fixture::OutagePolicyFixture;
use crate::discovery::roundtrip::signed_catalog;

#[tokio::test]
async fn follows_cpu_streams() -> Result<()> {
    let tls = MtlsFixture::new(false)?;
    let oidc = OidcFixture::start(&tls.files, "paired-operator").await?;
    let outcome: Result<()> = async {
        let (mut config, _, authority) = configuration(&tls, &oidc).await?;
        config.data_retention.raw_max_age_ns = None;
        let auth = config.client.as_ref().ok_or("paired auth")?.auth.clone();
        let at = i64::try_from(now()?)?;
        input::policy_config(&mut config, tls.path())?;
        let fixture = Fixture::configured(config, authority)?;
        let (fixture, server) = fixture.listening(&tls).await?;
        let tested: Result<()> = async {
            let owner = fixture
                .control
                .policy_desired_state()
                .ok_or("configured policy owner")?;
            let prepared = signed_catalog(owner, tls.path(), [7; 16].into(), at, None)?;
            assert!(fixture
                .control
                .replace_kubernetes_workload_inventory(vec![prepared.workload])?);
            let credential = tls.path().join("paired-token");
            fs::write(&credential, b"fixture-access")?;
            let tenant = EvidenceIdV1::new(1, 2).to_be_bytes();
            let (client, query) = fixture.client(&tls, &auth, &credential, tenant).await?;
            let tested: Result<()> = async {
                let mut trust = TrustCache::load(&tls.path().join("paired-trust"))?;
                let registration = OutagePolicyFixture::registration([7; 16], false);
                let mut node: ControlConnection = tls
                    .connector(&server, "node-a", [7; 16])
                    .connect(registration, false, &mut trust)
                    .await?;
                node.report_readiness(true, true).await?;
                fixture.control.bind_kubernetes_node_session(
                    "worker-a",
                    "dddddddd-dddd-4ddd-8ddd-dddddddddddd",
                )?;
                let delivered = input::fetch_policy(&mut node, &prepared.bundle).await?;
                let ack = OutagePolicyFixture::active_acknowledgement(&delivered, 8, at);
                assert_eq!(node.acknowledge_policy(ack).await?.rollout_state, "ACTIVE");
                input::background(&tls, &mut node).await?;
                let observed = Incident::subscribe(&client, 7, 0).await?;
                let catalog = Arc::new(prepared.catalog);
                let mut uploaded = Vec::new();
                for (name, event) in ["paired-denied", "paired-allowed"]
                    .into_iter()
                    .zip(input::events(prepared.raw))
                {
                    let input = wal(&tls, name, 3)?;
                    input.set_discovery_context(Some(catalog.clone()));
                    input.record_bytes(event.as_bytes());
                    uploaded.push(upload_on(&tls, &mut node, &input).await?);
                }
                assert_ne!(uploaded[0].0.source_id, uploaded[1].0.source_id);
                let observed = observed.wait(&client).await?;
                assert!(observed.partial_pages > 0);
                for (record, (source, bytes)) in observed.records.iter().zip(uploaded) {
                    assert_eq!(record.id.stream, source);
                    assert_eq!(record.wire_record, bytes);
                }
                let identity = observed.identity(&client).await?;
                let mut report = serde_json::to_value(&observed)?;
                report["identity"] = serde_json::to_value(identity)?;
                println!("INCIDENT_LIGHTWEIGHT={}", serde_json::to_string(&report)?);
                Ok(())
            }
            .await;
            drop(client);
            query.shutdown().await?;
            tested
        }
        .await;
        let network = server.shutdown().await;
        let stopped = fixture.shutdown().await;
        network?;
        stopped?;
        tested
    }
    .await;
    oidc.shutdown().await?;
    outcome
}
