use std::{
    sync::{Mutex, PoisonError},
    time::Duration,
};

use super::super::super::*;
use super::Incident;
use araphor_data::{DiscoveryRecordIdV1, DiscoveryRecordV1, ManagedGraphOperation};

#[tokio::test]
async fn progress_reads_independently() -> Result<()> {
    let tls = MtlsFixture::new(false)?;
    let oidc = OidcFixture::start(&tls.files, "progress-operator").await?;
    let mut auth = oidc.auth(
        "https://localhost:44444",
        Some([1; 16]),
        tls.files.ca.clone(),
    );
    auth.package_managers = auth.investigators.clone();
    let outcome: Result<()> = async {
        let mut config = lifecycle::configuration(&tls, &auth)?;
        config.graph_enabled = true;
        let fixture = Fixture::configured(config, Arc::new(ClientAuth::load(&auth).await?))?;
        let credential = tls.path().join("progress-token");
        fs::write(&credential, b"fixture-access")?;
        let (fixture, client, server) = fixture.connected(&tls, &auth, &credential).await?;
        let tested: Result<()> = async {
            let mut incident = Incident::subscribe(&client, 7, 0).await?;
            let mut source = tls.identity([3; 16]);
            source.tenant_id = [1; 16];
            // Only record IDs enter the diagnostic requests.
            for cursor in [1, 2] {
                let id = DiscoveryRecordIdV1 {
                    stream: source.clone(),
                    cpu_id: 1,
                    durable_cursor: cursor,
                };
                incident.records.insert(
                    id.clone(),
                    DiscoveryRecordV1 {
                        id,
                        original_kernel_sequence: None,
                        wire_record: Vec::new(),
                    },
                );
            }
            let output = Mutex::new(Vec::new());
            tokio::time::timeout(Duration::from_secs(5), incident.progress(&client, &output))
                .await?;
            let output = output.into_inner().unwrap_or_else(PoisonError::into_inner);
            let source_value = serde_json::to_value(&source)?;
            let missing = format!("Araphor RPC failed with {}", tonic::Code::NotFound);
            assert!(output.iter().all(|row| row["source"] == source_value));
            let started = output.iter().filter(|row| row["started"] == true).count();
            assert_eq!(started, 5);
            for operation in [
                ManagedGraphOperation::Evaluate,
                ManagedGraphOperation::Expire,
            ] {
                let id = operation.instance_id(&source);
                for read in ["InspectInstance", "InspectInstanceHistory"] {
                    let rows = output
                        .iter()
                        .filter(|row| row["instance"] == id && row["read"] == read)
                        .collect::<Vec<_>>();
                    assert_eq!(rows.len(), 2);
                    assert!(rows.iter().any(|row| row["started"] == true));
                    let result = rows
                        .iter()
                        .find_map(|row| row.get("result"))
                        .ok_or("inspect result")?;
                    let error = result["error"]
                        .as_str()
                        .ok_or("expected missing instance")?;
                    assert!(error.contains(&missing), "{error}");
                }
            }
            let empty = output
                .iter()
                .any(|row| row["frame"]["rows"] == serde_json::json!([]));
            let complete = output
                .iter()
                .any(|row| row["frame"]["terminal"] == "Completed");
            assert!(empty, "{output:?}");
            assert!(complete, "{output:?}");
            Ok(())
        }
        .await;
        drop(client);
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
