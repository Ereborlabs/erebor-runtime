use super::*;
use crate::control_fixture::{free_address, oidc::OidcFixture, ControlServerFixture, MtlsFixture};
use erebor_runtime_client::{AraphorClient, AraphorProfile};
use erebor_runtime_ipc::araphor::{self as proto, query_frame::Payload, query_value::Kind};
use mithril_control::{ClientGrpcConfig, ClientListener, ClientListenerConfig, ControlPlane};
use std::io::Write as _;

impl ObservabilityQualification {
    pub(crate) fn trace_inputs(
        fact: mithril_control::WorkloadTargetFactV1,
        now: u64,
    ) -> ProofResult<(
        mithril_control::TraceRequestV1,
        mithril_control::TraceAccessV1,
    )> {
        use mithril_control::{
            DiscoveryDigestV1, TraceAccessV1, TraceRecipeV1, TraceRequestV1, TraceTargetV1,
        };

        let tenant = *uuid::Uuid::parse_str(crate::control_fixture::OUTAGE_TENANT_ID)?.as_bytes();
        let target = TraceTargetV1 {
            fact_digest: DiscoveryDigestV1::of(&fact)?,
            fact,
            runtime_container_id: "1".repeat(64),
            node_boot_id: [7; 16],
            cgroup_id: 17,
            binding_id: [3; 16],
            binding_nonce: [4; 16],
            root_cgroup_live_interval_id: [5; 16],
            container_generation: 1,
            label_epoch: 1,
        };
        let grant = TraceAccessV1 {
            tenant_id: tenant,
            principal: "qualification".into(),
            valid_until_unix_ns: now
                .checked_add(120_000_000_000)
                .ok_or("fixture grant overflows")?,
            revoked: false,
        };
        let request = TraceRequestV1 {
            selection: None,
            finding_reference: None,
            tenant_id: tenant,
            request_id: [6; 16],
            source: TraceRecipeV1::FailedOpens.manifest()?.source,
            targets: vec![target],
            unresolved: Vec::new(),
            collection_seconds: 30,
        };
        Ok((request, grant))
    }

    pub fn query_upload(&self) -> ProofResult<()> {
        use crate::control_fixture::OutagePolicyFixture;

        fs::create_dir(&self.output)?;
        let fixture = OutagePolicyFixture::new(mithril_control::ControlStore::open(
            self.output.join("inventory"),
        )?);
        let fact = fixture
            .inventory(&fixture.resource(1)?)?
            .into_iter()
            .next()
            .ok_or("missing query case workload fact")?;
        drop(fixture);
        let now = u64::try_from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_nanos(),
        )?;
        let (request, grant) = Self::trace_inputs(fact, now)?;
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        let key = ed25519_dalek::SigningKey::from_bytes(&[23; 32]);
        let mut record = runtime.block_on(self.owned_node(&key, request, grant, true))?;
        record["schema_version"] = serde_json::json!(1);
        record["case"] = serde_json::json!("query-upload");
        record["discovery_enabled"] = serde_json::json!(false);
        record["proof_boundary"] = serde_json::json!(
            "The production TLS Query RPC authenticates a service credential through an external HTTPS OIDC provider. QueryOwner runs admitted SQL in process through its asynchronous API. A catalog conversion query returns EvaluationFailed and gRPC INTERNAL. A valid query then completes on the same client service. Production Node capture emits a new frame after the query error. Control commits that frame before its mTLS ACK. Cancellation, Node spool reopen, Control reopen, retained output and ACK replay use production owners. The backend and binding inputs are external fixtures. This case does not prove native interruption, process-crash isolation, BPF cleanup, enforcement or performance."
        );
        self.write("result.json", &record)
    }

    pub(super) async fn fail_query(
        control: ControlPlane,
        tls: &MtlsFixture,
        tenant: [u8; 16],
    ) -> ProofResult<serde_json::Value> {
        let provider = OidcFixture::start(&tls.files, "query-qualification").await?;
        let address = free_address()?;
        let origin = format!("https://localhost:{}", address.port());
        let config = ClientListenerConfig {
            listen: address,
            tls_certificate_path: tls.files.server_certificate.clone(),
            tls_private_key_path: tls.files.server_key.clone(),
            auth: provider.auth(&origin, Some(tenant), tls.files.ca.clone()),
            administrative: None,
            investigation: Some(ClientGrpcConfig::default()),
            assets: None,
        };
        let listener = ClientListener::load(config, control).await?;
        let server = ControlServerFixture::client(listener, address).await?;
        let mut credential = tempfile::NamedTempFile::new_in(tls.path())?;
        credential.write_all(b"fixture-access")?;
        let result = async {
            let client = AraphorClient::connect(AraphorProfile {
                endpoint: origin,
                tenant_id: uuid::Uuid::from_bytes(tenant).to_string(),
                credential_file: credential.path().to_path_buf(),
                ca_file: Some(tls.files.ca.clone()),
            })
            .await?;
            Self::query_failure(&client).await
        }
        .await;
        let server_stop = server.shutdown().await;
        let provider_stop = provider.shutdown().await;
        let record = result?;
        server_stop?;
        provider_stop?;
        Ok(record)
    }

    pub(crate) async fn query_failure(client: &AraphorClient) -> ProofResult<serde_json::Value> {
        tokio::time::timeout(Duration::from_secs(10), async {
            let mut failed = client
                .query(proto::QueryRequest {
                    sql: "SELECT CAST(relation AS BIGINT) AS value FROM catalog LIMIT 1".into(),
                    ..Default::default()
                })
                .await?;
            let failure = failed.message().await?.ok_or("query has no error frame")?;
            let Some(Payload::Error(error)) = &failure.payload else {
                return Err("conversion query did not return an error frame".into());
            };
            if failure.schema_version != 1
                || failure.store_uuid.len() != 16
                || failure.recovery_epoch == 0
                || error.code != "EvaluationFailed"
                || !error.last_checkpoint.is_empty()
            {
                return Err("conversion query returned an unexpected error envelope".into());
            }
            match failed.message().await {
                Err(status) if status.code() == tonic::Code::Internal => {}
                _ => return Err("conversion query has no gRPC INTERNAL status".into()),
            }
            let mut recovered = client
                .query(proto::QueryRequest {
                    sql: "SELECT relation FROM catalog LIMIT 1".into(),
                    ..Default::default()
                })
                .await?;
            let metadata = recovered.message().await?.ok_or("query has no metadata")?;
            let rows = recovered.message().await?.ok_or("query has no rows")?;
            let checkpoint = recovered.message().await?.ok_or("query has no checkpoint")?;
            let terminal = recovered.message().await?.ok_or("query has no terminal")?;
            let (Some(Payload::Metadata(schema)), Some(Payload::Rows(data)),
                Some(Payload::Checkpoint(bookmark)), Some(Payload::Terminal(done))) =
                (&metadata.payload, &rows.payload, &checkpoint.payload, &terminal.payload)
            else {
                return Err("the recovered query changed its frame order".into());
            };
            if [&metadata, &rows, &checkpoint, &terminal].into_iter().any(|frame| {
                frame.schema_version != 1 || frame.store_uuid != failure.store_uuid
                    || frame.recovery_epoch != failure.recovery_epoch
                    || frame.operation != proto::QueryOperation::Replace as i32
                    || frame.read_revision != metadata.read_revision
            }) || schema.columns.len() != 1 || schema.columns[0].name != "relation"
                || data.rows.len() != 1 || data.rows[0].values.len() != 1 || data.limited
                || !matches!(&data.rows[0].values[0].kind,
                    Some(Kind::Text(value)) if value.parse::<i64>().is_err())
                || bookmark.is_empty() || done.reason != "Completed"
                || done.last_checkpoint != *bookmark || recovered.message().await?.is_some()
            {
                return Err("the public query did not recover after the conversion error".into());
            }
            Ok(serde_json::json!({
                "execution": "in-process", "query_transport": "native-grpc-tls",
                "query_failure": error.code, "query_error": error.reason,
                "query_grpc_code": "Internal", "query_recovered": true, "catalog_rows": data.rows.len(),
                "native_interruption_proved": false, "process_isolation_proved": false,
            }))
        }).await?
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn observability_query_upload() -> ProofResult<()> {
        let directory = tempfile::tempdir()?;
        let owner = ObservabilityQualification::new(directory.path().join("query"));
        owner.query_upload()?;
        let record: serde_json::Value =
            serde_json::from_slice(&fs::read(owner.output.join("result.json"))?)?;
        assert_eq!(record["case"], "query-upload");
        assert_eq!(record["result"], "PASS");
        assert_eq!(record["physical"], false);
        assert_eq!(record["performance_claim"], false);
        assert_eq!(record["discovery_index_present"], false);
        assert_eq!(record["discovery_enabled"], false);
        let cases = record["cases"].as_array().ok_or("missing query case")?;
        assert_eq!(cases.len(), 1);
        let case = &cases[0];
        assert_eq!(case["initial_acknowledgement"]["last_sequence"], 2);
        assert!(case["initial_acknowledgement"]["terminal"].is_null());
        let failure = &case["query_failure"];
        for field in [
            "query_recovered",
            "capture_active",
            "prefix_unchanged",
            "writer_ready",
            "durable_receipt_advanced",
            "post_failure_acknowledged",
        ] {
            assert_eq!(failure[field], true, "{field}");
        }
        assert_eq!(failure["execution"], "in-process");
        assert_eq!(failure["query_transport"], "native-grpc-tls");
        assert_eq!(failure["query_failure"], "EvaluationFailed");
        assert_eq!(failure["query_grpc_code"], "Internal");
        assert_eq!(failure["catalog_rows"], 1);
        assert_eq!(failure["native_interruption_proved"], false);
        assert_eq!(failure["process_isolation_proved"], false);
        assert_eq!(failure["prefix_sequence"], 2);
        assert_eq!(failure["post_failure_sequence"], 3);
        assert_eq!(failure["post_failure_ack"], failure["post_failure_replay"]);
        assert!(failure["post_failure_revision"].as_u64() > failure["prefix_revision"].as_u64());
        assert!(
            failure["post_failure_output_bytes"].as_u64() > failure["prefix_output_bytes"].as_u64()
        );
        assert_eq!(case["launch_count"], 1);
        assert_eq!(case["process_reaped"], true);
        assert_eq!(case["terminal_reopen"], true);
        assert_eq!(case["control_reopen"], true);
        assert_eq!(case["acknowledgement"], case["replay_ack"]);
        assert_eq!(case["acknowledgement"]["last_sequence"], 3);
        assert_eq!(case["acknowledgement"]["terminal"]["reason"], "Cancelled");
        assert_eq!(case["acknowledgement"]["terminal"]["cleanup"], "Unknown");
        assert_eq!(
            case["acknowledgement"]["terminal"]["output_incomplete"],
            true
        );
        assert!(case["acknowledgement"]["terminal"]["kernel_lost_events"].is_null());
        assert_eq!(
            case["retained"][0]["frames"].as_array().map(Vec::len),
            Some(3)
        );
        assert_eq!(
            case["retained"][0]["frames"][2]["bytes"],
            serde_json::json!(b"output after query error\n")
        );
        Ok(())
    }
}
