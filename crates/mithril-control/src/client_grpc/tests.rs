use std::time::Duration;

use araphor_data::EvidenceRetentionOwner;
use araphor_observability::test_support;
use ed25519_dalek::SigningKey;
use futures_util::StreamExt as _;
use tempfile::TempDir;

use super::proto::araphor_client_service_server::AraphorClientService as _;
use super::*;
use crate::{
    ClientSession, ControlStore, PolicySignerTrustV1, TraceAcceptedV1, TraceAccessV1, TraceBatchV1,
    TraceCleanupV1, TraceFrameKindV1, TraceFrameV1, TraceOwner, TraceSelectionV1,
    TraceTerminalReasonV1, TraceTerminalV1, TrustGenerationV1,
};

type TestResult<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
const WAIT: Duration = Duration::from_secs(5);

struct Fixture {
    service: ClientGrpcOwner,
    session: ClientSession,
    _directory: TempDir,
}

impl Fixture {
    fn new() -> TestResult<Self> {
        Self::with_limits(QueryLimits::default())
    }

    fn with_limits(limits: QueryLimits) -> TestResult<Self> {
        let directory = TempDir::new()?;
        let key = SigningKey::from_bytes(&[23; 32]);
        let trust = TrustGenerationV1 {
            generation: 1,
            bundle_digest: String::new(),
            policy_issuer_sequence_epoch: 1,
            policy_signers: vec![PolicySignerTrustV1 {
                signing_key_id: "trace-key".into(),
                ed25519_public_key_hex: hex::encode(key.verifying_key().as_bytes()),
                revoked: false,
            }],
        }
        .with_computed_bundle_digest();
        let control = ControlPlane::with_control_store(
            Vec::new(),
            trust,
            ControlStore::open(directory.path().join("control"))?,
        )?
        .with_trace_signer("trace-key".into(), 1, key)?;
        let auth = crate::client_auth::tests::owner()?;
        let session = crate::client_auth::tests::session(&auth)?;
        let service = ClientGrpcOwner::new(control, auth, ClientGrpcConfig { query: limits })?;
        Ok(Self {
            service,
            session,
            _directory: directory,
        })
    }

    fn request<T>(&self, value: T, mutation: bool) -> TestResult<Request<T>> {
        let mut request = Request::new(value);
        let metadata = request.metadata_mut();
        metadata.insert(
            "x-araphor-tenant",
            uuid::Uuid::from_bytes([1; 16]).to_string().parse()?,
        );
        metadata.insert("origin", "https://control.example".parse()?);
        metadata.insert(
            "cookie",
            format!("araphor-session={}", self.session.token).parse()?,
        );
        if mutation {
            metadata.insert("x-araphor-csrf", self.session.csrf.parse()?);
        }
        Ok(request)
    }

    fn access(&self, tenant: [u8; 16]) -> TraceAccessV1 {
        TraceAccessV1 {
            tenant_id: tenant,
            principal: "alice".into(),
            valid_until_unix_ns: self.session.expires_ns,
            revoked: false,
        }
    }

    fn seed(&self, tenant: [u8; 16], id: u8) -> TestResult<TraceAcceptedV1> {
        let mut request = test_support::request()?;
        request.tenant_id = tenant;
        request.request_id = [id; 16];
        request.selection = Some(TraceSelectionV1 {
            target: "pod-uid/pod".into(),
            cluster: "cluster".into(),
            container: "worker".into(),
        });
        let owner = TraceOwner::new(self.service.data()?.store.clone());
        let access = self.access(tenant);
        owner.accept(request, access.clone(), ClientGrpcOwner::now()?)?;
        let (_, accepted) = owner.read(tenant, [id; 16], &access, ClientGrpcOwner::now()?)?;
        Ok(accepted)
    }

    fn submit(accepted: &TraceAcceptedV1) -> TestResult<proto::SubmitTraceRequest> {
        let selection = accepted
            .request
            .selection
            .as_ref()
            .ok_or("selection is absent")?;
        Ok(proto::SubmitTraceRequest {
            idempotency_key: accepted.request.request_id.to_vec(),
            selection: Some(proto::InputSelection {
                target: selection.target.clone(),
                cluster: selection.cluster.clone(),
                container: selection.container.clone(),
                node_ids: Vec::new(),
            }),
            source: Some(proto::submit_trace_request::Source::Script(
                accepted.request.source.bytes.clone(),
            )),
            collection_seconds: u32::from(accepted.request.collection_seconds),
            finding_reference: String::new(),
        })
    }

    fn record(&self, accepted: &TraceAcceptedV1) -> TestResult<()> {
        let identity = accepted.binding(0)?.identity;
        TraceOwner::new(self.service.data()?.store.clone()).append(
            identity.tenant_id,
            identity.request_id,
            0,
            &identity.node_id,
            identity.node_boot_id,
            TraceBatchV1 {
                execution_id: identity.execution_id,
                frames: vec![TraceFrameV1 {
                    execution_id: identity.execution_id,
                    sequence: 1,
                    kind: TraceFrameKindV1::Data,
                    bytes: b"hello".to_vec(),
                }],
                terminal: None,
            },
        )?;
        Ok(())
    }

    fn finish(&self, accepted: &TraceAcceptedV1) -> TestResult<()> {
        let identity = accepted.binding(0)?.identity;
        TraceOwner::new(self.service.data()?.store.clone()).append(
            identity.tenant_id,
            identity.request_id,
            0,
            &identity.node_id,
            identity.node_boot_id,
            TraceBatchV1 {
                execution_id: identity.execution_id,
                frames: Vec::new(),
                terminal: Some(TraceTerminalV1 {
                    execution_id: identity.execution_id,
                    reason: TraceTerminalReasonV1::Completed,
                    last_sequence: 1,
                    output_bytes: 5,
                    output_incomplete: false,
                    kernel_lost_events: Some(0),
                    ready_at_unix_ns: Some(accepted.accepted_unix_ns),
                    exit_code: Some(0),
                    forced_kill: false,
                    cleanup: TraceCleanupV1::Verified,
                }),
            },
        )?;
        Ok(())
    }

    async fn next<T>(
        stream: &mut (impl futures_util::Stream<Item = Result<T, Status>> + Unpin),
    ) -> TestResult<T> {
        tokio::time::timeout(WAIT, stream.next())
            .await?
            .ok_or("the RPC stream ended")?
            .map_err(Into::into)
    }
}

#[tokio::test]
async fn observability_grpc_output_deadline() -> TestResult {
    use std::sync::atomic::{AtomicUsize, Ordering};

    let fixture = Fixture::with_limits(QueryLimits {
        output_timeout: Duration::from_nanos(1),
        ..QueryLimits::default()
    })?;
    let retained = Arc::new(());
    let released = Arc::downgrade(&retained);
    let calls = Arc::new(AtomicUsize::new(0));
    let polled = calls.clone();
    let inner = futures_util::stream::unfold(retained, move |retained| {
        let calls = polled.clone();
        async move {
            calls.fetch_add(1, Ordering::SeqCst);
            Some((Ok::<_, Status>(7_u8), retained))
        }
    });
    let mut stream = fixture.service.output_stream(inner)?;
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert!(released.upgrade().is_some());
    assert_eq!(Fixture::next(&mut stream).await?, 7);
    tokio::time::sleep(Duration::from_millis(1)).await;
    let error = stream.next().await.ok_or("output timeout absent")?;
    assert_eq!(
        error.err().map(|error| error.code()),
        Some(tonic::Code::DeadlineExceeded)
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert!(released.upgrade().is_none());
    assert!(stream.next().await.is_none());
    assert!(stream.next().await.is_none());
    Ok(())
}

#[tokio::test]
async fn observability_grpc_output_wait() -> TestResult {
    let fixture = Fixture::with_limits(QueryLimits {
        output_timeout: Duration::from_millis(100),
        ..QueryLimits::default()
    })?;
    let inner = futures_util::stream::once(async { Ok::<_, Status>(1_u8) }).chain(
        futures_util::stream::once(async {
            tokio::time::sleep(Duration::from_millis(150)).await;
            Ok::<_, Status>(2_u8)
        }),
    );
    let mut stream = fixture.service.output_stream(inner)?;
    assert_eq!(Fixture::next(&mut stream).await?, 1);
    assert_eq!(Fixture::next(&mut stream).await?, 2);
    assert!(stream.next().await.is_none());
    Ok(())
}

#[tokio::test]
async fn observability_grpc_trace_timeout() -> TestResult {
    let fixture = Fixture::with_limits(QueryLimits {
        output_timeout: Duration::from_nanos(1),
        ..QueryLimits::default()
    })?;
    let accepted = fixture.seed([1; 16], 6)?;
    let owner = TraceOwner::new(fixture.service.data()?.store.clone());
    let before = owner.read(
        [1; 16],
        [6; 16],
        &fixture.access([1; 16]),
        ClientGrpcOwner::now()?,
    )?;
    let mut stream = fixture
        .service
        .watch_trace(fixture.request(
            proto::WatchTraceRequest {
                trace_id: vec![6; 16],
                bookmark: Vec::new(),
            },
            false,
        )?)
        .await?
        .into_inner();
    assert!(matches!(
        Fixture::next(&mut stream).await?.payload,
        Some(proto::trace_frame::Payload::Metadata(_))
    ));
    tokio::time::sleep(Duration::from_millis(1)).await;
    let error = stream.next().await.ok_or("trace output timeout absent")?;
    assert_eq!(
        error.err().map(|error| error.code()),
        Some(tonic::Code::DeadlineExceeded)
    );
    assert!(stream.next().await.is_none());
    assert_eq!(
        owner.read(
            [1; 16],
            [6; 16],
            &fixture.access([1; 16]),
            ClientGrpcOwner::now()?
        )?,
        before
    );
    fixture.record(&accepted)?;
    fixture.finish(&accepted)?;
    let receipt = fixture
        .service
        .data()?
        .store
        .trace_receipt(&accepted.binding(0)?.identity)?;
    assert!(receipt.is_some_and(|receipt| receipt.last_sequence == 1 && receipt.terminal.is_some()));
    Ok(())
}

#[tokio::test]
async fn observability_grpc_missing_data() -> TestResult {
    let directory = TempDir::new()?;
    let root = directory.path();
    let evidence = root.join("evidence");
    std::fs::create_dir_all(evidence.join("analysis"))?;
    let database = evidence.join("analysis/analysis.duckdb");
    std::fs::write(&database, b"invalid database")?;
    let policy = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../mithril-e2e/fixtures/mithril-policy")
        .canonicalize()?;
    let public = std::fs::read_to_string(policy.join("test-public-key.hex"))?;
    let trust = TrustGenerationV1 {
        generation: 1,
        bundle_digest: String::new(),
        policy_issuer_sequence_epoch: 1,
        policy_signers: vec![PolicySignerTrustV1 {
            signing_key_id: "effect-observation-test-key".into(),
            ed25519_public_key_hex: public.trim().into(),
            revoked: false,
        }],
    }
    .with_computed_bundle_digest();
    let tenant = uuid::Uuid::from_bytes([1; 16]).to_string();
    let source = serde_json::json!({
        "listen": "127.0.0.1:0",
        "tls": {
            "certificate_path": root.join("control.pem"),
            "private_key_path": root.join("control-key.pem"),
            "node_ca_path": root.join("node-ca.pem"),
        },
        "allowed_nodes": [{
            "node_id": "node-a", "certificate_sha256": "a".repeat(64),
            "tenant_id": tenant,
        }],
        "trust": trust,
        "evidence_directory": evidence,
        "control_store_directory": root.join("control"),
        "kubernetes_policy": {
            "tenant_id": tenant,
            "cluster_uid": "55555555-5555-4555-8555-555555555555",
            "signer": {
                "signing_key_id": "effect-observation-test-key",
                "signing_key_path": policy.join("test-signing-key.hex"),
                "seal_request_path": policy.join("observe-profile-seal-request.json"),
                "distribution_sequence_epoch": 1,
                "candidate_validity_ns": 60_000_000_000_u64,
            },
        },
        "client": {
            "listen": "127.0.0.1:0",
            "tls_certificate_path": root.join("client.pem"),
            "tls_private_key_path": root.join("client-key.pem"),
            "auth": {
                "origin": "https://control.example",
                "oidc": {
                    "issuer_url": "https://issuer.example", "client_id": "browser-client",
                },
                "investigators": [{"subject": "alice", "tenant_id": tenant}],
                "session_seconds": 60,
            },
            "investigation": {},
        },
    });
    let path = root.join("config.json");
    std::fs::write(&path, serde_json::to_vec(&source)?)?;
    let parts = crate::ControlConfig::load(&path)?.into_parts()?;
    assert!(parts.data_error.is_some());
    assert!(parts.control.analysis_store().is_none());
    let config = parts.client.ok_or("client configuration is absent")?;
    let control = parts.control;
    let health = control
        .policy_desired_state()
        .ok_or("policy owner is absent")?
        .health()?;
    let oidc = crate::client_auth::tests::owner()?.oidc();
    let auth = Arc::new(ClientAuth::new(config.auth.clone(), oidc)?);
    let session = crate::client_auth::tests::session(&auth)?;
    let service = ClientGrpcOwner::new(
        control.clone(),
        auth.clone(),
        config
            .investigation
            .clone()
            .ok_or("investigation is absent")?,
    )?;
    assert!(service.data.is_none());
    let listener = crate::ClientListener::new(config, auth, None, Some(service.clone()))?;
    let fixture = Fixture {
        service,
        session,
        _directory: directory,
    };
    let mut client =
        proto::araphor_client_service_client::AraphorClientServiceClient::new(listener.router());
    assert_eq!(
        client
            .query(proto::QueryRequest::default())
            .await
            .err()
            .map(|error| error.code()),
        Some(tonic::Code::Unauthenticated)
    );
    assert_eq!(
        client
            .query(fixture.request(proto::QueryRequest::default(), false)?)
            .await
            .err()
            .map(|error| error.code()),
        Some(tonic::Code::Unavailable)
    );
    assert_eq!(
        client
            .submit_trace(fixture.request(proto::SubmitTraceRequest::default(), false)?)
            .await
            .err()
            .map(|error| error.code()),
        Some(tonic::Code::Unauthenticated)
    );
    assert_eq!(
        client
            .submit_trace(fixture.request(proto::SubmitTraceRequest::default(), true)?)
            .await
            .err()
            .map(|error| error.code()),
        Some(tonic::Code::Unavailable)
    );
    assert_eq!(
        client
            .get_trace(fixture.request(proto::GetTraceRequest::default(), false)?)
            .await
            .err()
            .map(|error| error.code()),
        Some(tonic::Code::Unavailable)
    );
    assert_eq!(
        client
            .watch_trace(fixture.request(proto::WatchTraceRequest::default(), false)?)
            .await
            .err()
            .map(|error| error.code()),
        Some(tonic::Code::Unavailable)
    );
    assert_eq!(
        client
            .cancel_trace(fixture.request(proto::CancelTraceRequest::default(), true)?)
            .await
            .err()
            .map(|error| error.code()),
        Some(tonic::Code::Unavailable)
    );
    fixture.service.auth.replace_grants(Vec::new())?;
    assert_eq!(
        client
            .query(fixture.request(proto::QueryRequest::default(), false)?)
            .await
            .err()
            .map(|error| error.code()),
        Some(tonic::Code::PermissionDenied)
    );
    let policy = control
        .policy_desired_state()
        .ok_or("policy owner was lost")?;
    assert_eq!(policy.health()?, health);
    assert_eq!(
        policy.signer_identity(),
        ("effect-observation-test-key", public.trim().into(), 1)
    );
    assert!(policy
        .live_policies_in_namespace("tenant-namespace")?
        .is_empty());
    assert_eq!(control.allowed_nodes().len(), 1);
    assert_eq!(std::fs::read(database)?, b"invalid database");
    Ok(())
}

#[tokio::test]
async fn observability_grpc_result_revocation() -> TestResult {
    let fixture = Fixture::new()?;
    let accepted = fixture.seed([1; 16], 6)?;
    fixture.record(&accepted)?;
    fixture.finish(&accepted)?;
    let mut stream = fixture
        .service
        .watch_trace(fixture.request(
            proto::WatchTraceRequest {
                trace_id: vec![6; 16],
                bookmark: Vec::new(),
            },
            false,
        )?)
        .await?
        .into_inner();
    assert!(matches!(
        Fixture::next(&mut stream).await?.payload,
        Some(proto::trace_frame::Payload::Metadata(_))
    ));
    assert!(matches!(
        Fixture::next(&mut stream).await?.payload,
        Some(proto::trace_frame::Payload::Output(_))
    ));
    assert!(matches!(
        Fixture::next(&mut stream).await?.payload,
        Some(proto::trace_frame::Payload::Terminal(_))
    ));
    assert!(matches!(
        Fixture::next(&mut stream).await?.payload,
        Some(proto::trace_frame::Payload::Checkpoint(_))
    ));
    TraceOwner::new(fixture.service.data()?.store.clone()).cancel(
        [1; 16],
        [6; 16],
        &fixture.access([1; 16]),
        ClientGrpcOwner::now()?,
        true,
    )?;
    let status = tokio::time::timeout(WAIT, stream.next())
        .await?
        .ok_or("result revocation status is absent")?;
    assert_eq!(
        status.err().map(|error| error.code()),
        Some(tonic::Code::PermissionDenied)
    );
    assert!(tokio::time::timeout(WAIT, stream.next()).await?.is_none());
    Ok(())
}

#[tokio::test]
async fn observability_grpc_deadline_revocation() -> TestResult {
    let fixture = Fixture::new()?;
    let accepted = fixture.seed([1; 16], 6)?;
    fixture.record(&accepted)?;
    let request = fixture.request(
        proto::WatchTraceRequest {
            trace_id: vec![6; 16],
            bookmark: Vec::new(),
        },
        false,
    )?;
    let access = fixture.service.authenticate(&request, false).await?;
    let mut stream = fixture.service.watch(request.into_inner(), access).await?;
    assert!(matches!(
        Fixture::next(&mut stream).await?.payload,
        Some(proto::trace_frame::Payload::Metadata(_))
    ));
    assert!(matches!(
        Fixture::next(&mut stream).await?.payload,
        Some(proto::trace_frame::Payload::Output(_))
    ));
    assert!(matches!(
        Fixture::next(&mut stream).await?.payload,
        Some(proto::trace_frame::Payload::Checkpoint(_))
    ));
    TraceOwner::new(fixture.service.data()?.store.clone()).cancel(
        [1; 16],
        [6; 16],
        &fixture.access([1; 16]),
        ClientGrpcOwner::now()?,
        true,
    )?;
    stream.expire();
    let status = tokio::time::timeout(WAIT, stream.next())
        .await?
        .ok_or("deadline revocation status is absent")?;
    assert_eq!(
        status.err().map(|error| error.code()),
        Some(tonic::Code::PermissionDenied)
    );
    assert!(tokio::time::timeout(WAIT, stream.next()).await?.is_none());
    Ok(())
}

#[tokio::test]
async fn observability_grpc_duration_revocation() -> TestResult {
    let fixture = Fixture::new()?;
    let accepted = fixture.seed([1; 16], 6)?;
    fixture.record(&accepted)?;
    let request = fixture.request(
        proto::QueryRequest {
            sql: "SELECT * FROM trace_output".into(),
            follow: true,
            duration_ns: Some(60_000_000_000),
            ..Default::default()
        },
        false,
    )?;
    let access = fixture.service.authenticate(&request, false).await?;
    let mut stream = fixture
        .service
        .query_request(request.into_inner(), access)?;
    assert!(matches!(
        Fixture::next(&mut stream).await?.payload,
        Some(proto::query_frame::Payload::Metadata(_))
    ));
    assert!(matches!(
        Fixture::next(&mut stream).await?.payload,
        Some(proto::query_frame::Payload::Rows(_))
    ));
    assert!(matches!(
        Fixture::next(&mut stream).await?.payload,
        Some(proto::query_frame::Payload::Checkpoint(_))
    ));
    TraceOwner::new(fixture.service.data()?.store.clone()).cancel(
        [1; 16],
        [6; 16],
        &fixture.access([1; 16]),
        ClientGrpcOwner::now()?,
        true,
    )?;
    stream.expire().await;
    let status = tokio::time::timeout(WAIT, stream.next())
        .await?
        .ok_or("duration revocation status is absent")?;
    assert_eq!(
        status.err().map(|error| error.code()),
        Some(tonic::Code::PermissionDenied)
    );
    assert!(tokio::time::timeout(WAIT, stream.next()).await?.is_none());
    Ok(())
}

#[tokio::test]
async fn observability_grpc_duration_pending() -> TestResult {
    let fixture = Fixture::new()?;
    let accepted = fixture.seed([1; 16], 6)?;
    fixture.record(&accepted)?;
    let request = fixture.request(
        proto::QueryRequest {
            sql: "SELECT * FROM trace_output".into(),
            follow: true,
            duration_ns: Some(60_000_000_000),
            ..Default::default()
        },
        false,
    )?;
    let access = fixture.service.authenticate(&request, false).await?;
    let mut stream = fixture
        .service
        .query_request(request.into_inner(), access)?;
    assert!(matches!(
        Fixture::next(&mut stream).await?.payload,
        Some(proto::query_frame::Payload::Metadata(_))
    ));
    assert!(matches!(
        Fixture::next(&mut stream).await?.payload,
        Some(proto::query_frame::Payload::Rows(_))
    ));
    let checkpoint = Fixture::next(&mut stream).await?;
    let Some(proto::query_frame::Payload::Checkpoint(bookmark)) = checkpoint.payload else {
        return Err("the complete checkpoint is absent".into());
    };
    assert!(!bookmark.is_empty());
    fixture.finish(&accepted)?;
    let rows = Fixture::next(&mut stream).await?;
    assert!(rows.read_revision > checkpoint.read_revision);
    assert!(matches!(
        rows.payload,
        Some(proto::query_frame::Payload::Rows(value)) if value.rows.len() == 1
    ));
    stream.expire().await;
    let frame = Fixture::next(&mut stream).await?;
    assert_eq!(frame.read_revision, checkpoint.read_revision);
    assert!(matches!(
        frame.payload,
        Some(proto::query_frame::Payload::Error(error))
        if error.code == "DeadlineExceeded" && error.last_checkpoint == bookmark
    ));
    let status = tokio::time::timeout(WAIT, stream.next())
        .await?
        .ok_or("the duration failure status is absent")?;
    assert_eq!(
        status.err().map(|error| error.code()),
        Some(tonic::Code::DeadlineExceeded)
    );
    assert!(tokio::time::timeout(WAIT, stream.next()).await?.is_none());
    Ok(())
}

#[tokio::test]
async fn observability_grpc_tenant_count() -> TestResult {
    let fixture = Fixture::new()?;
    fixture.seed([1; 16], 6)?;
    fixture.seed([2; 16], 7)?;
    let mut stream = fixture
        .service
        .query(fixture.request(
            proto::QueryRequest {
                sql: "SELECT count(*) AS count FROM traces".into(),
                ..Default::default()
            },
            false,
        )?)
        .await?
        .into_inner();
    let metadata = Fixture::next(&mut stream).await?;
    assert_eq!(metadata.schema_version, 1);
    assert_eq!(metadata.store_uuid.len(), 16);
    assert!(metadata.read_revision > 0);
    assert!(matches!(
        metadata.payload,
        Some(proto::query_frame::Payload::Metadata(_))
    ));
    let frame = Fixture::next(&mut stream).await?;
    let Some(proto::query_frame::Payload::Rows(rows)) = frame.payload else {
        return Err("count rows are absent".into());
    };
    assert!(!rows.limited);
    assert!(rows.missing_contexts.is_empty());
    assert_eq!(rows.rows.len(), 1);
    assert_eq!(rows.rows[0].values.len(), 1);
    assert!(matches!(
        rows.rows[0].values[0].kind,
        Some(proto::query_value::Kind::Signed(1))
    ));
    let checkpoint = Fixture::next(&mut stream).await?;
    assert!(
        matches!(checkpoint.payload, Some(proto::query_frame::Payload::Checkpoint(value)) if !value.is_empty())
    );
    let terminal = Fixture::next(&mut stream).await?;
    assert!(
        matches!(terminal.payload, Some(proto::query_frame::Payload::Terminal(value)) if value.reason == "Completed")
    );
    assert!(tokio::time::timeout(WAIT, stream.next()).await?.is_none());
    Ok(())
}

#[tokio::test]
async fn observability_grpc_browser_guards() -> TestResult {
    let fixture = Fixture::new()?;
    let query = proto::QueryRequest {
        sql: "SELECT 1".into(),
        ..Default::default()
    };
    let mut wrong = fixture.request(query.clone(), false)?;
    wrong.metadata_mut().insert(
        "x-araphor-tenant",
        uuid::Uuid::from_bytes([2; 16]).to_string().parse()?,
    );
    assert_eq!(
        fixture
            .service
            .query(wrong)
            .await
            .err()
            .map(|error| error.code()),
        Some(tonic::Code::PermissionDenied)
    );
    let mut wrong = fixture.request(query.clone(), false)?;
    wrong
        .metadata_mut()
        .insert("origin", "https://foreign.example".parse()?);
    assert_eq!(
        fixture
            .service
            .query(wrong)
            .await
            .err()
            .map(|error| error.code()),
        Some(tonic::Code::Unauthenticated)
    );
    let submit = proto::SubmitTraceRequest {
        idempotency_key: vec![6; 16],
        ..Default::default()
    };
    assert_eq!(
        fixture
            .service
            .submit_trace(fixture.request(submit, false)?)
            .await
            .err()
            .map(|error| error.code()),
        Some(tonic::Code::Unauthenticated)
    );
    let readonly = proto::QueryRequest {
        sql: "DELETE FROM traces".into(),
        ..Default::default()
    };
    assert_eq!(
        fixture
            .service
            .query(fixture.request(readonly, false)?)
            .await
            .err()
            .map(|error| error.code()),
        Some(tonic::Code::InvalidArgument)
    );
    let mut stream = fixture
        .service
        .query(fixture.request(query, false)?)
        .await?
        .into_inner();
    assert!(matches!(
        Fixture::next(&mut stream).await?.payload,
        Some(proto::query_frame::Payload::Metadata(_))
    ));
    fixture.service.auth.replace_grants(Vec::new())?;
    let next = tokio::time::timeout(WAIT, stream.next())
        .await?
        .ok_or("revocation status is absent")?;
    assert_eq!(
        next.err().map(|error| error.code()),
        Some(tonic::Code::PermissionDenied)
    );
    assert!(tokio::time::timeout(WAIT, stream.next()).await?.is_none());
    Ok(())
}

#[tokio::test]
async fn observability_grpc_trace_retry() -> TestResult {
    let fixture = Fixture::new()?;
    let accepted = fixture.seed([1; 16], 6)?;
    let request = Fixture::submit(&accepted)?;
    let first = fixture
        .service
        .submit_trace(fixture.request(request.clone(), true)?)
        .await?
        .into_inner();
    let retry = fixture
        .service
        .submit_trace(fixture.request(request.clone(), true)?)
        .await?
        .into_inner();
    assert_eq!(first, retry);
    assert_eq!(first.trace_id, accepted.request.request_id);
    let detail = fixture
        .service
        .get_trace(fixture.request(
            proto::GetTraceRequest {
                trace_id: first.trace_id.clone(),
            },
            false,
        )?)
        .await?
        .into_inner();
    assert_eq!(detail.source, accepted.request.source.bytes);
    assert_eq!(detail.targets.len(), 1);
    assert_eq!(
        detail.targets[0].cgroup_id,
        accepted.request.targets[0].cgroup_id
    );
    assert_eq!(
        detail.targets[0].binding_id,
        accepted.request.targets[0].binding_id
    );
    assert_eq!(detail.requested, request.selection);
    assert!(detail.limits.is_some());
    let mut changed = request.clone();
    changed.source = Some(proto::submit_trace_request::Source::Recipe(
        "failed-opens@1".into(),
    ));
    assert_eq!(
        fixture
            .service
            .submit_trace(fixture.request(changed, true)?)
            .await
            .err()
            .map(|error| error.code()),
        Some(tonic::Code::AlreadyExists)
    );
    let mut changed = request;
    changed
        .selection
        .as_mut()
        .ok_or("selection is absent")?
        .target = "pod-uid/replacement".into();
    assert_eq!(
        fixture
            .service
            .submit_trace(fixture.request(changed, true)?)
            .await
            .err()
            .map(|error| error.code()),
        Some(tonic::Code::AlreadyExists)
    );
    let mut changed = Fixture::submit(&accepted)?;
    changed.collection_seconds += 1;
    assert_eq!(
        fixture
            .service
            .submit_trace(fixture.request(changed, true)?)
            .await
            .err()
            .map(|error| error.code()),
        Some(tonic::Code::AlreadyExists)
    );
    let cancel = proto::CancelTraceRequest {
        trace_id: first.trace_id.clone(),
    };
    assert_eq!(
        fixture
            .service
            .cancel_trace(fixture.request(cancel.clone(), false)?)
            .await
            .err()
            .map(|error| error.code()),
        Some(tonic::Code::Unauthenticated)
    );
    let cancelled = fixture
        .service
        .cancel_trace(fixture.request(cancel, true)?)
        .await?
        .into_inner();
    assert_eq!(cancelled.trace_id, first.trace_id);
    assert!(cancelled.cancel_requested);
    let detail = fixture
        .service
        .get_trace(fixture.request(
            proto::GetTraceRequest {
                trace_id: first.trace_id,
            },
            false,
        )?)
        .await?
        .into_inner();
    assert!(detail.receipt.ok_or("receipt is absent")?.cancel_requested);
    Ok(())
}

#[tokio::test]
async fn observability_grpc_trace_stream() -> TestResult {
    let fixture = Fixture::new()?;
    let accepted = fixture.seed([1; 16], 6)?;
    fixture.record(&accepted)?;
    let request = proto::WatchTraceRequest {
        trace_id: vec![6; 16],
        bookmark: Vec::new(),
    };
    let mut stream = fixture
        .service
        .watch_trace(fixture.request(request.clone(), false)?)
        .await?
        .into_inner();
    let metadata = Fixture::next(&mut stream).await?;
    assert_eq!(metadata.store_uuid.len(), 16);
    assert!(matches!(
        metadata.payload,
        Some(proto::trace_frame::Payload::Metadata(_))
    ));
    let output = Fixture::next(&mut stream).await?;
    assert_eq!(output.sequence, 1);
    assert!(output.commit_revision <= output.read_revision);
    assert!(
        matches!(output.payload, Some(proto::trace_frame::Payload::Output(value)) if value.bytes == b"hello")
    );
    let checkpoint = Fixture::next(&mut stream).await?;
    assert!(matches!(
        checkpoint.payload,
        Some(proto::trace_frame::Payload::Checkpoint(_))
    ));
    assert!(!checkpoint.bookmark.is_empty());
    let bookmark = checkpoint.bookmark;
    drop(stream);
    fixture.finish(&accepted)?;
    let mut resumed = fixture
        .service
        .watch_trace(fixture.request(
            proto::WatchTraceRequest {
                bookmark: bookmark.clone(),
                ..request.clone()
            },
            false,
        )?)
        .await?
        .into_inner();
    assert!(matches!(
        Fixture::next(&mut resumed).await?.payload,
        Some(proto::trace_frame::Payload::Metadata(_))
    ));
    let terminal = Fixture::next(&mut resumed).await?;
    assert!(
        matches!(terminal.payload, Some(proto::trace_frame::Payload::Terminal(value))
        if value.last_sequence == 1 && value.output_bytes == 5 && value.cleanup == "Verified")
    );
    assert!(matches!(
        Fixture::next(&mut resumed).await?.payload,
        Some(proto::trace_frame::Payload::Checkpoint(_))
    ));
    assert!(
        matches!(Fixture::next(&mut resumed).await?.payload, Some(proto::trace_frame::Payload::Result(value))
        if value.complete && value.cleanup_complete && !value.output_incomplete && value.missing_targets.is_empty())
    );
    assert!(tokio::time::timeout(WAIT, resumed.next()).await?.is_none());
    drop(resumed);
    fixture.seed([1; 16], 7)?;
    let other = proto::WatchTraceRequest {
        trace_id: vec![7; 16],
        bookmark: bookmark.clone(),
    };
    assert_eq!(
        fixture
            .service
            .watch_trace(fixture.request(other, false)?)
            .await
            .err()
            .map(|error| error.code()),
        Some(tonic::Code::InvalidArgument)
    );
    let identity = accepted.binding(0)?.identity;
    let future = ClientGrpcOwner::now()?
        .checked_add(2 * 24 * 60 * 60 * 1_000_000_000)
        .ok_or("retention time overflow")?;
    assert_eq!(
        EvidenceRetentionOwner::new(&fixture.service.data()?.store)
            .retain_trace(&identity, future)?
            .removed_records,
        2
    );
    let mut expired = fixture
        .service
        .watch_trace(fixture.request(
            proto::WatchTraceRequest {
                bookmark,
                ..request
            },
            false,
        )?)
        .await?
        .into_inner();
    assert!(
        matches!(Fixture::next(&mut expired).await?.payload, Some(proto::trace_frame::Payload::Error(value))
        if value.code == "CursorExpired" && value.position.is_some() && value.floor.is_some() && !value.last_checkpoint.is_empty())
    );
    let status = tokio::time::timeout(WAIT, expired.next())
        .await?
        .ok_or("expiry status is absent")?;
    assert_eq!(
        status.err().map(|error| error.code()),
        Some(tonic::Code::OutOfRange)
    );
    assert!(tokio::time::timeout(WAIT, expired.next()).await?.is_none());
    Ok(())
}

#[tokio::test]
async fn observability_grpc_read_revocation() -> TestResult {
    let fixture = Fixture::new()?;
    let accepted = fixture.seed([1; 16], 6)?;
    fixture.record(&accepted)?;
    let mut stream = fixture
        .service
        .watch_trace(fixture.request(
            proto::WatchTraceRequest {
                trace_id: vec![6; 16],
                bookmark: Vec::new(),
            },
            false,
        )?)
        .await?
        .into_inner();
    assert!(matches!(
        Fixture::next(&mut stream).await?.payload,
        Some(proto::trace_frame::Payload::Metadata(_))
    ));
    TraceOwner::new(fixture.service.data()?.store.clone()).cancel(
        [1; 16],
        [6; 16],
        &fixture.access([1; 16]),
        ClientGrpcOwner::now()?,
        true,
    )?;
    let status = tokio::time::timeout(WAIT, stream.next())
        .await?
        .ok_or("read revocation status is absent")?;
    assert_eq!(
        status.err().map(|error| error.code()),
        Some(tonic::Code::PermissionDenied)
    );
    assert_eq!(
        fixture
            .service
            .get_trace(fixture.request(
                proto::GetTraceRequest {
                    trace_id: accepted.request.request_id.to_vec()
                },
                false
            )?)
            .await
            .err()
            .map(|error| error.code()),
        Some(tonic::Code::PermissionDenied)
    );
    Ok(())
}
