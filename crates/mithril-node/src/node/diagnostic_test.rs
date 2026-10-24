use std::collections::BTreeMap;
use std::fs;
use std::net::TcpListener;
use std::os::unix::fs::MetadataExt as _;
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ed25519_dalek::SigningKey;
use erebor_interceptor::diagnostic::DiagnosticConfig;
use erebor_interceptor_abi::{BindingLifecycleStateV1, ExecutionSetBindingStateV1};
use mithril_control::{
    CapabilityRecord, ControlConfig, DiscoveryDigestV1, RegisteredWorkloadTarget, TraceAccessV1,
    TraceExchangeV1, TraceFrameKindV1, TraceFrameV1, TraceOwner, TraceRecipeV1, TraceRequestV1,
    TraceTargetV1, TraceTerminalReasonV1, TraceTerminalV1, TrustGenerationV1,
};
use serde_json::json;
use tokio::sync::oneshot;

use super::tests::AdmissionFixture;
use crate::{NodeControlConfig, NodeControlConnector, NodeTraceOwner, TraceTargetLeaseV1};

#[path = "../../../mithril-e2e/src/control_fixture/tls.rs"]
mod tls;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

#[tokio::test]
async fn diagnostic_ack_above_4096() -> TestResult {
    let mut fixture = AdmissionFixture::new()?;
    let root = fixture.node.config.state_directory.clone();
    let boot = fixture.node.node_boot_id.to_be_bytes();
    let tenant = [1; 16];
    let certificates = tls::Certificates::issue(false)?;
    let files = certificates.write(&root)?;
    let key = SigningKey::from_bytes(&[23; 32]);
    let trust = TrustGenerationV1 {
        generation: 1,
        bundle_digest: String::new(),
        policy_issuer_sequence_epoch: 1,
        policy_signers: vec![mithril_control::PolicySignerTrustV1 {
            signing_key_id: "trace-key".into(),
            ed25519_public_key_hex: hex::encode(key.verifying_key().as_bytes()),
            revoked: false,
        }],
    }
    .with_computed_bundle_digest();
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let address = listener.local_addr()?;
    drop(listener);
    let config_path = root.join("control.json");
    fs::write(
        &config_path,
        serde_json::to_vec(&json!({
            "listen": address,
            "tls": {
                "certificate_path": files.server_certificate,
                "private_key_path": files.server_key,
                "node_ca_path": files.ca,
            },
            "allowed_nodes": [{
                "node_id": "node-a",
                "certificate_sha256": certificates.node_digest(),
                "tenant_id": uuid::Uuid::from_bytes(tenant).to_string(),
            }],
            "trust": trust,
            "evidence_directory": root.join("evidence"),
            "control_store_directory": root.join("control-store"),
        }))?,
    )?;
    let parts = ControlConfig::load(&config_path)?.into_parts()?;
    assert!(parts.data_error.is_none(), "{:?}", parts.data_error);
    let control = parts
        .control
        .with_trace_signer("trace-key".into(), 1, key.clone())?;
    let data = control
        .analysis_store()
        .ok_or("diagnostic data is absent")?;
    let owner = TraceOwner::new(Arc::clone(&data));
    let serving = control.clone();
    let (shutdown, stopped) = oneshot::channel();
    let server = tokio::spawn(async move {
        mithril_control::serve(address, &parts.tls, serving, async {
            let _stopped = stopped.await;
        })
        .await
    });
    let connection_config = NodeControlConfig {
        endpoint: format!("https://{address}"),
        server_name: "localhost".into(),
        ca_path: files.ca.clone(),
        certificate_path: files.node_certificate.clone(),
        private_key_path: files.node_key.clone(),
        ..fixture.node.config.control.clone()
    };
    let connector = NodeControlConnector::new(connection_config, "node-a".into(), boot);
    fixture.node.registration.effect_prevention_claims_enabled = false;
    fixture.node.registration.startup_absence_proof_digest =
        mithril_control::startup_absence_proof_digest("node-a", &boot, 1, true, true);
    fixture.node.registration.capabilities = vec![CapabilityRecord {
        capability_id: "KERNEL_LSM_CHASSIS".into(),
        state: "SUPPORTED".into(),
        reason_code: "EXACT_ATTACH_READBACK".into(),
    }];
    fixture.node.registration.workload_targets = vec![RegisteredWorkloadTarget {
        workload_binding_generation_digest: "1".repeat(64),
        execution_set_id: "40000000-0000-4000-8000-000000000001".into(),
        cluster_uid: "50000000-0000-4000-8000-000000000001".into(),
        namespace_uid: "60000000-0000-4000-8000-000000000001".into(),
        controller_uid: "70000000-0000-4000-8000-000000000001".into(),
        service_account_uid: "80000000-0000-4000-8000-000000000001".into(),
        pod_uid: "90000000-0000-4000-8000-000000000001".into(),
        container_id: "containerd://converter".into(),
        container_name: "converter".into(),
        container_kind: "APPLICATION".into(),
        image_digest: format!("sha256:{}", "a".repeat(64)),
        pod_labels: Default::default(),
    }];
    let mut connection = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            match connector
                .connect(
                    fixture.node.registration.clone(),
                    true,
                    &mut fixture.node.trust,
                )
                .await
            {
                Ok(connection) => return Ok::<_, crate::Error>(connection),
                Err(crate::Error::ControlTransport { .. }) => {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
                Err(error) => return Err(error),
            }
        }
    })
    .await??;
    connection.report_readiness(true, true).await?;
    let fact = control
        .workload_inventory()
        .into_iter()
        .next()
        .ok_or("registered trace target is absent")?;
    let mut retained = Vec::new();
    for (request_id, maximum, expected) in [(10, Some(4096), 4096), (11, None, 4097)] {
        let path = root.join(format!("capture-{request_id}"));
        fs::create_dir(&path)?;
        let target_path = path.join("target");
        fs::create_dir(&target_path)?;
        let target = TraceTargetV1 {
            fact: fact.clone(),
            fact_digest: DiscoveryDigestV1::of(&fact)?,
            runtime_container_id: fact.container_id.clone(),
            node_boot_id: boot,
            cgroup_id: fs::metadata(&target_path)?.ino(),
            binding_id: [3; 16],
            binding_nonce: [4; 16],
            root_cgroup_live_interval_id: [5; 16],
            container_generation: 1,
            label_epoch: 1,
        };
        let state = ExecutionSetBindingStateV1 {
            node_boot_id: boot.into(),
            binding_id: target.binding_id.into(),
            binding_nonce: target.binding_nonce.into(),
            root_cgroup_live_interval_id: target.root_cgroup_live_interval_id.into(),
            root_cgroup_id: target.cgroup_id,
            label_epoch: target.label_epoch,
            container_generation: target.container_generation,
            lifecycle_state: BindingLifecycleStateV1::Active,
            ..Default::default()
        };
        let lease =
            TraceTargetLeaseV1::fixture(target.clone(), target_path, move || Ok(Some(state)))?;
        let now = u64::try_from(crate::policy::current_utc_ns()?)?;
        let access = TraceAccessV1 {
            tenant_id: tenant,
            principal: "node-ack-test".into(),
            valid_until_unix_ns: now + 600_000_000_000,
            revoked: false,
        };
        let request = TraceRequestV1 {
            tenant_id: tenant,
            request_id: [request_id; 16],
            source: TraceRecipeV1::SyscallErrors.manifest()?.source,
            targets: vec![target],
            unresolved: Vec::new(),
            collection_seconds: 60,
            selection: None,
            finding_reference: None,
        };
        control.accept_trace(request.clone(), access.clone())?;
        let dispatch = connection
            .exchange_diagnostics(&TraceExchangeV1::default())
            .await?
            .dispatch
            .ok_or("signed trace dispatch is absent")?;
        assert_eq!(dispatch.accepted.request, request);
        let identity = dispatch.accepted.binding(0)?.identity;
        let id = identity.execution_id;
        let launches = Arc::new(AtomicUsize::new(0));
        let started = Arc::clone(&launches);
        let mut spool = NodeTraceOwner::open_fixture(
            &path,
            tenant,
            "node-a".into(),
            boot,
            move || {
                started.fetch_add(1, Ordering::AcqRel);
                let mut command = Command::new("/bin/sh");
                command.args([
                    "-c",
                    "cat >/dev/null; printf '__BPFTRACE_NOTIFY_PROBES_ATTACHED\\n' >&2; n=0; while [ \"$n\" -lt 4096 ]; do printf 'x\\n'; n=$((n + 1)); done",
                ]);
                command
            },
            DiagnosticConfig {
                output_frames: maximum,
                ..Default::default()
            },
        )?;
        let dispatch_key = fixture
            .node
            .trust
            .policy_signing_key(&dispatch.signing_key_id, dispatch.issuer_epoch)?;
        assert_eq!(dispatch_key, key.verifying_key());
        let now = u64::try_from(crate::policy::current_utc_ns()?)?;
        assert!(
            (dispatch.accepted.accepted_unix_ns..dispatch.accepted.deadline_unix_ns).contains(&now)
        );
        assert_eq!(spool.admit(dispatch, Some(lease), &dispatch_key, now)?, id);
        let trace = Arc::new(Mutex::new(spool));
        fixture.node.trace = Some(Arc::clone(&trace));
        let terminal = tokio::time::timeout(Duration::from_secs(90), async {
            loop {
                let terminal = {
                    let mut spool = trace.lock().map_err(|_| "trace spool lock failed")?;
                    spool.reap()?;
                    spool.terminal(id)?
                };
                if let Some(terminal) = terminal {
                    return Ok::<_, Box<dyn std::error::Error + Send + Sync>>(terminal);
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await??;
        let mut frames = Vec::new();
        loop {
            let after = frames
                .last()
                .map_or(0, |frame: &TraceFrameV1| frame.sequence);
            let page = trace
                .lock()
                .map_err(|_| "trace spool lock failed")?
                .frames(id, after)?;
            if page.is_empty() {
                break;
            }
            frames.extend(page);
        }
        assert_eq!(frames.len(), expected as usize);
        for (index, frame) in frames.iter().enumerate() {
            assert_eq!(frame.execution_id, id);
            assert_eq!(frame.sequence, index as u64 + 1);
            match frame.kind {
                TraceFrameKindV1::Data => assert_eq!(frame.bytes, b"x\n"),
                TraceFrameKindV1::Diagnostic => {
                    assert_eq!(frame.bytes, b"__BPFTRACE_NOTIFY_PROBES_ATTACHED\n");
                }
                _ => return Err("unexpected backend frame kind".into()),
            }
        }
        let markers = frames
            .iter()
            .filter(|frame| frame.kind == TraceFrameKindV1::Diagnostic)
            .count();
        assert!(markers <= 1);
        assert_eq!(terminal.last_sequence, expected);
        assert_eq!(
            terminal.output_bytes,
            frames
                .iter()
                .map(|frame| frame.bytes.len() as u64)
                .sum::<u64>()
        );
        if maximum.is_none() {
            assert_eq!(markers, 1);
            assert_eq!(frames.len() - markers, 4096);
            assert_eq!(terminal.reason, TraceTerminalReasonV1::Completed);
            assert!(!terminal.output_incomplete);
        } else {
            assert_eq!(terminal.reason, TraceTerminalReasonV1::OutputLimit);
            assert!(terminal.output_incomplete);
        }
        assert_eq!(launches.load(Ordering::Acquire), 1);
        let mut altered = terminal.clone();
        altered.output_bytes += 1;
        assert!(trace
            .lock()
            .map_err(|_| "trace spool lock failed")?
            .acknowledge(id, &altered)
            .is_err());
        let mut cursors = BTreeMap::new();
        let mut resolved = None;
        let mut before = 0;
        while before < expected {
            let result = fixture
                .node
                .poll_diagnostics(&mut connection, &mut cursors, &mut resolved)
                .await;
            let receipt = data
                .trace_receipt(&identity)?
                .ok_or("Control did not retain the trace upload")?;
            let through = (before + 200).min(expected);
            assert_eq!(receipt.last_sequence, through);
            assert_eq!(
                receipt.terminal.as_ref(),
                (through == expected).then_some(&terminal)
            );
            if let Err(error) = result {
                assert_eq!(maximum, None);
                assert_eq!((before, through), (4000, 4097));
                assert_eq!(cursors.get(&id), Some(&4000));
                assert!(matches!(&error, crate::Error::IdentityState { reason, .. }
                    if reason == "diagnostic acknowledgement changed its execution or sequence"));
                return Err(format!(
                    "Node rejected durable ACK {through} after cursor {before}: {error}"
                )
                .into());
            }
            assert_eq!(cursors.get(&id), Some(&through));
            assert!(resolved.is_none());
            before = through;
        }
        assert!(trace
            .lock()
            .map_err(|_| "trace spool lock failed")?
            .next_batch(id, 0)?
            .is_none());
        assert_eq!(
            output_frames(&owner, &request, &access, now)?,
            (frames.clone(), terminal.clone())
        );
        fixture.node.trace = None;
        drop(trace);
        let restarted = Arc::clone(&launches);
        let reopened = NodeTraceOwner::open_fixture(
            &path,
            tenant,
            "node-a".into(),
            boot,
            move || {
                restarted.fetch_add(1, Ordering::AcqRel);
                Command::new("/bin/false")
            },
            DiagnosticConfig::default(),
        )?;
        assert_eq!(reopened.terminal(id)?.as_ref(), Some(&terminal));
        assert!(reopened.next_batch(id, 0)?.is_none());
        assert_eq!(launches.load(Ordering::Acquire), 1);
        retained.push((request, access, now, frames, terminal));
    }
    drop(connection);
    shutdown
        .send(())
        .map_err(|_| "Control server already stopped")?;
    server.await??;
    drop(owner);
    drop(data);
    drop(control);
    let parts = ControlConfig::load(&config_path)?.into_parts()?;
    assert!(parts.data_error.is_none(), "{:?}", parts.data_error);
    let data = parts
        .control
        .analysis_store()
        .ok_or("reopened data is absent")?;
    let owner = TraceOwner::new(data);
    for (request, access, now, frames, terminal) in retained {
        assert_eq!(
            output_frames(&owner, &request, &access, now)?,
            (frames, terminal)
        );
    }
    Ok(())
}

fn output_frames(
    owner: &TraceOwner,
    request: &TraceRequestV1,
    access: &TraceAccessV1,
    now: u64,
) -> TestResult<(Vec<TraceFrameV1>, TraceTerminalV1)> {
    let mut frames = Vec::new();
    loop {
        let after = frames
            .last()
            .map_or(0, |frame: &TraceFrameV1| frame.sequence);
        let batches = owner.output(request.tenant_id, request.request_id, 0, access, now, after)?;
        if batches.is_empty() {
            return Err("Control output ended before the terminal".into());
        }
        for batch in batches {
            frames.extend(batch.frames);
            if let Some(terminal) = batch.terminal {
                return Ok((frames, terminal));
            }
        }
    }
}
