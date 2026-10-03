use super::*;
use erebor_interceptor::diagnostic::{DiagnosticCapture, DiagnosticStop, MAX_OUTPUT_BYTES};
use serde_json::json;

const ATTACHED: &[u8] = b"__BPFTRACE_NOTIFY_PROBES_ATTACHED\n";

impl ObservabilityQualification {
    pub fn backend_lifecycle(&self) -> ProofResult<()> {
        fs::create_dir(&self.output)?;
        let cases = [
            ("parse-error", DiagnosticMode::Compile, "printf 'ERROR: unexpected end of file, expected {\\n' >&2; exit 1", DiagnosticStop::Exited),
            ("unsupported-hook", DiagnosticMode::Capture, "printf 'ERROR: missing hook\\n' >&2; exit 1", DiagnosticStop::Exited),
            ("quiet", DiagnosticMode::Capture, "printf '__BPFTRACE_NOTIFY_PROBES_ATTACHED\\n' >&2; exec sleep 60", DiagnosticStop::Cancelled),
            ("histogram", DiagnosticMode::Capture, r#"trap 'printf "%s\n" "{\"type\":\"hist\",\"data\":{}}"; exit 0' INT; printf '__BPFTRACE_NOTIFY_PROBES_ATTACHED\n' >&2; while :; do sleep 1; done"#, DiagnosticStop::Cancelled),
            ("raw-output", DiagnosticMode::Capture, "printf '__BPFTRACE_NOTIFY_PROBES_ATTACHED\\n' >&2; printf 'not-json\\n'", DiagnosticStop::Exited),
            ("oversize-output", DiagnosticMode::Capture, "printf '__BPFTRACE_NOTIFY_PROBES_ATTACHED\\n' >&2; head -c 1048577 /dev/zero", DiagnosticStop::OutputLimit),
            ("graceful", DiagnosticMode::Capture, "printf '__BPFTRACE_NOTIFY_PROBES_ATTACHED\\n' >&2", DiagnosticStop::Exited),
            ("deadline", DiagnosticMode::Capture, "printf '__BPFTRACE_NOTIFY_PROBES_ATTACHED\\n' >&2; exec sleep 60", DiagnosticStop::Deadline),
            ("forced-kill", DiagnosticMode::Capture, "trap '' INT; printf '__BPFTRACE_NOTIFY_PROBES_ATTACHED\\n' >&2; exec sleep 60", DiagnosticStop::Cancelled),
            ("compile-timeout", DiagnosticMode::Compile, "exec sleep 60", DiagnosticStop::Deadline),
            ("preparation-timeout", DiagnosticMode::Capture, "printf '__BPFTRACE_NOTIFY_PROBES_ATTACHED\\n'; exec sleep 60", DiagnosticStop::PreparationDeadline),
            ("slow-consumer", DiagnosticMode::Capture, "printf '__BPFTRACE_NOTIFY_PROBES_ATTACHED\\n' >&2; while :; do printf 'output\\n'; done", DiagnosticStop::ConsumerSlow),
        ];
        let mut results = Vec::new();
        for (name, mode, script, expected) in cases {
            let collection = if matches!(name, "oversize-output" | "slow-consumer") {
                Duration::from_secs(10)
            } else {
                Duration::from_millis(500)
            };
            let capture = Self::fixture_capture(script, mode, collection)?;
            let mut frames = Vec::new();
            let mut stopped = false;
            let deadline = Instant::now() + Duration::from_secs(20);
            while !capture.is_finished() && Instant::now() < deadline {
                if name != "slow-consumer" {
                    frames.extend(capture.frames().try_iter());
                }
                let ready = frames
                    .iter()
                    .any(|frame| frame.stderr && frame.bytes == ATTACHED);
                if !stopped && name == "compile-timeout" {
                    if let Some(pid) = capture
                        .process_id()
                        .and_then(|pid| rustix::process::Pid::from_raw(pid as i32))
                    {
                        let fd =
                            rustix::process::pidfd_open(pid, rustix::process::PidfdFlags::empty())?;
                        rustix::process::pidfd_send_signal(&fd, rustix::process::Signal::STOP)?;
                        stopped = true;
                    }
                } else if !stopped && ready && matches!(name, "quiet" | "histogram" | "forced-kill")
                {
                    capture.cancel();
                    stopped = true;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            if !capture.is_finished() {
                return Err(format!("{name}: supervisor did not finish").into());
            }
            frames.extend(capture.frames().try_iter());
            let result = capture.finish()?;
            let reaped = !Path::new(&format!("/proc/{}", result.process_id)).exists();
            let readiness = mode == DiagnosticMode::Capture
                && !matches!(name, "unsupported-hook" | "preparation-timeout");
            let record = json!({
                "name": name,
                "result": result,
                "frames": frames,
                "process_reaped": reaped,
                "kernel_cleanup_verified": null,
                "enforcement_manifest_unchanged": null,
            });
            self.write(&format!("{name}.json"), &record)?;
            if result.stop != expected
                || !reaped
                || result.attach_notification_ms.is_some() != readiness
                || result.cleanup_verified.is_some()
                || !result.program_ids.is_empty()
                || !result.map_ids.is_empty()
                || result.retained_bytes > MAX_OUTPUT_BYTES
                || frames
                    .iter()
                    .enumerate()
                    .any(|(index, frame)| frame.sequence != index as u64 + 1)
            {
                return Err(format!("{name}: incorrect lifecycle result: {result:?}").into());
            }
            if matches!(name, "forced-kill" | "compile-timeout") && !result.forced_kill {
                return Err(format!("{name}: forced cleanup did not run").into());
            }
            if matches!(name, "parse-error" | "unsupported-hook") && result.exit_code != Some(1) {
                return Err(format!("{name}: expected source failure").into());
            }
            if matches!(name, "graceful" | "raw-output" | "histogram")
                && result.exit_code != Some(0)
            {
                return Err(format!("{name}: expected graceful exit").into());
            }
            if name == "histogram"
                && !frames.iter().any(|frame| {
                    serde_json::from_slice::<serde_json::Value>(&frame.bytes)
                        .is_ok_and(|value| value["type"] == "hist")
                })
            {
                return Err("histogram: final output was lost".into());
            }
            if name == "raw-output" && !frames.iter().any(|frame| frame.bytes == b"not-json\n") {
                return Err("raw-output: bytes were not preserved".into());
            }
            results.push(record);
        }
        let parent = self.lifecycle_parent()?;
        self.write("result.json", &json!({
            "schema_version": 1,
            "case": "backend-lifecycle",
            "result": "PASS",
            "proof_boundary": "Production supervision with external-process doubles. Attachment notifications are simulated. No BPF attachment, kernel cleanup, or enforcement proof.",
            "cases": results,
            "parent_death": parent,
            "physical": false,
            "performance_claim": false,
        }))
    }

    fn fixture_capture(
        script: &str,
        mode: DiagnosticMode,
        collection: Duration,
    ) -> ProofResult<DiagnosticCapture> {
        let mut command = Command::new("/bin/sh");
        command.args(["-c", &format!("cat >/dev/null; {script}")]);
        Ok(DiagnosticBackend::start_fixture(command, mode, collection)?)
    }

    pub fn lifecycle_child(&self) -> ProofResult<()> {
        fs::create_dir(&self.output)?;
        let capture = Self::fixture_capture(
            "printf '__BPFTRACE_NOTIFY_PROBES_ATTACHED\\n' >&2; exec sleep 60",
            DiagnosticMode::Capture,
            Duration::from_secs(30),
        )?;
        let frame = capture.frames().recv_timeout(Duration::from_secs(2))?;
        if !frame.stderr || frame.bytes != ATTACHED {
            return Err("parent fixture did not reach simulated attachment".into());
        }
        self.write(
            "pid.json",
            &capture
                .process_id()
                .ok_or("fixture exited before readiness")?,
        )?;
        let _frames: Vec<_> = capture.frames().iter().collect();
        capture.finish()?;
        Ok(())
    }

    fn lifecycle_parent(&self) -> ProofResult<serde_json::Value> {
        let path = self.output.join("parent-fixture");
        let mut command = Command::new(std::env::current_exe()?);
        if cfg!(test) {
            command
                .args([
                    "--exact",
                    "observability::lifecycle::tests::observability_backend_child",
                    "--ignored",
                ])
                .env("ARAPHOR_DIAGNOSTIC_FIXTURE", &path);
        } else {
            command
                .args([
                    "--case",
                    "backend-lifecycle",
                    "--parent-fixture",
                    "--output-directory",
                ])
                .arg(&path);
        }
        let mut parent = QualificationChild(command.spawn()?);
        let deadline = Instant::now() + Duration::from_secs(3);
        let pid: u32 = loop {
            if let Some(pid) = fs::read(path.join("pid.json"))
                .ok()
                .and_then(|bytes| serde_json::from_slice(&bytes).ok())
            {
                break pid;
            }
            if Instant::now() >= deadline {
                return Err("parent fixture did not report its child identity".into());
            }
            std::thread::sleep(Duration::from_millis(10));
        };
        parent.0.kill()?;
        parent.0.wait()?;
        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            match fs::read_to_string(format!("/proc/{pid}/status")) {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => break,
                Ok(status)
                    if status
                        .lines()
                        .any(|line| line.starts_with("State:") && line.contains("Z (zombie)")) =>
                {
                    break
                }
                _ if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(10)),
                _ => return Err("diagnostic child survived parent death".into()),
            }
        }
        Ok(
            json!({"process_id": pid, "child_stopped": true, "terminal_missing": true, "kernel_cleanup_verified": null}),
        )
    }
}

#[cfg(test)]
impl ObservabilityQualification {
    fn owned_restart(&self) -> ProofResult<()> {
        fs::create_dir(&self.output)?;
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        let cases = runtime.block_on(async {
            let mut cases = Vec::new();
            for (stage, request_id) in [("before", 21), ("after", 22)] {
                let fixture = Self::new(self.output.join(stage));
                fs::create_dir(&fixture.output)?;
                cases.push(fixture.restart_case(stage, request_id).await?);
            }
            Ok::<_, Box<dyn std::error::Error>>(cases)
        })?;
        self.write("result.json", &json!({
            "schema_version": 1,
            "case": "owned-restart",
            "result": "PASS",
            "cases": cases,
            "proof_boundary": "Production Control, Node spool and Interceptor supervision use external process, binding-state and admission-clock inputs. The Node owner process receives SIGKILL before backend execution or after simulated attachment and committed output. Reopen retains the original execution and uses current mTLS transport. BPF cleanup, enforcement recovery and performance are not tested.",
            "physical": false,
            "performance_claim": false,
        }))
    }

    async fn restart_case(&self, stage: &str, request_id: u8) -> ProofResult<serde_json::Value> {
        use crate::control_fixture::{MtlsFixture, OutagePolicyFixture, OUTAGE_TENANT_ID};
        use ed25519_dalek::SigningKey;
        use mithril_control::{
            ControlStore, DiscoveryDigestV1, TraceBatchV1, TraceCleanupV1, TraceExchangeV1,
            TraceExecutionGrantV1, TraceOwner, TraceReadAccessV1, TraceRecipeV1, TraceRequestV1,
            TraceTargetV1, TraceTerminalReasonV1, TraceUploadV1,
        };
        use mithril_node::TrustCache;
        use std::os::unix::fs::MetadataExt as _;
        use std::os::unix::process::ExitStatusExt as _;

        let tls = MtlsFixture::new(false)?;
        let fixture = OutagePolicyFixture::new(ControlStore::open(tls.path().join("inventory"))?);
        let facts = fixture.inventory(&fixture.resource(1)?)?;
        let fact = facts
            .first()
            .ok_or("missing restart workload fact")?
            .clone();
        drop(fixture);
        fs::create_dir(self.output.join("target"))?;
        let target = TraceTargetV1 {
            fact_digest: DiscoveryDigestV1::of(&fact)?,
            fact,
            runtime_container_id: "1".repeat(64),
            node_boot_id: [7; 16],
            cgroup_id: fs::metadata(self.output.join("target"))?.ino(),
            binding_id: [3; 16],
            binding_nonce: [4; 16],
            root_cgroup_live_interval_id: [5; 16],
            container_generation: 1,
            label_epoch: 1,
        };
        let key = SigningKey::from_bytes(&[23; 32]);
        let control = Self::trace_control(&tls, &key)?;
        let data = control
            .analysis_store()
            .ok_or("missing restart data owner")?;
        let owner = TraceOwner::new(data.clone());
        control.replace_kubernetes_workload_inventory(facts)?;
        let server = tls.start(control.clone()).await?;
        let result = tokio::time::timeout(Duration::from_secs(15), async {
            let connector = tls.connector(&server, "node-a", [7; 16]);
            let mut cache = TrustCache::load(&tls.path().join("restart-trust"))?;
            let mut registration = OutagePolicyFixture::registration([7; 16], false);
            registration.effect_prevention_claims_enabled = false;
            let mut connection = connector
                .connect(registration.clone(), true, &mut cache)
                .await?;
            connection.report_readiness(true, true).await?;
            let now = u64::try_from(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)?
                    .as_nanos(),
            )?;
            let tenant = *uuid::Uuid::parse_str(OUTAGE_TENANT_ID)?.as_bytes();
            let grant = TraceExecutionGrantV1 {
                tenant_id: tenant,
                grant_id: [7; 16],
                principal: "qualification".into(),
                namespace_uids: [target.fact.namespace_uid.clone()].into(),
                node_ids: ["node-a".into()].into(),
                recipe_digests: [TraceRecipeV1::FailedOpens.digest()?].into(),
                host_diagnostic: false,
                valid_until_unix_ns: now + 120_000_000_000,
            };
            let access = TraceReadAccessV1 {
                tenant_id: tenant,
                namespace_uids: grant.namespace_uids.clone(),
                node_ids: grant.node_ids.clone(),
                host_sensitive: false,
                valid_until_unix_ns: grant.valid_until_unix_ns,
                revoked: false,
            };
            let request = TraceRequestV1 {
                tenant_id: tenant,
                request_id: [request_id; 16],
                source: TraceRecipeV1::FailedOpens.manifest()?.source,
                targets: vec![target.clone()],
                unresolved: Vec::new(),
                collection_seconds: 30,
            };
            control.accept_trace(request.clone(), grant, None)?;
            let now = u64::try_from(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)?
                    .as_nanos(),
            )?;
            let (_, accepted) = owner.read(tenant, request.request_id, &access, now)?;
            let dispatch = connection
                .exchange_diagnostics(&TraceExchangeV1::default())
                .await?
                .dispatch
                .ok_or("missing restart dispatch")?;
            if dispatch.accepted != accepted || dispatch.accepted.request != request {
                return Err("restart dispatch changed the accepted request".into());
            }
            let dispatch_key =
                cache.policy_signing_key(&dispatch.signing_key_id, dispatch.issuer_epoch)?;
            dispatch.verify(&dispatch_key, tenant, "node-a", [7; 16], now)?;
            let id = accepted.execution_id(dispatch.target_index)?;
            self.write("dispatch.json", &dispatch)?;
            let mut command = Command::new(std::env::current_exe()?);
            command
                .args([
                    "--exact",
                    "observability::lifecycle::tests::observability_restart_child",
                    "--ignored",
                    "--nocapture",
                ])
                .env("ARAPHOR_RESTART_FIXTURE", &self.output)
                .env("ARAPHOR_RESTART_STAGE", stage);
            let mut child = QualificationChild(command.spawn()?);
            let deadline = Instant::now() + Duration::from_secs(5);
            loop {
                if fs::read(self.output.join("ready")).is_ok_and(|bytes| bytes == b"ready") {
                    break;
                }
                if child.0.try_wait()?.is_some() || Instant::now() >= deadline {
                    return Err("restart child did not reach its crash barrier".into());
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            let prefix: Option<TraceBatchV1> = if stage == "after" {
                Some(serde_json::from_slice(&fs::read(
                    self.output.join("prefix.json"),
                )?)?)
            } else {
                None
            };
            let launches = match fs::read(self.output.join("launches")) {
                Ok(bytes) => bytes,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => Vec::new(),
                Err(error) => return Err(error.into()),
            };
            if launches
                != if stage == "after" {
                    b"launch\n".to_vec()
                } else {
                    Vec::new()
                }
                || (stage == "before" && self.output.join("child.pid").try_exists()?)
            {
                return Err("restart child executed outside its crash barrier".into());
            }
            let prefix_ack = if let Some(prefix) = &prefix {
                let reply = connection
                    .exchange_diagnostics(&TraceExchangeV1 {
                        retained: vec![id],
                        resolved: None,
                        output: Some(TraceUploadV1 {
                            request_id: request.request_id,
                            target_index: dispatch.target_index,
                            original_node_boot_id: [7; 16],
                            batch: prefix.clone(),
                        }),
                    })
                    .await?;
                let ack = reply
                    .acknowledgement
                    .ok_or("missing pre-crash prefix ACK")?;
                if prefix.execution_id != id
                    || prefix.frames.len() != 2
                    || prefix.terminal.is_some()
                    || ack.execution_id != id
                    || ack.last_sequence != 2
                    || ack.terminal.is_some()
                    || reply.dispatch.is_some()
                {
                    return Err("pre-crash prefix or ACK changed execution".into());
                }
                Some(ack)
            } else {
                if !owner
                    .output(tenant, request.request_id, 0, &access, now, 0)?
                    .is_empty()
                {
                    return Err("before-spawn restart already retained output".into());
                }
                None
            };
            child.0.kill()?;
            if child.0.wait()?.signal() != Some(libc::SIGKILL) {
                return Err("restart child did not stop through SIGKILL".into());
            }
            let pid = if stage == "after" {
                let pid: u32 = fs::read_to_string(self.output.join("child.pid"))?.parse()?;
                let deadline = Instant::now() + Duration::from_secs(3);
                loop {
                    match fs::read_to_string(format!("/proc/{pid}/status")) {
                        Err(error) if error.kind() == std::io::ErrorKind::NotFound => break,
                        Ok(status)
                            if status.lines().any(|line| {
                                line.starts_with("State:") && line.contains("Z (zombie)")
                            }) =>
                        {
                            break
                        }
                        _ if Instant::now() < deadline => {
                            tokio::time::sleep(Duration::from_millis(10)).await
                        }
                        _ => return Err("restart backend survived its owner process".into()),
                    }
                }
                Some(pid)
            } else {
                None
            };
            drop(connection);
            let (mut node, _lease) = self.restart_node(&dispatch)?;
            let terminal = node
                .terminal(id)?
                .ok_or("restart recovery omitted its terminal")?;
            let frames = prefix
                .as_ref()
                .map_or(&[][..], |prefix| prefix.frames.as_slice());
            if terminal.reason != TraceTerminalReasonV1::NodeRestarted
                || terminal.cleanup != TraceCleanupV1::Unknown
                || !terminal.output_incomplete
                || terminal.kernel_lost_events.is_some()
                || terminal.ready_at_unix_ns.is_some()
                || terminal.exit_code.is_some()
                || terminal.forced_kill
                || terminal.execution_id != id
                || terminal.last_sequence != frames.len() as u64
                || terminal.output_bytes
                    != frames
                        .iter()
                        .map(|frame| frame.bytes.len() as u64)
                        .sum::<u64>()
                || node.frames(id, 0)? != frames
                || node.retained()? != vec![(id, dispatch.clone())]
                || node.admit(dispatch.clone(), None, &dispatch_key, now)? != id
            {
                return Err("Node restart changed its frozen intent, prefix or terminal".into());
            }
            let batch = node
                .next_batch(id, 0)?
                .ok_or("restart recovery omitted retained output")?;
            if batch.execution_id != id
                || batch.frames != frames
                || batch.terminal.as_ref() != Some(&terminal)
            {
                return Err("restart upload differs from the retained prefix".into());
            }
            let mut connection = connector
                .connect(registration.clone(), true, &mut cache)
                .await?;
            let exchange = TraceExchangeV1 {
                retained: vec![id],
                resolved: None,
                output: Some(TraceUploadV1 {
                    request_id: request.request_id,
                    target_index: dispatch.target_index,
                    original_node_boot_id: [7; 16],
                    batch: batch.clone(),
                }),
            };
            let first = connection.exchange_diagnostics(&exchange).await?;
            drop(connection);
            let mut connection = connector.connect(registration, true, &mut cache).await?;
            let replay = connection.exchange_diagnostics(&exchange).await?;
            let ack = first
                .acknowledgement
                .as_ref()
                .ok_or("missing current-session restart ACK")?;
            if ack.execution_id != id
                || ack.last_sequence != terminal.last_sequence
                || ack.terminal.as_ref() != Some(&terminal)
                || replay != first
                || first.dispatch.is_some()
                || owner.output(tenant, request.request_id, 0, &access, now, 0)?
                    != vec![batch.clone()]
                || owner.read(tenant, request.request_id, &access, now)?.1 != accepted
            {
                return Err("current-session replay changed the restart result or ACK".into());
            }
            node.acknowledge(id, &terminal)?;
            drop(node);
            let (mut node, _lease) = self.restart_node(&dispatch)?;
            if node.admit(dispatch.clone(), None, &dispatch_key, now)? != id
                || node.next_batch(id, 0)?.is_some()
                || node.terminal(id)?.as_ref() != Some(&terminal)
                || !node.frames(id, 0)?.is_empty()
                || owner.output(tenant, request.request_id, 0, &access, now, 0)?
                    != vec![batch.clone()]
                || match fs::read(self.output.join("launches")) {
                    Ok(bytes) => bytes != launches,
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                        !launches.is_empty()
                    }
                    Err(error) => return Err(error.into()),
                }
            {
                return Err("restart retry changed output or repeated backend execution".into());
            }
            if tls
                .path()
                .join("control-store/discovery-index.sqlite")
                .try_exists()?
            {
                return Err("Node restart started discovery analysis".into());
            }
            Ok::<_, Box<dyn std::error::Error>>(json!({
                "stage": stage, "accepted": accepted, "target": target,
                "owner_sigkill": true, "backend_process_id": pid, "backend_stopped": true,
                "launch_count": launches.len() / b"launch\n".len(), "prefix_ack": prefix_ack,
                "terminal": terminal, "retained": batch, "acknowledgement": ack,
                "replay_ack": replay.acknowledgement, "retry_no_execution": true,
                "ack_reopen": true, "discovery_index_present": false,
                "kernel_cleanup_verified": null, "physical": false, "performance_claim": false,
            }))
        })
        .await;
        let shutdown = server.shutdown().await;
        let record = result??;
        shutdown?;
        Ok(record)
    }

    #[allow(clippy::expect_used)]
    fn restart_node(
        &self,
        dispatch: &mithril_control::TraceDispatchV1,
    ) -> ProofResult<(
        mithril_node::NodeTraceOwner,
        mithril_node::TraceTargetLeaseV1,
    )> {
        use erebor_interceptor_abi::{BindingLifecycleStateV1, ExecutionSetBindingStateV1};
        use mithril_node::{NodeTraceOwner, TraceTargetLeaseV1};

        let target = dispatch.accepted.request.targets[dispatch.target_index as usize].clone();
        let state = ExecutionSetBindingStateV1 {
            node_boot_id: target.node_boot_id.into(),
            binding_id: target.binding_id.into(),
            binding_nonce: target.binding_nonce.into(),
            root_cgroup_live_interval_id: target.root_cgroup_live_interval_id.into(),
            root_cgroup_id: target.cgroup_id,
            label_epoch: target.label_epoch,
            container_generation: target.container_generation,
            lifecycle_state: BindingLifecycleStateV1::Active,
            ..Default::default()
        };
        let lease = TraceTargetLeaseV1::fixture(target, self.output.join("target"), move || {
            Ok(Some(state))
        })?;
        let launches = self.output.join("launches");
        let pid_path = self.output.join("child.pid");
        let node = NodeTraceOwner::open_fixture(
            &self.output,
            dispatch.accepted.request.tenant_id,
            "node-a".into(),
            [7; 16],
            move || {
                let mut file = fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(&launches)
                    .expect("open the external executor counter");
                std::io::Write::write_all(&mut file, b"launch\n")
                    .expect("write the external executor counter");
                let mut command = Command::new("/bin/sh");
                command.args([
                    "-c",
                    "cat >/dev/null; printf '%s' \"$$\" >\"$1\"; printf '__BPFTRACE_NOTIFY_PROBES_ATTACHED\\n' >&2; printf 'node-owned output\\n'; exec sleep 60",
                    "trace-fixture",
                ]).arg(&pid_path);
                command
            },
        )?;
        Ok((node, lease))
    }

    #[allow(clippy::expect_used)]
    fn restart_child(&self, stage: &str) -> ProofResult<()> {
        use mithril_control::{TraceDispatchV1, TraceFrameKindV1};

        let dispatch: TraceDispatchV1 =
            serde_json::from_slice(&fs::read(self.output.join("dispatch.json"))?)?;
        let (mut node, lease) = self.restart_node(&dispatch)?;
        if stage == "before" {
            let path = self.output.join("ready");
            node.set_intent_hook(move || {
                fs::write(&path, b"ready").expect("write the durable-intent barrier");
                loop {
                    std::thread::park();
                }
            })?;
        } else if stage != "after" {
            return Err("invalid restart child stage".into());
        }
        let now = u64::try_from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_nanos(),
        )?;
        let id = node.admit(
            dispatch,
            Some(lease),
            &ed25519_dalek::SigningKey::from_bytes(&[23; 32]).verifying_key(),
            now,
        )?;
        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            node.reap()?;
            if let Some(batch) = node.next_batch(id, 0)? {
                if batch.frames.len() == 2
                    && batch.terminal.is_none()
                    && batch
                        .frames
                        .iter()
                        .filter(|frame| {
                            frame.kind == TraceFrameKindV1::Diagnostic && frame.bytes == ATTACHED
                        })
                        .count()
                        == 1
                    && batch
                        .frames
                        .iter()
                        .filter(|frame| {
                            frame.kind == TraceFrameKindV1::Data
                                && frame.bytes == b"node-owned output\n"
                        })
                        .count()
                        == 1
                {
                    self.write("prefix.json", &batch)?;
                    fs::write(self.output.join("ready"), b"ready")?;
                    loop {
                        std::thread::park();
                    }
                }
            }
            if Instant::now() >= deadline {
                return Err(
                    "restart child did not retain its simulated attachment and output".into(),
                );
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn observability_backend_lifecycle() -> ProofResult<()> {
        let directory = tempfile::tempdir()?;
        let owner = ObservabilityQualification::new(directory.path().join("result"));
        owner.backend_lifecycle()?;
        let receipt: serde_json::Value =
            serde_json::from_slice(&fs::read(owner.output.join("result.json"))?)?;
        assert_eq!(receipt["result"], "PASS");
        assert_eq!(receipt["cases"].as_array().map(Vec::len), Some(12));
        assert_eq!(receipt["physical"], false);
        assert!(owner.backend_lifecycle().is_err());
        Ok(())
    }

    #[test]
    #[ignore = "subprocess fixture for the parent-death check"]
    fn observability_backend_child() -> ProofResult<()> {
        let path =
            std::env::var_os("ARAPHOR_DIAGNOSTIC_FIXTURE").ok_or("missing fixture directory")?;
        ObservabilityQualification::new(PathBuf::from(path)).lifecycle_child()
    }

    #[test]
    fn observability_owned_restart() -> ProofResult<()> {
        let directory = tempfile::tempdir()?;
        let owner = ObservabilityQualification::new(directory.path().join("restart"));
        owner.owned_restart()?;
        let receipt: serde_json::Value =
            serde_json::from_slice(&fs::read(owner.output.join("result.json"))?)?;
        assert_eq!(receipt["result"], "PASS");
        assert_eq!(receipt["physical"], false);
        assert_eq!(receipt["performance_claim"], false);
        let cases = receipt["cases"].as_array().ok_or("missing restart cases")?;
        assert_eq!(cases.len(), 2);
        for (case, stage, count) in [(&cases[0], "before", 0), (&cases[1], "after", 1)] {
            assert_eq!(case["stage"], stage);
            assert_eq!(case["owner_sigkill"], true);
            assert_eq!(case["backend_stopped"], true);
            assert_eq!(case["launch_count"], count);
            assert_eq!(case["terminal"]["reason"], "NodeRestarted");
            assert_eq!(case["terminal"]["cleanup"], "Unknown");
            assert_eq!(case["terminal"]["output_incomplete"], true);
            assert!(case["terminal"]["kernel_lost_events"].is_null());
            assert!(case["kernel_cleanup_verified"].is_null());
            assert_eq!(case["acknowledgement"], case["replay_ack"]);
            assert_eq!(case["retry_no_execution"], true);
            assert_eq!(case["ack_reopen"], true);
            assert_eq!(case["discovery_index_present"], false);
            assert_eq!(
                case["retained"]["frames"].as_array().map(Vec::len),
                Some(count * 2)
            );
        }
        assert!(owner.owned_restart().is_err());
        Ok(())
    }

    #[test]
    #[ignore = "subprocess fixture for the Node owner restart check"]
    fn observability_restart_child() -> ProofResult<()> {
        let path = std::env::var_os("ARAPHOR_RESTART_FIXTURE")
            .ok_or("missing restart fixture directory")?;
        let stage = std::env::var("ARAPHOR_RESTART_STAGE")?;
        ObservabilityQualification::new(PathBuf::from(path)).restart_child(&stage)
    }
}
