use std::ffi::OsString;
use std::fs::{self, File};
use std::os::fd::AsRawFd as _;
use std::path::{Path, PathBuf};

use erebor_interceptor::KernelStateReader;
use erebor_runtime_ipc::v1::MithrilObservationSnapshot;
use mithril_node::RuntimeAdmissionOperationV1;
use snafu::{ensure, ResultExt as _};

use super::shared::Shared;
use super::{Platform, Task, TestResult, PROCESS_FIXTURES};
use crate::error::{InvalidInputSnafu, IoSnafu};
use crate::physical::ProbeDirectory;
use crate::process::ProcessFixture;

pub(crate) struct Host {
    shared: Shared,
    bundle: Option<ProbeDirectory>,
    init_pid: Option<u32>,
    staged: bool,
    admitted: bool,
    mounts: Vec<PathBuf>,
}

impl Host {
    fn qualify_diagnostic_failures() -> TestResult<()> {
        use mithril_control::{
            DiscoveryDigestV1, TraceApprovalV1, TraceCleanupV1, TraceExecutionGrantV1,
            TraceReadAccessV1, TraceRecipeV1, TraceRequestV1, TraceSourceV1, TraceTerminalReasonV1,
            TraceTerminalV1,
        };
        use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
        let config: mithril_node::NodeTraceConfigV1 =
            serde_json::from_slice(&fs::read(std::env::var("MITHRIL_TRACE_CONFIG")?)?)?;
        config.validate()?;
        let proof = PathBuf::from(std::env::var("MITHRIL_TRACE_PROOF")?);
        if proof.exists() {
            return Err("the failure proof already exists".into());
        }
        let mut env = Self::setup("observability-failures")?;
        env.shared.configure_diagnostics(config)?;
        env.start_control()?;
        env.shared.enable_diagnostic_partition()?;
        let mut init = env.start_actor("ready.py", &[])?;
        env.place(init.id())?;
        let mut probe = env.add_actor("python", &["/fixtures/proc_read.py", "/work"])?;
        probe.ready()?;
        env.place(probe.id())?;
        env.install_policy("python_policy.json")?;
        env.start_node()?;
        env.sync_policy()?;
        env.node_ready()?;
        env.running(init.id())?;
        env.recovered(init.id(), "diagnostic failure workload")?;
        let initial = env.snapshot()?;
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        let (control, fact) = env.shared.diagnostic_context()?;
        let now = || -> TestResult<u64> {
            Ok(u64::try_from(
                SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos(),
            )?)
        };
        let tenant = *uuid::Uuid::parse_str(super::shared::TENANT_ID)?.as_bytes();
        let grant = TraceExecutionGrantV1 {
            tenant_id: tenant,
            grant_id: [7; 16],
            principal: "qualification".into(),
            namespace_uids: [fact.namespace_uid.clone()].into(),
            node_ids: [fact.node_id.clone()].into(),
            recipe_digests: [TraceRecipeV1::FailedOpens.digest()?].into(),
            host_diagnostic: false,
            valid_until_unix_ns: now()? + 600_000_000_000,
        };
        let mut access = TraceReadAccessV1 {
            tenant_id: tenant,
            namespace_uids: grant.namespace_uids.clone(),
            node_ids: grant.node_ids.clone(),
            host_sensitive: false,
            valid_until_unix_ns: grant.valid_until_unix_ns,
            revoked: false,
        };
        let targets = runtime.block_on(control.resolve_trace_targets(vec![fact], &grant))?;
        let target = targets
            .first()
            .and_then(|participant| participant.target.clone())
            .ok_or_else(|| format!("failure target resolution failed: {targets:?}"))?;
        let owner = mithril_control::TraceOwner::new(
            control
                .policy_desired_state()
                .ok_or("missing policy store")?
                .store(),
        );
        let mut records = Vec::new();
        for case in [
            "partition",
            "revocation",
            "map-exhaustion",
            "output-limit",
            "retirement",
        ] {
            env.node_ready()?;
            let request_id = *uuid::Uuid::new_v4().as_bytes();
            let mut request = TraceRequestV1 {
                tenant_id: tenant,
                request_id,
                source: TraceRecipeV1::FailedOpens.manifest()?.source,
                targets: vec![target.clone()],
                unresolved: Vec::new(),
                collection_seconds: if case == "partition" { 3 } else { 30 },
            };
            let mut execution_grant = grant.clone();
            let approval = if matches!(case, "map-exhaustion" | "output-limit") {
                request.source = TraceSourceV1::new(if case == "map-exhaustion" {
                    b"BEGIN { $i = 0; while ($i < 8192) { @full[$i] = 1; $i++; } } interval:s:2 { exit(); }".to_vec()
                } else {
                    b"interval:hz:10000 { printf(\"bounded diagnostic output\\n\"); }".to_vec()
                })?;
                execution_grant.host_diagnostic = true;
                access.host_sensitive = true;
                Some(TraceApprovalV1 {
                    approval_id: [8; 16],
                    request_digest: request.digest()?,
                    grant_digest: DiscoveryDigestV1::of(&execution_grant)?,
                    valid_until_unix_ns: execution_grant.valid_until_unix_ns,
                })
            } else {
                None
            };
            control.accept_trace(request, execution_grant, approval)?;
            let (_, accepted) = owner.read(tenant, request_id, &access, now()?)?;
            let id = accepted.execution_id(0)?;
            let spool = env.shared.diagnostic_spool(id);
            let mut frames = Vec::new();
            let mut after = 0;
            let deadline = Instant::now() + Duration::from_secs(15);
            loop {
                for batch in owner.output(tenant, request_id, 0, &access, now()?, after)? {
                    for frame in batch.frames {
                        after = frame.sequence;
                        frames.push(frame);
                    }
                }
                if frames.iter().any(|frame: &mithril_control::TraceFrameV1| {
                    frame.bytes == b"__BPFTRACE_NOTIFY_PROBES_ATTACHED\n"
                }) {
                    break;
                }
                if Instant::now() >= deadline {
                    return Err(format!("{case}: attachment absent: {frames:?}").into());
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            match case {
                "partition" => env.shared.partition_diagnostics(true)?,
                "revocation" => {
                    owner.cancel(tenant, request_id, "qualification", true)?;
                    assert!(owner
                        .output(tenant, request_id, 0, &access, now()?, after)
                        .is_err());
                }
                "retirement" => {
                    fs::write(env.work().join("release"), b"release")?;
                    probe.stop()?;
                    init.stop()?;
                    env.shared.retire_diagnostic_runtime()?;
                }
                _ => {}
            }
            let deadline = Instant::now() + Duration::from_secs(12);
            let terminal: TraceTerminalV1 = loop {
                match fs::read(spool.join("terminal.json")) {
                    Ok(bytes) => {
                        if let Some(end) = bytes.iter().position(|byte| *byte == b'\n') {
                            break serde_json::from_slice(&bytes[..end])?;
                        }
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    Err(error) => return Err(error.into()),
                }
                if Instant::now() >= deadline {
                    return Err(format!("{case}: local terminal absent").into());
                }
                std::thread::sleep(Duration::from_millis(20));
            };
            let expected = match case {
                "partition" => TraceTerminalReasonV1::Deadline,
                "revocation" => TraceTerminalReasonV1::Cancelled,
                "retirement" => TraceTerminalReasonV1::TargetChanged,
                _ => TraceTerminalReasonV1::Completed,
            };
            if case == "output-limit" {
                assert!(matches!(
                    terminal.reason,
                    TraceTerminalReasonV1::ConsumerSlow | TraceTerminalReasonV1::OutputLimit
                ));
                assert!(terminal.output_incomplete);
            } else {
                assert_eq!(terminal.reason, expected);
            }
            assert_eq!(terminal.cleanup, TraceCleanupV1::Verified);
            assert_eq!(terminal.execution_id, id);
            assert!(terminal.kernel_lost_events.is_none());
            if case == "partition" {
                env.shared.partition_diagnostics(false)?;
            }
            let deadline = Instant::now() + Duration::from_secs(50);
            while !spool.join("ack.json").exists() {
                if Instant::now() >= deadline {
                    return Err(format!("{case}: terminal was not acknowledged").into());
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            if case != "revocation" {
                for batch in owner.output(tenant, request_id, 0, &access, now()?, after)? {
                    frames.extend(batch.frames);
                }
            }
            if case == "map-exhaustion" {
                let size = frames
                    .iter()
                    .filter_map(|frame| {
                        serde_json::from_slice::<serde_json::Value>(&frame.bytes).ok()
                    })
                    .filter_map(|value| value["data"]["@full"].as_object().map(|map| map.len()))
                    .max();
                assert_eq!(size, Some(4096));
                assert!(accepted.recipe.is_none());
            }
            assert_eq!(env.snapshot()?.program_digest, initial.program_digest);
            records.push(serde_json::json!({"case":case,"accepted":accepted,"frames":frames,"terminal":terminal}));
            fs::write(&proof, serde_json::to_vec_pretty(&records)?)?;
            if case == "output-limit" {
                fs::write(env.work().join("act"), b"act")?;
                let deadline = Instant::now() + Duration::from_secs(5);
                while fs::read_to_string(format!("/proc/{}/comm", probe.id()))?.trim()
                    != format!("proc-read-{}", libc::EACCES)
                {
                    if Instant::now() >= deadline {
                        return Err("failures changed the physical denial".into());
                    }
                    std::thread::sleep(Duration::from_millis(10));
                }
            }
        }
        fs::write(env.work().join("release"), b"release")?;
        probe.stop()?;
        init.stop()?;
        env.stop()
    }

    #[cfg(test)]
    fn qualify_diagnostics() -> TestResult<()> {
        use mithril_control::{
            TraceExecutionGrantV1, TraceReadAccessV1, TraceRecipeV1, TraceRequestV1,
            TraceTerminalReasonV1,
        };
        use mithril_node::{NodeTraceConfigV1, TraceQualificationPairV1, TraceQualificationV1};
        use sha2::{Digest as _, Sha256};
        use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
        let executable = PathBuf::from(std::env::var("MITHRIL_TRACE_EXECUTABLE")?);
        let proof = PathBuf::from(std::env::var("MITHRIL_TRACE_PROOF")?);
        if proof.exists() {
            return Err("the trace proof path already exists".into());
        }
        let limit: u32 = std::env::var("MITHRIL_TRACE_MAX_OVERHEAD_BP")?.parse()?;
        let digest: [u8; 32] = Sha256::digest(fs::read(&executable)?).into();
        // Synthetic admission values enable this test only. The result stores measured pairs.
        let mut qualification = TraceQualificationV1 {
            evidence_sha256: [1; 32],
            executable_sha256: digest,
            kernel_release: fs::read_to_string("/proc/sys/kernel/osrelease")?
                .trim()
                .into(),
            architecture: std::env::consts::ARCH.into(),
            logical_cpus: std::thread::available_parallelism()?.get(),
            maximum_overhead_basis_points: limit,
            pairs: vec![
                TraceQualificationPairV1 {
                    trace_off_p99_ns: 1,
                    trace_on_p99_ns: 1,
                    trace_off_lost_events: 0,
                    trace_on_lost_events: 0,
                    physical_decisions_equal: true
                };
                5
            ],
        };
        let mut env = Self::setup("observability-owned-capture")?;
        env.shared.configure_diagnostics(NodeTraceConfigV1 {
            executable: executable.clone(),
            executable_sha256: digest,
            storage_reserve_bytes: 256 * 1024 * 1024,
            qualification: qualification.clone(),
        })?;
        env.start_control()?;
        let mut init = env.start_actor("ready.py", &[])?;
        env.place(init.id())?;
        let mut actor = env.add_actor("python", &["/fixtures/observability.py", "/work"])?;
        actor.ready()?;
        env.place(actor.id())?;
        env.install_policy("python_policy.json")?;
        env.start_node()?;
        env.sync_policy()?;
        env.node_ready()?;
        env.running(init.id())?;
        env.recovered(init.id(), "trace workload")?;
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        let (control, fact) = env.shared.diagnostic_context()?;
        let now = || -> TestResult<u64> {
            Ok(u64::try_from(
                SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos(),
            )?)
        };
        let tenant = *uuid::Uuid::parse_str(super::shared::TENANT_ID)?.as_bytes();
        let grant = TraceExecutionGrantV1 {
            tenant_id: tenant,
            grant_id: [7; 16],
            principal: "qualification".into(),
            namespace_uids: [fact.namespace_uid.clone()].into(),
            node_ids: [fact.node_id.clone()].into(),
            recipe_digests: [TraceRecipeV1::FailedOpens.digest()?].into(),
            host_diagnostic: false,
            valid_until_unix_ns: now()? + 600_000_000_000,
        };
        let access = TraceReadAccessV1 {
            tenant_id: tenant,
            namespace_uids: grant.namespace_uids.clone(),
            node_ids: grant.node_ids.clone(),
            host_sensitive: false,
            valid_until_unix_ns: grant.valid_until_unix_ns,
            revoked: false,
        };
        let targets = runtime.block_on(control.resolve_trace_targets(vec![fact], &grant))?;
        let target = targets
            .first()
            .and_then(|participant| participant.target.clone())
            .ok_or_else(|| format!("target resolution failed: {targets:?}"))?;
        let owner = mithril_control::TraceOwner::new(
            control
                .policy_desired_state()
                .ok_or("missing policy store owner")?
                .store(),
        );
        let mut records = Vec::new();
        let mut pairs = Vec::new();
        let mut off = (0, 0);
        for run in 0..10 {
            let on = run % 2 == 1;
            let request_id = *uuid::Uuid::new_v4().as_bytes();
            let mut frames = Vec::new();
            let mut after = 0;
            if on {
                env.node_ready()?;
                control.accept_trace(
                    TraceRequestV1 {
                        tenant_id: tenant,
                        request_id,
                        source: TraceRecipeV1::FailedOpens.manifest()?.source,
                        targets: vec![target.clone()],
                        unresolved: Vec::new(),
                        collection_seconds: 5,
                    },
                    grant.clone(),
                    None,
                )?;
                let deadline = Instant::now() + Duration::from_secs(15);
                loop {
                    for batch in owner.output(tenant, request_id, 0, &access, now()?, after)? {
                        for frame in batch.frames {
                            after = frame.sequence;
                            frames.push(frame);
                        }
                        if batch.terminal.is_some() {
                            return Err(format!(
                                "capture ended before attach: {:?}",
                                batch.terminal
                            )
                            .into());
                        }
                    }
                    if frames.iter().any(|frame: &mithril_control::TraceFrameV1| {
                        frame.bytes == b"__BPFTRACE_NOTIFY_PROBES_ATTACHED\n"
                    }) {
                        break;
                    }
                    if Instant::now() >= deadline {
                        return Err("capture did not attach".into());
                    }
                    std::thread::sleep(Duration::from_millis(20));
                }
            }
            let before = env.snapshot()?;
            fs::write(env.work().join(format!("trace-run-{run}")), b"run")?;
            let path = PathBuf::from(format!("/proc/{}/comm", actor.id()));
            let deadline = Instant::now() + Duration::from_secs(15);
            let p99: u64 = loop {
                actor.ensure_running("trace latency samples")?;
                let value = fs::read_to_string(&path)?;
                if let Some(value) = value.trim().strip_prefix(&format!("tr{run}:")) {
                    break value.parse()?;
                }
                if Instant::now() >= deadline {
                    return Err("trace latency samples did not finish".into());
                }
                std::thread::sleep(Duration::from_millis(10));
            };
            let result = serde_json::json!({"samples":1000,"denied":1000,"p99_ns":p99});
            let after_health = env.snapshot()?;
            let loss = after_health
                .lost_effects
                .saturating_sub(before.lost_effects)
                + after_health
                    .reader_queue_dropped_events
                    .saturating_sub(before.reader_queue_dropped_events)
                + after_health
                    .evidence_errors
                    .saturating_sub(before.evidence_errors);
            if !before.effect_health_available || !after_health.effect_health_available || loss != 0
            {
                return Err("trace measurement has missing or lost enforcement evidence".into());
            }
            let mut terminal = None;
            if on {
                let deadline = Instant::now() + Duration::from_secs(20);
                while terminal.is_none() {
                    for batch in owner.output(tenant, request_id, 0, &access, now()?, after)? {
                        for frame in batch.frames {
                            after = frame.sequence;
                            frames.push(frame);
                        }
                        terminal = batch.terminal.or(terminal);
                    }
                    if Instant::now() >= deadline {
                        return Err("capture terminal did not arrive".into());
                    }
                    std::thread::sleep(Duration::from_millis(20));
                }
                let end = terminal.as_ref().ok_or("missing terminal")?;
                if end.reason != TraceTerminalReasonV1::Deadline
                    || end.output_incomplete
                    || end.cleanup != mithril_control::TraceCleanupV1::Verified
                {
                    return Err(format!("capture failed: {end:?}").into());
                }
                if !frames
                    .iter()
                    .filter_map(|frame| TraceRecipeV1::FailedOpens.measurements(frame))
                    .flatten()
                    .any(|row| row.errno == -i64::from(libc::EACCES) && row.count >= 1000)
                {
                    return Err("capture did not measure the enforced denials".into());
                }
                pairs.push(TraceQualificationPairV1 {
                    trace_off_p99_ns: off.0,
                    trace_on_p99_ns: p99,
                    trace_off_lost_events: off.1,
                    trace_on_lost_events: loss,
                    physical_decisions_equal: true,
                });
            } else {
                off = (p99, loss);
            }
            records.push(
                serde_json::json!({"run":run,"trace_on":on,"request_id":request_id,
                "result":result,"frames":frames,"terminal":terminal,"loss":loss}),
            );
            fs::write(&proof, serde_json::to_vec_pretty(&records)?)?;
        }
        qualification.pairs = pairs;
        qualification.evidence_sha256 = Sha256::digest(fs::read(&proof)?).into();
        let config = NodeTraceConfigV1 {
            executable,
            executable_sha256: digest,
            storage_reserve_bytes: 256 * 1024 * 1024,
            qualification,
        };
        fs::write(
            proof.with_extension("config.json"),
            serde_json::to_vec_pretty(&config)?,
        )?;
        config.validate()?;
        fs::write(env.work().join("release"), b"release")?;
        actor.stop()?;
        init.stop()?;
        env.stop()?;
        Ok(())
    }
    fn bind(&mut self, source: &Path, target: &Path) -> TestResult<()> {
        fs::create_dir_all(target).context(IoSnafu { path: target })?;
        rustix::mount::mount_bind(source, target)
            .map_err(std::io::Error::from)
            .context(IoSnafu { path: target })?;
        self.mounts.push(target.to_owned());
        Ok(())
    }

    fn actor_root(&mut self) -> TestResult<PathBuf> {
        let bundle_path = self.shared.output().join("bundle");
        let rootfs = bundle_path.join("rootfs");
        if self.bundle.is_some() {
            return Ok(rootfs);
        }
        let bundle = ProbeDirectory::create(&bundle_path)?;
        fs::create_dir_all(rootfs.join("bundle"))?;
        self.bind(&rootfs, &rootfs)?;
        for path in ["/usr", "/lib", "/lib64", "/proc"] {
            let source = Path::new(path);
            if source.exists() {
                self.bind(source, &rootfs.join(path.trim_start_matches('/')))?;
            }
        }
        self.bind(Path::new("/dev/net"), &rootfs.join("dev/net"))?;
        let fixtures = self.shared.source().join(PROCESS_FIXTURES);
        self.bind(&fixtures, &rootfs.join("fixtures"))?;
        let work = self.shared.work().to_owned();
        self.bind(&work, &rootfs.join("work"))?;
        self.bundle = Some(bundle);
        Ok(rootfs)
    }

    fn stage_entries(&self, rootfs: &Path) -> TestResult<()> {
        let config = rootfs.join("bundle/config.json");
        fs::write(&config, br#"{"root":{"path":"/"}}"#).context(IoSnafu { path: &config })?;
        let root = File::open(rootfs).context(IoSnafu { path: rootfs })?;
        let mut request = self
            .shared
            .request(RuntimeAdmissionOperationV1::PrepareDeclaredEntries, None)?;
        request.oci_bundle = Some(PathBuf::from("/bundle"));
        request.oci_root_fd = Some(u32::try_from(root.as_raw_fd())?);
        let response = self.shared.submit(&request)?;
        ensure!(
            response.allowed && response.reason_code == "DECLARED_ENTRY_CANDIDATE_STAGED",
            InvalidInputSnafu {
                path: self.shared.admit_path(),
                reason: format!("Node rejected declared entries: {response:?}"),
            }
        );
        Ok(())
    }

    fn start_entry(&mut self, command: &str, args: &[&str]) -> TestResult<ProcessFixture> {
        let init = self.init_pid.ok_or("the initial actor is not running")?;
        let maps_path = PathBuf::from(format!("/proc/{init}/maps"));
        let maps = fs::read(&maps_path).context(IoSnafu { path: &maps_path })?;
        ensure!(
            !maps.is_empty(),
            InvalidInputSnafu {
                path: &maps_path,
                reason: "the runtime read an empty initial actor map",
            }
        );
        let rootfs = self.shared.output().join("bundle/rootfs");
        let program = Path::new(command);
        let mut actor =
            ProcessFixture::held_cgroup(program, args, self.shared.cgroup(), &rootfs, init)?;
        let pid = actor.id();
        let placement = self
            .shared
            .node_running()
            .then(|| self.shared.task(pid, "added actor placement"))
            .transpose()?;
        actor.release()?;
        if let Err(source) = actor.wait_command(pid, command) {
            if let Some(placement) = placement {
                return Err(format!(
                    "{source}; pre-exec PID: {}; snapshot: {:?}; coordinate: {:?}; identity health: {:?}",
                    placement.pid,
                    placement.snapshot,
                    placement.coordinate,
                    self.shared.health()?
                )
                .into());
            }
            return Err(source.into());
        }
        Ok(actor)
    }

    fn close(&mut self) -> TestResult<()> {
        for target in self.mounts.drain(..).rev() {
            rustix::mount::unmount(&target, rustix::mount::UnmountFlags::DETACH)
                .map_err(std::io::Error::from)
                .context(IoSnafu { path: &target })?;
        }
        if let Some(bundle) = self.bundle.take() {
            bundle.cleanup()?;
        }
        self.init_pid = None;
        self.staged = false;
        self.admitted = false;
        self.shared.stop()
    }
}

#[test]
#[ignore = "requires the owned Linux VM, BPF LSM, and diagnostic backend"]
fn observability_owned_capture_five_pairs() -> TestResult<()> {
    super::test_lifecycle::<Host, _>("observability", Host::qualify_diagnostics)
}

#[test]
#[ignore = "requires the owned Linux VM and a passing diagnostic qualification record"]
fn observability_owned_capture_failures() -> TestResult<()> {
    super::test_lifecycle::<Host, _>("observability-failures", Host::qualify_diagnostic_failures)
}

impl Platform for Host {
    fn source(&self) -> &Path {
        self.shared.source()
    }

    fn setup(name: &str) -> TestResult<Self> {
        Ok(Self {
            shared: Shared::setup(name)?,
            bundle: None,
            init_pid: None,
            staged: false,
            admitted: false,
            mounts: Vec::new(),
        })
    }

    fn start_control(&mut self) -> TestResult<()> {
        self.shared.start_control()
    }

    fn start_node(&mut self) -> TestResult<()> {
        self.shared.start_node()
    }

    fn stop_node(&mut self) -> TestResult<()> {
        self.shared.stop_node()
    }

    fn install_policy(&mut self, name: &str) -> TestResult<()> {
        self.shared.install_policy(name)
    }

    fn sync_policy(&mut self) -> TestResult<()> {
        self.shared.sync_policy()
    }

    fn node_ready(&mut self) -> TestResult<()> {
        self.shared.node_ready()
    }

    fn start_actor(&mut self, name: &str, extra: &[&str]) -> TestResult<ProcessFixture> {
        ensure!(
            self.init_pid.is_none(),
            InvalidInputSnafu {
                path: self.shared.work(),
                reason: "the initial actor is already running",
            }
        );
        let protected = self.shared.protected();
        let rootfs = self.actor_root()?;
        let mut args = vec![OsString::from("/work")];
        args.extend(extra.iter().map(OsString::from));
        args.insert(0, OsString::from(format!("/fixtures/{name}")));
        let mut actor = ProcessFixture::held_pidns(
            Path::new("/usr/bin/python3"),
            args,
            self.shared.cgroup(),
            &rootfs,
            Path::new(name),
        )?;
        let pid = actor.id();
        self.init_pid = Some(pid);
        if protected {
            self.stage()?;
            self.admit(pid)?;
            self.stage_entries(&rootfs)?;
        }
        actor.release()?;
        if let Err(source) = actor.ready() {
            if protected {
                return Err(format!("{source}; identity health: {:?}", self.health()?).into());
            }
            return Err(source.into());
        }
        if protected {
            self.running(pid)?;
        }
        Ok(actor)
    }

    fn add_actor(&mut self, command: &str, args: &[&str]) -> TestResult<ProcessFixture> {
        self.start_entry(command, args)
    }

    fn approve(&mut self, command: &str, args: &[&str]) -> TestResult<()> {
        self.shared.approve(command, args)
    }

    fn place(&mut self, pid: u32) -> TestResult<()> {
        self.shared.place(pid)
    }

    fn stage(&mut self) -> TestResult<()> {
        if self.staged {
            return Ok(());
        }
        self.shared.observe()?;
        let request = self
            .shared
            .request(RuntimeAdmissionOperationV1::StageRuntimeFacts, None)?;
        let response = self.shared.submit(&request)?;
        ensure!(
            response.allowed && response.reason_code == "RUNTIME_FACTS_STAGING",
            InvalidInputSnafu {
                path: self.shared.admit_path(),
                reason: format!("Node rejected runtime staging: {response:?}"),
            }
        );
        self.staged = true;
        Ok(())
    }

    fn admit(&mut self, pid: u32) -> TestResult<()> {
        if self.admitted {
            ensure!(
                self.init_pid == Some(pid),
                InvalidInputSnafu {
                    path: self.shared.admit_path(),
                    reason: "the admitted actor PID changed",
                }
            );
            return Ok(());
        }
        let request = self
            .shared
            .request(RuntimeAdmissionOperationV1::PrepareContainer, Some(pid))?;
        let response = self.shared.submit(&request)?;
        ensure!(
            response.allowed && response.reason_code == "ACTIVE_POLICY_AND_BINDING_VERIFIED",
            InvalidInputSnafu {
                path: self.shared.admit_path(),
                reason: format!("Node rejected runtime preparation: {response:?}"),
            }
        );
        self.admitted = true;
        Ok(())
    }

    fn running(&mut self, pid: u32) -> TestResult<()> {
        self.shared.running(pid)
    }

    fn health(&self) -> TestResult<mithril_node::ReconciliationReportV1> {
        self.shared.health()
    }

    fn move_task(&mut self, pid: u32, name: &str) -> TestResult<Task> {
        self.shared.move_task(pid, name)
    }

    fn task(&mut self, pid: u32, name: &str) -> TestResult<Task> {
        self.shared.task(pid, name)
    }

    fn wait_exec(
        &mut self,
        actor: &mut ProcessFixture,
        pid: u32,
        cookie: u64,
        before: &Task,
        name: &str,
    ) -> TestResult<Task> {
        self.shared.wait_exec(actor, pid, cookie, before, name)
    }

    fn wait_pid_exec(
        &mut self,
        pid: u32,
        cookie: u64,
        before: &Task,
        name: &str,
    ) -> TestResult<Task> {
        self.shared.wait_pid_exec(pid, cookie, before, name)
    }

    fn recovered(&mut self, pid: u32, name: &str) -> TestResult<Task> {
        self.shared.recovered(pid, name)
    }

    fn snapshot(&self) -> TestResult<MithrilObservationSnapshot> {
        self.shared.snapshot()
    }

    fn maps(&self) -> (&Path, &KernelStateReader) {
        self.shared.maps()
    }

    fn work(&self) -> &Path {
        self.shared.work()
    }

    fn actor_group(&self) -> TestResult<&Path> {
        Ok(self.shared.cgroup())
    }

    fn stop(&mut self) -> TestResult<()> {
        self.close()
    }
}

impl Drop for Host {
    fn drop(&mut self) {
        let _result = self.close();
    }
}
