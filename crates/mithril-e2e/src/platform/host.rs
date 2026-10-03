use std::ffi::OsString;
use std::fs::{self, File};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use erebor_interceptor::KernelStateReader;
use erebor_runtime_ipc::v1::MithrilObservationSnapshot;
use snafu::{ensure, ResultExt as _};

use super::shared::Shared;
use super::{GroupActor, Labels, Platform, Task, TestResult, PROCESS_FIXTURES};
use crate::error::{InvalidInputSnafu, IoSnafu};
use crate::physical::ProbeDirectory;
use crate::process::ProcessFixture;

pub(crate) struct Host {
    shared: Shared,
    bundles: Vec<ProbeDirectory>,
    init_pid: Option<u32>,
    staged: bool,
    admitted: bool,
    mounts: Vec<PathBuf>,
}

impl Host {
    #[cfg(test)]
    fn capture_frames(spool: &Path) -> TestResult<Vec<mithril_control::TraceFrameV1>> {
        use std::io::Read as _;

        let mut bytes = Vec::new();
        File::open(spool.join("output.jsonl"))?
            .take(5 * 1024 * 1024)
            .read_to_end(&mut bytes)?;
        assert!(
            bytes.contains(&0),
            "the fixture output exceeds its read bound"
        );
        bytes
            .split_inclusive(|byte| *byte == b'\n')
            .take_while(|line| line.first() != Some(&0) && line.last() == Some(&b'\n'))
            .map(|line| {
                Ok(serde_json::from_slice::<mithril_control::TraceFrameV1>(
                    line,
                )?)
            })
            .collect()
    }

    #[cfg(test)]
    fn qualify_storage() -> TestResult<()> {
        use araphor_data::AnalysisCommitStage;
        use mithril_control::{
            TraceBatchV1, TraceCleanupV1, TraceExchangeV1, TraceFrameKindV1, TraceFrameV1,
            TraceOwner, TraceReadAccessV1, TraceRecipeV1, TraceRequestV1, TraceTerminalReasonV1,
            TraceTerminalV1, TraceUploadV1,
        };
        use std::io::Write as _;
        use std::sync::{
            atomic::{AtomicBool, Ordering},
            Arc,
        };
        use std::time::{Instant, SystemTime, UNIX_EPOCH};

        const GIB: u64 = 1024 * 1024 * 1024;
        let disk = PathBuf::from(std::env::var("MITHRIL_TEST_TRACE_DISK")?);
        assert_eq!(disk.parent(), Some(Path::new("/tmp")));
        assert!(disk
            .file_name()
            .ok_or("the fault filesystem has no name")?
            .to_string_lossy()
            .starts_with("araphor-observability-disk-"));
        assert_eq!(fs::canonicalize(&disk)?, disk);
        assert!(!fs::symlink_metadata(&disk)?.file_type().is_symlink());
        assert_eq!(rustix::fs::statfs(&disk)?.f_type, libc::TMPFS_MAGIC);
        let volume = rustix::fs::statvfs(&disk)?;
        assert_eq!(volume.f_blocks * volume.f_frsize, GIB);
        assert_eq!(fs::read_dir(&disk)?.count(), 0);
        let owned = ProbeDirectory::create(&disk.join("capture"))?;
        let path = owned.path().join("analysis");
        let config: mithril_node::NodeTraceConfigV1 =
            serde_json::from_slice(&fs::read(std::env::var("MITHRIL_TRACE_CONFIG")?)?)?;
        config.validate()?;
        let proof = PathBuf::from(std::env::var("MITHRIL_TRACE_PROOF")?);
        if proof.exists() {
            return Err("the storage proof already exists".into());
        }
        let mut env = Self::setup("observability-storage")?;
        env.shared.configure_diagnostics(config)?;
        env.shared.configure_diagnostic_store(&path)?;
        env.start_control()?;
        env.shared.enable_diagnostic_partition()?;
        let policy = serde_json::from_slice(&fs::read(super::policy_path(
            env.source(),
            "policy_replace_policy.json",
        )?)?)?;
        let labels = super::policy_labels(&policy)?;
        let mut init = env.start_actor("ready.py", &[], &labels)?;
        env.place(init.id())?;
        fs::create_dir(env.work().join("second"))?;
        fs::create_dir(env.work().join("third"))?;
        env.install_policy("policy_replace_policy.json")?;
        env.start_node()?;
        env.sync_policy()?;
        env.node_ready()?;
        env.running(init.id())?;
        env.recovered(init.id(), "diagnostic storage workload")?;
        let mut first = env.add_actor(
            "python",
            &[
                "/fixtures/proc_read.py",
                "/work",
                "/fixtures/policy_replace.py",
            ],
        )?;
        first.ready()?;
        env.place(first.id())?;
        let mut second = env.add_actor(
            "python",
            &[
                "/fixtures/proc_read.py",
                "/work/second",
                "/fixtures/policy_replace.py",
            ],
        )?;
        second.ready()?;
        env.place(second.id())?;
        let mut third = env.add_actor(
            "python",
            &[
                "/fixtures/proc_read.py",
                "/work/third",
                "/fixtures/policy_replace.py",
            ],
        )?;
        third.ready()?;
        env.place(third.id())?;
        let initial = env.snapshot()?;
        let first_work = env.work().to_owned();
        let mut denials = vec![env.capture_denial(
            &mut first,
            &first_work,
            &initial,
            "denial before the storage fault",
        )?];
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        let now = || -> TestResult<u64> {
            Ok(u64::try_from(
                SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos(),
            )?)
        };
        let (control, fact) = env.shared.diagnostic_context()?;
        let grant = mithril_control::TraceExecutionGrantV1 {
            tenant_id: *uuid::Uuid::parse_str(super::shared::TENANT_ID)?.as_bytes(),
            grant_id: [7; 16],
            principal: "qualification".into(),
            namespace_uids: [fact.namespace_uid.clone()].into(),
            node_ids: [fact.node_id.clone()].into(),
            recipe_digests: [TraceRecipeV1::FailedOpens.digest()?].into(),
            host_diagnostic: false,
            valid_until_unix_ns: now()? + 600_000_000_000,
        };
        let access = TraceReadAccessV1 {
            tenant_id: grant.tenant_id,
            namespace_uids: grant.namespace_uids.clone(),
            node_ids: grant.node_ids.clone(),
            host_sensitive: false,
            valid_until_unix_ns: grant.valid_until_unix_ns,
            revoked: false,
        };
        let targets = runtime.block_on(control.resolve_trace_targets(vec![fact], &grant))?;
        let target = targets
            .first()
            .and_then(|item| item.target.clone())
            .ok_or("the diagnostic storage target is unavailable")?;
        let request = TraceRequestV1 {
            tenant_id: grant.tenant_id,
            request_id: *uuid::Uuid::new_v4().as_bytes(),
            source: TraceRecipeV1::FailedOpens.manifest()?.source,
            targets: vec![target],
            unresolved: Vec::new(),
            collection_seconds: 30,
        };
        env.shared.partition_diagnostics(true)?;
        control.accept_trace(request.clone(), grant, None)?;
        let data = control.analysis_store().ok_or("missing analysis store")?;
        let owner = TraceOwner::new(data.clone());
        let (_, accepted) = owner.read(request.tenant_id, request.request_id, &access, now()?)?;
        let id = accepted.execution_id(0)?;
        let (_, intent) = data
            .trace_intent(request.tenant_id, request.request_id)?
            .ok_or("the diagnostic intent is absent")?;
        let identity = intent
            .bindings
            .first()
            .ok_or("the diagnostic binding is absent")?
            .identity
            .clone();
        assert_eq!(identity.execution_id, id);
        let before = data.trace_receipt(&identity)?;
        assert!(before.as_ref().is_none_or(|receipt| {
            receipt.last_sequence == 0
                && receipt.output_bytes == 0
                && receipt.commit_revision == 0
                && receipt.terminal.is_none()
        }));
        let spool = env.shared.diagnostic_spool(id);
        let deadline = Instant::now() + Duration::from_secs(20);
        while Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(20));
        }
        env.shared.partition_diagnostics(false)?;
        let marker = env.shared.output().join("trace-store.ready");
        let deadline = Instant::now() + Duration::from_secs(20);
        while !marker.exists() {
            if Instant::now() >= deadline {
                return Err("the durable diagnostic intent marker is absent".into());
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        let live = env.snapshot()?;
        let (connector, registration) = env.shared.diagnostic_connector(&live)?;
        env.shared.partition_diagnostics(true)?;
        fs::write(env.shared.output().join("trace-store.release"), b"release")?;
        let deadline = Instant::now() + Duration::from_secs(15);
        let frames = loop {
            let frames = Self::capture_frames(&spool)?;
            if frames.iter().any(|frame| {
                frame.kind == TraceFrameKindV1::Diagnostic
                    && frame.bytes == b"__BPFTRACE_NOTIFY_PROBES_ATTACHED\n"
            }) {
                break frames;
            }
            if Instant::now() >= deadline || spool.join("terminal.json").exists() {
                return Err("capture did not attach before the storage fault".into());
            }
            std::thread::sleep(Duration::from_millis(20));
        };
        let attached = now()?;
        assert!(attached < accepted.deadline_unix_ns);
        assert!(accepted.deadline_unix_ns < attached + 30_000_000_000);
        assert!(!spool.join("terminal.json").exists());
        assert_eq!(data.trace_receipt(&identity)?, before);
        let frame = frames.first().ok_or("the Node output is empty")?.clone();
        frame.validate()?;
        assert_eq!(frame.execution_id, id);
        assert_eq!(frame.sequence, 1);
        let exchange = TraceExchangeV1 {
            retained: vec![id],
            resolved: None,
            output: Some(TraceUploadV1 {
                request_id: request.request_id,
                target_index: 0,
                original_node_boot_id: identity.node_boot_id,
                batch: TraceBatchV1 {
                    execution_id: id,
                    frames: vec![frame],
                    terminal: None,
                },
            }),
        };
        let mut trust = mithril_node::TrustCache::load(&env.shared.output().join("node"))?;
        let mut connection = runtime.block_on(connector.connect(registration, true, &mut trust))?;
        let filler = tempfile::NamedTempFile::new_in(&disk)?;
        let mut file = filler.as_file().try_clone()?;
        let fill_path = filler.path().to_owned();
        let filled = Arc::new(AtomicBool::new(false));
        let synced = Arc::new(AtomicBool::new(false));
        let did_fill = filled.clone();
        let did_sync = synced.clone();
        let hooked = data.clone();
        data.set_commit_hook(AnalysisCommitStage::BeforeAppend, move || {
            let mut full = false;
            let block = vec![0_u8; 64 * 1024];
            for _ in 0..=GIB / (64 * 1024) {
                match file.write_all(&block) {
                    Ok(()) => {}
                    Err(error) if error.raw_os_error() == Some(libc::ENOSPC) => {
                        full = true;
                        break;
                    }
                    Err(source) => {
                        return Err(araphor_data::Error::Io {
                            path: fill_path.clone(),
                            source,
                            location: snafu::Location::default(),
                        });
                    }
                }
            }
            assert!(full, "the bounded filler did not reach ENOSPC");
            file.sync_all().map_err(|source| araphor_data::Error::Io {
                path: fill_path,
                source,
                location: snafu::Location::default(),
            })?;
            did_fill.store(true, Ordering::Release);
            hooked.set_commit_hook(AnalysisCommitStage::AfterSync, move || {
                did_sync.store(true, Ordering::Release);
                Ok(())
            })?;
            Ok(())
        })?;
        let failure = match runtime.block_on(connection.exchange_diagnostics(&exchange)) {
            Err(mithril_node::Error::ControlRpc { source, .. })
                if source.code() == tonic::Code::Unavailable
                    && source.message().contains("No space left on device")
                    && source.message().contains("os error 28")
                    && source.message().contains("/analysis/segments/") =>
            {
                source.message().to_owned()
            }
            other => {
                return Err(format!("the real append did not fail without ACK: {other:?}").into())
            }
        };
        assert!(filled.load(Ordering::Acquire));
        assert!(!synced.load(Ordering::Acquire));
        assert_eq!(rustix::fs::statvfs(&disk)?.f_bavail, 0);
        assert!(!data.storage_health()?.write_ready);
        assert!(!spool.join("terminal.json").exists());
        denials.push(env.capture_denial(
            &mut second,
            &first_work.join("second"),
            &initial,
            "denial while the store is full",
        )?);
        let deadline = Instant::now() + Duration::from_secs(30);
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
                return Err("the full store did not preserve bounded local expiry".into());
            }
            std::thread::sleep(Duration::from_millis(20));
        };
        assert_eq!(terminal.reason, TraceTerminalReasonV1::Deadline);
        assert_eq!(terminal.cleanup, TraceCleanupV1::Verified);
        assert_eq!(terminal.execution_id, id);
        assert!(terminal.output_incomplete && terminal.kernel_lost_events.is_none());
        let frames = Self::capture_frames(&spool)?;
        for (index, frame) in frames.iter().enumerate() {
            frame.validate()?;
            assert_eq!(frame.execution_id, id);
            assert_eq!(frame.sequence, index as u64 + 1);
        }
        assert_eq!(terminal.last_sequence, frames.len() as u64);
        assert!(terminal.output_bytes <= mithril_control::MAX_TRACE_OUTPUT_BYTES);
        assert!(frames.len() <= 4096);
        assert_eq!(
            fs::metadata(spool.join("output.jsonl"))?.len(),
            68 * 1024 * 1024
        );
        assert!(!spool.join("ack.json").exists());
        let stopped = env.snapshot()?;
        Self::capture_health(&initial, &stopped)?;
        drop(connection);
        env.shared.stop_node()?;
        drop(owner);
        drop(data);
        drop(control);
        env.shared.stop_control()?;
        filler.close()?;
        env.start_control()?;
        let (control, _) = env.shared.diagnostic_context()?;
        let data = control
            .analysis_store()
            .ok_or("missing recovered analysis store")?;
        let recovered_receipt = data
            .trace_receipt(&identity)?
            .ok_or("the recovered terminal reservation is absent")?;
        assert_eq!(recovered_receipt.last_sequence, 0);
        assert_eq!(recovered_receipt.output_bytes, 0);
        assert_eq!(recovered_receipt.commit_revision, 0);
        assert!(recovered_receipt.terminal.is_none());
        let owner = TraceOwner::new(data.clone());
        assert_eq!(
            owner
                .read(request.tenant_id, request.request_id, &access, now()?)?
                .1,
            accepted
        );
        env.start_node()?;
        env.node_ready()?;
        let resumed = env.capture_recovery(&stopped)?;
        let deadline = Instant::now() + Duration::from_secs(50);
        while !spool.join("ack.json").exists() {
            if Instant::now() >= deadline {
                return Err("recovered output was not acknowledged through current mTLS".into());
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        let ack: TraceTerminalV1 = serde_json::from_slice(&fs::read(spool.join("ack.json"))?)?;
        assert_eq!(ack, terminal);
        assert_eq!(fs::metadata(spool.join("output.jsonl"))?.len(), 0);
        let mut output = Vec::new();
        let mut saved = None;
        loop {
            let after = output
                .last()
                .map_or(0, |frame: &TraceFrameV1| frame.sequence);
            let batches = owner.output(
                request.tenant_id,
                request.request_id,
                0,
                &access,
                now()?,
                after,
            )?;
            if batches.is_empty() {
                break;
            }
            for batch in batches {
                output.extend(batch.frames);
                saved = batch.terminal.or(saved);
            }
            if saved.is_some() {
                break;
            }
        }
        assert_eq!(output, frames);
        assert_eq!(saved.as_ref(), Some(&terminal));
        assert_eq!(
            output
                .iter()
                .filter(|frame| frame.bytes == b"__BPFTRACE_NOTIFY_PROBES_ATTACHED\n")
                .count(),
            1
        );
        let current = env.snapshot()?;
        let (connector, registration) = env.shared.diagnostic_connector(&current)?;
        let mut trust = mithril_node::TrustCache::load(&env.shared.output().join("node"))?;
        let mut connection = runtime.block_on(connector.connect(registration, true, &mut trust))?;
        let reply = runtime.block_on(connection.exchange_diagnostics(&exchange))?;
        assert_eq!(
            runtime.block_on(connection.exchange_diagnostics(&exchange))?,
            reply
        );
        let acknowledgement = reply.acknowledgement.ok_or("the exact replay has no ACK")?;
        assert_eq!(acknowledgement.execution_id, id);
        assert_eq!(acknowledgement.last_sequence, terminal.last_sequence);
        assert_eq!(acknowledgement.terminal.as_ref(), Some(&terminal));
        denials.push(env.capture_denial(
            &mut third,
            &first_work.join("third"),
            &resumed,
            "denial after storage recovery",
        )?);
        fs::write(
            &proof,
            serde_json::to_vec_pretty(&serde_json::json!({
                "case": "data-store-full", "accepted": accepted,
                "append_error": failure, "before_append_ran": true, "after_sync_ran": false,
                "raw_receipt_before": before.as_ref().map(|receipt| receipt.last_sequence),
                "raw_receipt_before_replay": recovered_receipt.last_sequence,
                "frames": output, "terminal": terminal, "acknowledgement": acknowledgement,
                "attached_unix_ns": attached, "dispatch_delay_seconds": 20,
                "frame_upload_ack_on_failure": false, "physical_denials": denials.len(),
                "denial_events": denials,
                "enforcement_before_restart": Self::capture_evidence(&stopped),
                "enforcement_after_restart": Self::capture_evidence(&resumed),
                "spool_max_bytes": 68 * 1024 * 1024, "discovery_enabled": false
            }))?,
        )?;
        drop(connection);
        for name in ["release", "second/release", "third/release"] {
            fs::write(env.work().join(name), b"release")?;
        }
        first.stop()?;
        second.stop()?;
        third.stop()?;
        init.stop()?;
        env.shared.stop_node()?;
        drop(owner);
        drop(data);
        drop(control);
        env.shared.stop_control()?;
        env.stop()?;
        owned.cleanup()?;
        Ok(())
    }

    #[cfg(test)]
    fn qualify_restart() -> TestResult<()> {
        use crate::observability::ResourceSnapshot;
        use mithril_control::{
            TraceCleanupV1, TraceExecutionGrantV1, TraceFrameKindV1, TraceOwner, TraceReadAccessV1,
            TraceRecipeV1, TraceRequestV1, TraceTerminalReasonV1,
        };
        use rustix::process::{pidfd_open, pidfd_send_signal, Pid, PidfdFlags, Signal};
        use std::os::unix::process::ExitStatusExt as _;
        use std::time::{Instant, SystemTime, UNIX_EPOCH};

        let mode = std::env::var("MITHRIL_TRACE_RESTART")?;
        if !matches!(mode.as_str(), "before" | "after") {
            return Err("the restart stage must be before or after".into());
        }
        let config: mithril_node::NodeTraceConfigV1 =
            serde_json::from_slice(&fs::read(std::env::var("MITHRIL_TRACE_CONFIG")?)?)?;
        config.validate()?;
        let proof = PathBuf::from(std::env::var("MITHRIL_TRACE_PROOF")?);
        if proof.exists() {
            return Err("the restart proof already exists".into());
        }
        let mut env = Self::setup("observability-restart")?;
        env.shared.configure_diagnostics(config)?;
        env.start_control()?;
        let policy = serde_json::from_slice(&fs::read(super::policy_path(
            env.source(),
            "policy_replace_policy.json",
        )?)?)?;
        let labels = super::policy_labels(&policy)?;
        let mut init = env.start_actor("ready.py", &[], &labels)?;
        env.place(init.id())?;
        fs::create_dir(env.work().join("second"))?;
        env.install_policy("policy_replace_policy.json")?;
        env.start_node()?;
        env.sync_policy()?;
        env.node_ready()?;
        env.running(init.id())?;
        env.recovered(init.id(), "diagnostic restart workload")?;
        let mut first = env.add_actor(
            "python",
            &[
                "/fixtures/proc_read.py",
                "/work",
                "/fixtures/policy_replace.py",
            ],
        )?;
        first.ready()?;
        env.place(first.id())?;
        let mut second = env.add_actor(
            "python",
            &[
                "/fixtures/proc_read.py",
                "/work/second",
                "/fixtures/policy_replace.py",
            ],
        )?;
        second.ready()?;
        env.place(second.id())?;
        let initial = env.snapshot()?;
        Self::capture_health(&initial, &initial)?;
        let (control, fact) = env.shared.diagnostic_context()?;
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
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
            .and_then(|item| item.target.clone())
            .ok_or("the diagnostic restart target is unavailable")?;
        let mut node = env.shared.diagnostic_process()?;
        let started = env.capture_recovery(&initial)?;
        let first_work = env.work().to_owned();
        let mut denials = vec![env.capture_denial(
            &mut first,
            &first_work,
            &started,
            "denial before Node restart",
        )?];
        let baseline = ResourceSnapshot::read()?;
        let request = TraceRequestV1 {
            tenant_id: tenant,
            request_id: *uuid::Uuid::new_v4().as_bytes(),
            source: TraceRecipeV1::FailedOpens.manifest()?.source,
            targets: vec![target],
            unresolved: Vec::new(),
            collection_seconds: 30,
        };
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            match control.accept_trace(request.clone(), grant.clone(), None) {
                Ok(_) => break,
                Err(error)
                    if error.code() == tonic::Code::Unavailable && Instant::now() < deadline =>
                {
                    node.ensure_running("diagnostic acceptance")?;
                    std::thread::sleep(Duration::from_millis(20));
                }
                Err(error) => return Err(error.into()),
            }
        }
        let owner = TraceOwner::new(control.analysis_store().ok_or("missing analysis store")?);
        let (_, accepted) = owner.read(tenant, request.request_id, &access, now()?)?;
        let id = accepted.execution_id(0)?;
        let spool = env.shared.diagnostic_spool(id);
        let marker = env.shared.output().join("trace-intent.ready");
        let mut prefix = Vec::new();
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            node.ensure_running("diagnostic crash boundary")?;
            if mode == "before" && marker.exists() {
                break;
            }
            if mode == "after" {
                let after = prefix
                    .last()
                    .map_or(0, |frame: &mithril_control::TraceFrameV1| frame.sequence);
                for batch in owner.output(tenant, request.request_id, 0, &access, now()?, after)? {
                    if batch.terminal.is_some() {
                        return Err("capture ended before the crash boundary".into());
                    }
                    prefix.extend(batch.frames);
                }
                if prefix.iter().any(|frame| {
                    frame.kind == TraceFrameKindV1::Diagnostic
                        && frame.bytes == b"__BPFTRACE_NOTIFY_PROBES_ATTACHED\n"
                }) {
                    break;
                }
            }
            if Instant::now() >= deadline {
                return Err("the diagnostic crash boundary was not reached".into());
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        let attached = ResourceSnapshot::read()?;
        let programs = attached
            .programs
            .difference(&baseline.programs)
            .copied()
            .collect::<Vec<_>>();
        let maps = attached
            .maps
            .difference(&baseline.maps)
            .copied()
            .collect::<Vec<_>>();
        let links = attached
            .links
            .difference(&baseline.links)
            .copied()
            .collect::<Vec<_>>();
        if mode == "before" {
            assert!(programs.is_empty() && maps.is_empty() && links.is_empty());
        } else {
            assert!(
                !programs.is_empty(),
                "the attach marker has no observed BPF programs"
            );
        }
        let stopped = env.snapshot()?;
        Self::capture_health(&started, &stopped)?;
        let pid = Pid::from_raw(i32::try_from(node.id())?).ok_or("invalid diagnostic Node PID")?;
        let handle = pidfd_open(pid, PidfdFlags::empty())?;
        pidfd_send_signal(&handle, Signal::KILL)?;
        assert_eq!(
            node.wait_exit("diagnostic Node crash", Duration::from_secs(10))?
                .signal(),
            Some(libc::SIGKILL)
        );
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let current = ResourceSnapshot::read()?;
            if programs.iter().all(|id| !current.programs.contains(id))
                && maps.iter().all(|id| !current.maps.contains(id))
                && links.iter().all(|id| !current.links.contains(id))
            {
                break;
            }
            if Instant::now() >= deadline {
                return Err("diagnostic resources survived Node death".into());
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        // Do not let fixture cleanup supply the parent-death result.
        node.stop()?;
        let mut recovered = env.shared.diagnostic_process()?;
        let resumed = env.capture_recovery(&stopped)?;
        let deadline = Instant::now() + Duration::from_secs(20);
        while !spool.join("ack.json").exists() {
            recovered.ensure_running("recovered diagnostic acknowledgement")?;
            if Instant::now() >= deadline {
                return Err("recovered diagnostic terminal was not acknowledged".into());
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        let mut frames = Vec::new();
        let mut terminal = None;
        loop {
            let after = frames
                .last()
                .map_or(0, |frame: &mithril_control::TraceFrameV1| frame.sequence);
            let batches = owner.output(tenant, request.request_id, 0, &access, now()?, after)?;
            if batches.is_empty() {
                break;
            }
            for batch in batches {
                frames.extend(batch.frames);
                terminal = batch.terminal.or(terminal);
            }
            if terminal.is_some() {
                break;
            }
        }
        let terminal = terminal.ok_or("missing recovered diagnostic terminal")?;
        assert_eq!(terminal.reason, TraceTerminalReasonV1::NodeRestarted);
        assert_eq!(terminal.cleanup, TraceCleanupV1::Unknown);
        assert!(terminal.output_incomplete && frames.starts_with(&prefix));
        assert_eq!(terminal.last_sequence, frames.len() as u64);
        assert_eq!(terminal.execution_id, id);
        let (_, retained) = owner.read(tenant, request.request_id, &access, now()?)?;
        assert_eq!(retained, accepted);
        assert_eq!(
            frames
                .iter()
                .filter(|frame| frame.bytes == b"__BPFTRACE_NOTIFY_PROBES_ATTACHED\n")
                .count(),
            usize::from(mode == "after")
        );
        denials.push(env.capture_denial(
            &mut second,
            &first_work.join("second"),
            &resumed,
            "denial after Node restart",
        )?);
        fs::write(
            &proof,
            serde_json::to_vec_pretty(&serde_json::json!({
                "case": "node-restart", "stage": mode, "accepted": accepted,
                "frames": frames, "terminal": terminal, "observed_programs": programs,
                "observed_maps": maps, "observed_links": links,
                "cleanup_observed_before_fixture_stop": true, "physical_denials": denials.len(),
                "denial_events": denials,
                "enforcement_before_handoff": Self::capture_evidence(&initial),
                "enforcement_after_handoff": Self::capture_evidence(&started),
                "enforcement_before_restart": Self::capture_evidence(&stopped),
                "enforcement_after_restart": Self::capture_evidence(&resumed)
            }))?,
        )?;
        fs::write(env.work().join("release"), b"release")?;
        fs::write(env.work().join("second/release"), b"release")?;
        first.stop()?;
        second.stop()?;
        init.stop()?;
        let pid =
            Pid::from_raw(i32::try_from(recovered.id())?).ok_or("invalid recovered Node PID")?;
        let handle = pidfd_open(pid, PidfdFlags::empty())?;
        pidfd_send_signal(&handle, Signal::TERM)?;
        assert!(recovered
            .wait_exit("recovered Node shutdown", Duration::from_secs(30))?
            .success());
        recovered.stop()?;
        env.stop()
    }

    #[cfg(test)]
    fn qualify_diagnostic_failures() -> TestResult<()> {
        use mithril_control::{
            DiscoveryDigestV1, TraceApprovalV1, TraceCleanupV1, TraceExecutionGrantV1,
            TraceFrameKindV1, TraceReadAccessV1, TraceRecipeV1, TraceRequestV1, TraceSourceV1,
            TraceTerminalReasonV1, TraceTerminalV1,
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
        let policy = serde_json::from_slice(&fs::read(super::policy_path(
            env.source(),
            "policy_replace_policy.json",
        )?)?)?;
        let labels = super::policy_labels(&policy)?;
        let mut init = env.start_actor("ready.py", &[], &labels)?;
        env.place(init.id())?;
        env.install_policy("policy_replace_policy.json")?;
        env.start_node()?;
        env.sync_policy()?;
        env.node_ready()?;
        env.running(init.id())?;
        env.recovered(init.id(), "diagnostic failure workload")?;
        let initial = env.snapshot()?;
        Self::capture_health(&initial, &initial)?;
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
            control.analysis_store().ok_or("missing analysis store")?,
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
            let mut work = env.work().join(case);
            fs::create_dir(&work)?;
            let command = format!("/work/{case}");
            let mut probe = env.add_actor(
                "python",
                &[
                    "/fixtures/proc_read.py",
                    &command,
                    "/fixtures/policy_replace.py",
                ],
            )?;
            probe.ready()?;
            env.place(probe.id())?;
            let mut denials = Vec::new();
            let mut coverage = initial.clone();
            let request_id = *uuid::Uuid::new_v4().as_bytes();
            let mut request = TraceRequestV1 {
                tenant_id: tenant,
                request_id,
                source: TraceRecipeV1::FailedOpens.manifest()?.source,
                targets: vec![target.clone()],
                unresolved: Vec::new(),
                collection_seconds: 30,
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
            if case == "partition" {
                env.shared.partition_diagnostics(true)?;
            }
            control.accept_trace(request, execution_grant, approval)?;
            let (_, accepted) = owner.read(tenant, request_id, &access, now()?)?;
            let id = accepted.execution_id(0)?;
            let spool = env.shared.diagnostic_spool(id);
            let mut release_at = None;
            if case == "partition" {
                let deadline = Instant::now() + Duration::from_secs(25);
                while Instant::now() < deadline {
                    assert!(
                        !spool.exists(),
                        "partition dispatched before transport repair"
                    );
                    std::thread::sleep(Duration::from_millis(20));
                }
                assert!(
                    !spool.exists(),
                    "partition dispatched during the initial hold"
                );
                release_at = Some((Instant::now(), now()?));
                env.shared.partition_diagnostics(false)?;
            }
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
                    frame.kind == TraceFrameKindV1::Diagnostic
                        && frame.bytes == b"__BPFTRACE_NOTIFY_PROBES_ATTACHED\n"
                }) {
                    break;
                }
                if Instant::now() >= deadline {
                    return Err(format!("{case}: attachment absent: {frames:?}").into());
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            let original_pid = probe.id();
            match case {
                "partition" => env.shared.partition_diagnostics(true)?,
                "revocation" => {
                    owner.cancel(tenant, request_id, "qualification", true)?;
                    assert!(owner
                        .output(tenant, request_id, 0, &access, now()?, after)
                        .is_err());
                }
                "retirement" => {
                    denials.push(env.capture_denial(
                        &mut probe,
                        &work,
                        &coverage,
                        "diagnostic retirement denial",
                    )?);
                    coverage = env.snapshot()?;
                    fs::write(work.join("release"), b"release")?;
                    probe.stop()?;
                    init.stop()?;
                    env.shared.retire_diagnostic_runtime()?;
                }
                _ => {}
            }
            let deadline = Instant::now()
                + Duration::from_nanos(accepted.deadline_unix_ns.saturating_sub(now()?))
                + Duration::from_secs(7);
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
            let terminal_at = now()?;
            let pending = if let Some((released, stamp)) = release_at {
                assert!(stamp > accepted.accepted_unix_ns + 15_000_000_000);
                assert!(terminal_at >= accepted.deadline_unix_ns);
                assert!(
                    Instant::now()
                        < released
                            + Duration::from_secs(accepted.request.collection_seconds.into()),
                    "partition reached the backend collection timeout"
                );
                assert!(terminal.output_incomplete);
                assert!(!spool.join("ack.json").exists());
                assert!(owner
                    .output(tenant, request_id, 0, &access, now()?, after)?
                    .is_empty());
                let pending = Self::capture_frames(&spool)?;
                assert!(pending.starts_with(&frames));
                assert_eq!(pending.len() as u64, terminal.last_sequence);
                Some(pending)
            } else {
                None
            };
            if case == "retirement" {
                init = env.start_actor("ready.py", &[], &labels)?;
                env.place(init.id())?;
                work = env.work().join(case);
                fs::create_dir(&work)?;
                probe = env.add_actor(
                    "python",
                    &[
                        "/fixtures/proc_read.py",
                        &command,
                        "/fixtures/policy_replace.py",
                    ],
                )?;
                probe.ready()?;
                env.place(probe.id())?;
                coverage = env.capture_recovery(&coverage)?;
            }
            denials.push(env.capture_denial(
                &mut probe,
                &work,
                &coverage,
                "diagnostic failure denial",
            )?);
            let (_, protected) = env.shared.diagnostic_context()?;
            if case == "retirement" {
                assert_ne!(protected.pod_uid, target.fact.pod_uid);
                assert_ne!(protected.container_id, target.fact.container_id);
            }
            if case == "partition" {
                assert!(!spool.join("ack.json").exists());
                env.shared.partition_diagnostics(false)?;
            }
            let deadline = Instant::now() + Duration::from_secs(50);
            while !spool.join("ack.json").exists() {
                if Instant::now() >= deadline {
                    return Err(format!("{case}: terminal was not acknowledged").into());
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            let ack: TraceTerminalV1 = serde_json::from_slice(&fs::read(spool.join("ack.json"))?)?;
            assert_eq!(ack, terminal);
            if case != "revocation" {
                let mut replay = Vec::new();
                let mut cursor = 0;
                let mut retained = None;
                while retained.is_none() {
                    let batches = owner.output(tenant, request_id, 0, &access, now()?, cursor)?;
                    assert!(!batches.is_empty(), "the retained terminal is absent");
                    for batch in batches {
                        for frame in batch.frames {
                            assert_eq!(frame.execution_id, id);
                            assert_eq!(frame.sequence, cursor + 1);
                            cursor = frame.sequence;
                            replay.push(frame);
                        }
                        retained = batch.terminal.or(retained);
                    }
                }
                assert_eq!(retained, Some(terminal.clone()));
                assert!(replay.starts_with(&frames));
                assert_eq!(cursor, terminal.last_sequence);
                if let Some(pending) = pending {
                    assert_eq!(replay, pending);
                }
                assert_eq!(
                    replay
                        .iter()
                        .filter(|frame| {
                            frame.kind == TraceFrameKindV1::Diagnostic
                                && frame.bytes == b"__BPFTRACE_NOTIFY_PROBES_ATTACHED\n"
                        })
                        .count(),
                    1
                );
                let (_, retained) = owner.read(tenant, request_id, &access, now()?)?;
                assert_eq!(retained, accepted);
                frames = replay;
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
            records.push(serde_json::json!({
                "case": case, "accepted": accepted, "frames": frames, "terminal": terminal,
                "acknowledgement": ack,
                "transport_released_unix_ns": release_at.map(|(_, stamp)| stamp),
                "terminal_observed_unix_ns": terminal_at,
                "backend_collection_floor_unix_ns": release_at.map(|(_, stamp)| {
                    stamp + u64::from(accepted.request.collection_seconds) * 1_000_000_000
                }),
                "terminal_ack_absent_before_repair": case == "partition",
                "exact_spool_replay": case == "partition",
                "physical_denials": denials.len(), "denial_events": denials,
                "enforcement_before": Self::capture_evidence(&coverage),
                "enforcement_after": Self::capture_evidence(&env.snapshot()?),
                "retired_denial_pid": (case == "retirement").then_some(original_pid),
                "physical_denial_target": protected,
                "physical_denial_pid": probe.id(), "physical_denial_errno": libc::EACCES,
            }));
            fs::write(&proof, serde_json::to_vec_pretty(&records)?)?;
            fs::write(work.join("release"), b"release")?;
            probe.stop()?;
        }
        fs::write(env.work().join("release"), b"release")?;
        init.stop()?;
        env.stop()
    }

    #[cfg(test)]
    fn capture_denial(
        &mut self,
        actor: &mut ProcessFixture,
        work: &Path,
        baseline: &MithrilObservationSnapshot,
        name: &str,
    ) -> TestResult<serde_json::Value> {
        use crate::effect::EffectCheck;
        use erebor_interceptor_abi::{KernelEffectFamilyV1, KernelEffectOperationV1};

        let task = self.task(actor.id(), name)?;
        assert_ne!(task.snapshot.admitted_entry_rule_id, 0);
        assert_eq!(
            task.entry_rule(self)?.target_role_id,
            task.snapshot.active_role_id
        );
        let generation = task.snapshot.profile_generation_ref_id;
        let check = EffectCheck::new(self, task)?;
        Self::capture_health(baseline, &self.snapshot()?)?;
        fs::write(work.join("act"), b"act")?;
        actor.wait_name(
            actor.id(),
            &format!("proc-read-{}", libc::EACCES),
            name,
            Duration::from_secs(5),
        )?;
        let event = check.wait(
            self,
            "EXACT_POLICY_DENY",
            KernelEffectFamilyV1::File,
            KernelEffectOperationV1::OpenRead,
            -libc::EACCES,
            name,
        )?;
        assert_eq!(event.profile_generation_ref_id, generation);
        Self::capture_health(baseline, &self.snapshot()?)?;
        Ok(serde_json::json!({
            "source_cpu_id": event.source_cpu_id, "source_sequence": event.source_sequence,
            "task_cookie": event.task_cookie, "reason": event.reason,
            "effect_family": event.effect_family, "operation": event.operation,
            "kernel_result": event.kernel_result, "active_role_id": event.active_role_id,
            "admitted_entry_rule_id": event.admitted_entry_rule_id,
            "profile_generation_ref_id": event.profile_generation_ref_id,
            "composite_atom_id": event.composite_atom_id,
            "exact_object_key_id": event.exact_object_key_id,
        }))
    }

    #[cfg(test)]
    fn capture_evidence(snapshot: &MithrilObservationSnapshot) -> serde_json::Value {
        let intervals = snapshot
            .coverage_intervals
            .iter()
            .map(|interval| {
                serde_json::json!({
                    "interval_id": interval.interval_id, "source_id": interval.source_id,
                    "source_epoch": interval.source_epoch, "cpu_id": interval.cpu_id,
                    "revision": interval.revision, "state": interval.state,
                    "gap_reasons": interval.gap_reasons,
                    "classifier_miss_count": interval.classifier_miss_count,
                    "unresolved": interval.unresolved, "lost": interval.lost,
                    "negative_claim_eligible": interval.negative_claim_eligible,
                })
            })
            .collect::<Vec<_>>();
        serde_json::json!({
            "node_boot_id": snapshot.node_boot_id, "label_epoch": snapshot.label_epoch,
            "program_digest": snapshot.program_digest, "kernel_ready": snapshot.kernel_ready,
            "effect_health_available": snapshot.effect_health_available,
            "negative_claim_eligible": snapshot.negative_claim_eligible,
            "lost_effects": snapshot.lost_effects, "unresolved_effects": snapshot.unresolved_effects,
            "decoder_errors": snapshot.decoder_errors, "evidence_errors": snapshot.evidence_errors,
            "wal_capacity_blocked": snapshot.wal_capacity_blocked,
            "reader_queue_dropped_events": snapshot.reader_queue_dropped_events,
            "coverage_intervals": intervals,
        })
    }

    #[cfg(test)]
    fn capture_boundary(
        before: &MithrilObservationSnapshot,
        after: &MithrilObservationSnapshot,
    ) -> TestResult<()> {
        if before.program_digest != after.program_digest {
            return Err("capture recovery changed the enforcement program".into());
        }
        if after.lost_effects != 0
            || after.unresolved_effects != 0
            || after.decoder_errors != 0
            || after.evidence_errors != 0
            || after.wal_capacity_blocked != 0
            || after.reader_queue_dropped_events != 0
        {
            return Err("capture recovery contains enforcement loss or errors".into());
        }
        for interval in &after.coverage_intervals {
            if interval.classifier_miss_count != 0 || interval.unresolved != 0 || interval.lost != 0
            {
                return Err("capture recovery contains classification or coverage loss".into());
            }
            let prior = before
                .coverage_intervals
                .iter()
                .find(|prior| prior.interval_id == interval.interval_id);
            if interval.gap_reasons.iter().any(|reason| {
                !matches!(reason.as_str(), "UNCLEAN_RESTART" | "READER_STOPPED")
                    && !prior.is_some_and(|prior| prior.gap_reasons.contains(reason))
            }) {
                return Err("capture recovery introduced an unexpected coverage gap".into());
            }
        }
        Ok(())
    }

    #[cfg(test)]
    fn capture_recovery(
        &self,
        before: &MithrilObservationSnapshot,
    ) -> TestResult<MithrilObservationSnapshot> {
        let deadline = std::time::Instant::now() + Duration::from_secs(20);
        loop {
            let current = match self.snapshot() {
                Ok(current) => current,
                Err(_) if std::time::Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(20));
                    continue;
                }
                Err(error) => return Err(error),
            };
            Self::capture_boundary(before, &current)?;
            if Self::capture_health(&current, &current).is_ok() {
                return Ok(current);
            }
            if std::time::Instant::now() >= deadline {
                return Err(
                    "capture recovery did not establish healthy enforcement coverage".into(),
                );
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    #[cfg(test)]
    fn capture_health(
        before: &MithrilObservationSnapshot,
        after: &MithrilObservationSnapshot,
    ) -> TestResult<()> {
        use erebor_runtime_ipc::v1::MithrilCoverageInterval;
        use std::collections::BTreeMap;

        if [before, after].iter().any(|snapshot| {
            !snapshot.kernel_ready
                || !snapshot.effect_health_available
                || !snapshot.negative_claim_eligible
                || snapshot.coverage_intervals.is_empty()
        }) || before.node_boot_id != after.node_boot_id
            || before.label_epoch != after.label_epoch
            || before.program_digest != after.program_digest
        {
            return Err("capture requires unchanged, healthy enforcement coverage".into());
        }
        let faults = [before, after].map(|snapshot| {
            (
                snapshot.lost_effects,
                snapshot.unresolved_effects,
                snapshot.decoder_errors,
                snapshot.evidence_errors,
                snapshot.wal_capacity_blocked,
                snapshot.reader_queue_dropped_events,
            )
        });
        if faults[0] != faults[1] {
            return Err("capture changed enforcement loss or error counters".into());
        }
        let counters = [before, after].map(|snapshot| {
            let mut sources: BTreeMap<_, &MithrilCoverageInterval> = BTreeMap::new();
            for interval in &snapshot.coverage_intervals {
                let key = (
                    interval.source_id.as_str(),
                    interval.source_epoch,
                    interval.cpu_id,
                );
                let prior = sources.entry(key).or_insert(interval);
                if interval.revision > prior.revision {
                    *prior = interval;
                }
            }
            sources
                .into_iter()
                .map(|(key, interval)| {
                    (
                        key,
                        (
                            interval.classifier_miss_count,
                            interval.unresolved,
                            interval.lost,
                        ),
                    )
                })
                .collect::<BTreeMap<_, _>>()
        });
        if counters[0] != counters[1] {
            return Err("capture changed classification or coverage loss counters".into());
        }
        for interval in &after.coverage_intervals {
            let prior = before
                .coverage_intervals
                .iter()
                .find(|prior| prior.interval_id == interval.interval_id);
            if interval
                .gap_reasons
                .iter()
                .any(|reason| !prior.is_some_and(|prior| prior.gap_reasons.contains(reason)))
            {
                return Err("capture introduced an enforcement coverage gap".into());
            }
        }
        Ok(())
    }

    #[cfg(test)]
    fn capture_route(mode: &str, run: usize) -> TestResult<(bool, bool, &str)> {
        if !matches!(mode, "plain" | "araphor" | "compare") {
            return Err("the trace mode must be plain, araphor or compare".into());
        }
        let on = run % 2 == 1;
        let capture = on || mode == "compare";
        let path = if mode == "compare" {
            if on {
                "araphor"
            } else {
                "plain"
            }
        } else {
            mode
        };
        Ok((on, capture, path))
    }

    #[cfg(test)]
    fn capture_parity(pairs: &[mithril_node::TraceQualificationPairV1]) -> TestResult<()> {
        if pairs.len() != 5
            || !pairs.iter().all(|pair| {
                pair.trace_off_p99_ns > 0
                    && pair.trace_on_p99_ns > 0
                    && pair.trace_on_p99_ns <= pair.trace_off_p99_ns
                    && pair.trace_off_lost_events == 0
                    && pair.trace_on_lost_events == 0
                    && pair.physical_decisions_equal
            })
        {
            return Err(
                "Araphor must not increase plain-bpftrace p99 or change enforcement".into(),
            );
        }
        Ok(())
    }

    #[cfg(test)]
    fn qualify_diagnostics() -> TestResult<()> {
        use crate::observability::{PlainCapture, ResourceSnapshot};
        use erebor_interceptor_abi::{KernelEffectFamilyV1, KernelEffectOperationV1};
        use mithril_control::{
            TraceExecutionGrantV1, TraceReadAccessV1, TraceRecipeV1, TraceRequestV1,
            TraceTerminalReasonV1,
        };
        use mithril_node::{NodeTraceConfigV1, TraceQualificationPairV1, TraceQualificationV1};
        use sha2::{Digest as _, Sha256};
        use std::collections::{BTreeMap, BTreeSet};
        use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
        let executable = PathBuf::from(std::env::var("MITHRIL_TRACE_EXECUTABLE")?);
        let mode = std::env::var("MITHRIL_TRACE_MODE").unwrap_or_else(|_| "araphor".into());
        Self::capture_route(&mode, 0)?;
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
        let mut config = NodeTraceConfigV1 {
            executable: executable.clone(),
            executable_sha256: digest,
            storage_reserve_bytes: 272 * 1024 * 1024,
            qualification: qualification.clone(),
        };
        env.shared.configure_diagnostics(config.clone())?;
        env.start_control()?;
        let policy = serde_json::from_slice(&fs::read(super::policy_path(
            env.source(),
            "policy_replace_policy.json",
        )?)?)?;
        let labels = super::policy_labels(&policy)?;
        let mut init = env.start_actor("ready.py", &[], &labels)?;
        env.place(init.id())?;
        env.install_policy("policy_replace_policy.json")?;
        env.start_node()?;
        env.sync_policy()?;
        env.node_ready()?;
        env.running(init.id())?;
        env.recovered(init.id(), "trace workload")?;
        let mut actor = env.add_actor("python", &["/fixtures/observability.py", "/work"])?;
        actor.ready()?;
        env.place(actor.id())?;
        let task = env.task(actor.id(), "trace measurement identity")?;
        assert_eq!(
            task.entry_rule(&env)?.target_role_id,
            task.snapshot.active_role_id
        );
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
            control.analysis_store().ok_or("missing analysis store")?,
        );
        let mut records = Vec::new();
        let mut pairs = Vec::new();
        let mut off = (0, 0);
        let baseline = env.snapshot()?;
        Self::capture_health(&baseline, &baseline)?;
        for run in 0..10 {
            env.node_ready()?;
            let (on, capture, capture_path) = Self::capture_route(&mode, run)?;
            let request_id = *uuid::Uuid::new_v4().as_bytes();
            let mut frames = Vec::new();
            let mut after = 0;
            let mut native = None;
            let mut native_result = None;
            let resources = (capture && capture_path == "plain")
                .then(ResourceSnapshot::read)
                .transpose()?;
            let mut attached = None;
            if capture && capture_path == "plain" {
                let output = env.shared.output().join(format!("plain-{run}"));
                native = Some(PlainCapture::start(
                    &executable,
                    &TraceRecipeV1::FailedOpens.manifest()?.source.bytes,
                    target.cgroup_id,
                    &output,
                )?);
                attached = Some(ResourceSnapshot::read()?);
            } else if capture {
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
            Self::capture_health(&baseline, &before)?;
            let mut floors = BTreeMap::<u32, u64>::new();
            for event in &before.recent_effects {
                let floor = floors.entry(event.source_cpu_id).or_default();
                *floor = (*floor).max(event.source_sequence);
            }
            for interval in &before.coverage_intervals {
                let floor = floors.entry(interval.cpu_id).or_default();
                *floor = (*floor).max(interval.next_sequence);
            }
            fs::write(env.work().join(format!("trace-run-{run}")), b"run")?;
            let path = PathBuf::from(format!("/proc/{}/comm", actor.id()));
            let deadline = Instant::now() + Duration::from_secs(15);
            let p99: u64 = loop {
                if let Some(native) = native.as_mut() {
                    native.poll()?;
                }
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
            let deadline = Instant::now() + Duration::from_secs(30);
            let mut denials = BTreeSet::new();
            let after_health = loop {
                if let Some(native) = native.as_mut() {
                    native.poll()?;
                }
                let snapshot = env.snapshot()?;
                for event in &snapshot.recent_effects {
                    if event.source_sequence
                        > floors.get(&event.source_cpu_id).copied().unwrap_or(0)
                        && event.profile_generation_ref_id
                            == task.snapshot.profile_generation_ref_id
                        && task.matches_effect(
                            event,
                            "EXACT_POLICY_DENY",
                            KernelEffectFamilyV1::File,
                            KernelEffectOperationV1::OpenRead,
                            -libc::EACCES,
                        )
                    {
                        denials.insert((event.source_cpu_id, event.source_sequence));
                    }
                }
                if denials.len() > 1000 {
                    return Err("capture has more than 1,000 current-run policy denials".into());
                }
                if denials.len() == 1000 && snapshot.negative_claim_eligible {
                    Self::capture_health(&baseline, &snapshot)?;
                    break snapshot;
                }
                if Instant::now() >= deadline {
                    return Err(format!(
                        "capture retained {} of 1,000 exact policy denials; healthy coverage={}",
                        denials.len(),
                        snapshot.negative_claim_eligible
                    )
                    .into());
                }
                std::thread::sleep(Duration::from_millis(10));
            };
            if native.is_none() {
                env.node_ready()?;
            }
            let loss = after_health.lost_effects - before.lost_effects;
            let mut terminal = None;
            if let Some(native) = native.as_mut() {
                let mut result = native.finish()?;
                assert!(result["collection_ms"]
                    .as_u64()
                    .is_some_and(|duration| (5000..=5100).contains(&duration)));
                let stdout = result["stdout"].as_str().ok_or("native output is absent")?;
                let count = stdout
                    .lines()
                    .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
                    .filter(|row| row["type"] == "map")
                    .filter_map(|row| row["data"]["@errors"]["-13"].as_u64())
                    .max();
                assert!(count.is_some_and(|count| count >= 1000));
                let resources = resources.as_ref().ok_or("native baseline is absent")?;
                let attached = attached.as_ref().ok_or("native attachment is absent")?;
                let programs = attached
                    .programs
                    .difference(&resources.programs)
                    .copied()
                    .collect::<Vec<_>>();
                let maps = attached
                    .maps
                    .difference(&resources.maps)
                    .copied()
                    .collect::<Vec<_>>();
                let links = attached
                    .links
                    .difference(&resources.links)
                    .copied()
                    .collect::<Vec<_>>();
                assert!(
                    !programs.is_empty(),
                    "native attachment has no observed programs"
                );
                let deadline = Instant::now() + Duration::from_secs(10);
                loop {
                    let current = ResourceSnapshot::read()?;
                    assert!(resources.programs.is_subset(&current.programs));
                    assert!(resources.maps.is_subset(&current.maps));
                    assert!(resources.links.is_subset(&current.links));
                    if programs.iter().all(|id| !current.programs.contains(id))
                        && maps.iter().all(|id| !current.maps.contains(id))
                        && links.iter().all(|id| !current.links.contains(id))
                    {
                        break;
                    }
                    if Instant::now() >= deadline {
                        return Err("plain bpftrace left attached resources".into());
                    }
                    std::thread::sleep(Duration::from_millis(20));
                }
                result["observed_programs"] = serde_json::to_value(programs)?;
                result["observed_maps"] = serde_json::to_value(maps)?;
                result["observed_links"] = serde_json::to_value(links)?;
                result["cleanup_verified"] = true.into();
                result["enforcement_resources_unchanged"] = true.into();
                native_result = Some(result);
            } else if capture {
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
            }
            if on {
                pairs.push(TraceQualificationPairV1 {
                    trace_off_p99_ns: off.0,
                    trace_on_p99_ns: p99,
                    trace_off_lost_events: off.1,
                    trace_on_lost_events: loss,
                    physical_decisions_equal: true,
                });
                if mode == "compare" {
                    let plain = off.0;
                    let difference = i128::from(p99) - i128::from(plain);
                    println!(
                        "plain/Araphor pair {}: plain_p99_ns={plain} araphor_p99_ns={p99} difference_ns={difference} difference_percent={:.6}",
                        pairs.len(),
                        difference as f64 * 100.0 / plain as f64,
                    );
                }
            } else {
                off = (p99, loss);
            }
            Self::capture_health(&baseline, &env.snapshot()?)?;
            env.node_ready()?;
            records.push(
                serde_json::json!({"run":run,"trace_on":capture,"request_id":request_id,
                "capture_path":capture_path,"direct_comparison":mode == "compare",
                "cgroup_id":target.cgroup_id,
                "plain_bpftrace":native_result,
                "result":result,"frames":frames,"terminal":terminal,"loss":loss,
                "exact_denials":denials,"task_cookie":task.snapshot.task_cookie,
                "active_role_id":task.snapshot.active_role_id,
                "admitted_entry_rule_id":task.snapshot.admitted_entry_rule_id,
                "profile_generation_ref_id":task.snapshot.profile_generation_ref_id,
                "negative_claim_eligible":after_health.negative_claim_eligible,
                "unresolved_effects":after_health.unresolved_effects}),
            );
            fs::write(&proof, serde_json::to_vec_pretty(&records)?)?;
        }
        qualification.pairs = pairs;
        qualification.evidence_sha256 = Sha256::digest(fs::read(&proof)?).into();
        config.qualification = qualification;
        if mode == "compare" {
            Self::capture_parity(&config.qualification.pairs)?;
        } else {
            config.validate()?;
        }
        if mode == "araphor" {
            fs::write(
                proof.with_extension("config.json"),
                serde_json::to_vec_pretty(&config)?,
            )?;
        }
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
        let bundle_path = self.shared.work().with_extension("bundle");
        let rootfs = bundle_path.join("rootfs");
        if rootfs.exists() {
            return Err("the actor directory already has an initial process".into());
        }
        let bundle = ProbeDirectory::create(&bundle_path)?;
        fs::create_dir_all(rootfs.join("bundle"))?;
        self.bind(&rootfs, &rootfs)?;
        for path in ["/usr", "/lib", "/lib64", "/proc", "/dev/pts"] {
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
        self.bundles.push(bundle);
        Ok(rootfs)
    }

    fn stage_entries(&self, rootfs: &Path) -> TestResult<()> {
        let config = rootfs.join("bundle/config.json");
        fs::write(&config, br#"{"root":{"path":"/"}}"#).context(IoSnafu { path: &config })?;
        let pid = self.init_pid.ok_or("the initial actor is not held")?;
        let state = self.shared.work().join("oci-state.json");
        fs::write(
            &state,
            serde_json::to_vec(&serde_json::json!({
                "id": self.shared.actor_id()?, "pid": pid, "bundle": "/bundle",
                "annotations": self.shared.annotations()?,
            }))?,
        )?;
        let hook = std::env::var_os("MITHRIL_TEST_OCI_HOOK")
            .map(PathBuf::from)
            .unwrap_or_else(|| self.shared.source().join("target/debug/mithril-oci-hook"));
        let manifest = self
            .shared
            .source()
            .join("crates/mithril-e2e/fixtures/convergence/direct-runc-recovery-v1.json");
        let child = Command::new("nsenter")
            .arg(format!("--mount=/proc/{pid}/ns/mnt"))
            .arg(format!("--wdns={}", rootfs.display()))
            .arg(&hook)
            .args(["run", "--stage", "prepare-declared-entries", "--socket"])
            .arg(self.shared.admit_path())
            .arg("--recovery-manifest")
            .arg(manifest)
            .stdin(File::open(&state)?)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        let mut hook = ProcessFixture::new(child, &hook);
        let status = hook.wait_exit("declared entry preparation", Duration::from_secs(30))?;
        if !status.success() {
            return Err(format!(
                "declared entry preparation failed: {status}; stderr: {:?}",
                hook.stderr()?
            )
            .into());
        }
        Ok(())
    }

    fn start_entry(&self, command: &str, args: &[&str]) -> TestResult<ProcessFixture> {
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
        let rootfs = self.shared.work().with_extension("bundle").join("rootfs");
        let program = Path::new(command);
        let mut actor =
            ProcessFixture::held_cgroup(program, args, self.shared.cgroup(), &rootfs, init)?;
        let pid = actor.id();
        let placement = self
            .shared
            .protected()
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

    fn start_named(
        &mut self,
        name: &str,
        extra: &[&str],
        labels: &Labels,
        member: &str,
        kind: mithril_control::ContainerKindV1,
    ) -> TestResult<ProcessFixture> {
        self.shared.prepare_member(labels, member, kind)?;
        if self.shared.node_running() && self.shared.policy_installed() && !self.shared.has_policy()
        {
            self.shared.sync_policy()?;
        }
        self.staged = false;
        self.admitted = false;
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
        self.running(pid)?;
        Ok(actor)
    }

    fn close(&mut self) -> TestResult<()> {
        for target in self.mounts.drain(..).rev() {
            rustix::mount::unmount(&target, rustix::mount::UnmountFlags::DETACH)
                .map_err(std::io::Error::from)
                .context(IoSnafu { path: &target })?;
        }
        for bundle in self.bundles.drain(..) {
            bundle.cleanup()?;
        }
        self.init_pid = None;
        self.staged = false;
        self.admitted = false;
        self.shared.stop()
    }
}

#[test]
fn observability_spool_tail() -> TestResult<()> {
    use mithril_control::{TraceFrameKindV1, TraceFrameV1};
    use std::io::Write as _;
    use std::os::unix::fs::MetadataExt as _;

    let directory = tempfile::tempdir()?;
    let mut file = File::create(directory.path().join("output.jsonl"))?;
    rustix::fs::fallocate(
        &file,
        rustix::fs::FallocateFlags::empty(),
        0,
        68 * 1024 * 1024,
    )?;
    let frames = vec![
        TraceFrameV1 {
            execution_id: [7; 16],
            sequence: 1,
            kind: TraceFrameKindV1::Diagnostic,
            bytes: b"__BPFTRACE_NOTIFY_PROBES_ATTACHED\n".to_vec(),
        },
        TraceFrameV1 {
            execution_id: [7; 16],
            sequence: 2,
            kind: TraceFrameKindV1::Data,
            bytes: b"failed opens: 1000\n".to_vec(),
        },
    ];
    for frame in &frames {
        frame.validate()?;
        file.write_all(&serde_json::to_vec(frame)?)?;
        file.write_all(b"\n")?;
    }
    file.sync_all()?;
    assert_eq!(file.metadata()?.len(), 68 * 1024 * 1024);
    assert!(file.metadata()?.blocks() * 512 >= 68 * 1024 * 1024);
    assert_eq!(Host::capture_frames(directory.path())?, frames);
    assert_eq!(file.metadata()?.len(), 68 * 1024 * 1024);
    Ok(())
}

#[test]
fn capture_rejects_coverage_faults() -> TestResult<()> {
    use erebor_runtime_ipc::v1::MithrilCoverageInterval;

    let before = MithrilObservationSnapshot {
        kernel_ready: true,
        effect_health_available: true,
        negative_claim_eligible: true,
        coverage_intervals: vec![MithrilCoverageInterval {
            interval_id: "healthy".into(),
            source_id: "source".into(),
            source_epoch: 1,
            revision: 1,
            state: "HEALTHY".into(),
            negative_claim_eligible: true,
            ..Default::default()
        }],
        ..Default::default()
    };
    Host::capture_health(&before, &before)?;

    let mut after = before.clone();
    after.coverage_intervals[0].classifier_miss_count = 1;
    assert!(Host::capture_health(&before, &after).is_err());
    after = before.clone();
    after.unresolved_effects = 1;
    assert!(Host::capture_health(&before, &after).is_err());
    after = before.clone();
    after.coverage_intervals.push(MithrilCoverageInterval {
        interval_id: "recovered-gap".into(),
        revision: 2,
        state: "CLOSED".into(),
        gap_reasons: vec!["READER_DELAY".into()],
        ..before.coverage_intervals[0].clone()
    });
    assert!(Host::capture_health(&before, &after).is_err());
    after.coverage_intervals[1].gap_reasons.clear();
    Host::capture_health(&before, &after)?;
    after.negative_claim_eligible = false;
    assert!(Host::capture_health(&before, &after).is_err());

    let mut baseline = before.clone();
    baseline.coverage_intervals[0].classifier_miss_count = 2;
    after = baseline.clone();
    after.coverage_intervals.push(MithrilCoverageInterval {
        interval_id: "next".into(),
        revision: 2,
        ..baseline.coverage_intervals[0].clone()
    });
    Host::capture_health(&baseline, &after)?;
    after.reader_queue_dropped_events = 1;
    assert!(Host::capture_health(&baseline, &after).is_err());

    after = before.clone();
    after.coverage_intervals.push(MithrilCoverageInterval {
        interval_id: "restart-gap".into(),
        revision: 2,
        state: "CLOSED".into(),
        gap_reasons: vec!["UNCLEAN_RESTART".into(), "READER_STOPPED".into()],
        ..before.coverage_intervals[0].clone()
    });
    Host::capture_boundary(&before, &after)?;
    assert!(Host::capture_health(&before, &after).is_err());
    for reason in [
        "CLASSIFIER_MISS",
        "READER_DELAY",
        "WAL_CAPACITY",
        "DECODER_ERROR",
    ] {
        after.coverage_intervals[1].gap_reasons.push(reason.into());
        assert!(Host::capture_boundary(&before, &after).is_err());
        after.coverage_intervals[1].gap_reasons.pop();
    }
    after.coverage_intervals[1].classifier_miss_count = 1;
    assert!(Host::capture_boundary(&before, &after).is_err());
    after.coverage_intervals[1].classifier_miss_count = 0;
    after.unresolved_effects = 1;
    assert!(Host::capture_boundary(&before, &after).is_err());
    after.unresolved_effects = 0;
    after.program_digest = "changed".into();
    assert!(Host::capture_boundary(&before, &after).is_err());
    Ok(())
}

#[test]
fn observability_compare_routes() -> TestResult<()> {
    for run in 0..10 {
        let on = run % 2 == 1;
        assert_eq!(
            Host::capture_route("compare", run)?,
            (on, true, if on { "araphor" } else { "plain" })
        );
        for mode in ["plain", "araphor"] {
            assert_eq!(Host::capture_route(mode, run)?, (on, on, mode));
        }
    }
    assert!(Host::capture_route("unknown", 0).is_err());
    Ok(())
}

#[test]
fn observability_compare_parity() -> TestResult<()> {
    let mut pairs = vec![
        mithril_node::TraceQualificationPairV1 {
            trace_off_p99_ns: 100,
            trace_on_p99_ns: 100,
            trace_off_lost_events: 0,
            trace_on_lost_events: 0,
            physical_decisions_equal: true,
        };
        5
    ];
    Host::capture_parity(&pairs)?;
    pairs[0].trace_on_p99_ns = 99;
    Host::capture_parity(&pairs)?;
    pairs[4].trace_on_p99_ns = 101;
    assert!(Host::capture_parity(&pairs).is_err());
    pairs[4].trace_off_p99_ns = u64::MAX - 1;
    pairs[4].trace_on_p99_ns = u64::MAX;
    assert!(Host::capture_parity(&pairs).is_err());
    pairs[4].trace_on_p99_ns = u64::MAX - 1;
    Host::capture_parity(&pairs)?;
    pairs[0].trace_off_lost_events = 1;
    assert!(Host::capture_parity(&pairs).is_err());
    pairs[0].trace_off_lost_events = 0;
    pairs[0].trace_on_lost_events = 1;
    assert!(Host::capture_parity(&pairs).is_err());
    pairs[0].trace_on_lost_events = 0;
    pairs[0].physical_decisions_equal = false;
    assert!(Host::capture_parity(&pairs).is_err());
    pairs[0].physical_decisions_equal = true;
    pairs[0].trace_off_p99_ns = 0;
    assert!(Host::capture_parity(&pairs).is_err());
    pairs[0].trace_off_p99_ns = 100;
    pairs[0].trace_on_p99_ns = 0;
    assert!(Host::capture_parity(&pairs).is_err());
    pairs[0].trace_on_p99_ns = 100;
    assert!(Host::capture_parity(&pairs[..4]).is_err());
    pairs.push(pairs[0].clone());
    assert!(Host::capture_parity(&pairs).is_err());
    Ok(())
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

#[test]
#[ignore = "requires the owned Linux VM, qualified diagnostics, and the task-owned tmpfs"]
fn observability_owned_storage() -> TestResult<()> {
    super::test_lifecycle::<Host, _>("observability-storage", Host::qualify_storage)
}

#[test]
#[ignore = "subprocess helper for the owned diagnostic restart case"]
fn observability_restart_child() -> TestResult<()> {
    let root = PathBuf::from(std::env::var("MITHRIL_TEST_OUTPUT")?);
    let config = mithril_node::NodeConfig::load(&root.join("trace-node.json"))?;
    let before = std::env::var("MITHRIL_TRACE_RESTART")? == "before";
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async {
        let mut signal = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
        let (stop, receiver) = tokio::sync::watch::channel(false);
        let mut node = mithril_node::NodeChassis::start(config).await?;
        let marker = root.join("trace-intent.ready");
        node.set_trace_hook(move || {
            let saved = std::fs::OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(&marker)
                .and_then(|file| file.sync_all());
            if saved.is_err() {
                std::process::exit(74);
            }
            if before {
                loop {
                    std::thread::park();
                }
            }
        })?;
        tokio::spawn(async move {
            signal.recv().await;
            stop.send_replace(true);
        });
        node.run(receiver).await?;
        Ok::<_, Box<dyn std::error::Error>>(())
    })
}

#[test]
#[ignore = "requires the owned Linux VM and a passing diagnostic qualification record"]
fn observability_owned_restart() -> TestResult<()> {
    super::test_lifecycle::<Host, _>("observability-restart", Host::qualify_restart)
}

impl Platform for Host {
    fn source(&self) -> &Path {
        self.shared.source()
    }

    fn setup(name: &str) -> TestResult<Self> {
        let shared = Shared::setup(name)?;
        Ok(Self {
            shared,
            bundles: Vec::new(),
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

    fn install_policy(&mut self, name: &str) -> TestResult<Labels> {
        self.shared.install_policy(name)
    }

    fn sync_policy(&mut self) -> TestResult<()> {
        self.shared.sync_policy()
    }

    fn node_ready(&mut self) -> TestResult<()> {
        self.shared.node_ready()
    }

    fn start_actor(
        &mut self,
        name: &str,
        extra: &[&str],
        labels: &Labels,
    ) -> TestResult<ProcessFixture> {
        self.shared.begin_pod(labels);
        self.start_named(
            name,
            extra,
            labels,
            "worker",
            mithril_control::ContainerKindV1::Application,
        )
    }

    fn start_actor_group<F>(
        &mut self,
        actors: &[GroupActor<'_>],
        labels: &Labels,
        before_app: F,
    ) -> TestResult<Vec<(ProcessFixture, PathBuf)>>
    where
        F: FnOnce(&mut Self, &mut Vec<(ProcessFixture, PathBuf)>) -> TestResult<()>,
    {
        self.shared.begin_pod(labels);
        let mut group = Vec::with_capacity(actors.len());
        let mut before_app = Some(before_app);
        for actor in actors {
            let kind = actor.kind;
            if kind == mithril_control::ContainerKindV1::Application {
                if let Some(check) = before_app.take() {
                    check(self, &mut group)?;
                    for (member, (process, _)) in actors.iter().zip(&mut group) {
                        if member.kind == mithril_control::ContainerKindV1::Init {
                            self.shared.finish_init(labels, member.name, process)?;
                        }
                    }
                }
            }
            let script = actor
                .script
                .ok_or("Host group actor needs a Python script")?;
            let process = self.start_named(script, actor.args, labels, actor.name, kind)?;
            group.push((process, self.shared.work().join(actor.name)));
        }
        Ok(group)
    }

    fn add_actor(&self, command: &str, args: &[&str]) -> TestResult<ProcessFixture> {
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
        let response = self.shared.stage()?;
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
        let response = self.shared.prepare(pid)?;
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
