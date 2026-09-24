use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::{BufRead as _, BufReader, Read as _, Seek as _, SeekFrom, Write as _},
    os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _, PermissionsExt as _},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc,
    },
    thread::JoinHandle,
    time::{Duration, Instant},
};

use erebor_interceptor::{
    diagnostic::{DiagnosticBackend, DiagnosticMode, DiagnosticStop},
    KernelStateReader,
};
use mithril_control::{
    TraceBatchV1, TraceCleanupV1, TraceDispatchV1, TraceFrameKindV1, TraceFrameV1,
    TraceTerminalReasonV1, TraceTerminalV1,
};
use serde::{Deserialize, Serialize};
use snafu::{ensure, ResultExt as _};

use crate::{
    error::{
        AuthorizationSnafu, IdentityStateSnafu, InterceptorSnafu, IoSnafu, JsonSnafu, TraceSnafu,
    },
    Result, TraceTargetLeaseV1,
};

const SPOOL_BYTES: u64 = 68 * 1024 * 1024;
const TERMINAL_BYTES: u64 = 4096;
const MAX_ENCODED_FRAME: u64 = 5 * 1024 * 1024;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NodeTraceConfigV1 {
    pub executable: PathBuf,
    pub executable_sha256: [u8; 32],
    pub storage_reserve_bytes: u64,
    pub qualification: TraceQualificationV1,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TraceQualificationV1 {
    pub evidence_sha256: [u8; 32],
    pub executable_sha256: [u8; 32],
    pub kernel_release: String,
    pub architecture: String,
    pub logical_cpus: usize,
    pub maximum_overhead_basis_points: u32,
    pub pairs: Vec<TraceQualificationPairV1>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TraceQualificationPairV1 {
    pub trace_off_p99_ns: u64,
    pub trace_on_p99_ns: u64,
    pub trace_off_lost_events: u64,
    pub trace_on_lost_events: u64,
    pub physical_decisions_equal: bool,
}

impl NodeTraceConfigV1 {
    pub fn validate(&self) -> Result<()> {
        let proof = &self.qualification;
        ensure!(self.executable.is_absolute() && self.executable_sha256 != [0; 32]
            && self.storage_reserve_bytes >= 256 * 1024 * 1024
            && proof.evidence_sha256 != [0; 32] && proof.executable_sha256 == self.executable_sha256
            && !proof.kernel_release.is_empty() && proof.architecture == std::env::consts::ARCH
            && proof.logical_cpus > 0 && proof.maximum_overhead_basis_points > 0
            && (5..=100).contains(&proof.pairs.len())
            && proof.pairs.iter().all(|pair| pair.physical_decisions_equal
                && pair.trace_off_lost_events == 0 && pair.trace_on_lost_events == 0
                && pair.trace_off_p99_ns > 0 && pair.trace_on_p99_ns > 0
                && u128::from(pair.trace_on_p99_ns) * 10_000
                    <= u128::from(pair.trace_off_p99_ns) * (10_000 + u128::from(proof.maximum_overhead_basis_points))),
            crate::error::InvalidConfigurationSnafu {
                reason: "diagnostics require five passed paired runs, a pinned backend, an overhead limit, and an independent storage reserve"
            });
        Ok(())
    }
}

struct ActiveTrace {
    cancel: Arc<AtomicBool>,
    committed: Arc<AtomicU64>,
    worker: JoinHandle<Result<()>>,
}

pub struct NodeTraceOwner {
    root: PathBuf,
    tenant_id: [u8; 16],
    node_id: String,
    node_boot_id: [u8; 16],
    _lease: File,
    config: NodeTraceConfigV1,
    reader: KernelStateReader,
    active: BTreeMap<[u8; 16], ActiveTrace>,
}

struct TraceSpool {
    root: PathBuf,
    output: File,
    terminal: File,
    sequence: u64,
    output_bytes: u64,
    offset: u64,
    committed: Arc<AtomicU64>,
}

impl NodeTraceOwner {
    pub fn open(
        state_directory: &Path,
        tenant_id: [u8; 16],
        node_id: String,
        node_boot_id: [u8; 16],
        config: NodeTraceConfigV1,
        reader: KernelStateReader,
    ) -> Result<Self> {
        config.validate()?;
        let kernel_path = Path::new("/proc/sys/kernel/osrelease");
        let release = fs::read_to_string(kernel_path).context(IoSnafu { path: kernel_path })?;
        ensure!(
            config.qualification.kernel_release == release.trim()
                && std::thread::available_parallelism()
                    .is_ok_and(|count| count.get() == config.qualification.logical_cpus),
            crate::error::InvalidConfigurationSnafu {
                reason:
                    "diagnostic qualification does not match the current kernel or CPU allocation"
            }
        );
        ensure!(
            state_directory.is_absolute()
                && tenant_id != [0; 16]
                && !node_id.is_empty()
                && node_boot_id != [0; 16]
                && config.executable.is_absolute()
                && config.executable_sha256 != [0; 32]
                && config.storage_reserve_bytes >= 256 * 1024 * 1024,
            crate::error::InvalidConfigurationSnafu {
                reason: "diagnostics require pinned execution and at least 256 MiB storage reserve"
            }
        );
        let root = state_directory.join("diagnostics");
        TraceSpool::directory(&root)?;
        let path = root.join("owner.lock");
        let lease = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
            .open(&path)
            .context(IoSnafu { path: &path })?;
        lease
            .try_lock()
            .map_err(|error| std::io::Error::other(error.to_string()))
            .context(IoSnafu { path: &path })?;
        let owner = Self {
            root,
            tenant_id,
            node_id,
            node_boot_id,
            _lease: lease,
            config,
            reader,
            active: BTreeMap::new(),
        };
        for entry in fs::read_dir(&owner.root).context(IoSnafu { path: &owner.root })? {
            let entry = entry.context(IoSnafu { path: &owner.root })?;
            if entry.file_name().to_str().is_some_and(|name| {
                name.strip_prefix("pending-")
                    .is_some_and(|id| id.len() == 32 && hex::decode(id).is_ok())
            }) {
                // No child can start before the final directory rename.
                TraceSpool::remove(&entry.path())?;
            }
        }
        owner.recover_inactive()?;
        Ok(owner)
    }

    fn recover_inactive(&self) -> Result<()> {
        for (id, dispatch) in self.retained()? {
            if !self.active.contains_key(&id) && self.terminal(id)?.is_none() {
                let mut last_sequence = 0;
                let mut output_bytes = 0;
                loop {
                    let frames = self.frames(id, last_sequence)?;
                    if frames.is_empty() {
                        break;
                    }
                    last_sequence = frames.last().map_or(last_sequence, |frame| frame.sequence);
                    output_bytes += frames
                        .iter()
                        .map(|frame| frame.bytes.len() as u64)
                        .sum::<u64>();
                }
                // Recovery never starts another child for a durable intent.
                let terminal = TraceTerminalV1 {
                    execution_id: id,
                    reason: TraceTerminalReasonV1::NodeRestarted,
                    last_sequence,
                    output_bytes,
                    output_incomplete: true,
                    kernel_lost_events: None,
                    ready_at_unix_ns: None,
                    exit_code: None,
                    forced_kill: false,
                    cleanup: TraceCleanupV1::Unknown,
                };
                let mut spool = TraceSpool::existing(self.path(id), &dispatch)?;
                spool.complete(&terminal)?;
            }
            if !self.active.contains_key(&id) {
                let root = self.path(id);
                File::open(&root)
                    .and_then(|file| file.sync_all())
                    .context(IoSnafu { path: &root })?;
            }
        }
        Ok(())
    }

    pub fn retained(&self) -> Result<Vec<([u8; 16], TraceDispatchV1)>> {
        let mut records = Vec::new();
        for entry in fs::read_dir(&self.root).context(IoSnafu { path: &self.root })? {
            let entry = entry.context(IoSnafu { path: &self.root })?;
            if matches!(
                entry.file_name().to_str(),
                Some("owner.lock" | "retired-before.json" | "retired-before.pending")
            ) {
                continue;
            }
            let id = entry
                .file_name()
                .to_str()
                .and_then(|name| hex::decode(name).ok())
                .and_then(|bytes| <[u8; 16]>::try_from(bytes).ok());
            ensure!(
                records.len() < 128
                    && id.is_some()
                    && entry
                        .file_type()
                        .context(IoSnafu { path: entry.path() })?
                        .is_dir(),
                IdentityStateSnafu {
                    reason: "diagnostic spool has unknown or excess entries"
                }
            );
            let id = id.ok_or_else(|| {
                IdentityStateSnafu {
                    reason: "diagnostic identity is invalid",
                }
                .build()
            })?;
            let path = entry.path().join("intent.json");
            let dispatch: TraceDispatchV1 = TraceSpool::json(&path, 5 * 1024 * 1024)?;
            ensure!(
                dispatch.accepted.request.tenant_id == self.tenant_id
                    && dispatch
                        .accepted
                        .execution_id(dispatch.target_index)
                        .context(TraceSnafu)?
                        == id,
                IdentityStateSnafu {
                    reason: "diagnostic directory does not match its execution"
                }
            );
            records.push((id, dispatch));
        }
        records.sort_by_key(|(id, _)| *id);
        Ok(records)
    }

    pub fn admit(
        &mut self,
        dispatch: TraceDispatchV1,
        target: Option<TraceTargetLeaseV1>,
        key: &ed25519_dalek::VerifyingKey,
        now: u64,
    ) -> Result<[u8; 16]> {
        let admission_started = Instant::now();
        let accepted = &dispatch.accepted;
        let expected = &accepted
            .request
            .targets
            .get(dispatch.target_index as usize)
            .ok_or_else(|| {
                AuthorizationSnafu {
                    reason: "diagnostic target index is invalid",
                }
                .build()
            })?;
        dispatch
            .verify(key, self.tenant_id, &self.node_id, self.node_boot_id, now)
            .context(TraceSnafu)?;
        ensure!(
            target
                .as_ref()
                .is_none_or(|target| target.target() == *expected),
            AuthorizationSnafu {
                reason: "diagnostic target differs from its signed lifetime"
            }
        );
        let id = accepted
            .execution_id(dispatch.target_index)
            .context(TraceSnafu)?;
        self.reap()?;
        self.expire_acknowledged(now)?;
        let retained = self.retained()?;
        if let Some((_, prior)) = retained.iter().find(|(prior, _)| *prior == id) {
            ensure!(
                *prior == dispatch,
                AuthorizationSnafu {
                    reason: "duplicate diagnostic changed its dispatch"
                }
            );
            return Ok(id);
        }
        let floor_path = self.root.join("retired-before.json");
        if floor_path.exists() {
            let floor: u64 = TraceSpool::json(&floor_path, 32)?;
            ensure!(
                accepted.deadline_unix_ns > floor,
                AuthorizationSnafu {
                    reason: "diagnostic lease is older than durable retirement"
                }
            );
        }
        let occupied = retained
            .iter()
            .filter(|(id, _)| !self.path(*id).join("ack.json").exists())
            .count();
        ensure!(
            occupied < 2 && retained.len() < 128 && self.active.len() < 2,
            IdentityStateSnafu {
                reason: "the two diagnostic slots are occupied"
            }
        );
        let filesystem = rustix::fs::statvfs(&self.root)
            .map_err(std::io::Error::from)
            .context(IoSnafu { path: &self.root })?;
        let available = filesystem.f_bavail.saturating_mul(filesystem.f_frsize);
        ensure!(
            available
                >= self
                    .config
                    .storage_reserve_bytes
                    .saturating_add(SPOOL_BYTES + TERMINAL_BYTES + 5 * 1024 * 1024),
            IdentityStateSnafu {
                reason: "diagnostic allocation would consume the evidence reserve"
            }
        );
        let mut spool = match TraceSpool::create(self.path(id), &dispatch) {
            Ok(spool) => spool,
            Err(error) => {
                let pending = self.root.join(format!("pending-{}", hex::encode(id)));
                if pending.exists() {
                    TraceSpool::remove(&pending)?;
                }
                return Err(error);
            }
        };
        let Some(target) = target.filter(|target| target.validate(&self.reader).is_ok()) else {
            spool.complete(&TraceTerminalV1 {
                execution_id: id,
                reason: TraceTerminalReasonV1::TargetChanged,
                last_sequence: 0,
                output_bytes: 0,
                output_incomplete: true,
                kernel_lost_events: None,
                ready_at_unix_ns: None,
                exit_code: None,
                forced_kill: false,
                cleanup: TraceCleanupV1::Verified,
            })?;
            return Ok(id);
        };
        let backend = DiagnosticBackend::new(
            self.config.executable.clone(),
            self.config.executable_sha256,
        )
        .context(InterceptorSnafu)?;
        let reader = self.reader.clone();
        let committed = spool.committed.clone();
        let cancel = Arc::new(AtomicBool::new(false));
        let signal = cancel.clone();
        let deadline = admission_started + Duration::from_nanos(accepted.deadline_unix_ns - now);
        let worker = std::thread::Builder::new()
            .name("araphor-trace-spool".into())
            .spawn(move || {
                Self::capture(spool, backend, dispatch, target, reader, signal, deadline)
            })
            .context(IoSnafu { path: &self.root })?;
        self.active.insert(
            id,
            ActiveTrace {
                cancel,
                committed,
                worker,
            },
        );
        Ok(id)
    }

    pub fn cancel(&self, id: [u8; 16]) {
        if let Some(active) = self.active.get(&id) {
            active.cancel.store(true, Ordering::Release);
        }
    }

    pub fn reap(&mut self) -> Result<()> {
        let finished: Vec<_> = self
            .active
            .iter()
            .filter(|(_, active)| active.worker.is_finished())
            .map(|(id, _)| *id)
            .collect();
        for id in finished {
            if let Some(active) = self.active.remove(&id) {
                active.worker.join().map_err(|_| {
                    IdentityStateSnafu {
                        reason: "diagnostic storage worker panicked",
                    }
                    .build()
                })??;
            }
        }
        self.recover_inactive()
    }

    pub fn frames(&self, id: [u8; 16], after: u64) -> Result<Vec<TraceFrameV1>> {
        let through = if let Some(active) = self.active.get(&id) {
            active.committed.load(Ordering::Acquire)
        } else {
            self.terminal(id)?
                .map_or(4096, |terminal| terminal.last_sequence)
        };
        let mut frames = TraceSpool::frames(&self.path(id), after)?;
        frames.retain(|frame| frame.sequence <= through);
        Ok(frames)
    }

    pub fn terminal(&self, id: [u8; 16]) -> Result<Option<TraceTerminalV1>> {
        if self.active.contains_key(&id) {
            return Ok(None);
        }
        let path = self.path(id).join("terminal.json");
        if !path.try_exists().context(IoSnafu { path: &path })? {
            return Ok(None);
        }
        let file = TraceSpool::open_file(&path, false)?;
        let mut bytes = Vec::new();
        file.take(TERMINAL_BYTES)
            .read_to_end(&mut bytes)
            .context(IoSnafu { path: &path })?;
        let Some(end) = bytes.iter().position(|byte| *byte == b'\n') else {
            return Ok(None);
        };
        let terminal: TraceTerminalV1 =
            serde_json::from_slice(&bytes[..end]).context(JsonSnafu { path: &path })?;
        terminal.validate().context(TraceSnafu)?;
        ensure!(
            terminal.execution_id == id,
            IdentityStateSnafu {
                reason: "diagnostic terminal identity changed"
            }
        );
        Ok(Some(terminal))
    }

    pub fn next_batch(&self, id: [u8; 16], after: u64) -> Result<Option<TraceBatchV1>> {
        if self.path(id).join("ack.json").exists() {
            return Ok(None);
        }
        let frames = self.frames(id, after)?;
        let last = frames.last().map_or(after, |frame| frame.sequence);
        let terminal = self
            .terminal(id)?
            .filter(|terminal| terminal.last_sequence == last);
        if frames.is_empty() && terminal.is_none() {
            return Ok(None);
        }
        Ok(Some(TraceBatchV1 {
            execution_id: id,
            frames,
            terminal,
        }))
    }

    pub fn acknowledge(&mut self, id: [u8; 16], terminal: &TraceTerminalV1) -> Result<()> {
        ensure!(
            self.terminal(id)?.as_ref() == Some(terminal),
            IdentityStateSnafu {
                reason: "diagnostic acknowledgement does not match the durable terminal"
            }
        );
        let path = self.path(id).join("ack.json");
        if path.exists() {
            let prior: TraceTerminalV1 = TraceSpool::json(&path, TERMINAL_BYTES)?;
            ensure!(
                prior == *terminal,
                IdentityStateSnafu {
                    reason: "diagnostic acknowledgement changed"
                }
            );
        } else {
            let pending = self.path(id).join("ack.pending");
            let mut file = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
                .open(&pending)
                .context(IoSnafu { path: &path })?;
            let bytes = serde_json::to_vec(terminal).context(JsonSnafu { path: &path })?;
            file.write_all(&bytes)
                .and_then(|()| file.sync_all())
                .context(IoSnafu { path: &path })?;
            fs::rename(&pending, &path).context(IoSnafu { path: &path })?;
            File::open(self.path(id))
                .and_then(|file| file.sync_all())
                .context(IoSnafu { path: &path })?;
        }
        let output = self.path(id).join("output.jsonl");
        let file = TraceSpool::open_file(&output, true)?;
        file.set_len(0)
            .and_then(|()| file.sync_all())
            .context(IoSnafu { path: &output })
    }

    fn expire_acknowledged(&mut self, now: u64) -> Result<()> {
        for (id, dispatch) in self.retained()? {
            if !self.active.contains_key(&id)
                && dispatch.accepted.deadline_unix_ns <= now
                && self.path(id).join("ack.json").exists()
            {
                let ack: TraceTerminalV1 =
                    TraceSpool::json(&self.path(id).join("ack.json"), TERMINAL_BYTES)?;
                ensure!(
                    self.terminal(id)?.as_ref() == Some(&ack),
                    IdentityStateSnafu {
                        reason: "diagnostic acknowledgement is invalid"
                    }
                );
                let floor_path = self.root.join("retired-before.json");
                let prior: u64 = if floor_path.exists() {
                    TraceSpool::json(&floor_path, 32)?
                } else {
                    0
                };
                if prior < dispatch.accepted.deadline_unix_ns {
                    let pending = self.root.join("retired-before.pending");
                    let mut file = OpenOptions::new()
                        .write(true)
                        .create(true)
                        .truncate(true)
                        .mode(0o600)
                        .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
                        .open(&pending)
                        .context(IoSnafu { path: &pending })?;
                    let bytes = dispatch.accepted.deadline_unix_ns.to_string();
                    file.write_all(bytes.as_bytes())
                        .and_then(|()| file.sync_all())
                        .context(IoSnafu { path: &pending })?;
                    fs::rename(&pending, &floor_path).context(IoSnafu { path: &pending })?;
                    File::open(&self.root)
                        .and_then(|file| file.sync_all())
                        .context(IoSnafu { path: &self.root })?;
                }
                TraceSpool::remove(&self.path(id))?;
            }
        }
        Ok(())
    }

    fn path(&self, id: [u8; 16]) -> PathBuf {
        self.root.join(hex::encode(id))
    }

    fn capture(
        mut spool: TraceSpool,
        backend: DiagnosticBackend,
        dispatch: TraceDispatchV1,
        target: TraceTargetLeaseV1,
        reader: KernelStateReader,
        cancel: Arc<AtomicBool>,
        deadline: Instant,
    ) -> Result<()> {
        let id = dispatch
            .accepted
            .execution_id(dispatch.target_index)
            .context(TraceSnafu)?;
        let mut reason = None;
        let result = (|| {
            target.validate(&reader)?;
            ensure!(
                Instant::now() < deadline,
                AuthorizationSnafu {
                    reason: "diagnostic lease expired before attachment"
                }
            );
            let capture = backend
                .start(
                    &dispatch.accepted.request.source.bytes,
                    target.target().cgroup_id,
                    DiagnosticMode::Capture,
                    Duration::from_secs(dispatch.accepted.request.collection_seconds.into()),
                )
                .context(InterceptorSnafu)?;
            loop {
                if reason.is_none() {
                    reason = if cancel.load(Ordering::Acquire) {
                        Some(TraceTerminalReasonV1::Cancelled)
                    } else if Instant::now() >= deadline {
                        Some(TraceTerminalReasonV1::Deadline)
                    } else if target.validate(&reader).is_err() {
                        Some(TraceTerminalReasonV1::TargetChanged)
                    } else {
                        None
                    };
                }
                if reason.is_some() {
                    capture.cancel();
                }
                for frame in capture.frames().try_iter() {
                    if reason == Some(TraceTerminalReasonV1::StorageFailure) {
                        continue;
                    }
                    let frame = TraceFrameV1 {
                        execution_id: id,
                        sequence: frame.sequence,
                        kind: if frame.stderr {
                            TraceFrameKindV1::Diagnostic
                        } else {
                            TraceFrameKindV1::Data
                        },
                        bytes: frame.bytes,
                    };
                    if spool.append(&frame).is_err() {
                        reason = Some(TraceTerminalReasonV1::StorageFailure);
                        capture.cancel();
                    }
                }
                if capture.is_finished() {
                    // Drain frames that arrived after the preceding empty read.
                    for frame in capture.frames().try_iter() {
                        let frame = TraceFrameV1 {
                            execution_id: id,
                            sequence: frame.sequence,
                            kind: if frame.stderr {
                                TraceFrameKindV1::Diagnostic
                            } else {
                                TraceFrameKindV1::Data
                            },
                            bytes: frame.bytes,
                        };
                        if spool.append(&frame).is_err() {
                            reason = Some(TraceTerminalReasonV1::StorageFailure);
                        }
                    }
                    break;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            capture.finish().context(InterceptorSnafu)
        })();
        let terminal = match result {
            Ok(result) => TraceTerminalV1 {
                execution_id: id,
                reason: reason.unwrap_or(match result.stop {
                    DiagnosticStop::Exited if result.exit_code == Some(0) => {
                        TraceTerminalReasonV1::Completed
                    }
                    DiagnosticStop::Cancelled => TraceTerminalReasonV1::Cancelled,
                    DiagnosticStop::Deadline => TraceTerminalReasonV1::Deadline,
                    DiagnosticStop::PreparationDeadline => TraceTerminalReasonV1::PreparationFailed,
                    DiagnosticStop::OutputLimit => TraceTerminalReasonV1::OutputLimit,
                    DiagnosticStop::ConsumerSlow => TraceTerminalReasonV1::ConsumerSlow,
                    _ => TraceTerminalReasonV1::BackendFailed,
                }),
                last_sequence: spool.sequence,
                output_bytes: spool.output_bytes,
                output_incomplete: result.output_incomplete || reason.is_some(),
                kernel_lost_events: None,
                ready_at_unix_ns: None,
                exit_code: result.exit_code,
                forced_kill: result.forced_kill,
                cleanup: match result.cleanup_verified {
                    Some(true) => TraceCleanupV1::Verified,
                    Some(false) => TraceCleanupV1::Failed,
                    None => TraceCleanupV1::Unknown,
                },
            },
            Err(_) => TraceTerminalV1 {
                execution_id: id,
                reason: TraceTerminalReasonV1::BackendFailed,
                last_sequence: spool.sequence,
                output_bytes: spool.output_bytes,
                output_incomplete: true,
                kernel_lost_events: None,
                ready_at_unix_ns: None,
                exit_code: None,
                forced_kill: false,
                cleanup: TraceCleanupV1::Unknown,
            },
        };
        spool.complete(&terminal)
    }
}

impl Drop for NodeTraceOwner {
    fn drop(&mut self) {
        for active in self.active.values() {
            active.cancel.store(true, Ordering::Release);
        }
        for (_, active) in std::mem::take(&mut self.active) {
            let _result = active.worker.join();
        }
    }
}

impl TraceSpool {
    fn remove(root: &Path) -> Result<()> {
        Self::directory(root)?;
        for name in [
            "output.jsonl",
            "terminal.json",
            "terminal.pending",
            "intent.json",
            "ack.json",
            "ack.pending",
        ] {
            let path = root.join(name);
            match fs::remove_file(&path) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error).context(IoSnafu { path }),
            }
        }
        fs::remove_dir(root).context(IoSnafu { path: root })?;
        if let Some(parent) = root.parent() {
            File::open(parent)
                .and_then(|file| file.sync_all())
                .context(IoSnafu { path: parent })?;
        }
        Ok(())
    }

    fn directory(path: &Path) -> Result<()> {
        match fs::DirBuilder::new().mode(0o700).create(path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(source) => return Err(source).context(IoSnafu { path }),
        }
        let metadata = fs::symlink_metadata(path).context(IoSnafu { path })?;
        ensure!(
            metadata.is_dir() && metadata.permissions().mode() & 0o077 == 0,
            IdentityStateSnafu {
                reason: "diagnostic storage requires a private real directory"
            }
        );
        Ok(())
    }

    fn open_file(path: &Path, write: bool) -> Result<File> {
        let file = OpenOptions::new()
            .read(true)
            .write(write)
            .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
            .open(path)
            .context(IoSnafu { path })?;
        let metadata = file.metadata().context(IoSnafu { path })?;
        ensure!(
            metadata.is_file() && metadata.permissions().mode() & 0o077 == 0,
            IdentityStateSnafu {
                reason: "diagnostic storage requires a private regular file"
            }
        );
        Ok(file)
    }

    fn create(root: PathBuf, dispatch: &TraceDispatchV1) -> Result<Self> {
        let final_root = root;
        let root = final_root.with_file_name(format!(
            "pending-{}",
            hex::encode(
                dispatch
                    .accepted
                    .execution_id(dispatch.target_index)
                    .context(TraceSnafu)?
            )
        ));
        Self::directory(&root)?;
        let mut files = Vec::new();
        for (name, bytes) in [
            ("output.jsonl", SPOOL_BYTES),
            ("terminal.pending", TERMINAL_BYTES),
        ] {
            let path = root.join(name);
            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&path)
                .context(IoSnafu { path: &path })?;
            rustix::fs::fallocate(&file, rustix::fs::FallocateFlags::empty(), 0, bytes)
                .map_err(std::io::Error::from)
                .context(IoSnafu { path: &path })?;
            file.sync_all().context(IoSnafu { path: &path })?;
            files.push(file);
        }
        let path = root.join("intent.json");
        let bytes = serde_json::to_vec(dispatch).context(JsonSnafu { path: &path })?;
        ensure!(
            bytes.len() <= 5 * 1024 * 1024,
            IdentityStateSnafu {
                reason: "diagnostic intent exceeds its bound"
            }
        );
        let mut intent = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .context(IoSnafu { path: &path })?;
        intent
            .write_all(&bytes)
            .and_then(|()| intent.sync_all())
            .context(IoSnafu { path: &path })?;
        File::open(&root)
            .and_then(|file| file.sync_all())
            .context(IoSnafu { path: &root })?;
        fs::rename(&root, &final_root).context(IoSnafu { path: &root })?;
        if let Some(parent) = root.parent() {
            File::open(parent)
                .and_then(|file| file.sync_all())
                .context(IoSnafu { path: parent })?;
        }
        let terminal = files.pop().ok_or_else(|| {
            IdentityStateSnafu {
                reason: "diagnostic terminal allocation is absent",
            }
            .build()
        })?;
        let output = files.pop().ok_or_else(|| {
            IdentityStateSnafu {
                reason: "diagnostic output allocation is absent",
            }
            .build()
        })?;
        Ok(Self {
            root: final_root,
            output,
            terminal,
            sequence: 0,
            output_bytes: 0,
            offset: 0,
            committed: Arc::new(AtomicU64::new(0)),
        })
    }

    fn existing(root: PathBuf, _dispatch: &TraceDispatchV1) -> Result<Self> {
        Ok(Self {
            output: Self::open_file(&root.join("output.jsonl"), true)?,
            terminal: Self::open_file(&root.join("terminal.pending"), true)?,
            root,
            sequence: 0,
            output_bytes: 0,
            offset: 0,
            committed: Arc::new(AtomicU64::new(0)),
        })
    }

    fn json<T: serde::de::DeserializeOwned>(path: &Path, limit: u64) -> Result<T> {
        let mut bytes = Vec::new();
        Self::open_file(path, false)?
            .take(limit + 1)
            .read_to_end(&mut bytes)
            .context(IoSnafu { path })?;
        ensure!(
            bytes.len() as u64 <= limit,
            IdentityStateSnafu {
                reason: "diagnostic record exceeds its bound"
            }
        );
        serde_json::from_slice(&bytes).context(JsonSnafu { path })
    }

    fn append(&mut self, frame: &TraceFrameV1) -> Result<()> {
        frame.validate().context(TraceSnafu)?;
        ensure!(
            frame.sequence == self.sequence + 1
                && frame.sequence <= 4096
                && self.output_bytes + frame.bytes.len() as u64
                    <= mithril_control::MAX_TRACE_OUTPUT_BYTES,
            IdentityStateSnafu {
                reason: "diagnostic output sequence or quota changed"
            }
        );
        let path = self.root.join("output.jsonl");
        let mut bytes = serde_json::to_vec(frame).context(JsonSnafu { path: &path })?;
        bytes.push(b'\n');
        ensure!(
            self.offset + bytes.len() as u64 <= SPOOL_BYTES,
            IdentityStateSnafu {
                reason: "diagnostic spool is full"
            }
        );
        self.output
            .seek(SeekFrom::Start(self.offset))
            .and_then(|_| self.output.write_all(&bytes))
            .and_then(|()| self.output.sync_data())
            .context(IoSnafu { path: &path })?;
        self.offset += bytes.len() as u64;
        self.sequence = frame.sequence;
        self.output_bytes += frame.bytes.len() as u64;
        self.committed.store(frame.sequence, Ordering::Release);
        Ok(())
    }

    fn complete(&mut self, terminal: &TraceTerminalV1) -> Result<()> {
        terminal.validate().context(TraceSnafu)?;
        let path = self.root.join("terminal.pending");
        let mut bytes = serde_json::to_vec(terminal).context(JsonSnafu { path: &path })?;
        bytes.push(b'\n');
        ensure!(
            bytes.len() as u64 <= TERMINAL_BYTES,
            IdentityStateSnafu {
                reason: "diagnostic terminal exceeds its reserve"
            }
        );
        self.terminal
            .seek(SeekFrom::Start(0))
            .and_then(|_| self.terminal.write_all(&bytes))
            .and_then(|()| self.terminal.sync_data())
            .context(IoSnafu { path: &path })?;
        fs::rename(&path, self.root.join("terminal.json")).context(IoSnafu { path: &path })?;
        File::open(&self.root)
            .and_then(|file| file.sync_all())
            .context(IoSnafu { path: &self.root })
    }

    fn frames(root: &Path, after: u64) -> Result<Vec<TraceFrameV1>> {
        let path = root.join("output.jsonl");
        let mut reader = BufReader::new(Self::open_file(&path, false)?);
        let mut frames = Vec::new();
        let mut sequence = 0;
        let mut bytes = 0;
        loop {
            if reader
                .fill_buf()
                .context(IoSnafu { path: &path })?
                .first()
                .is_none_or(|byte| *byte == 0)
            {
                break;
            }
            let mut line = Vec::new();
            reader
                .by_ref()
                .take(MAX_ENCODED_FRAME)
                .read_until(b'\n', &mut line)
                .context(IoSnafu { path: &path })?;
            if line.last() != Some(&b'\n') {
                break;
            }
            let frame: TraceFrameV1 =
                serde_json::from_slice(&line).context(JsonSnafu { path: &path })?;
            frame.validate().context(TraceSnafu)?;
            ensure!(
                frame.sequence == sequence + 1
                    && frame.sequence <= 4096
                    && root.file_name().and_then(|name| name.to_str())
                        == Some(hex::encode(frame.execution_id).as_str()),
                IdentityStateSnafu {
                    reason: "diagnostic spool sequence changed"
                }
            );
            sequence = frame.sequence;
            if frame.sequence <= after {
                continue;
            }
            if frames.len() == 200 || bytes + frame.bytes.len() > 1024 * 1024 {
                break;
            }
            bytes += frame.bytes.len();
            frames.push(frame);
        }
        Ok(frames)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mithril_control::{
        ContainerKindV1, DiscoveryDigestV1, TraceAcceptedV1, TraceExecutionGrantV1, TraceRecipeV1,
        TraceRequestV1, TraceTargetV1, WorkloadTargetFactV1,
    };

    fn dispatch() -> std::result::Result<TraceDispatchV1, Box<dyn std::error::Error>> {
        let fact = WorkloadTargetFactV1 {
            node_id: "node-a".into(),
            workload_binding_generation_digest: "generation".into(),
            execution_set_id: "execution".into(),
            cluster_uid: "cluster".into(),
            namespace_uid: "namespace".into(),
            controller_uid: "controller".into(),
            service_account_uid: "account".into(),
            pod_uid: "pod".into(),
            container_id: "container".into(),
            container_name: "worker".into(),
            container_kind: ContainerKindV1::Application,
            image_digest: "image".into(),
            pod_labels: Default::default(),
            kubernetes: None,
        };
        let target = TraceTargetV1 {
            fact_digest: DiscoveryDigestV1::of(&fact)?,
            fact,
            runtime_container_id: "container".into(),
            node_boot_id: [2; 16],
            cgroup_id: 17,
            binding_id: [3; 16],
            binding_nonce: [4; 16],
            root_cgroup_live_interval_id: [5; 16],
            container_generation: 1,
            label_epoch: 2,
        };
        let request = TraceRequestV1 {
            unresolved: Vec::new(),
            tenant_id: [1; 16],
            request_id: [6; 16],
            source: TraceRecipeV1::SyscallErrors.manifest()?.source,
            targets: vec![target],
            collection_seconds: 1,
        };
        let grant = TraceExecutionGrantV1 {
            tenant_id: [1; 16],
            grant_id: [7; 16],
            principal: "operator".into(),
            namespace_uids: ["namespace".into()].into(),
            node_ids: ["node-a".into()].into(),
            recipe_digests: [TraceRecipeV1::SyscallErrors.digest()?].into(),
            host_diagnostic: false,
            valid_until_unix_ns: 100_000_000_000,
        };
        Ok(TraceDispatchV1::sign(
            TraceAcceptedV1 {
                request,
                grant,
                approval: None,
                accepted_unix_ns: 1,
                deadline_unix_ns: 16_000_000_001,
                recipe: Some(TraceRecipeV1::SyscallErrors),
            },
            0,
            "key".into(),
            1,
            &ed25519_dalek::SigningKey::from_bytes(&[23; 32]),
        )?)
    }

    fn config() -> NodeTraceConfigV1 {
        NodeTraceConfigV1 {
            executable: "/not-executed".into(),
            executable_sha256: [1; 32],
            storage_reserve_bytes: 256 * 1024 * 1024,
            qualification: TraceQualificationV1 {
                evidence_sha256: [9; 32],
                executable_sha256: [1; 32],
                kernel_release: fs::read_to_string("/proc/sys/kernel/osrelease")
                    .unwrap_or_default()
                    .trim()
                    .into(),
                architecture: std::env::consts::ARCH.into(),
                logical_cpus: std::thread::available_parallelism().map_or(0, |count| count.get()),
                maximum_overhead_basis_points: 1000,
                pairs: vec![
                    TraceQualificationPairV1 {
                        trace_off_p99_ns: 100,
                        trace_on_p99_ns: 105,
                        trace_off_lost_events: 0,
                        trace_on_lost_events: 0,
                        physical_decisions_equal: true
                    };
                    5
                ],
            },
        }
    }

    #[test]
    fn observability_target_rejects_unqualified_overhead_and_missing_lifetime_once(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let mut invalid = config();
        invalid.qualification.pairs[0].trace_on_p99_ns = 111;
        assert!(invalid.validate().is_err());
        invalid = config();
        invalid.qualification.pairs[0].trace_on_lost_events = 1;
        assert!(invalid.validate().is_err());
        invalid = config();
        invalid.qualification.pairs.pop();
        assert!(invalid.validate().is_err());
        let directory = tempfile::tempdir()?;
        let mut owner = NodeTraceOwner::open(
            directory.path(),
            [1; 16],
            "node-a".into(),
            [2; 16],
            config(),
            KernelStateReader::new(directory.path()),
        )?;
        let dispatch = dispatch()?;
        let key = ed25519_dalek::SigningKey::from_bytes(&[23; 32]).verifying_key();
        let id = owner.admit(dispatch.clone(), None, &key, 2)?;
        assert_eq!(owner.admit(dispatch, None, &key, 3)?, id);
        let terminal = owner.terminal(id)?.ok_or("missing terminal")?;
        assert_eq!(terminal.reason, TraceTerminalReasonV1::TargetChanged);
        assert!(owner.active.is_empty());
        assert_eq!(owner.retained()?.len(), 1);
        Ok(())
    }

    #[test]
    fn observability_recovery_preserves_all_pages_and_never_respawns(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let root = directory.path().join("diagnostics");
        TraceSpool::directory(&root)?;
        let dispatch = dispatch()?;
        let id = dispatch.accepted.execution_id(0)?;
        let mut spool = TraceSpool::create(root.join(hex::encode(id)), &dispatch)?;
        for sequence in 1..=401 {
            spool.append(&TraceFrameV1 {
                execution_id: id,
                sequence,
                kind: TraceFrameKindV1::Data,
                bytes: vec![1; 17],
            })?;
        }
        // A torn last frame is not committed output.
        spool.output.write_all(b"{\"execution_id\":")?;
        spool.output.sync_data()?;
        spool.terminal.write_all(b"{\"execution_id\":[1,")?;
        spool.terminal.sync_data()?;
        drop(spool);
        let reader = KernelStateReader::new(directory.path());
        let mut owner = NodeTraceOwner::open(
            directory.path(),
            [1; 16],
            "node-a".into(),
            [2; 16],
            config(),
            reader.clone(),
        )?;
        let terminal = owner.terminal(id)?.ok_or("missing terminal")?;
        assert_eq!(
            (terminal.last_sequence, terminal.output_bytes),
            (401, 401 * 17)
        );
        assert_eq!(terminal.reason, TraceTerminalReasonV1::NodeRestarted);
        assert_eq!(terminal.cleanup, TraceCleanupV1::Unknown);
        assert!(terminal.output_incomplete);
        assert_eq!(owner.frames(id, 0)?.len(), 200);
        assert_eq!(owner.frames(id, 200)?.len(), 200);
        assert_eq!(owner.frames(id, 400)?.len(), 1);
        assert!(owner.active.is_empty());
        assert!(NodeTraceOwner::open(
            directory.path(),
            [1; 16],
            "node-a".into(),
            [2; 16],
            config(),
            reader.clone()
        )
        .is_err());
        let mut changed = terminal.clone();
        changed.output_bytes += 1;
        assert!(owner.acknowledge(id, &changed).is_err());
        let unavailable = owner.path(id).join("ack.pending");
        fs::create_dir(&unavailable)?;
        assert!(owner.acknowledge(id, &terminal).is_err());
        assert!(owner.next_batch(id, 0)?.is_some());
        fs::remove_dir(unavailable)?;
        owner.acknowledge(id, &terminal)?;
        assert!(owner.next_batch(id, 0)?.is_none());
        assert_eq!(owner.retained()?.len(), 1);
        owner.expire_acknowledged(2)?;
        assert_eq!(owner.retained()?.len(), 1);
        drop(owner);
        let mut owner = NodeTraceOwner::open(
            directory.path(),
            [1; 16],
            "node-a".into(),
            [2; 16],
            config(),
            reader,
        )?;
        assert_eq!(owner.terminal(id)?, Some(terminal));
        owner.expire_acknowledged(16_000_000_001)?;
        assert!(owner.retained()?.is_empty());
        let key = ed25519_dalek::SigningKey::from_bytes(&[23; 32]).verifying_key();
        assert!(owner.admit(dispatch, None, &key, 2).is_err());
        Ok(())
    }

    #[test]
    fn observability_recovery_uploads_only_the_synced_prefix(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let mut owner = NodeTraceOwner::open(
            directory.path(),
            [1; 16],
            "node-a".into(),
            [2; 16],
            config(),
            KernelStateReader::new(directory.path()),
        )?;
        let dispatch = dispatch()?;
        let id = dispatch.accepted.execution_id(0)?;
        let mut spool = TraceSpool::create(owner.path(id), &dispatch)?;
        let frame = TraceFrameV1 {
            execution_id: id,
            sequence: 1,
            kind: TraceFrameKindV1::Data,
            bytes: b"first".to_vec(),
        };
        spool.append(&frame)?;
        let second = TraceFrameV1 {
            sequence: 2,
            bytes: b"not-committed".to_vec(),
            ..frame.clone()
        };
        let mut bytes = serde_json::to_vec(&second)?;
        bytes.push(b'\n');
        spool.output.write_all(&bytes)?;
        owner.active.insert(
            id,
            ActiveTrace {
                cancel: Arc::new(AtomicBool::new(false)),
                committed: spool.committed.clone(),
                worker: std::thread::spawn(|| Ok(())),
            },
        );
        assert_eq!(owner.frames(id, 0)?, vec![frame]);
        let terminal = TraceTerminalV1 {
            execution_id: id,
            reason: TraceTerminalReasonV1::StorageFailure,
            last_sequence: 1,
            output_bytes: 5,
            output_incomplete: true,
            kernel_lost_events: None,
            ready_at_unix_ns: None,
            exit_code: None,
            forced_kill: false,
            cleanup: TraceCleanupV1::Unknown,
        };
        spool.complete(&terminal)?;
        assert!(owner.terminal(id)?.is_none());
        owner.reap()?;
        assert!(owner.frames(id, 1)?.is_empty());
        assert_eq!(
            owner.next_batch(id, 1)?.and_then(|batch| batch.terminal),
            Some(terminal)
        );
        Ok(())
    }

    #[test]
    fn observability_recovery_discards_only_preintent_allocations(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let root = directory.path().join("diagnostics");
        TraceSpool::directory(&root)?;
        let pending = root.join(format!("pending-{}", hex::encode([7; 16])));
        TraceSpool::directory(&pending)?;
        fs::write(pending.join("output.jsonl"), b"incomplete allocation")?;
        let owner = NodeTraceOwner::open(
            directory.path(),
            [1; 16],
            "node-a".into(),
            [2; 16],
            config(),
            KernelStateReader::new(directory.path()),
        )?;
        assert!(owner.retained()?.is_empty());
        assert!(!pending.exists());
        assert!(owner.active.is_empty());
        Ok(())
    }

    #[test]
    #[ignore = "requires the task-owned, empty 384 MiB tmpfs"]
    fn observability_recovery_disk_full_retains_unacknowledged_terminal(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let root = PathBuf::from(std::env::var("MITHRIL_TEST_TRACE_DISK")?);
        assert!(root
            .to_string_lossy()
            .starts_with("/tmp/araphor-observability-disk-"));
        // TMPFS_MAGIC from linux/magic.h. Never fill another filesystem.
        assert_eq!(rustix::fs::statfs(&root)?.f_type, 0x0102_1994);
        let directory = tempfile::tempdir_in(&root)?;
        let mut owner = NodeTraceOwner::open(
            directory.path(),
            [1; 16],
            "node-a".into(),
            [2; 16],
            config(),
            KernelStateReader::new(directory.path()),
        )?;
        let key = ed25519_dalek::SigningKey::from_bytes(&[23; 32]).verifying_key();
        let id = owner.admit(dispatch()?, None, &key, 2)?;
        let terminal = owner
            .terminal(id)?
            .ok_or("missing terminal before disk exhaustion")?;
        let fill = tempfile::tempfile_in(&root)?;
        let status = rustix::fs::statvfs(&root)?;
        let bytes = status.f_bavail * status.f_frsize;
        assert!(bytes < 384 * 1024 * 1024);
        rustix::fs::fallocate(&fill, rustix::fs::FallocateFlags::empty(), 0, bytes)?;
        assert_eq!(rustix::fs::statvfs(&root)?.f_bavail, 0);
        assert!(owner.acknowledge(id, &terminal).is_err());
        assert!(!owner.path(id).join("ack.json").exists());
        assert_eq!(
            owner.next_batch(id, 0)?.and_then(|batch| batch.terminal),
            Some(terminal.clone())
        );
        fill.set_len(0)?;
        fill.sync_all()?;
        owner.acknowledge(id, &terminal)?;
        assert!(owner.next_batch(id, 0)?.is_none());
        assert_eq!(fs::metadata(owner.path(id).join("output.jsonl"))?.len(), 0);
        Ok(())
    }

    #[test]
    fn observability_recovery_preserves_evidence_reserve_before_intent(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let mut config = config();
        config.storage_reserve_bytes = u64::MAX;
        let mut owner = NodeTraceOwner::open(
            directory.path(),
            [1; 16],
            "node-a".into(),
            [2; 16],
            config,
            KernelStateReader::new(directory.path()),
        )?;
        let key = ed25519_dalek::SigningKey::from_bytes(&[23; 32]).verifying_key();
        assert!(owner.admit(dispatch()?, None, &key, 2).is_err());
        assert!(owner.retained()?.is_empty());
        assert!(owner.active.is_empty());
        Ok(())
    }
}
