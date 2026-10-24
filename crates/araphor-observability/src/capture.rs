use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    io::{BufRead as _, BufReader, Read as _, Seek as _, SeekFrom, Write as _},
    os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _, PermissionsExt as _},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc, Mutex,
    },
    thread::JoinHandle,
    time::{Duration, Instant},
};

use erebor_interceptor::{
    diagnostic::{
        DiagnosticBackend, DiagnosticCapture, DiagnosticConfig, DiagnosticMode, DiagnosticStop,
    },
    KernelStateReader,
};
use serde::{Deserialize, Serialize};
use snafu::{ensure, ResultExt as _};

use crate::{
    error::{AuthorizationSnafu, IdentityStateSnafu, InterceptorSnafu, IoSnafu, JsonSnafu},
    Result, TraceBatchV1, TraceCleanupV1, TraceDispatchV1, TraceFrameKindV1, TraceFrameV1,
    TraceTargetLeaseV1, TraceTerminalReasonV1, TraceTerminalV1,
};

const TERMINAL_BYTES: u64 = 4096;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NodeTraceConfigV1 {
    pub executable: PathBuf,
    #[serde(default)]
    pub storage_reserve_bytes: Option<u64>,
    #[serde(default)]
    pub backend: DiagnosticConfig,
    #[serde(default)]
    pub active: Option<usize>,
    #[serde(default)]
    pub retained: Option<usize>,
    #[serde(default)]
    pub spool_bytes: Option<u64>,
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
        ensure!(self.executable.is_absolute() && proof.executable_sha256 != [0; 32]
            && proof.evidence_sha256 != [0; 32]
            && !proof.kernel_release.is_empty() && proof.architecture == std::env::consts::ARCH
            && proof.logical_cpus > 0 && proof.maximum_overhead_basis_points > 0
            && proof.pairs.len() >= 5
            && proof.pairs.iter().all(|pair| pair.physical_decisions_equal
                && pair.trace_off_lost_events == 0 && pair.trace_on_lost_events == 0
                && pair.trace_off_p99_ns > 0 && pair.trace_on_p99_ns > 0
                && u128::from(pair.trace_on_p99_ns) * 10_000
                    <= u128::from(pair.trace_off_p99_ns) * (10_000 + u128::from(proof.maximum_overhead_basis_points))),
            crate::error::InvalidConfigurationSnafu {
                reason: "diagnostics require five passed paired runs, a pinned backend, an overhead limit, and a valid resource configuration"
            });
        Ok(())
    }
}

struct ActiveTrace {
    cancel: Arc<AtomicBool>,
    committed: Arc<AtomicU64>,
    worker: JoinHandle<Result<()>>,
}

#[derive(Clone)]
enum TraceBackend {
    Pinned(Arc<DiagnosticBackend>),
    #[cfg(feature = "test-support")]
    Fixture(
        Arc<dyn Fn() -> std::process::Command + Send + Sync>,
        DiagnosticConfig,
    ),
}

impl TraceBackend {
    fn check_source(&self, source: &[u8]) -> Result<()> {
        match self {
            Self::Pinned(backend) => backend.check_source(source).context(InterceptorSnafu),
            #[cfg(feature = "test-support")]
            Self::Fixture(_, config) => crate::TraceErrorCodeV1::Capacity.require(
                config
                    .source_bytes
                    .is_none_or(|limit| source.len() <= limit),
                "diagnostic source exceeds its configured quota",
            ),
        }
    }

    fn start(
        &self,
        source: &[u8],
        cgroup: u64,
        duration: Duration,
    ) -> erebor_interceptor::Result<DiagnosticCapture> {
        match self {
            Self::Pinned(backend) => {
                backend.start(source, cgroup, DiagnosticMode::Capture, duration)
            }
            #[cfg(feature = "test-support")]
            Self::Fixture(command, config) => DiagnosticBackend::start_fixture(
                command(),
                DiagnosticMode::Capture,
                duration,
                *config,
            ),
        }
    }
}

pub struct NodeTraceOwner {
    root: PathBuf,
    tenant_id: [u8; 16],
    node_id: String,
    node_boot_id: [u8; 16],
    _lease: File,
    storage_reserve_bytes: u64,
    allocation: Arc<Mutex<()>>,
    active_limit: Option<usize>,
    retained_limit: Option<usize>,
    spool_bytes: Option<u64>,
    backend: TraceBackend,
    reader: KernelStateReader,
    retained: BTreeMap<[u8; 16], RetainedTrace>,
    recovery_pending: bool,
    #[cfg(any(test, feature = "test-support"))]
    intent_hook: Option<Box<dyn FnOnce() + Send>>,
}

struct RetainedTrace {
    dispatch: TraceDispatchV1,
    active: Option<ActiveTrace>,
    cursor: Mutex<SpoolCursor>,
}

impl RetainedTrace {
    fn new(dispatch: TraceDispatchV1) -> Self {
        Self {
            dispatch,
            active: None,
            cursor: Mutex::new(SpoolCursor::default()),
        }
    }
}

struct TraceSpool {
    root: PathBuf,
    output: File,
    terminal: File,
    sequence: u64,
    output_bytes: u64,
    offset: u64,
    committed: Arc<AtomicU64>,
    allocated: u64,
    storage_reserve_bytes: u64,
    allocation: Arc<Mutex<()>>,
    spool_bytes: Option<u64>,
}

#[derive(Clone, Copy, Default)]
struct SpoolCursor {
    sequence: u64,
    // The offset follows the last complete, checked frame.
    offset: u64,
}

impl NodeTraceOwner {
    pub fn open(
        state_directory: &Path,
        tenant_id: [u8; 16],
        node_id: String,
        node_boot_id: [u8; 16],
        config: NodeTraceConfigV1,
        reader: KernelStateReader,
        protected_wal_bytes: u64,
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
        let backend = DiagnosticBackend::new(
            config.executable,
            config.qualification.executable_sha256,
            config.backend,
        )
        .context(InterceptorSnafu)?;
        let reserve = protected_wal_bytes
            .checked_add(config.storage_reserve_bytes.unwrap_or(0))
            .ok_or_else(|| {
                crate::error::InvalidConfigurationSnafu {
                    reason: "diagnostic storage reserve overflowed",
                }
                .build()
            })?;
        let mut owner = Self::open_state(
            state_directory,
            tenant_id,
            node_id,
            node_boot_id,
            reserve,
            TraceBackend::Pinned(Arc::new(backend)),
            reader,
        )?;
        owner.active_limit = config.active;
        owner.retained_limit = config.retained;
        owner.spool_bytes = config.spool_bytes;
        Ok(owner)
    }

    #[cfg(feature = "test-support")]
    pub fn open_fixture(
        state_directory: &Path,
        tenant_id: [u8; 16],
        node_id: String,
        node_boot_id: [u8; 16],
        command: impl Fn() -> std::process::Command + Send + Sync + 'static,
        config: DiagnosticConfig,
    ) -> Result<Self> {
        Self::open_state(
            state_directory,
            tenant_id,
            node_id,
            node_boot_id,
            0,
            TraceBackend::Fixture(Arc::new(command), config),
            KernelStateReader::new(state_directory),
        )
    }

    fn open_state(
        state_directory: &Path,
        tenant_id: [u8; 16],
        node_id: String,
        node_boot_id: [u8; 16],
        storage_reserve_bytes: u64,
        backend: TraceBackend,
        reader: KernelStateReader,
    ) -> Result<Self> {
        ensure!(
            state_directory.is_absolute()
                && tenant_id != [0; 16]
                && !node_id.is_empty()
                && node_boot_id != [0; 16],
            crate::error::InvalidConfigurationSnafu {
                reason: "diagnostics require a private path and current node identity"
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
        let mut owner = Self {
            root,
            tenant_id,
            node_id,
            node_boot_id,
            _lease: lease,
            storage_reserve_bytes,
            allocation: Arc::new(Mutex::new(())),
            active_limit: None,
            retained_limit: None,
            spool_bytes: None,
            backend,
            reader,
            retained: BTreeMap::new(),
            recovery_pending: true,
            #[cfg(any(test, feature = "test-support"))]
            intent_hook: None,
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

    #[cfg(any(test, feature = "test-support"))]
    pub fn set_intent_hook(&mut self, callback: impl FnOnce() + Send + 'static) -> Result<()> {
        ensure!(
            self.intent_hook.is_none(),
            IdentityStateSnafu {
                reason: "a diagnostic intent hook is already installed"
            }
        );
        self.intent_hook = Some(Box::new(callback));
        Ok(())
    }

    fn recover_inactive(&mut self) -> Result<()> {
        if !self.recovery_pending {
            return Ok(());
        }
        self.read_retained()?;
        for (id, _) in self.retained() {
            if self.running(id).is_none() && self.terminal(id)?.is_none() {
                let mut last_sequence = 0;
                let mut output_bytes = 0_u64;
                loop {
                    let frames = self.frames(id, last_sequence)?;
                    if frames.is_empty() {
                        break;
                    }
                    last_sequence = frames.last().map_or(last_sequence, |frame| frame.sequence);
                    output_bytes = frames.iter().try_fold(output_bytes, |total, frame| {
                        total.checked_add(frame.bytes.len() as u64).ok_or_else(|| {
                            IdentityStateSnafu {
                                reason: "diagnostic recovered byte count overflowed",
                            }
                            .build()
                        })
                    })?;
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
                let mut spool = TraceSpool::existing(
                    self.path(id),
                    self.storage_reserve_bytes,
                    self.allocation.clone(),
                )?;
                spool.output.sync_all().context(IoSnafu {
                    path: spool.root.join("output.jsonl"),
                })?;
                spool.complete(&terminal)?;
            }
            if self.running(id).is_none() {
                let root = self.path(id);
                File::open(&root)
                    .and_then(|file| file.sync_all())
                    .context(IoSnafu { path: &root })?;
            }
        }
        File::open(&self.root)
            .and_then(|file| file.sync_all())
            .context(IoSnafu { path: &self.root })?;
        self.recovery_pending = false;
        Ok(())
    }

    pub fn retained(&self) -> impl ExactSizeIterator<Item = ([u8; 16], &TraceDispatchV1)> + Clone {
        self.retained
            .iter()
            .map(|(id, trace)| (*id, &trace.dispatch))
    }

    fn running(&self, id: [u8; 16]) -> Option<&ActiveTrace> {
        self.retained.get(&id)?.active.as_ref()
    }

    fn active(&self) -> impl Iterator<Item = (&[u8; 16], &ActiveTrace)> {
        self.retained
            .iter()
            .filter_map(|(id, trace)| trace.active.as_ref().map(|active| (id, active)))
    }

    fn read_retained(&mut self) -> Result<()> {
        let mut records = BTreeSet::new();
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
                id.is_some()
                    && entry
                        .file_type()
                        .context(IoSnafu { path: entry.path() })?
                        .is_dir(),
                IdentityStateSnafu {
                    reason: "diagnostic spool has unknown entries"
                }
            );
            let id = id.ok_or_else(|| {
                IdentityStateSnafu {
                    reason: "diagnostic identity is invalid",
                }
                .build()
            })?;
            let path = entry.path().join("intent.json");
            let dispatch: TraceDispatchV1 = TraceSpool::json(&path)?;
            ensure!(
                dispatch.accepted.request.tenant_id == self.tenant_id
                    && dispatch.accepted.execution_id(dispatch.target_index)? == id,
                IdentityStateSnafu {
                    reason: "diagnostic directory does not match its execution"
                }
            );
            ensure!(
                records.insert(id)
                    && self
                        .retained
                        .get(&id)
                        .is_none_or(|trace| trace.dispatch == dispatch),
                IdentityStateSnafu {
                    reason: "diagnostic intent is duplicated or changed"
                }
            );
            self.retained
                .entry(id)
                .or_insert_with(|| RetainedTrace::new(dispatch));
        }
        Ok(())
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
        dispatch.verify(key, self.tenant_id, &self.node_id, self.node_boot_id, now)?;
        ensure!(
            target
                .as_ref()
                .is_none_or(|target| target.target() == *expected),
            AuthorizationSnafu {
                reason: "diagnostic target differs from its signed lifetime"
            }
        );
        let id = accepted.execution_id(dispatch.target_index)?;
        self.reap()?;
        self.expire_acknowledged(now)?;
        if let Some(prior) = self.retained.get(&id) {
            ensure!(
                prior.dispatch == dispatch,
                AuthorizationSnafu {
                    reason: "duplicate diagnostic changed its dispatch"
                }
            );
            return Ok(id);
        }
        let floor_path = self.root.join("retired-before.json");
        if floor_path.exists() {
            let floor: u64 = TraceSpool::json(&floor_path)?;
            ensure!(
                accepted.deadline_unix_ns > floor,
                AuthorizationSnafu {
                    reason: "diagnostic lease is older than durable retirement"
                }
            );
        }
        self.backend.check_source(&accepted.request.source.bytes)?;
        crate::TraceErrorCodeV1::Capacity.require(
            self.retained_limit
                .is_none_or(|limit| self.retained.len() < limit)
                && self
                    .active_limit
                    .is_none_or(|limit| self.active().count() < limit),
            "diagnostic admission exceeds its configured quota",
        )?;
        self.recovery_pending = true;
        let mut spool = match TraceSpool::create(
            self.path(id),
            &dispatch,
            self.storage_reserve_bytes,
            self.allocation.clone(),
            self.spool_bytes,
        ) {
            Ok(spool) => spool,
            Err(error) => {
                let pending = self.root.join(format!("pending-{}", hex::encode(id)));
                if pending.exists() {
                    TraceSpool::remove(&pending)?;
                }
                return Err(error);
            }
        };
        let trace = self
            .retained
            .entry(id)
            .or_insert_with(|| RetainedTrace::new(dispatch.clone()));
        #[cfg(any(test, feature = "test-support"))]
        if let Some(callback) = self.intent_hook.take() {
            callback();
        }
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
        let backend = self.backend.clone();
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
        trace.active = Some(ActiveTrace {
            cancel,
            committed,
            worker,
        });
        Ok(id)
    }

    pub fn cancel(&self, id: [u8; 16]) {
        if let Some(active) = self.running(id) {
            active.cancel.store(true, Ordering::Release);
        }
    }

    pub fn reap(&mut self) -> Result<()> {
        let finished: Vec<_> = self
            .active()
            .filter(|(_, active)| active.worker.is_finished())
            .map(|(id, _)| *id)
            .collect();
        for id in finished {
            if let Some(active) = self
                .retained
                .get_mut(&id)
                .and_then(|trace| trace.active.take())
            {
                self.recovery_pending = true;
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
        let through = if let Some(active) = self.running(id) {
            let through = active.committed.load(Ordering::Acquire);
            if through <= after {
                return Ok(Vec::new());
            }
            Some(through)
        } else {
            self.terminal(id)?.map(|terminal| terminal.last_sequence)
        };
        if through.is_some_and(|through| through <= after) {
            return Ok(Vec::new());
        }
        let Some(trace) = self.retained.get(&id) else {
            return TraceSpool::frames(&self.path(id), after, through, &mut SpoolCursor::default());
        };
        let mut saved = trace.cursor.lock().map_err(|_| {
            IdentityStateSnafu {
                reason: "diagnostic cursor lock failed",
            }
            .build()
        })?;
        let mut cursor = *saved;
        if after < cursor.sequence || through.is_some_and(|through| through < cursor.sequence) {
            cursor = SpoolCursor::default();
        }
        let frames = TraceSpool::frames(&self.path(id), after, through, &mut cursor)?;
        *saved = cursor;
        Ok(frames)
    }

    pub fn terminal(&self, id: [u8; 16]) -> Result<Option<TraceTerminalV1>> {
        if self.running(id).is_some() {
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
        terminal.validate()?;
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
            let prior: TraceTerminalV1 = TraceSpool::json(&path)?;
            ensure!(
                prior == *terminal,
                IdentityStateSnafu {
                    reason: "diagnostic acknowledgement changed"
                }
            );
        } else {
            let bytes = serde_json::to_vec(terminal).context(JsonSnafu { path: &path })?;
            TraceSpool::replace(&path, &bytes, self.storage_reserve_bytes, &self.allocation)?;
        }
        let output = self.path(id).join("output.jsonl");
        let file = TraceSpool::open_file(&output, true)?;
        file.set_len(0)
            .and_then(|()| file.sync_all())
            .context(IoSnafu { path: &output })?;
        if let Some(trace) = self.retained.get_mut(&id) {
            *trace.cursor.get_mut().map_err(|_| {
                IdentityStateSnafu {
                    reason: "diagnostic cursor lock failed",
                }
                .build()
            })? = SpoolCursor::default();
        }
        Ok(())
    }

    fn expire_acknowledged(&mut self, now: u64) -> Result<()> {
        let retained: Vec<_> = self
            .retained
            .iter()
            .map(|(id, trace)| (*id, trace.dispatch.accepted.deadline_unix_ns))
            .collect();
        for (id, deadline) in retained {
            if self.running(id).is_none()
                && deadline <= now
                && self.path(id).join("ack.json").exists()
            {
                let ack: TraceTerminalV1 = TraceSpool::json(&self.path(id).join("ack.json"))?;
                ensure!(
                    self.terminal(id)?.as_ref() == Some(&ack),
                    IdentityStateSnafu {
                        reason: "diagnostic acknowledgement is invalid"
                    }
                );
                let floor_path = self.root.join("retired-before.json");
                let prior: u64 = if floor_path.exists() {
                    TraceSpool::json(&floor_path)?
                } else {
                    0
                };
                if prior < deadline {
                    TraceSpool::replace(
                        &floor_path,
                        deadline.to_string().as_bytes(),
                        self.storage_reserve_bytes,
                        &self.allocation,
                    )?;
                }
                TraceSpool::remove(&self.path(id))?;
                self.retained.remove(&id);
            }
        }
        Ok(())
    }

    fn path(&self, id: [u8; 16]) -> PathBuf {
        self.root.join(hex::encode(id))
    }

    fn capture(
        mut spool: TraceSpool,
        backend: TraceBackend,
        dispatch: TraceDispatchV1,
        target: TraceTargetLeaseV1,
        reader: KernelStateReader,
        cancel: Arc<AtomicBool>,
        deadline: Instant,
    ) -> Result<()> {
        let id = dispatch.accepted.execution_id(dispatch.target_index)?;
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
                    if matches!(
                        reason,
                        Some(
                            TraceTerminalReasonV1::StorageFailure
                                | TraceTerminalReasonV1::OutputLimit
                        )
                    ) {
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
                    match spool.append(&frame) {
                        Ok(true) => {}
                        Ok(false) => {
                            reason = Some(TraceTerminalReasonV1::OutputLimit);
                            capture.cancel();
                        }
                        Err(_) => {
                            reason = Some(TraceTerminalReasonV1::StorageFailure);
                            capture.cancel();
                        }
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
                        if matches!(
                            reason,
                            Some(
                                TraceTerminalReasonV1::StorageFailure
                                    | TraceTerminalReasonV1::OutputLimit
                            )
                        ) {
                            continue;
                        }
                        match spool.append(&frame) {
                            Ok(true) => {}
                            Ok(false) => reason = Some(TraceTerminalReasonV1::OutputLimit),
                            Err(_) => reason = Some(TraceTerminalReasonV1::StorageFailure),
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
                reason: reason.unwrap_or(TraceTerminalReasonV1::BackendFailed),
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
        for (_, active) in self.active() {
            active.cancel.store(true, Ordering::Release);
        }
        for active in self
            .retained
            .values_mut()
            .filter_map(|trace| trace.active.take())
        {
            let _result = active.worker.join();
        }
    }
}

impl TraceSpool {
    fn replace(path: &Path, bytes: &[u8], reserve: u64, allocation: &Mutex<()>) -> Result<()> {
        let pending = path.with_extension("pending");
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
            .open(&pending)
            .context(IoSnafu { path })?;
        Self::allocate(&file, &pending, 0, bytes.len() as u64, reserve, allocation)?;
        file.write_all(bytes)
            .and_then(|()| file.sync_all())
            .context(IoSnafu { path })?;
        fs::rename(&pending, path).context(IoSnafu { path })?;
        let root = path.parent().unwrap_or(path);
        File::open(root)
            .and_then(|directory| directory.sync_all())
            .context(IoSnafu { path: root })
    }

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

    fn create(
        root: PathBuf,
        dispatch: &TraceDispatchV1,
        reserve: u64,
        allocation: Arc<Mutex<()>>,
        spool_bytes: Option<u64>,
    ) -> Result<Self> {
        let final_root = root;
        let root = final_root.with_file_name(format!(
            "pending-{}",
            hex::encode(dispatch.accepted.execution_id(dispatch.target_index)?)
        ));
        Self::directory(&root)?;
        let open = |name: &str| -> Result<File> {
            let path = root.join(name);
            OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&path)
                .context(IoSnafu { path })
        };
        let output = open("output.jsonl")?;
        let terminal = open("terminal.pending")?;
        Self::allocate(
            &terminal,
            &root.join("terminal.pending"),
            0,
            TERMINAL_BYTES,
            reserve,
            &allocation,
        )?;
        terminal.sync_all().context(IoSnafu {
            path: root.join("terminal.pending"),
        })?;
        output.sync_all().context(IoSnafu {
            path: root.join("output.jsonl"),
        })?;
        let path = root.join("intent.json");
        let bytes = serde_json::to_vec(dispatch).context(JsonSnafu { path: &path })?;
        let mut intent = open("intent.json")?;
        Self::allocate(&intent, &path, 0, bytes.len() as u64, reserve, &allocation)?;
        intent
            .write_all(&bytes)
            .and_then(|()| intent.sync_all())
            .context(IoSnafu { path: &path })?;
        File::open(&root)
            .and_then(|file| file.sync_all())
            .context(IoSnafu { path: &root })?;
        fs::rename(&root, &final_root).context(IoSnafu { path: &root })?;
        if let Some(parent) = final_root.parent() {
            File::open(parent)
                .and_then(|file| file.sync_all())
                .context(IoSnafu { path: parent })?;
        }
        Ok(Self {
            root: final_root,
            output,
            terminal,
            sequence: 0,
            output_bytes: 0,
            offset: 0,
            committed: Arc::new(AtomicU64::new(0)),
            allocated: 0,
            storage_reserve_bytes: reserve,
            allocation,
            spool_bytes,
        })
    }

    fn allocate(
        file: &File,
        path: &Path,
        allocated: u64,
        required: u64,
        reserve: u64,
        allocation: &Mutex<()>,
    ) -> Result<u64> {
        if required <= allocated {
            return Ok(allocated);
        }
        let _guard = allocation.lock().map_err(|_| {
            IdentityStateSnafu {
                reason: "diagnostic allocation lock failed",
            }
            .build()
        })?;
        let filesystem = rustix::fs::fstatvfs(file)
            .map_err(std::io::Error::from)
            .context(IoSnafu { path })?;
        let block = filesystem.f_frsize;
        let end = block
            .checked_sub(1)
            .and_then(|rounding| required.checked_add(rounding))
            .map(|bytes| bytes / block)
            .and_then(|blocks| blocks.checked_mul(block))
            .ok_or_else(|| {
                IdentityStateSnafu {
                    reason: "diagnostic allocation size overflowed",
                }
                .build()
            })?;
        let added = end - allocated;
        let needed = reserve.checked_add(added).ok_or_else(|| {
            IdentityStateSnafu {
                reason: "diagnostic storage reserve overflowed",
            }
            .build()
        })?;
        let available = filesystem.f_bavail.checked_mul(block).ok_or_else(|| {
            IdentityStateSnafu {
                reason: "diagnostic filesystem size overflowed",
            }
            .build()
        })?;
        ensure!(
            available >= needed,
            IdentityStateSnafu {
                reason: "diagnostic allocation would consume the evidence reserve",
            }
        );
        rustix::fs::fallocate(
            file,
            rustix::fs::FallocateFlags::KEEP_SIZE,
            allocated,
            added,
        )
        .map_err(std::io::Error::from)
        .context(IoSnafu { path })?;
        Ok(end)
    }

    fn existing(root: PathBuf, reserve: u64, allocation: Arc<Mutex<()>>) -> Result<Self> {
        Ok(Self {
            output: Self::open_file(&root.join("output.jsonl"), true)?,
            terminal: Self::open_file(&root.join("terminal.pending"), true)?,
            root,
            sequence: 0,
            output_bytes: 0,
            offset: 0,
            committed: Arc::new(AtomicU64::new(0)),
            allocated: 0,
            storage_reserve_bytes: reserve,
            allocation,
            spool_bytes: None,
        })
    }

    fn json<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T> {
        let mut bytes = Vec::new();
        Self::open_file(path, false)?
            .read_to_end(&mut bytes)
            .context(IoSnafu { path })?;
        serde_json::from_slice(&bytes).context(JsonSnafu { path })
    }

    fn append(&mut self, frame: &TraceFrameV1) -> Result<bool> {
        frame.validate()?;
        ensure!(
            self.sequence.checked_add(1) == Some(frame.sequence),
            IdentityStateSnafu {
                reason: "diagnostic output sequence changed",
            }
        );
        let output_bytes = self
            .output_bytes
            .checked_add(frame.bytes.len() as u64)
            .ok_or_else(|| {
                IdentityStateSnafu {
                    reason: "diagnostic output byte count overflowed",
                }
                .build()
            })?;
        let path = self.root.join("output.jsonl");
        let mut bytes = serde_json::to_vec(frame).context(JsonSnafu { path: &path })?;
        bytes.push(b'\n');
        let end = self.offset.checked_add(bytes.len() as u64).ok_or_else(|| {
            IdentityStateSnafu {
                reason: "diagnostic spool offset overflowed",
            }
            .build()
        })?;
        if self.spool_bytes.is_some_and(|limit| end > limit) {
            return Ok(false);
        }
        self.allocated = Self::allocate(
            &self.output,
            &path,
            self.allocated,
            end,
            self.storage_reserve_bytes,
            &self.allocation,
        )?;
        self.output
            .seek(SeekFrom::Start(self.offset))
            .and_then(|_| self.output.write_all(&bytes))
            .and_then(|()| self.output.sync_data())
            .context(IoSnafu { path: &path })?;
        self.offset = end;
        self.sequence = frame.sequence;
        self.output_bytes = output_bytes;
        self.committed.store(frame.sequence, Ordering::Release);
        Ok(true)
    }

    fn complete(&mut self, terminal: &TraceTerminalV1) -> Result<()> {
        terminal.validate()?;
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

    fn frames(
        root: &Path,
        after: u64,
        through: Option<u64>,
        cursor: &mut SpoolCursor,
    ) -> Result<Vec<TraceFrameV1>> {
        let path = root.join("output.jsonl");
        let file = Self::open_file(&path, false)?;
        ensure!(
            file.metadata().context(IoSnafu { path: &path })?.len() >= cursor.offset,
            IdentityStateSnafu {
                reason: "diagnostic spool prefix was truncated"
            }
        );
        let mut reader = BufReader::new(file);
        reader
            .seek(SeekFrom::Start(cursor.offset))
            .context(IoSnafu { path: &path })?;
        let mut frames = Vec::new();
        let mut bytes = 0_usize;
        while through.is_none_or(|through| cursor.sequence < through) && frames.len() < 200 {
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
                .read_until(b'\n', &mut line)
                .context(IoSnafu { path: &path })?;
            if line.last() != Some(&b'\n') {
                break;
            }
            let frame: TraceFrameV1 =
                serde_json::from_slice(&line).context(JsonSnafu { path: &path })?;
            frame.validate()?;
            ensure!(
                cursor.sequence.checked_add(1) == Some(frame.sequence)
                    && root.file_name().and_then(|name| name.to_str())
                        == Some(hex::encode(frame.execution_id).as_str()),
                IdentityStateSnafu {
                    reason: "diagnostic spool sequence changed"
                }
            );
            if frame.sequence > after
                && !frames.is_empty()
                && bytes
                    .checked_add(frame.bytes.len())
                    .is_none_or(|bytes| bytes > 1024 * 1024)
            {
                break;
            }
            cursor.sequence = frame.sequence;
            cursor.offset = cursor
                .offset
                .checked_add(line.len() as u64)
                .ok_or_else(|| {
                    IdentityStateSnafu {
                        reason: "diagnostic read offset overflowed",
                    }
                    .build()
                })?;
            if frame.sequence <= after {
                continue;
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
    use crate::{
        ContainerKindV1, DiscoveryDigestV1, TraceAcceptedV1, TraceAccessV1, TraceRecipeV1,
        TraceRequestV1, TraceTargetV1, WorkloadTargetFactV1,
    };

    type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;

    fn open(root: &Path) -> Result<NodeTraceOwner> {
        NodeTraceOwner::open(
            root,
            [1; 16],
            "node-a".into(),
            [2; 16],
            config(),
            KernelStateReader::new(root),
            0,
        )
    }

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
            selection: None,
            finding_reference: None,
            tenant_id: [1; 16],
            request_id: [6; 16],
            source: TraceRecipeV1::SyscallErrors.manifest()?.source,
            targets: vec![target],
            collection_seconds: 1,
        };
        let access = TraceAccessV1 {
            tenant_id: [1; 16],
            principal: "operator".into(),
            valid_until_unix_ns: 100_000_000_000,
            revoked: false,
        };
        Ok(TraceDispatchV1::sign(
            TraceAcceptedV1 {
                request,
                access,
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
            storage_reserve_bytes: Some(256 * 1024 * 1024),
            backend: DiagnosticConfig::default(),
            active: None,
            retained: None,
            spool_bytes: None,
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
    fn observability_optional_retention() -> TestResult {
        let directory = tempfile::tempdir()?;
        let key = ed25519_dalek::SigningKey::from_bytes(&[23; 32]);
        let mut value = serde_json::to_value(config())?;
        for field in [
            "storage_reserve_bytes",
            "backend",
            "active",
            "retained",
            "spool_bytes",
        ] {
            value
                .as_object_mut()
                .ok_or("configuration object")?
                .remove(field);
        }
        let config: NodeTraceConfigV1 = serde_json::from_value(value)?;
        assert!(config.storage_reserve_bytes.is_none());
        assert!(
            config.active.is_none() && config.retained.is_none() && config.spool_bytes.is_none()
        );
        let mut owner = NodeTraceOwner::open(
            directory.path(),
            [1; 16],
            "node-a".into(),
            [2; 16],
            config.clone(),
            KernelStateReader::new(directory.path()),
            0,
        )?;
        for index in 1_u16..=129 {
            let mut dispatch = dispatch()?;
            dispatch.accepted.request.request_id[..2].copy_from_slice(&index.to_be_bytes());
            let dispatch = TraceDispatchV1::sign(dispatch.accepted, 0, "key".into(), 1, &key)?;
            let id = owner.admit(dispatch, None, &key.verifying_key(), 2)?;
            assert_eq!(
                owner.terminal(id)?.ok_or("terminal absent")?.reason,
                TraceTerminalReasonV1::TargetChanged
            );
        }
        assert_eq!(owner.retained().len(), 129);
        drop(owner);
        let mut config = config;
        config.active = Some(0);
        config.retained = Some(0);
        config.spool_bytes = Some(0);
        let owner = NodeTraceOwner::open(
            directory.path(),
            [1; 16],
            "node-a".into(),
            [2; 16],
            config,
            KernelStateReader::new(directory.path()),
            0,
        )?;
        assert_eq!(owner.retained().len(), 129);
        for (id, _) in owner.retained() {
            assert_eq!(
                owner.terminal(id)?.ok_or("terminal absent")?.reason,
                TraceTerminalReasonV1::TargetChanged
            );
        }
        Ok(())
    }

    #[test]
    fn observability_terminal_reserve() -> TestResult {
        for reason in [
            TraceTerminalReasonV1::Completed,
            TraceTerminalReasonV1::Cancelled,
            TraceTerminalReasonV1::Deadline,
            TraceTerminalReasonV1::PreparationFailed,
            TraceTerminalReasonV1::TargetChanged,
            TraceTerminalReasonV1::OutputLimit,
            TraceTerminalReasonV1::ConsumerSlow,
            TraceTerminalReasonV1::NodeRestarted,
            TraceTerminalReasonV1::StorageFailure,
            TraceTerminalReasonV1::BackendFailed,
        ] {
            for cleanup in [
                TraceCleanupV1::Verified,
                TraceCleanupV1::Failed,
                TraceCleanupV1::Unknown,
            ] {
                let terminal = TraceTerminalV1 {
                    execution_id: [255; 16],
                    reason,
                    last_sequence: u64::MAX - 1,
                    output_bytes: u64::MAX,
                    output_incomplete: false,
                    kernel_lost_events: Some(u64::MAX),
                    ready_at_unix_ns: Some(u64::MAX),
                    exit_code: Some(i32::MIN),
                    forced_kill: false,
                    cleanup,
                };
                terminal.validate()?;
                assert!((serde_json::to_vec(&terminal)?.len() as u64) < TERMINAL_BYTES);
            }
        }
        Ok(())
    }

    #[test]
    #[allow(clippy::panic, reason = "The test must poison the held mutex.")]
    fn observability_spool_allocation_failure() -> TestResult {
        use std::os::unix::fs::MetadataExt as _;
        let directory = tempfile::tempdir()?;
        let owner = open(directory.path())?;
        let dispatch = dispatch()?;
        let id = dispatch.accepted.execution_id(0)?;
        let mut spool =
            TraceSpool::create(owner.path(id), &dispatch, 0, owner.allocation.clone(), None)?;
        assert!(Arc::ptr_eq(&spool.allocation, &owner.allocation));
        let frame = TraceFrameV1 {
            execution_id: id,
            sequence: 1,
            kind: TraceFrameKindV1::Data,
            bytes: b"first".to_vec(),
        };
        assert!(spool.append(&frame)?);
        let block = rustix::fs::fstatvfs(&spool.output)?.f_frsize;
        assert_eq!(spool.allocated % block, 0);
        let allocated = spool.allocated;
        let blocks = spool.output.metadata()?.blocks();
        let prefix = fs::read(spool.root.join("output.jsonl"))?;
        let gate = owner.allocation.clone();
        assert!(
            std::thread::spawn(move || -> std::result::Result<(), &'static str> {
                let _held = gate.lock().map_err(|_| "allocation fixture lock")?;
                panic!("poison the allocation fixture lock");
            })
            .join()
            .is_err()
        );
        assert_eq!(
            TraceSpool::allocate(
                &spool.output,
                &spool.root.join("output.jsonl"),
                allocated,
                spool.offset,
                u64::MAX,
                &spool.allocation
            )?,
            allocated
        );
        assert_eq!(spool.output.metadata()?.blocks(), blocks);
        let next = TraceFrameV1 {
            sequence: 2,
            bytes: vec![7; block as usize],
            ..frame
        };
        assert!(spool.append(&next).is_err());
        assert_eq!(spool.sequence, 1);
        assert_eq!(spool.output_bytes, 5);
        assert_eq!(spool.committed.load(Ordering::Acquire), 1);
        assert_eq!(spool.allocated, allocated);
        assert_eq!(fs::read(spool.root.join("output.jsonl"))?, prefix);
        assert_eq!(spool.output.metadata()?.blocks(), blocks);
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
        assert_eq!(owner.terminal(id)?, Some(terminal));
        Ok(())
    }

    #[test]
    fn observability_spool_optional_limits() -> TestResult {
        let directory = tempfile::tempdir()?;
        let root = directory.path().join("diagnostics");
        TraceSpool::directory(&root)?;
        let dispatch = dispatch()?;
        let id = dispatch.accepted.execution_id(0)?;
        let mut spool = TraceSpool::create(
            root.join(hex::encode(id)),
            &dispatch,
            0,
            Arc::new(Mutex::new(())),
            Some(68 * 1024 * 1024),
        )?;
        let frame = TraceFrameV1 {
            execution_id: id,
            sequence: 1,
            kind: TraceFrameKindV1::Data,
            bytes: vec![255; 17 * 1024 * 1024],
        };
        assert!(!spool.append(&frame)?);
        assert_eq!(spool.sequence, 0);
        assert_eq!(spool.committed.load(Ordering::Acquire), 0);
        assert_eq!(spool.output.metadata()?.len(), 0);
        spool.spool_bytes = None;
        assert!(spool.append(&frame)?);
        assert!(spool.offset > 68 * 1024 * 1024);
        let block = rustix::fs::fstatvfs(&spool.output)?.f_frsize;
        assert!(spool.allocated >= spool.offset && spool.allocated - spool.offset < block);
        let terminal = TraceTerminalV1 {
            execution_id: id,
            reason: TraceTerminalReasonV1::Completed,
            last_sequence: 1,
            output_bytes: frame.bytes.len() as u64,
            output_incomplete: false,
            kernel_lost_events: None,
            ready_at_unix_ns: None,
            exit_code: Some(0),
            forced_kill: false,
            cleanup: TraceCleanupV1::Unknown,
        };
        spool.complete(&terminal)?;
        drop(spool);
        let mut lower = config();
        lower.storage_reserve_bytes = None;
        lower.active = Some(0);
        lower.retained = Some(0);
        lower.spool_bytes = Some(0);
        let mut owner = NodeTraceOwner::open(
            directory.path(),
            [1; 16],
            "node-a".into(),
            [2; 16],
            lower,
            KernelStateReader::new(directory.path()),
            0,
        )?;
        assert_eq!(owner.frames(id, 0)?, vec![frame]);
        assert_eq!(
            owner.next_batch(id, 1)?.and_then(|batch| batch.terminal),
            Some(terminal)
        );
        let key = ed25519_dalek::SigningKey::from_bytes(&[23; 32]);
        assert_eq!(
            owner.admit(dispatch.clone(), None, &key.verifying_key(), 2)?,
            id
        );
        let mut next = dispatch.accepted;
        next.request.request_id = [7; 16];
        let next = TraceDispatchV1::sign(next, 0, "key".into(), 1, &key)?;
        assert!(matches!(
            owner.admit(next, None, &key.verifying_key(), 2),
            Err(crate::Error::Observability {
                code: crate::TraceErrorCodeV1::Capacity,
                ..
            })
        ));
        assert!(owner.active().next().is_none());
        Ok(())
    }

    #[test]
    fn observability_qualification_digest() -> TestResult {
        let valid = config();
        valid.validate()?;
        let mut encoded = serde_json::to_value(&valid)?;
        assert!(encoded.get("executable_sha256").is_none());
        let mut decoded: NodeTraceConfigV1 = serde_json::from_value(encoded.clone())?;
        decoded.validate()?;
        assert_eq!(
            decoded.qualification.executable_sha256,
            valid.qualification.executable_sha256
        );
        decoded.qualification.executable_sha256 = [0; 32];
        assert!(decoded.validate().is_err());
        encoded["executable_sha256"] = serde_json::to_value(valid.qualification.executable_sha256)?;
        assert!(serde_json::from_value::<NodeTraceConfigV1>(encoded).is_err());
        Ok(())
    }

    #[test]
    fn observability_target_rejects_unqualified_overhead_and_missing_lifetime_once() -> TestResult {
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
        let mut owner = open(directory.path())?;
        let dispatch = dispatch()?;
        let key = ed25519_dalek::SigningKey::from_bytes(&[23; 32]).verifying_key();
        let id = owner.admit(dispatch.clone(), None, &key, 2)?;
        assert_eq!(owner.admit(dispatch, None, &key, 3)?, id);
        let terminal = owner.terminal(id)?.ok_or("missing terminal")?;
        assert_eq!(terminal.reason, TraceTerminalReasonV1::TargetChanged);
        assert!(owner.active().next().is_none());
        assert_eq!(owner.retained().len(), 1);
        Ok(())
    }

    #[test]
    #[ignore = "subprocess helper; run through observability_intent_crash"]
    fn observability_intent_crash_child() -> TestResult {
        let root =
            PathBuf::from(std::env::var_os("ARAPHOR_TRACE_CRASH_ROOT").ok_or("missing root")?);
        let mut owner = open(&root)?;
        owner.set_intent_hook(|| std::process::exit(73))?;
        assert!(owner.set_intent_hook(|| {}).is_err());
        let key = ed25519_dalek::SigningKey::from_bytes(&[23; 32]).verifying_key();
        owner.admit(dispatch()?, None, &key, 2)?;
        Err("the intent hook did not exit".into())
    }

    #[test]
    fn observability_intent_crash() -> TestResult {
        let directory = tempfile::tempdir()?;
        let status = std::process::Command::new(std::env::current_exe()?)
            .args([
                "--exact",
                "capture::tests::observability_intent_crash_child",
                "--ignored",
            ])
            .env("ARAPHOR_TRACE_CRASH_ROOT", directory.path())
            .status()?;
        assert_eq!(status.code(), Some(73));
        let mut owner = open(directory.path())?;
        let dispatch = dispatch()?;
        let id = dispatch.accepted.execution_id(0)?;
        let terminal = owner.terminal(id)?.ok_or("missing recovered terminal")?;
        assert_eq!(terminal.reason, TraceTerminalReasonV1::NodeRestarted);
        assert_eq!(terminal.cleanup, TraceCleanupV1::Unknown);
        assert!(terminal.output_incomplete);
        assert_eq!(terminal.last_sequence, 0);
        assert_eq!(terminal.output_bytes, 0);
        assert!(owner.active().next().is_none());
        assert!(owner.retained().eq([(id, &dispatch)]));
        let key = ed25519_dalek::SigningKey::from_bytes(&[23; 32]).verifying_key();
        owner.set_intent_hook(|| {})?;
        assert_eq!(owner.admit(dispatch, None, &key, 3)?, id);
        assert!(owner.intent_hook.is_some());
        assert_eq!(owner.terminal(id)?, Some(terminal));
        Ok(())
    }

    #[test]
    fn observability_recovery_preserves_all_pages_and_never_respawns() -> TestResult {
        let directory = tempfile::tempdir()?;
        let root = directory.path().join("diagnostics");
        TraceSpool::directory(&root)?;
        let dispatch = dispatch()?;
        let id = dispatch.accepted.execution_id(0)?;
        let mut spool = TraceSpool::create(
            root.join(hex::encode(id)),
            &dispatch,
            0,
            Arc::new(Mutex::new(())),
            None,
        )?;
        for sequence in 1..=401 {
            spool.append(&TraceFrameV1 {
                execution_id: id,
                sequence,
                kind: TraceFrameKindV1::Data,
                bytes: vec![1; 17],
            })?;
        }
        let frame = TraceFrameV1 {
            execution_id: id,
            sequence: 402,
            kind: TraceFrameKindV1::Data,
            bytes: vec![1; 17],
        };
        spool.output.write_all(&serde_json::to_vec(&frame)?)?;
        spool.output.write_all(b"\n")?;
        // Recovery synchronizes the complete prefix before it publishes a terminal.
        spool.output.write_all(b"{\"execution_id\":")?;
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
            0,
        )?;
        let terminal = owner.terminal(id)?.ok_or("missing terminal")?;
        assert_eq!(
            (terminal.last_sequence, terminal.output_bytes),
            (402, 402 * 17)
        );
        assert_eq!(terminal.reason, TraceTerminalReasonV1::NodeRestarted);
        assert_eq!(terminal.cleanup, TraceCleanupV1::Unknown);
        assert!(terminal.output_incomplete);
        assert_eq!(owner.frames(id, 0)?.len(), 200);
        assert_eq!(owner.frames(id, 200)?.len(), 200);
        assert_eq!(owner.frames(id, 400)?.len(), 2);
        assert!(owner.active().next().is_none());
        assert!(!owner.recovery_pending);
        let terminal_path = owner.path(id).join("terminal.json");
        let saved = directory.path().join("saved-terminal.json");
        fs::rename(&terminal_path, &saved)?;
        fs::create_dir(&terminal_path)?;
        owner.reap()?;
        owner.reap()?;
        assert!(!owner.recovery_pending);
        owner.recovery_pending = true;
        assert!(matches!(
            owner.reap(),
            Err(crate::Error::IdentityState { .. })
        ));
        assert!(owner.recovery_pending);
        fs::remove_dir(&terminal_path)?;
        fs::rename(&saved, &terminal_path)?;
        owner.reap()?;
        assert!(!owner.recovery_pending);
        assert_eq!(owner.terminal(id)?, Some(terminal.clone()));
        assert!(NodeTraceOwner::open(
            directory.path(),
            [1; 16],
            "node-a".into(),
            [2; 16],
            config(),
            reader.clone(),
            0,
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
        assert_eq!(owner.retained().len(), 1);
        owner.expire_acknowledged(2)?;
        assert_eq!(owner.retained().len(), 1);
        drop(owner);
        let mut owner = NodeTraceOwner::open(
            directory.path(),
            [1; 16],
            "node-a".into(),
            [2; 16],
            config(),
            reader,
            0,
        )?;
        assert_eq!(owner.terminal(id)?, Some(terminal));
        owner.expire_acknowledged(16_000_000_001)?;
        assert!(owner.retained().next().is_none());
        let key = ed25519_dalek::SigningKey::from_bytes(&[23; 32]).verifying_key();
        assert!(owner.admit(dispatch, None, &key, 2).is_err());
        Ok(())
    }

    #[test]
    fn observability_spool_seeks_forward_and_checks_replay() -> TestResult {
        let directory = tempfile::tempdir()?;
        let dispatch = dispatch()?;
        let id = dispatch.accepted.execution_id(0)?;
        let root = directory.path().join("diagnostics");
        TraceSpool::directory(&root)?;
        let mut spool = TraceSpool::create(
            root.join(hex::encode(id)),
            &dispatch,
            0,
            Arc::new(Mutex::new(())),
            None,
        )?;
        for sequence in 1..=3 {
            spool.append(&TraceFrameV1 {
                execution_id: id,
                sequence,
                kind: TraceFrameKindV1::Data,
                bytes: vec![1; 600 * 1024],
            })?;
        }
        drop(spool);
        let owner = open(directory.path())?;
        assert_eq!(owner.frames(id, 0)?[0].sequence, 1);
        let path = owner.path(id).join("output.jsonl");
        let mut file = TraceSpool::open_file(&path, true)?;
        file.write_all(b"!")?;
        file.sync_data()?;
        assert_eq!(owner.frames(id, 1)?[0].sequence, 2);
        assert_eq!(owner.frames(id, 2)?[0].sequence, 3);
        assert!(owner.frames(id, 3)?.is_empty());
        assert!(matches!(
            owner.frames(id, 0),
            Err(crate::Error::Json { .. })
        ));
        file.seek(SeekFrom::Start(0))?;
        file.write_all(b"{")?;
        file.sync_data()?;
        assert_eq!(owner.frames(id, 0)?[0].sequence, 1);
        drop(owner);
        let owner = open(directory.path())?;
        assert!(owner.retained().eq([(id, &dispatch)]));
        assert_eq!(owner.frames(id, 2)?[0].sequence, 3);
        Ok(())
    }

    #[test]
    fn observability_recovery_retries_transitions() -> TestResult {
        for worker_failure in [false, true] {
            let directory = tempfile::tempdir()?;
            let mut owner = open(directory.path())?;
            assert!(!owner.recovery_pending);
            let dispatch = dispatch()?;
            let id = dispatch.accepted.execution_id(0)?;
            let fault = owner.path(id).join("terminal.json");
            let key = ed25519_dalek::SigningKey::from_bytes(&[23; 32]).verifying_key();
            let failed = if worker_failure {
                let mut spool = TraceSpool::create(
                    owner.path(id),
                    &dispatch,
                    0,
                    owner.allocation.clone(),
                    None,
                )?;
                spool.append(&TraceFrameV1 {
                    execution_id: id,
                    sequence: 1,
                    kind: TraceFrameKindV1::Data,
                    bytes: b"first".to_vec(),
                })?;
                let committed = spool.committed.clone();
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
                fs::create_dir(&fault)?;
                let worker = std::thread::spawn(move || spool.complete(&terminal));
                while !worker.is_finished() {
                    std::thread::yield_now();
                }
                owner
                    .retained
                    .entry(id)
                    .or_insert_with(|| RetainedTrace::new(dispatch.clone()))
                    .active = Some(ActiveTrace {
                    cancel: Arc::new(AtomicBool::new(false)),
                    committed,
                    worker,
                });
                owner.reap()
            } else {
                let path = fault.clone();
                let (send, receive) = std::sync::mpsc::channel();
                owner.set_intent_hook(move || {
                    let _ = send.send(fs::create_dir(path));
                })?;
                let result = owner.admit(dispatch.clone(), None, &key, 2);
                receive.try_recv()??;
                result.map(|_| ())
            };
            assert!(matches!(failed,
                Err(crate::Error::Io { source, .. })
                    if source.kind() == std::io::ErrorKind::IsADirectory));
            assert!(owner.recovery_pending);
            assert!(owner.active().next().is_none());
            assert!(matches!(
                owner.reap(),
                Err(crate::Error::IdentityState { .. })
            ));
            assert!(owner.recovery_pending);
            fs::remove_dir(&fault)?;
            owner.reap()?;
            assert!(!owner.recovery_pending);
            let terminal = owner.terminal(id)?.ok_or("missing repaired terminal")?;
            assert_eq!(terminal.reason, TraceTerminalReasonV1::NodeRestarted);
            assert_eq!(terminal.last_sequence, u64::from(worker_failure));
            assert_eq!(terminal.output_bytes, u64::from(worker_failure) * 5);
            assert!(terminal.output_incomplete);
            assert_eq!(terminal.cleanup, TraceCleanupV1::Unknown);
            assert!(owner.retained().eq([(id, &dispatch)]));
            owner.set_intent_hook(|| {})?;
            assert_eq!(owner.admit(dispatch, None, &key, 3)?, id);
            assert!(owner.intent_hook.is_some());
            owner.reap()?;
            assert!(!owner.recovery_pending);
            assert!(owner.active().next().is_none());
            assert_eq!(owner.terminal(id)?, Some(terminal));
        }
        Ok(())
    }

    #[test]
    fn observability_recovery_uploads_only_the_synced_prefix() -> TestResult {
        let directory = tempfile::tempdir()?;
        let mut owner = open(directory.path())?;
        let dispatch = dispatch()?;
        let id = dispatch.accepted.execution_id(0)?;
        let mut spool =
            TraceSpool::create(owner.path(id), &dispatch, 0, owner.allocation.clone(), None)?;
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
        owner
            .retained
            .entry(id)
            .or_insert_with(|| RetainedTrace::new(dispatch.clone()))
            .active = Some(ActiveTrace {
            cancel: Arc::new(AtomicBool::new(false)),
            committed: spool.committed.clone(),
            worker: std::thread::spawn(|| Ok(())),
        });
        assert_eq!(owner.frames(id, 0)?, vec![frame.clone()]);
        spool.output.seek(SeekFrom::Start(spool.offset))?;
        spool.output.write_all(b"!")?;
        assert!(owner.frames(id, 1)?.is_empty());
        assert_eq!(owner.frames(id, 0)?, vec![frame]);
        spool.output.seek(SeekFrom::Start(spool.offset))?;
        spool.output.write_all(&bytes[..1])?;
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
    fn observability_recovery_discards_only_preintent_allocations() -> TestResult {
        let directory = tempfile::tempdir()?;
        let root = directory.path().join("diagnostics");
        TraceSpool::directory(&root)?;
        let pending = root.join(format!("pending-{}", hex::encode([7; 16])));
        TraceSpool::directory(&pending)?;
        fs::write(pending.join("output.jsonl"), b"incomplete allocation")?;
        let owner = open(directory.path())?;
        assert!(owner.retained().next().is_none());
        assert!(!pending.exists());
        assert!(owner.active().next().is_none());
        Ok(())
    }

    #[test]
    #[ignore = "requires the task-owned, empty 384 MiB tmpfs"]
    fn observability_recovery_disk_full_retains_unacknowledged_terminal() -> TestResult {
        let root = PathBuf::from(std::env::var("MITHRIL_TEST_TRACE_DISK")?);
        assert!(root
            .to_string_lossy()
            .starts_with("/tmp/araphor-observability-disk-"));
        // TMPFS_MAGIC from linux/magic.h. Never fill another filesystem.
        assert_eq!(rustix::fs::statfs(&root)?.f_type, 0x0102_1994);
        let directory = tempfile::tempdir_in(&root)?;
        let mut owner = open(directory.path())?;
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
    fn observability_recovery_preserves_evidence_reserve_before_intent() -> TestResult {
        let directory = tempfile::tempdir()?;
        let mut config = config();
        config.storage_reserve_bytes = Some(u64::MAX);
        let mut owner = NodeTraceOwner::open(
            directory.path(),
            [1; 16],
            "node-a".into(),
            [2; 16],
            config,
            KernelStateReader::new(directory.path()),
            0,
        )?;
        let key = ed25519_dalek::SigningKey::from_bytes(&[23; 32]).verifying_key();
        assert!(owner.admit(dispatch()?, None, &key, 2).is_err());
        assert!(owner.retained().next().is_none());
        assert!(owner.active().next().is_none());
        Ok(())
    }
}
