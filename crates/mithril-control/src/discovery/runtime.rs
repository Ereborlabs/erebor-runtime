use std::{
    collections::{BTreeMap, VecDeque},
    time::{Duration, Instant},
};

use erebor_telemetry::{debug, info, warn};
use serde::{Deserialize, Serialize};
use tokio::sync::watch;

use super::*;
use crate::{
    ControlStore, DiscoveryArtifactV1, DiscoveryHeadKeyV1, DiscoveryHeadV1,
    EvidenceIntakeIdentityV1, Result,
};

#[derive(Clone, Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DiscoveryRuntimeConfigV1 {
    pub checkpoint_seconds: u64,
}

impl Default for DiscoveryRuntimeConfigV1 {
    fn default() -> Self {
        Self {
            checkpoint_seconds: 60,
        }
    }
}

impl DiscoveryRuntimeConfigV1 {
    pub(crate) fn validate(&self) -> Result<()> {
        DiscoveryInputManifestV1::require(
            (1..=3600).contains(&self.checkpoint_seconds),
            "DISCOVERY_CADENCE",
        )
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct StreamCheckpoint {
    pub(super) schema_version: u32,
    pub(super) stream: EvidenceIntakeIdentityV1,
    pub(super) next_interval_cursor: u64,
    pub(super) snapshot: DiscoveryHeadV1,
}

impl StreamCheckpoint {
    pub(super) fn key(stream: &EvidenceIntakeIdentityV1) -> Result<DiscoveryHeadKeyV1> {
        Ok(DiscoveryHeadKeyV1 {
            tenant_id: stream.tenant_id,
            id: DiscoveryDigestV1::of(&("discovery-stream-checkpoint-v1", stream))?,
        })
    }
}

struct ActiveInterval {
    stream: EvidenceIntakeIdentityV1,
    first_cursor: u64,
    deadline: Instant,
    checkpoint: Option<DiscoveryHeadV1>,
    export: Option<DiscoveryHeadV1>,
}

struct DerivationRuntime {
    owner: DiscoveryOwner,
    store: ControlStore,
    config: DiscoveryRuntimeConfigV1,
    scan_after: Option<EvidenceIntakeIdentityV1>,
    pending: VecDeque<EvidenceIntakeIdentityV1>,
    active: VecDeque<ActiveInterval>,
    failures: u64,
    partial_reasons: BTreeMap<String, u64>,
}

impl DerivationRuntime {
    fn open(store: ControlStore, config: DiscoveryRuntimeConfigV1) -> Result<Self> {
        config.validate()?;
        Ok(Self {
            owner: DiscoveryOwner::open(store.clone())?,
            store,
            config,
            scan_after: None,
            pending: VecDeque::new(),
            active: VecDeque::new(),
            failures: 0,
            partial_reasons: BTreeMap::new(),
        })
    }

    fn admit(&mut self) -> Result<()> {
        let sources = self.store.discovery_sources(self.scan_after.as_ref())?;
        self.scan_after = if sources.len() == 32 {
            sources.last().cloned()
        } else {
            None
        };
        for stream in sources {
            if self.pending.len() == 32 {
                break;
            }
            if self.pending.contains(&stream)
                || self.active.iter().any(|active| active.stream == stream)
                || self
                    .pending
                    .iter()
                    .filter(|queued| queued.tenant_id == stream.tenant_id)
                    .count()
                    >= 8
            {
                continue;
            }
            self.pending.push_back(stream);
        }
        for _ in 0..self.pending.len() {
            if self.active.len() == 4 {
                break;
            }
            let Some(stream) = self.pending.pop_front() else {
                break;
            };
            if self
                .active
                .iter()
                .filter(|active| active.stream.tenant_id == stream.tenant_id)
                .count()
                >= 2
            {
                self.pending.push_back(stream);
                continue;
            }
            let key = StreamCheckpoint::key(&stream)?;
            let mut checkpoint = self.store.discovery_head(&key)?;
            let first_cursor = if let Some(head) = &checkpoint {
                let artifact = self.store.read_discovery_artifact(&head.artifact)?;
                DiscoveryInputManifestV1::require(
                    artifact.payload.len() <= 64 * 1024,
                    "CHECKPOINT_LIMIT",
                )?;
                let saved: StreamCheckpoint =
                    rmp_serde::from_slice(&artifact.payload).map_err(|error| {
                        crate::error::DiscoverySnafu {
                            code: "CHECKPOINT_SCHEMA",
                            reason: error.to_string(),
                        }
                        .build()
                    })?;
                DiscoveryInputManifestV1::require(
                    saved.schema_version == 1
                        && saved.stream == stream
                        && saved.next_interval_cursor > 1
                        && saved.snapshot.key.tenant_id == stream.tenant_id
                        && saved.snapshot.commit_index < head.commit_index
                        && artifact.dependencies == vec![saved.snapshot.artifact.clone()],
                    "CHECKPOINT_INTEGRITY",
                )?;
                let manifest = self
                    .store
                    .read_discovery_artifact(&saved.snapshot.artifact)?;
                let profile: DiscoveryProfileV1 = rmp_serde::from_slice(&manifest.payload)
                    .map_err(|error| {
                        crate::error::DiscoverySnafu {
                            code: "PROFILE_ENCODING",
                            reason: error.to_string(),
                        }
                        .build()
                    })?;
                DiscoveryInputManifestV1::require(
                    self.owner.seal_interval(&profile.export)? == saved.snapshot
                        && profile.stream == stream
                        && profile.last_cursor.checked_add(1) == Some(saved.next_interval_cursor),
                    "CHECKPOINT_INTEGRITY",
                )?;
                let refreshed = self.owner.refresh_coverage(&profile)?;
                if refreshed != profile.export {
                    let snapshot = self.owner.seal_interval(&refreshed)?;
                    checkpoint = Some(self.commit_checkpoint(
                        &StreamCheckpoint {
                            schema_version: 1,
                            stream: stream.clone(),
                            next_interval_cursor: saved.next_interval_cursor,
                            snapshot,
                        },
                        checkpoint.as_ref(),
                    )?);
                }
                saved.next_interval_cursor
            } else {
                1
            };
            let export = self
                .store
                .discovery_head(&DiscoveryOwner::interval_key(&stream, first_cursor)?)?;
            self.active.push_back(ActiveInterval {
                stream,
                first_cursor,
                export,
                checkpoint,
                deadline: Instant::now() + Duration::from_secs(self.config.checkpoint_seconds),
            });
        }
        Ok(())
    }

    fn advance(&mut self, active: &mut ActiveInterval, now: Instant) -> Result<(bool, bool)> {
        active.export = self.store.discovery_head(&DiscoveryOwner::interval_key(
            &active.stream,
            active.first_cursor,
        )?)?;
        let mut seal = now >= active.deadline;
        if let Some(export) = &active.export {
            seal |= self
                .store
                .discovery_head(&DiscoveryProfileV1::head_key(export)?)?
                .is_some();
        }
        let mut progressed = false;
        if !seal || active.export.is_none() {
            match self.owner.advance(&active.stream, active.first_cursor) {
                Ok(DiscoveryAdvanceV1::Applied { export, progress }) => {
                    active.export = Some(export);
                    progressed = true;
                    seal |= progress.accepted_records >= MAX_DISCOVERY_RECORDS as u64
                        || progress.input_bytes >= MAX_DISCOVERY_INPUT_BYTES as u64;
                    let source_lag = self
                        .store
                        .evidence_cursor(&active.stream)?
                        .saturating_sub(progress.next_cursor - 1);
                    let queue_bytes = self.pending.capacity()
                        * std::mem::size_of::<EvidenceIntakeIdentityV1>()
                        + self
                            .pending
                            .iter()
                            .map(|stream| stream.node_id.capacity())
                            .sum::<usize>()
                        + self.active.capacity() * std::mem::size_of::<ActiveInterval>()
                        + self
                            .active
                            .iter()
                            .map(|item| item.stream.node_id.capacity())
                            .sum::<usize>()
                        + active.stream.node_id.capacity();
                    debug!("advanced discovery interval", active = %(self.active.len() + 1),
                        pending = %self.pending.len(), queue_bytes = %queue_bytes,
                        input_bytes = %progress.input_bytes, source_lag = %source_lag);
                }
                Ok(DiscoveryAdvanceV1::Idle { .. }) => {
                    if active.export.is_none() {
                        return Ok((true, false));
                    }
                }
                Err(crate::Error::Discovery {
                    code: "INTERVAL_SEAL_REQUIRED",
                    ..
                }) => {
                    seal = true;
                }
                Err(error) => return Err(error),
            }
        }
        if !seal {
            return Ok((false, progressed));
        }
        let export = active.export.as_ref().ok_or_else(|| {
            crate::error::DiscoverySnafu {
                code: "CHECKPOINT_EXPORT",
                reason: "the interval has no committed export",
            }
            .build()
        })?;
        let snapshot = self.owner.seal_interval(export)?;
        let profile = self.owner.read_snapshot(&snapshot, None)?.profile;
        let next_interval_cursor = profile.last_cursor.checked_add(1).ok_or_else(|| {
            crate::error::DiscoverySnafu {
                code: "CHECKPOINT_LIMIT",
                reason: "the source cursor is exhausted",
            }
            .build()
        })?;
        let checkpoint = StreamCheckpoint {
            schema_version: 1,
            stream: active.stream.clone(),
            next_interval_cursor,
            snapshot: snapshot.clone(),
        };
        self.commit_checkpoint(&checkpoint, active.checkpoint.as_ref())?;
        let lag = self
            .store
            .evidence_cursor(&active.stream)?
            .saturating_sub(profile.last_cursor);
        for reason in profile.partial_reasons {
            let count = self.partial_reasons.entry(reason).or_default();
            *count = count.saturating_add(1);
        }
        info!(active = self.active.len() + 1,
            pending = self.pending.len(), source_lag = lag, failures = self.failures,
            accepted = profile.accepted_records, unresolved = profile.unresolved_records,
            partial_reasons = ?self.partial_reasons, "sealed discovery interval");
        Ok((true, true))
    }

    fn commit_checkpoint(
        &self,
        checkpoint: &StreamCheckpoint,
        expected: Option<&DiscoveryHeadV1>,
    ) -> Result<DiscoveryHeadV1> {
        let payload = rmp_serde::to_vec_named(checkpoint).map_err(|error| {
            crate::error::DiscoverySnafu {
                code: "CHECKPOINT_SCHEMA",
                reason: error.to_string(),
            }
            .build()
        })?;
        let artifact = self.store.put_discovery_artifact(&DiscoveryArtifactV1 {
            schema_version: 1,
            tenant_id: checkpoint.stream.tenant_id,
            dependencies: vec![checkpoint.snapshot.artifact.clone()],
            payload,
        })?;
        let head = self.store.commit_discovery_head(
            StreamCheckpoint::key(&checkpoint.stream)?,
            expected,
            artifact,
        )?;
        #[cfg(test)]
        super::test_crash_boundary("stream-checkpoint");
        Ok(head)
    }

    fn step(&mut self, now: Instant) -> Result<bool> {
        self.owner.project_revisions()?;
        self.admit()?;
        let Some(mut active) = self.active.pop_front() else {
            return Ok(false);
        };
        let result = self.advance(&mut active, now);
        if !matches!(result, Ok((true, _))) {
            self.active.push_back(active);
        }
        result.map(|(_, progressed)| progressed)
    }
}

impl DiscoveryOwner {
    pub async fn run(
        store: ControlStore,
        config: DiscoveryRuntimeConfigV1,
        mut shutdown: watch::Receiver<bool>,
    ) {
        if *shutdown.borrow() || shutdown.has_changed().is_err() {
            return;
        }
        let opened =
            tokio::task::spawn_blocking(move || DerivationRuntime::open(store, config)).await;
        let mut runtime = match opened {
            Ok(Ok(runtime)) => runtime,
            Ok(Err(error)) => {
                warn!(error; "discovery startup failed; primary Control remains active");
                while !*shutdown.borrow() && shutdown.changed().await.is_ok() {}
                return;
            }
            Err(_) => {
                warn!("discovery startup failed; primary Control remains active");
                while !*shutdown.borrow() && shutdown.changed().await.is_ok() {}
                return;
            }
        };
        loop {
            if *shutdown.borrow() || shutdown.has_changed().is_err() {
                break;
            }
            let work = tokio::task::spawn_blocking(move || {
                let result = runtime.step(Instant::now());
                (runtime, result)
            })
            .await;
            let (returned, result) = match work {
                Ok(result) => result,
                Err(_) => {
                    warn!("discovery task failed; primary Control remains active");
                    while !*shutdown.borrow() && shutdown.changed().await.is_ok() {}
                    return;
                }
            };
            runtime = returned;
            let delay = match result {
                Ok(true) => Duration::ZERO,
                Ok(false) => Duration::from_millis(250),
                Err(error) => {
                    runtime.failures = runtime.failures.saturating_add(1);
                    warn!(error; "discovery derivation failed; retry is bounded", failures = %runtime.failures);
                    Duration::from_secs(5)
                }
            };
            tokio::select! {
                _ = shutdown.changed() => {},
                _ = tokio::time::sleep(delay) => {},
            }
            if shutdown.has_changed().is_err() {
                break;
            }
        }
        info!("stopped discovery after committed work");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use prost::Message as _;

    fn receive(
        store: &ControlStore,
        tenant: u8,
        source: u8,
        cursor: u64,
    ) -> std::result::Result<EvidenceIntakeIdentityV1, Box<dyn std::error::Error>> {
        let input = DiscoveryInputManifestV1::from_json(include_bytes!(
            "../../../mithril-e2e/fixtures/discovery/manifest.json"
        ))?;
        let record = &input.records[0];
        let mut stream = record.id.stream.clone();
        stream.tenant_id = [tenant; 16];
        stream.source_id = [source; 16];
        let wire = record.observation.to_wire_record()?.encode_to_vec();
        let mut framed = u32::try_from(wire.len())?.to_be_bytes().to_vec();
        framed.extend_from_slice(&wire);
        framed.extend_from_slice(&crc32c::crc32c(&framed).to_be_bytes());
        crate::EvidenceIntakeOwner::from_store(store.clone()).receive(
            &crate::AuthenticatedEvidenceNodeV1 {
                tenant_id: stream.tenant_id,
                node_id: stream.node_id.clone(),
                node_boot_id: stream.node_boot_id,
                label_epoch: stream.label_epoch,
            },
            crate::EvidenceBatch {
                node_boot_id: stream.node_boot_id.to_vec(),
                source_id: stream.source_id.to_vec(),
                source_epoch: stream.source_epoch,
                cpu_id: record.id.cpu_id,
                first_cursor: cursor,
                framed_records: framed.into(),
                commit_group_tail: true,
            },
        )?;
        Ok(stream)
    }

    #[test]
    fn discovery_derivation_runtime_bounds_sources_and_tenant_admission(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let store = ControlStore::open(directory.path())?;
        for tenant in 1..=6 {
            for source in 1..=10 {
                receive(&store, tenant, source, 1)?;
            }
        }
        let first = store.discovery_sources(None)?;
        assert_eq!(first.len(), 32);
        let second = store.discovery_sources(first.last())?;
        assert_eq!(second.len(), 28);
        assert!(first.last() < second.first());
        let mut runtime = DerivationRuntime::open(store, DiscoveryRuntimeConfigV1::default())?;
        for _ in 0..8 {
            runtime.admit()?;
            assert!(runtime.active.len() <= 4 && runtime.pending.len() <= 32);
            for tenant in 1..=6 {
                assert!(
                    runtime
                        .active
                        .iter()
                        .filter(|item| item.stream.tenant_id == [tenant; 16])
                        .count()
                        <= 2
                );
                assert!(
                    runtime
                        .pending
                        .iter()
                        .filter(|stream| stream.tenant_id == [tenant; 16])
                        .count()
                        <= 8
                );
            }
        }
        assert_eq!(runtime.active.len(), 4);
        assert_eq!(runtime.pending.len(), 32);
        let before = runtime.store.health()?;
        drop(runtime);
        let reopened = ControlStore::open(directory.path())?;
        assert_eq!(reopened.health()?.evidence_cursors, before.evidence_cursors);
        Ok(())
    }

    #[test]
    fn discovery_derivation_runtime_recovers_interval_and_snapshot_checkpoints(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let store = ControlStore::open(directory.path())?;
        let stream = receive(&store, 1, 1, 1)?;
        let mut runtime =
            DerivationRuntime::open(store.clone(), DiscoveryRuntimeConfigV1::default())?;
        assert!(runtime.step(Instant::now())?);
        let export = store
            .discovery_head(&DiscoveryOwner::interval_key(&stream, 1)?)?
            .ok_or("export absent")?;
        let snapshot = runtime.owner.seal_interval(&export)?;
        let original = runtime.owner.read_snapshot(&snapshot, None)?;
        assert!(store
            .discovery_head(&StreamCheckpoint::key(&stream)?)?
            .is_none());
        drop(runtime);
        drop(store);
        let store = ControlStore::open(directory.path())?;
        let mut runtime =
            DerivationRuntime::open(store.clone(), DiscoveryRuntimeConfigV1::default())?;
        assert!(runtime.step(Instant::now())?);
        assert_eq!(
            store.discovery_head(&DiscoveryOwner::interval_key(&stream, 1)?)?,
            Some(export)
        );
        let head = store
            .discovery_head(&StreamCheckpoint::key(&stream)?)?
            .ok_or("checkpoint absent")?;
        let checkpoint: StreamCheckpoint =
            rmp_serde::from_slice(&store.read_discovery_artifact(&head.artifact)?.payload)?;
        assert_eq!(checkpoint.next_interval_cursor, 2);
        assert_eq!(checkpoint.snapshot, snapshot);
        assert_eq!(runtime.owner.read_snapshot(&snapshot, None)?, original);
        drop(runtime);
        drop(store);
        std::fs::remove_file(directory.path().join("discovery-index.sqlite"))?;
        let store = ControlStore::open(directory.path())?;
        let mut runtime =
            DerivationRuntime::open(store.clone(), DiscoveryRuntimeConfigV1::default())?;
        assert!(!runtime.step(Instant::now())?);
        assert_eq!(runtime.owner.read_snapshot(&snapshot, None)?, original);
        receive(&store, 1, 1, 2)?;
        assert!(runtime.step(Instant::now())?);
        assert!(runtime.step(Instant::now() + Duration::from_secs(61))?);
        let head = store
            .discovery_head(&StreamCheckpoint::key(&stream)?)?
            .ok_or("checkpoint absent")?;
        let next: StreamCheckpoint =
            rmp_serde::from_slice(&store.read_discovery_artifact(&head.artifact)?.payload)?;
        assert_eq!(next.next_interval_cursor, 3);
        let current = runtime.owner.read_snapshot(&next.snapshot, None)?;
        assert_eq!(
            (
                current.profile.first_cursor,
                current.profile.last_cursor,
                current.profile.accepted_records
            ),
            (2, 2, 1)
        );
        assert_eq!(runtime.owner.read_snapshot(&snapshot, None)?, original);
        let input = DiscoveryInputManifestV1::from_json(include_bytes!(
            "../../../mithril-e2e/fixtures/discovery/manifest.json"
        ))?;
        let record = &input.records[0];
        crate::EvidenceIntakeOwner::from_store(store.clone()).receive_coverage(
            &crate::AuthenticatedEvidenceNodeV1 {
                tenant_id: stream.tenant_id,
                node_id: stream.node_id.clone(),
                node_boot_id: stream.node_boot_id,
                label_epoch: stream.label_epoch,
            },
            &crate::CoverageReport {
                source_id: stream.source_id.to_vec(),
                cpu_id: record.id.cpu_id,
                source_epoch: stream.source_epoch,
                revision: 1,
                intervals: vec![crate::CoverageInterval {
                    interval_id: record
                        .observation
                        .coverage_interval_id
                        .to_be_bytes()
                        .to_vec(),
                    source_epoch: stream.source_epoch,
                    revision: 1,
                    state: "HEALTHY".into(),
                    first_sequence: 1,
                    last_sequence: Some(2),
                    current: true,
                    gap_reasons: Vec::new(),
                    opening_counters: Some(crate::CoverageCounters::default()),
                    closing_counters: Some(crate::CoverageCounters {
                        attempted: 2,
                        requested: 2,
                        emitted: 2,
                        next_sequence: 3,
                        ..Default::default()
                    }),
                }],
            },
        )?;
        let corrected_export = runtime.owner.refresh_coverage(&current.profile)?;
        assert_ne!(corrected_export, current.profile.export);
        {
            let intake = crate::EvidenceIntakeOwner::from_store(store.clone());
            let mut newer = intake
                .latest_coverage_report(&stream)?
                .ok_or("coverage absent")?;
            newer.revision = 2;
            intake.receive_coverage(
                &crate::AuthenticatedEvidenceNodeV1 {
                    tenant_id: stream.tenant_id,
                    node_id: stream.node_id.clone(),
                    node_boot_id: stream.node_boot_id,
                    label_epoch: stream.label_epoch,
                },
                &newer,
            )?;
        }
        drop(runtime);
        drop(store);
        let store = ControlStore::open(directory.path())?;
        let mut runtime =
            DerivationRuntime::open(store.clone(), DiscoveryRuntimeConfigV1::default())?;
        assert!(!runtime.step(Instant::now())?);
        let corrected_head = store
            .discovery_head(&StreamCheckpoint::key(&stream)?)?
            .ok_or("checkpoint absent")?;
        let corrected: StreamCheckpoint = rmp_serde::from_slice(
            &store
                .read_discovery_artifact(&corrected_head.artifact)?
                .payload,
        )?;
        assert_eq!(corrected.next_interval_cursor, 3);
        assert_ne!(corrected.snapshot, next.snapshot);
        let corrected_page = runtime.owner.read_snapshot(&corrected.snapshot, None)?;
        assert_eq!(corrected_page.profile.replaces, Some(next.snapshot.clone()));
        assert_eq!(corrected_page.profile.accepted_records, 1);
        assert_eq!(corrected_page.atoms, current.atoms);
        assert_eq!(runtime.owner.read_snapshot(&next.snapshot, None)?, current);
        assert!(!runtime.step(Instant::now())?);
        let newer_head = store
            .discovery_head(&StreamCheckpoint::key(&stream)?)?
            .ok_or("checkpoint absent")?;
        assert_ne!(newer_head, corrected_head);
        let newer: StreamCheckpoint =
            rmp_serde::from_slice(&store.read_discovery_artifact(&newer_head.artifact)?.payload)?;
        let newer_page = runtime.owner.read_snapshot(&newer.snapshot, None)?;
        assert_eq!(newer_page.profile.replaces, Some(corrected.snapshot));
        assert_eq!(newer_page.profile.accepted_records, 1);
        assert_eq!(newer_page.atoms, current.atoms);
        assert!(!runtime.step(Instant::now())?);
        assert_eq!(
            store.discovery_head(&StreamCheckpoint::key(&stream)?)?,
            Some(newer_head)
        );
        let watermark = crate::EvidenceRetentionOwner::from_store(store).watermark(&stream)?;
        assert_eq!(
            (watermark.evidence_cursor, watermark.coverage_revision),
            (0, 0)
        );
        Ok(())
    }

    #[test]
    #[ignore = "subprocess worker for derivation crash boundaries"]
    fn discovery_derivation_crash_worker() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let root = std::env::var("ARAPHOR_TEST_DERIVATION_ROOT")?;
        let mut runtime = DerivationRuntime::open(
            ControlStore::open(root)?,
            DiscoveryRuntimeConfigV1::default(),
        )?;
        let now = Instant::now();
        for tick in 0..4 {
            runtime.step(now + Duration::from_secs(tick * 61))?;
        }
        Err("the requested crash boundary was not reached".into())
    }

    #[test]
    fn discovery_derivation_process_crashes_preserve_counts_heads_and_positions(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let mut baseline = None;
        for boundary in [
            "none",
            "artifact-synced",
            "artifact-linked",
            "artifact-installed",
            "export-head",
            "before-sql-commit",
            "sql-commit",
            "snapshot-head",
            "snapshot-visible",
            "stream-checkpoint",
        ] {
            let directory = tempfile::tempdir()?;
            let store = ControlStore::open(directory.path())?;
            let stream = receive(&store, 1, 1, 1)?;
            let before = store.evidence_cursor(&stream)?;
            drop(store);
            if boundary != "none" {
                let status = std::process::Command::new(std::env::current_exe()?)
                    .args([
                        "discovery::runtime::tests::discovery_derivation_crash_worker",
                        "--exact",
                        "--ignored",
                        "--nocapture",
                    ])
                    .env("ARAPHOR_TEST_DERIVATION_ROOT", directory.path())
                    .env("ARAPHOR_TEST_DERIVATION_KILL", boundary)
                    .status()?;
                assert_eq!(status.code(), Some(73), "{boundary}");
            }
            let store = ControlStore::open(directory.path())?;
            let mut runtime =
                DerivationRuntime::open(store.clone(), DiscoveryRuntimeConfigV1::default())?;
            if boundary == "snapshot-head" {
                let export = store
                    .discovery_head(&DiscoveryOwner::interval_key(&stream, 1)?)?
                    .ok_or("export absent")?;
                let snapshot = store
                    .discovery_head(&super::super::live::DiscoveryProfileV1::head_key(&export)?)?
                    .ok_or("snapshot absent")?;
                assert!(runtime.owner.read_snapshot(&snapshot, None).is_err());
            }
            let now = Instant::now();
            for tick in 0..4 {
                runtime.step(now + Duration::from_secs(tick * 61))?;
            }
            while !runtime.owner.project_revisions()? {}
            let head = store
                .discovery_head(&StreamCheckpoint::key(&stream)?)?
                .ok_or("checkpoint absent")?;
            let checkpoint: StreamCheckpoint =
                rmp_serde::from_slice(&store.read_discovery_artifact(&head.artifact)?.payload)?;
            let snapshot = runtime.owner.read_snapshot(&checkpoint.snapshot, None)?;
            assert_eq!(snapshot.profile.accepted_records, 1, "{boundary}");
            assert_eq!(snapshot.profile.unresolved_records, 1, "{boundary}");
            assert_eq!(checkpoint.next_interval_cursor, 2, "{boundary}");
            assert_eq!(store.evidence_cursor(&stream)?, before);
            assert_eq!(
                crate::EvidenceRetentionOwner::from_store(store.clone())
                    .watermark(&stream)?
                    .evidence_cursor,
                0
            );
            let events = runtime
                .owner
                .read_revisions(stream.tenant_id.into(), None)?
                .events;
            let result = (head, snapshot, events);
            if let Some(expected) = &baseline {
                assert_eq!(&result, expected, "{boundary}");
            } else {
                baseline = Some(result);
            }
            receive(&store, 1, 1, 2)?;
            assert_eq!(store.evidence_cursor(&stream)?, 2);
        }
        Ok(())
    }

    #[tokio::test]
    async fn discovery_derivation_runtime_disable_and_failure_leave_intake_active(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let store = ControlStore::open(directory.path())?;
        let (_, shutdown) = watch::channel(true);
        DiscoveryOwner::run(store.clone(), DiscoveryRuntimeConfigV1::default(), shutdown).await;
        assert!(!directory.path().join("discovery-index.sqlite").exists());
        assert!(!directory.path().join("discovery").exists());
        std::fs::write(directory.path().join("discovery-index.sqlite"), b"invalid")?;
        let (stop, shutdown) = watch::channel(false);
        let task = tokio::spawn(DiscoveryOwner::run(
            store.clone(),
            DiscoveryRuntimeConfigV1::default(),
            shutdown,
        ));
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(!task.is_finished());
        let stream = receive(&store, 1, 1, 1)?;
        assert_eq!(store.evidence_cursor(&stream)?, 1);
        stop.send(true)?;
        tokio::time::timeout(Duration::from_secs(5), task).await??;
        assert_eq!(store.evidence_cursor(&stream)?, 1);
        for seconds in [0, 3601] {
            assert!(DiscoveryRuntimeConfigV1 {
                checkpoint_seconds: seconds
            }
            .validate()
            .is_err());
        }
        for seconds in [1, 3600] {
            DiscoveryRuntimeConfigV1 {
                checkpoint_seconds: seconds,
            }
            .validate()?;
        }
        Ok(())
    }
}
