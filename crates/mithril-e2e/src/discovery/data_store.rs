use std::{
    error::Error as StdError,
    fs,
    os::unix::fs::DirBuilderExt as _,
    path::PathBuf,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use araphor_data::{
    AnalysisRecoveryStatusV1, AnalysisResultCommitV1, AnalysisStore, AnalysisWitnessV1,
    EvidenceIntakeIdentityV1, EvidenceRetentionOwner, ProcessorClassV1, ProcessorScopeV1,
    RetentionLimitsV1,
};
use mithril_control::{
    ControlStore, EvidenceIdV1, EvidenceIntakeOwner, IntakeClock, NodeRegistration,
};
use mithril_node::{
    ControlConnection, EffectObservationStore, EvidenceWalLimits, NodeControlMessage,
    ObservationCanonicalizer, TrustCache,
};
use zerocopy::IntoBytes as _;

use crate::control_fixture::{
    reopen_control_store, ControlServerFixture, MtlsFixture, OutagePolicyFixture,
    OUTAGE_NAMESPACE_UID,
};

type Result<T> = std::result::Result<T, Box<dyn StdError>>;
const START: u64 = 1_800_000_000_000_000_000;
const HOUR: u64 = 3_600_000_000_000;

struct TestClock(AtomicU64);

impl IntakeClock for TestClock {
    fn now(&self) -> SystemTime {
        UNIX_EPOCH + Duration::from_nanos(self.0.load(Ordering::SeqCst))
    }
}

pub struct DataStoreQualification {
    output: PathBuf,
}

impl DataStoreQualification {
    pub fn new(output: PathBuf) -> Self {
        Self { output }
    }

    pub async fn recovery(&self) -> Result<()> {
        self.check(!self.output.exists(), "the output directory already exists")?;
        let tls = MtlsFixture::new(false)?;
        let backup_root = tls.path().join("backups");
        fs::DirBuilder::new().mode(0o700).create(&backup_root)?;
        let control_root = tls.path().join("control-store");
        let data_root = tls.path().join("analysis");
        let control = ControlStore::open(&control_root)?;
        let policy_id = {
            let fixture = OutagePolicyFixture::new(control.clone());
            let resource = fixture.resource(1)?;
            let inventory = fixture.inventory(&resource)?;
            fixture
                .owner
                .reconcile(
                    &resource,
                    OUTAGE_NAMESPACE_UID,
                    &inventory,
                    i64::try_from(START)?,
                )?
                .source_revision
                .policy_source_revision_id
        };
        let policy = control
            .policy_document(&policy_id)?
            .ok_or("policy was not committed")?;
        let clock = Arc::new(TestClock(AtomicU64::new(START)));
        let data = Arc::new(AnalysisStore::open(&data_root)?);
        let stale_path = backup_root.join("stale.duckdb");
        data.backup(&stale_path)?;
        let intake = EvidenceIntakeOwner::new(control.clone(), data.clone(), clock.clone())?;
        let server = tls.start(tls.control_from_intake(intake, 1)?).await?;
        let observations = EffectObservationStore::durable(
            8,
            tls.path().join("wal"),
            EvidenceWalLimits::default(),
            ObservationCanonicalizer::new(
                EvidenceIdV1::new(1, 2),
                EvidenceIdV1::new(3, 4),
                1,
                [7; 16].into(),
            )?,
        )?;
        Self::record(&observations, 1);
        Self::record(&observations, 2);
        let batch = observations
            .next_evidence_batch()
            .ok_or("Node has no batch")?;
        let wire: mithril_control::EvidenceBatch = batch.clone().into();
        let identity = EvidenceIntakeIdentityV1 {
            tenant_id: EvidenceIdV1::new(1, 2).to_be_bytes(),
            node_id: "node-a".into(),
            node_boot_id: [7; 16],
            label_epoch: 1,
            source_id: wire.source_id.as_slice().try_into()?,
            source_epoch: wire.source_epoch,
        };
        let required = ProcessorScopeV1 {
            processor_id: "required-fixture".into(),
            method_version: 1,
            identity: identity.clone(),
        };
        let optional = ProcessorScopeV1 {
            processor_id: "disabled-discovery".into(),
            ..required.clone()
        };
        data.register_processor(&required, ProcessorClassV1::Required, 1)?;
        data.register_processor(&optional, ProcessorClassV1::Optional, 1)?;
        let mut connection = self.connect(&tls, &server).await?;
        let control_revision = control.health()?.commit_index;
        let mut changes = data.subscribe_revision();
        let started = Instant::now();
        connection.send_evidence_batch(batch.clone()).await?;
        tokio::time::timeout(Duration::from_secs(5), async {
            while data
                .source_receipt(&identity)?
                .is_none_or(|receipt| receipt.contiguous_cursor < 2)
            {
                changes.changed().await?;
            }
            Ok::<_, Box<dyn StdError>>(())
        })
        .await??;
        let commit_us = started.elapsed().as_micros();
        let page = data.read_page(&identity, 1)?;
        let frames: Vec<u8> = page
            .records
            .iter()
            .flat_map(|record| record.framed_record.iter().copied())
            .collect();
        self.check(
            page.records.len() == 2 && frames == wire.framed_records,
            "intake changed Node frames",
        )?;
        let snapshot = observations
            .coverage_snapshot()
            .ok_or("Node coverage is absent")?;
        let interval = snapshot
            .current_intervals()
            .into_iter()
            .find(|interval| interval.source_id.to_be_bytes() == identity.source_id)
            .ok_or("source coverage is absent")?;
        connection
            .send_coverage_report(&snapshot, &interval)
            .await?;
        let status = data
            .source_status(&identity)?
            .ok_or("source status is absent")?;
        self.check(
            status.receipt.coverage_revision > 0,
            "coverage did not commit",
        )?;
        self.check(
            control.health()?.commit_index == control_revision,
            "data intake changed Control persistence",
        )?;
        let before = data.meta()?;
        drop(connection);
        server.shutdown().await?;
        self.check(
            observations.pending_evidence_records() == 2,
            "Node purged evidence without an ACK",
        )?;
        drop(data);
        drop(control);

        let control = reopen_control_store(&control_root).await?;
        let data = Arc::new(AnalysisStore::open(&data_root)?);
        self.check(
            data.meta()? == before && data.source_status(&identity)? == Some(status),
            "restart changed identity, receipt, coverage, or count",
        )?;
        self.check(
            control.policy_document(&policy_id)?.as_ref() == Some(&policy),
            "restart changed policy",
        )?;
        let intake = EvidenceIntakeOwner::new(control.clone(), data.clone(), clock.clone())?;
        let server = tls.start(tls.control_from_intake(intake, 1)?).await?;
        let mut connection = self.connect(&tls, &server).await?;
        let started = Instant::now();
        connection.send_evidence_batch(batch).await?;
        let ack = Self::ack(&mut connection).await?;
        let ack_us = started.elapsed().as_micros();
        self.check(
            ack.contiguous_cursor == 2 && data.meta()? == before,
            "retry changed the durable result",
        )?;
        observations.acknowledge_evidence(ack)?;
        self.check(
            observations.pending_evidence_records() == 0,
            "Node did not purge acknowledged evidence",
        )?;

        clock.0.store(START + 8 * HOUR, Ordering::SeqCst);
        Self::record(&observations, 3);
        connection
            .send_evidence_batch(
                observations
                    .next_evidence_batch()
                    .ok_or("third record is absent")?,
            )
            .await?;
        let ack = Self::ack(&mut connection).await?;
        self.check(
            ack.contiguous_cursor == 3,
            "disabled discovery stopped intake",
        )?;
        observations.acknowledge_evidence(ack)?;
        let limits = RetentionLimitsV1 {
            raw_max_age_ns: 24 * HOUR,
            raw_max_bytes: 1024 * 1024,
        };
        self.check(
            EvidenceRetentionOwner::new(&data, limits)?
                .retain(&identity, START + 8 * HOUR)?
                .removed_records
                == 0,
            "unexpired input was deleted",
        )?;
        clock.0.store(START + 48 * HOUR, Ordering::SeqCst);
        self.check(
            EvidenceRetentionOwner::new(&data, limits)?
                .retain(&identity, START + 48 * HOUR)?
                .removed_records
                == 0,
            "required input was deleted",
        )?;
        let result = AnalysisResultCommitV1 {
            scope: required,
            expected_cursor: 0,
            consumed_cursor: 3,
            coverage_revision: data
                .source_receipt(&identity)?
                .ok_or("receipt absent")?
                .coverage_revision,
            context_revision: 0,
            result_id: "retained-fixture-result".into(),
            body: br#"{"proof_kind":"synthetic","accepted_records":3}"#.to_vec(),
            created_utc_ns: START + 48 * HOUR,
            witnesses: vec![AnalysisWitnessV1 {
                identity: identity.clone(),
                cursor: 3,
                expires_utc_ns: START + 96 * HOUR,
            }],
            context_refs: Vec::new(),
        };
        let result_receipt = data.commit_result(&result)?;
        let mut competing = result.clone();
        competing.result_id = "competing-result".into();
        self.check(
            matches!(
                data.commit_result(&competing),
                Err(araphor_data::Error::AnalysisConflict { .. })
            ),
            "stale progress was accepted",
        )?;
        let expired =
            EvidenceRetentionOwner::new(&data, limits)?.retain(&identity, START + 48 * HOUR)?;
        self.check(
            expired.removed_records == 2 && expired.retained_floor == 2,
            "expiry did not preserve the exact witness",
        )?;
        self.check(
            matches!(
                data.read_page(&identity, 1),
                Err(araphor_data::Error::RetainedRangeExpired {
                    first_cursor: 1,
                    last_cursor: 2,
                    ..
                })
            ),
            "expiry was not explicit",
        )?;
        let witness = data.read_page(&identity, 3)?;
        self.check(
            witness.records.len() == 1 && witness.records[0].cursor == 3,
            "the exact witness is not readable",
        )?;
        let gap = data
            .resume_optional(&optional)?
            .ok_or("optional missing range is absent")?;
        self.check(
            gap.first_cursor == 1
                && gap.last_cursor == 2
                && data.resume_optional(&optional)?.is_none(),
            "optional resume changed or repeated the gap",
        )?;
        self.check(
            data.read_result(identity.tenant_id, &result.result_id)? == Some(result.body.clone())
                && data.read_result([9; 16], &result.result_id)?.is_none(),
            "result read crossed its tenant or changed content",
        )?;
        self.check(
            control.health()?.evidence_cursors == 0
                && control.policy_document(&policy_id)?.as_ref() == Some(&policy),
            "data work changed policy or used the old writer",
        )?;
        let checkpoint_start = Instant::now();
        data.checkpoint()?;
        let checkpoint_us = checkpoint_start.elapsed().as_micros();
        let database_bytes = fs::metadata(data_root.join("analysis.duckdb"))?.len();
        let wal_bytes = match fs::metadata(data_root.join("analysis.duckdb.wal")) {
            Ok(metadata) => metadata.len(),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => 0,
            Err(error) => return Err(error.into()),
        };
        let backup_path = backup_root.join("after-expiry.duckdb");
        let backup = data.backup(&backup_path)?;
        let restored = AnalysisStore::restore(&backup_path, &tls.path().join("restored"))?;
        self.check(
            restored.source_status(&identity)? == data.source_status(&identity)?
                && restored.read_result(identity.tenant_id, &result.result_id)?
                    == Some(result.body.clone())
                && restored.commit_result(&result)? == result_receipt
                && restored.read_page(&identity, 3)?.records == witness.records,
            "backup lost retained results, witness, receipt, or coverage",
        )?;
        self.check(
            restored.meta()?.recovery_epoch == data.meta()?.recovery_epoch + 1,
            "restore did not change the recovery epoch",
        )?;
        let stale = AnalysisStore::restore(&stale_path, &tls.path().join("stale-restored"))?;
        self.check(
            observations.pending_evidence_records() == 0
                && stale.record_recovery_floor(&identity, 3)?
                    == AnalysisRecoveryStatusV1::Partial {
                        first_cursor: 1,
                        last_cursor: 3,
                    },
            "stale backup hid purged Node input",
        )?;
        drop(connection);
        server.shutdown().await?;
        let checks = [
            "production-mtls-intake",
            "exact-node-frames",
            "coverage-commit",
            "lost-ack-keeps-node-wal",
            "restart-keeps-source-state",
            "duplicate-noop",
            "durable-ack-purges-node-wal",
            "disabled-discovery-intake",
            "required-progress-protection",
            "atomic-result-progress-conflict",
            "exact-witness-retention",
            "explicit-expired-range",
            "optional-resume-gap",
            "tenant-scoped-result",
            "unchanged-policy",
            "single-evidence-writer",
            "backup-after-expiry",
            "restore-recovery-epoch",
            "stale-backup-partial",
        ];
        fs::create_dir(&self.output)?;
        super::write_json(
            &self.output.join("result.json"),
            &serde_json::json!({
                "schema_version": 1, "case": "data-store-recovery", "result": "PASS",
                "production_intake": true, "proof_kind": "synthetic",
                "assertion_count": checks.len(), "asserted_contracts": checks,
                "source_identity": identity, "contiguous_cursor": 3, "retained_floor": 2,
                "retained_event_count": 1, "backup_revision": backup.commit_revision,
                "batch_commit_us": commit_us, "durable_ack_us": ack_us,
                "checkpoint_us": checkpoint_us, "database_bytes": database_bytes,
                "wal_bytes_after_checkpoint": wal_bytes,
                "remaining_qualification": ["capacity-backpressure", "crash-injection", "physical-disk-reuse"],
            }),
        )?;
        Ok(())
    }

    fn record(observations: &EffectObservationStore, sequence: u64) {
        let raw = erebor_interceptor_abi::EffectObservationV1 {
            observed_boottime_ns: sequence + 100,
            source_sequence: sequence,
            source_cpu_id: 3,
            task_cookie: 7,
            process_instance_id: EvidenceIdV1::new(8, 9),
            entry_instance_id: EvidenceIdV1::new(10, 11),
            reason: 9,
            physical_result: 1,
            effect_family: 1,
            operation: 1,
            ..Default::default()
        };
        observations.record_bytes(raw.as_bytes());
    }

    async fn connect(
        &self,
        tls: &MtlsFixture,
        server: &ControlServerFixture,
    ) -> Result<ControlConnection> {
        let mut trust = TrustCache::load(&tls.path().join("trust"))?;
        Ok(tls
            .connector(server, "node-a", [7; 16])
            .connect(
                NodeRegistration {
                    platform_digest: "a".repeat(64),
                    program_digest: "b".repeat(64),
                    label_epoch: 1,
                    kernel_ready: true,
                    effect_prevention_claims_enabled: false,
                    kubernetes_node_name: String::new(),
                    startup_absence_proof_digest: mithril_control::startup_absence_proof_digest(
                        "node-a", &[7; 16], 1, true, true,
                    ),
                    policy_authority_absent: true,
                    exception_authority_absent: true,
                    capabilities: vec![mithril_control::CapabilityRecord {
                        capability_id: "KERNEL_LSM_CHASSIS".into(),
                        state: "UNSUPPORTED".into(),
                        reason_code: "SYNTHETIC_INPUT_ONLY".into(),
                    }],
                    workload_targets: Vec::new(),
                },
                false,
                &mut trust,
            )
            .await?)
    }

    async fn ack(connection: &mut ControlConnection) -> Result<mithril_node::EvidenceAckV1> {
        Ok(tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if let NodeControlMessage::EvidenceAck(ack) = connection.next_message().await? {
                    return Ok::<_, mithril_node::Error>(ack);
                }
            }
        })
        .await??)
    }

    fn check(&self, passed: bool, reason: &str) -> Result<()> {
        if !passed {
            return Err(crate::error::InvalidInputSnafu {
                path: &self.output,
                reason,
            }
            .build()
            .into());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn data_store_recovery() -> Result<()> {
        let output = tempfile::tempdir()?;
        DataStoreQualification::new(output.path().join("result"))
            .recovery()
            .await
    }
}
