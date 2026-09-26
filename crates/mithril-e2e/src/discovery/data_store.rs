use std::{
    error::Error as StdError,
    fs,
    os::unix::fs::DirBuilderExt as _,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use araphor_data::{
    AnalysisRecoveryStatusV1, AnalysisResultCommitV1, AnalysisStore, AnalysisWitnessV1,
    EvidenceIntakeIdentityV1, EvidenceRetentionOwner, ProcessorClassV1, ProcessorScopeV1,
    ProcessorStateV1, RetentionLimitsV1,
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

    pub async fn startup(&self) -> Result<()> {
        self.check(!self.output.exists(), "the output directory already exists")?;
        let tls = MtlsFixture::new(false)?;
        let control_root = tls.path().join("control-store");
        let control = ControlStore::open(&control_root)?;
        let policy_id = {
            let fixture = OutagePolicyFixture::new(control.clone());
            let resource = fixture.resource(1)?;
            fixture
                .owner
                .reconcile(
                    &resource,
                    OUTAGE_NAMESPACE_UID,
                    &fixture.inventory(&resource)?,
                    i64::try_from(START)?,
                )?
                .source_revision
                .policy_source_revision_id
        };
        let policy = control
            .policy_document(&policy_id)?
            .ok_or("policy is absent")?;
        drop(control);
        let parts = tls.configuration()?.into_parts()?;
        if let Some(error) = parts.data_error {
            return Err(error.into());
        }
        let data = parts
            .control
            .analysis_store()
            .ok_or("data owner is absent")?;
        let server = tls.start(parts.control).await?;
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
        let batch = observations
            .next_evidence_batch()
            .ok_or("Node batch is absent")?;
        let wire: mithril_control::EvidenceBatch = batch.clone().into();
        let identity = EvidenceIntakeIdentityV1 {
            tenant_id: EvidenceIdV1::new(1, 2).to_be_bytes(),
            node_id: "node-a".into(),
            node_boot_id: [7; 16],
            label_epoch: 1,
            source_id: wire.source_id.as_slice().try_into()?,
            source_epoch: wire.source_epoch,
        };
        let mut connection = self.connect(&tls, &server).await?;
        connection.send_evidence_batch(batch.clone()).await?;
        let ack = Self::ack(&mut connection).await?;
        self.check(
            ack.contiguous_cursor == 1,
            "default intake did not acknowledge",
        )?;
        observations.acknowledge_evidence(ack)?;
        let page = data.read_page(&identity, 1)?;
        self.check(
            page.records.len() == 1 && page.records[0].framed_record == wire.framed_records,
            "default intake did not retain the exact frame",
        )?;
        drop(connection);
        server.shutdown().await?;
        let before = data.meta()?;
        drop(data);
        drop(Self::reopen_data(&tls.path().join("evidence/analysis")).await?);
        let control = reopen_control_store(&control_root).await?;
        self.check(
            control.health()?.evidence_cursors == 0
                && control.policy_document(&policy_id)?.as_ref() == Some(&policy),
            "default intake changed policy or used the old evidence writer",
        )?;
        drop(control);

        let parts = tls.configuration()?.into_parts()?;
        if let Some(error) = parts.data_error {
            return Err(error.into());
        }
        let data = parts
            .control
            .analysis_store()
            .ok_or("data owner is absent")?;
        self.check(
            data.meta()? == before,
            "restart changed data identity or revision",
        )?;
        let server = tls.start(parts.control).await?;
        let mut connection = self.connect(&tls, &server).await?;
        connection.send_evidence_batch(batch.clone()).await?;
        self.check(
            Self::ack(&mut connection).await?.contiguous_cursor == 1,
            "restart lost the durable ACK",
        )?;
        self.check(data.meta()? == before, "retry changed committed data")?;
        drop(connection);
        server.shutdown().await?;
        drop(data);
        drop(Self::reopen_data(&tls.path().join("evidence/analysis")).await?);
        drop(reopen_control_store(&control_root).await?);

        let database = tls.path().join("evidence/analysis/analysis.duckdb");
        Self::record(&observations, 2);
        let faults = [
            Some("UPDATE source_receipts SET contiguous_cursor = 2"),
            Some("UPDATE store_meta SET schema_version = 99"),
            Some("UPDATE store_meta SET schema_version = 5; ALTER TABLE events RENAME TO missing_events"),
            None,
        ];
        for fault in faults {
            match fault {
                Some(sql) => duckdb::Connection::open(&database)?.execute_batch(sql)?,
                None => fs::write(&database, b"invalid database")?,
            }
            let parts = tls.configuration()?.into_parts()?;
            self.check(
                parts.data_error.is_some() && parts.control.analysis_store().is_none(),
                "corrupt data enabled intake",
            )?;
            let server = tls.start(parts.control).await?;
            let mut connection = self.connect(&tls, &server).await?;
            connection.report_readiness(true, true).await?;
            connection.policy_inventory(None, Vec::new()).await?;
            connection
                .send_evidence_batch(
                    observations
                        .next_evidence_batch()
                        .ok_or("Node batch is absent")?,
                )
                .await?;
            let error =
                tokio::time::timeout(Duration::from_secs(5), connection.next_message()).await?;
            self.check(
                matches!(error, Err(mithril_node::Error::ControlRpc { source, .. })
                if source.code() == tonic::Code::Unavailable),
                "corrupt data did not return Unavailable",
            )?;
            self.check(
                observations.pending_evidence_records() == 1,
                "Node purged unacknowledged input",
            )?;
            let snapshot = observations
                .coverage_snapshot()
                .ok_or("Node coverage is absent")?;
            let interval = snapshot
                .current_intervals()
                .into_iter()
                .find(|interval| interval.source_id.to_be_bytes() == identity.source_id)
                .ok_or("source coverage is absent")?;
            let coverage = connection.send_coverage_report(&snapshot, &interval).await;
            self.check(
                matches!(coverage, Err(mithril_node::Error::ControlRpc { source, .. })
                if source.code() == tonic::Code::Unavailable),
                "unavailable data acknowledged coverage",
            )?;
            connection.policy_inventory(None, Vec::new()).await?;
            drop(connection);
            server.shutdown().await?;
            let control = reopen_control_store(&control_root).await?;
            self.check(
                control.health()?.evidence_cursors == 0
                    && control.policy_document(&policy_id)?.as_ref() == Some(&policy),
                "data failure changed policy or selected the old writer",
            )?;
            drop(control);
        }
        self.check(
            fs::read(&database)? == b"invalid database",
            "corrupt data was rewritten",
        )?;

        let old = MtlsFixture::new(false)?;
        let control = ControlStore::open(old.path().join("control-store"))?;
        let intake = EvidenceIntakeOwner::from_store(control.clone());
        intake.receive(
            &mithril_control::AuthenticatedEvidenceNodeV1 {
                tenant_id: identity.tenant_id,
                node_id: identity.node_id.clone(),
                node_boot_id: identity.node_boot_id,
                label_epoch: identity.label_epoch,
            },
            wire,
        )?;
        drop(intake);
        drop(control);
        self.check(
            old.configuration()?.into_parts().is_err(),
            "old receipts were accepted",
        )?;
        self.check(
            !old.path().join("evidence/analysis").exists(),
            "old receipts created a new data store",
        )?;

        let checks = [
            "default-data-owner",
            "exact-frame",
            "durable-ack",
            "single-writer",
            "unchanged-policy",
            "current-format-restart",
            "duplicate-noop",
            "corrupt-data-unavailable",
            "invalid-receipt-unavailable",
            "unsupported-schema-unavailable",
            "missing-table-unavailable",
            "coverage-unavailable",
            "policy-rpc-survives",
            "node-keeps-unacknowledged-input",
            "no-empty-store-fallback",
            "old-receipt-refusal",
        ];
        fs::create_dir(&self.output)?;
        super::write_json(
            &self.output.join("result.json"),
            &serde_json::json!({
                "schema_version": 1, "case": "data-store-startup", "result": "PASS",
                "proof_kind": "synthetic", "production_intake": true,
                "assertion_count": checks.len(), "asserted_contracts": checks,
                "source_identity": identity, "store_uuid": before.store_uuid.to_string(),
                "commit_revision": before.commit_revision,
            }),
        )?;
        Ok(())
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
        let data = Arc::new(Self::reopen_data(&data_root).await?);
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
        let health = data
            .processor_health(&required)?
            .ok_or("required health is absent")?;
        self.check(
            health.state == ProcessorStateV1::Lagging
                && health.cursor_lag == 3
                && data.storage_health()?.retention_healthy,
            "required lag was hidden or changed intake health",
        )?;
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
        let protected_revision = data.meta()?.commit_revision;
        Self::record(&observations, 4);
        let blocked = observations
            .next_evidence_batch()
            .ok_or("fourth record absent")?;
        connection.report_readiness(true, true).await?;
        connection.send_evidence_batch(blocked.clone()).await?;
        let rejected =
            tokio::time::timeout(Duration::from_secs(5), connection.next_message()).await?;
        self.check(
            matches!(rejected, Err(mithril_node::Error::ControlRpc { source, .. })
            if source.code() == tonic::Code::ResourceExhausted),
            "required age bound did not backpressure intake",
        )?;
        self.check(
            observations.pending_evidence_records() == 1
                && data.meta()?.commit_revision == protected_revision,
            "backpressure lost Node input or committed a partial batch",
        )?;
        connection.policy_inventory(None, Vec::new()).await?;
        drop(connection);
        let mut connection = self.connect(&tls, &server).await?;
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
        connection.send_evidence_batch(blocked.clone()).await?;
        let ack = Self::ack(&mut connection).await?;
        self.check(
            ack.contiguous_cursor == 4,
            "caught-up processor did not release intake",
        )?;
        observations.acknowledge_evidence(ack)?;
        let mut revisions = data.subscribe_revision();
        tokio::time::timeout(Duration::from_secs(5), async {
            while data
                .source_receipt(&identity)?
                .ok_or("receipt absent")?
                .retained_floor
                != 2
            {
                revisions.changed().await?;
            }
            Ok::<_, Box<dyn StdError>>(())
        })
        .await??;
        self.check(data.retention_healthy(), "automatic retention failed")?;
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
            witness.records.len() == 2
                && witness.records[0].cursor == 3
                && witness.records[1].cursor == 4,
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
        let health = data
            .processor_health(&optional)?
            .ok_or("optional health is absent")?;
        self.check(
            health.state == ProcessorStateV1::Lagging
                && health.incomplete
                && health.consumed_cursor == 0
                && health.resume_floor == 2,
            "optional health hid the missing interval or invented consumed progress",
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
        connection.send_evidence_batch(blocked).await?;
        let ack = Self::ack(&mut connection).await?;
        self.check(
            ack.contiguous_cursor == 4 && data.meta()?.commit_revision == backup.commit_revision,
            "backup did not reopen intake or replay changed the revision",
        )?;
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
                && stale.record_recovery_floor(&identity, 4)?
                    == AnalysisRecoveryStatusV1::Partial {
                        first_cursor: 1,
                        last_cursor: 4,
                    },
            "stale backup hid purged Node input",
        )?;
        let gaps = stale.recovery_gaps(&identity, 0)?;
        let before = stale.meta()?;
        drop(stale);
        let stale = AnalysisStore::open(tls.path().join("stale-restored"))?;
        self.check(
            gaps.len() == 1
                && gaps[0].first_cursor == 1
                && gaps[0].last_cursor == 4
                && stale.recovery_gaps(&identity, 0)? == gaps
                && stale.meta()? == before
                && stale.source_receipt(&identity)?.is_none(),
            "recovery gap restart lost evidence or invented an accepted receipt",
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
            "required-lag-health",
            "required-age-backpressure",
            "protected-input-retry",
            "policy-rpc-during-backpressure",
            "automatic-retention",
            "atomic-result-progress-conflict",
            "exact-witness-retention",
            "explicit-expired-range",
            "optional-resume-gap",
            "optional-incomplete-health",
            "tenant-scoped-result",
            "unchanged-policy",
            "single-evidence-writer",
            "backup-after-expiry",
            "backup-reopens-intake",
            "restore-recovery-epoch",
            "stale-backup-partial",
            "recovery-gap-restart",
        ];
        fs::create_dir(&self.output)?;
        super::write_json(
            &self.output.join("result.json"),
            &serde_json::json!({
                "schema_version": 1, "case": "data-store-recovery", "result": "PASS",
                "production_intake": true, "proof_kind": "synthetic",
                "assertion_count": checks.len(), "asserted_contracts": checks,
                "source_identity": identity, "contiguous_cursor": 4, "retained_floor": 2,
                "retained_event_count": 2, "backup_revision": backup.commit_revision,
                "batch_commit_us": commit_us, "durable_ack_us": ack_us,
                "checkpoint_us": checkpoint_us, "database_bytes": database_bytes,
                "wal_bytes_after_checkpoint": wal_bytes,
                "remaining_qualification": ["physical-capacity-backpressure", "crash-injection", "physical-disk-reuse"],
            }),
        )?;
        Ok(())
    }

    async fn reopen_data(root: &Path) -> Result<AnalysisStore> {
        Ok(crate::physical::wait_for_async(
            root,
            "the stopped server to release its data lease",
            Duration::from_secs(5),
            || match AnalysisStore::open(root) {
                Err(araphor_data::Error::AnalysisState { reason, .. })
                    if reason.starts_with("the analysis writer is already owned:") =>
                {
                    Ok(None)
                }
                result => Ok(Some(result)),
            },
            || "the stopped server still holds the data lease".into(),
        )
        .await??)
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
    async fn data_context_projection() -> Result<()> {
        use araphor_data::AnalysisContextKeyV1;
        let tls = MtlsFixture::new(false)?;
        let store = ControlStore::open(tls.path().join("control-store"))?;
        let fixture = OutagePolicyFixture::new(store.clone());
        let resource = fixture.resource(1)?;
        let first = fixture.owner.reconcile(
            &resource,
            OUTAGE_NAMESPACE_UID,
            &fixture.inventory(&resource)?,
            i64::try_from(START)?,
        )?;
        let data = Arc::new(AnalysisStore::open(tls.path().join("analysis"))?);
        let intake = EvidenceIntakeOwner::new(
            store.clone(),
            data.clone(),
            Arc::new(TestClock(AtomicU64::new(START))),
        )?;
        let control = tls.control_from_intake(intake, 1)?;
        let authority = store.commit_index();
        let source = &first.source_revision;
        let source_key = AnalysisContextKeyV1 {
            tenant_id: EvidenceIdV1::new(1, 2).to_be_bytes(),
            owner_id: "mithril-control/policy".into(),
            entity_key: source.object_uid.as_bytes().to_vec(),
            lifetime_key: source.policy_source_revision_id.as_bytes().to_vec(),
            owner_revision: source.object_generation,
        };
        assert_eq!(data.context_version(&source_key)?, None);
        let server = tls.start(control.clone()).await?;
        let projected = ControlServerFixture::wait_context(&data, &source_key).await?;
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&projected.body)?,
            serde_json::json!({"source": source,
                "document": store.policy_document(&source.policy_source_revision_id)?})
        );
        assert_eq!(projected.valid_from_utc_ns, None);
        assert_eq!(projected.valid_until_utc_ns, None);
        let rollout = first.rollout_states.first().ok_or("rollout absent")?;
        assert_eq!(rollout.transition_version, 0);
        let rollout_key = AnalysisContextKeyV1 {
            tenant_id: source_key.tenant_id,
            owner_id: "mithril-control/rollout".into(),
            entity_key: rollout.target.node_id.as_bytes().to_vec(),
            lifetime_key: rollout.desired_candidate_content_id.as_bytes().to_vec(),
            owner_revision: rollout.transition_version,
        };
        let pending = ControlServerFixture::wait_context(&data, &rollout_key).await?;
        assert_eq!(pending.body, serde_json::to_vec(rollout)?);
        assert_eq!(store.commit_index(), authority);
        let mut foreign = source_key.clone();
        foreign.tenant_id = [9; 16];
        assert_eq!(data.context_version(&foreign)?, None);

        let resource = fixture.resource(2)?;
        let second = fixture.owner.reconcile(
            &resource,
            OUTAGE_NAMESPACE_UID,
            &fixture.inventory(&resource)?,
            i64::try_from(START + 1)?,
        )?;
        let source = &second.source_revision;
        let second_key = AnalysisContextKeyV1 {
            lifetime_key: source.policy_source_revision_id.as_bytes().to_vec(),
            owner_revision: source.object_generation,
            ..source_key.clone()
        };
        let second_copy = ControlServerFixture::wait_context(&data, &second_key).await?;
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&second_copy.body)?,
            serde_json::json!({"source": source,
                "document": store.policy_document(&source.policy_source_revision_id)?})
        );
        assert_eq!(data.context_version(&source_key)?, Some(projected));
        assert_eq!(data.context_version(&rollout_key)?, Some(pending));
        server.shutdown().await?;
        let allowed: Vec<_> = control.allowed_nodes().values().cloned().collect();
        let mut projector =
            mithril_control::ControlContextOwner::new(store.clone(), data.clone(), &allowed)?;
        projector.reconcile()?;
        let before = data.meta()?;
        projector.reconcile()?;
        assert_eq!(data.meta()?, before);
        let server = tls.start(control).await?;
        let case = DataStoreQualification::new(tls.path().join("result"));
        let mut connection = case.connect(&tls, &server).await?;
        connection.report_readiness(true, true).await?;
        connection.policy_inventory(None, Vec::new()).await?;
        assert_eq!(data.meta()?, before);
        drop(connection);
        server.shutdown().await?;
        Ok(())
    }

    #[tokio::test]
    async fn data_reopen_preserves_errors() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let root = directory.path().join("analysis");
        let store = AnalysisStore::open(&root)?;
        let reopening = DataStoreQualification::reopen_data(&root);
        tokio::pin!(reopening);
        assert!(
            tokio::time::timeout(Duration::from_millis(20), &mut reopening)
                .await
                .is_err()
        );
        drop(store);
        drop(reopening.await?);
        fs::write(root.join("analysis.duckdb"), b"invalid database")?;
        let error = DataStoreQualification::reopen_data(&root)
            .await
            .err()
            .ok_or("corrupt store accepted")?;
        assert!(matches!(
            error.downcast_ref::<araphor_data::Error>(),
            Some(araphor_data::Error::AnalysisDatabase { .. })
        ));
        Ok(())
    }

    #[tokio::test]
    async fn data_store_startup() -> Result<()> {
        let output = tempfile::tempdir()?;
        DataStoreQualification::new(output.path().join("result"))
            .startup()
            .await
    }

    #[tokio::test]
    async fn data_store_recovery() -> Result<()> {
        let output = tempfile::tempdir()?;
        DataStoreQualification::new(output.path().join("result"))
            .recovery()
            .await
    }

    #[tokio::test]
    async fn data_retirement_startup() -> Result<()> {
        let tls = MtlsFixture::new(false)?;
        let case = DataStoreQualification::new(tls.path().join("result"));
        let parts = tls.configuration()?.into_parts()?;
        let data = parts.control.analysis_store().ok_or("data owner absent")?;
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
        DataStoreQualification::record(&observations, 1);
        let batch = observations.next_evidence_batch().ok_or("batch absent")?;
        let wire: mithril_control::EvidenceBatch = batch.clone().into();
        let request = araphor_data::ProcessorRetirementV1 {
            scope: ProcessorScopeV1 {
                processor_id: "security-fixture".into(),
                method_version: 1,
                identity: EvidenceIntakeIdentityV1 {
                    tenant_id: EvidenceIdV1::new(1, 2).to_be_bytes(),
                    node_id: "node-a".into(),
                    node_boot_id: [7; 16],
                    label_epoch: 1,
                    source_id: wire.source_id.as_slice().try_into()?,
                    source_epoch: wire.source_epoch,
                },
            },
            change_id: "operator-change-1".into(),
            reason: "Retire this fixture package.".into(),
            expected_cursor: 0,
            cutoff_cursor: 1,
        };
        data.register_processor(&request.scope, ProcessorClassV1::Required, 1)?;
        let server = tls.start(parts.control).await?;
        let mut connection = case.connect(&tls, &server).await?;
        connection.send_evidence_batch(batch).await?;
        observations.acknowledge_evidence(DataStoreQualification::ack(&mut connection).await?)?;
        let before = data.meta()?;
        let mut config = tls.configuration()?;
        let mut foreign = request.clone();
        foreign.scope.identity.tenant_id = [9; 16];
        config.data_retirements = vec![foreign];
        assert!(config.into_parts().is_err());
        let mut config = tls.configuration()?;
        config.data_retirements = vec![request.clone(), request.clone()];
        assert!(config.into_parts().is_err());
        let mut config = tls.configuration()?;
        config.data_retirements = vec![request.clone(); 33];
        assert!(config.into_parts().is_err());
        assert_eq!(data.meta()?, before);
        assert!(data.processor_retirement(&request.scope)?.is_none());
        drop(connection);
        server.shutdown().await?;
        drop(data);
        drop(DataStoreQualification::reopen_data(&tls.path().join("evidence/analysis")).await?);
        drop(reopen_control_store(&tls.path().join("control-store")).await?);

        let mut config = tls.configuration()?;
        let mut stale = request.clone();
        stale.cutoff_cursor = 0;
        config.data_retirements = vec![stale];
        let parts = config.into_parts()?;
        assert!(parts.data_error.is_some());
        assert!(parts.control.analysis_store().is_none());
        let server = tls.start(parts.control).await?;
        let mut connection = case.connect(&tls, &server).await?;
        connection.report_readiness(true, true).await?;
        connection.policy_inventory(None, Vec::new()).await?;
        DataStoreQualification::record(&observations, 2);
        let pending = observations
            .next_evidence_batch()
            .ok_or("pending batch absent")?;
        connection.send_evidence_batch(pending.clone()).await?;
        let rejected =
            tokio::time::timeout(Duration::from_secs(5), connection.next_message()).await?;
        assert!(
            matches!(rejected, Err(mithril_node::Error::ControlRpc { source, .. }) if source.code() == tonic::Code::Unavailable)
        );
        assert_eq!(observations.pending_evidence_records(), 1);
        drop(connection);
        server.shutdown().await?;
        drop(reopen_control_store(&tls.path().join("control-store")).await?);

        let mut config = tls.configuration()?;
        config.data_retirements = vec![request.clone()];
        let parts = config.into_parts()?;
        assert!(parts.data_error.is_none(), "{:?}", parts.data_error);
        let data = parts.control.analysis_store().ok_or("data owner absent")?;
        let retirement = data
            .processor_retirement(&request.scope)?
            .ok_or("retirement absent")?;
        assert_eq!(retirement.0, request);
        let health = data
            .processor_health(&request.scope)?
            .ok_or("health absent")?;
        assert_eq!(health.state, ProcessorStateV1::Retired);
        assert_eq!(health.consumed_cursor, 0);
        assert!(health.incomplete);
        let server = tls.start(parts.control).await?;
        let mut connection = case.connect(&tls, &server).await?;
        connection.send_evidence_batch(pending).await?;
        let ack = DataStoreQualification::ack(&mut connection).await?;
        assert_eq!(ack.contiguous_cursor, 2);
        observations.acknowledge_evidence(ack)?;
        assert_eq!(observations.pending_evidence_records(), 0);
        let before = data.meta()?;
        drop(connection);
        server.shutdown().await?;
        drop(data);
        drop(DataStoreQualification::reopen_data(&tls.path().join("evidence/analysis")).await?);
        drop(reopen_control_store(&tls.path().join("control-store")).await?);
        let mut config = tls.configuration()?;
        config.data_retirements = vec![request.clone()];
        let parts = config.into_parts()?;
        assert!(parts.data_error.is_none(), "{:?}", parts.data_error);
        let data = parts.control.analysis_store().ok_or("data owner absent")?;
        assert_eq!(data.meta()?, before);
        assert_eq!(data.processor_retirement(&request.scope)?, Some(retirement));
        Ok(())
    }

    #[tokio::test]
    async fn data_capacity_retry() -> Result<()> {
        for logical in [false, true] {
            let tls = MtlsFixture::new(false)?;
            let case = DataStoreQualification::new(tls.path().join("result"));
            let mut config = tls.configuration()?;
            if logical {
                config.data_storage.tenant_max_bytes = 1;
            } else {
                config.data_storage.policy_reserve_bytes = u64::MAX / 4;
            }
            let parts = config.into_parts()?;
            assert!(parts.data_error.is_none());
            let data = parts.control.analysis_store().ok_or("data owner absent")?;
            let server = tls.start(parts.control).await?;
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
            DataStoreQualification::record(&observations, 1);
            let batch = observations.next_evidence_batch().ok_or("batch absent")?;
            let mut connection = case.connect(&tls, &server).await?;
            connection.report_readiness(true, true).await?;
            connection.send_evidence_batch(batch.clone()).await?;
            let rejected =
                tokio::time::timeout(Duration::from_secs(5), connection.next_message()).await?;
            assert!(
                matches!(rejected, Err(mithril_node::Error::ControlRpc { source, .. }) if source.code() == tonic::Code::ResourceExhausted)
            );
            assert_eq!(observations.pending_evidence_records(), 1);
            assert_eq!(data.meta()?.commit_revision, 0);
            connection.policy_inventory(None, Vec::new()).await?;
            drop(connection);
            server.shutdown().await?;
            drop(data);
            drop(DataStoreQualification::reopen_data(&tls.path().join("evidence/analysis")).await?);
            drop(reopen_control_store(&tls.path().join("control-store")).await?);

            let parts = tls.configuration()?.into_parts()?;
            assert!(parts.data_error.is_none(), "{:?}", parts.data_error);
            let data = parts.control.analysis_store().ok_or("data owner absent")?;
            let trust = parts.control.trust_bundle_owner().current()?;
            let server = tls.start(parts.control).await?;
            ControlServerFixture::wait_context(
                &data,
                &araphor_data::AnalysisContextKeyV1 {
                    tenant_id: EvidenceIdV1::new(1, 2).to_be_bytes(),
                    owner_id: "mithril-control/trust".into(),
                    entity_key: b"trust".to_vec(),
                    lifetime_key: trust.bundle_digest.into_bytes(),
                    owner_revision: trust.generation,
                },
            )
            .await?;
            let baseline = data.meta()?.commit_revision;
            let mut connection = case.connect(&tls, &server).await?;
            connection.send_evidence_batch(batch).await?;
            let ack = DataStoreQualification::ack(&mut connection).await?;
            assert_eq!(ack.contiguous_cursor, 1);
            observations.acknowledge_evidence(ack)?;
            assert_eq!(observations.pending_evidence_records(), 0);
            assert_eq!(data.meta()?.commit_revision, baseline + 1);
            drop(connection);
            server.shutdown().await?;
        }
        Ok(())
    }
}
