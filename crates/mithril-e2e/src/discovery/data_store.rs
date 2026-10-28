use std::{
    error::Error as StdError,
    fs,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use araphor_data::{
    AnalysisResultCommitV1, AnalysisStore, AnalysisWitnessV1, EvidenceIntakeIdentityV1,
    EvidenceRetentionOwner, ProcessorClassV1, ProcessorScopeV1, ProcessorStateV1,
};
use mithril_control::{
    ControlStore, EvidenceIdV1, EvidenceIntakeOwner, IntakeClock, NodeRegistration,
};
use mithril_node::{
    ControlConnection, EffectObservationStore, EvidenceWalLimits, NodeControlMessage,
    ObservationCanonicalizer, TrustCache,
};
use zerocopy::IntoBytes as _;

mod inspection;
mod rollout;

use crate::control_fixture::{
    reopen_control_store, ControlServerFixture, MtlsFixture, OutagePolicyFixture,
    OUTAGE_NAMESPACE_UID,
};

type Result<T> = std::result::Result<T, Box<dyn StdError>>;
const START: u64 = 1_800_000_000_000_000_000;
const HOUR: u64 = 3_600_000_000_000;

struct TestClock(AtomicU64);

enum StartupFault {
    Pending,
    Sql(&'static str),
    Corrupt,
}

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

    pub async fn load(&self) -> Result<()> {
        self.load_tenants(64, 1).await
    }

    async fn load_group(
        &self,
        observations: &EffectObservationStore,
        group: u64,
    ) -> Result<Vec<mithril_node::EvidenceBatchV1>> {
        let (ingress, worker) = observations.ingestion_queue(Some(4096), 1024)?;
        for cursor in group * 4096 + 1..=(group + 1) * 4096 {
            ingress.record_bytes(Self::event(cursor).as_bytes());
        }
        drop(ingress);
        tokio::task::spawn_blocking(move || worker.run()).await?;
        self.check(
            observations.evidence_errors() == 0,
            "Node dropped load input",
        )?;
        let batches = observations.next_evidence_batches();
        self.check(
            batches
                .iter()
                .map(|batch| batch.record_count())
                .sum::<usize>()
                == 4096,
            "Node did not return one complete load group",
        )?;
        Ok(batches)
    }

    pub async fn tenant_load(&self, tenants: usize) -> Result<()> {
        self.check((2..=10).contains(&tenants), "the tenant count is invalid")?;
        self.load_tenants(32, tenants).await
    }

    async fn load_tenants(&self, groups: u64, tenants: usize) -> Result<()> {
        use sha2::{Digest as _, Sha256};

        self.check(!self.output.exists(), "the output directory already exists")?;
        self.check((1..=10).contains(&tenants), "the tenant count is invalid")?;
        let group_limit = if tenants == 1 { 64 } else { 32 };
        self.check(
            (1..=group_limit).contains(&groups),
            "the load group count is invalid",
        )?;
        let fixtures = (0..tenants)
            .map(|_| MtlsFixture::new(false))
            .collect::<Result<Vec<_>>>()?;
        let mut roots = String::new();
        for tls in &fixtures {
            roots.push_str(&fs::read_to_string(&tls.files.ca)?);
        }
        let mut allowed = Vec::new();
        for (index, tls) in fixtures.iter().enumerate() {
            fs::write(&tls.files.ca, &roots)?;
            let mut node = tls.configuration()?.allowed_nodes.remove(0);
            node.node_id = format!("node-{index}");
            node.tenant_id =
                uuid::Uuid::from_bytes(EvidenceIdV1::new(1, 2 + index as u64).to_be_bytes())
                    .to_string();
            allowed.push(node);
        }
        let root = fixtures[0].path().join("analysis");
        let control = ControlStore::open(fixtures[0].path().join("control-store"))?;
        let data = Arc::new(AnalysisStore::open(&root)?);
        let intake = EvidenceIntakeOwner::new(
            control.clone(),
            data.clone(),
            Arc::new(TestClock(AtomicU64::new(START))),
        )?;
        let plane = mithril_control::ControlPlane::from_intake(
            allowed.clone(),
            mithril_control::TrustGenerationV1 {
                generation: 1,
                bundle_digest: "d".repeat(64),
                policy_issuer_sequence_epoch: 0,
                policy_signers: Vec::new(),
            },
            intake,
        )?;
        let trust = plane.trust_bundle_owner().current()?;
        let server = fixtures[0].start(plane).await?;
        for index in 0..tenants {
            ControlServerFixture::wait_context(
                &data,
                &araphor_data::AnalysisContextKeyV1 {
                    tenant_id: EvidenceIdV1::new(1, 2 + index as u64).to_be_bytes(),
                    owner_id: "mithril-control/trust".into(),
                    entity_key: b"trust".to_vec(),
                    lifetime_key: trust.bundle_digest.as_bytes().to_vec(),
                    owner_revision: trust.generation,
                },
            )
            .await?;
        }
        let mut connections = Vec::new();
        let mut observations = Vec::new();
        for (index, tls) in fixtures.iter().enumerate() {
            let boot = [7 + index as u8; 16];
            observations.push(EffectObservationStore::durable(
                4096,
                tls.path().join("wal"),
                EvidenceWalLimits::default(),
                ObservationCanonicalizer::new(
                    EvidenceIdV1::new(1, 2 + index as u64),
                    EvidenceIdV1::new(3, 4),
                    1,
                    boot.into(),
                )?,
            )?);
            let connection = self
                .connect_at(tls, server.address(), &allowed[index].node_id, boot)
                .await?;
            connection.report_readiness(true, true).await?;
            connections.push(connection);
        }
        let mut identities = Vec::new();
        let mut digests = vec![Sha256::new(); tenants];
        let mut input_bytes = vec![0_usize; tenants];
        let mut samples = Vec::new();
        let mut peak_bytes = 0;
        let started = Instant::now();
        for group in 0..groups {
            let mut batches = Vec::new();
            let mut node_times = Vec::new();
            for index in 0..tenants {
                let generated = Instant::now();
                let input = self.load_group(&observations[index], group).await?;
                node_times.push(generated.elapsed().as_micros());
                for batch in &input {
                    let wire: mithril_control::EvidenceBatch = batch.clone().into();
                    if identities.len() <= index {
                        identities.push(EvidenceIntakeIdentityV1 {
                            tenant_id: EvidenceIdV1::new(1, 2 + index as u64).to_be_bytes(),
                            node_id: allowed[index].node_id.clone(),
                            node_boot_id: [7 + index as u8; 16],
                            label_epoch: 1,
                            source_id: wire.source_id.as_slice().try_into()?,
                            source_epoch: wire.source_epoch,
                        });
                    }
                    input_bytes[index] += wire.framed_records.len();
                    digests[index].update(&wire.framed_records);
                }
                batches.push(input);
            }
            let sent = Instant::now();
            for index in 0..tenants {
                connections[index]
                    .send_evidence_group(batches[index].clone())
                    .await?;
            }
            let expected = (group + 1) * 4096;
            let replies = futures_util::future::try_join_all(
                connections
                    .iter_mut()
                    .map(|connection| self.load_reply(connection, expected, sent)),
            )
            .await?;
            let usage = data.storage_usage()?;
            let database_bytes = Self::file_size(&root.join("analysis.duckdb"))?;
            let wal_bytes = Self::file_size(&root.join("analysis.duckdb.wal"))?;
            for (index, (ack, policy_us, ack_us)) in replies.into_iter().enumerate() {
                observations[index].acknowledge_evidence(ack)?;
                self.check(
                    observations[index].next_evidence_batch().is_none(),
                    "Node retained acknowledged input",
                )?;
                samples.push(serde_json::json!({ "tenant": index,
                    "node_us": node_times[index],
                    "accepted_cursor": expected, "durable_ack_us": ack_us,
                    "policy_rpc_us": policy_us, "database_bytes": database_bytes,
                    "wal_bytes": wal_bytes, "usage": usage }));
            }
            let before = data.meta()?;
            for (index, input) in batches.into_iter().enumerate() {
                connections[index].send_evidence_group(input).await?;
            }
            for connection in &mut connections {
                self.load_ack(connection, expected).await?;
            }
            self.check(
                data.meta()? == before,
                "tenant replay changed data metadata",
            )?;
            peak_bytes = peak_bytes.max(data.storage_usage()?.file_bytes);
        }
        let intake_us = started.elapsed().as_micros();
        let mut sources = Vec::new();
        let mut statuses = Vec::new();
        let read_start = Instant::now();
        for (index, identity) in identities.iter().enumerate() {
            let mut cursor = 1;
            let mut count = 0_u64;
            let mut digest = Sha256::new();
            loop {
                let page = data.read_page(identity, cursor)?;
                for record in page.records {
                    digest.update(&record.framed_record);
                    count += 1;
                }
                match page.next_cursor {
                    Some(next) => cursor = next,
                    None => break,
                }
            }
            self.check(count == groups * 4096, "tenant record count differs")?;
            let expected = digests[index].clone().finalize();
            self.check(digest.finalize() == expected, "tenant frame digest differs")?;
            let mut foreign = identity.clone();
            foreign.tenant_id = if tenants > 1 {
                identities[(index + 1) % tenants].tenant_id
            } else {
                [9; 16]
            };
            match data.read_page(&foreign, 1) {
                Err(araphor_data::Error::AnalysisState { reason, .. })
                    if reason == "the raw source is absent" => {}
                Err(error) => self.check(
                    false,
                    &format!("foreign tenant read returned an unexpected error: {error:?}"),
                )?,
                Ok(_) => self.check(false, "foreign tenant read succeeded")?,
            }
            let status = data
                .source_status(identity)?
                .ok_or("tenant source absent")?;
            self.check(
                status.receipt.contiguous_cursor == count && status.retained_event_count == count,
                "tenant source state differs",
            )?;
            sources.push(
                serde_json::json!({ "identity": identity, "record_count": count,
                "input_bytes": input_bytes[index], "input_sha256": hex::encode(expected),
                "status": { "contiguous_cursor": status.receipt.contiguous_cursor,
                    "retained_floor": status.receipt.retained_floor,
                    "retained_event_count": status.retained_event_count } }),
            );
            statuses.push(status);
        }
        let read_us = read_start.elapsed().as_micros();
        self.check(
            !control.root().join("evidence/segments-v2").exists(),
            "load used the old evidence writer",
        )?;
        let checkpoint = Instant::now();
        data.checkpoint()?;
        let checkpoint_us = checkpoint.elapsed().as_micros();
        let usage = data.storage_usage()?;
        let meta = data.meta()?;
        drop(connections);
        server.shutdown().await?;
        drop(data);
        let restart = Instant::now();
        let data = Self::reopen_data(&root).await?;
        let restart_us = restart.elapsed().as_micros();
        self.check(data.meta()? == meta, "tenant restart changed metadata")?;
        for (identity, status) in identities.iter().zip(statuses) {
            self.check(
                data.source_status(identity)? == Some(status),
                "tenant restart changed source",
            )?;
        }
        fs::create_dir(&self.output)?;
        super::write_json(
            &self.output.join("result.json"),
            &serde_json::json!({
                "schema_version": 1, "case": if tenants == 1 { "data-store-load" } else { "data-store-tenants" }, "result": "PASS",
                "proof_kind": "synthetic-mtls", "kernel_evidence": false,
                "tenant_count": tenants, "groups_per_tenant": groups,
                "record_count": groups * 4096 * tenants as u64,
                "input_bytes": input_bytes.iter().sum::<usize>(),
                "sources": sources, "samples": samples, "intake_us": intake_us,
                "read_us": read_us, "checkpoint_us": checkpoint_us, "restart_us": restart_us,
                "sampled_peak_bytes": peak_bytes, "after_checkpoint": usage,
                "commit_revision": meta.commit_revision,
                "recovery_epoch": meta.recovery_epoch,
                "database_bytes": Self::file_size(&root.join("analysis.duckdb"))?,
                "wal_bytes": Self::file_size(&root.join("analysis.duckdb.wal"))?,
                "qualification": "measurement only; no rollout, full-quota, or reserve claim",
            }),
        )?;
        Ok(())
    }

    async fn load_reply(
        &self,
        connection: &mut ControlConnection,
        expected: u64,
        sent: Instant,
    ) -> Result<(mithril_node::EvidenceAckV1, u128, u128)> {
        let policy = Instant::now();
        connection.policy_inventory(None, Vec::new()).await?;
        let policy_us = policy.elapsed().as_micros();
        let ack = self.load_ack(connection, expected).await?;
        Ok((ack, policy_us, sent.elapsed().as_micros()))
    }

    async fn load_ack(
        &self,
        connection: &mut ControlConnection,
        expected: u64,
    ) -> Result<mithril_node::EvidenceAckV1> {
        loop {
            let ack = Self::ack(connection).await?;
            if ack.contiguous_cursor == expected {
                return Ok(ack);
            }
            self.check(
                ack.contiguous_cursor < expected,
                "ACK exceeds the load group",
            )?;
        }
    }

    fn file_size(path: &Path) -> Result<u64> {
        match fs::metadata(path) {
            Ok(meta) => Ok(meta.len()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(0),
            Err(error) => Err(error.into()),
        }
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
            !control.root().join("evidence/segments-v2").exists()
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
        let pending = tls.path().join("evidence/analysis/restore.pending");
        Self::record(&observations, 2);
        let faults = [
            StartupFault::Pending,
            StartupFault::Sql("UPDATE source_receipts SET contiguous_cursor = 2"),
            StartupFault::Sql("UPDATE store_meta SET schema_version = 99"),
            StartupFault::Sql("ALTER TABLE segments RENAME TO missing_segments"),
            StartupFault::Corrupt,
        ];
        for fault in faults {
            let saved = match fault {
                StartupFault::Pending => {
                    let bytes = fs::read(&database)?;
                    fs::write(&pending, b"")?;
                    Some(bytes)
                }
                StartupFault::Sql(sql) => {
                    duckdb::Connection::open(&database)?.execute_batch(sql)?;
                    None
                }
                StartupFault::Corrupt => {
                    fs::write(&database, b"invalid database")?;
                    None
                }
            };
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
                !control.root().join("evidence/segments-v2").exists()
                    && control.policy_document(&policy_id)?.as_ref() == Some(&policy),
                "data failure changed policy or selected the old writer",
            )?;
            drop(control);
            if let Some(bytes) = saved {
                self.check(
                    pending.is_file() && fs::read(&database)? == bytes,
                    "startup changed an incomplete restore",
                )?;
                fs::remove_file(&pending)?;
            }
        }
        self.check(
            fs::read(&database)? == b"invalid database",
            "corrupt data was rewritten",
        )?;

        let old = MtlsFixture::new(false)?;
        let old_root = old.path().join("control-store/evidence/segments-v2");
        fs::create_dir_all(&old_root)?;
        let old_file = old_root.join("unsupported-segment");
        fs::write(&old_file, b"old raw evidence")?;
        self.check(
            old.configuration()?.into_parts().is_err(),
            "old receipts were accepted",
        )?;
        self.check(
            !old.path().join("evidence/analysis").exists(),
            "old receipts created a new data store",
        )?;
        self.check(
            fs::read(&old_file)? == b"old raw evidence",
            "old evidence changed",
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
            "incomplete-restore-unavailable",
            "incomplete-restore-unchanged",
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
        let control_root = tls.path().join("control-store");
        let data_root = tls.path().join("analysis");
        let backup_root = data_root.join("backups");
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
        let retention = araphor_data::RetentionLimitsV1 {
            raw_max_age_ns: Some(24 * HOUR),
            ..Default::default()
        };
        let data = Arc::new(AnalysisStore::open_with_limits(
            &data_root,
            retention,
            Default::default(),
        )?);
        let stale_path = backup_root.join("stale");
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
        connection.report_readiness(true, true).await?;
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
        let selected_data = data.clone();
        let selected_source = identity.clone();
        let (entered, reading) = tokio::sync::oneshot::channel();
        let (release, released) = std::sync::mpsc::channel();
        let extract_started = Instant::now();
        let extraction = tokio::task::spawn_blocking(move || {
            use araphor_data::{
                AnalysisExtractLimits, AnalysisReadControl, AnalysisReadModeV1,
                AnalysisSelectionV1, AnalysisTableRead,
            };
            use std::collections::{BTreeMap, BTreeSet};
            use std::ops::Bound;

            let control = AnalysisReadControl::default();
            control.on_read_step(move || {
                let _sent = entered.send(());
                released
                    .recv_timeout(Duration::from_millis(500))
                    .map_err(|error| araphor_data::Error::AnalysisState {
                        path: PathBuf::from("<qualified-table-read>"),
                        reason: format!("policy probe did not release extraction: {error}"),
                        location: snafu::Location::default(),
                    })
            })?;
            let mut selection =
                AnalysisSelectionV1::new(selected_source.tenant_id, vec![selected_source]);
            selection.received_from = Bound::Included(START);
            selection.received_until = Bound::Included(START);
            let schema = &AnalysisStore::table_schemas()["events"];
            let columns = ["source_cursor", "operation"]
                .into_iter()
                .map(|name| {
                    schema
                        .index_of(name)
                        .map_err(|source| araphor_data::Error::AnalysisContract {
                            source: source.into(),
                            location: snafu::Location::default(),
                        })
                })
                .collect::<araphor_data::Result<BTreeSet<_>>>()?;
            let columns = BTreeMap::from([("events".to_owned(), Some(columns))]);
            selected_data.read_tables(
                &selection,
                AnalysisTableRead {
                    requests: &columns,
                    event_ranges: None,
                    inputs: None,
                    mode: AnalysisReadModeV1::Complete,
                    now: START,
                },
                AnalysisExtractLimits::default(),
                &control,
            )
        });
        tokio::time::timeout(Duration::from_millis(500), reading).await??;
        connection.policy_inventory(None, Vec::new()).await?;
        self.check(
            !extraction.is_finished(),
            "extraction ended before the policy probe",
        )?;
        release.send(())?;
        let page = extraction.await??;
        let mut rows = Vec::new();
        let mut selected_count = 0;
        for batch in &page.tables["events"] {
            use araphor_analysis_sdk::arrow_array::{UInt32Array, UInt64Array};

            let cursors = batch
                .column_by_name("source_cursor")
                .ok_or("source cursor absent")?
                .as_any()
                .downcast_ref::<UInt64Array>()
                .ok_or("source cursor type")?;
            let operations = batch
                .column_by_name("operation")
                .ok_or("operation absent")?
                .as_any()
                .downcast_ref::<UInt32Array>()
                .ok_or("operation type")?;
            selected_count += batch.num_rows();
            for index in 0..batch.num_rows() {
                if cursors.value(index) == 2 {
                    rows.push(operations.value(index));
                }
            }
        }
        let extracted = page.extraction;
        let extraction_us = extract_started.elapsed().as_micros();
        let segment_bytes = fs::read_dir(data_root.join("segments"))?
            .try_fold(0_u64, |total, entry| -> std::io::Result<u64> {
                Ok(total + entry?.metadata()?.len())
            })?;
        self.check(
            extracted.meta.commit_revision == page.scanned_through.commit_revision
                && page.scanned_through.ordinal == u32::MAX
                && page.exhausted
                && extracted.sources[0].receipt.contiguous_cursor == 2
                && extracted.sources[0].receipt.cpu_id == 3
                && extracted.scanned_bytes > wire.framed_records.len()
                && extracted.scanned_bytes as u64 <= segment_bytes
                && extracted.projected_bytes == 2 * (size_of::<u64>() + size_of::<u32>() + 2)
                && selected_count == 2
                && rows == [1],
            "selected extraction changed scope, projection, or snapshot",
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
        let data = Arc::new(Self::reopen_with_retention(&data_root, retention).await?);
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
        data.backup(&backup_root.join("before-witness"))?;

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
            EvidenceRetentionOwner::new(&data)
                .retain(&identity, START + 8 * HOUR)?
                .removed_records
                == 0,
            "unexpired input was deleted",
        )?;
        clock.0.store(START + 48 * HOUR, Ordering::SeqCst);
        self.check(
            EvidenceRetentionOwner::new(&data)
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
                identity: identity.clone().into(),
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
        .await
        .map_err(|_| "automatic retention did not expire the unpinned segment")??;
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
            witness.records.len() == 1 && witness.records[0].cursor == 3,
            "the pinned witness is not readable",
        )?;
        let witness_usage = data.witness_usage(identity.tenant_id, START + 48 * HOUR)?;
        let segment_bytes = fs::read_dir(data_root.join("segments"))?
            .try_fold(0_u64, |total, entry| -> std::io::Result<u64> {
                Ok(total + entry?.metadata()?.len())
            })?;
        self.check(
            witness_usage.referenced_bytes == witness.records[0].framed_record.len() as u64
                && witness_usage.segment_bytes == segment_bytes
                && witness_usage.extra_segment_bytes
                    == segment_bytes - witness_usage.referenced_bytes
                && witness_usage.context_bytes == 0
                && witness_usage.charged_bytes == segment_bytes,
            "witness accounting did not separate exact frames from retained segments",
        )?;
        connection.send_evidence_batch(blocked.clone()).await?;
        let ack = Self::ack(&mut connection).await?;
        self.check(
            ack.contiguous_cursor == 4,
            "caught-up processor did not release intake",
        )?;
        observations.acknowledge_evidence(ack)?;
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
            !control.root().join("evidence/segments-v2").exists()
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
        let backup_path = backup_root.join("after-expiry");
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
        drop(connection);
        server.shutdown().await?;
        let stale = Arc::new(AnalysisStore::restore(
            &stale_path,
            &tls.path().join("stale-restored"),
        )?);
        let intake = EvidenceIntakeOwner::new(control.clone(), stale.clone(), clock)?;
        let server = tls.start(tls.control_from_intake(intake, 1)?).await?;
        let mut connection = self.connect(&tls, &server).await?;
        let floor = observations
            .evidence_floor(None)?
            .ok_or("Node floor absent")?;
        connection.report_evidence_floor(&floor).await?;
        self.check(
            observations.pending_evidence_records() == 0
                && observations.next_evidence_batch().is_none()
                && floor.purged_cursor == 4
                && stale.source_receipt(&identity)?.is_none(),
            "stale backup hid purged Node input",
        )?;
        let gaps = stale.recovery_gaps(&identity, 0)?;
        drop(connection);
        server.shutdown().await?;
        let before = stale.meta()?;
        drop(stale);
        let stale = Arc::new(Self::reopen_data(&tls.path().join("stale-restored")).await?);
        self.check(
            gaps.len() == 1
                && gaps[0].first_cursor == 1
                && gaps[0].last_cursor == 4
                && stale.recovery_gaps(&identity, 0)? == gaps
                && stale.meta()? == before
                && stale.source_receipt(&identity)?.is_none(),
            "recovery gap restart lost evidence or invented an accepted receipt",
        )?;
        let intake = EvidenceIntakeOwner::new(
            control.clone(),
            stale.clone(),
            Arc::new(TestClock(AtomicU64::new(START))),
        )?;
        let server = tls.start(tls.control_from_intake(intake, 1)?).await?;
        let mut connection = self.connect(&tls, &server).await?;
        connection.report_evidence_floor(&floor).await?;
        self.check(
            stale.meta()? == before
                && stale.recovery_gaps(&identity, 0)? == gaps
                && observations.evidence_floor(None)? == Some(floor)
                && observations.pending_evidence_records() == 0,
            "floor retry changed recovery state or Node truncation",
        )?;
        drop(connection);
        server.shutdown().await?;
        let checks = [
            "production-mtls-intake",
            "exact-node-frames",
            "scoped-field-extraction",
            "policy-rpc-during-extraction",
            "whole-segment-witness-cost",
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
            "authenticated-node-floor",
            "floor-retry-noop",
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
                "extraction_us": extraction_us,
                "extraction_scan_bytes": extracted.scanned_bytes,
                "extraction_input_bytes": extracted.input_bytes,
                "extraction_projected_bytes": extracted.projected_bytes,
                "witness_usage": witness_usage,
                "checkpoint_us": checkpoint_us, "database_bytes": database_bytes,
                "wal_bytes_after_checkpoint": wal_bytes,
                "remaining_qualification": ["physical-capacity-backpressure", "crash-injection", "physical-disk-reuse"],
            }),
        )?;
        Ok(())
    }

    pub(super) async fn reopen_data(root: &Path) -> Result<AnalysisStore> {
        Self::reopen_with_retention(root, Default::default()).await
    }

    async fn reopen_with_retention(
        root: &Path,
        retention: araphor_data::RetentionLimitsV1,
    ) -> Result<AnalysisStore> {
        Ok(crate::physical::wait_for_async(
            root,
            "the stopped server to release its data lease",
            Duration::from_secs(5),
            || match AnalysisStore::open_with_limits(root, retention, Default::default()) {
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
        observations.record_bytes(Self::event(sequence).as_bytes());
    }

    fn event(sequence: u64) -> erebor_interceptor_abi::EffectObservationV1 {
        erebor_interceptor_abi::EffectObservationV1 {
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
        }
    }

    async fn connect(
        &self,
        tls: &MtlsFixture,
        server: &ControlServerFixture,
    ) -> Result<ControlConnection> {
        self.connect_at(tls, server.address(), "node-a", [7; 16])
            .await
    }

    async fn connect_at(
        &self,
        tls: &MtlsFixture,
        address: std::net::SocketAddr,
        node_id: &str,
        boot: [u8; 16],
    ) -> Result<ControlConnection> {
        let mut trust = TrustCache::load(&tls.path().join("trust"))?;
        Ok(mithril_node::NodeControlConnector::new(
            tls.node_config(address),
            node_id.to_owned(),
            boot,
        )
        .connect(
            NodeRegistration {
                platform_digest: "a".repeat(64),
                program_digest: "b".repeat(64),
                label_epoch: 1,
                kernel_ready: true,
                effect_prevention_claims_enabled: false,
                kubernetes_node_name: String::new(),
                startup_absence_proof_digest: mithril_control::startup_absence_proof_digest(
                    node_id, &boot, 1, true, true,
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
mod tests;
