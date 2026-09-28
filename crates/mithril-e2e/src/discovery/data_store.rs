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

mod inspection;
mod quota;
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
        let (ingress, worker) = observations.bounded_ingestion_queue(4096, 1024)?;
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

    pub async fn tenant_load(&self) -> Result<()> {
        self.load_tenants(32, 2).await
    }

    async fn load_tenants(&self, groups: u64, tenants: usize) -> Result<()> {
        use sha2::{Digest as _, Sha256};

        self.check(!self.output.exists(), "the output directory already exists")?;
        self.check(matches!(tenants, 1 | 2), "the tenant count is invalid")?;
        self.check(
            (1..=64 / tenants as u64).contains(&groups),
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
            let replies = match connections.as_mut_slice() {
                [one] => vec![self.load_reply(one, expected, sent).await?],
                [one, two] => {
                    let (one, two) = tokio::try_join!(
                        self.load_reply(one, expected, sent),
                        self.load_reply(two, expected, sent),
                    )?;
                    vec![one, two]
                }
                _ => return Err("the load connection count is invalid".into()),
            };
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
            foreign.tenant_id = if tenants == 2 {
                identities[1 - index].tenant_id
            } else {
                [9; 16]
            };
            self.check(
                matches!(data.read_page(&foreign, 1),
                Err(araphor_data::Error::AnalysisState { reason, .. })
                    if reason == "the evidence source is absent"),
                "foreign tenant read succeeded",
            )?;
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
                "groups_per_tenant": groups, "record_count": groups * 4096 * tenants as u64,
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
            StartupFault::Sql("ALTER TABLE batch_ranges RENAME TO missing_ranges"),
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
        let data = Arc::new(AnalysisStore::open(&data_root)?);
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
            use araphor_data::{AnalysisInputV1, AnalysisReadControl, AnalysisSelectionV1};
            use prost::Message as _;
            use std::ops::Bound;

            let mut selection =
                AnalysisSelectionV1::new(selected_source.tenant_id, vec![selected_source]);
            selection.received_from = Bound::Included(START);
            selection.received_until = Bound::Included(START);
            let mut entered = Some(entered);
            selected_data.extract(&selection, &AnalysisReadControl::default(), |input| {
                let AnalysisInputV1::Event { record, .. } = input else {
                    return Ok(None);
                };
                if let Some(entered) = entered.take() {
                    let _sent = entered.send(());
                    released
                        .recv_timeout(Duration::from_millis(500))
                        .map_err(|error| araphor_data::Error::AnalysisState {
                            path: PathBuf::from("<qualified-projection>"),
                            reason: format!("policy probe did not release extraction: {error}"),
                            location: snafu::Location::default(),
                        })?;
                }
                let length = record.framed_record.len();
                let wire =
                    mithril_control::EvidenceRecord::decode(&record.framed_record[4..length - 4])
                        .map_err(|error| araphor_data::Error::AnalysisState {
                        path: PathBuf::from("<qualified-projection>"),
                        reason: error.to_string(),
                        location: snafu::Location::default(),
                    })?;
                Ok((record.cursor == 2).then(|| wire.operation.to_be_bytes().to_vec()))
            })
        });
        tokio::time::timeout(Duration::from_millis(500), reading).await??;
        connection.policy_inventory(None, Vec::new()).await?;
        self.check(
            !extraction.is_finished(),
            "extraction ended before the policy probe",
        )?;
        release.send(())?;
        let extracted = extraction.await??;
        let extraction_us = extract_started.elapsed().as_micros();
        self.check(
            extracted.meta.commit_revision >= page.read_revision
                && extracted.sources[0].receipt.contiguous_cursor == 2
                && extracted.sources[0].receipt.cpu_id == 3
                && extracted.scanned_bytes == wire.framed_records.len()
                && extracted.projected_bytes == 4
                && extracted.pages.len() == 1
                && extracted.pages[0].rows.len() == 1
                && extracted.pages[0].rows[0].as_ref() == 1_u32.to_be_bytes(),
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
            witness.records.len() == 2
                && witness.records[0].cursor == 3
                && witness.records[1].cursor == 4,
            "the exact witness is not readable",
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
mod tests {
    use std::os::unix::fs::DirBuilderExt as _;

    use super::*;

    #[derive(Clone, Copy)]
    enum IntakeFault<'a> {
        Quota,
        FullDisk(&'a Path),
        CommitLimit,
        SegmentLimit,
    }

    #[tokio::test]
    async fn data_load_contract() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let output = directory.path().join("load");
        DataStoreQualification::new(output.clone())
            .load_tenants(2, 1)
            .await?;
        let result: serde_json::Value =
            serde_json::from_slice(&fs::read(output.join("result.json"))?)?;
        assert_eq!(result["record_count"], 8192);
        assert_eq!(
            result["samples"].as_array().ok_or("samples absent")?.len(),
            2
        );
        assert!(result["input_bytes"].as_u64().ok_or("bytes absent")? > 0);
        Ok(())
    }

    #[tokio::test]
    async fn data_context_bounds() -> Result<()> {
        use mithril_control::{
            MAX_EVIDENCE_BATCH_PAYLOAD_BYTES, MAX_EVIDENCE_DECISION_CONTEXT_BYTES,
        };
        use mithril_node::{EvidenceWal, TemporalCoverageV1};
        use prost::Message as _;
        use sha2::{Digest as _, Sha256};

        let tls = MtlsFixture::new(false)?;
        let case = DataStoreQualification::new(tls.path().join("proof"));
        let control = ControlStore::open(tls.path().join("control-store"))?;
        let boot = EvidenceIdV1::from([7; 16]);
        let (catalog, mut raw, _) =
            super::super::roundtrip::signed_catalog(&control, tls.path(), boot)?;
        raw.source_sequence = 1;
        raw.source_cpu_id = 3;
        raw.observed_boottime_ns = 101;
        raw.task_cookie = 7;
        raw.process_instance_id = EvidenceIdV1::new(8, 9);
        raw.entry_instance_id = EvidenceIdV1::new(10, 11);
        raw.reason = 9;
        raw.physical_result = 1;
        let canonicalizer = ObservationCanonicalizer::new(
            EvidenceIdV1::new(1, 2),
            EvidenceIdV1::new(3, 4),
            1,
            boot,
        )?;
        let wal_root = tls.path().join("large-wal");
        let limits = EvidenceWalLimits {
            maximum_batch_records: 4096,
            ..Default::default()
        };
        let mut wal = EvidenceWal::open(&wal_root, limits)?;
        let mut last = None;
        for cursor in 1..=256 {
            raw.source_sequence = cursor;
            raw.observed_boottime_ns = cursor + 100;
            let mut observation = canonicalizer.normalize_kernel(
                raw,
                EvidenceIdV1::new(5, 6),
                TemporalCoverageV1::Complete,
                i64::try_from(START)?,
            )?;
            catalog.attach(&mut observation);
            let context = observation
                .decision_context
                .as_mut()
                .ok_or("decision context absent")?;
            let expected = context.catalog()?.ok_or("verified catalog absent")?;
            let padding = MAX_EVIDENCE_DECISION_CONTEXT_BYTES
                .checked_sub(context.encoded_len())
                .ok_or("catalog exceeds context limit")?;
            // JSON whitespace changes encoded size, not catalog content.
            context
                .catalog_json
                .resize(context.catalog_json.len() + padding, b' ');
            assert_eq!(context.encoded_len(), MAX_EVIDENCE_DECISION_CONTEXT_BYTES);
            assert_eq!(context.catalog()?, Some(expected));
            assert_eq!(wal.append(&observation)?, cursor);
            last = Some(observation);
        }
        let mut oversized = last.ok_or("last observation absent")?;
        oversized.source_sequence = 257;
        let context = oversized
            .decision_context
            .as_mut()
            .ok_or("decision context absent")?;
        context.original_kernel_sequence = 257;
        context.catalog_json.push(b' ');
        assert_eq!(
            context.encoded_len(),
            MAX_EVIDENCE_DECISION_CONTEXT_BYTES + 1
        );
        assert!(wal.append(&oversized).is_err());
        assert_eq!(wal.pending_records(), 256);
        drop(wal);
        let mut wal = EvidenceWal::open(&wal_root, limits)?;
        assert_eq!(wal.pending_records(), 256);
        let first = wal.next_batch().ok_or("first batch absent")?;
        assert!(first.record_count() < 256);
        let wire: mithril_control::EvidenceBatch = first.into();
        assert!(wire.encoded_len() <= MAX_EVIDENCE_BATCH_PAYLOAD_BYTES);
        assert!(wire.encoded_len() > MAX_EVIDENCE_BATCH_PAYLOAD_BYTES - 32 * 1024);
        let identity = EvidenceIntakeIdentityV1 {
            tenant_id: EvidenceIdV1::new(1, 2).to_be_bytes(),
            node_id: "node-a".into(),
            node_boot_id: boot.to_be_bytes(),
            label_epoch: 1,
            source_id: wire.source_id.as_slice().try_into()?,
            source_epoch: wire.source_epoch,
        };
        let root = tls.path().join("analysis");
        let data = Arc::new(AnalysisStore::open(&root)?);
        let intake = EvidenceIntakeOwner::new(
            control,
            data.clone(),
            Arc::new(TestClock(AtomicU64::new(START))),
        )?;
        let server = tls.start(tls.control_from_intake(intake, 1)?).await?;
        let mut connection = case.connect(&tls, &server).await?;
        connection.report_readiness(true, true).await?;
        let mut expected = Sha256::new();
        let mut batches = 0;
        while let Some(batch) = wal.next_batch() {
            let end = batch.last_cursor;
            let wire: mithril_control::EvidenceBatch = batch.clone().into();
            assert!(wire.encoded_len() <= MAX_EVIDENCE_BATCH_PAYLOAD_BYTES);
            expected.update(&wire.framed_records);
            connection.send_evidence_batch(batch).await?;
            let ack = DataStoreQualification::ack(&mut connection).await?;
            assert_eq!(ack.contiguous_cursor, end);
            assert_eq!(
                data.source_receipt(&identity)?
                    .ok_or("receipt absent")?
                    .contiguous_cursor,
                end
            );
            wal.acknowledge(ack)?;
            batches += 1;
        }
        assert_eq!(batches, 2);
        assert_eq!(wal.pending_records(), 0);
        let receipt = data.source_receipt(&identity)?;
        drop(connection);
        server.shutdown().await?;
        drop(data);
        let data = DataStoreQualification::reopen_data(&root).await?;
        assert_eq!(data.source_receipt(&identity)?, receipt);
        let mut actual = Sha256::new();
        let mut cursor = 1;
        let mut count = 0;
        loop {
            let page = data.read_page(&identity, cursor)?;
            for record in page.records {
                actual.update(&record.framed_record);
                count += 1;
            }
            match page.next_cursor {
                Some(next) => cursor = next,
                None => break,
            }
        }
        assert_eq!(count, 256);
        assert_eq!(actual.finalize(), expected.finalize());
        Ok(())
    }

    #[tokio::test]
    async fn data_tenant_load() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let output = directory.path().join("tenants");
        let case = DataStoreQualification::new(output.clone());
        for (groups, tenants) in [(0, 2), (33, 2), (65, 1), (1, 0), (1, 3)] {
            assert!(case.load_tenants(groups, tenants).await.is_err());
            assert!(!output.exists());
        }
        tokio::time::timeout(Duration::from_secs(30), case.load_tenants(2, 2)).await??;
        let result: serde_json::Value =
            serde_json::from_slice(&fs::read(output.join("result.json"))?)?;
        assert_eq!(result["record_count"], 16384);
        let sources = result["sources"].as_array().ok_or("sources absent")?;
        assert_eq!(sources.len(), 2);
        assert_ne!(
            sources[0]["identity"]["tenant_id"],
            sources[1]["identity"]["tenant_id"]
        );
        for source in sources {
            assert_eq!(source["record_count"], 8192);
            assert_eq!(source["status"]["retained_event_count"], 8192);
        }
        assert_eq!(
            result["samples"].as_array().ok_or("samples absent")?.len(),
            4
        );
        for sample in result["samples"].as_array().ok_or("samples absent")? {
            assert!(sample["node_us"].as_u64().ok_or("Node time absent")? > 0);
        }
        Ok(())
    }

    #[tokio::test]
    #[ignore = "subprocess helper; requires the parent's temporary data store"]
    async fn data_commit_child() -> Result<()> {
        use rustix::process::{getrlimit, setrlimit, Resource};

        let root = PathBuf::from(std::env::var_os("ARAPHOR_COMMIT_ROOT").ok_or("root absent")?);
        let kind = std::env::var("ARAPHOR_COMMIT_KIND")?;
        let result = kind == "result";
        let data = AnalysisStore::open(root)?;
        let watch = data.subscribe_revision();
        let limit = std::env::var("ARAPHOR_COMMIT_LIMIT")?.parse()?;
        let _signal =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::from_raw(libc::SIGXFSZ))?;
        let prior = getrlimit(Resource::Fsize);
        match kind.as_str() {
            "segment" | "metadata" => {
                let stage = if kind == "segment" {
                    araphor_data::AnalysisCommitStage::BeforeAppend
                } else {
                    araphor_data::AnalysisCommitStage::AfterSync
                };
                data.set_commit_hook(stage, move || DataStoreQualification::limit_file(limit))?;
            }
            "result" => DataStoreQualification::limit_file(limit)?,
            _ => return Err("unknown commit kind".into()),
        }
        let failure = DataStoreQualification::native_commit(&data, result);
        setrlimit(Resource::Fsize, prior)?;
        let error = failure
            .err()
            .ok_or("native commit unexpectedly succeeded")?;
        let expected = if result {
            "commit analysis result"
        } else {
            "commit evidence"
        };
        if kind == "segment" {
            assert!(
                matches!(&error, araphor_data::Error::Io { path, source, .. }
                if path.extension().is_some_and(|extension| extension == "seg")
                    && source.raw_os_error() == Some(libc::EFBIG)),
                "{error}"
            );
        } else {
            assert!(
                matches!(&error,
            araphor_data::Error::AnalysisDatabase { operation, source, .. }
                if *operation == expected && source.to_string().contains("File too large")
                    && source.to_string().contains("analysis.duckdb.wal")),
                "{error}"
            );
        }
        assert!(!watch.has_changed()?);
        std::process::exit(73);
    }

    #[tokio::test]
    async fn data_commit_failure() -> Result<()> {
        for limit in [0, 64] {
            for kind in ["segment", "metadata", "result"] {
                let result = kind == "result";
                let directory = tempfile::tempdir()?;
                let root = directory.path().join("analysis");
                let data = AnalysisStore::open(&root)?;
                let scope = DataStoreQualification::native_scope();
                data.register_processor(&scope, ProcessorClassV1::Required, 1)?;
                data.accept_validated_batch(
                    scope.identity.clone(),
                    araphor_data::ValidatedEvidenceBatchV1 {
                        cpu_id: 0,
                        first_cursor: 1,
                        last_cursor: 1,
                        intake_utc_ns: START,
                        framed_records: b"prior".to_vec().into(),
                        frame_ends: vec![5],
                    },
                )?;
                let before = data.meta()?;
                let status = data.source_status(&scope.identity)?;
                let records = data.read_page(&scope.identity, 1)?.records;
                drop(data);
                let mut child = tokio::process::Command::new(std::env::current_exe()?)
                    .args([
                        "--exact",
                        "discovery::data_store::tests::data_commit_child",
                        "--ignored",
                        "--nocapture",
                    ])
                    .env("ARAPHOR_COMMIT_ROOT", &root)
                    .env("ARAPHOR_COMMIT_LIMIT", limit.to_string())
                    .env("ARAPHOR_COMMIT_KIND", kind)
                    .kill_on_drop(true)
                    .spawn()?;
                let exit = tokio::time::timeout(Duration::from_secs(10), child.wait()).await??;
                assert_eq!(exit.code(), Some(73));
                let data = AnalysisStore::open(&root)?;
                assert_eq!(data.meta()?, before);
                assert_eq!(data.source_status(&scope.identity)?, status);
                assert_eq!(data.read_page(&scope.identity, 1)?.records, records);
                assert_eq!(
                    data.read_result(scope.identity.tenant_id, "native-result")?,
                    None
                );
                assert_eq!(
                    data.processor_health(&scope)?
                        .ok_or("processor absent")?
                        .consumed_cursor,
                    0
                );
                let mut watch = data.subscribe_revision();
                assert_eq!(*watch.borrow_and_update(), before.commit_revision);
                DataStoreQualification::native_commit(&data, result)?;
                let after = data.meta()?;
                assert_eq!(after.commit_revision, before.commit_revision + 1);
                assert!(watch.has_changed()?);
                assert_eq!(*watch.borrow_and_update(), after.commit_revision);
                DataStoreQualification::native_commit(&data, result)?;
                assert!(!watch.has_changed()?);
                assert_eq!(data.meta()?, after);
                assert_eq!(
                    data.processor_health(&scope)?
                        .ok_or("processor absent")?
                        .consumed_cursor,
                    u64::from(result)
                );
                if result {
                    assert_eq!(
                        data.read_result(scope.identity.tenant_id, "native-result")?,
                        Some(b"finding".to_vec())
                    );
                    let retained =
                        EvidenceRetentionOwner::new(&data, RetentionLimitsV1::default())?
                            .retain(&scope.identity, START + 25 * HOUR)?;
                    assert_eq!(retained.removed_records, 0);
                } else {
                    assert_eq!(
                        data.source_receipt(&scope.identity)?
                            .ok_or("receipt absent")?
                            .contiguous_cursor,
                        2
                    );
                }
                let final_meta = data.meta()?;
                drop(data);
                let data = AnalysisStore::open(&root)?;
                assert_eq!(data.meta()?, final_meta);
                let page = data.read_page(&scope.identity, 1)?;
                assert_eq!(page.records.len(), if result { 1 } else { 2 });
                assert_eq!(page.records[0], records[0]);
                assert_eq!(
                    data.processor_health(&scope)?
                        .ok_or("processor absent")?
                        .consumed_cursor,
                    u64::from(result)
                );
                assert_eq!(
                    data.read_result(scope.identity.tenant_id, "native-result")?,
                    result.then(|| b"finding".to_vec())
                );
            }
        }
        Ok(())
    }

    #[tokio::test]
    #[ignore = "subprocess helper; requires the parent's temporary Control configuration"]
    async fn data_control_child() -> Result<()> {
        let root =
            PathBuf::from(std::env::var_os("ARAPHOR_CONTROL_CRASH_ROOT").ok_or("root absent")?);
        let mut parts =
            mithril_control::ControlConfig::load(&root.join("control.json"))?.into_parts()?;
        if let Some(error) = parts.data_error {
            return Err(error.into());
        }
        parts
            .control
            .set_evidence_commit_hook(|| std::process::exit(73));
        let server = ControlServerFixture::start_tls(parts.tls, parts.control).await?;
        // The serial test harness can leave its test name on this line.
        println!("\nCONTROL_READY={}", server.address());
        std::future::pending::<()>().await;
        Ok(())
    }

    #[tokio::test]
    async fn data_control_crash() -> Result<()> {
        use std::process::Stdio;
        use tokio::io::AsyncBufReadExt as _;

        let tls = MtlsFixture::new(false)?;
        let control_root = tls.path().join("control-store");
        let store = ControlStore::open(&control_root)?;
        let policy_id = {
            let fixture = OutagePolicyFixture::new(store.clone());
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
        let policy = store.policy_document(&policy_id)?.ok_or("policy absent")?;
        drop(store);
        tls.configuration()?;
        let open_node = || {
            EffectObservationStore::durable(
                8,
                tls.path().join("wal"),
                EvidenceWalLimits::default(),
                ObservationCanonicalizer::new(
                    EvidenceIdV1::new(1, 2),
                    EvidenceIdV1::new(3, 4),
                    1,
                    [7; 16].into(),
                )?,
            )
        };
        let observations = open_node()?;
        DataStoreQualification::record(&observations, 1);
        let batch = observations
            .next_evidence_batch()
            .ok_or("Node batch absent")?;
        let wire: mithril_control::EvidenceBatch = batch.clone().into();
        let identity = EvidenceIntakeIdentityV1 {
            tenant_id: EvidenceIdV1::new(1, 2).to_be_bytes(),
            node_id: "node-a".into(),
            node_boot_id: [7; 16],
            label_epoch: 1,
            source_id: wire.source_id.as_slice().try_into()?,
            source_epoch: wire.source_epoch,
        };
        let mut child = tokio::process::Command::new(std::env::current_exe()?)
            .args([
                "--exact",
                "discovery::data_store::tests::data_control_child",
                "--ignored",
                "--nocapture",
            ])
            .env("ARAPHOR_CONTROL_CRASH_ROOT", tls.path())
            .env("RUST_TEST_THREADS", "1")
            .stdout(Stdio::piped())
            .kill_on_drop(true)
            .spawn()?;
        let mut output =
            tokio::io::BufReader::new(child.stdout.take().ok_or("child stdout absent")?).lines();
        let address = tokio::time::timeout(Duration::from_secs(10), async {
            while let Some(line) = output.next_line().await? {
                if let Some(value) = line.strip_prefix("CONTROL_READY=") {
                    return Ok::<std::net::SocketAddr, Box<dyn StdError>>(value.parse()?);
                }
            }
            Err("Control child exited before readiness".into())
        })
        .await??;
        let case = DataStoreQualification::new(tls.path().join("result"));
        let mut connection = case.connect_at(&tls, address, "node-a", [7; 16]).await?;
        connection.report_readiness(true, true).await?;
        connection.policy_inventory(None, Vec::new()).await?;
        let mut invalid = batch.clone();
        invalid.first_cursor = 0;
        connection.send_evidence_batch(invalid).await?;
        let error = DataStoreQualification::ack(&mut connection)
            .await
            .err()
            .ok_or("invalid batch accepted")?;
        assert!(matches!(error.downcast_ref::<mithril_node::Error>(),
            Some(mithril_node::Error::ControlRpc { source, .. }) if source.code() == tonic::Code::InvalidArgument));
        assert!(child.try_wait()?.is_none());
        assert_eq!(observations.pending_evidence_records(), 1);
        drop(connection);
        let mut connection = case.connect_at(&tls, address, "node-a", [7; 16]).await?;
        connection.send_evidence_batch(batch).await?;
        assert!(
            DataStoreQualification::ack(&mut connection).await.is_err(),
            "Control sent an ACK before its injected exit"
        );
        let status = tokio::time::timeout(Duration::from_secs(5), child.wait()).await??;
        assert_eq!(status.code(), Some(73));
        assert_eq!(observations.pending_evidence_records(), 1);
        drop(connection);
        drop(observations);
        let observations = open_node()?;
        let replay = observations
            .next_evidence_batch()
            .ok_or("Node replay absent")?;
        assert_eq!(mithril_control::EvidenceBatch::from(replay.clone()), wire);
        let data = Arc::new(AnalysisStore::open(tls.path().join("evidence/analysis"))?);
        let receipt = data
            .source_receipt(&identity)?
            .ok_or("committed receipt absent")?;
        assert_eq!(receipt.contiguous_cursor, 1);
        let committed = data.read_page(&identity, 1)?;
        assert_eq!(committed.records.len(), 1);
        assert_eq!(committed.records[0].framed_record, wire.framed_records);
        let store = ControlStore::open(&control_root)?;
        assert_eq!(store.policy_document(&policy_id)?, Some(policy.clone()));
        assert!(!store.root().join("evidence/segments-v2").exists());
        let intake = EvidenceIntakeOwner::new(
            store.clone(),
            data.clone(),
            Arc::new(mithril_control::SystemIntakeClock),
        )?;
        let control = tls.control_from_intake(intake, 1)?;
        let allowed: Vec<_> = control.allowed_nodes().values().cloned().collect();
        let mut projector =
            mithril_control::ControlContextOwner::new(store.clone(), data.clone(), &allowed)?;
        projector.reconcile()?;
        let before = data.meta()?;
        projector.reconcile()?;
        assert_eq!(data.meta()?, before);
        drop(projector);
        let server = tls.start(control).await?;
        let mut connection = case.connect(&tls, &server).await?;
        connection.send_evidence_batch(replay.clone()).await?;
        let ack = DataStoreQualification::ack(&mut connection).await?;
        assert_eq!(ack.contiguous_cursor, 1);
        assert_eq!(data.meta()?, before);
        assert_eq!(data.source_receipt(&identity)?, Some(receipt));
        assert_eq!(data.read_page(&identity, 1)?.records, committed.records);
        observations.acknowledge_evidence(ack)?;
        assert_eq!(observations.pending_evidence_records(), 0);
        connection.send_evidence_batch(replay).await?;
        assert_eq!(
            DataStoreQualification::ack(&mut connection)
                .await?
                .contiguous_cursor,
            1
        );
        assert_eq!(data.meta()?, before);
        DataStoreQualification::record(&observations, 2);
        connection
            .send_evidence_batch(
                observations
                    .next_evidence_batch()
                    .ok_or("new Node batch absent")?,
            )
            .await?;
        let ack = DataStoreQualification::ack(&mut connection).await?;
        assert_eq!(ack.contiguous_cursor, 2);
        observations.acknowledge_evidence(ack)?;
        assert_eq!(observations.pending_evidence_records(), 0);
        assert_eq!(data.meta()?.commit_revision, before.commit_revision + 1);
        connection.report_readiness(true, true).await?;
        connection.policy_inventory(None, Vec::new()).await?;
        assert_eq!(store.policy_document(&policy_id)?, Some(policy));
        let after = data.meta()?;
        drop(connection);
        server.shutdown().await?;
        drop(data);
        let reopened =
            DataStoreQualification::reopen_data(&tls.path().join("evidence/analysis")).await?;
        assert_eq!(reopened.meta()?, after);
        let page = reopened.read_page(&identity, 1)?;
        assert_eq!(page.records.len(), 2);
        assert_eq!(page.records[0], committed.records[0]);
        Ok(())
    }

    impl DataStoreQualification {
        fn limit_file(limit: u64) -> araphor_data::Result<()> {
            use rustix::process::{getrlimit, setrlimit, Resource, Rlimit};
            setrlimit(
                Resource::Fsize,
                Rlimit {
                    current: Some(limit),
                    ..getrlimit(Resource::Fsize)
                },
            )
            .map_err(|source| araphor_data::Error::Io {
                path: "<file-size-limit>".into(),
                source: source.into(),
                location: Default::default(),
            })
        }

        fn native_scope() -> ProcessorScopeV1 {
            ProcessorScopeV1 {
                processor_id: "native-processor".into(),
                method_version: 1,
                identity: EvidenceIntakeIdentityV1 {
                    tenant_id: [1; 16],
                    node_id: "node-a".into(),
                    node_boot_id: [2; 16],
                    label_epoch: 1,
                    source_id: [3; 16],
                    source_epoch: 1,
                },
            }
        }

        fn native_commit(data: &AnalysisStore, result: bool) -> araphor_data::Result<()> {
            let scope = Self::native_scope();
            if result {
                data.commit_result(&AnalysisResultCommitV1 {
                    witnesses: vec![AnalysisWitnessV1 {
                        identity: scope.identity.clone(),
                        cursor: 1,
                        expires_utc_ns: START + 48 * HOUR,
                    }],
                    scope,
                    expected_cursor: 0,
                    consumed_cursor: 1,
                    coverage_revision: 0,
                    context_revision: 0,
                    result_id: "native-result".into(),
                    body: b"finding".to_vec(),
                    created_utc_ns: START + 1,
                    context_refs: Vec::new(),
                })?;
            } else {
                data.accept_validated_batch(
                    scope.identity,
                    araphor_data::ValidatedEvidenceBatchV1 {
                        cpu_id: 0,
                        first_cursor: 2,
                        last_cursor: 2,
                        intake_utc_ns: START + 1,
                        framed_records: b"next".to_vec().into(),
                        frame_ends: vec![4],
                    },
                )?;
            }
            Ok(())
        }

        async fn capacity_recovery(&self, fault: IntakeFault<'_>) -> Result<()> {
            use rustix::process::{getrlimit, setrlimit, Resource};
            use std::io::{Seek as _, SeekFrom, Write as _};
            use std::os::unix::fs::MetadataExt as _;

            const GIB: u64 = 1024 * 1024 * 1024;
            let disk = match fault {
                IntakeFault::FullDisk(root) => Some(root),
                _ => None,
            };
            let native = matches!(fault, IntakeFault::CommitLimit | IntakeFault::SegmentLimit);
            let directory = match disk {
                Some(root) => {
                    assert_eq!(root.parent(), Some(Path::new("/tmp")));
                    assert!(root
                        .file_name()
                        .ok_or("filesystem name absent")?
                        .to_string_lossy()
                        .starts_with("araphor-data-disk-"));
                    assert!(!fs::symlink_metadata(root)?.file_type().is_symlink());
                    assert_eq!(rustix::fs::statfs(root)?.f_type, libc::TMPFS_MAGIC);
                    let volume = rustix::fs::statvfs(root)?;
                    assert_eq!(volume.f_blocks * volume.f_frsize, GIB);
                    assert_eq!(fs::read_dir(root)?.count(), 0);
                    tempfile::tempdir_in(root)?
                }
                None => tempfile::tempdir()?,
            };
            let tls = MtlsFixture::new(false)?;
            let mut config = tls.configuration()?;
            config.evidence_directory = directory.path().join("evidence");
            config.data_storage.disk_max_bytes = GIB;
            let parts = config.into_parts()?;
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
            let first = observations.next_evidence_batch().ok_or("batch absent")?;
            let wire: mithril_control::EvidenceBatch = first.clone().into();
            let identity = EvidenceIntakeIdentityV1 {
                tenant_id: EvidenceIdV1::new(1, 2).to_be_bytes(),
                node_id: "node-a".into(),
                node_boot_id: [7; 16],
                label_epoch: 1,
                source_id: wire.source_id.as_slice().try_into()?,
                source_epoch: wire.source_epoch,
            };
            let mut connection = self.connect(&tls, &server).await?;
            connection.report_readiness(true, true).await?;
            connection.send_evidence_batch(first).await?;
            let ack = Self::ack(&mut connection).await?;
            assert_eq!(ack.contiguous_cursor, 1);
            observations.acknowledge_evidence(ack)?;
            let cancelled = araphor_data::AnalysisReadControl::default();
            cancelled.cancel()?;
            assert!(matches!(
                data.read_page_cancel(&identity, 1, &cancelled),
                Err(araphor_data::Error::AnalysisReadCancelled { .. })
            ));
            connection.policy_inventory(None, Vec::new()).await?;
            assert_eq!(data.read_page(&identity, 1)?.records.len(), 1);
            data.checkpoint()?;
            let backup_root = tls.path().join("backups");
            fs::DirBuilder::new().mode(0o700).create(&backup_root)?;
            let backup_path = backup_root.join("saved");
            let managed = directory.path().join("evidence/analysis/backups/saved");
            let manifest = data.backup(&managed)?;
            fs::DirBuilder::new().mode(0o700).create(&backup_path)?;
            fs::DirBuilder::new()
                .mode(0o700)
                .create(backup_path.join("segments"))?;
            for file in ["analysis.duckdb", "manifest.json"] {
                fs::copy(managed.join(file), backup_path.join(file))?;
            }
            for segment in &manifest.segments {
                let file = format!("segments/{:016x}.seg", segment.segment_id);
                fs::copy(managed.join(&file), backup_path.join(&file))?;
            }
            let saved = AnalysisStore::restore(&backup_path, &backup_root.join("source"))?;
            let saved_meta = saved.meta()?;
            let restore_root = directory.path().join("restore");
            fs::DirBuilder::new().mode(0o700).create(&restore_root)?;
            let before = data.meta()?;
            let status = data.source_status(&identity)?;
            let changed = data.subscribe_revision();
            Self::record(&observations, 2);
            let pending = observations.next_evidence_batch().ok_or("batch absent")?;
            let padding_file = if disk.is_some() {
                tempfile::NamedTempFile::new_in(directory.path())?
            } else {
                tempfile::NamedTempFile::new_in(directory.path().join("evidence/analysis"))?
            };
            let mut padding = padding_file.as_file();
            if disk.is_some() {
                let volume = rustix::fs::statvfs(directory.path())?;
                rustix::fs::fallocate(
                    padding,
                    rustix::fs::FallocateFlags::empty(),
                    0,
                    volume.f_bavail * volume.f_frsize,
                )?;
                assert_eq!(rustix::fs::statvfs(directory.path())?.f_bavail, 0);
                padding.seek(SeekFrom::End(0))?;
                assert!(matches!(padding.write_all(b"full"),
                    Err(error) if error.raw_os_error() == Some(libc::ENOSPC)));
                assert!(matches!(
                    EvidenceRetentionOwner::new(&data, data.retention_limits())?.sweep(None, START),
                    Err(araphor_data::Error::StorageCapacity {
                        resource: "filesystem reserve",
                        ..
                    })
                ));
                assert!(!data.retention_healthy());
            } else if !native {
                padding.set_len(GIB)?;
            }
            let full = data.storage_health()?;
            assert_eq!(full.intake_capacity, native);
            assert_eq!(full.maintenance_capacity, disk.is_none());
            let allocated = padding.metadata()?.blocks() * 512;
            if disk.is_some() {
                assert!(allocated > GIB / 2);
                let destination = directory.path().join("evidence/analysis/backups/blocked");
                assert!(matches!(
                    data.backup(&destination),
                    Err(araphor_data::Error::StorageCapacity {
                        resource: "filesystem reserve",
                        ..
                    })
                ));
                assert!(!destination.exists());
                assert!(!destination.join("manifest.json").exists());
                assert_eq!(saved.meta()?, saved_meta);
                assert_eq!(saved.read_page(&identity, 1)?.records.len(), 1);
                assert!(matches!(
                    AnalysisStore::restore(&backup_path, &restore_root),
                    Err(araphor_data::Error::StorageCapacity {
                        resource: "copy reserve",
                        ..
                    })
                ));
                assert!(restore_root.join("restore.pending").is_file());
                assert!(!restore_root.join("analysis.duckdb").exists());
                assert_eq!(fs::read_dir(&restore_root)?.count(), 2);
                assert!(restore_root.join("analysis.lock").is_file());
                assert!(matches!(
                    AnalysisStore::open(&restore_root),
                    Err(araphor_data::Error::AnalysisState { reason, .. })
                        if reason.contains("restore is incomplete")
                ));
                assert!(!restore_root.join("analysis.duckdb").exists());
            }
            let _signal = if native {
                Some(tokio::signal::unix::signal(
                    tokio::signal::unix::SignalKind::from_raw(libc::SIGXFSZ),
                )?)
            } else {
                None
            };
            let prior = getrlimit(Resource::Fsize);
            if native {
                let stage = if matches!(fault, IntakeFault::SegmentLimit) {
                    araphor_data::AnalysisCommitStage::BeforeAppend
                } else {
                    araphor_data::AnalysisCommitStage::AfterSync
                };
                data.set_commit_hook(stage, || Self::limit_file(64))?;
            }
            let received: Result<_> = async {
                connection.send_evidence_batch(pending.clone()).await?;
                Ok(tokio::time::timeout(Duration::from_secs(5), connection.next_message()).await?)
            }
            .await;
            if native {
                setrlimit(Resource::Fsize, prior)?;
            }
            let error = received?.err().ok_or("failed write received an ACK")?;
            let mithril_node::Error::ControlRpc { source, .. } = error else {
                return Err(error.into());
            };
            if native {
                assert_eq!(source.code(), tonic::Code::Unavailable);
                assert!(source.message().contains("File too large"), "{source}");
                if matches!(fault, IntakeFault::SegmentLimit) {
                    assert!(source.message().contains(".seg"), "{source}");
                } else {
                    assert!(source.message().contains("commit evidence"), "{source}");
                    assert!(source.message().contains("analysis.duckdb.wal"), "{source}");
                }
            } else {
                assert_eq!(source.code(), tonic::Code::ResourceExhausted);
            }
            assert!(!changed.has_changed()?);
            assert_eq!(observations.pending_evidence_records(), 1);
            assert_eq!(data.storage_health()?.write_ready, !native);
            connection.policy_inventory(None, Vec::new()).await?;
            if native {
                data.recover()?;
                assert!(data.storage_health()?.write_ready);
                assert!(!changed.has_changed()?);
            }
            assert_eq!(data.meta()?, before);
            assert_eq!(data.source_status(&identity)?, status);
            assert_eq!(
                data.read_page(&identity, 1)?.records[0].framed_record,
                wire.framed_records
            );
            connection.policy_inventory(None, Vec::new()).await?;
            padding.set_len(0)?;
            padding.sync_all()?;
            let restored = AnalysisStore::restore(&backup_path, &backup_root.join("retry"))?;
            assert_eq!(restored.meta()?, saved_meta);
            assert_eq!(restored.meta()?.commit_revision, manifest.commit_revision);
            assert_eq!(
                restored.read_page(&identity, 1)?.records[0].framed_record,
                wire.framed_records
            );
            drop(connection);
            tokio::time::timeout(Duration::from_secs(5), async {
                loop {
                    let health = data.storage_health()?;
                    if health.write_ready && health.retention_healthy && health.intake_capacity {
                        break Ok::<_, araphor_data::Error>(());
                    }
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
            })
            .await??;
            let mut connection = self.connect(&tls, &server).await?;
            connection.send_evidence_batch(pending.clone()).await?;
            let ack = Self::ack(&mut connection).await?;
            assert_eq!(ack.contiguous_cursor, 2);
            observations.acknowledge_evidence(ack)?;
            assert_eq!(observations.pending_evidence_records(), 0);
            assert_eq!(data.meta()?.commit_revision, before.commit_revision + 1);
            connection.send_evidence_batch(pending).await?;
            assert_eq!(Self::ack(&mut connection).await?.contiguous_cursor, 2);
            assert_eq!(data.meta()?.commit_revision, before.commit_revision + 1);
            data.checkpoint()?;
            drop(connection);
            server.shutdown().await?;
            let after = data.meta()?;
            drop(data);
            let data = Self::reopen_data(&directory.path().join("evidence/analysis")).await?;
            assert_eq!(data.meta()?, after);
            assert_eq!(data.read_page(&identity, 1)?.records.len(), 2);
            assert_eq!(
                data.source_receipt(&identity)?
                    .ok_or("receipt absent")?
                    .contiguous_cursor,
                2
            );
            println!(
                "{}",
                serde_json::json!({
                    "case": "data-capacity-recovery", "result": "PASS",
                    "filesystem_full": disk.is_some(), "padding_allocated_bytes": allocated,
                    "native_commit_failure": native,
                    "copy_reserve_rejected": disk.is_some(),
                    "rejected_health": full, "recovered_usage": data.storage_usage()?,
                    "source_identity": identity, "commit_revision": after.commit_revision,
                    "contiguous_cursor": 2, "retained_count": 2,
                    "proof_kind": "synthetic-mtls", "kernel_evidence": false,
                })
            );
            Ok(())
        }
    }

    #[tokio::test]
    async fn data_capacity_recovery() -> Result<()> {
        let directory = tempfile::tempdir()?;
        DataStoreQualification::new(directory.path().join("result"))
            .capacity_recovery(IntakeFault::Quota)
            .await
    }

    #[tokio::test]
    #[ignore = "requires the task-owned, empty 1 GiB tmpfs"]
    async fn data_full_disk() -> Result<()> {
        let root = PathBuf::from(std::env::var("ARAPHOR_TEST_DATA_DISK")?);
        DataStoreQualification::new(root.join("result"))
            .capacity_recovery(IntakeFault::FullDisk(&root))
            .await
    }

    #[tokio::test]
    async fn data_intake_failure() -> Result<()> {
        for kind in ["segment", "metadata"] {
            let mut child = tokio::process::Command::new(std::env::current_exe()?)
                .args([
                    "--exact",
                    "discovery::data_store::tests::data_intake_child",
                    "--ignored",
                    "--nocapture",
                ])
                .env("ARAPHOR_INTAKE_KIND", kind)
                .kill_on_drop(true)
                .spawn()?;
            let status = tokio::time::timeout(Duration::from_secs(20), child.wait()).await??;
            assert!(status.success(), "{status}");
        }
        Ok(())
    }

    #[tokio::test]
    #[ignore = "subprocess helper; applies a process-wide native file-size limit"]
    async fn data_intake_child() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let fault = match std::env::var("ARAPHOR_INTAKE_KIND")?.as_str() {
            "segment" => IntakeFault::SegmentLimit,
            "metadata" => IntakeFault::CommitLimit,
            _ => return Err("unknown intake fault".into()),
        };
        DataStoreQualification::new(directory.path().join("result"))
            .capacity_recovery(fault)
            .await
    }

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
        for (logical, seeded) in [(false, false), (true, false), (false, true)] {
            let tls = MtlsFixture::new(false)?;
            let case = DataStoreQualification::new(tls.path().join("result"));
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
            if seeded {
                let parts = tls.configuration()?.into_parts()?;
                assert!(parts.data_error.is_none(), "{:?}", parts.data_error);
                let server = tls.start(parts.control).await?;
                let mut connection = case.connect(&tls, &server).await?;
                DataStoreQualification::record(&observations, 1);
                connection
                    .send_evidence_batch(observations.next_evidence_batch().ok_or("batch absent")?)
                    .await?;
                let ack = DataStoreQualification::ack(&mut connection).await?;
                assert_eq!(ack.contiguous_cursor, 1);
                observations.acknowledge_evidence(ack)?;
                drop(connection);
                server.shutdown().await?;
                drop(
                    DataStoreQualification::reopen_data(&tls.path().join("evidence/analysis"))
                        .await?,
                );
                drop(reopen_control_store(&tls.path().join("control-store")).await?);
            }
            let mut config = tls.configuration()?;
            if logical {
                config.data_storage.tenant_max_bytes = 1;
            } else {
                config.data_storage.policy_reserve_bytes = u64::MAX / 4;
            }
            let parts = config.into_parts()?;
            assert!(parts.data_error.is_none());
            let data = parts.control.analysis_store().ok_or("data owner absent")?;
            if seeded {
                assert!(matches!(
                    EvidenceRetentionOwner::new(&data, data.retention_limits())?.sweep(None, START),
                    Err(araphor_data::Error::StorageCapacity {
                        resource: "filesystem reserve",
                        ..
                    })
                ));
                assert!(!data.retention_healthy());
            }
            let before = data.meta()?;
            let changed = data.subscribe_revision();
            let server = tls.start(parts.control).await?;
            let cursor = if seeded { 2 } else { 1 };
            DataStoreQualification::record(&observations, cursor);
            let batch = observations.next_evidence_batch().ok_or("batch absent")?;
            let mut connection = case.connect(&tls, &server).await?;
            connection.report_readiness(true, true).await?;
            connection.send_evidence_batch(batch.clone()).await?;
            let rejected =
                tokio::time::timeout(Duration::from_secs(5), connection.next_message()).await?;
            assert!(
                matches!(rejected, Err(mithril_node::Error::ControlRpc { source, .. }) if source.code() == tonic::Code::ResourceExhausted)
            );
            if seeded {
                let snapshot = observations.coverage_snapshot().ok_or("coverage absent")?;
                let interval = snapshot
                    .current_intervals()
                    .into_iter()
                    .next()
                    .ok_or("source coverage absent")?;
                let coverage = connection.send_coverage_report(&snapshot, &interval).await;
                assert!(
                    matches!(coverage, Err(mithril_node::Error::ControlRpc { source, .. })
                        if source.code() == tonic::Code::ResourceExhausted)
                );
            }
            assert_eq!(observations.pending_evidence_records(), 1);
            assert_eq!(data.meta()?, before);
            assert!(!changed.has_changed()?);
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
            assert_eq!(ack.contiguous_cursor, cursor);
            observations.acknowledge_evidence(ack)?;
            assert_eq!(observations.pending_evidence_records(), 0);
            assert_eq!(data.meta()?.commit_revision, baseline + 1);
            drop(connection);
            server.shutdown().await?;
        }
        Ok(())
    }
}
