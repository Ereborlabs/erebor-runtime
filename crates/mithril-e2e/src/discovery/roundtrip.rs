use std::{error::Error as StdError, fs, path::PathBuf};

use mithril_control::{
    ControlStore, DiscoveryAdvanceV1, DiscoveryOwner, DiscoveryProfileStateV1,
    EvidenceConsumptionWatermarkV1, EvidenceIdV1, EvidenceIntakeIdentityV1, EvidenceRetentionOwner,
    NodeRegistration,
};
use mithril_node::{
    EffectObservationStore, EvidenceWalLimits, NodeControlMessage, ObservationCanonicalizer,
    TrustCache,
};
use snafu::ensure;
use zerocopy::IntoBytes as _;

use crate::{control_fixture::MtlsFixture, error::InvalidInputSnafu};

pub struct DiscoveryQualificationRunner {
    output: PathBuf,
}

impl DiscoveryQualificationRunner {
    pub fn new(output: PathBuf) -> Self {
        Self { output }
    }

    pub async fn profile_restart(&self) -> Result<(), Box<dyn StdError>> {
        ensure!(
            !self.output.exists(),
            InvalidInputSnafu {
                path: &self.output,
                reason: "the qualification output already exists",
            }
        );
        let tls = MtlsFixture::new(false)?;
        let root = tls.path().join("control-store");
        let store = ControlStore::open(&root)?;
        let control = tls.control_with_store(store.clone(), 1)?;
        let server = tls.start(control).await?;
        let boot = EvidenceIdV1::from([7; 16]);
        let source = EvidenceIdV1::new(3, 4);
        let observations = EffectObservationStore::durable(
            8,
            tls.path().join("wal"),
            EvidenceWalLimits::default(),
            ObservationCanonicalizer::new(EvidenceIdV1::new(1, 2), source, 1, boot)?,
        )?;
        let process = EvidenceIdV1::new(8, 9);
        let entry = EvidenceIdV1::new(10, 11);
        observations.record_bytes(
            erebor_interceptor_abi::EffectObservationV1 {
                observed_boottime_ns: 102,
                source_sequence: 101,
                source_cpu_id: 3,
                task_cookie: 7,
                process_instance_id: process,
                entry_instance_id: entry,
                reason: 9,
                physical_result: 1,
                effect_family: 1,
                operation: 1,
                ..Default::default()
            }
            .as_bytes(),
        );
        let batch = observations
            .next_evidence_batch()
            .ok_or("Node WAL has no evidence")?;
        let original = batch.decode_records()?;
        let wire: mithril_control::EvidenceBatch = batch.clone().into();
        let mut trust = TrustCache::load(&tls.path().join("trust"))?;
        let mut connection = tls
            .connector(&server, "node-a", boot.to_be_bytes())
            .connect(
                NodeRegistration {
                    platform_digest: "a".repeat(64),
                    program_digest: "b".repeat(64),
                    label_epoch: 1,
                    kernel_ready: true,
                    effect_prevention_claims_enabled: false,
                    kubernetes_node_name: String::new(),
                    startup_absence_proof_digest: mithril_control::startup_absence_proof_digest(
                        "node-a",
                        &boot.to_be_bytes(),
                        1,
                        true,
                        true,
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
            .await?;
        connection.send_evidence_batch(batch).await?;
        let message =
            tokio::time::timeout(std::time::Duration::from_secs(5), connection.next_message())
                .await??;
        let NodeControlMessage::EvidenceAck(ack) = message else {
            return Err("Control did not acknowledge the evidence".into());
        };
        ensure!(
            ack.contiguous_cursor == 1,
            InvalidInputSnafu {
                path: &self.output,
                reason: "the durable evidence cursor differs",
            }
        );
        observations.acknowledge_evidence(ack)?;
        let stream = EvidenceIntakeIdentityV1 {
            tenant_id: EvidenceIdV1::new(1, 2).to_be_bytes(),
            node_id: "node-a".into(),
            node_boot_id: boot.to_be_bytes(),
            label_epoch: 1,
            source_id: wire.source_id.as_slice().try_into()?,
            source_epoch: wire.source_epoch,
        };
        let retained = {
            let read = store.begin_evidence_read(&stream, 1)?;
            store.read_evidence_page(&read, 1)?.records
        };
        ensure!(
            retained == original && retained.len() == 1,
            InvalidInputSnafu {
                path: &self.output,
                reason: "Control changed the retained Node record",
            }
        );
        let context = retained[0]
            .decision_context
            .as_ref()
            .ok_or("raw context absent")?;
        ensure!(
            context.original_kernel_sequence == 101
                && context.process_instance_id.as_slice() == process.to_be_bytes()
                && context.entry_instance_id.as_slice() == entry.to_be_bytes(),
            InvalidInputSnafu {
                path: &self.output,
                reason: "raw context differs after the transport roundtrip",
            }
        );
        let before = EvidenceRetentionOwner::from_store(store.clone()).watermark(&stream)?;
        let owner = DiscoveryOwner::open(store.clone())?;
        let DiscoveryAdvanceV1::Applied { export, progress } = owner.advance(&stream, 1)? else {
            return Err("discovery did not export the accepted record".into());
        };
        let snapshot = owner.seal_interval(&export)?;
        let page = owner.read_snapshot(&snapshot, None)?;
        ensure!(
            page.profile.state == DiscoveryProfileStateV1::Partial
                && page.profile.accepted_records == 1
                && page.profile.unresolved_records == 1
                && progress.next_cursor == 2
                && EvidenceRetentionOwner::from_store(store.clone()).watermark(&stream)? == before,
            InvalidInputSnafu {
                path: &self.output,
                reason: "discovery counts or retention changed"
            }
        );
        let copied = store.read_discovery_artifact(&export.artifact)?;
        EvidenceRetentionOwner::from_store(store.clone()).acknowledge(
            EvidenceConsumptionWatermarkV1 {
                identity: stream.clone(),
                evidence_cursor: 1,
                coverage_revision: 0,
            },
        )?;
        drop(owner);
        drop(connection);
        server.shutdown().await?;
        drop(store);
        fs::remove_file(root.join("discovery-index.sqlite"))?;
        let store = ControlStore::open(&root)?;
        let recovered = DiscoveryOwner::open(store.clone())?;
        ensure!(
            recovered.read_snapshot(&snapshot, None).is_err(),
            InvalidInputSnafu {
                path: &self.output,
                reason: "a missing projection was exposed as ready",
            }
        );
        let recovered_head = recovered.seal_interval(&export)?;
        let recovered_page = recovered.read_snapshot(&recovered_head, None)?;
        ensure!(
            recovered_head == snapshot
                && recovered_page == page
                && store.read_discovery_artifact(&export.artifact)? == copied
                && store
                    .begin_evidence_read(&stream, 1)?
                    .metadata()
                    .retained_floor
                    == 2,
            InvalidInputSnafu {
                path: &self.output,
                reason: "profile recovery changed retained proof"
            }
        );
        fs::create_dir(&self.output)?;
        super::write_json(&self.output.join("export.json"), &copied)?;
        super::write_json(&self.output.join("snapshot.json"), &recovered_page)?;
        super::write_json(
            &self.output.join("result.json"),
            &serde_json::json!({
                "schema_version": 1, "case": "profile-restart", "result": "PASS",
                "qualification": "LIGHTWEIGHT", "input": "synthetic kernel record",
                "production_authority": false, "physical_action_attempted": false,
                "signed_context_resolved": false, "durable_cursor": 1,
                "original_kernel_sequence": context.original_kernel_sequence,
                "context_digest": crate::DigestV1::of(serde_json::to_vec(context)?),
                "checkpoint": progress, "export": export, "snapshot": snapshot,
                "recovered_snapshot": recovered_head, "recovered_digest": recovered_page.profile.content_digest,
                "asserted_contracts": ["node-wal", "mtls-intake", "raw-context", "bounded-export",
                    "explicit-unresolved-context", "sealing", "source-reclamation", "projection-repair", "stable-snapshot"]
            }),
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #[tokio::test]
    async fn discovery_derivation_profile_restart_uses_wal_and_mtls(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let output = directory.path().join("proof");
        let runner = super::DiscoveryQualificationRunner::new(output.clone());
        runner.profile_restart().await?;
        let before = std::fs::read(output.join("result.json"))?;
        assert!(runner.profile_restart().await.is_err());
        assert_eq!(std::fs::read(output.join("result.json"))?, before);
        Ok(())
    }
}
