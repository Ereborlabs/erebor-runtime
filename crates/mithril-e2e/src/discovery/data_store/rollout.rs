use sha2::{Digest as _, Sha256};

use super::*;
use mithril_control::{PolicyBundleV1, PolicyRolloutStateV1, WorkloadTargetFactV1};

impl DataStoreQualification {
    pub async fn rollout_load(&self) -> Result<()> {
        self.rollout_pairs(32).await
    }

    async fn rollout_pairs(&self, pairs: u64) -> Result<()> {
        self.check(!self.output.exists(), "the output directory already exists")?;
        self.check(
            (2..=32).contains(&pairs) && pairs.is_multiple_of(2),
            "the rollout pair count is invalid",
        )?;
        let tls = MtlsFixture::new(false)?;
        let root = tls.path().join("analysis");
        let control_root = tls.path().join("control-store");
        let control = ControlStore::open(&control_root)?;
        let data = Arc::new(AnalysisStore::open(&root)?);
        let fixture = OutagePolicyFixture::new(control.clone());
        let targets = fixture.inventory(&fixture.resource(1)?)?;
        let intake = EvidenceIntakeOwner::new(
            control.clone(),
            data.clone(),
            Arc::new(TestClock(AtomicU64::new(START))),
        )?;
        let plane = tls
            .control_from_intake(intake, 1)?
            .with_policy_desired_state(fixture.owner.clone());
        let server = tls.start(plane.clone()).await?;
        let mut trust = TrustCache::load(&tls.path().join("trust"))?;
        let mut connection = tls
            .connector(&server, "node-a", [7; 16])
            .connect(
                OutagePolicyFixture::registration([7; 16], false),
                false,
                &mut trust,
            )
            .await?;
        connection.report_readiness(true, true).await?;
        plane.bind_kubernetes_node_session("worker-a", "dddddddd-dddd-4ddd-8ddd-dddddddddddd")?;
        self.check(
            plane.replace_kubernetes_workload_inventory(targets.clone())?,
            "rollout workload inventory did not change",
        )?;
        let observations = EffectObservationStore::durable(
            4096,
            tls.path().join("wal"),
            EvidenceWalLimits::default(),
            ObservationCanonicalizer::new(
                EvidenceIdV1::new(1, 2),
                EvidenceIdV1::new(3, 4),
                1,
                [7; 16].into(),
            )?,
        )?;
        let mut identity = None;
        let mut digest = Sha256::new();
        let mut samples = Vec::new();
        let mut states = Vec::new();
        for pair in 0..pairs {
            let mut batches = self.load_group(&observations, pair).await?;
            for batch in &batches {
                let wire: mithril_control::EvidenceBatch = batch.clone().into();
                identity.get_or_insert(EvidenceIntakeIdentityV1 {
                    tenant_id: EvidenceIdV1::new(1, 2).to_be_bytes(),
                    node_id: "node-a".into(),
                    node_boot_id: [7; 16],
                    label_epoch: 1,
                    source_id: wire.source_id.as_slice().try_into()?,
                    source_epoch: wire.source_epoch,
                });
                digest.update(&wire.framed_records);
            }
            let generation = i64::try_from(pair * 2 + 3)?;
            let accepted = (pair + 1) * 4096;
            let loaded_first = !pair.is_multiple_of(2);
            let mut idle_us = 0;
            let mut loaded_us = 0;
            let mut ack_us = 0;
            for (offset, loaded) in [loaded_first, !loaded_first].into_iter().enumerate() {
                let sent = Instant::now();
                if loaded {
                    connection.send_evidence_group(batches.clone()).await?;
                }
                let started = Instant::now();
                states.push(
                    self.rollout_step(
                        &fixture,
                        &mut connection,
                        &targets,
                        generation + i64::try_from(offset)?,
                    )
                    .await?,
                );
                let elapsed = started.elapsed().as_micros();
                if loaded {
                    loaded_us = elapsed;
                    let ack = self.load_ack(&mut connection, accepted).await?;
                    ack_us = sent.elapsed().as_micros();
                    observations.acknowledge_evidence(ack)?;
                    self.check(
                        observations.next_evidence_batch().is_none(),
                        "rollout load kept acknowledged input",
                    )?;
                    let identity = identity.as_ref().ok_or("rollout source absent")?;
                    let before = data.source_status(identity)?;
                    connection
                        .send_evidence_group(std::mem::take(&mut batches))
                        .await?;
                    self.check(
                        self.load_ack(&mut connection, accepted)
                            .await?
                            .contiguous_cursor
                            == accepted
                            && data.source_status(identity)? == before,
                        "rollout load replay changed source state",
                    )?;
                } else {
                    idle_us = elapsed;
                }
            }
            samples.push(serde_json::json!({
                "pair": pair, "loaded_first": loaded_first,
                "idle_rollout_us": idle_us, "loaded_rollout_us": loaded_us,
                "durable_ack_us": ack_us, "accepted_cursor": accepted,
            }));
        }
        let identity = identity.ok_or("rollout source absent")?;
        let mut cursor = 1;
        let mut count = 0;
        let mut retained = Sha256::new();
        loop {
            let page = data.read_page(&identity, cursor)?;
            for record in page.records {
                retained.update(&record.framed_record);
                count += 1;
            }
            match page.next_cursor {
                Some(next) => cursor = next,
                None => break,
            }
        }
        let expected = digest.finalize();
        self.check(
            count == pairs * 4096 && retained.finalize() == expected,
            "rollout load changed retained input",
        )?;
        self.check(
            !control.root().join("evidence/segments-v2").exists(),
            "rollout load used the old evidence writer",
        )?;
        let status = data.source_status(&identity)?;
        drop(connection);
        server.shutdown().await?;
        drop(plane);
        drop(fixture);
        drop(control);
        drop(data);
        let control = reopen_control_store(&control_root).await?;
        let data = Self::reopen_data(&root).await?;
        self.check(
            data.source_status(&identity)? == status,
            "rollout restart changed evidence state",
        )?;
        for state in &states {
            self.check(
                control
                    .rollout_state(&state.desired_candidate_content_id, "node-a")?
                    .as_ref()
                    == Some(state),
                "rollout restart changed an accepted transition",
            )?;
        }
        fs::create_dir(&self.output)?;
        super::super::write_json(
            &self.output.join("result.json"),
            &serde_json::json!({
                "schema_version": 1, "case": "data-store-rollout", "result": "PASS",
                "proof_kind": "synthetic-mtls", "kernel_evidence": false,
                "node_activation": "fixture report; no kernel policy installation",
                "pair_count": pairs, "record_count": count, "rollout_count": states.len(),
                "input_sha256": hex::encode(expected), "samples": samples,
                "rollout_states": states, "usage": data.storage_usage()?,
                "qualification": "Control rollout with in-flight evidence; no physical activation, full-quota, or reserve claim",
            }),
        )?;
        Ok(())
    }

    async fn rollout_step(
        &self,
        fixture: &OutagePolicyFixture,
        connection: &mut ControlConnection,
        targets: &[WorkloadTargetFactV1],
        generation: i64,
    ) -> Result<PolicyRolloutStateV1> {
        let resource = fixture.resource(generation)?;
        let now = i64::try_from(START)? + generation * 3;
        let desired = fixture
            .owner
            .reconcile(&resource, OUTAGE_NAMESPACE_UID, targets, now)?;
        self.check(
            desired.bundles.len() == 1,
            "rollout did not select exactly one bundle",
        )?;
        let bundle = &desired.bundles[0];
        let inventory = connection.policy_inventory(None, Vec::new()).await?;
        self.check(
            inventory.desired_inventory_complete
                && inventory.candidate_available
                && inventory.candidate_content_id == bundle.candidate.candidate_content_id
                && inventory.bundle_digest == bundle.bundle_digest,
            "rollout inventory differs from the desired bundle",
        )?;
        let mut bytes = Vec::new();
        for index in 0..inventory.chunk_count {
            let chunk = connection
                .fetch_policy_chunk(
                    inventory.candidate_content_id.clone(),
                    inventory.bundle_digest.clone(),
                    index,
                )
                .await?;
            self.check(
                chunk.chunk_index == index && chunk.chunk_count == inventory.chunk_count,
                "rollout chunk order differs",
            )?;
            bytes.extend_from_slice(&chunk.payload);
        }
        self.check(
            bytes.len() as u64 == inventory.bundle_bytes,
            "rollout bundle size differs",
        )?;
        let delivered: PolicyBundleV1 = serde_json::from_slice(&bytes)?;
        self.check(
            delivered == *bundle,
            "rollout delivered different policy bytes",
        )?;
        let accepted = connection
            .acknowledge_policy(OutagePolicyFixture::active_acknowledgement(
                &delivered,
                u64::try_from(generation)?,
                now + 1,
            ))
            .await?;
        self.check(
            accepted.rollout_state == "ACTIVE",
            "rollout acknowledgement was not active",
        )?;
        let result = fixture
            .owner
            .reconcile(&resource, OUTAGE_NAMESPACE_UID, targets, now + 2)?;
        self.check(
            result.status.rollout.desired == 1
                && result.status.rollout.active == 1
                && result.status.rollout.updating == 0
                && result.status.rollout.failed == 0,
            "rollout did not converge",
        )?;
        result
            .rollout_states
            .into_iter()
            .next()
            .ok_or_else(|| "rollout state absent".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn data_rollout_load() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let output = directory.path().join("rollout");
        let case = DataStoreQualification::new(output.clone());
        for pairs in [0, 1, 3, 33, 34] {
            assert!(case.rollout_pairs(pairs).await.is_err());
            assert!(!output.exists());
        }
        tokio::time::timeout(Duration::from_secs(30), case.rollout_pairs(2)).await??;
        let bytes = fs::read(output.join("result.json"))?;
        let result: serde_json::Value = serde_json::from_slice(&bytes)?;
        assert_eq!(result["result"], "PASS");
        assert_eq!(result["record_count"], 8192);
        assert_eq!(result["rollout_count"], 4);
        assert_eq!(
            result["samples"].as_array().ok_or("samples absent")?.len(),
            2
        );
        assert_eq!(result["samples"][0]["loaded_first"], false);
        assert_eq!(result["samples"][1]["loaded_first"], true);
        assert_eq!(result["kernel_evidence"], false);
        assert!(case.rollout_pairs(2).await.is_err());
        assert_eq!(fs::read(output.join("result.json"))?, bytes);
        Ok(())
    }
}
