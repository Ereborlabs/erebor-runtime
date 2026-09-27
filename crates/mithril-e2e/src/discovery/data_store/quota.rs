use sha2::{Digest as _, Sha256};

use super::*;
use araphor_data::StorageLimitsV1;

impl DataStoreQualification {
    pub async fn quota(&self) -> Result<()> {
        self.quota_with_limits(StorageLimitsV1::default()).await
    }

    fn quota_failure(
        &self,
        accepted: u64,
        elapsed: Duration,
        samples: &[serde_json::Value],
        error: &dyn StdError,
    ) -> Result<()> {
        fs::create_dir(&self.output)?;
        super::super::write_json(
            &self.output.join("result.json"),
            &serde_json::json!({
                "schema_version": 1, "case": "data-store-quota", "result": "FAIL",
                "proof_kind": "synthetic-mtls", "kernel_evidence": false,
                "debug_assertions": cfg!(debug_assertions),
                "last_observed_ack": accepted, "elapsed_us": elapsed.as_micros(),
                "ack_deadline_seconds": 5, "error": error.to_string(), "samples": samples,
                "qualification": "incomplete; the last observed ACK is not a final store receipt",
            }),
        )?;
        Ok(())
    }

    async fn quota_with_limits(&self, limits: StorageLimitsV1) -> Result<()> {
        self.check(!self.output.exists(), "the output directory already exists")?;
        let tls = MtlsFixture::new(false)?;
        let root = tls.path().join("analysis");
        let control = ControlStore::open(tls.path().join("control-store"))?;
        let data = Arc::new(AnalysisStore::open_with_limits(
            &root,
            Default::default(),
            limits,
        )?);
        let clock = Arc::new(TestClock(AtomicU64::new(START)));
        let intake = EvidenceIntakeOwner::new(control.clone(), data.clone(), clock.clone())?;
        let plane = tls.control_from_intake(intake, 1)?;
        let trust = plane.trust_bundle_owner().current()?;
        let server = tls.start(plane).await?;
        ControlServerFixture::wait_context(
            &data,
            &araphor_data::AnalysisContextKeyV1 {
                tenant_id: EvidenceIdV1::new(1, 2).to_be_bytes(),
                owner_id: "mithril-control/trust".into(),
                entity_key: b"trust".to_vec(),
                lifetime_key: trust.bundle_digest.as_bytes().to_vec(),
                owner_revision: trust.generation,
            },
        )
        .await?;
        let observations = EffectObservationStore::durable(
            4096,
            tls.path().join("wal"),
            EvidenceWalLimits {
                maximum_batch_records: 1024,
                ..Default::default()
            },
            ObservationCanonicalizer::new(
                EvidenceIdV1::new(1, 2),
                EvidenceIdV1::new(3, 4),
                1,
                [7; 16].into(),
            )?,
        )?;
        let mut batches = self.load_group(&observations, 0).await?;
        let wire: mithril_control::EvidenceBatch = batches[0].clone().into();
        let identity = EvidenceIntakeIdentityV1 {
            tenant_id: EvidenceIdV1::new(1, 2).to_be_bytes(),
            node_id: "node-a".into(),
            node_boot_id: [7; 16],
            label_epoch: 1,
            source_id: wire.source_id.as_slice().try_into()?,
            source_epoch: wire.source_epoch,
        };
        let scope = ProcessorScopeV1 {
            processor_id: "quota-required".into(),
            method_version: 1,
            identity: identity.clone(),
        };
        data.register_processor(&scope, ProcessorClassV1::Required, 1)?;
        let mut connection = self.connect(&tls, &server).await?;
        connection.report_readiness(true, true).await?;
        let mut accepted = 0_u64;
        let mut input_bytes = 0_usize;
        let mut digest = Sha256::new();
        let mut samples = Vec::new();
        let mut previous = None;
        let allowance = limits.tenant_max_bytes - limits.tenant_max_bytes / 4;
        let batch_limit = allowance
            .checked_div(wire.framed_records.len() as u64)
            .and_then(|count| count.checked_add(2))
            .ok_or("the quota batch bound is invalid")?;
        let group_limit = batch_limit.div_ceil(batches.len() as u64);
        let started = Instant::now();
        let blocked = 'fill: {
            for group in 0..group_limit {
                if group > 0 {
                    batches = self.load_group(&observations, group).await?;
                }
                for batch in &batches {
                    self.check(batch.record_count() == 1024, "quota batch size differs")?;
                    let before = data.meta()?;
                    let receipt = data.source_receipt(&identity)?;
                    let pending = observations.pending_evidence_records();
                    let sent = Instant::now();
                    connection.send_evidence_batch(batch.clone()).await?;
                    match Self::ack(&mut connection).await {
                        Ok(ack) => {
                            let ack_us = sent.elapsed().as_micros();
                            self.check(
                                ack.contiguous_cursor == accepted + 1024,
                                "quota load ACK differs",
                            )?;
                            accepted = ack.contiguous_cursor;
                            observations.acknowledge_evidence(ack)?;
                            let wire: mithril_control::EvidenceBatch = batch.clone().into();
                            input_bytes += wire.framed_records.len();
                            digest.update(&wire.framed_records);
                            previous = Some(batch.clone());
                            samples.push(serde_json::json!({
                                "accepted_cursor": accepted, "ack_us": ack_us,
                                "database_bytes": Self::file_size(&root.join("analysis.duckdb"))?,
                                "wal_bytes": Self::file_size(&root.join("analysis.duckdb.wal"))?,
                                "usage": data.storage_usage()?,
                            }));
                        }
                        Err(error) => {
                            if !matches!(error.downcast_ref::<mithril_node::Error>(),
                                Some(mithril_node::Error::ControlRpc { source, .. })
                                if source.code() == tonic::Code::ResourceExhausted
                                    && source.message().contains("tenant logical bytes"))
                            {
                                self.quota_failure(
                                    accepted,
                                    started.elapsed(),
                                    &samples,
                                    error.as_ref(),
                                )?;
                                return Err(error);
                            }
                            self.check(
                                data.meta()? == before
                                    && data.source_receipt(&identity)? == receipt
                                    && observations.pending_evidence_records() == pending,
                                "quota rejection changed committed or pending input",
                            )?;
                            break 'fill batch.clone();
                        }
                    }
                }
            }
            return Err("tenant quota was not reached within the bounded load".into());
        };
        let intake_us = started.elapsed().as_micros();
        let at_capacity = data.storage_usage()?;
        self.check(accepted > 0, "quota rejected the first batch")?;
        connection.policy_inventory(None, Vec::new()).await?;
        drop(connection);
        let mut connection = self.connect(&tls, &server).await?;
        connection.report_readiness(true, true).await?;
        let before = data.meta()?;
        connection
            .send_evidence_batch(previous.ok_or("accepted batch absent")?)
            .await?;
        let ack = Self::ack(&mut connection).await?;
        self.check(
            ack.contiguous_cursor == accepted && data.meta()? == before,
            "retained retry at quota changed committed state",
        )?;

        let reading = Instant::now();
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
            tokio::task::yield_now().await;
        }
        let expected = digest.finalize();
        self.check(
            count == accepted && actual.finalize() == expected,
            "quota load changed retained frames",
        )?;
        let read_us = reading.elapsed().as_micros();
        let witness = data.read_page(&identity, accepted)?.records;
        let result = AnalysisResultCommitV1 {
            scope,
            expected_cursor: 0,
            consumed_cursor: accepted,
            coverage_revision: 0,
            context_revision: 0,
            result_id: "quota-result".into(),
            body: b"quota recovery".to_vec(),
            created_utc_ns: START,
            witnesses: vec![AnalysisWitnessV1 {
                identity: identity.clone(),
                cursor: accepted,
                expires_utc_ns: START + 96 * HOUR,
            }],
            context_refs: Vec::new(),
        };
        let maintenance = Instant::now();
        data.commit_result(&result)?;
        let result_us = maintenance.elapsed().as_micros();
        clock.0.store(START + 25 * HOUR, Ordering::SeqCst);
        let retention = EvidenceRetentionOwner::new(&data, data.retention_limits())?;
        let maintenance = Instant::now();
        for _ in 0..16 {
            retention.retain(&identity, START + 25 * HOUR)?;
            tokio::task::yield_now().await;
        }
        let retention_us = maintenance.elapsed().as_micros();
        let checkpoint = Instant::now();
        data.checkpoint()?;
        let checkpoint_us = checkpoint.elapsed().as_micros();
        self.check(
            matches!(
                data.read_page(&identity, 1),
                Err(araphor_data::Error::RetainedRangeExpired { .. })
            ),
            "quota maintenance did not record expiry",
        )?;
        let pending = observations.pending_evidence_records();
        connection.send_evidence_batch(blocked.clone()).await?;
        let ack = Self::ack(&mut connection).await?;
        self.check(
            ack.contiguous_cursor == accepted + 1024,
            "quota recovery did not accept the retained batch",
        )?;
        observations.acknowledge_evidence(ack)?;
        self.check(
            observations.pending_evidence_records() + 1024 == pending,
            "quota recovery removed unrelated pending input",
        )?;
        connection.send_evidence_batch(blocked.clone()).await?;
        self.check(
            Self::ack(&mut connection).await?.contiguous_cursor == accepted + 1024,
            "quota recovery replay changed the receipt",
        )?;
        self.check(
            data.read_page(&identity, accepted)?.records.first() == witness.first(),
            "quota recovery changed its exact witness",
        )?;
        self.check(
            control.health()?.evidence_cursors == 0,
            "quota load used the old evidence writer",
        )?;
        drop(connection);
        server.shutdown().await?;
        let status = data
            .source_status(&identity)?
            .ok_or("quota source absent")?;
        let meta = data.meta()?;
        let final_usage = data.storage_usage()?;
        drop(data);
        let restart = Instant::now();
        let data = AnalysisStore::open_with_limits(&root, Default::default(), limits)?;
        let restart_us = restart.elapsed().as_micros();
        self.check(
            data.meta()? == meta
                && data.source_status(&identity)? == Some(status)
                && data.read_result(identity.tenant_id, &result.result_id)? == Some(result.body)
                && data.read_page(&identity, accepted)?.records.first() == witness.first(),
            "quota restart changed durable state",
        )?;
        let mut recovered = Vec::new();
        for cursor in (accepted + 1..=accepted + 1024).step_by(256) {
            for record in data.read_page(&identity, cursor)?.records {
                recovered.extend_from_slice(&record.framed_record);
            }
        }
        self.check(
            recovered == mithril_control::EvidenceBatch::from(blocked).framed_records,
            "quota recovery changed replayed frames",
        )?;
        fs::create_dir(&self.output)?;
        super::super::write_json(
            &self.output.join("result.json"),
            &serde_json::json!({
                "schema_version": 1, "case": "data-store-quota", "result": "PASS",
                "proof_kind": "synthetic-mtls", "kernel_evidence": false,
                "debug_assertions": cfg!(debug_assertions),
                "tenant_max_bytes": limits.tenant_max_bytes,
                "accepted_before_limit": accepted, "accepted_after_recovery": accepted + 1024,
                "input_bytes": input_bytes, "input_sha256": hex::encode(expected),
                "intake_us": intake_us, "read_us": read_us, "result_us": result_us,
                "retention_us": retention_us, "checkpoint_us": checkpoint_us,
                "restart_us": restart_us, "at_capacity": at_capacity,
                "after_recovery": final_usage, "samples": samples,
                "qualification": "tenant logical quota; no global or physical reserve claim",
            }),
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn data_quota_failure() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let output = directory.path().join("failed");
        let case = DataStoreQualification::new(output.clone());
        let error = std::io::Error::other("test ACK failure");
        let samples = [serde_json::json!({ "accepted_cursor": 1024, "ack_us": 12 })];
        case.quota_failure(1024, Duration::from_secs(6), &samples, &error)?;
        let bytes = fs::read(output.join("result.json"))?;
        let result: serde_json::Value = serde_json::from_slice(&bytes)?;
        assert_eq!(result["result"], "FAIL");
        assert_eq!(result["last_observed_ack"], 1024);
        assert_eq!(result["elapsed_us"], 6_000_000);
        assert_eq!(result["samples"], serde_json::json!(samples));
        assert_eq!(result["error"], "test ACK failure");
        assert!(case.quota_failure(0, Duration::ZERO, &[], &error).is_err());
        assert_eq!(fs::read(output.join("result.json"))?, bytes);
        Ok(())
    }

    #[tokio::test]
    async fn data_quota_recovery() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let output = directory.path().join("quota");
        DataStoreQualification::new(output.clone())
            .quota_with_limits(StorageLimitsV1 {
                tenant_max_bytes: 64 * 1024 * 1024,
                ..Default::default()
            })
            .await?;
        let result: serde_json::Value =
            serde_json::from_slice(&fs::read(output.join("result.json"))?)?;
        let accepted = result["accepted_before_limit"]
            .as_u64()
            .ok_or("accepted count absent")?;
        assert!(accepted > 0);
        assert_eq!(result["accepted_after_recovery"], accepted + 1024);
        assert_eq!(result["tenant_max_bytes"], 64 * 1024 * 1024);
        Ok(())
    }
}
