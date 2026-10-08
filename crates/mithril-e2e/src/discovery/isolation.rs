use std::{
    error::Error as StdError,
    fs,
    path::Path,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use araphor_data::{
    AnalysisSelectionV1, DiscoveryReplayV1, EvidenceRetentionOwner, QueryLimits, QueryOwner,
    QueryPlan, QueryTemplate,
};
use duckdb::types::Value;
use mithril_control::{
    EvidenceIdV1, IntakeClock, PolicyDesiredStateConfigV1, PolicySignerConfigV1,
    PolicySignerTrustV1, ProfileSealRequestV1, TraceBatchV1, TraceExchangeV1, TraceFrameKindV1,
    TraceFrameV1, TraceOwner, TraceUploadV1,
};
use mithril_node::{
    ControlConnection, EffectObservationStore, EvidenceWalLimits, NodeControlMessage,
    ObservationCanonicalizer, TrustCache,
};
use snafu::ensure;
use zerocopy::IntoBytes as _;

use crate::{
    control_fixture::{
        MtlsFixture, OutagePolicyFixture, OUTAGE_CLUSTER_UID, OUTAGE_NAMESPACE_UID,
        OUTAGE_TENANT_ID,
    },
    error::InvalidInputSnafu,
    ObservabilityQualification,
};

struct Clock(SystemTime);

impl IntakeClock for Clock {
    fn now(&self) -> SystemTime {
        self.0
    }
}

pub(super) async fn run(output: &Path) -> Result<(), Box<dyn StdError>> {
    ensure!(
        !output.exists(),
        InvalidInputSnafu {
            path: output,
            reason: "the qualification output already exists",
        }
    );
    let mut cases = Vec::new();
    for enabled in [false, true] {
        let tls = MtlsFixture::new(false)?;
        let key = ed25519_dalek::SigningKey::from_bytes(&[23; 32]);
        let mut config = tls.configuration()?;
        config.discovery = enabled.then(araphor_data::DiscoveryConfigV1::default);
        config.data_retention.raw_max_age_ns = 1;
        config.trust.policy_issuer_sequence_epoch = 1;
        config.trust.policy_signers = vec![PolicySignerTrustV1 {
            signing_key_id: "trace-key".into(),
            ed25519_public_key_hex: hex::encode(key.verifying_key().as_bytes()),
            revoked: false,
        }];
        config.trust = config.trust.with_computed_bundle_digest();
        let key_path = tls.path().join("policy-key");
        let seal_path = tls.path().join("policy-seal.json");
        fs::write(&key_path, hex::encode(key.to_bytes()))?;
        let mut seal: ProfileSealRequestV1 = serde_json::from_slice(include_bytes!(
            "../../fixtures/mithril-policy/observe-profile-seal-request.json"
        ))?;
        seal.signing_key_id = "trace-key".into();
        seal.issuer_sequence = 0;
        fs::write(&seal_path, serde_json::to_vec(&seal)?)?;
        config.kubernetes_policy = Some(PolicyDesiredStateConfigV1 {
            tenant_id: OUTAGE_TENANT_ID.into(),
            cluster_uid: OUTAGE_CLUSTER_UID.into(),
            signer: PolicySignerConfigV1 {
                signing_key_id: "trace-key".into(),
                signing_key_path: key_path,
                seal_request_path: seal_path,
                distribution_sequence_epoch: 1,
                candidate_validity_ns: 900_000_000_000,
            },
        });
        let clock = Arc::new(Clock(SystemTime::now()));
        let now = u64::try_from(clock.now().duration_since(UNIX_EPOCH)?.as_nanos())?;
        let parts = config.into_parts_with_clock(clock)?;
        ensure!(
            parts.data_error.is_none() && parts.discovery_error.is_none(),
            InvalidInputSnafu {
                path: output,
                reason: "an optional owner failed to start",
            }
        );
        let control = parts
            .control
            .clone()
            .with_trace_signer("trace-key".into(), 1, key)?;
        let data = control.analysis_store().ok_or("the data owner is absent")?;
        let fixture = OutagePolicyFixture {
            owner: control
                .policy_desired_state()
                .ok_or("the native policy owner is absent")?,
        };
        let store = fixture.owner.store();
        let policy = fixture.resource(1)?;
        let facts = fixture.inventory(&policy)?;
        let initial =
            fixture
                .owner
                .reconcile(&policy, OUTAGE_NAMESPACE_UID, &facts, i64::try_from(now)?)?;
        let initial_policy = store
            .policy_document(&initial.source_revision.policy_source_revision_id)?
            .ok_or("the initial native policy is absent")?;
        control.replace_kubernetes_workload_inventory(facts.clone())?;
        let server = tls.start(control.clone()).await?;
        let boot = [7; 16];
        let observations = EffectObservationStore::durable(
            8,
            tls.path().join("wal"),
            EvidenceWalLimits::default(),
            ObservationCanonicalizer::new(
                EvidenceIdV1::new(1, 2),
                EvidenceIdV1::new(3, 4),
                1,
                boot.into(),
            )?,
        )?;
        let mut cache = TrustCache::load(&tls.path().join("trust"))?;
        let mut registration = OutagePolicyFixture::registration(boot, false);
        registration.effect_prevention_claims_enabled = false;
        let mut connection = tls
            .connector(&server, "node-a", boot)
            .connect(registration, true, &mut cache)
            .await?;
        connection.report_readiness(true, true).await?;
        for cursor in [1, 2] {
            accept_record(output, &observations, &mut connection, cursor).await?;
            if cursor == 1 {
                if let Some(owner) = &parts.discovery {
                    ensure!(
                        owner.process(now)? == 1,
                        InvalidInputSnafu {
                            path: output,
                            reason:
                                "the configured discovery owner did not process its first record",
                        }
                    );
                }
            }
        }
        let sources = data.source_page(EvidenceIdV1::new(1, 2).to_be_bytes(), None)?;
        ensure!(
            sources.len() == 1,
            InvalidInputSnafu {
                path: output,
                reason: "the Node upload did not retain one exact source",
            }
        );
        let source = sources.into_iter().next().ok_or("source absent")?;
        let query = QueryOwner::new(data.clone(), QueryLimits::default())?;
        let plan = QueryPlan::new(
            AnalysisSelectionV1::new(source.tenant_id, vec![source.clone()]),
            QueryTemplate::OperationCounts,
        )?;
        let queried = query.query_at(&plan, now)?;
        ensure!(
            queried.rows == [vec![Value::UInt(1), Value::BigInt(2)]],
            InvalidInputSnafu {
                path: output,
                reason: "discovery blocked or changed the raw evidence query",
            }
        );
        let (request, access) = ObservabilityQualification::trace_inputs(
            facts.into_iter().next().ok_or("workload fact absent")?,
            now,
        )?;
        control.accept_trace(request.clone(), access.clone())?;
        let dispatch = connection
            .exchange_diagnostics(&TraceExchangeV1::default())
            .await?
            .dispatch
            .ok_or("trace dispatch absent")?;
        let execution = dispatch.accepted.execution_id(0)?;
        let frame = TraceFrameV1 {
            execution_id: execution,
            sequence: 1,
            kind: TraceFrameKindV1::Data,
            bytes: b"external output fixture\n".to_vec(),
        };
        let uploaded = connection
            .exchange_diagnostics(&TraceExchangeV1 {
                retained: vec![execution],
                resolved: None,
                output: Some(TraceUploadV1 {
                    request_id: request.request_id,
                    target_index: 0,
                    original_node_boot_id: boot,
                    batch: TraceBatchV1 {
                        execution_id: execution,
                        frames: vec![frame.clone()],
                        terminal: None,
                    },
                }),
            })
            .await?;
        let output_batches = TraceOwner::new(data.clone()).output(
            source.tenant_id,
            request.request_id,
            0,
            &access,
            now,
            0,
        )?;
        ensure!(
            uploaded
                .acknowledgement
                .is_some_and(|ack| ack.last_sequence == 1)
                && output_batches.len() == 1
                && output_batches[0].frames == [frame],
            InvalidInputSnafu {
                path: output,
                reason: "discovery blocked trace acceptance, output, or acknowledgement",
            }
        );
        let updated = fixture.resource(2)?;
        let updated = fixture.owner.reconcile(
            &updated,
            OUTAGE_NAMESPACE_UID,
            &fixture.inventory(&updated)?,
            i64::try_from(now + 1)?,
        )?;
        ensure!(
            updated.source_revision.policy_source_revision_id
                != initial.source_revision.policy_source_revision_id
                && !updated.bundles.is_empty()
                && store
                    .policy_document(&updated.source_revision.policy_source_revision_id)?
                    .is_some()
                && store
                    .policy_document(&initial.source_revision.policy_source_revision_id)?
                    .as_ref()
                    == Some(&initial_policy),
            InvalidInputSnafu {
                path: output,
                reason: "discovery blocked native policy work or changed retained authority"
            }
        );
        let prior = if let Some(owner) = &parts.discovery {
            let profile = owner
                .profile(&source)?
                .ok_or("lagged discovery profile absent")?;
            ensure!(
                profile.snapshot.accepted_records == 1
                    && data
                        .processor_health(&profile.scope)?
                        .is_some_and(|health| health.cursor_lag == 1),
                InvalidInputSnafu {
                    path: output,
                    reason: "the paused owner did not retain its exact cursor lag"
                }
            );
            Some(profile)
        } else {
            None
        };
        ensure!(
            data.source_receipt(&source)?
                .is_some_and(|receipt| receipt.contiguous_cursor == 2)
                && observations.pending_evidence_records() == 0,
            InvalidInputSnafu {
                path: output,
                reason: "optional discovery changed durable intake progress",
            }
        );
        let retained_at = now + 1;
        let retained = EvidenceRetentionOwner::new(&data).retain(&source, retained_at)?;
        ensure!(
            retained.removed_records == 2 && retained.retained_floor == 2,
            InvalidInputSnafu {
                path: output,
                reason: "optional discovery prevented raw evidence retention",
            }
        );
        if let (Some(owner), Some(profile)) = (&parts.discovery, &prior) {
            ensure!(
                owner.profile(&source)?.as_ref() == Some(profile)
                    && data
                        .read_result(source.tenant_id, &profile.profile_id)?
                        .is_some()
                    && matches!(
                        owner.replay(profile)?,
                        DiscoveryReplayV1::Unavailable { .. }
                    ),
                InvalidInputSnafu {
                    path: output,
                    reason: "raw expiry changed retained counts or invented replay input",
                }
            );
        }
        accept_record(output, &observations, &mut connection, 3).await?;
        let resumed_at = u64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos())?;
        ensure!(
            query.query_at(&plan, resumed_at)?.rows == [vec![Value::UInt(1), Value::BigInt(1)]]
                && TraceOwner::new(data.clone()).output(
                    source.tenant_id,
                    request.request_id,
                    0,
                    &access,
                    resumed_at,
                    0,
                )? == output_batches
                && data
                    .source_receipt(&source)?
                    .is_some_and(|receipt| receipt.contiguous_cursor == 3)
                && observations.pending_evidence_records() == 0,
            InvalidInputSnafu {
                path: output,
                reason: "raw expiry blocked intake, query, or retained trace output",
            }
        );
        if let Some(owner) = &parts.discovery {
            ensure!(
                owner.process(resumed_at)? == 1,
                InvalidInputSnafu {
                    path: output,
                    reason: "discovery did not resume after raw expiry",
                }
            );
            let resumed = owner.profile(&source)?.ok_or("resumed profile absent")?;
            ensure!(
                resumed.incomplete
                    && resumed.snapshot.accepted_records == 2
                    && resumed.gaps.len() == 1
                    && resumed.gaps[0].first_cursor == 2
                    && resumed.gaps[0].last_cursor == 2
                    && data
                        .processor_health(&resumed.scope)?
                        .is_some_and(|health| health.consumed_cursor == 3 && health.incomplete),
                InvalidInputSnafu {
                    path: output,
                    reason: "resumption lost retained counts or omitted the expired cursor gap",
                }
            );
        }
        let trace = TraceOwner::new(data.clone())
            .read(source.tenant_id, request.request_id, &access, resumed_at)?
            .1
            .binding(0)?
            .identity;
        let diagnostic = EvidenceRetentionOwner::new(&data).retain_trace(&trace, retained_at)?;
        ensure!(
            diagnostic.removed_records == 1
                && diagnostic.retained_floor == 1
                && matches!(
                    data.read_trace(&trace, 1, &araphor_data::AnalysisReadControl::default()),
                    Err(araphor_data::Error::RetainedRangeExpired {
                        first_cursor: 1,
                        last_cursor: 1,
                        ..
                    })
                ),
            InvalidInputSnafu {
                path: output,
                reason: "diagnostic retention did not expire its frame at the configured age",
            }
        );
        cases.push(serde_json::json!({
            "state": if enabled { "lagged" } else { "disabled" }, "result": "PASS",
            "accepted_cursor": 3, "queried_before_retention": 2,
            "queried_after_retention": 1, "trace_output_sequence": 1,
            "retention_removed_records": retained.removed_records,
            "diagnostic_removed_records": diagnostic.removed_records,
            "intake_utc_ns": now, "expiry_utc_ns": retained_at,
            "discovery_consumed_before": enabled.then_some(1),
            "discovery_consumed_after": enabled.then_some(3),
            "profile_count_before": enabled.then_some(1),
            "profile_count_after": enabled.then_some(2),
            "profile_incomplete": enabled.then_some(true),
            "expired_gap": enabled.then_some([2, 2]),
            "frozen_replay_unavailable": enabled,
            "policy_source_before": initial.source_revision.policy_source_revision_id,
            "policy_source_after": updated.source_revision.policy_source_revision_id,
        }));
        drop(connection);
        server.shutdown().await?;
    }
    fs::create_dir(output)?;
    super::write_json(
        &output.join("result.json"),
        &serde_json::json!({
            "schema_version": 1, "case": "owner-isolation", "result": "PASS",
            "qualification": "LIGHTWEIGHT", "cases": cases,
            "physical_action_attempted": false, "performance_claim": false,
        "proof_boundary": "Production Control configuration, mTLS intake, query, trace output, and native policy reconciliation operate with discovery disabled or one cursor behind. Explicit retention removes two raw records without changing the retained count. Intake, query, and trace output continue. Discovery resumes with an expired cursor gap and an incomplete profile. Synthetic kernel records, workload inventory, trace grant, and trace bytes are fixtures. This case does not qualify physical enforcement or performance.",
        }),
    )?;
    Ok(())
}

async fn accept_record(
    output: &Path,
    observations: &EffectObservationStore,
    connection: &mut ControlConnection,
    cursor: u64,
) -> Result<(), Box<dyn StdError>> {
    observations.record_bytes(
        erebor_interceptor_abi::EffectObservationV1 {
            observed_boottime_ns: cursor,
            source_sequence: cursor,
            source_cpu_id: 3,
            task_cookie: 7,
            reason: 9,
            physical_result: 1,
            effect_family: 1,
            operation: 1,
            ..Default::default()
        }
        .as_bytes(),
    );
    connection
        .send_evidence_batch(observations.next_evidence_batch().ok_or("batch absent")?)
        .await?;
    let ack = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            if let NodeControlMessage::EvidenceAck(ack) = connection.next_message().await? {
                return Ok::<_, mithril_node::Error>(ack);
            }
        }
    })
    .await??;
    ensure!(
        ack.contiguous_cursor == cursor,
        InvalidInputSnafu {
            path: output,
            reason: "discovery blocked the durable evidence acknowledgement",
        }
    );
    observations.acknowledge_evidence(ack)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    #[tokio::test]
    async fn discovery_owner_service_isolation() -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let output = directory.path().join("proof");
        super::run(&output).await?;
        let before = std::fs::read(output.join("result.json"))?;
        assert!(super::run(&output).await.is_err());
        assert_eq!(std::fs::read(output.join("result.json"))?, before);
        Ok(())
    }
}
