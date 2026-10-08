use super::*;

use std::{cell::RefCell, env};

use crate::error::InvalidInputSnafu;
use crate::physical::wait_for;
use crate::platform::{test_lifecycle, Kubernetes, Platform, TestResult};

#[test]
#[ignore = "needs the isolated Kubernetes incident harness"]
fn graph_notification_incident() -> TestResult<()> {
    test_lifecycle::<Kubernetes, _>("graph-notification", || {
        let output = PathBuf::from(env::var("MITHRIL_GRAPH_NOTIFICATION_OUTPUT")?);
        let expected = fs::read(env::var("MITHRIL_GRAPH_NOTIFICATION_EXPECTED")?)?;
        GraphNotificationQualification::new(output).physical(&serde_json::from_slice(&expected)?)
    })
}

impl GraphNotificationQualification {
    fn physical(&self, expected: &serde_json::Value) -> TestResult<()> {
        if !self.output.is_absolute() || self.output.exists() {
            return Err("the physical output must be a new absolute directory".into());
        }
        assert_eq!(expected["result"], "PASS");
        assert_eq!(expected["qualification"], "LIGHTWEIGHT");
        let contracts = expected["acceptance"]["local_contract"]
            .as_array()
            .ok_or("the lightweight local contracts are absent")?;
        fs::create_dir(&self.output)?;
        let mut env = Kubernetes::setup("graph-notification")?;
        env.start_control()?;
        env.start_node()?;
        let labels = env.install_policy("multi_policy_deny.json")?;
        env.node_ready()?;
        let mut actor = env.start_actor("read_path.py", &[], &labels)?;
        let work = env.work().to_owned();
        actor.send(b"/fixtures/policy_replace.py\n")?;
        let denied: (i32, usize) =
            serde_json::from_str(&actor.wait_text(&work.join("0.json"), "protected file read")?)?;
        assert_eq!(denied, (libc::EACCES, 0));
        actor.send(b"/fixtures/read_path.py\n")?;
        let allowed: (i32, usize) =
            serde_json::from_str(&actor.wait_text(&work.join("1.json"), "benign file read")?)?;
        assert_eq!(allowed.0, 0);
        assert!(allowed.1 > 0);
        actor.ensure_running("file read controls")?;
        let task = env.task(actor.id(), "file read actor")?;
        let pin = env.maps().0.to_owned();
        let last = RefCell::new(String::new());
        let observed = wait_for(
            &pin,
            "accepted file read evidence",
            Duration::from_secs(30),
            || {
                let snapshot = env.snapshot().map_err(|source| {
                    InvalidInputSnafu {
                        path: &pin,
                        reason: source.to_string(),
                    }
                    .build()
                })?;
                *last.borrow_mut() = format!(
                    "pending={}; recent={}",
                    snapshot.pending_evidence_records,
                    snapshot.recent_effects.len()
                );
                let file = KernelEffectFamilyV1::File;
                let read = KernelEffectOperationV1::OpenRead;
                let denied = snapshot.recent_effects.iter().find(|event| {
                    task.matches_effect(event, "EXACT_POLICY_DENY", file, read, -libc::EACCES)
                });
                let allowed = snapshot.recent_effects.iter().rev().find(|event| {
                    task.matches_effect(event, "APPLICATION_DEFAULT_ALLOW", file, read, 0)
                });
                Ok(match (denied, allowed) {
                    (Some(denied), Some(allowed)) if snapshot.pending_evidence_records == 0 => {
                        Some((denied.clone(), allowed.clone()))
                    }
                    _ => None,
                })
            },
            || last.borrow().clone(),
        )?;
        actor.stop()?;
        wait_for(
            &pin,
            "final evidence ACK",
            Duration::from_secs(30),
            || {
                let state = env.snapshot().map_err(|source| {
                    InvalidInputSnafu {
                        path: &pin,
                        reason: source.to_string(),
                    }
                    .build()
                })?;
                Ok((state.pending_evidence_records == 0).then_some(()))
            },
            || "Node still has unacknowledged evidence".into(),
        )?;
        env.stop_node()?;
        let (store_root, data_root) = env.graph_store()?;
        let store = ControlStore::open(&store_root)?;
        let data = Arc::new(AnalysisStore::open(&data_root)?);
        let tenant = EvidenceIdV1::new(1, 2).to_be_bytes();
        let denied_record = Self::physical_record(&data, tenant, &observed.0)?;
        let allowed_record = Self::physical_record(&data, tenant, &observed.1)?;
        let digests = [&denied_record.id, &allowed_record.id]
            .into_iter()
            .map(|id| {
                let accepted = data.read_page(&id.stream, id.durable_cursor)?;
                let accepted = accepted.records.first().ok_or("accepted frame absent")?;
                if accepted.cursor != id.durable_cursor {
                    return Err("accepted frame cursor differs".into());
                }
                Ok(crate::DigestV1::of(&accepted.framed_record).to_string())
            })
            .collect::<TestResult<Vec<_>>>()?;
        let now = u64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos())?;
        let graph = GraphAndFindingOwner::new(data.clone(), Arc::new(store.clone()))?;
        let mut consumed = false;
        for _ in 0..1024 {
            graph.process(now)?;
            consumed = true;
            for record in [&denied_record, &allowed_record] {
                let scope = ProcessorScopeV1 {
                    processor_id: GRAPH_PROCESSOR.into(),
                    method_version: u64::from(GRAPH_SCHEMA_VERSION),
                    identity: record.id.stream.clone(),
                };
                consumed &= data
                    .processor_health(&scope)?
                    .is_some_and(|health| health.consumed_cursor >= record.id.durable_cursor);
            }
            if consumed {
                break;
            }
        }
        assert!(consumed, "graph did not consume both incident records");
        let mut after = None;
        let mut selected = None;
        let mut finding_count = 0;
        while let Some((result_id, finding)) =
            graph.next_current_finding(tenant, after.as_deref())?
        {
            finding_count += 1;
            assert!(!finding
                .effects
                .iter()
                .any(|effect| effect.evidence == allowed_record.id));
            after = Some(finding.finding_id.clone());
            if finding.package_id == "HF-PROC-001"
                && finding
                    .effects
                    .iter()
                    .any(|effect| effect.evidence == denied_record.id)
            {
                assert!(selected.is_none());
                selected = Some((result_id, finding));
            }
        }
        let (result_id, finding) = selected.ok_or("the physical denial finding is absent")?;
        let decision = Self::decision(&finding);
        super::super::write_json(&self.output.join("observed-graph-decision.json"), &decision)?;
        let paired = contracts
            .iter()
            .find(|contract| contract["decision"] == decision)
            .ok_or("the physical graph decision has no matching lightweight input condition")?;
        assert_eq!(
            finding.effects[0].physical_result,
            GraphPhysicalResultV1::Prevented
        );
        let snapshot = graph
            .snapshot_result(tenant, &result_id)?
            .ok_or("physical graph absent")?;
        assert_eq!(snapshot.input_manifest, finding.revision);
        assert!(snapshot.findings.contains(&finding));
        super::super::write_json(
            &self.output.join("observed-graph-input.json"),
            &json!({
                "graph_result_id": result_id, "finding_id": finding.finding_id,
                "finding_revision": finding.revision,
                "current_findings": finding_count, "graph_decision": decision,
                "source_coverage": snapshot.input_manifest.coverage,
                "accepted_denied_record": denied_record.id,
                "accepted_allowed_record": allowed_record.id, "evidence_digests": digests,
                "original_volume_used": true, "pending_evidence_records": 0,
            }),
        )?;
        Self::check_replay(
            &Self::replay(&data, &denied_record.id.stream, &snapshot)?,
            &snapshot,
        )?;
        let mut notification = Self::notify(&store, data.clone(), &graph, &finding, now)?;
        drop(graph);
        drop(data);
        drop(store);
        let store = ControlStore::open(&store_root)?;
        let data = Arc::new(AnalysisStore::open(&data_root)?);
        let graph = GraphAndFindingOwner::new(data.clone(), Arc::new(store.clone()))?;
        assert_eq!(
            graph.snapshot_result(tenant, &result_id)?,
            Some(snapshot.clone())
        );
        Self::resume(&store, &data, &graph, &finding, now, &mut notification)?;
        assert_eq!(
            notification["transitions"],
            expected["notification"]["transitions"]
        );
        super::super::write_json(&self.output.join("graph.json"), &snapshot)?;
        super::super::write_json(
            &self.output.join("result.json"),
            &json!({
                "schema_version": 1, "case": "graph-notification", "result": "PASS",
                "qualification": "KUBERNETES", "paired_input": paired["input"],
                "graph_result_id": result_id,
                "current_findings": finding_count,
                "graph_decision": decision, "graph_revision": snapshot.input_manifest,
                "finding_id": finding.finding_id, "finding_revision": finding.revision,
                "source_coverage": snapshot.input_manifest.coverage, "notification": notification,
                "accepted_denied_record": denied_record.id, "accepted_allowed_record": allowed_record.id,
                "evidence_digests": digests,
                "physical_controls": {"actor": "read_path.py", "policy": "multi_policy_deny.json",
                    "denied_path": "/fixtures/policy_replace.py", "denied_errno": denied.0,
                    "denied_bytes": denied.1, "allowed_path": "/fixtures/read_path.py",
                    "allowed_errno": allowed.0, "allowed_bytes": allowed.1},
                "control_store_reopened": true, "original_volume_used": true,
                "canonical_replay_equal": true, "pending_evidence_records": 0,
                "cross_node_qualified": false, "provider_issuance_qualified": false,
                "full_hugging_face_incident_reproduced": false, "performance_claim": false,
                "proof_boundary": "One protected file-open denial and one benign read use the real kernel, Node WAL, mTLS intake, Control context, graph, and notification owners. HDF5, Jinja, projected-token semantics, controller operations, remote payload, and cloud effects remain unqualified.",
            }),
        )?;
        drop(graph);
        drop(data);
        drop(store);
        env.stop()
    }

    fn physical_record(
        data: &AnalysisStore,
        tenant: [u8; 16],
        event: &erebor_runtime_ipc::v1::MithrilEffectObservation,
    ) -> TestResult<DiscoveryRecordV1> {
        let mut after = None;
        loop {
            let sources = data.source_page(tenant, after.as_ref())?;
            if sources.is_empty() {
                return Err("the physical event has no accepted evidence record".into());
            }
            after = sources.last().cloned();
            for source in sources {
                let receipt = data
                    .source_receipt(&source)?
                    .ok_or("source receipt absent")?;
                if receipt.cpu_id != event.source_cpu_id {
                    continue;
                }
                let mut cursor = receipt.retained_floor + 1;
                while cursor <= receipt.contiguous_cursor {
                    let page = data.read_page(&source, cursor)?;
                    if page.records.is_empty() {
                        return Err("the physical retained range has a gap".into());
                    }
                    for accepted in page.records {
                        cursor = accepted.cursor.checked_add(1).ok_or("cursor overflow")?;
                        let wire = EvidenceRecord::try_from(accepted.framed_record.as_slice())?;
                        if wire.task_cookie == event.task_cookie
                            && wire.effect_family == event.effect_family
                            && wire.operation == event.operation
                            && wire.reason == event.reason_code
                            && wire.kernel_result == event.kernel_result
                            && wire.decision_context.as_ref().is_some_and(|context| {
                                context.original_kernel_sequence == event.source_sequence
                            })
                        {
                            return Ok(DiscoveryRecordV1::try_from((
                                &source,
                                receipt.cpu_id,
                                &accepted,
                            ))?);
                        }
                    }
                }
            }
        }
    }
}
