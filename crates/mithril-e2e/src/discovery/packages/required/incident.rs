use std::{collections::BTreeMap, time::Duration};

use araphor_data::{
    DiscoveryCoverageStateV1, DiscoveryRecordIdV1, DiscoveryRecordV1, EvidenceIntakeIdentityV1,
    FindingStateV1, FindingV1, GraphPhysicalResultV1, GraphSnapshotV1, NotificationAttemptV1,
    NotificationFailureV1, NotificationSinkResultV1, PolicyProvenanceStateV1,
};
use erebor_interceptor_abi::{
    EffectObservationReasonV1, KernelEffectFamilyV1, KernelEffectOperationV1,
};
use erebor_runtime_client::AraphorClient;
use erebor_runtime_ipc::araphor::{self as wire, query_frame::Payload, query_value::Kind};
use serde::Serialize;
use serde_json::json;

use super::Result;

mod input;
mod lightweight;

pub(super) struct Incident {
    streams: [tonic::Streaming<wire::QueryFrame>; 3],
    records: BTreeMap<DiscoveryRecordIdV1, DiscoveryRecordV1>,
    graphs: BTreeMap<EvidenceIntakeIdentityV1, (String, GraphSnapshotV1)>,
    notices: BTreeMap<String, Notice>,
    complete: [bool; 3],
}

#[derive(Clone, Serialize)]
struct Notice {
    finding_id: String,
    result_id: String,
    first_seen: u64,
    deadline: u64,
    acknowledged: bool,
    failure: String,
    attempts: Vec<NotificationAttemptV1>,
}

#[derive(Serialize)]
pub(super) struct Observed {
    pub(super) records: [DiscoveryRecordV1; 2],
    graphs: Vec<(String, GraphSnapshotV1)>,
    notice: Notice,
    pub(super) decision: serde_json::Value,
}

impl Incident {
    pub(super) async fn subscribe(client: &AraphorClient, cookie: u64, since: u64) -> Result<Self> {
        let events = client.query(wire::QueryRequest {
            sql: "SELECT tenant_id, node_id, node_boot_id, label_epoch, source_id, source_epoch, cpu_id, source_cursor, framed_record FROM events WHERE task_cookie = $1 AND observed_boottime_ns >= $2 AND effect_family = $3 AND operation = $4 AND reason IN ($5, $6)".into(),
            parameters: [
                cookie,
                since,
                u64::from(KernelEffectFamilyV1::File as u16),
                u64::from(KernelEffectOperationV1::OpenRead as u16),
                u64::from(EffectObservationReasonV1::ExactPolicyDeny as u8),
                u64::from(EffectObservationReasonV1::ApplicationDefaultAllow as u8),
            ].into_iter().map(|value| wire::QueryValue {
                kind: Some(Kind::Unsigned(value)),
            }).collect(),
            follow: true,
            ..Default::default()
        }).await?;
        let graphs = client
            .query(wire::QueryRequest {
                sql: "SELECT graph_result_id, snapshot FROM graph_manifest".into(),
                follow: true,
                ..Default::default()
            })
            .await?;
        let notices = client.query(wire::QueryRequest {
            sql: "SELECT finding_id, finding_result_id, first_seen_utc_ns, deadline_utc_ns, acknowledged, failure, delivery_attempts FROM notifications WHERE package_id = 'HF-PROC-001' AND route_id = 'primary'".into(),
            follow: true,
            ..Default::default()
        }).await?;
        Ok(Self {
            streams: [events, graphs, notices],
            records: BTreeMap::new(),
            graphs: BTreeMap::new(),
            notices: BTreeMap::new(),
            complete: [false; 3],
        })
    }

    pub(super) async fn wait(mut self) -> Result<Observed> {
        let waited = tokio::time::timeout(Duration::from_secs(90), async {
            loop {
                if let Some(observed) = self.result()? {
                    return Ok(observed);
                }
                let (source, frame) = {
                    let [events, graphs, notices] = &mut self.streams;
                    tokio::select! {
                        frame = events.message() => (0, frame?),
                        frame = graphs.message() => (1, frame?),
                        frame = notices.message() => (2, frame?),
                    }
                };
                let frame = frame.ok_or("incident Follow stream closed")?;
                match frame.payload {
                    Some(Payload::Rows(rows)) => {
                        assert!(!rows.limited);
                        self.complete[source] = false;
                        if frame.operation == wire::QueryOperation::Replace as i32 {
                            match source {
                                0 => self.records.clear(),
                                1 => self.graphs.clear(),
                                2 => self.notices.clear(),
                                _ => unreachable!(),
                            }
                        }
                        for row in rows.rows {
                            self.row(source, row)?;
                        }
                    }
                    Some(Payload::Checkpoint(_)) => self.complete[source] = true,
                    Some(Payload::Error(error)) => {
                        return Err(format!("incident Follow: {error:?}").into())
                    }
                    Some(Payload::Terminal(terminal)) => {
                        return Err(format!("incident Follow terminated: {terminal:?}").into())
                    }
                    _ => {}
                }
            }
        })
        .await;
        let result: Result<Observed> = match waited {
            Ok(result) => result,
            Err(error) => Err(error.into()),
        };
        if result.is_err() {
            eprintln!(
                "incident Follow state={}",
                json!({
                    "complete": self.complete,
                    "records": self.records.keys().take(8).collect::<Vec<_>>(),
                    "graphs": self.graphs.values().take(8).map(|(id, graph)| json!({
                        "id": id, "source": graph.scope.identity, "cursor": graph.last_cursor,
                        "coverage": graph.input_manifest.coverage.iter().take(8).collect::<Vec<_>>(),
                        "missing_ranges": graph.missing_ranges.iter().take(8).collect::<Vec<_>>(),
                        "findings": graph.findings.iter().take(8).map(|finding| json!({
                            "id": finding.finding_id, "state": finding.state,
                            "policy": finding.policy_provenance.iter().take(8)
                                .map(|policy| (&policy.state, &policy.limits)).collect::<Vec<_>>(),
                        })).collect::<Vec<_>>(),
                    })).collect::<Vec<_>>(),
                    "notices": self.notices.values().take(8).map(|notice| json!({
                        "finding": notice.finding_id, "result": notice.result_id,
                        "attempts": notice.attempts.len(), "failure": notice.failure,
                        "deadline": notice.deadline,
                    })).collect::<Vec<_>>(),
                })
            );
        }
        result
    }

    fn row(&mut self, source: usize, row: wire::QueryRow) -> Result<()> {
        match source {
            0 => {
                assert_eq!(row.values.len(), 9);
                let bytes = Self::binary(&row, 8)?.to_vec();
                let wire = araphor_data::EvidenceRecord::try_from(bytes.as_slice())?;
                let record = DiscoveryRecordV1 {
                    id: DiscoveryRecordIdV1 {
                        stream: EvidenceIntakeIdentityV1 {
                            tenant_id: Self::binary(&row, 0)?.try_into()?,
                            node_id: Self::text(&row, 1)?.into(),
                            node_boot_id: Self::binary(&row, 2)?.try_into()?,
                            label_epoch: Self::number(&row, 3)?,
                            source_id: Self::binary(&row, 4)?.try_into()?,
                            source_epoch: Self::number(&row, 5)?,
                        },
                        cpu_id: Self::number(&row, 6)?.try_into()?,
                        durable_cursor: Self::number(&row, 7)?,
                    },
                    original_kernel_sequence: wire
                        .decision_context
                        .as_ref()
                        .map(|context| context.original_kernel_sequence),
                    wire_record: bytes,
                };
                record.decode()?;
                if let Some(old) = self.records.insert(record.id.clone(), record.clone()) {
                    assert_eq!(old, record);
                }
            }
            1 => {
                assert_eq!(row.values.len(), 2);
                let graph: GraphSnapshotV1 = serde_json::from_slice(Self::binary(&row, 1)?)?;
                graph.validate()?;
                self.graphs.insert(
                    graph.scope.identity.clone(),
                    (Self::text(&row, 0)?.into(), graph),
                );
            }
            2 => {
                assert_eq!(row.values.len(), 7);
                let Some(Kind::Boolean(acknowledged)) = &row.values[4].kind else {
                    return Err("incident acknowledgement type".into());
                };
                if matches!(row.values[3].kind, Some(Kind::Null(_)))
                    || matches!(row.values[5].kind, Some(Kind::Null(_)))
                {
                    return Ok(());
                }
                let notice = Notice {
                    finding_id: Self::text(&row, 0)?.into(),
                    result_id: Self::text(&row, 1)?.into(),
                    first_seen: Self::number(&row, 2)?,
                    deadline: Self::number(&row, 3)?,
                    acknowledged: *acknowledged,
                    failure: Self::text(&row, 5)?.into(),
                    attempts: serde_json::from_slice(Self::binary(&row, 6)?)?,
                };
                self.notices.insert(notice.finding_id.clone(), notice);
            }
            _ => unreachable!(),
        }
        Ok(())
    }

    fn result(&self) -> Result<Option<Observed>> {
        if !self.complete.into_iter().all(|complete| complete) {
            return Ok(None);
        }
        let (mut denied, mut allowed) = (None, None);
        for record in self.records.values() {
            let wire = record.decode()?;
            if wire.reason == EffectObservationReasonV1::ExactPolicyDeny as u32
                && wire.kernel_result == -libc::EACCES
            {
                assert!(
                    denied.replace(record).is_none(),
                    "multiple protected denials"
                );
            } else if wire.reason == EffectObservationReasonV1::ApplicationDefaultAllow as u32
                && wire.kernel_result == 0
            {
                assert!(allowed.replace(record).is_none(), "multiple benign reads");
            }
        }
        let (Some(denied), Some(allowed)) = (denied, allowed) else {
            return Ok(None);
        };
        let mut graphs = Vec::new();
        for record in [denied, allowed] {
            let Some((id, graph)) = self.graphs.get(&record.id.stream) else {
                return Ok(None);
            };
            let wire = record.decode()?;
            if graph.last_cursor < record.id.durable_cursor
                || !graph.input_manifest.evidence.contains(&record.id)
                || !graph.missing_ranges.is_empty()
                || !graph.input_manifest.coverage.iter().any(|coverage| {
                    coverage.source == record.id.stream
                        && coverage.cpu_id == record.id.cpu_id
                        && coverage.interval_id.as_slice() == wire.coverage_interval_id.as_ref()
                        && matches!(
                            coverage.state,
                            DiscoveryCoverageStateV1::Healthy | DiscoveryCoverageStateV1::Closed
                        )
                        && coverage.gap_reasons.is_empty()
                })
            {
                return Ok(None);
            }
            if !graphs.iter().any(|(key, _)| key == id) {
                graphs.push((id.clone(), graph.clone()));
            }
        }
        assert_eq!(denied.id.stream.tenant_id, allowed.id.stream.tenant_id);
        assert_eq!(denied.id.stream.node_id, allowed.id.stream.node_id);
        assert_eq!(
            denied.id.stream.node_boot_id,
            allowed.id.stream.node_boot_id
        );
        assert_eq!(denied.id.stream.label_epoch, allowed.id.stream.label_epoch);
        assert_eq!(
            denied.id.stream.source_epoch,
            allowed.id.stream.source_epoch
        );
        assert!(self
            .graphs
            .values()
            .all(|(_, graph)| graph.findings.iter().all(|finding| {
                !finding
                    .effects
                    .iter()
                    .any(|effect| effect.evidence == allowed.id)
            })));
        let matched = self
            .graphs
            .values()
            .flat_map(|(id, graph)| graph.findings.iter().map(move |finding| (id, finding)))
            .filter(|(_, finding)| {
                finding.package_id == "HF-PROC-001"
                    && finding
                        .effects
                        .iter()
                        .any(|effect| effect.evidence == denied.id)
            })
            .collect::<Vec<_>>();
        assert!(matched.len() <= 1, "multiple protected findings");
        let Some((id, finding)) = matched.first() else {
            return Ok(None);
        };
        if finding.state != FindingStateV1::Confirmed
            || finding.policy_provenance.is_empty()
            || finding
                .policy_provenance
                .iter()
                .any(|policy| policy.state != PolicyProvenanceStateV1::Exact)
        {
            return Ok(None);
        }
        let Some(notice) = self.notices.get(&finding.finding_id) else {
            return Ok(None);
        };
        if &notice.result_id != *id
            || notice.attempts.len() != 2
            || notice.attempts.iter().any(|attempt| {
                attempt.result
                    != Some(NotificationSinkResultV1::Failed {
                        reason: NotificationFailureV1::SinkUnavailable,
                    })
            })
        {
            return Ok(None);
        }
        assert_eq!(finding.effects.len(), 1);
        assert_eq!(
            finding.effects[0].physical_result,
            GraphPhysicalResultV1::Prevented
        );
        assert!(notice.first_seen > 0 && notice.deadline > notice.first_seen);
        assert!(!notice.acknowledged);
        assert_eq!(notice.failure, "sink_unavailable");
        let denied_wire = denied.decode()?;
        let allowed_wire = allowed.decode()?;
        assert_eq!(denied_wire.task_cookie, allowed_wire.task_cookie);
        let before = denied_wire
            .decision_context
            .as_ref()
            .ok_or("denied decision context")?;
        let after = allowed_wire
            .decision_context
            .as_ref()
            .ok_or("allowed decision context")?;
        assert_eq!(before.process_instance_id, after.process_instance_id);
        assert_eq!(before.entry_instance_id, after.entry_instance_id);
        assert_eq!(before.binding_id, after.binding_id);
        assert_eq!(
            before.profile_generation_ref_id,
            after.profile_generation_ref_id
        );
        Ok(Some(Observed {
            records: [denied.clone(), allowed.clone()],
            decision: Self::decision(finding),
            notice: notice.clone(),
            graphs,
        }))
    }

    fn decision(finding: &FindingV1) -> serde_json::Value {
        json!({
            "package_id": finding.package_id, "state": finding.state, "reason": finding.reason,
            "limits": finding.limits, "severity": finding.severity,
            "required_action": finding.required_action,
            "effects": finding.effects.iter().map(|effect| json!({
                "family": effect.effect_family, "operation": effect.operation,
                "decision": effect.source_decision, "reason": effect.source_reason,
                "configured_errno": effect.configured_errno, "kernel_result": effect.kernel_result,
                "physical_result": effect.physical_result, "proof_quality": effect.proof_quality,
            })).collect::<Vec<_>>(),
            "policy_states": finding.policy_provenance.iter().map(|policy| policy.state).collect::<Vec<_>>(),
            "policy_limits": finding.policy_provenance.iter().map(|policy| &policy.limits).collect::<Vec<_>>(),
        })
    }

    fn text(row: &wire::QueryRow, index: usize) -> Result<&str> {
        match row.values.get(index).and_then(|value| value.kind.as_ref()) {
            Some(Kind::Text(value)) => Ok(value),
            _ => Err("incident text column".into()),
        }
    }

    fn binary(row: &wire::QueryRow, index: usize) -> Result<&[u8]> {
        match row.values.get(index).and_then(|value| value.kind.as_ref()) {
            Some(Kind::Binary(value)) => Ok(value),
            _ => Err("incident binary column".into()),
        }
    }

    fn number(row: &wire::QueryRow, index: usize) -> Result<u64> {
        match row.values.get(index).and_then(|value| value.kind.as_ref()) {
            Some(Kind::Unsigned(value)) => Ok(*value),
            _ => Err("incident number column".into()),
        }
    }
}
