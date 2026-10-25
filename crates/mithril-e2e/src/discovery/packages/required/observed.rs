use std::{collections::BTreeMap, time::Duration};

use araphor_analysis_sdk::wire;
use araphor_data::{
    AnalysisProcessorResultV1, AnalysisReadControl, AnalysisSelectionV1, AnalysisStore,
    EvidenceIntakeIdentityV1, FindingStateV1, GraphPhysicalResultV1, GraphSnapshotV1,
    ManagedGraphOperation, ManagedOutput, ManagedReceipt, NotificationFailureV1,
    NotificationGrantV1, NotificationObligationV1, NotificationSinkResultV1, PackageErrorCodeV1,
    PackageReadinessV1, ProcessorClassV1, ProcessorScopeV1, ProcessorStateV1, ResultContext,
    GRAPH_PROCESSOR, GRAPH_SCHEMA_VERSION,
};

use super::super::*;
use super::input::now;

pub(super) fn store(fixture: &Fixture) -> Result<Arc<AnalysisStore>> {
    fixture
        .control
        .analysis_store()
        .ok_or_else(|| "required data".into())
}

pub(super) struct Saved {
    pub(super) source: EvidenceIntakeIdentityV1,
    graph: GraphSnapshotV1,
    head: AnalysisProcessorResultV1,
    receipt: ManagedReceipt,
    outputs: BTreeMap<u64, (ResultContext, wire::Output)>,
    obligation: NotificationObligationV1,
}

fn scope(source: &EvidenceIntakeIdentityV1) -> ProcessorScopeV1 {
    ProcessorScopeV1 {
        processor_id: GRAPH_PROCESSOR.into(),
        method_version: u64::from(GRAPH_SCHEMA_VERSION),
        identity: source.clone(),
    }
}

fn outputs(
    fixture: &Fixture,
    tenant: [u8; 16],
    receipt: &ManagedReceipt,
) -> Result<BTreeMap<u64, (ResultContext, wire::Output)>> {
    let data = fixture
        .control
        .analysis_store()
        .ok_or("required output data")?;
    let control = AnalysisReadControl::default();
    let instance = data
        .managed_instance(tenant, &receipt.instance, &control)?
        .ok_or("required output instance")?;
    receipt
        .results
        .iter()
        .map(|(call, reference)| {
            let ManagedOutput::Call { result, .. } =
                data.managed_output(&instance, &reference.result_id, now()?, &control)?
            else {
                return Err("required call output".into());
            };
            Ok((*call, (result.context, result.output)))
        })
        .collect()
}

impl Saved {
    pub(super) async fn initial(
        fixture: &Fixture,
        source: EvidenceIntakeIdentityV1,
        grant: &NotificationGrantV1,
    ) -> Result<Self> {
        let tenant = source.tenant_id;
        let data = fixture
            .control
            .analysis_store()
            .ok_or("initial required data")?;
        let owner = fixture
            .control
            .notification_owner()
            .ok_or("required Router")?;
        let (graph, obligation) = fixture
            .observe(Duration::from_secs(90), |data| {
                let Some(graph) = data.graph_snapshot(&source)? else {
                    return Ok(None);
                };
                if graph.last_cursor != 2
                    || !graph.findings.iter().any(|finding| {
                        finding.package_id == "HF-PROC-001"
                            && finding.state == FindingStateV1::Confirmed
                    })
                {
                    return Ok(None);
                }
                let Some(head) = data.processor_result(&scope(&source))? else {
                    return Ok(None);
                };
                let obligation = owner
                    .router()
                    .obligations(grant, now()?)?
                    .into_iter()
                    .find(|item| {
                        item.finding.as_ref().is_some_and(|finding| {
                            finding.result_id == head.result_id
                                && graph
                                    .findings
                                    .iter()
                                    .any(|value| value.finding_id == finding.finding_id)
                        }) && item.attempts.iter().any(|attempt| {
                            attempt.finding_revision == item.finding_revision
                                && attempt.result.is_some()
                        }) && item.attempts.len() >= 2
                            && item.attempts.iter().all(|attempt| attempt.result.is_some())
                    });
                Ok(obligation.map(|obligation| (graph, obligation)))
            })
            .await
            .map_err(|error| {
                let readiness = [
                    ManagedGraphOperation::Evaluate.instance_id(&source),
                    ManagedGraphOperation::Expire.instance_id(&source),
                    "notifications".into(),
                ].into_iter().map(|id| {
                    let status = data.managed_status(&AnalysisSelectionV1::tenant(tenant), &id, &Default::default()).map(|status| (status.readiness, status.instance.progress));
                    (id, status)
                }).collect::<Vec<_>>();
                let graph = data.graph_snapshot(&source).map(|graph| graph.map(|graph| (
                    graph.last_cursor,
                    graph.findings.into_iter().map(|finding| (finding.package_id, finding.state)).collect::<Vec<_>>(),
                    graph.packages.into_iter().map(|package| (package.package_id, package.state)).collect::<Vec<_>>(),
                )));
                let obligations = now().and_then(|at| Ok(owner.router().obligations(grant, at)?)).map(|items| items.into_iter().map(|item| (item.finding, item.finding_revision, item.attempts.len(), item.deadline_utc_ns)).collect::<Vec<_>>());
                format!("initial required publication: {error}; readiness={readiness:?}; graph={graph:?}; obligations={obligations:?}")
            })?;
        assert_eq!(graph.findings.len(), 1);
        let finding = &graph.findings[0];
        assert_eq!(finding.package_id, "HF-PROC-001");
        assert_eq!(finding.state, FindingStateV1::Confirmed);
        assert_eq!(finding.effects.len(), 1);
        assert_eq!(finding.effects[0].evidence.durable_cursor, 1);
        assert_eq!(
            finding.effects[0].physical_result,
            GraphPhysicalResultV1::Prevented
        );
        assert!(obligation.first_seen_utc_ns > 0);
        assert!(obligation
            .deadline_utc_ns
            .is_some_and(|deadline| deadline > obligation.first_seen_utc_ns));
        assert!(obligation.attempts.iter().all(|attempt| attempt.result
            == Some(NotificationSinkResultV1::Failed {
                reason: NotificationFailureV1::SinkUnavailable
            })));
        let data = fixture
            .control
            .analysis_store()
            .ok_or("required saved data")?;
        let health = data
            .processor_health(&scope(&source))?
            .ok_or("required initial health")?;
        assert_eq!(health.class, ProcessorClassV1::Required);
        assert_eq!(health.consumed_cursor, 2);
        let id = ManagedGraphOperation::Evaluate.instance_id(&source);
        let head = data
            .processor_result(&scope(&source))?
            .ok_or("initial Graph head")?;
        let history = data.managed_history(
            &AnalysisSelectionV1::tenant(tenant),
            &id,
            &Default::default(),
        )?;
        let receipt = history
            .iter()
            .find(|receipt| receipt.commit_revision == head.commit_revision)
            .ok_or("initial atomic Graph receipt")?
            .clone();
        assert_eq!(receipt.results.len(), 3);
        assert!(receipt
            .results
            .values()
            .all(|reference| reference.commit_revision == head.commit_revision));
        assert_eq!(receipt.selected.commit_revision, receipt.commit_revision);
        let saved = outputs(fixture, tenant, &receipt)?;
        assert_eq!(saved.len(), 3);
        assert!(saved
            .values()
            .all(|(context, _)| context.target == "wasm" && context.artifact.is_some()));
        assert!(saved.values().all(|(_, output)| output
            .checkpoint
            .as_ref()
            .is_some_and(|checkpoint| checkpoint.version == 1)));
        Ok(Self {
            source,
            graph,
            head,
            receipt,
            outputs: saved,
            obligation,
        })
    }

    pub(super) async fn failed(
        &self,
        fixture: &Fixture,
        blocked: &EvidenceIntakeIdentityV1,
    ) -> Result<()> {
        let tenant = self.source.tenant_id;
        let id = ManagedGraphOperation::Evaluate.instance_id(blocked);
        let (health, status) = fixture
            .observe(Duration::from_secs(90), |data| {
                let Some(_) = data.managed_instance(tenant, &id, &Default::default())? else {
                    return Ok(None);
                };
                let status = match data.managed_status(
                    &AnalysisSelectionV1::tenant(tenant),
                    &id,
                    &Default::default(),
                ) {
                    Ok(status) => status,
                    Err(araphor_data::Error::Package {
                        code: PackageErrorCodeV1::Incomplete,
                        field: "managed pending attempt",
                        ..
                    }) => return Ok(None),
                    Err(error) => return Err(error.into()),
                };
                if !matches!(
                    status.readiness,
                    PackageReadinessV1::Failed {
                        code: PackageErrorCodeV1::Limit,
                        ..
                    }
                ) {
                    return Ok(None);
                }
                let health = data
                    .processor_health(&scope(blocked))?
                    .ok_or("failed required health")?;
                Ok(Some((health, status)))
            })
            .await?;
        assert_eq!(health.class, ProcessorClassV1::Required);
        assert_eq!(health.state, ProcessorStateV1::ProcessingFailed);
        assert_eq!(health.accepted_cursor, 2);
        assert_eq!(health.consumed_cursor, 0);
        assert_eq!(health.cursor_lag, 2);
        assert!(health.incomplete);
        assert_eq!(status.instance.progress, 0);
        let data = fixture
            .control
            .analysis_store()
            .ok_or("failed required data")?;
        assert!(data
            .managed_history(
                &AnalysisSelectionV1::tenant(tenant),
                &id,
                &Default::default()
            )?
            .is_empty());
        assert!(data.graph_snapshot(blocked)?.is_none());
        assert_eq!(
            data.graph_result(tenant, &self.head.result_id)?,
            Some(self.graph.clone())
        );
        assert_eq!(outputs(fixture, tenant, &self.receipt)?, self.outputs);
        Ok(())
    }

    pub(super) async fn recovered(
        &self,
        fixture: &Fixture,
        blocked: &EvidenceIntakeIdentityV1,
        frames: &[u8],
        grant: &NotificationGrantV1,
    ) -> Result<()> {
        let tenant = self.source.tenant_id;
        let graph = fixture
            .observe(Duration::from_secs(90), |data| {
                Ok(data
                    .graph_snapshot(blocked)?
                    .filter(|graph| graph.last_cursor == 3))
            })
            .await?;
        assert_eq!(graph.input_manifest.evidence.len(), 3);
        assert_eq!(
            graph
                .input_positions
                .iter()
                .map(|(record, _)| record.durable_cursor)
                .collect::<Vec<_>>(),
            [1, 2, 3]
        );
        assert!(graph
            .findings
            .iter()
            .any(|finding| finding.package_id == "HF-PROC-001"
                && finding
                    .effects
                    .iter()
                    .any(|effect| effect.evidence.durable_cursor == 1)));
        assert!(!graph
            .findings
            .iter()
            .flat_map(|finding| &finding.effects)
            .any(|effect| [2, 3].contains(&effect.evidence.durable_cursor)));
        let data = fixture
            .control
            .analysis_store()
            .ok_or("repaired required data")?;
        let health = data
            .processor_health(&scope(blocked))?
            .ok_or("repaired required health")?;
        assert_eq!(health.class, ProcessorClassV1::Required);
        assert_eq!(health.state, ProcessorStateV1::Current);
        assert_eq!(health.consumed_cursor, 3);
        assert_eq!(health.cursor_lag, 0);
        assert!(!health.incomplete);
        let id = ManagedGraphOperation::Evaluate.instance_id(blocked);
        let repaired = data
            .processor_result(&scope(blocked))?
            .ok_or("repaired Graph head")?;
        let history = data.managed_history(
            &AnalysisSelectionV1::tenant(tenant),
            &id,
            &Default::default(),
        )?;
        let committed = history
            .iter()
            .find(|receipt| receipt.commit_revision == repaired.commit_revision)
            .ok_or("repaired atomic receipt")?;
        assert_eq!(committed.results.len(), 3);
        assert!(committed
            .results
            .values()
            .all(|reference| reference.commit_revision == repaired.commit_revision));
        assert_eq!(
            committed.selected.commit_revision,
            committed.commit_revision
        );
        assert!(outputs(fixture, tenant, committed)?
            .values()
            .all(|(_, output)| output.checkpoint.is_some()));
        assert_eq!(
            data.graph_result(tenant, &self.head.result_id)?,
            Some(self.graph.clone())
        );
        assert_eq!(outputs(fixture, tenant, &self.receipt)?, self.outputs);
        assert!(data
            .managed_history(
                &AnalysisSelectionV1::tenant(tenant),
                &self.receipt.instance,
                &Default::default()
            )?
            .contains(&self.receipt));
        assert!(data
            .processor_health(&scope(&self.source))?
            .is_some_and(|health| health.consumed_cursor >= 2));
        let retained = data.read_page(blocked, 1)?;
        assert_eq!(
            retained
                .records
                .iter()
                .take(2)
                .flat_map(|record| record.framed_record.iter().copied())
                .collect::<Vec<_>>(),
            frames
        );
        let state = fixture
            .control
            .notification_owner()
            .ok_or("repaired Router")?
            .router()
            .obligations(grant, now()?)?
            .into_iter()
            .find(|item| item.key == self.obligation.key)
            .ok_or("repaired required obligation")?;
        assert_eq!(state.first_seen_utc_ns, self.obligation.first_seen_utc_ns);
        assert_eq!(state.deadline_utc_ns, self.obligation.deadline_utc_ns);
        assert!(state.human_acknowledgement.is_none());
        Ok(())
    }

    pub(super) fn retained(
        &self,
        fixture: &Fixture,
        blocked: &EvidenceIntakeIdentityV1,
        frames: &[u8],
        grant: &NotificationGrantV1,
    ) -> Result<()> {
        let data = store(fixture)?;
        let retained = data.read_page(blocked, 1)?;
        assert_eq!(retained.records.len(), 2);
        assert_eq!(
            retained
                .records
                .iter()
                .flat_map(|record| record.framed_record.iter().copied())
                .collect::<Vec<_>>(),
            frames
        );
        let state = fixture
            .control
            .notification_owner()
            .ok_or("failed required Router")?
            .router()
            .obligations(grant, now()?)?
            .into_iter()
            .find(|item| item.key == self.obligation.key)
            .ok_or("preserved required obligation")?;
        assert_eq!(state.first_seen_utc_ns, self.obligation.first_seen_utc_ns);
        assert_eq!(state.deadline_utc_ns, self.obligation.deadline_utc_ns);
        assert!(state.human_acknowledgement.is_none());
        Ok(())
    }
}
