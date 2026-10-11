use crate::analysis::{AnalysisProjection, PackageResultRefV1, ProjectionSink};
use crate::{AnalysisContextRefV1, AnalysisInputV1, AnalysisWitnessV1, Result};

use super::super::{InputProjection, InputRow};

pub(super) struct ModelProjection<'a> {
    pub(super) inner: InputProjection<'a>,
    pub(super) witnesses: &'a mut Vec<AnalysisWitnessV1>,
    pub(super) contexts: &'a mut Vec<AnalysisContextRefV1>,
    pub(super) results: &'a mut Vec<PackageResultRefV1>,
}

impl ModelProjection<'_> {
    fn result(
        &mut self,
        result_id: &str,
        commit_revision: u64,
        sink: &mut ProjectionSink<'_, InputRow>,
    ) -> Result<()> {
        if let Some(reference) = self
            .results
            .iter_mut()
            .find(|row| row.result_id == result_id)
        {
            if reference.commit_revision != 0
                && commit_revision != 0
                && reference.commit_revision != commit_revision
            {
                return crate::QueryInvalidSnafu {
                    field: "changed model source",
                }
                .fail();
            }
            reference.commit_revision = reference.commit_revision.max(commit_revision);
        } else {
            sink.charge(result_id.len())?;
            sink.grow(self.results)?;
            self.results.push(PackageResultRefV1 {
                result_id: result_id.into(),
                commit_revision,
            });
        }
        Ok(())
    }
}

impl AnalysisProjection for ModelProjection<'_> {
    type Row = InputRow;

    fn decodes_events(&self) -> bool {
        self.inner.decodes_events()
    }
    fn graph_subjects(&self) -> bool {
        self.inner.graph_subjects()
    }
    fn graph_relationships(&self) -> bool {
        self.inner.graph_relationships()
    }

    fn project(
        &mut self,
        input: AnalysisInputV1<'_>,
        sink: &mut ProjectionSink<'_, InputRow>,
    ) -> Result<bool> {
        match &input {
            AnalysisInputV1::Event {
                identity, record, ..
            } => {
                sink.charge(identity.node_id.len())?;
                sink.grow(self.witnesses)?;
                self.witnesses.push(AnalysisWitnessV1 {
                    identity: (*identity).clone().into(),
                    cursor: record.cursor,
                    expires_utc_ns: 0,
                });
            }
            AnalysisInputV1::Context(context) => {
                sink.charge(
                    context.key.owner_id.len()
                        + context.key.entity_key.len()
                        + context.key.lifetime_key.len(),
                )?;
                sink.grow(self.contexts)?;
                self.contexts.push(AnalysisContextRefV1 {
                    key: context.key.clone(),
                    commit_revision: 0,
                });
            }
            AnalysisInputV1::TraceOutput {
                identity, sequence, ..
            } => {
                sink.grow(self.witnesses)?;
                self.witnesses.push(AnalysisWitnessV1 {
                    identity: (*identity).clone().into(),
                    cursor: *sequence,
                    expires_utc_ns: 0,
                });
            }
            AnalysisInputV1::Profile {
                result_id,
                body,
                commit_revision,
                ..
            } => {
                if !crate::DiscoveryProfileV1::try_from(*body)?.sealed {
                    return Err(
                        crate::PackageErrorCodeV1::Unsupported.error("mutable discovery input")
                    );
                }
                self.result(result_id, *commit_revision, sink)?;
            }
            AnalysisInputV1::Graph {
                result_id,
                commit_revision,
                ..
            } => {
                self.result(result_id, *commit_revision, sink)?;
            }
            AnalysisInputV1::Result { result_id, .. } => {
                self.result(result_id, 0, sink)?;
            }
            AnalysisInputV1::Notification {
                obligation,
                commit_revision,
                ..
            } => {
                let key = crate::AnalysisContextKeyV1 {
                    tenant_id: obligation.key.tenant_id,
                    owner_id: crate::NOTIFICATION_STATE_OWNER.into(),
                    entity_key: obligation.key.notification_id.to_vec(),
                    lifetime_key: b"obligation".to_vec(),
                    owner_revision: obligation.revision,
                };
                sink.charge(key.owner_id.len() + key.entity_key.len() + key.lifetime_key.len())?;
                sink.grow(self.contexts)?;
                self.contexts.push(AnalysisContextRefV1 {
                    key,
                    commit_revision: *commit_revision,
                });
                if let Some(finding) = &obligation.finding {
                    self.result(&finding.result_id, 0, sink)?;
                }
            }
            _ => {}
        }
        self.inner.project(input, sink)
    }
}
