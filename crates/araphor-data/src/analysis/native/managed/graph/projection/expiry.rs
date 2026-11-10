use super::*;
use araphor_analysis_types::{
    values::RelationshipChange, FindingMember, FindingStateV1, GraphCauseV1, TemporalCoverageV1,
};

impl DataWrite<'_> {
    pub(in crate::analysis::native::managed) fn check_unwritten_expiry(
        &self,
        input: &ManagedCommit<'_>,
        memory: &PreparedMemory<'_>,
    ) -> Result<()> {
        if input
            .attempt
            .source_frame()
            .map(|frame| frame.input_selection())
            .transpose()?
            .flatten()
            .is_none_or(|source| !source.expired())
        {
            return Ok(());
        }
        let reserve = |bytes| {
            if bytes == 0 {
                memory.check().map(|()| None)
            } else {
                memory.reserve(bytes).map(Some)
            }
        };
        let mut values = Values {
            store: self.store,
            reserve: &reserve,
            views: BTreeMap::new(),
            values: BTreeMap::new(),
            leases: Vec::new(),
        };
        self.check_expired_source(input, &mut values)
    }

    pub(super) fn check_expired_source(
        &self,
        input: &ManagedCommit<'_>,
        values: &mut Values<'_>,
    ) -> Result<()> {
        let Some(selection) = input
            .attempt
            .source_frame()
            .map(|frame| frame.input_selection())
            .transpose()?
            .flatten()
        else {
            return Ok(());
        };
        if !selection.expired() {
            return Ok(());
        }
        let spec = &input.attempt.instance().spec;
        let graph = Records::find(
            &super::super::super::InstanceRecord::identity(spec.tenant, &spec.id)?,
            |key| Records::staged(key, &self.transaction),
        )?
        .ok_or_else(|| Code::Missing.error("expired source graph owner"))?;
        let references = self
            .projection_refs(&Index::key(Index::OWNED, &[graph]), &mut |bytes| {
                values.charge(bytes)
            })?;
        for id in references {
            let property = self.projected_property(id, &mut |bytes| values.charge(bytes))?;
            values.load(id, &property)?;
            let port = match property.kind {
                Kind::Relationship => RelationshipChange::port(),
                Kind::Finding => FindingMember::port(),
            };
            let bytes = values.values[&id]
                .batch
                .get_array_memory_size()
                .checked_mul(12)
                .and_then(|bytes| {
                    bytes.checked_add(
                        4 * (size_of::<RelationshipChange>() + size_of::<FindingMember>()),
                    )
                })
                .ok_or_else(|| Code::Limit.error("expired Graph property memory"))?;
            let _lease = (values.reserve)(bytes)?;
            let data = sdk::Dataset {
                name: port.name,
                batches: vec![sdk::Dataset::normalize_batch(
                    values.values[&id].batch.clone(),
                    Arc::new(port.schema),
                )
                .context(crate::AnalysisContractSnafu)?],
            };
            let inside = |record: &crate::DiscoveryRecordIdV1| {
                record.stream == selection.source
                    && (selection.first..=selection.last).contains(&record.durable_cursor)
            };
            let invalid = match property.kind {
                Kind::Relationship => RelationshipChange::decode(&data)
                    .context(crate::AnalysisContractSnafu)?
                    .iter()
                    .any(|row| {
                        inside(&row.anchor.record)
                            && (row.key.cause != GraphCauseV1::Superseded
                                || row.proof_quality.temporal_coverage
                                    != TemporalCoverageV1::Unknown)
                    }),
                Kind::Finding => FindingMember::decode(&data)
                    .context(crate::AnalysisContractSnafu)?
                    .iter()
                    .any(|row| {
                        inside(&row.anchor.record)
                            && (row.value.state != FindingStateV1::CoverageInsufficient
                                || ![
                                    "RETAINED_INPUT_EXPIRED",
                                    "LATE_EVIDENCE_UNSUPPORTED_AFTER_RETENTION",
                                ]
                                .iter()
                                .all(|limit| row.value.limits.iter().any(|actual| actual == limit))
                                || row.value.effects.iter().any(|effect| {
                                    effect.proof_quality.temporal_coverage
                                        != TemporalCoverageV1::Unknown
                                }))
                    }),
            };
            if invalid {
                return Err(Code::Denied.error("expired source proof claim"));
            }
        }
        Ok(())
    }
}
