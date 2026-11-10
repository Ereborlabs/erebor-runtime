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
        self.check_expired_states(input, graph, values)?;
        Ok(())
    }
    fn check_expired_states(
        &self,
        input: &ManagedCommit<'_>,
        graph: u64,
        values: &mut Values<'_>,
    ) -> Result<()> {
        use araphor_analysis_types::{GraphPackageStateV1, GraphStateMember};
        let mapping =
            super::super::ManagedGraph::read(graph, |key| Records::staged(key, &self.transaction))?
                .ok_or_else(|| Code::Missing.error("expired Graph mapping"))?;
        let current = self.store.view()?;
        let view = Graph::new(graph)?.view(
            current.snapshot.clone(),
            BTreeMap::new(),
            &|writer, bytes, total| values.graph_reserve(writer, bytes, total),
        )?;
        let keys = sdk::RecordBatch::new_empty(Arc::new(sdk::Schema::empty()));
        for (relation, declaration) in mapping
            .relations
            .values()
            .filter(|(_, declaration)| DomainRelations::states(declaration))
        {
            for (&call, &writer) in &mapping.writers {
                let mut batches = Vec::new();
                let mut held = Vec::new();
                view.read(
                    *relation,
                    araphor_graph::Read::Owned(writer),
                    &keys,
                    &|writer, bytes, total| values.graph_reserve(writer, bytes, total),
                    |read| {
                        batches.push(read.batch().clone());
                        held.push(read);
                        Ok(())
                    },
                )?;
                let had_state = batches.iter().any(|batch| batch.num_rows() != 0);
                if let Some(journal) = input
                    .returns
                    .iter()
                    .find(|returned| returned.call == call)
                    .and_then(|returned| returned.graph)
                {
                    let bytes = journal
                        .work
                        .journal
                        .batches()
                        .iter()
                        .try_fold(0usize, |bytes, staged| {
                            let batch = match staged {
                                araphor_graph::Staged::Edits { batch, .. }
                                | araphor_graph::Staged::Clear { batch, .. } => batch,
                            };
                            bytes.checked_add(batch.get_array_memory_size().saturating_mul(4))
                        })
                        .ok_or_else(|| Code::Limit.error("expired Graph state memory"))?;
                    values.charge(bytes)?;
                    batches = journal.work.journal.overlay(
                        *relation,
                        &declaration.engine(),
                        araphor_graph::Read::Owned(writer),
                        &[],
                        batches,
                    )?;
                }
                let mut fallback = None;
                let mut selected = None::<GraphStateMember>;
                for batch in batches {
                    let properties = batch
                        .column_by_name("properties")
                        .and_then(|array| array.as_any().downcast_ref::<StructArray>())
                        .ok_or_else(|| Code::Invalid.error("expired Graph state properties"))?;
                    values.charge(properties.get_array_memory_size().saturating_mul(12))?;
                    let port = GraphStateMember::port();
                    let batch = sdk::RecordBatch::try_new(
                        Arc::new(port.schema),
                        properties.columns().to_vec(),
                    )
                    .context(crate::PackageArrowSnafu)?;
                    for row in GraphStateMember::decode(&sdk::Dataset {
                        name: port.name,
                        batches: vec![batch],
                    })
                    .context(crate::AnalysisContractSnafu)?
                    {
                        if row.record.is_none() {
                            fallback = Some(row.state);
                            continue;
                        }
                        let greater = if let Some(prior) = &selected {
                            match (&row.fact, &prior.fact) {
                                (Some(left), Some(right)) => {
                                    (left, &row.record) > (right, &prior.record)
                                }
                                (None, None) => row.record > prior.record,
                                _ => return Err(Code::Invalid.error("Graph state ordering mode")),
                            }
                        } else {
                            true
                        };
                        if greater {
                            selected = Some(row);
                        }
                    }
                }
                let state = selected.map(|row| row.state).or(fallback);
                if (had_state || state.is_some())
                    && state != Some(GraphPackageStateV1::CoverageInsufficient)
                {
                    return Err(Code::Denied.error("expired source package state"));
                }
            }
        }
        Ok(())
    }
}
