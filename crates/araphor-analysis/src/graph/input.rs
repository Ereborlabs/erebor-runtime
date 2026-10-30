use super::*;

impl Graph<'_> {
    pub(super) fn projection(&self) -> Result<&[sdk::Dataset; 3]> {
        if self.projection.get().is_none() {
            let facts = self
                .facts
                .iter()
                .zip(&self.input.facts)
                .map(|(fact, context)| {
                    let record = self
                        .input
                        .records
                        .binary_search_by(|row| row.id.cmp(&fact.record_id))
                        .ok()
                        .and_then(|index| u32::try_from(index).ok())
                        .ok_or_else(|| {
                            GraphInvalidSnafu {
                                field: "graph fact record",
                            }
                            .build()
                        })?;
                    Ok(algorithm::Fact {
                        record,
                        key: context.key.clone(),
                        sensitivity: context.sensitivity,
                        value: fact.value.clone(),
                    })
                })
                .collect::<Result<Vec<_>>>()?;
            let values = [
                algorithm::Observation::encode(&self.observations)
                    .context(AnalysisContractSnafu)?,
                algorithm::Fact::encode(&facts).context(AnalysisContractSnafu)?,
                algorithm::Manifest::encode(&[algorithm::Manifest {
                    window_ns: GRAPH_WINDOW_NS,
                }])
                .context(AnalysisContractSnafu)?,
            ];
            self.projection.set(values).map_err(|_| {
                GraphInvalidSnafu {
                    field: "graph input projection",
                }
                .build()
            })?;
        }
        self.projection.get().ok_or_else(|| {
            GraphInvalidSnafu {
                field: "graph input projection",
            }
            .build()
        })
    }

    pub(super) fn check_inputs(
        &self,
        model: &sdk::Model,
        evaluation: &sdk::Evaluation,
    ) -> Result<()> {
        Self::require(
            evaluation.inputs.len() == model.inputs.len(),
            "graph input count",
        )?;
        for port in &model.inputs {
            let actual = evaluation
                .inputs
                .iter()
                .find(|input| input.data.name == port.port.name)
                .ok_or_else(|| {
                    GraphInvalidSnafu {
                        field: "graph input binding",
                    }
                    .build()
                })?;
            let valid = match port.port.name.as_str() {
                "records" => {
                    algorithm::Observation::decode(&actual.data).context(AnalysisContractSnafu)?
                        == self.observations
                }
                "facts" => {
                    let rows =
                        algorithm::Fact::decode(&actual.data).context(AnalysisContractSnafu)?;
                    rows.len() == self.facts.len()
                        && rows
                            .iter()
                            .zip(self.facts.iter().zip(&self.input.facts))
                            .all(|(row, (fact, context))| {
                                self.input
                                    .records
                                    .get(row.record as usize)
                                    .is_some_and(|record| record.id == fact.record_id)
                                    && row.key == context.key
                                    && row.sensitivity == context.sensitivity
                                    && row.value == fact.value
                            })
                }
                "manifest" => {
                    algorithm::Manifest::decode(&actual.data).context(AnalysisContractSnafu)?
                        == [algorithm::Manifest {
                            window_ns: GRAPH_WINDOW_NS,
                        }]
                }
                _ => false,
            };
            Self::require(valid, "graph input binding")?;
        }
        Ok(())
    }

    pub(super) fn qualify_record(
        &self,
        record: &DiscoveryRecordV1,
        position: araphor_data::StorePositionV1,
    ) -> Result<algorithm::Observation> {
        let wire = record.decode()?;
        let context = wire.decision_context.as_ref();
        Ok(algorithm::Observation {
            id: record.id.clone(),
            position: algorithm::Position {
                commit_revision: position.commit_revision,
                ordinal: position.ordinal,
            },
            effect: araphor_data::DiscoveryEffectKeyV1::from(&wire),
            ingested_utc_ns: wire.ingested_utc_ns,
            observed_boottime_ns: wire.observed_boottime_ns,
            profile_generation_ref_id: wire.profile_generation_ref_id,
            original_kernel_sequence: record.original_kernel_sequence,
            coverage_interval_id: wire.coverage_interval_id.to_vec(),
            process_instance_id: context
                .and_then(|value| value.process_instance_id.as_slice().try_into().ok())
                .filter(|id| *id != [0; 16]),
            entry_instance_id: context
                .and_then(|value| value.entry_instance_id.as_slice().try_into().ok())
                .filter(|id| *id != [0; 16]),
            binding_id: context
                .and_then(|value| value.binding_id.as_slice().try_into().ok())
                .filter(|id| *id != [0; 16]),
            role_id: context.map(|value| value.role_id).filter(|id| *id > 0),
            state_id: context.map(|value| value.state_id).filter(|id| *id > 0),
            entry_rule_id: context
                .map(|value| value.entry_rule_id)
                .filter(|id| *id > 0),
            proof_quality: self.proof(record),
        })
    }

    pub(super) fn proof(&self, record: &DiscoveryRecordV1) -> ProofQualityV1 {
        let ranges = self
            .input
            .coverage
            .iter()
            .filter(|range| {
                range.stream == record.id.stream
                    && range.cpu_id == record.id.cpu_id
                    && (range.first_cursor..=range.last_cursor).contains(&record.id.durable_cursor)
            })
            .collect::<Vec<_>>();
        let temporal = if !self.input.missing_ranges.is_empty()
            || ranges
                .iter()
                .any(|range| range.state == DiscoveryCoverageStateV1::Gapped)
        {
            TemporalCoverageV1::Gapped
        } else {
            match ranges
                .iter()
                .max_by_key(|range| range.coverage_revision)
                .map(|range| range.state)
            {
                Some(DiscoveryCoverageStateV1::Healthy | DiscoveryCoverageStateV1::Closed) => {
                    TemporalCoverageV1::Complete
                }
                Some(DiscoveryCoverageStateV1::Gapped) => TemporalCoverageV1::Gapped,
                _ => TemporalCoverageV1::Unknown,
            }
        };
        let mut proof = ProofQualityV1::kernel_decision(temporal);
        proof.integrity = ProofIntegrityV1::AuthenticatedChannel;
        if record.decode().is_ok_and(|wire| wire.task_cookie == 0) {
            proof.local_subject_binding = LocalSubjectBindingV1::None;
        }
        proof
    }

    pub(super) fn observation(
        &self,
        record: &DiscoveryRecordV1,
    ) -> Result<&algorithm::Observation> {
        self.observations
            .binary_search_by(|row| row.id.cmp(&record.id))
            .ok()
            .map(|index| &self.observations[index])
            .ok_or_else(|| {
                GraphInvalidSnafu {
                    field: "graph output record",
                }
                .build()
            })
    }

    pub(super) fn positions(&self, anchor: &algorithm::Anchor) -> Result<(u32, Option<u32>)> {
        let record = self
            .input
            .records
            .binary_search_by(|row| row.id.cmp(&anchor.record))
            .ok()
            .and_then(|index| u32::try_from(index).ok())
            .ok_or_else(|| {
                GraphInvalidSnafu {
                    field: "graph anchor record",
                }
                .build()
            })?;
        let context = anchor
            .fact
            .as_ref()
            .map(|fact| {
                self.input
                    .facts
                    .binary_search_by(|row| row.key.cmp(&fact.key))
                    .ok()
                    .filter(|&index| {
                        self.facts[index].record_id == fact.record
                            && self.facts[index].value == fact.value
                            && self.input.facts[index].sensitivity == fact.sensitivity
                    })
                    .and_then(|index| u32::try_from(index).ok())
                    .ok_or_else(|| {
                        GraphInvalidSnafu {
                            field: "graph anchor fact",
                        }
                        .build()
                    })
            })
            .transpose()?;
        Ok((record, context))
    }
}
