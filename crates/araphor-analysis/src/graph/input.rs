use super::*;

impl Graph<'_> {
    #[cfg(test)]
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
                algorithm::Fact::encode_source(&facts, &self.observations)
                    .context(AnalysisContractSnafu)?,
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
            algorithm::Detector::supports_units(model),
            "graph unit contract",
        )?;
        Self::require(
            evaluation.inputs.len() == model.inputs.len(),
            "graph input count",
        )?;
        self.check_units(evaluation)
    }

    fn check_units(&self, evaluation: &sdk::Evaluation) -> Result<()> {
        let units = algorithm::Unit::decode(
            &evaluation
                .input("units")
                .context(AnalysisContractSnafu)?
                .data,
        )
        .context(AnalysisContractSnafu)?;
        let mut selected = BTreeMap::new();
        let mut roots = BTreeSet::new();
        for unit in &units {
            Self::require(
                roots.insert(&unit.record)
                    && unit.window_ns == GRAPH_WINDOW_NS
                    && unit.restricted == self.restricted
                    && unit
                        .support
                        .windows(2)
                        .all(|pair| pair[0].record < pair[1].record)
                    && unit
                        .support
                        .iter()
                        .any(|support| support.record == unit.record),
                "graph unit controls",
            )?;
            for support in &unit.support {
                let record = self
                    .observations
                    .binary_search_by(|record| record.id.cmp(&support.record))
                    .ok()
                    .and_then(|index| self.observations.get(index))
                    .ok_or_else(|| {
                        GraphInvalidSnafu {
                            field: "graph unit source",
                        }
                        .build()
                    })?;
                Self::require(record.proof_quality == support.proof, "graph unit proof")?;
                let keys = self
                    .input
                    .facts
                    .iter()
                    .zip(&self.facts)
                    .filter(|(_, fact)| fact.record_id == support.record)
                    .map(|(context, _)| &context.key)
                    .collect::<Vec<_>>();
                Self::require(support.facts.iter().eq(keys), "graph unit facts")?;
                if let Some(old) = selected.insert(&support.record, support) {
                    Self::require(old == support, "graph shared unit support")?;
                }
            }
        }
        let records = algorithm::Observation::decode(
            &evaluation
                .input("records")
                .context(AnalysisContractSnafu)?
                .data,
        )
        .context(AnalysisContractSnafu)?;
        let indices = records
            .iter()
            .enumerate()
            .map(|(index, record)| (&record.id, index as u32))
            .collect::<BTreeMap<_, _>>();
        Self::require(
            records.len() == selected.len()
                && indices.len() == records.len()
                && indices.keys().eq(selected.keys()),
            "graph unit lookup records",
        )?;
        for record in &records {
            let index = self
                .observations
                .binary_search_by(|current| current.id.cmp(&record.id))
                .map_err(|_| {
                    GraphInvalidSnafu {
                        field: "graph unit lookup record",
                    }
                    .build()
                })?;
            Self::require(
                record == &self.observations[index],
                "graph unit lookup record",
            )?;
        }
        let facts = algorithm::Fact::decode(
            &evaluation
                .input("facts")
                .context(AnalysisContractSnafu)?
                .data,
        )
        .context(AnalysisContractSnafu)?;
        let expected = self
            .input
            .facts
            .iter()
            .zip(&self.facts)
            .filter_map(|(context, fact)| {
                indices.get(&fact.record_id).map(|&record| {
                    (
                        &context.key,
                        algorithm::Fact {
                            record,
                            key: context.key.clone(),
                            sensitivity: context.sensitivity,
                            value: fact.value.clone(),
                        },
                    )
                })
            })
            .collect::<BTreeMap<_, _>>();
        let actual = facts
            .iter()
            .map(|fact| (&fact.key, fact))
            .collect::<BTreeMap<_, _>>();
        Self::require(
            actual.len() == facts.len()
                && actual.len() == expected.len()
                && actual
                    .iter()
                    .all(|(key, fact)| expected.get(key) == Some(*fact)),
            "graph unit lookup facts",
        )
    }

    pub(super) fn check_targets(&self, model: &sdk::Model, result: &CallResult) -> Result<()> {
        if !algorithm::Detector::supports_units(model) {
            return Ok(());
        }
        Self::require(result.changes().is_some(), "graph unit change basis")?;
        let evaluation = result.evaluation();
        let affected = algorithm::Unit::decode_affected(
            &evaluation
                .input("affected")
                .context(AnalysisContractSnafu)?
                .data,
        )
        .context(AnalysisContractSnafu)?;
        let units = algorithm::Unit::decode(
            &evaluation
                .input("units")
                .context(AnalysisContractSnafu)?
                .data,
        )
        .context(AnalysisContractSnafu)?;
        let before = algorithm::Unit::decode(
            &evaluation
                .input("unit_removals")
                .context(AnalysisContractSnafu)?
                .data,
        )
        .context(AnalysisContractSnafu)?;
        self.check_selection(&affected, &before, &units)
    }

    pub(super) fn check_selection(
        &self,
        affected: &[DiscoveryRecordIdV1],
        before: &[algorithm::Unit],
        units: &[algorithm::Unit],
    ) -> Result<()> {
        let keys = affected.iter().collect::<BTreeSet<_>>();
        let removed = before
            .iter()
            .map(|unit| &unit.record)
            .collect::<BTreeSet<_>>();
        let ids = units
            .iter()
            .map(|unit| &unit.record)
            .collect::<BTreeSet<_>>();
        Self::require(
            keys.len() == affected.len()
                && keys
                    .iter()
                    .all(|key| key.stream == self.input.source && key.durable_cursor > 0)
                && ids.len() == units.len()
                && removed.len() == before.len()
                && ids.union(&removed).copied().eq(keys.iter().copied())
                && keys.iter().all(|key| {
                    self.observations
                        .binary_search_by(|record| record.id.cmp(key))
                        .is_ok()
                        == ids.contains(key)
                }),
            "graph unit target selection",
        )
    }

    pub(super) fn qualify_records(
        input: &GraphReplayInputV1,
    ) -> Result<Vec<algorithm::Observation>> {
        let positions = input
            .input_positions
            .iter()
            .map(|(id, position)| (id, position))
            .collect::<BTreeMap<_, _>>();
        input
            .records
            .iter()
            .map(|record| {
                let position = positions.get(&record.id).ok_or_else(|| {
                    GraphInvalidSnafu {
                        field: "graph input position",
                    }
                    .build()
                })?;
                Self::qualify_record(input, record, **position)
            })
            .collect()
    }

    fn qualify_record(
        input: &GraphReplayInputV1,
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
            proof_quality: Self::proof(input, record),
        })
    }

    fn proof(input: &GraphReplayInputV1, record: &DiscoveryRecordV1) -> ProofQualityV1 {
        let ranges = input
            .coverage
            .iter()
            .filter(|range| {
                range.stream == record.id.stream
                    && range.cpu_id == record.id.cpu_id
                    && (range.first_cursor..=range.last_cursor).contains(&record.id.durable_cursor)
            })
            .collect::<Vec<_>>();
        let temporal = if !input.missing_ranges.is_empty()
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
