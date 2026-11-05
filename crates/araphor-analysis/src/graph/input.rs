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
            araphor_analysis_builtins::graph::Detector::supports_units(model),
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
        let mut roots = BTreeSet::new();
        for unit in &units {
            Self::require(
                roots.insert(&unit.record)
                    && unit.window_ns == GRAPH_WINDOW_NS
                    && unit.restricted == self.restricted
                    && self
                        .observations
                        .binary_search_by(|record| record.id.cmp(&unit.record))
                        .is_ok(),
                "graph unit controls",
            )?;
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
            indices.len() == records.len() && roots.iter().all(|key| indices.contains_key(key)),
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
        if !araphor_analysis_builtins::graph::Detector::supports_units(model) {
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
        araphor_data::EvidenceBasis::qualify(input)
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
