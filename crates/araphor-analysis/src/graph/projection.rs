use super::*;

impl Graph<'_> {
    pub(super) fn check_inputs(
        &self,
        model: &sdk::Model,
        evaluation: &sdk::Evaluation,
    ) -> Result<()> {
        if evaluation.inputs.len() != model.inputs.len() {
            return GraphInvalidSnafu {
                field: "graph input count",
            }
            .fail();
        }
        for (input, expected) in model.inputs.iter().zip(self.projection()?) {
            let actual = evaluation
                .inputs
                .iter()
                .find(|value| value.data.name == input.port.name)
                .ok_or_else(|| {
                    GraphInvalidSnafu {
                        field: "graph input binding",
                    }
                    .build()
                })?;
            let rows: Vec<serde_json::Value> =
                Rows::decode(&input.port, &actual.data, evaluation.context.limits)
                    .context(AnalysisContractSnafu)?;
            if rows != expected {
                return GraphInvalidSnafu {
                    field: "graph input binding",
                }
                .fail();
            }
        }
        Ok(())
    }

    pub(super) fn projection(&self) -> Result<[Vec<serde_json::Value>; 3]> {
        let records = self
            .input
            .records
            .iter()
            .map(|record| {
                serde_json::to_value(self.observation(record)?).context(GraphEncodingSnafu)
            })
            .collect::<Result<Vec<_>>>()?;
        let facts = self
            .facts
            .iter()
            .enumerate()
            .map(|(index, fact)| {
                serde_json::to_value(self.algorithm_fact(index, fact)?).context(GraphEncodingSnafu)
            })
            .collect::<Result<Vec<_>>>()?;
        let manifest = serde_json::to_value(algorithm::Manifest {
            window_ns: GRAPH_WINDOW_NS,
            window_records: GRAPH_WINDOW_RECORDS,
        })
        .context(GraphEncodingSnafu)?;
        Ok([records, facts, vec![manifest]])
    }

    pub(super) fn observation(&self, record: &DiscoveryRecordV1) -> Result<algorithm::Observation> {
        let wire = record.decode()?;
        let effect = self.effect(record, &wire);
        Ok(algorithm::Observation {
            lifetime: serde_json::to_vec(&(
                &record.id.stream.node_id,
                record.id.stream.node_boot_id,
                record.id.stream.label_epoch,
            ))
            .context(GraphEncodingSnafu)?,
            task: wire.task_cookie,
            process: effect.process_instance_id,
            execution: wire.execution_set_id.to_vec(),
            object: wire.exact_object_id.to_vec(),
            role: effect.role_id,
            state: effect.state_id,
            exact_identity: wire.task_cookie > 0
                && effect.process_instance_id.is_some()
                && effect.entry_instance_id.is_some()
                && effect.binding_id.is_some()
                && effect.role_id.is_some()
                && effect.state_id.is_some()
                && effect.entry_rule_id.is_some(),
            policy_conflict: self.policy_conflict(record),
            complete: effect.proof_quality.temporal_coverage == TemporalCoverageV1::Complete,
            network: wire.effect_family == KernelEffectFamilyV1::Network as u32,
            denied: wire.decision == EffectPhysicalResultV1::DeniedBeforeEffect as u32,
            admitted: wire.decision == EffectPhysicalResultV1::UnknownAfterPreEffect as u32,
            operation: match wire.operation {
                value if value == KernelEffectOperationV1::Read as u32 => {
                    algorithm::Operation::Read
                }
                value if value == KernelEffectOperationV1::OpenRead as u32 => {
                    algorithm::Operation::OpenRead
                }
                value if value == KernelEffectOperationV1::MmapRead as u32 => {
                    algorithm::Operation::MmapRead
                }
                _ => algorithm::Operation::Other,
            },
            physical: match effect.physical_result {
                GraphPhysicalResultV1::Prevented => algorithm::Physical::Prevented,
                GraphPhysicalResultV1::PacketDropped => algorithm::Physical::PacketDropped,
                GraphPhysicalResultV1::TerminationQueued => algorithm::Physical::TerminationQueued,
                GraphPhysicalResultV1::Unknown => algorithm::Physical::Unknown,
            },
            boottime: wire.observed_boottime_ns,
        })
    }
}
