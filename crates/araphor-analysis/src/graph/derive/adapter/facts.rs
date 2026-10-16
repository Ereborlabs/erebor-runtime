use super::*;

impl GraphDerivation<'_> {
    pub(super) fn algorithm_fact(
        &self,
        index: usize,
        fact: &GraphFactV1,
    ) -> Result<algorithm::Fact> {
        let row = self
            .input
            .records
            .iter()
            .position(|record| record.id == fact.record_id)
            .ok_or_else(|| {
                GraphInvalidSnafu {
                    field: "graph fact record",
                }
                .build()
            })?;
        let record = &self.input.records[row];
        let reviewed = match &fact.value {
            GraphFactValueV1::Baseline {
                reviewed_policy_revision,
                ..
            }
            | GraphFactValueV1::Credential {
                reviewed_policy_revision,
                ..
            } => self.reviewed_policy(record, reviewed_policy_revision),
            _ => false,
        };
        Ok(algorithm::Fact {
            identity: self.facts[..index]
                .iter()
                .position(|previous| previous == fact)
                .unwrap_or(index) as u64,
            record: row as u64,
            reviewed,
            value: fact.value.clone(),
        })
    }
}
