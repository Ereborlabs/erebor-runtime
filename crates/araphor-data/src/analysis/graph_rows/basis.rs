use super::*;
use crate::{AnalysisContractSnafu, DiscoveryRecordIdV1};

pub(super) struct CallBasis {
    pub(super) records: BTreeMap<DiscoveryRecordIdV1, u32>,
    pub(super) facts: BTreeMap<crate::AnalysisContextKeyV1, (u32, FactAnchor)>,
}

impl CallBasis {
    pub(super) fn new(evaluation: &sdk::Evaluation) -> Result<Self> {
        let records = Observation::decode(
            &evaluation
                .input("records")
                .context(AnalysisContractSnafu)?
                .data,
        )
        .context(AnalysisContractSnafu)?;
        let facts = Fact::decode(
            &evaluation
                .input("facts")
                .context(AnalysisContractSnafu)?
                .data,
        )
        .context(AnalysisContractSnafu)?;
        let mut indexed = BTreeMap::new();
        for (index, row) in records.iter().enumerate() {
            if indexed
                .insert(
                    row.id.clone(),
                    u32::try_from(index).map_err(|_| GraphRows::invalid("graph record ordinal"))?,
                )
                .is_some()
            {
                return Err(GraphRows::invalid("graph duplicate record"));
            }
        }
        let mut anchored = BTreeMap::new();
        for (index, fact) in facts.into_iter().enumerate() {
            let record = records
                .get(fact.record as usize)
                .ok_or_else(|| GraphRows::invalid("graph fact record"))?;
            let anchor = FactAnchor {
                record: record.id.clone(),
                key: fact.key.clone(),
                sensitivity: fact.sensitivity,
                value: fact.value,
            };
            if anchored
                .insert(
                    fact.key,
                    (
                        u32::try_from(index)
                            .map_err(|_| GraphRows::invalid("graph fact ordinal"))?,
                        anchor,
                    ),
                )
                .is_some()
            {
                return Err(GraphRows::invalid("graph duplicate fact"));
            }
        }
        Ok(Self {
            records: indexed,
            facts: anchored,
        })
    }

    pub(super) fn local(&self, anchor: &Anchor) -> Result<(u32, Option<u32>)> {
        let record = *self
            .records
            .get(&anchor.record)
            .ok_or_else(|| GraphRows::invalid("graph anchor record"))?;
        let fact = anchor
            .fact
            .as_ref()
            .map(|fact| {
                let (index, expected) = self
                    .facts
                    .get(&fact.key)
                    .ok_or_else(|| GraphRows::invalid("graph anchor fact"))?;
                if fact != expected {
                    return Err(GraphRows::invalid("graph anchor fact"));
                }
                Ok(*index)
            })
            .transpose()?;
        Ok((record, fact))
    }

    pub(super) fn local_for(&self, unit: &Unit, anchor: &Anchor) -> Result<(u32, Option<u32>)> {
        let local = self.local(anchor)?;
        if !unit
            .support
            .iter()
            .any(|support| support.record == anchor.record)
            || anchor.fact.as_ref().is_some_and(|fact| {
                !unit.support.iter().any(|support| {
                    support.record == fact.record && support.facts.contains(&fact.key)
                })
            })
        {
            return Err(GraphRows::invalid("graph unit anchor ownership"));
        }
        Ok(local)
    }
}
