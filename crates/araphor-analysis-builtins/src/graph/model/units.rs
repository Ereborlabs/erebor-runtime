use super::{AnalysisContextKeyV1, GraphPackageStateV1, ProofQualityV1};
use crate::discovery::DiscoveryRecordIdV1;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct UnitSupport {
    pub record: DiscoveryRecordIdV1,
    pub proof: ProofQualityV1,
    pub facts: Vec<AnalysisContextKeyV1>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Unit {
    pub record: DiscoveryRecordIdV1,
    pub window_ns: u64,
    pub restricted: bool,
}

pub use araphor_analysis_types::GraphStateChange as UnitState;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Contribution {
    pub record: DiscoveryRecordIdV1,
    pub support: Vec<UnitSupport>,
    pub subjects: Vec<u64>,
    pub relationships: Vec<u64>,
    pub findings: Vec<u64>,
    pub state: Option<UnitState>,
}

impl Contribution {
    pub fn validate<'a>(
        units: impl IntoIterator<Item = &'a Unit>,
        records: &[super::Observation],
        facts: &[super::Fact],
        rows: &[Self],
        counts: [usize; 3],
    ) -> araphor_analysis_sdk::Result<[Vec<usize>; 3]> {
        use std::collections::{BTreeMap, BTreeSet};
        let invalid = |field| {
            araphor_analysis_sdk::Error::contract(araphor_analysis_sdk::ErrorCode::Invalid, field)
        };
        let mut selected = BTreeMap::new();
        for unit in units {
            if selected.insert(&unit.record, unit).is_some() {
                return Err(invalid("graph duplicate unit"));
            }
        }
        let observations = records
            .iter()
            .map(|record| (&record.id, record))
            .collect::<BTreeMap<_, _>>();
        if observations.len() != records.len() || rows.len() != selected.len() {
            return Err(invalid("graph unit contribution roots"));
        }
        let mut fact_keys = BTreeMap::<_, Vec<_>>::new();
        for fact in facts {
            let record = records
                .get(fact.record as usize)
                .ok_or_else(|| invalid("graph contribution fact record"))?;
            fact_keys.entry(&record.id).or_default().push(&fact.key);
        }
        let mut seen = BTreeSet::new();
        let mut owners = counts.map(|count| vec![usize::MAX; count]);
        for (owner, row) in rows.iter().enumerate() {
            let unit = selected
                .get(&row.record)
                .ok_or_else(|| invalid("graph unit contribution roots"))?;
            if !seen.insert(&row.record) {
                return Err(invalid("graph unit contribution roots"));
            }
            if row
                .support
                .windows(2)
                .any(|pair| pair[0].record >= pair[1].record)
                || !row
                    .support
                    .iter()
                    .any(|support| support.record == row.record)
                || facts
                    .iter()
                    .filter(|fact| {
                        records
                            .get(fact.record as usize)
                            .is_some_and(|record| record.id == unit.record)
                    })
                    .filter_map(|fact| match &fact.value {
                        super::GraphFactValueV1::Policy(policy) => Some(&policy.observations),
                        _ => None,
                    })
                    .flatten()
                    .any(|id| !row.support.iter().any(|support| &support.record == id))
            {
                return Err(invalid("graph contribution support"));
            }
            for support in &row.support {
                let record = observations
                    .get(&support.record)
                    .ok_or_else(|| invalid("graph contribution support record"))?;
                let keys = fact_keys
                    .get(&support.record)
                    .map(Vec::as_slice)
                    .unwrap_or(&[]);
                if support.proof != record.proof_quality
                    || support.facts.windows(2).any(|pair| pair[0] >= pair[1])
                    || !support.facts.iter().eq(keys.iter().copied())
                {
                    return Err(invalid("graph contribution support value"));
                }
            }
            for (slots, indices) in
                owners
                    .iter_mut()
                    .zip([&row.subjects, &row.relationships, &row.findings])
            {
                for &index in indices {
                    let slot = usize::try_from(index)
                        .ok()
                        .and_then(|index| slots.get_mut(index))
                        .ok_or_else(|| invalid("graph unit output row"))?;
                    if *slot != usize::MAX {
                        return Err(invalid("graph duplicate unit ownership"));
                    }
                    *slot = owner;
                }
            }
            let Some(state) = &row.state else {
                continue;
            };
            let root = observations
                .get(&row.record)
                .ok_or_else(|| invalid("graph unit state record"))?;
            if state.position != root.position
                || matches!(&state.state, GraphPackageStateV1::Declared(value) if value.is_empty())
                || state.fact.as_ref().is_some_and(|key| {
                    !row.support
                        .iter()
                        .any(|support| support.record == row.record && support.facts.contains(key))
                        || !facts.iter().any(|fact| {
                            &fact.key == key
                                && records
                                    .get(fact.record as usize)
                                    .is_some_and(|record| record.id == row.record)
                        })
                })
            {
                return Err(invalid("graph unit state provenance"));
            }
        }
        if owners.iter().any(|slots| slots.contains(&usize::MAX)) {
            return Err(invalid("graph absent unit ownership"));
        }
        Ok(owners)
    }
}
