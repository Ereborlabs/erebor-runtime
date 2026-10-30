use super::*;
use crate::{AnalysisContractSnafu, DiscoveryRecordIdV1};

pub(super) struct ProgressPlan {
    pub additions: Vec<Progress>,
    pub removals: Vec<DiscoveryRecordIdV1>,
    pub root: Option<Vec<u8>>,
    pub next: Option<BTreeMap<DiscoveryRecordIdV1, Progress>>,
}

impl GraphRows {
    pub(super) fn progress_plan(
        evaluation: &sdk::Evaluation,
        output: &sdk::Output,
        detector: Option<Detector>,
        full: bool,
    ) -> Result<ProgressPlan> {
        let dataset = |name: &str| {
            output
                .datasets
                .iter()
                .find(|dataset| dataset.name == name)
                .ok_or_else(|| Self::invalid("graph progress dataset"))
        };
        let additions = Progress::decode(dataset("progress")?).context(AnalysisContractSnafu)?;
        let removals = ProgressRemoval::decode(dataset("progress_removals")?)
            .context(AnalysisContractSnafu)?
            .into_iter()
            .map(|row| row.record)
            .collect::<Vec<_>>();
        let Some(detector) = detector else {
            return Ok(ProgressPlan {
                additions,
                removals,
                root: None,
                next: None,
            });
        };
        if full && !removals.is_empty() {
            return Err(Self::invalid("graph full progress removals"));
        }
        let prior = if full {
            BTreeMap::new()
        } else {
            let dataset = evaluation
                .previous_outputs
                .iter()
                .find(|dataset| dataset.name == "progress")
                .ok_or_else(|| Self::invalid("graph previous progress"))?;
            let mut prior = BTreeMap::new();
            for row in Progress::decode(dataset).context(AnalysisContractSnafu)? {
                if !row.compatible(detector) || prior.insert(row.record.clone(), row).is_some() {
                    return Err(Self::invalid("graph previous progress"));
                }
            }
            prior
        };
        let mut actual = prior.clone();
        let mut removed = BTreeSet::new();
        for record in removals {
            if !removed.insert(record.clone()) || actual.remove(&record).is_none() {
                return Err(Self::invalid("graph progress removal"));
            }
        }
        let mut added = BTreeSet::new();
        for row in additions {
            if !row.compatible(detector)
                || !added.insert(row.record.clone())
                || actual.insert(row.record.clone(), row).is_some()
            {
                return Err(Self::invalid("graph progress addition"));
            }
        }
        let expected = Progress::from_evaluation(evaluation).context(AnalysisContractSnafu)?;
        if actual.len() != expected.len()
            || expected.iter().any(|row| {
                actual
                    .get(&row.record)
                    .is_none_or(|actual| actual.digest != row.digest)
            })
        {
            return Err(Self::invalid("graph progress input coverage"));
        }
        let full = actual.values().cloned().collect::<Vec<_>>();
        let root = Progress::output_digest(&full)
            .context(AnalysisContractSnafu)?
            .to_vec();
        let removals = prior
            .iter()
            .filter(|(record, row)| row.state.is_some() && actual.get(*record) != Some(*row))
            .map(|(record, _)| record.clone())
            .collect();
        let additions = actual
            .iter()
            .filter(|(record, row)| row.state.is_some() && prior.get(*record) != Some(*row))
            .map(|(_, row)| row.clone())
            .collect();
        Ok(ProgressPlan {
            additions,
            removals,
            root: Some(root),
            next: Some(actual),
        })
    }

    pub(super) fn expand_progress(
        evaluation: &sdk::Evaluation,
        physical: Vec<Progress>,
        root: Option<&[u8]>,
        detector: Option<Detector>,
    ) -> Result<BTreeMap<DiscoveryRecordIdV1, Progress>> {
        let Some(detector) = detector else {
            if root.is_some() {
                return Err(Self::invalid("graph explicit progress root"));
            }
            let mut rows = BTreeMap::new();
            for row in physical {
                if row.digest.len() != 32 || rows.insert(row.record.clone(), row).is_some() {
                    return Err(Self::invalid("graph explicit progress"));
                }
            }
            return Ok(rows);
        };
        let root = root
            .filter(|root| root.len() == 32)
            .ok_or_else(|| Self::invalid("graph derived progress root"))?;
        let mut rows = Progress::from_evaluation(evaluation)
            .context(AnalysisContractSnafu)?
            .into_iter()
            .map(|row| (row.record.clone(), row))
            .collect::<BTreeMap<_, _>>();
        let mut seen = BTreeSet::new();
        for row in physical {
            if row.state.is_none() || !row.compatible(detector) || !seen.insert(row.record.clone())
            {
                return Err(Self::invalid("graph derived progress value"));
            }
            let default = rows
                .get_mut(&row.record)
                .ok_or_else(|| Self::invalid("graph derived progress input"))?;
            if default.digest != row.digest {
                return Err(Self::invalid("graph derived progress digest"));
            }
            default.state = row.state;
        }
        let full = rows.values().cloned().collect::<Vec<_>>();
        if Progress::output_digest(&full)
            .context(AnalysisContractSnafu)?
            .as_slice()
            != root
        {
            return Err(Self::invalid("graph derived progress root"));
        }
        Ok(rows)
    }
}

#[cfg(test)]
#[path = "tests/progress.rs"]
mod tests;
