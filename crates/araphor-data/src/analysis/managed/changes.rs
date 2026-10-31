use araphor_analysis_sdk as sdk;
use duckdb::{params, Connection};
use snafu::ResultExt as _;

use super::model::*;
use crate::{
    AnalysisDatabaseSnafu, AnalysisReadControl, AnalysisStore, PackageErrorCodeV1 as Code, Result,
};

impl AnalysisStore {
    pub(super) fn prepare_changes(
        input: &ManagedCommit<'_>,
        returned: &ManagedReturn<'_>,
        model: &sdk::Model,
    ) -> Result<Option<RecordChanges>> {
        let (Some(contract), Some(changes)) = (&model.change_inputs, returned.changes) else {
            return if model.change_inputs.is_some() || returned.changes.is_some() {
                Err(Code::Invalid.error("managed change inputs"))
            } else {
                Ok(None)
            };
        };
        if returned.retained.is_some() {
            return Err(Code::Invalid.error("retained change call"));
        }
        let evaluation = returned.evaluation;
        let reset = contract
            .is_reset(evaluation)
            .context(crate::AnalysisContractSnafu)?;
        let prior = input.attempt.3.get(&returned.call);
        let expected = input.attempt.prior_result(returned.call);
        let old = if reset {
            if changes.base.is_some() {
                return Err(Code::Invalid.error("reset change base"));
            }
            None
        } else {
            if changes.base.as_ref() != expected || expected.is_none() {
                return Err(Code::Conflict.error("managed change base"));
            }
            Some(
                prior
                    .and_then(|prior| prior.retained.as_ref())
                    .and_then(|retained| retained.changes.as_ref())
                    .ok_or_else(|| Code::Missing.error("managed change target"))?,
            )
        };
        let ports = model
            .inputs
            .iter()
            .filter(|port| {
                !contract.generated(&port.port.name)
                    && !matches!(&port.source, sdk::InputSource::Lookup(_))
            })
            .map(|port| port.port.clone())
            .collect::<Vec<_>>();
        let datasets = changes
            .targets
            .iter()
            .map(|target| target.data.clone())
            .collect::<Vec<_>>();
        sdk::Dataset::validate_all(&datasets, &ports).context(crate::AnalysisContractSnafu)?;
        for target in &changes.targets {
            let actual = evaluation
                .input(&target.data.name)
                .context(crate::AnalysisContractSnafu)?;
            let paired = contract
                .ports
                .iter()
                .any(|pair| pair.after == target.data.name);
            if actual.revision != target.revision
                || actual.coverage != target.coverage
                || ((!paired || reset) && actual.data.batches != target.data.batches)
            {
                return Err(Code::Invalid.error("managed current change input"));
            }
            if let Some(old) = old.filter(|_| !paired) {
                if old
                    .targets
                    .iter()
                    .find(|old| old.data.name == target.data.name)
                    .is_none_or(|old| !Self::same_change_input(old, target))
                {
                    return Err(Code::Conflict.error("managed change support"));
                }
            }
        }
        for pair in &contract.ports {
            let before = evaluation
                .input(&pair.before)
                .context(crate::AnalysisContractSnafu)?;
            let basis = if let Some(old) = old {
                old.targets.iter().find(|old| old.data.name == pair.after)
            } else {
                changes
                    .targets
                    .iter()
                    .find(|target| target.data.name == pair.after)
            }
            .ok_or_else(|| Code::Missing.error("managed change basis"))?;
            if before.revision != basis.revision || before.coverage != basis.coverage {
                return Err(Code::Conflict.error("managed historical change input"));
            }
        }
        let targets = changes
            .targets
            .iter()
            .map(|target| {
                let port = ports
                    .iter()
                    .find(|port| port.name == target.data.name)
                    .ok_or_else(|| Code::Invalid.error("managed target port"))?;
                Ok(RecordTarget {
                    input: sdk::wire::Input {
                        data: sdk::wire::Dataset::encode(&target.data, &port.schema)
                            .context(crate::AnalysisContractSnafu)?,
                        revision: target.revision.clone(),
                        coverage: target.coverage.clone(),
                    },
                    rows: target.data.rows(),
                    batches: target.data.batches.len(),
                })
            })
            .collect::<Result<_>>()?;
        Ok(Some(RecordChanges {
            base: changes.base.clone(),
            targets,
        }))
    }

    pub(super) fn same_change_input(left: &sdk::Input, right: &sdk::Input) -> bool {
        left.data.name == right.data.name
            && left.data.batches == right.data.batches
            && left.revision == right.revision
            && left.coverage == right.coverage
    }

    pub(super) fn check_change_record(
        reader: &Connection,
        tenant: [u8; 16],
        record: &Record,
        model: &sdk::Model,
        attempt: &Attempt,
    ) -> Result<()> {
        let (Some(contract), Some(changes)) = (&model.change_inputs, &record.changes) else {
            return if model.change_inputs.is_some() || record.changes.is_some() {
                Err(Code::Invalid.error("managed change contract"))
            } else {
                Ok(())
            };
        };
        if !matches!(
            (record.input_basis, changes.base.is_some()),
            (InputBasis::None, false) | (InputBasis::Complete, true)
        ) {
            return Err(Code::Invalid.error("managed change input basis"));
        }
        let expected = attempt
            .capture
            .prior
            .get(&record.call)
            .and_then(Option::as_ref);
        let names = model
            .inputs
            .iter()
            .filter(|port| {
                !contract.generated(&port.port.name)
                    && !matches!(&port.source, sdk::InputSource::Lookup(_))
            })
            .map(|port| port.port.name.as_str())
            .collect::<std::collections::BTreeSet<_>>();
        if changes
            .targets
            .iter()
            .map(|target| target.input.data.name.as_str())
            .collect::<std::collections::BTreeSet<_>>()
            != names
            || changes.targets.len() != names.len()
        {
            return Err(Code::Invalid.error("managed change target names"));
        }
        let prior = changes
            .base
            .as_ref()
            .map(|base| {
                if Some(base) != expected
                    || base.commit_revision == 0
                    || base.commit_revision >= attempt.registered
                {
                    return Err(Code::Conflict.error("managed historical base"));
                }
                let (old, _, revision) =
                    Self::managed_header_from(reader, tenant, &base.result_id)?;
                if old.call != record.call
                    || old.instance != record.instance
                    || old.declaration != record.declaration
                    || revision != base.commit_revision
                {
                    return Err(Code::Invalid.error("managed historical call"));
                }
                old.changes
                    .ok_or_else(|| Code::Missing.error("managed historical target"))
            })
            .transpose()?;
        for (slot, port) in record.inputs.iter().enumerate() {
            if port.name == contract.reset
                || matches!(&model.inputs[slot].source, sdk::InputSource::Lookup(_))
            {
                continue;
            }
            let (basis, name) = match contract.ports.iter().find(|pair| pair.before == port.name) {
                Some(pair) => (prior.as_ref().unwrap_or(changes), pair.after.as_str()),
                None => (changes, port.name.as_str()),
            };
            let target = &basis
                .targets
                .iter()
                .find(|target| target.input.data.name == name)
                .ok_or_else(|| Code::Invalid.error("managed target binding"))?
                .input;
            if record.context.inputs.get(slot) != Some(&target.revision)
                || record.context.input_coverage.get(slot) != Some(&target.coverage)
            {
                return Err(Code::Invalid.error("managed target provenance"));
            }
        }
        Ok(())
    }

    pub(super) fn managed_changes_from(
        reader: &Connection,
        id: &str,
        record: &Record,
        control: &AnalysisReadControl,
    ) -> Result<Option<RecordChanges>> {
        let Some(mut changes) = record.changes.clone() else {
            return Ok(None);
        };
        changes.check_header()?;
        let mut statement = reader.prepare("SELECT slot, ipc FROM managed_arrow WHERE result_id = ? AND role = 'target' ORDER BY slot")
            .context(AnalysisDatabaseSnafu { operation: "prepare saved change targets" })?;
        let rows = statement
            .query_map(params![id], |row| {
                Ok((row.get::<_, usize>(0)?, row.get::<_, Vec<u8>>(1)?))
            })
            .context(AnalysisDatabaseSnafu {
                operation: "read saved change targets",
            })?;
        let mut count = 0;
        for row in rows {
            control.check()?;
            let (slot, bytes) = row.context(AnalysisDatabaseSnafu {
                operation: "decode saved change target",
            })?;
            if slot != count || bytes.is_empty() {
                return Err(Code::Invalid.error("saved target slot"));
            }
            changes
                .targets
                .get_mut(slot)
                .ok_or_else(|| Code::Invalid.error("saved target shape"))?
                .input
                .data
                .arrow_ipc = bytes;
            count += 1;
        }
        if count != changes.targets.len() {
            return Err(Code::Missing.error("saved change targets"));
        }
        Ok(Some(changes))
    }
}

impl RecordChanges {
    pub(super) fn check_header(&self) -> Result<()> {
        if self
            .targets
            .iter()
            .any(|target| !target.input.data.arrow_ipc.is_empty())
        {
            return Err(Code::Invalid.error("inline managed target payload"));
        }
        Ok(())
    }

    pub(super) fn decoding_bytes(&self, control: &AnalysisReadControl) -> Result<usize> {
        self.targets.iter().try_fold(
            std::mem::size_of::<Self>()
                .saturating_add(
                    self.targets
                        .capacity()
                        .saturating_mul(std::mem::size_of::<RecordTarget>()),
                )
                .saturating_add(
                    self.base
                        .as_ref()
                        .map_or(0, |base| base.result_id.capacity()),
                ),
            |bytes, target| {
                control.check()?;
                let decoded = sdk::wire::Dataset::decoding_bytes(&target.input.data.arrow_ipc)
                    .context(crate::AnalysisContractSnafu)?;
                bytes
                    .checked_add(target.input.allocated_bytes())
                    .and_then(|bytes| bytes.checked_add(decoded))
                    .ok_or_else(|| Code::Limit.error("saved target memory"))
            },
        )
    }

    pub(super) fn decode(
        &self,
        model: &sdk::Model,
        control: &AnalysisReadControl,
    ) -> Result<ManagedChanges> {
        let targets = self
            .targets
            .iter()
            .map(|target| {
                control.check()?;
                let input = &target.input;
                let port = model
                    .inputs
                    .iter()
                    .find(|port| port.port.name == input.data.name)
                    .ok_or_else(|| Code::Invalid.error("saved target port"))?;
                let mut data = input
                    .data
                    .decode(&port.port.schema)
                    .context(crate::AnalysisContractSnafu)?;
                if target.batches == 0 && data.rows() == 0 {
                    data.batches.clear();
                }
                if data.rows() != target.rows || data.batches.len() != target.batches {
                    return Err(Code::Invalid.error("saved target rows"));
                }
                Ok(sdk::Input {
                    data,
                    revision: input.revision.clone(),
                    coverage: input.coverage.clone(),
                })
            })
            .collect::<Result<_>>()?;
        Ok(ManagedChanges {
            base: self.base.clone(),
            targets,
        })
    }
}
