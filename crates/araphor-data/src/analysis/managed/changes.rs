use araphor_analysis_sdk as sdk;
use duckdb::Connection;
use snafu::ResultExt as _;

use super::model::*;
use crate::{AnalysisReadControl, AnalysisStore, PackageErrorCodeV1 as Code, Result};

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
        let reset = contract
            .is_reset(returned.evaluation)
            .context(crate::AnalysisContractSnafu)?;
        let expected = input.attempt.prior_result(returned.call);
        if reset {
            if changes.base.is_some() {
                return Err(Code::Invalid.error("reset change base"));
            }
        } else if changes.base.as_ref() != expected || expected.is_none() {
            return Err(Code::Conflict.error("managed change base"));
        }
        Ok(Some(RecordChanges {
            base: changes.base.clone(),
        }))
    }

    pub(super) fn check_change_record(
        reader: &Connection,
        tenant: [u8; 16],
        record: &Record,
        model: &sdk::Model,
        attempt: &Attempt,
    ) -> Result<()> {
        let (Some(_), Some(changes)) = (&model.change_inputs, &record.changes) else {
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
        if let Some(base) = &changes.base {
            let expected = attempt
                .capture
                .prior
                .get(&record.call)
                .and_then(Option::as_ref);
            if Some(base) != expected
                || base.commit_revision == 0
                || base.commit_revision >= attempt.registered
            {
                return Err(Code::Conflict.error("managed historical base"));
            }
            let (old, _, revision) = Self::managed_header_from(reader, tenant, &base.result_id)?;
            if old.call != record.call
                || old.instance != record.instance
                || old.declaration != record.declaration
                || revision != base.commit_revision
                || old.changes.is_none()
            {
                return Err(Code::Invalid.error("managed historical call"));
            }
        }
        Ok(())
    }

    pub(super) fn managed_changes_from(
        _reader: &Connection,
        _id: &str,
        record: &Record,
        control: &AnalysisReadControl,
    ) -> Result<Option<RecordChanges>> {
        control.check()?;
        Ok(record.changes.clone())
    }
}

impl RecordChanges {
    pub(super) fn decoding_bytes(&self, control: &AnalysisReadControl) -> Result<usize> {
        control.check()?;
        Ok(std::mem::size_of::<Self>().saturating_add(
            self.base
                .as_ref()
                .map_or(0, |base| base.result_id.capacity()),
        ))
    }

    pub(super) fn decode(
        &self,
        _model: &sdk::Model,
        control: &AnalysisReadControl,
    ) -> Result<ManagedChanges> {
        control.check()?;
        Ok(ManagedChanges {
            base: self.base.clone(),
        })
    }
}
