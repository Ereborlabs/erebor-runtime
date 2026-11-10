use araphor_analysis_sdk as sdk;
use duckdb::Connection;
use snafu::ResultExt as _;

use super::model::*;
use crate::{AnalysisReadControl, AnalysisStore, PackageErrorCodeV1 as Code, Result};

impl AnalysisStore {
    pub fn managed_changes(
        &self,
        reference: &ManagedAttempt,
        call: u64,
        control: &AnalysisReadControl,
    ) -> Result<Option<ManagedChanges>> {
        let instance = reference.instance();
        let receipt = reference
            .receipt()
            .ok_or_else(|| Code::Invalid.error("managed change receipt"))?;
        let result = receipt
            .results
            .get(&call)
            .ok_or_else(|| Code::Missing.error("managed change call"))?;
        if reference.terminal().is_some()
            || result.commit_revision != receipt.commit_revision
            || receipt.selected.commit_revision != receipt.commit_revision
        {
            return Err(Code::Conflict.error("managed change publication"));
        }
        let mut reader = self.reader_until(control)?;
        control.run(&mut reader, |reader| {
            let (record, revision) =
                Self::managed_meta_from(reader, instance.spec.tenant, &result.result_id)?;
            if revision != result.commit_revision
                || record.call != call
                || record.instance != instance.spec.id
                || record.attempt != reference.request().id
            {
                return Err(Code::Conflict.error("managed change reference"));
            }
            let (_, saved, spec) = Self::validate_managed_header(
                reader,
                instance.spec.tenant,
                &result.result_id,
                &record,
                revision,
            )?;
            if saved != reference.0
                || spec != instance.spec
                || Self::managed_edges(reader, instance.spec.tenant, &result.result_id)?
                    != record.dependencies
            {
                return Err(Code::Conflict.error("managed change owner"));
            }
            saved
                .capture
                .grant
                .permitted_by(&instance.grant.selection)?;
            Ok(record
                .changes
                .map(|changes| ManagedChanges { base: changes.base }))
        })
    }

    pub(super) fn check_change_record(
        reader: &Connection,
        tenant: [u8; 16],
        record: &Record,
        declaration: &ManagedCall,
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
            let (old, revision) = Self::managed_meta_from(reader, tenant, &base.result_id)?;
            let (_, owner) =
                Self::managed_call_owner(reader, tenant, &base.result_id, revision, &old)?;
            if old.call != record.call
                || old.instance != record.instance
                || owner.manifest.calls.get(&record.call) != Some(declaration)
                || revision != base.commit_revision
                || old.changes.is_none()
            {
                return Err(Code::Invalid.error("managed historical call"));
            }
        }
        Ok(())
    }
}

impl RecordChanges {
    pub(in crate::analysis) fn prepare(
        attempt: &ManagedAttempt,
        call: u64,
        evaluation: &sdk::Evaluation,
        changes: Option<&ManagedChanges>,
        model: &sdk::Model,
    ) -> Result<Option<RecordChanges>> {
        let (Some(contract), Some(changes)) = (&model.change_inputs, changes) else {
            return if model.change_inputs.is_some() || changes.is_some() {
                Err(Code::Invalid.error("managed change inputs"))
            } else {
                Ok(None)
            };
        };
        let reset = contract
            .is_reset(evaluation)
            .context(crate::AnalysisContractSnafu)?;
        let expected = attempt.prior_result(call);
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
}
