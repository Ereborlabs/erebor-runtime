use duckdb::{params, Connection, OptionalExt as _};
use serde::{Deserialize, Serialize};
use snafu::ResultExt as _;

use super::super::AnalysisStore;
use super::{model::Attempt, ManagedExit, ManagedInstance, ManagedStatus};
use crate::{
    AnalysisDatabaseSnafu, AnalysisReadControl, AnalysisSelectionV1, PackageErrorCodeV1 as Code,
    PackageReadinessV1, Result,
};

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Failure {
    pub code: Code,
    pub progress: u64,
    pub revision: u64,
}

impl Failure {
    fn decode(
        bytes: Option<Vec<u8>>,
        instance: &ManagedInstance,
        head: u64,
    ) -> Result<Option<Self>> {
        let failure: Option<Self> = bytes
            .map(|bytes| serde_json::from_slice(&bytes).context(crate::PackageEncodingSnafu))
            .transpose()?;
        if failure.as_ref().is_some_and(|failure| {
            failure.progress > instance.progress
                || failure.revision <= instance.generation
                || failure.revision <= failure.progress
                || failure.revision > head
        }) {
            return Err(Code::Invalid.error("managed failure status"));
        }
        Ok(failure)
    }
}

impl AnalysisStore {
    pub fn managed_status(
        &self,
        selection: &AnalysisSelectionV1,
        id: &str,
        control: &AnalysisReadControl,
    ) -> Result<ManagedStatus> {
        let mut reader = self.reader_until(control)?;
        control.run(&mut reader, |reader| {
            let (values, bytes, head) = reader.query_row(
                "SELECT i.spec, i.authority, i.generation, i.progress, i.running, i.lifecycle, i.failure, m.commit_revision FROM managed_instances i CROSS JOIN store_meta m WHERE i.tenant_id = ? AND i.instance_id = ?",
                params![selection.tenant_id.as_slice(), id], |row| Ok((
                    (row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?),
                    row.get::<_, Option<Vec<u8>>>(6)?, row.get::<_, u64>(7)?)),
            ).optional().context(AnalysisDatabaseSnafu { operation: "read managed status" })?
                .ok_or_else(|| Code::Missing.error("managed status instance"))?;
            let instance = Self::managed_row(selection.tenant_id, id, values)?;
            instance.grant.permitted_by(selection)?;
            Self::check_managed_pending(reader, selection.tenant_id, id)?;
            let failure = Failure::decode(bytes, &instance, head)?
                .filter(|failure| failure.progress == instance.progress);
            let (readiness, status_progress) = if let Some(failure) = failure {
                (PackageReadinessV1::Failed { code: failure.code, field: "model evaluation".into() }, failure.progress)
            } else {
                (if instance.running { PackageReadinessV1::Ready } else { PackageReadinessV1::Inactive }, instance.progress)
            };
            Ok(ManagedStatus { instance, readiness, status_progress })
        })
    }

    pub(super) fn validate_managed_failure(
        reader: &Connection,
        instance: &ManagedInstance,
    ) -> Result<Option<Failure>> {
        let (bytes, head) = reader.query_row(
            "SELECT failure, commit_revision FROM managed_instances CROSS JOIN store_meta WHERE tenant_id = ? AND instance_id = ?",
            params![instance.spec.tenant.as_slice(), instance.spec.id],
            |row| Ok((row.get::<_, Option<Vec<u8>>>(0)?, row.get::<_, u64>(1)?)),
        ).context(AnalysisDatabaseSnafu { operation: "read recovered managed failure" })?;
        let Some(failure) = Failure::decode(bytes, instance, head)? else {
            return Ok(None);
        };
        let bytes: Option<Vec<u8>> = reader.query_row(
            "SELECT contract FROM managed_attempts WHERE tenant_id = ? AND instance_id = ? AND completed = ?",
            params![instance.spec.tenant.as_slice(), instance.spec.id, failure.revision], |row| row.get(0),
        ).optional().context(AnalysisDatabaseSnafu { operation: "read managed failure attempt" })?;
        if let Some(bytes) = bytes {
            let attempt: Attempt =
                serde_json::from_slice(&bytes).context(crate::PackageEncodingSnafu)?;
            if attempt.terminal.is_none_or(|terminal| {
                terminal.exit != ManagedExit::Failed(failure.code)
                    || terminal.revision != failure.revision
            }) || attempt.capture.generation != instance.generation
                || attempt.capture.progress != failure.progress
            {
                return Err(Code::Invalid.error("managed terminal failure status"));
            }
        } else if failure.code != Code::Denied
            || failure.revision > instance.lifecycle
            || (failure.revision == instance.lifecycle && instance.running)
        {
            return Err(Code::Invalid.error("managed idle failure status"));
        }
        if failure.progress != 0 {
            let bytes: Vec<u8> = reader.query_row(
                "SELECT contract FROM managed_attempts WHERE tenant_id = ? AND instance_id = ? AND completed = ?",
                params![instance.spec.tenant.as_slice(), instance.spec.id, failure.progress], |row| row.get(0),
            ).context(AnalysisDatabaseSnafu { operation: "read managed failure progress" })?;
            let attempt: Attempt =
                serde_json::from_slice(&bytes).context(crate::PackageEncodingSnafu)?;
            if attempt
                .receipt
                .as_ref()
                .is_none_or(|receipt| receipt.commit_revision != failure.progress)
            {
                return Err(Code::Invalid.error("managed failure progress"));
            }
        }
        Ok(Some(failure))
    }
}
