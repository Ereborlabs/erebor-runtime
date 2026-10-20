use araphor_analysis_builtins::{discovery::Counts, Rows};
use araphor_data::{
    BehaviorDisplayGroupV1, BehaviorSnapshotV1, DiscoveryComparisonV1, DiscoveryInputManifestV1,
    DiscoveryProofKindV1, DiscoveryRecordedResultV1, DiscoveryReviewedBaselineV1,
    DiscoverySnapshotRowV1, PackageErrorCodeV1 as Code, DISCOVERY_SCHEMA_VERSION,
};
use araphor_query::definition::{CallResult, PackageCall};
use serde::de::DeserializeOwned;
use snafu::ResultExt as _;

use super::DiscoveryOwner;
use crate::Result;

impl DiscoveryOwner {
    pub fn recorded_result(
        input: &DiscoveryInputManifestV1,
        call: &PackageCall,
        result: &CallResult,
    ) -> Result<DiscoveryRecordedResultV1> {
        Self::result_scope(call, result, input.tenant_id)?;
        let recorded = Self::snapshot_result(
            call,
            result,
            input.tenant_id,
            &input.source_revision,
            input.proof_kind,
            true,
        )?;
        input.validate_result(&recorded)?;
        Ok(recorded)
    }

    pub fn merge_result(
        current: &BehaviorSnapshotV1,
        next: &BehaviorSnapshotV1,
        call: &PackageCall,
        result: &CallResult,
    ) -> Result<BehaviorSnapshotV1> {
        Self::result_scope(call, result, current.tenant_id)?;
        let snapshot = Self::snapshot_result(
            call,
            result,
            current.tenant_id,
            &current.source_revision,
            current.proof_kind,
            false,
        )?
        .snapshot;
        current.validate_merge(next, &snapshot)?;
        Ok(snapshot)
    }

    pub fn group_result(
        current: &BehaviorSnapshotV1,
        call: &PackageCall,
        result: &CallResult,
    ) -> Result<Vec<BehaviorDisplayGroupV1>> {
        Self::result_scope(call, result, current.tenant_id)?;
        let mut groups: Vec<BehaviorDisplayGroupV1> =
            Self::result_rows(call, result, call.output())?;
        groups.sort_by(|left, right| left.key.cmp(&right.key));
        current.validate_groups(&groups)?;
        Ok(groups)
    }

    pub fn comparison_result(
        current: &BehaviorSnapshotV1,
        baseline: &DiscoveryReviewedBaselineV1,
        groups: &[BehaviorDisplayGroupV1],
        prior: &[BehaviorDisplayGroupV1],
        call: &PackageCall,
        result: &CallResult,
    ) -> Result<DiscoveryComparisonV1> {
        Self::result_scope(call, result, current.tenant_id)?;
        if baseline.reviewer.is_empty()
            || baseline.reviewer.len() > 256
            || baseline.reviewed_utc_ns == 0
        {
            return Err(araphor_data::DiscoveryInvalidSnafu {
                field: "reviewed baseline",
            }
            .build()
            .into());
        }
        if current.tenant_id != baseline.snapshot.tenant_id {
            return Err(araphor_data::DiscoveryConflictSnafu {
                kind: "baseline tenant",
            }
            .build()
            .into());
        }
        current.validate_groups(groups)?;
        baseline.snapshot.validate_groups(prior)?;
        let comparison = Self::one_result(Self::result_rows(call, result, call.output())?)?;
        current.validate_comparison(&baseline.snapshot, groups, prior, &comparison)?;
        Ok(comparison)
    }

    fn result_scope(call: &PackageCall, result: &CallResult, tenant: [u8; 16]) -> Result<()> {
        if call.tenant() != tenant || !result.belongs_to(call) {
            return Err(Code::Denied.error("discovery call result").into());
        }
        Ok(())
    }

    fn snapshot_result(
        call: &PackageCall,
        result: &CallResult,
        tenant: [u8; 16],
        revision: &str,
        proof: DiscoveryProofKindV1,
        duplicates: bool,
    ) -> Result<DiscoveryRecordedResultV1> {
        let recorded = if Self::result_model(call)?
            .outputs
            .iter()
            .any(|port| port.name == "counts")
        {
            let counts: Counts = Self::one_result(Self::result_rows(call, result, "counts")?)?;
            let mut snapshot = BehaviorSnapshotV1 {
                schema_version: DISCOVERY_SCHEMA_VERSION,
                tenant_id: tenant,
                source_revision: revision.into(),
                proof_kind: proof,
                accepted_records: counts.accepted,
                included_records: counts.included,
                unresolved_records: counts.unresolved,
                excluded_records: counts.excluded,
                atoms: Self::result_rows(call, result, "atoms")?,
                coverage: Self::result_rows(call, result, "coverage")?,
                unresolved: Self::result_rows(call, result, "unresolved")?,
                excluded: Self::result_rows(call, result, "excluded")?,
                lifecycle: Self::result_rows(call, result, "lifecycle")?,
            };
            snapshot
                .atoms
                .sort_by(|left, right| left.key.cmp(&right.key));
            snapshot.coverage.sort();
            snapshot.validate()?;
            DiscoveryRecordedResultV1 {
                snapshot,
                duplicate_deliveries: counts.duplicates,
            }
        } else {
            let (_, data) = Self::result_data(call, result, call.output())?;
            let mut rows = Vec::new();
            let mut duplicate_rows = Vec::new();
            for batch in &data.batches {
                let indices = DiscoverySnapshotRowV1::schema()
                    .fields()
                    .iter()
                    .map(|field| {
                        batch
                            .schema()
                            .index_of(field.name())
                            .map_err(araphor_analysis_sdk::Error::from)
                    })
                    .collect::<std::result::Result<Vec<_>, _>>()
                    .context(araphor_data::AnalysisContractSnafu)?;
                let projected = batch
                    .project(&indices)
                    .map_err(araphor_analysis_sdk::Error::from)
                    .context(araphor_data::AnalysisContractSnafu)?;
                rows.extend(
                    serde_arrow::from_record_batch::<Vec<DiscoverySnapshotRowV1>>(&projected)
                        .context(crate::error::ArrowSnafu)?,
                );
                if duplicates {
                    let column = batch
                        .column_by_name("duplicate_deliveries")
                        .and_then(|array| {
                            array
                                .as_any()
                                .downcast_ref::<araphor_analysis_sdk::arrow_array::UInt64Array>()
                        })
                        .ok_or_else(|| Code::Invalid.error("discovery duplicate count"))?;
                    duplicate_rows.extend(column.iter());
                }
            }
            let snapshot = Self::one_result(rows)?.into_snapshot()?;
            let duplicate_deliveries = if duplicates {
                Self::one_result(duplicate_rows)?
                    .ok_or_else(|| Code::Invalid.error("discovery duplicate count"))?
            } else {
                0
            };
            DiscoveryRecordedResultV1 {
                snapshot,
                duplicate_deliveries,
            }
        };
        let snapshot = &recorded.snapshot;
        if snapshot.tenant_id != tenant
            || snapshot.source_revision != revision
            || snapshot.proof_kind != proof
        {
            return Err(araphor_data::DiscoveryConflictSnafu {
                kind: "snapshot source",
            }
            .build()
            .into());
        }
        Ok(recorded)
    }

    fn result_model(call: &PackageCall) -> Result<&araphor_analysis_sdk::Model> {
        call.descriptor()
            .exports
            .iter()
            .find(|model| model.name == call.export())
            .ok_or_else(|| Code::Invalid.error("discovery export").into())
    }

    fn result_data<'a>(
        call: &'a PackageCall,
        result: &'a CallResult,
        name: &str,
    ) -> Result<(
        &'a araphor_analysis_sdk::Port,
        &'a araphor_analysis_sdk::Dataset,
    )> {
        let port = Self::result_model(call)?
            .outputs
            .iter()
            .find(|port| port.name == name)
            .ok_or_else(|| Code::Invalid.error("discovery output port"))?;
        let data = result
            .output()
            .datasets
            .iter()
            .find(|data| data.name == name)
            .ok_or_else(|| Code::Invalid.error("discovery output"))?;
        if data
            .batches
            .iter()
            .any(|batch| batch.schema().as_ref() != &port.schema)
        {
            return Err(Code::Invalid.error("discovery output schema").into());
        }
        Ok((port, data))
    }

    fn result_rows<T: DeserializeOwned>(
        call: &PackageCall,
        result: &CallResult,
        name: &str,
    ) -> Result<Vec<T>> {
        let (port, data) = Self::result_data(call, result, name)?;
        if port.schema.fields().len() == 1
            && port
                .schema
                .field(0)
                .metadata()
                .get("araphor.encoding")
                .is_some_and(|encoding| encoding == "serde-json-v1")
        {
            return Rows::decode(port, data, result.evaluation().context.limits)
                .context(araphor_data::AnalysisContractSnafu)
                .map_err(Into::into);
        }
        let mut rows = Vec::new();
        for batch in &data.batches {
            rows.extend(
                serde_arrow::from_record_batch::<Vec<T>>(batch)
                    .context(crate::error::ArrowSnafu)?,
            );
        }
        Ok(rows)
    }

    fn one_result<T>(mut rows: Vec<T>) -> Result<T> {
        if rows.len() != 1 {
            return Err(Code::Invalid.error("discovery output row").into());
        }
        Ok(rows.remove(0))
    }
}

#[cfg(test)]
mod tests;
