use std::collections::BTreeSet;
use std::io::Cursor;
use std::sync::Arc;

use araphor_analysis_builtins::discovery::DiscoveryRecordIdV1;
use araphor_analysis_builtins::graph::{
    ContextSensitivityV1, DeclaredFindingReasonV1, FindingReasonV1, FindingSeverityV1,
    FindingStateV1, FindingV1, GraphSubjectKeyV1,
};
use duckdb::arrow::array::{
    builder::{LargeBinaryBuilder, LargeListBuilder, LargeStringBuilder, UInt64Builder},
    ArrayRef, Int64Array, LargeBinaryArray, LargeStringArray, RecordBatch, UInt64Array,
};
use duckdb::arrow::datatypes::{Field, Schema};
use duckdb::{params, types::Value, Appender, Connection, Row};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sha2::{Digest, Sha256};
use snafu::ResultExt as _;

use crate::error::{DatabaseSnafu, DecodingSnafu, EncodingSnafu, InvalidSnafu};
use crate::Result;

#[cfg(test)]
mod tests;

pub struct FindingRows;

pub struct FindingRefs<'a> {
    pub finding: &'a FindingV1,
    pub subject: u64,
    pub evidence: Vec<u64>,
}

#[derive(Deserialize, Serialize)]
enum StoredReason<T> {
    Builtin(String),
    Declared(T),
}

impl FindingRows {
    pub const SCHEMA: &'static str = include_str!("findings.sql");
    pub const COLUMNS: &'static str = "ordinal, tenant_id, finding_id, package_id, package_version,
        subject_ref, state, window_start_utc_ns, window_end_utc_ns, evidence_refs,
        required_coverage_interval_ids, policy_provenance, effects, reason, severity,
        sensitivity, required_action, limits";

    pub fn validate(writer: &Connection) -> Result<()> {
        let overlaps: bool = writer
            .query_row(
                "WITH ranges AS (
                    SELECT m.lineage_id, f.tenant_id, f.finding_id,
                        m.valid_from, m.valid_to,
                        lag(m.valid_from) OVER part AS prior_from,
                        lag(m.valid_to) OVER part AS prior_to
                    FROM graph_finding_membership m
                    JOIN graph_finding_values f USING (value_id)
                    WINDOW part AS (PARTITION BY m.lineage_id, f.tenant_id, f.finding_id
                        ORDER BY m.valid_from, m.value_id)
                ) SELECT EXISTS(SELECT 1 FROM ranges WHERE prior_from IS NOT NULL
                    AND (prior_to IS NULL OR prior_to > valid_from))",
                [],
                |row| row.get(0),
            )
            .context(DatabaseSnafu {
                operation: "validate graph finding membership",
            })?;
        if overlaps {
            return InvalidSnafu {
                field: "overlapping graph finding membership",
            }
            .fail();
        }
        Ok(())
    }

    pub fn apply(
        writer: &Connection,
        tenant: [u8; 16],
        lineage: u64,
        revision: u64,
        findings: &[FindingRefs<'_>],
        batch_rows: usize,
    ) -> Result<()> {
        if batch_rows == 0 {
            return InvalidSnafu {
                field: "graph finding batch size",
            }
            .fail();
        }
        let mut next: u64 = writer
            .query_row(
                "SELECT coalesce(max(value_id), 0) FROM graph_finding_values",
                [],
                |row| row.get(0),
            )
            .context(DatabaseSnafu {
                operation: "read next graph finding value ID",
            })?;
        let mut selected = BTreeSet::new();
        let mut names = BTreeSet::new();
        let mut added = Vec::new();
        let mut candidates = writer
            .prepare(
                "SELECT value_id, tenant_id, finding_id, package_id, package_version,
                subject_ref, state, window_start_utc_ns, window_end_utc_ns, evidence_refs,
                required_coverage_interval_ids, policy_provenance, effects, reason, severity,
                sensitivity, required_action, limits
                FROM graph_finding_values WHERE tenant_id = ? AND finding_id = ?
                    AND value_hash = ?",
            )
            .context(DatabaseSnafu {
                operation: "prepare graph finding value lookup",
            })?;
        for references in findings {
            let finding = references.finding;
            if finding.tenant_id != tenant
                || references.evidence.len() != finding.evidence.len()
                || !names.insert(finding.finding_id.as_str())
            {
                return InvalidSnafu {
                    field: "graph finding identity",
                }
                .fail();
            }
            let hash = Self::value_hash(references)?;
            let mut rows = candidates
                .query(params![
                    tenant.as_slice(),
                    &finding.finding_id,
                    hash.as_slice()
                ])
                .context(DatabaseSnafu {
                    operation: "read graph finding values",
                })?;
            let mut value_id = None;
            while let Some(row) = rows.next().context(DatabaseSnafu {
                operation: "advance graph finding values",
            })? {
                let ids = Self::references(row)?;
                let value =
                    Self::decode(row, finding.subject_id.clone(), finding.evidence.clone())?;
                if ids.0 == references.subject && ids.1 == references.evidence && value == *finding
                {
                    if value_id.is_some() {
                        return InvalidSnafu {
                            field: "duplicate graph finding value",
                        }
                        .fail();
                    }
                    value_id = Some(Self::column(row, 0)?);
                }
            }
            let id = match value_id {
                Some(id) => id,
                None => {
                    next = next.checked_add(1).ok_or_else(|| {
                        InvalidSnafu {
                            field: "graph finding value ID",
                        }
                        .build()
                    })?;
                    added.push((next, references, hash));
                    next
                }
            };
            if !selected.insert(id) {
                return InvalidSnafu {
                    field: "graph finding membership",
                }
                .fail();
            }
        }
        drop(candidates);
        if !added.is_empty() {
            let mut appender = writer
                .appender("graph_finding_values")
                .context(DatabaseSnafu {
                    operation: "prepare graph finding value insert",
                })?;
            for rows in added.chunks(batch_rows) {
                Self::insert(&mut appender, rows)?;
            }
            appender.flush().context(DatabaseSnafu {
                operation: "flush graph finding values",
            })?;
        }
        let mut active = BTreeSet::new();
        let mut identities = BTreeSet::new();
        let mut statement = writer
            .prepare(
                "SELECT m.value_id, f.tenant_id, f.finding_id
                FROM graph_finding_membership m
                LEFT JOIN graph_finding_values f USING (value_id)
                WHERE m.lineage_id = ? AND m.valid_to IS NULL",
            )
            .context(DatabaseSnafu {
                operation: "prepare active graph findings",
            })?;
        let mut rows = statement.query(params![lineage]).context(DatabaseSnafu {
            operation: "read active graph findings",
        })?;
        while let Some(row) = rows.next().context(DatabaseSnafu {
            operation: "advance active graph findings",
        })? {
            let id: u64 = Self::column(row, 0)?;
            let stored: Option<Vec<u8>> = Self::column(row, 1)?;
            let name: Option<String> = Self::column(row, 2)?;
            if stored.as_deref() != Some(tenant.as_slice())
                || name
                    .as_ref()
                    .is_none_or(|name| !identities.insert(name.clone()))
                || !active.insert(id)
            {
                return InvalidSnafu {
                    field: "active graph finding identity",
                }
                .fail();
            }
        }
        drop(rows);
        drop(statement);
        for id in active.difference(&selected) {
            let changed = writer
                .execute(
                    "UPDATE graph_finding_membership SET valid_to = ?
                    WHERE lineage_id = ? AND value_id = ? AND valid_to IS NULL",
                    params![revision, lineage, id],
                )
                .context(DatabaseSnafu {
                    operation: "close graph finding membership",
                })?;
            if changed != 1 {
                return InvalidSnafu {
                    field: "graph finding membership",
                }
                .fail();
            }
        }
        let mut appender = writer
            .appender("graph_finding_membership")
            .context(DatabaseSnafu {
                operation: "prepare graph finding membership insert",
            })?;
        for id in selected.difference(&active) {
            appender
                .append_row(params![lineage, id, revision, None::<u64>])
                .context(DatabaseSnafu {
                    operation: "insert graph finding membership",
                })?;
        }
        appender.flush().context(DatabaseSnafu {
            operation: "flush graph finding membership",
        })?;
        Ok(())
    }

    fn value_hash(references: &FindingRefs<'_>) -> Result<[u8; 32]> {
        let value =
            serde_value::to_value(&(references.finding, references.subject, &references.evidence))
                .map_err(|_| {
                    InvalidSnafu {
                        field: "graph finding canonical value",
                    }
                    .build()
                })?;
        let mut digest = Sha256::new();
        value
            .serialize(&mut rmp_serde::Serializer::new(&mut digest))
            .context(EncodingSnafu)?;
        let mut hash = [0; 32];
        hash.copy_from_slice(&digest.finalize());
        Ok(hash)
    }

    fn insert(writer: &mut Appender<'_>, rows: &[(u64, &FindingRefs<'_>, [u8; 32])]) -> Result<()> {
        let mut offsets = [0usize; 6];
        for (_, references, _) in rows {
            let finding = references.finding;
            let coverage_bytes = finding
                .required_coverage_interval_ids
                .len()
                .checked_mul(16)
                .ok_or_else(|| {
                    InvalidSnafu {
                        field: "graph finding array offsets",
                    }
                    .build()
                })?;
            let limit_bytes = finding.limits.iter().try_fold(0usize, |total, value| {
                total.checked_add(value.len()).ok_or_else(|| {
                    InvalidSnafu {
                        field: "graph finding array offsets",
                    }
                    .build()
                })
            })?;
            let strings = finding
                .finding_id
                .len()
                .checked_add(finding.package_id.len())
                .and_then(|length| {
                    length.checked_add(finding.required_action.as_ref().map_or(0, String::len))
                })
                .ok_or_else(|| {
                    InvalidSnafu {
                        field: "graph finding array offsets",
                    }
                    .build()
                })?;
            for (total, next) in offsets.iter_mut().zip([
                references.evidence.len(),
                finding.required_coverage_interval_ids.len(),
                coverage_bytes,
                finding.limits.len(),
                limit_bytes,
                strings,
            ]) {
                *total = total.checked_add(next).ok_or_else(|| {
                    InvalidSnafu {
                        field: "graph finding array offsets",
                    }
                    .build()
                })?;
            }
        }
        if offsets
            .into_iter()
            .any(|count| i64::try_from(count).is_err())
        {
            return InvalidSnafu {
                field: "graph finding array offsets",
            }
            .fail();
        }
        let mut evidence = LargeListBuilder::new(UInt64Builder::new());
        let mut coverage = LargeListBuilder::new(LargeBinaryBuilder::new());
        let mut limits = LargeListBuilder::new(LargeStringBuilder::new());
        let mut provenance = LargeBinaryBuilder::new();
        let mut effects = LargeBinaryBuilder::new();
        let mut reasons = LargeBinaryBuilder::new();
        for (_, references, _) in rows {
            let finding = references.finding;
            evidence.values().append_slice(&references.evidence);
            evidence.append(true);
            for id in &finding.required_coverage_interval_ids {
                coverage.values().append_value(id);
            }
            coverage.append(true);
            for value in &finding.limits {
                limits.values().append_value(value);
            }
            limits.append(true);
            provenance.append_value(Self::encode(&finding.policy_provenance)?);
            effects.append_value(Self::encode(&finding.effects)?);
            reasons.append_value(Self::reason(&finding.reason)?);
        }
        let arrays: Vec<ArrayRef> = vec![
            Arc::new(UInt64Array::from_iter_values(
                rows.iter().map(|(id, _, _)| *id),
            )),
            Arc::new(LargeBinaryArray::from_iter_values(
                rows.iter().map(|(_, row, _)| row.finding.tenant_id),
            )),
            Arc::new(LargeStringArray::from_iter_values(
                rows.iter()
                    .map(|(_, row, _)| row.finding.finding_id.as_str()),
            )),
            Arc::new(LargeStringArray::from_iter_values(
                rows.iter()
                    .map(|(_, row, _)| row.finding.package_id.as_str()),
            )),
            Arc::new(UInt64Array::from_iter_values(
                rows.iter().map(|(_, row, _)| row.finding.package_version),
            )),
            Arc::new(UInt64Array::from_iter_values(
                rows.iter().map(|(_, row, _)| row.subject),
            )),
            Arc::new(LargeStringArray::from_iter_values(
                rows.iter()
                    .map(|(_, row, _)| Self::state_label(row.finding.state)),
            )),
            Arc::new(Int64Array::from_iter_values(
                rows.iter()
                    .map(|(_, row, _)| row.finding.window_start_utc_ns),
            )),
            Arc::new(Int64Array::from_iter_values(
                rows.iter().map(|(_, row, _)| row.finding.window_end_utc_ns),
            )),
            Arc::new(evidence.finish()),
            Arc::new(coverage.finish()),
            Arc::new(provenance.finish()),
            Arc::new(effects.finish()),
            Arc::new(reasons.finish()),
            Arc::new(LargeStringArray::from_iter_values(
                rows.iter()
                    .map(|(_, row, _)| Self::severity_label(row.finding.severity)),
            )),
            Arc::new(LargeStringArray::from_iter_values(
                rows.iter()
                    .map(|(_, row, _)| <&str>::from(row.finding.sensitivity)),
            )),
            Arc::new(LargeStringArray::from_iter(
                rows.iter()
                    .map(|(_, row, _)| row.finding.required_action.as_deref()),
            )),
            Arc::new(limits.finish()),
            Arc::new(LargeBinaryArray::from_iter_values(
                rows.iter().map(|(_, _, hash)| hash.as_slice()),
            )),
        ];
        let fields = Self::COLUMNS
            .split(',')
            .chain(std::iter::once("value_hash"))
            .zip(&arrays)
            .enumerate()
            .map(|(index, (name, array))| {
                Field::new(
                    if index == 0 { "value_id" } else { name.trim() },
                    array.data_type().clone(),
                    index == 16,
                )
            })
            .collect::<Vec<_>>();
        let batch = RecordBatch::try_new(Arc::new(Schema::new(fields)), arrays).map_err(|_| {
            InvalidSnafu {
                field: "graph finding record batch",
            }
            .build()
        })?;
        writer.append_record_batch(batch).context(DatabaseSnafu {
            operation: "insert graph finding values",
        })?;
        Ok(())
    }

    pub fn references(row: &Row<'_>) -> Result<(u64, Vec<u64>)> {
        let subject = Self::column(row, 5)?;
        Ok((subject, Self::evidence_references(row, 9)?))
    }

    pub fn evidence_references(row: &Row<'_>, index: usize) -> Result<Vec<u64>> {
        Self::list_column(row, index)?
            .into_iter()
            .map(|value| match value {
                Value::UBigInt(value) => Ok(value),
                _ => InvalidSnafu {
                    field: "graph finding evidence reference",
                }
                .fail(),
            })
            .collect()
    }

    pub fn decode(
        row: &Row<'_>,
        subject: GraphSubjectKeyV1,
        evidence: Vec<DiscoveryRecordIdV1>,
    ) -> Result<FindingV1> {
        let tenant: Vec<u8> = Self::column(row, 1)?;
        let sensitivity: String = Self::column(row, 15)?;
        Ok(FindingV1 {
            tenant_id: tenant.try_into().map_err(|_| {
                InvalidSnafu {
                    field: "finding tenant bytes",
                }
                .build()
            })?,
            finding_id: Self::column(row, 2)?,
            package_id: Self::column(row, 3)?,
            package_version: Self::column(row, 4)?,
            subject_id: subject,
            state: Self::label_column(row, 6)?,
            window_start_utc_ns: Self::column(row, 7)?,
            window_end_utc_ns: Self::column(row, 8)?,
            evidence,
            required_coverage_interval_ids: Self::list_column(row, 10)?
                .into_iter()
                .map(|value| match value {
                    Value::Blob(bytes) => bytes.try_into().map_err(|_| {
                        InvalidSnafu {
                            field: "graph finding coverage bytes",
                        }
                        .build()
                    }),
                    _ => InvalidSnafu {
                        field: "graph finding coverage bytes",
                    }
                    .fail(),
                })
                .collect::<Result<_>>()?,
            policy_provenance: Self::binary_column(row, 11)?,
            effects: Self::binary_column(row, 12)?,
            reason: Self::restore_reason(Self::binary_column(row, 13)?)?,
            severity: Self::label_column(row, 14)?,
            sensitivity: ContextSensitivityV1::try_from(sensitivity.as_str()).map_err(|_| {
                InvalidSnafu {
                    field: "finding sensitivity",
                }
                .build()
            })?,
            required_action: Self::column(row, 16)?,
            limits: Self::list_column(row, 17)?
                .into_iter()
                .map(|value| match value {
                    Value::Text(value) => Ok(value),
                    _ => InvalidSnafu {
                        field: "graph finding limit",
                    }
                    .fail(),
                })
                .collect::<Result<_>>()?,
        })
    }

    pub fn reason_label(reason: &FindingReasonV1) -> Result<String> {
        Ok(match reason {
            FindingReasonV1::UnexpectedEffect => "UNEXPECTED_EFFECT",
            FindingReasonV1::AuditedRoleDeviation => "AUDITED_ROLE_DEVIATION",
            FindingReasonV1::LineageCoverageGap => "LINEAGE_COVERAGE_GAP",
            FindingReasonV1::CredentialPivot => "CREDENTIAL_PIVOT",
            FindingReasonV1::ContextualCredentialPivot => "CONTEXTUAL_CREDENTIAL_PIVOT",
            FindingReasonV1::MissingAuthorityProof => "MISSING_AUTHORITY_PROOF",
            FindingReasonV1::Contradiction => "CONTRADICTION",
            FindingReasonV1::KubernetesProofMissing => "KUBERNETES_PROOF_MISSING",
            FindingReasonV1::OutsideAuthority => "OUTSIDE_AUTHORITY",
            FindingReasonV1::InMemoryOnly => "IN_MEMORY_ONLY",
            FindingReasonV1::PayloadUnobservable => "PAYLOAD_UNOBSERVABLE",
            FindingReasonV1::Declared(reason) => &reason.code,
        }
        .to_owned())
    }

    fn reason(reason: &FindingReasonV1) -> Result<Vec<u8>> {
        Self::encode(&match reason {
            FindingReasonV1::Declared(value) => StoredReason::Declared(value),
            _ => StoredReason::Builtin(Self::reason_label(reason)?),
        })
    }

    fn restore_reason(value: StoredReason<DeclaredFindingReasonV1>) -> Result<FindingReasonV1> {
        match value {
            StoredReason::Declared(reason) => Ok(FindingReasonV1::Declared(reason)),
            StoredReason::Builtin(label) => {
                FindingReasonV1::deserialize(serde::de::value::StringDeserializer::<
                    serde::de::value::Error,
                >::new(label))
                .map_err(|_| {
                    InvalidSnafu {
                        field: "graph finding reason",
                    }
                    .build()
                })
            }
        }
    }

    fn state_label(state: FindingStateV1) -> &'static str {
        match state {
            FindingStateV1::Provisional => "PROVISIONAL",
            FindingStateV1::Confirmed => "CONFIRMED",
            FindingStateV1::Superseded => "SUPERSEDED",
            FindingStateV1::Retracted => "RETRACTED",
            FindingStateV1::CoverageInsufficient => "COVERAGE_INSUFFICIENT",
        }
    }

    fn severity_label(severity: FindingSeverityV1) -> &'static str {
        match severity {
            FindingSeverityV1::Info => "Info",
            FindingSeverityV1::Warning => "Warning",
            FindingSeverityV1::High => "High",
            FindingSeverityV1::Critical => "Critical",
        }
    }

    fn column<T: duckdb::types::FromSql>(row: &Row<'_>, index: usize) -> Result<T> {
        row.get(index).context(DatabaseSnafu {
            operation: "decode graph finding columns",
        })
    }

    fn encode(value: &impl Serialize) -> Result<Vec<u8>> {
        let mut bytes = Vec::new();
        value
            .serialize(
                &mut rmp_serde::Serializer::new(&mut bytes)
                    .with_struct_map()
                    .with_bytes(rmp_serde::config::BytesMode::ForceIterables),
            )
            .context(EncodingSnafu)?;
        Ok(bytes)
    }

    fn binary_column<T: DeserializeOwned>(row: &Row<'_>, index: usize) -> Result<T> {
        let value = row.get_ref(index).context(DatabaseSnafu {
            operation: "decode graph finding columns",
        })?;
        let bytes = value
            .as_blob()
            .map_err(|source| {
                duckdb::Error::FromSqlConversionFailure(index, value.data_type(), Box::new(source))
            })
            .context(DatabaseSnafu {
                operation: "decode graph finding columns",
            })?;
        Self::decode_bytes(bytes)
    }

    fn decode_bytes<T: DeserializeOwned>(bytes: &[u8]) -> Result<T> {
        let mut decoder = rmp_serde::Deserializer::new(Cursor::new(bytes));
        let value = T::deserialize(&mut decoder).context(DecodingSnafu)?;
        if decoder.position() != bytes.len() as u64 {
            return InvalidSnafu {
                field: "graph finding trailing bytes",
            }
            .fail();
        }
        Ok(value)
    }

    fn list_column(row: &Row<'_>, index: usize) -> Result<Vec<Value>> {
        match Self::column(row, index)? {
            Value::List(values) => Ok(values),
            _ => InvalidSnafu {
                field: "graph finding list",
            }
            .fail(),
        }
    }

    fn label_column<T: DeserializeOwned>(row: &Row<'_>, index: usize) -> Result<T> {
        let label: String = Self::column(row, index)?;
        T::deserialize(serde::de::value::StringDeserializer::<
            serde::de::value::Error,
        >::new(label))
        .map_err(|_| {
            InvalidSnafu {
                field: "graph finding label",
            }
            .build()
        })
    }
}
