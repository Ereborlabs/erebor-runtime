use std::collections::{BTreeMap, BTreeSet};
use std::io::Cursor;

use araphor_analysis_builtins::{discovery::DiscoveryRecordIdV1, graph::*};
use duckdb::{params, types::Value, Connection, Row};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use snafu::ResultExt as _;

use crate::{
    error::{DatabaseSnafu, DecodingSnafu, InvalidSnafu},
    native::NativeRows,
    Result,
};

pub struct FindingRows;
pub struct FindingRefs<'a> {
    pub finding: &'a FindingV1,
    pub subject: u64,
    pub evidence: Vec<u64>,
}

#[derive(Deserialize, Serialize)]
pub(super) enum StoredReason<T> {
    Builtin(String),
    Declared(T),
}

impl FindingRows {
    pub const SCHEMA: &str = include_str!("findings.sql");
    pub const COLUMNS:&str="ordinal,tenant_id,finding_id,package_id,package_version,subject_ref,state,window_start_utc_ns,window_end_utc_ns,evidence_refs,required_coverage_interval_ids,policy_provenance,effects,reason,severity,sensitivity,required_action,limits";

    pub fn intern(
        writer: &Connection,
        references: &[FindingRefs<'_>],
    ) -> Result<BTreeMap<String, u64>> {
        if references.is_empty() {
            return Ok(BTreeMap::new());
        }
        let mut names = BTreeSet::new();
        for reference in references {
            if !names.insert(reference.finding.finding_id.as_str()) {
                return InvalidSnafu {
                    field: "duplicate finding identity",
                }
                .fail();
            }
        }
        let mut selected = vec![None; references.len()];
        let columns = Self::COLUMNS
            .split_once(',')
            .map(|(_, columns)| columns)
            .ok_or_else(|| {
                InvalidSnafu {
                    field: "finding columns",
                }
                .build()
            })?;
        let mut statement = writer
            .prepare(&format!(
                "WITH candidates AS MATERIALIZED (
                    SELECT * FROM graph_finding_values WHERE finding_id=?
                 ) SELECT f.value_id AS ordinal,{} FROM candidates f WHERE tenant_id=?",
                columns
            ))
            .context(DatabaseSnafu {
                operation: "prepare finding candidates",
            })?;
        for (ordinal, reference) in references.iter().enumerate() {
            let mut rows = statement
                .query(params![
                    reference.finding.finding_id,
                    reference.finding.tenant_id.as_slice(),
                ])
                .context(DatabaseSnafu {
                    operation: "read finding candidates",
                })?;
            while let Some(row) = rows.next().context(DatabaseSnafu {
                operation: "advance finding candidates",
            })? {
                let native = Self::references(row)?;
                if native.0 == reference.subject
                    && native.1 == reference.evidence
                    && Self::decode(
                        row,
                        reference.finding.subject_id.clone(),
                        reference.finding.evidence.clone(),
                    )? == *reference.finding
                {
                    let slot = &mut selected[ordinal];
                    if slot.replace(NativeRows::column(row, 0)?).is_some() {
                        return InvalidSnafu {
                            field: "duplicate finding value",
                        }
                        .fail();
                    }
                }
            }
        }
        drop(statement);

        let missing = selected.iter().filter(|id| id.is_none()).count();
        let mut allocated = Vec::with_capacity(missing);
        if missing > 0 {
            let count = i64::try_from(missing).map_err(|_| {
                InvalidSnafu {
                    field: "finding identity count",
                }
                .build()
            })?;
            let mut statement = writer
                .prepare("SELECT nextval('graph_finding_values_seq') FROM range(?)")
                .context(DatabaseSnafu {
                    operation: "prepare finding identities",
                })?;
            let mut rows = statement.query(params![count]).context(DatabaseSnafu {
                operation: "allocate finding identities",
            })?;
            while let Some(row) = rows.next().context(DatabaseSnafu {
                operation: "advance finding identities",
            })? {
                allocated.push(NativeRows::column::<u64>(row, 0)?);
            }
        }
        if allocated.len() != missing {
            return InvalidSnafu {
                field: "finding identity count",
            }
            .fail();
        }
        let mut ids = BTreeMap::new();
        let mut inserts = Vec::with_capacity(missing);
        let mut allocated = allocated.into_iter();
        for (reference, selected) in references.iter().zip(selected) {
            let id = if let Some(id) = selected {
                id
            } else {
                let id = allocated.next().ok_or_else(|| {
                    InvalidSnafu {
                        field: "finding identity count",
                    }
                    .build()
                })?;
                inserts.push((id, reference));
                id
            };
            ids.insert(reference.finding.finding_id.clone(), id);
        }
        if !inserts.is_empty() {
            Self::append(writer, &inserts)?;
        }
        Ok(ids)
    }

    pub fn references(row: &Row<'_>) -> Result<(u64, Vec<u64>)> {
        Ok((
            NativeRows::column(row, 5)?,
            Self::evidence_references(row, 9)?,
        ))
    }

    pub fn evidence_references(row: &Row<'_>, index: usize) -> Result<Vec<u64>> {
        Self::list(row, index)?
            .into_iter()
            .map(|value| match value {
                Value::UBigInt(id) => Ok(id),
                _ => InvalidSnafu {
                    field: "finding evidence reference",
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
        let tenant: Vec<u8> = NativeRows::column(row, 1)?;
        let sensitivity: String = NativeRows::column(row, 15)?;
        Ok(FindingV1 {
            tenant_id: tenant.try_into().map_err(|_| {
                InvalidSnafu {
                    field: "finding tenant",
                }
                .build()
            })?,
            finding_id: NativeRows::column(row, 2)?,
            package_id: NativeRows::column(row, 3)?,
            package_version: NativeRows::column(row, 4)?,
            subject_id: subject,
            state: NativeRows::parse(&NativeRows::column::<String>(row, 6)?)?,
            window_start_utc_ns: NativeRows::column(row, 7)?,
            window_end_utc_ns: NativeRows::column(row, 8)?,
            evidence,
            required_coverage_interval_ids: Self::list(row, 10)?
                .into_iter()
                .map(|value| match value {
                    Value::Blob(bytes) => bytes.try_into().map_err(|_| {
                        InvalidSnafu {
                            field: "finding coverage",
                        }
                        .build()
                    }),
                    _ => InvalidSnafu {
                        field: "finding coverage",
                    }
                    .fail(),
                })
                .collect::<Result<_>>()?,
            policy_provenance: Self::decode_bytes(&NativeRows::column::<Vec<u8>>(row, 11)?)?,
            effects: Self::decode_bytes(&NativeRows::column::<Vec<u8>>(row, 12)?)?,
            reason: Self::restore_reason(Self::decode_bytes(&NativeRows::column::<Vec<u8>>(
                row, 13,
            )?)?)?,
            severity: NativeRows::parse(&NativeRows::column::<String>(row, 14)?)?,
            sensitivity: ContextSensitivityV1::try_from(sensitivity.as_str()).map_err(|_| {
                InvalidSnafu {
                    field: "finding sensitivity",
                }
                .build()
            })?,
            required_action: NativeRows::column(row, 16)?,
            limits: Self::list(row, 17)?
                .into_iter()
                .map(|value| match value {
                    Value::Text(text) => Ok(text),
                    _ => InvalidSnafu {
                        field: "finding limit",
                    }
                    .fail(),
                })
                .collect::<Result<_>>()?,
        })
    }

    pub fn validate(writer: &Connection) -> Result<()> {
        let duplicate:bool=writer.query_row("SELECT EXISTS(SELECT tenant_id,finding_id,package_id,package_version,subject_ref,state,window_start_utc_ns,window_end_utc_ns,evidence_refs,required_coverage_interval_ids,policy_provenance,effects,reason,severity,sensitivity,required_action,limits FROM graph_finding_values GROUP BY ALL HAVING count(*)>1)",[],|row|row.get(0)).context(DatabaseSnafu {operation:"check duplicate finding values"})?;
        if duplicate {
            return InvalidSnafu {
                field: "duplicate finding value",
            }
            .fail();
        }
        let mut statement=writer.prepare("SELECT value_id,tenant_id,finding_id,package_id,package_version,subject_ref,state,window_start_utc_ns,window_end_utc_ns,evidence_refs,required_coverage_interval_ids,policy_provenance,effects,reason,severity,sensitivity,required_action,limits FROM graph_finding_values").context(DatabaseSnafu {operation:"prepare finding validation"})?;
        let mut rows = statement.query([]).context(DatabaseSnafu {
            operation: "read finding validation",
        })?;
        while let Some(row) = rows.next().context(DatabaseSnafu {
            operation: "advance finding validation",
        })? {
            let tenant: Vec<u8> = NativeRows::column(row, 1)?;
            if tenant.len() != 16
                || NativeRows::column::<i64>(row, 7)? > NativeRows::column::<i64>(row, 8)?
            {
                return InvalidSnafu {
                    field: "finding stored value",
                }
                .fail();
            }
            let _: Vec<PolicyObservationProvenanceV1> =
                Self::decode_bytes(&NativeRows::column::<Vec<u8>>(row, 11)?)?;
            let _: Vec<GraphEffectV1> =
                Self::decode_bytes(&NativeRows::column::<Vec<u8>>(row, 12)?)?;
            Self::restore_reason(Self::decode_bytes(&NativeRows::column::<Vec<u8>>(
                row, 13,
            )?)?)?;
            Self::references(row)?;
            Self::decode(
                row,
                GraphSubjectKeyV1 {
                    tenant_id: tenant.try_into().map_err(|_| {
                        InvalidSnafu {
                            field: "finding tenant",
                        }
                        .build()
                    })?,
                    authority: GraphSubjectAuthorityV1::External {
                        authority_id: "validation".into(),
                    },
                    kind: GraphSubjectKindV1::External,
                    identity: vec![1],
                },
                Vec::new(),
            )?;
        }
        Ok(())
    }

    pub fn reason_label(reason: &FindingReasonV1) -> Result<String> {
        if let FindingReasonV1::Declared(reason) = reason {
            return Ok(reason.code.clone());
        }
        NativeRows::label(reason)
    }

    fn reason(reason: &FindingReasonV1) -> Result<Vec<u8>> {
        NativeRows::encode(&match reason {
            FindingReasonV1::Declared(reason) => StoredReason::Declared(reason),
            reason => StoredReason::Builtin(Self::reason_label(reason)?),
        })
    }

    fn restore_reason(reason: StoredReason<DeclaredFindingReasonV1>) -> Result<FindingReasonV1> {
        match reason {
            StoredReason::Builtin(label) => NativeRows::parse(&label),
            StoredReason::Declared(reason) => Ok(FindingReasonV1::Declared(reason)),
        }
    }

    #[cfg(test)]
    fn state_label(state: FindingStateV1) -> Result<String> {
        NativeRows::label(&state)
    }
    #[cfg(test)]
    fn severity_label(severity: FindingSeverityV1) -> Result<String> {
        NativeRows::label(&severity)
    }
    #[cfg(test)]
    fn label_column<T: DeserializeOwned>(row: &Row<'_>, index: usize) -> Result<T> {
        NativeRows::parse(&NativeRows::column::<String>(row, index)?)
    }
    fn list(row: &Row<'_>, index: usize) -> Result<Vec<Value>> {
        match NativeRows::column(row, index)? {
            Value::List(values) => Ok(values),
            _ => InvalidSnafu {
                field: "finding native list",
            }
            .fail(),
        }
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

    fn append(writer: &Connection, values: &[(u64, &FindingRefs<'_>)]) -> Result<()> {
        use araphor_analysis_sdk::{
            arrow_array::{
                builder::{
                    Int64Builder, LargeBinaryBuilder, LargeListBuilder, LargeStringBuilder,
                    UInt64Builder,
                },
                ArrayRef, RecordBatch,
            },
            arrow_schema::{Field, Schema},
        };
        use std::sync::Arc;
        let mut ids = UInt64Builder::new();
        let mut tenants = LargeBinaryBuilder::new();
        let mut names = LargeStringBuilder::new();
        let mut packages = LargeStringBuilder::new();
        let mut versions = UInt64Builder::new();
        let mut subjects = UInt64Builder::new();
        let mut states = LargeStringBuilder::new();
        let mut starts = Int64Builder::new();
        let mut ends = Int64Builder::new();
        let mut evidence = LargeListBuilder::new(UInt64Builder::new());
        let mut coverage = LargeListBuilder::new(LargeBinaryBuilder::new());
        let mut policies = LargeBinaryBuilder::new();
        let mut effects = LargeBinaryBuilder::new();
        let mut reasons = LargeBinaryBuilder::new();
        let mut severities = LargeStringBuilder::new();
        let mut sensitivities = LargeStringBuilder::new();
        let mut actions = LargeStringBuilder::new();
        let mut limits = LargeListBuilder::new(LargeStringBuilder::new());
        for (id, reference) in values {
            let finding = reference.finding;
            ids.append_value(*id);
            tenants.append_value(finding.tenant_id);
            names.append_value(&finding.finding_id);
            packages.append_value(&finding.package_id);
            versions.append_value(finding.package_version);
            subjects.append_value(reference.subject);
            states.append_value(NativeRows::label(&finding.state)?);
            starts.append_value(finding.window_start_utc_ns);
            ends.append_value(finding.window_end_utc_ns);
            evidence.values().append_slice(&reference.evidence);
            evidence.append(true);
            for value in &finding.required_coverage_interval_ids {
                coverage.values().append_value(value);
            }
            coverage.append(true);
            policies.append_value(NativeRows::encode(&finding.policy_provenance)?);
            effects.append_value(NativeRows::encode(&finding.effects)?);
            reasons.append_value(Self::reason(&finding.reason)?);
            severities.append_value(NativeRows::label(&finding.severity)?);
            sensitivities.append_value(<&str>::from(finding.sensitivity));
            if let Some(action) = &finding.required_action {
                actions.append_value(action);
            } else {
                actions.append_null();
            }
            for limit in &finding.limits {
                limits.values().append_value(limit);
            }
            limits.append(true);
        }
        let arrays: Vec<ArrayRef> = vec![
            Arc::new(ids.finish()),
            Arc::new(tenants.finish()),
            Arc::new(names.finish()),
            Arc::new(packages.finish()),
            Arc::new(versions.finish()),
            Arc::new(subjects.finish()),
            Arc::new(states.finish()),
            Arc::new(starts.finish()),
            Arc::new(ends.finish()),
            Arc::new(evidence.finish()),
            Arc::new(coverage.finish()),
            Arc::new(policies.finish()),
            Arc::new(effects.finish()),
            Arc::new(reasons.finish()),
            Arc::new(severities.finish()),
            Arc::new(sensitivities.finish()),
            Arc::new(actions.finish()),
            Arc::new(limits.finish()),
        ];
        let names = std::iter::once("value_id").chain(Self::COLUMNS.split(',').skip(1));
        let fields = names
            .zip(&arrays)
            .enumerate()
            .map(|(index, (name, array))| Field::new(name, array.data_type().clone(), index == 16))
            .collect::<Vec<_>>();
        let batch = RecordBatch::try_new(Arc::new(Schema::new(fields)), arrays).map_err(|_| {
            InvalidSnafu {
                field: "finding native batch",
            }
            .build()
        })?;
        let mut appender = writer
            .appender("graph_finding_values")
            .context(DatabaseSnafu {
                operation: "open finding appender",
            })?;
        appender.append_record_batch(batch).context(DatabaseSnafu {
            operation: "append finding values",
        })?;
        appender.flush().context(DatabaseSnafu {
            operation: "flush finding values",
        })?;
        Ok(())
    }
}

#[cfg(test)]
mod tests;
