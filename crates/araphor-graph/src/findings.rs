use std::collections::{BTreeMap, BTreeSet};
use std::io::Cursor;

use araphor_analysis_builtins::{discovery::DiscoveryRecordIdV1, graph::*};
use duckdb::{params, types::Value, Connection, Row};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use snafu::ResultExt as _;

use crate::{
    error::{DatabaseSnafu, DecodingSnafu, EncodingSnafu, InvalidSnafu},
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
        let mut hashes = Vec::with_capacity(references.len());
        for reference in references {
            if !names.insert(reference.finding.finding_id.as_str()) {
                return InvalidSnafu {
                    field: "duplicate finding identity",
                }
                .fail();
            }
            hashes.push(Self::value_hash(reference)?);
        }
        writer
            .execute_batch("CREATE TEMP TABLE graph_finding_candidates (request_ordinal UBIGINT, value_hash BLOB)")
            .context(DatabaseSnafu {
                operation: "create finding candidates",
            })?;
        {
            let mut appender =
                writer
                    .appender("graph_finding_candidates")
                    .context(DatabaseSnafu {
                        operation: "open finding candidates",
                    })?;
            for (ordinal, hash) in hashes.iter().enumerate() {
                appender
                    .append_row(params![ordinal as u64, hash.as_slice()])
                    .context(DatabaseSnafu {
                        operation: "append finding candidate",
                    })?;
            }
            appender.flush().context(DatabaseSnafu {
                operation: "flush finding candidates",
            })?;
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
                "SELECT f.value_id AS ordinal,{},c.request_ordinal \
                 FROM graph_finding_candidates c \
                 JOIN graph_finding_values f ON f.value_hash=c.value_hash",
                columns
            ))
            .context(DatabaseSnafu {
                operation: "prepare finding candidates",
            })?;
        let mut rows = statement.query([]).context(DatabaseSnafu {
            operation: "read finding candidates",
        })?;
        while let Some(row) = rows.next().context(DatabaseSnafu {
            operation: "advance finding candidates",
        })? {
            let ordinal: u64 = Self::column(row, 18)?;
            let reference = references
                .get(usize::try_from(ordinal).map_err(|_| {
                    InvalidSnafu {
                        field: "finding candidate ordinal",
                    }
                    .build()
                })?)
                .ok_or_else(|| {
                    InvalidSnafu {
                        field: "finding candidate ordinal",
                    }
                    .build()
                })?;
            let native = Self::references(row)?;
            if native.0 == reference.subject
                && native.1 == reference.evidence
                && Self::decode(
                    row,
                    reference.finding.subject_id.clone(),
                    reference.finding.evidence.clone(),
                )? == *reference.finding
            {
                let slot = &mut selected[ordinal as usize];
                if slot.replace(Self::column(row, 0)?).is_some() {
                    return InvalidSnafu {
                        field: "duplicate finding value",
                    }
                    .fail();
                }
            }
        }
        drop(rows);
        drop(statement);
        writer
            .execute_batch("DROP TABLE graph_finding_candidates")
            .context(DatabaseSnafu {
                operation: "release finding candidates",
            })?;

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
                allocated.push(Self::column::<u64>(row, 0)?);
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
        for ((reference, hash), selected) in references.iter().zip(hashes).zip(selected) {
            let id = if let Some(id) = selected {
                id
            } else {
                let id = allocated.next().ok_or_else(|| {
                    InvalidSnafu {
                        field: "finding identity count",
                    }
                    .build()
                })?;
                inserts.push((id, reference, hash));
                id
            };
            ids.insert(reference.finding.finding_id.clone(), id);
        }
        if !inserts.is_empty() {
            Self::append(writer, &inserts)?;
        }
        Ok(ids)
    }

    fn value_hash(reference: &FindingRefs<'_>) -> Result<[u8; 32]> {
        let finding = reference.finding;
        let reason = match &finding.reason {
            FindingReasonV1::Declared(reason) => StoredReason::Declared(reason),
            reason => StoredReason::Builtin(Self::reason_label(reason)?),
        };
        let canonical = serde_value::to_value((
            (
                finding.tenant_id,
                &finding.finding_id,
                &finding.package_id,
                finding.package_version,
                reference.subject,
                &finding.state,
                finding.window_start_utc_ns,
                finding.window_end_utc_ns,
            ),
            (
                &reference.evidence,
                &finding.required_coverage_interval_ids,
                &finding.policy_provenance,
                &finding.effects,
                reason,
                &finding.severity,
                &finding.sensitivity,
                &finding.required_action,
                &finding.limits,
            ),
        ))
        .map_err(|_| {
            InvalidSnafu {
                field: "finding canonical value",
            }
            .build()
        })?;
        Ok(Sha256::digest(Self::encode(&canonical)?).into())
    }

    pub fn references(row: &Row<'_>) -> Result<(u64, Vec<u64>)> {
        Ok((Self::column(row, 5)?, Self::evidence_references(row, 9)?))
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
        let tenant: Vec<u8> = Self::column(row, 1)?;
        let sensitivity: String = Self::column(row, 15)?;
        Ok(FindingV1 {
            tenant_id: tenant.try_into().map_err(|_| {
                InvalidSnafu {
                    field: "finding tenant",
                }
                .build()
            })?,
            finding_id: Self::column(row, 2)?,
            package_id: Self::column(row, 3)?,
            package_version: Self::column(row, 4)?,
            subject_id: subject,
            state: Self::parse(&Self::column::<String>(row, 6)?)?,
            window_start_utc_ns: Self::column(row, 7)?,
            window_end_utc_ns: Self::column(row, 8)?,
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
            policy_provenance: Self::decode_bytes(&Self::column::<Vec<u8>>(row, 11)?)?,
            effects: Self::decode_bytes(&Self::column::<Vec<u8>>(row, 12)?)?,
            reason: Self::restore_reason(Self::decode_bytes(&Self::column::<Vec<u8>>(row, 13)?)?)?,
            severity: Self::parse(&Self::column::<String>(row, 14)?)?,
            sensitivity: ContextSensitivityV1::try_from(sensitivity.as_str()).map_err(|_| {
                InvalidSnafu {
                    field: "finding sensitivity",
                }
                .build()
            })?,
            required_action: Self::column(row, 16)?,
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
        let duplicate:bool=writer.query_row("SELECT EXISTS(SELECT tenant_id,finding_id,package_id,package_version,subject_ref,state,window_start_utc_ns,window_end_utc_ns,evidence_refs,required_coverage_interval_ids,policy_provenance,effects,reason,severity,sensitivity,required_action,limits,value_hash FROM graph_finding_values GROUP BY ALL HAVING count(*)>1)",[],|row|row.get(0)).context(DatabaseSnafu {operation:"check duplicate finding values"})?;
        if duplicate {
            return InvalidSnafu {
                field: "duplicate finding value",
            }
            .fail();
        }
        let mut statement=writer.prepare("SELECT value_id,tenant_id,finding_id,package_id,package_version,subject_ref,state,window_start_utc_ns,window_end_utc_ns,evidence_refs,required_coverage_interval_ids,policy_provenance,effects,reason,severity,sensitivity,required_action,limits,value_hash FROM graph_finding_values").context(DatabaseSnafu {operation:"prepare finding validation"})?;
        let mut rows = statement.query([]).context(DatabaseSnafu {
            operation: "read finding validation",
        })?;
        while let Some(row) = rows.next().context(DatabaseSnafu {
            operation: "advance finding validation",
        })? {
            let tenant: Vec<u8> = Self::column(row, 1)?;
            if tenant.len() != 16 || Self::column::<i64>(row, 7)? > Self::column::<i64>(row, 8)? {
                return InvalidSnafu {
                    field: "finding stored value",
                }
                .fail();
            }
            let _: Vec<PolicyObservationProvenanceV1> =
                Self::decode_bytes(&Self::column::<Vec<u8>>(row, 11)?)?;
            let _: Vec<GraphEffectV1> = Self::decode_bytes(&Self::column::<Vec<u8>>(row, 12)?)?;
            Self::restore_reason(Self::decode_bytes(&Self::column::<Vec<u8>>(row, 13)?)?)?;
            let refs = Self::references(row)?;
            let finding = Self::decode(
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
            let hash: Vec<u8> = Self::column(row, 18)?;
            if hash
                != Self::value_hash(&FindingRefs {
                    finding: &finding,
                    subject: refs.0,
                    evidence: refs.1,
                })?
            {
                return InvalidSnafu {
                    field: "finding value hash",
                }
                .fail();
            }
        }
        Ok(())
    }

    pub fn reason_label(reason: &FindingReasonV1) -> Result<String> {
        if let FindingReasonV1::Declared(reason) = reason {
            return Ok(reason.code.clone());
        }
        Self::label(reason)
    }

    fn reason(reason: &FindingReasonV1) -> Result<Vec<u8>> {
        Self::encode(&match reason {
            FindingReasonV1::Declared(reason) => StoredReason::Declared(reason),
            reason => StoredReason::Builtin(Self::reason_label(reason)?),
        })
    }

    fn restore_reason(reason: StoredReason<DeclaredFindingReasonV1>) -> Result<FindingReasonV1> {
        match reason {
            StoredReason::Builtin(label) => Self::parse(&label),
            StoredReason::Declared(reason) => Ok(FindingReasonV1::Declared(reason)),
        }
    }

    fn label(value: &impl Serialize) -> Result<String> {
        let value = serde_value::to_value(value).map_err(|_| {
            InvalidSnafu {
                field: "finding label",
            }
            .build()
        })?;
        match value {
            serde_value::Value::String(label) => Ok(label),
            _ => InvalidSnafu {
                field: "finding label",
            }
            .fail(),
        }
    }

    fn parse<T: DeserializeOwned>(label: &str) -> Result<T> {
        T::deserialize(serde::de::value::StringDeserializer::<
            serde::de::value::Error,
        >::new(label.to_owned()))
        .map_err(|_| {
            InvalidSnafu {
                field: "finding label",
            }
            .build()
        })
    }

    fn column<T: duckdb::types::FromSql>(row: &Row<'_>, index: usize) -> Result<T> {
        row.get(index).context(DatabaseSnafu {
            operation: "decode finding row",
        })
    }
    #[cfg(test)]
    fn state_label(state: FindingStateV1) -> Result<String> {
        Self::label(&state)
    }
    #[cfg(test)]
    fn severity_label(severity: FindingSeverityV1) -> Result<String> {
        Self::label(&severity)
    }
    #[cfg(test)]
    fn label_column<T: DeserializeOwned>(row: &Row<'_>, index: usize) -> Result<T> {
        Self::parse(&Self::column::<String>(row, index)?)
    }
    fn list(row: &Row<'_>, index: usize) -> Result<Vec<Value>> {
        match Self::column(row, index)? {
            Value::List(values) => Ok(values),
            _ => InvalidSnafu {
                field: "finding native list",
            }
            .fail(),
        }
    }
    fn encode(value: &impl Serialize) -> Result<Vec<u8>> {
        let mut bytes = Vec::new();
        value
            .serialize(&mut rmp_serde::Serializer::new(&mut bytes).with_struct_map())
            .context(EncodingSnafu)?;
        Ok(bytes)
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

    fn append(writer: &Connection, values: &[(u64, &FindingRefs<'_>, [u8; 32])]) -> Result<()> {
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
        let mut hashes = LargeBinaryBuilder::new();
        for (id, reference, hash) in values {
            let finding = reference.finding;
            ids.append_value(*id);
            tenants.append_value(finding.tenant_id);
            names.append_value(&finding.finding_id);
            packages.append_value(&finding.package_id);
            versions.append_value(finding.package_version);
            subjects.append_value(reference.subject);
            states.append_value(Self::label(&finding.state)?);
            starts.append_value(finding.window_start_utc_ns);
            ends.append_value(finding.window_end_utc_ns);
            evidence.values().append_slice(&reference.evidence);
            evidence.append(true);
            for value in &finding.required_coverage_interval_ids {
                coverage.values().append_value(value);
            }
            coverage.append(true);
            policies.append_value(Self::encode(&finding.policy_provenance)?);
            effects.append_value(Self::encode(&finding.effects)?);
            reasons.append_value(Self::reason(&finding.reason)?);
            severities.append_value(Self::label(&finding.severity)?);
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
            hashes.append_value(hash);
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
            Arc::new(hashes.finish()),
        ];
        let names = std::iter::once("value_id")
            .chain(Self::COLUMNS.split(',').skip(1))
            .chain(std::iter::once("value_hash"));
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
