use araphor_analysis_builtins::graph::ProofQualityV1;
use araphor_analysis_sdk::{
    arrow_array::{ArrayRef, StructArray, UInt8Array},
    arrow_schema::{DataType, Field},
};
use duckdb::{types::Value, Row};
use serde::{de::DeserializeOwned, Serialize};
use snafu::ResultExt as _;
use std::sync::Arc;

use crate::{
    error::{DatabaseSnafu, EncodingSnafu, InvalidSnafu},
    Error, Result,
};

pub(super) struct NativeRows;

impl NativeRows {
    const PROOF_FIELDS: [&'static str; 6] = [
        "source_authority",
        "local_subject_binding",
        "remote_subject_binding",
        "operation_result_authority",
        "temporal_coverage",
        "integrity",
    ];

    pub(super) fn invalid(field: &'static str) -> Error {
        InvalidSnafu { field }.build()
    }

    pub(super) fn column<T: duckdb::types::FromSql>(row: &Row<'_>, index: usize) -> Result<T> {
        row.get(index).context(DatabaseSnafu {
            operation: "decode Graph row",
        })
    }

    pub(super) fn encode(value: &impl Serialize) -> Result<Vec<u8>> {
        let mut bytes = Vec::new();
        value
            .serialize(&mut rmp_serde::Serializer::new(&mut bytes).with_struct_map())
            .context(EncodingSnafu)?;
        Ok(bytes)
    }

    pub(super) fn label(value: &impl Serialize) -> Result<String> {
        match serde_value::to_value(value).map_err(|_| Self::invalid("graph scalar label"))? {
            serde_value::Value::String(label) => Ok(label),
            _ => Err(Self::invalid("graph scalar label")),
        }
    }

    pub(super) fn parse<T: DeserializeOwned>(label: &str) -> Result<T> {
        T::deserialize(serde::de::value::StringDeserializer::<
            serde::de::value::Error,
        >::new(label.to_owned()))
        .map_err(|_| Self::invalid("graph scalar label"))
    }

    pub(super) fn label_column<T: DeserializeOwned>(row: &Row<'_>, index: usize) -> Result<T> {
        Self::parse(&Self::column::<String>(row, index)?)
    }

    pub(super) fn proof(row: &Row<'_>, index: usize) -> Result<ProofQualityV1> {
        let Value::Struct(fields) = Self::column(row, index)? else {
            return Err(Self::invalid("graph native proof"));
        };
        if fields.iter().count() != Self::PROOF_FIELDS.len() {
            return Err(Self::invalid("graph native proof"));
        }
        let rank = |name: &str| match fields.get(&name.to_owned()) {
            Some(Value::UTinyInt(value)) => Ok(*value),
            _ => Err(Self::invalid("graph native proof")),
        };
        Ok(ProofQualityV1 {
            source_authority: Self::rank(rank(Self::PROOF_FIELDS[0])?)?,
            local_subject_binding: Self::rank(rank(Self::PROOF_FIELDS[1])?)?,
            remote_subject_binding: Self::rank(rank(Self::PROOF_FIELDS[2])?)?,
            operation_result_authority: Self::rank(rank(Self::PROOF_FIELDS[3])?)?,
            temporal_coverage: Self::rank(rank(Self::PROOF_FIELDS[4])?)?,
            integrity: Self::rank(rank(Self::PROOF_FIELDS[5])?)?,
        })
    }

    fn rank<T: DeserializeOwned>(rank: u8) -> Result<T> {
        T::deserialize(
            serde::de::value::U32Deserializer::<serde::de::value::Error>::new(u32::from(rank)),
        )
        .map_err(|_| Self::invalid("graph native proof"))
    }

    pub(super) fn proofs(proofs: impl Iterator<Item = ProofQualityV1>) -> StructArray {
        let ranks = proofs
            .map(|proof| {
                [
                    proof.source_authority as u8,
                    proof.local_subject_binding as u8,
                    proof.remote_subject_binding as u8,
                    proof.operation_result_authority as u8,
                    proof.temporal_coverage as u8,
                    proof.integrity as u8,
                ]
            })
            .collect::<Vec<_>>();
        StructArray::from(
            Self::PROOF_FIELDS
                .into_iter()
                .enumerate()
                .map(|(index, name)| {
                    (
                        Arc::new(Field::new(name, DataType::UInt8, false)),
                        Arc::new(UInt8Array::from_iter_values(
                            ranks.iter().map(|ranks| ranks[index]),
                        )) as ArrayRef,
                    )
                })
                .collect::<Vec<_>>(),
        )
    }

    pub(super) fn coverage(row: &Row<'_>, index: usize) -> Result<Vec<[u8; 16]>> {
        let Value::List(values) = Self::column(row, index)? else {
            return Err(Self::invalid("graph list column"));
        };
        values
            .into_iter()
            .map(|value| match value {
                Value::Blob(bytes) => bytes
                    .try_into()
                    .map_err(|_| Self::invalid("graph byte array")),
                _ => Err(Self::invalid("graph byte array")),
            })
            .collect()
    }
}

#[cfg(test)]
mod tests;
