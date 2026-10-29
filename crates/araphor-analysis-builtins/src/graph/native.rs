use super::*;
use araphor_analysis_sdk as sdk;
use serde::{de::DeserializeOwned, Serialize};
use serde_arrow::schema::{SchemaLike as _, TracingOptions};
use std::sync::{Arc, OnceLock};

mod variants;
mod views;

fn invalid(field: &str) -> sdk::Error {
    sdk::Error::contract(sdk::ErrorCode::Invalid, field)
}
fn error(source: serde_arrow::Error) -> sdk::Error {
    sdk::Error::from(sdk::arrow_schema::ArrowError::ExternalError(Box::new(
        source,
    )))
}
fn row_count(rows: usize) -> sdk::Result<()> {
    u32::try_from(rows)
        .map(|_| ())
        .map_err(|_| sdk::Error::contract(sdk::ErrorCode::Limit, "graph native row count"))
}
fn native_field(field: Arc<sdk::Field>) -> Arc<sdk::Field> {
    let data_type = match field.data_type() {
        sdk::DataType::Dictionary(key, value)
            if key.as_ref() == &sdk::DataType::UInt32 && value.as_ref() == &sdk::DataType::Utf8 =>
        {
            sdk::DataType::Utf8
        }
        sdk::DataType::Struct(fields) => {
            sdk::DataType::Struct(fields.iter().cloned().map(native_field).collect())
        }
        sdk::DataType::List(child) => sdk::DataType::List(native_field(child.clone())),
        _ => return field,
    };
    Arc::new(field.as_ref().clone().with_data_type(data_type))
}
#[expect(
    clippy::expect_used,
    reason = "The native schema comes from fixed internal row types."
)]
fn port<T: DeserializeOwned>(name: &str, slot: &OnceLock<sdk::Port>) -> sdk::Port {
    slot.get_or_init(|| {
        let options = TracingOptions::default()
            .strings_as_large_utf8(false)
            .sequence_as_large_list(false)
            .bytes_as_large_binary(false)
            .enums_without_data_as_strings(true);
        let fields = Vec::<Arc<sdk::Field>>::from_type::<T>(options)
            .expect("the native Graph row schema is valid");
        let fields: Vec<_> = fields.into_iter().map(native_field).collect();
        sdk::Port::new(name, sdk::Schema::new(fields))
    })
    .clone()
}
fn encode<'a, T: 'a, V: Serialize>(
    port: sdk::Port,
    rows: &'a [T],
    convert: impl FnMut(&'a T) -> V,
) -> sdk::Result<sdk::Dataset> {
    row_count(rows.len())?;
    let rows = rows.iter().map(convert).collect::<Vec<_>>();
    let batch = serde_arrow::to_record_batch(port.schema.fields(), &rows).map_err(error)?;
    Ok(sdk::Dataset {
        name: port.name,
        batches: vec![batch],
    })
}
fn decode<T: DeserializeOwned, V>(
    port: sdk::Port,
    data: &sdk::Dataset,
    mut convert: impl FnMut(T) -> sdk::Result<V>,
) -> sdk::Result<Vec<V>> {
    if data.name != port.name {
        return Err(invalid("graph native dataset"));
    }
    let mut output = Vec::new();
    for batch in &data.batches {
        if batch.schema().as_ref() != &port.schema {
            return Err(invalid("graph native schema"));
        }
        let total = output
            .len()
            .checked_add(batch.num_rows())
            .ok_or_else(|| sdk::Error::contract(sdk::ErrorCode::Limit, "graph native row count"))?;
        row_count(total)?;
        let rows: Vec<T> = serde_arrow::from_record_batch(batch).map_err(error)?;
        output
            .try_reserve(rows.len())
            .map_err(|_| sdk::Error::contract(sdk::ErrorCode::Limit, "graph native allocation"))?;
        for row in rows {
            output.push(convert(row)?);
        }
    }
    Ok(output)
}

impl Observation {
    pub fn port() -> sdk::Port {
        static PORT: OnceLock<sdk::Port> = OnceLock::new();
        port::<views::ObservationRow>("records", &PORT)
    }
    pub fn encode(rows: &[Self]) -> sdk::Result<sdk::Dataset> {
        encode(Self::port(), rows, views::ObservationRow::from)
    }
    pub fn decode(data: &sdk::Dataset) -> sdk::Result<Vec<Self>> {
        decode::<views::ObservationRow, Self>(Self::port(), data, TryInto::try_into)
    }
    pub fn read(checked: &sdk::CheckedEvaluation<'_>) -> sdk::Result<Vec<Self>> {
        Self::decode(&checked.evaluation().input("records")?.data)
    }
}

impl Fact {
    pub fn port() -> sdk::Port {
        static PORT: OnceLock<sdk::Port> = OnceLock::new();
        port::<views::FactRow>("facts", &PORT)
    }
    pub fn encode(rows: &[Self]) -> sdk::Result<sdk::Dataset> {
        encode(Self::port(), rows, views::FactRow::from)
    }
    pub fn decode(data: &sdk::Dataset) -> sdk::Result<Vec<Self>> {
        decode::<views::FactRow, Self>(Self::port(), data, TryInto::try_into)
    }
    pub fn read(checked: &sdk::CheckedEvaluation<'_>) -> sdk::Result<Vec<Self>> {
        Self::decode(&checked.evaluation().input("facts")?.data)
    }
}

impl Manifest {
    pub fn port() -> sdk::Port {
        static PORT: OnceLock<sdk::Port> = OnceLock::new();
        port::<Manifest>("manifest", &PORT)
    }
    pub fn encode(rows: &[Self]) -> sdk::Result<sdk::Dataset> {
        encode(Self::port(), rows, Clone::clone)
    }
    pub fn decode(data: &sdk::Dataset) -> sdk::Result<Vec<Self>> {
        decode::<Manifest, Self>(Self::port(), data, Ok)
    }
    pub fn read(checked: &sdk::CheckedEvaluation<'_>) -> sdk::Result<Vec<Self>> {
        Self::decode(&checked.evaluation().input("manifest")?.data)
    }
}

impl Progress {
    pub fn port() -> sdk::Port {
        static PORT: OnceLock<sdk::Port> = OnceLock::new();
        port::<views::ProgressRow>("progress", &PORT)
    }
    pub fn encode(rows: &[Self]) -> sdk::Result<sdk::Dataset> {
        encode(Self::port(), rows, views::ProgressRow::from)
    }
    pub fn decode(data: &sdk::Dataset) -> sdk::Result<Vec<Self>> {
        decode::<views::ProgressRow, Self>(Self::port(), data, TryInto::try_into)
    }
}

impl ProgressRemoval {
    pub fn port() -> sdk::Port {
        static PORT: OnceLock<sdk::Port> = OnceLock::new();
        port::<views::ProgressRemovalRow>("progress_removals", &PORT)
    }
    pub fn encode(rows: &[Self]) -> sdk::Result<sdk::Dataset> {
        encode(Self::port(), rows, views::ProgressRemovalRow::from)
    }
    pub fn decode(data: &sdk::Dataset) -> sdk::Result<Vec<Self>> {
        decode::<views::ProgressRemovalRow, Self>(Self::port(), data, TryInto::try_into)
    }
}

impl GraphPackageStateV1 {
    pub(super) fn from_marker(value: &str) -> sdk::Result<Self> {
        views::StateRow {
            tag: value.into(),
            declared: None,
        }
        .try_into()
    }

    pub fn port() -> sdk::Port {
        static PORT: OnceLock<sdk::Port> = OnceLock::new();
        port::<views::StateRow>("state", &PORT)
    }

    pub fn encode(rows: &[Self]) -> sdk::Result<sdk::Dataset> {
        encode(Self::port(), rows, views::StateRow::from)
    }

    pub fn decode(data: &sdk::Dataset) -> sdk::Result<Vec<Self>> {
        decode::<views::StateRow, Self>(Self::port(), data, TryInto::try_into)
    }
}

impl Metadata {
    pub fn port() -> sdk::Port {
        static PORT: OnceLock<sdk::Port> = OnceLock::new();
        port::<views::MetadataRow>("metadata", &PORT)
    }
    pub fn encode(rows: &[Self]) -> sdk::Result<sdk::Dataset> {
        encode(Self::port(), rows, views::MetadataRow::from)
    }
    pub fn decode(data: &sdk::Dataset) -> sdk::Result<Vec<Self>> {
        decode::<views::MetadataRow, Self>(Self::port(), data, TryInto::try_into)
    }
}

impl Subject {
    pub fn port() -> sdk::Port {
        static PORT: OnceLock<sdk::Port> = OnceLock::new();
        port::<views::SubjectRow>("subjects", &PORT)
    }
    pub fn encode(rows: &[Self]) -> sdk::Result<sdk::Dataset> {
        encode(Self::port(), rows, views::SubjectRow::from)
    }
    pub fn decode(data: &sdk::Dataset) -> sdk::Result<Vec<Self>> {
        decode::<views::SubjectRow, Self>(Self::port(), data, TryInto::try_into)
    }
}

impl Relationship {
    pub fn port() -> sdk::Port {
        static PORT: OnceLock<sdk::Port> = OnceLock::new();
        port::<views::RelationshipRow>("relationships", &PORT)
    }
    pub fn encode(rows: &[Self]) -> sdk::Result<sdk::Dataset> {
        encode(Self::port(), rows, views::RelationshipRow::from)
    }
    pub fn decode(data: &sdk::Dataset) -> sdk::Result<Vec<Self>> {
        decode::<views::RelationshipRow, Self>(Self::port(), data, TryInto::try_into)
    }
}

impl Finding {
    pub fn port() -> sdk::Port {
        static PORT: OnceLock<sdk::Port> = OnceLock::new();
        port::<views::FindingRow>("findings", &PORT)
    }
    pub fn encode(rows: &[Self]) -> sdk::Result<sdk::Dataset> {
        encode(Self::port(), rows, views::FindingRow::from)
    }
    pub fn decode(data: &sdk::Dataset) -> sdk::Result<Vec<Self>> {
        decode::<views::FindingRow, Self>(Self::port(), data, TryInto::try_into)
    }
}

impl FindingRemoval {
    pub fn port() -> sdk::Port {
        static PORT: OnceLock<sdk::Port> = OnceLock::new();
        port::<Self>("finding_removals", &PORT)
    }
    pub fn encode(rows: &[Self]) -> sdk::Result<sdk::Dataset> {
        encode(Self::port(), rows, Clone::clone)
    }
    pub fn decode(data: &sdk::Dataset) -> sdk::Result<Vec<Self>> {
        decode::<Self, Self>(Self::port(), data, Ok)
    }
}

impl SubjectChange {
    pub fn port() -> sdk::Port {
        static PORT: OnceLock<sdk::Port> = OnceLock::new();
        port::<views::SubjectChangeRow>("subjects", &PORT)
    }
    pub fn encode(rows: &[Self]) -> sdk::Result<sdk::Dataset> {
        encode(Self::port(), rows, views::SubjectChangeRow::from)
    }
    pub fn decode(data: &sdk::Dataset) -> sdk::Result<Vec<Self>> {
        decode::<views::SubjectChangeRow, Self>(Self::port(), data, TryInto::try_into)
    }
}

impl SubjectRemoval {
    pub fn port() -> sdk::Port {
        static PORT: OnceLock<sdk::Port> = OnceLock::new();
        port::<views::SubjectRemovalRow>("subject_removals", &PORT)
    }
    pub fn encode(rows: &[Self]) -> sdk::Result<sdk::Dataset> {
        encode(Self::port(), rows, views::SubjectRemovalRow::from)
    }
    pub fn decode(data: &sdk::Dataset) -> sdk::Result<Vec<Self>> {
        decode::<views::SubjectRemovalRow, Self>(Self::port(), data, TryInto::try_into)
    }
}

impl RelationshipChange {
    pub fn port() -> sdk::Port {
        static PORT: OnceLock<sdk::Port> = OnceLock::new();
        port::<views::RelationshipChangeRow>("relationships", &PORT)
    }
    pub fn encode(rows: &[Self]) -> sdk::Result<sdk::Dataset> {
        encode(Self::port(), rows, views::RelationshipChangeRow::from)
    }
    pub fn decode(data: &sdk::Dataset) -> sdk::Result<Vec<Self>> {
        decode::<views::RelationshipChangeRow, Self>(Self::port(), data, TryInto::try_into)
    }
}

impl RelationshipRemoval {
    pub fn port() -> sdk::Port {
        static PORT: OnceLock<sdk::Port> = OnceLock::new();
        port::<views::RelationshipRemovalRow>("relationship_removals", &PORT)
    }
    pub fn encode(rows: &[Self]) -> sdk::Result<sdk::Dataset> {
        encode(Self::port(), rows, views::RelationshipRemovalRow::from)
    }
    pub fn decode(data: &sdk::Dataset) -> sdk::Result<Vec<Self>> {
        decode::<views::RelationshipRemovalRow, Self>(Self::port(), data, TryInto::try_into)
    }
}

impl FindingChange {
    pub fn port() -> sdk::Port {
        static PORT: OnceLock<sdk::Port> = OnceLock::new();
        port::<views::FindingChangeRow>("findings", &PORT)
    }
    pub fn encode(rows: &[Self]) -> sdk::Result<sdk::Dataset> {
        let views = rows
            .iter()
            .map(views::FindingChangeRow::try_from)
            .collect::<sdk::Result<Vec<_>>>()?;
        encode(Self::port(), &views, Clone::clone)
    }
    pub fn decode(data: &sdk::Dataset) -> sdk::Result<Vec<Self>> {
        decode::<views::FindingChangeRow, Self>(Self::port(), data, TryInto::try_into)
    }
}

#[cfg(test)]
mod tests;
