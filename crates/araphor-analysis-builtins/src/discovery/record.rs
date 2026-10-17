use std::sync::OnceLock;

use araphor_analysis_sdk as sdk;
use sdk::{DataType as Type, Field};

use super::Record;

impl Record<'_> {
    pub fn port() -> sdk::Port {
        static PORT: OnceLock<sdk::Port> = OnceLock::new();
        PORT.get_or_init(Self::build_port).clone()
    }

    fn build_port() -> sdk::Port {
        let identity = Type::Struct(
            vec![
                Field::new("tenant_id", Type::Binary, false),
                Field::new("node_id", Type::Utf8, false),
                Field::new("node_boot_id", Type::Binary, false),
                Field::new("label_epoch", Type::UInt64, false),
                Field::new("source_id", Type::Binary, false),
                Field::new("source_epoch", Type::UInt64, false),
            ]
            .into(),
        );
        let id = Type::Struct(
            vec![
                Field::new("stream", identity, false),
                Field::new("cpu_id", Type::UInt32, false),
                Field::new("durable_cursor", Type::UInt64, false),
            ]
            .into(),
        );
        let file = Type::Struct(
            vec![
                Field::new("profile_generation_ref_id", Type::UInt64, false),
                Field::new("mount_id_unique", Type::UInt64, false),
                Field::new("inode", Type::UInt64, false),
                Field::new("inode_generation", Type::UInt64, false),
                Field::new("mount_namespace_inode", Type::UInt32, false),
                Field::new("filesystem_device", Type::UInt32, false),
            ]
            .into(),
        );
        let effect = Type::Struct(
            vec![
                Field::new("task_cookie", Type::UInt64, false),
                Field::new("target_task_cookie", Type::UInt64, true),
                Field::new("process_lineage_id", Type::Binary, false),
                Field::new("authority_domain_id", Type::Binary, false),
                Field::new("execution_set_id", Type::Binary, false),
                Field::new("exact_object_id", Type::Binary, false),
                Field::new("destination_id", Type::UInt64, false),
                Field::new("policy_rule_id", Type::UInt64, false),
                Field::new("reason", Type::UInt32, false),
                Field::new("decision", Type::UInt32, false),
                Field::new("effect_family", Type::UInt32, false),
                Field::new("operation", Type::UInt32, false),
                Field::new("operation_argument", Type::UInt32, true),
                Field::new("configured_errno", Type::Int32, false),
                Field::new("kernel_result", Type::Int32, false),
                Field::new("exact_file_object", file, true),
            ]
            .into(),
        );
        let source = Type::Struct(
            vec![
                Field::new("process", Type::Binary, false),
                Field::new("entry", Type::Binary, false),
                Field::new("binding", Type::Binary, false),
                Field::new("role", Type::UInt32, false),
                Field::new("state", Type::UInt32, false),
                Field::new("rule", Type::UInt32, false),
                Field::new("sequence", Type::UInt64, false),
            ]
            .into(),
        );
        sdk::Port::new(
            "records",
            sdk::Schema::new(vec![
                Field::new("id", id, false),
                Field::new("bytes", Type::Binary, false),
                Field::new("temporal", Type::Int32, false),
                Field::new("effect", effect, false),
                Field::new("generation", Type::UInt64, true),
                Field::new("original_sequence", Type::UInt64, true),
                Field::new("source", source, true),
            ]),
        )
    }

    pub fn encode(rows: &[Self]) -> sdk::Result<sdk::Dataset> {
        let port = Self::port();
        let batch =
            serde_arrow::to_record_batch(port.schema.fields(), &rows).map_err(Self::error)?;
        Ok(sdk::Dataset {
            name: port.name,
            batches: vec![batch],
        })
    }

    pub fn read<'a>(checked: &'a sdk::CheckedEvaluation<'_>) -> sdk::Result<Vec<Record<'a>>> {
        Self::decode(&checked.evaluation().input("records")?.data)
    }

    pub(super) fn decode<'a>(data: &'a sdk::Dataset) -> sdk::Result<Vec<Record<'a>>> {
        let mut rows = Vec::new();
        for batch in &data.batches {
            rows.extend(
                serde_arrow::from_record_batch::<Vec<Record<'a>>>(batch).map_err(Self::error)?,
            );
        }
        Ok(rows)
    }

    fn error(source: serde_arrow::Error) -> sdk::Error {
        sdk::Error::from(sdk::arrow_schema::ArrowError::ExternalError(Box::new(
            source,
        )))
    }
}
