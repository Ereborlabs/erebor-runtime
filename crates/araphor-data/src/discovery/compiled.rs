use std::sync::LazyLock;

use araphor_analysis_sdk as sdk;
use serde::{Deserialize, Serialize};
use serde_arrow::schema::{SchemaLike as _, TracingOptions};

use super::DiscoveryPolicyKeyV1;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CompiledPolicyContextV1 {
    pub source_revision_id: String,
    pub signed_profile_digest: String,
    pub profile_id: String,
    pub profile_version: u64,
    pub policy_document_digest: String,
    pub execution_set_ids: Vec<String>,
    pub compiled_keys: Vec<DiscoveryPolicyKeyV1>,
}

impl CompiledPolicyContextV1 {
    pub fn schema() -> &'static sdk::Schema {
        #[expect(
            clippy::expect_used,
            reason = "The native schema comes from one fixed internal type."
        )]
        static SCHEMA: LazyLock<sdk::Schema> = LazyLock::new(|| {
            sdk::Schema::new(
                Vec::<std::sync::Arc<sdk::Field>>::from_type::<CompiledPolicyContextV1>(
                    TracingOptions::default()
                        .strings_as_large_utf8(false)
                        .sequence_as_large_list(false),
                )
                .expect("the compiled policy proof has a native Arrow schema"),
            )
        });
        &SCHEMA
    }

    pub fn encode(&self) -> crate::Result<Vec<u8>> {
        let schema = Self::schema();
        let batch = serde_arrow::to_record_batch(schema.fields(), &[self]).map_err(codec_error)?;
        let mut writer =
            arrow_ipc::writer::FileWriter::try_new(Vec::new(), schema).map_err(codec_error)?;
        writer.write(&batch).map_err(codec_error)?;
        writer.into_inner().map_err(codec_error)
    }
}

fn codec_error(source: impl std::error::Error + Send + Sync + 'static) -> crate::Error {
    crate::Error::DiscoveryContext {
        source: Box::new(source),
        location: snafu::location!(),
    }
}
