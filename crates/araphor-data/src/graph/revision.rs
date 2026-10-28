use std::sync::{Arc, LazyLock};

use araphor_analysis_sdk as sdk;
use serde_arrow::schema::{SchemaLike as _, TracingOptions};

use crate::{
    AnalysisContextKeyV1, DiscoveryCoverageStateV1, DiscoveryRecordIdV1, EvidenceIntakeIdentityV1,
    GraphCoverageKeyV1, GraphRevisionV1,
};

impl GraphRevisionV1 {
    pub fn arrow_schema() -> &'static sdk::Schema {
        #[expect(
            clippy::expect_used,
            reason = "The native schema comes from one complete internal typed sample."
        )]
        static SCHEMA: LazyLock<sdk::Schema> = LazyLock::new(|| {
            let options = TracingOptions::default()
                .strings_as_large_utf8(false)
                .sequence_as_large_list(false)
                .bytes_as_large_binary(false)
                .enums_without_data_as_strings(true)
                .overwrite(
                    "coverage.element.state",
                    sdk::Field::new("state", sdk::DataType::Utf8, false),
                )
                .expect("the Graph coverage state has a native Utf8 schema");
            sdk::Schema::new(
                Vec::<Arc<sdk::Field>>::from_samples([GraphRevisionV1::schema_sample()], options)
                    .expect("the Graph revision has a native Arrow schema"),
            )
        });
        &SCHEMA
    }

    // Type tracing supplies empty bytes. Fixed IDs require complete samples.
    fn schema_sample() -> Self {
        let source = EvidenceIntakeIdentityV1 {
            tenant_id: [1; 16],
            node_id: "node".into(),
            node_boot_id: [2; 16],
            label_epoch: 1,
            source_id: [3; 16],
            source_epoch: 1,
        };
        Self {
            evidence: vec![DiscoveryRecordIdV1 {
                stream: source.clone(),
                cpu_id: 0,
                durable_cursor: 1,
            }],
            coverage: vec![GraphCoverageKeyV1 {
                source,
                cpu_id: 0,
                report_revision: 1,
                interval_id: [4; 16],
                interval_revision: 1,
                state: DiscoveryCoverageStateV1::Healthy,
                gap_reasons: vec![String::new()],
            }],
            context: vec![AnalysisContextKeyV1 {
                tenant_id: [1; 16],
                owner_id: "schema".into(),
                entity_key: vec![1],
                lifetime_key: vec![1],
                owner_revision: 1,
            }],
            missing_ranges: vec![(1, 1)],
        }
    }
}
