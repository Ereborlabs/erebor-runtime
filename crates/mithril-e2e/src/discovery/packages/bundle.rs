use std::collections::BTreeMap;

use araphor_analysis_sdk::{
    CheckpointSpec, DataType, Field, InputMode, InputSource, Model, OutputRef, Package, Port,
    Schema, TableRef,
};
use araphor_data::{
    PackageArtifactV1, PackageBundleV1, PackageImplementationV1, PackageRefV1, SqlModelV1,
};

pub(super) struct Denials;

impl Denials {
    pub(super) fn bundle(revision: &str, threshold: u64, broken: bool) -> PackageBundleV1 {
        let input = Port::new(
            "denials",
            Schema::new(vec![
                Field::new("event", DataType::Binary, false),
                Field::new("subject", DataType::Binary, false),
                Field::new("resource", DataType::Binary, false),
            ]),
        );
        let counts = Port::new(
            "counts",
            Schema::new(vec![
                Field::new("subject", DataType::Binary, false),
                Field::new("resource", DataType::Binary, false),
                Field::new("count", DataType::UInt64, false),
            ]),
        );
        let mut count = Model::new("count", vec![input], vec![counts.clone()]);
        count.checkpoint = Some(CheckpointSpec {
            version: 1,
            datasets: vec![Port::new(
                "state",
                Schema::new(vec![Field::new("runs", DataType::UInt64, false)]),
            )],
        });
        count.input_mode = InputMode::Resolved;
        count.inputs[0].source = InputSource::Query("WITH latest AS (SELECT MAX(owner_revision) AS revision FROM context_versions WHERE owner_id='qualification-window-v1') SELECT d.entity_key AS event,d.lifetime_key AS subject,d.body AS resource FROM context_versions d JOIN latest w ON d.owner_revision=w.revision WHERE d.owner_id='qualification-denials-v1' ORDER BY d.entity_key".into());
        let count = PackageArtifactV1 {
            descriptor: Package::new("denials.count", "1", vec![count]),
            implementations: vec![PackageImplementationV1::Sql {
                export: "count".into(),
                program: SqlModelV1 {
                    outputs: BTreeMap::from([("counts".into(), "SELECT subject,resource,CAST(COUNT(DISTINCT event) AS BIGINT UNSIGNED) AS count FROM denials GROUP BY subject,resource ORDER BY subject,resource".into())]),
                    checkpoint: BTreeMap::from([("state".into(), "SELECT CAST(COALESCE(MAX(runs),0)+1 AS BIGINT UNSIGNED) AS runs FROM prior_state".into())]),
                    ..Default::default()
                },
            }], fixtures: Vec::new(),
        };
        let mut rows = counts.clone();
        rows.name = "rows".into();
        let mut descriptor = Package::new(
            "denials.repeated",
            revision,
            vec![Model::new("repeated", vec![counts], vec![rows])],
        );
        descriptor.exports[0].input_mode = InputMode::Resolved;
        descriptor.exports[0].inputs[0].source = InputSource::Table(TableRef::Output(OutputRef {
            package: "denials.count".into(),
            revision: "1".into(),
            export: "count".into(),
            output: "counts".into(),
        }));
        let sql = if broken {
            "SELECT subject,resource,CAST('invalid' AS BIGINT UNSIGNED) AS count FROM counts".into()
        } else {
            format!("SELECT subject,resource,count FROM counts WHERE count>={threshold} ORDER BY subject,resource")
        };
        PackageBundleV1 {
            schema_version: 1,
            root: PackageRefV1 {
                package_id: "denials.repeated".into(),
                revision: revision.into(),
            },
            artifacts: vec![
                count,
                PackageArtifactV1 {
                    descriptor,
                    implementations: vec![PackageImplementationV1::Sql {
                        export: "repeated".into(),
                        program: SqlModelV1 {
                            outputs: BTreeMap::from([("rows".into(), sql)]),
                            ..Default::default()
                        },
                    }],
                    fixtures: Vec::new(),
                },
            ],
        }
    }
}
