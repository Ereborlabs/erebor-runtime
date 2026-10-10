use arrow_array::{Array, ArrayRef, BinaryArray, BooleanArray, TimestampNanosecondArray};

use super::*;

// These bytes are fixture identities. They do not use the host identity encoding.

pub(super) const KEYS: [&[u8]; 3] = [
    b"tenant.1/node.1/boot.1/epoch.1/task/process.1\0",
    b"tenant.1/node.2/boot.2/epoch.1/task/process.1\0",
    b"tenant.1/node.2/boot.2/epoch.2/task/process.1\0",
];
pub(super) const SOURCES: [&[u8]; 2] = [
    b"tenant.1/node.1/boot.1/epoch.1/source.1/epoch.1",
    b"tenant.1/node.2/boot.2/epoch.1/source.2/epoch.1",
];
pub(super) const WINDOW_START: i64 = 9_007_199_254_740_993;

pub(super) struct SelectedGraph {
    pub(super) package: Package,
    pub(super) fixture: Fixture,
}

impl SelectedGraph {
    fn package() -> Package {
        let version = Field::new("result_id", DataType::Utf8, false);
        let subject = Schema::new(vec![
            version.clone(),
            Field::new("subject_key", DataType::Binary, false),
        ]);
        let relationship = Schema::new(vec![
            version.clone(),
            Field::new("from_subject", DataType::Binary, false),
            Field::new("to_subject", DataType::Binary, false),
        ]);
        let timestamp = DataType::Timestamp(TimeUnit::Nanosecond, Some("UTC".into()));
        let selection = Schema::new(vec![
            version,
            Field::new("source_key", DataType::Binary, false),
            Field::new("hop_boundary", DataType::Boolean, false),
            Field::new("window_start", timestamp.clone(), false),
            Field::new("window_end", timestamp, false),
        ]);
        let inputs = vec![
            Port::new("subjects", subject),
            Port::new("relationships", relationship),
            Port::new("selection", selection.clone()),
        ];
        let mut summary = selection.fields().to_vec();
        summary.extend([
            Arc::new(Field::new("subject_count", DataType::UInt64, false)),
            Arc::new(Field::new("relationship_count", DataType::UInt64, false)),
        ]);
        let mut outputs = inputs.clone();
        outputs[0].kind = OutputKind::Subjects;
        outputs[1].kind = OutputKind::Relationships;
        outputs[2].schema = Schema::new(summary);
        for output in &mut outputs {
            output.evidence_required = true;
        }
        Package::new(
            "graph.fixture",
            "1",
            vec![Model::new("select", inputs, outputs)],
        )
    }

    fn columns() -> [Vec<ArrayRef>; 3] {
        [
            vec![
                Arc::new(StringArray::from(vec![
                    "result.1", "result.1", "result.2", "result.2",
                ])),
                Arc::new(BinaryArray::from(vec![KEYS[0], KEYS[1], KEYS[0], KEYS[2]])),
            ],
            vec![
                Arc::new(StringArray::from(vec!["result.1", "result.2"])),
                Arc::new(BinaryArray::from(vec![KEYS[0], KEYS[0]])),
                Arc::new(BinaryArray::from(vec![KEYS[1], KEYS[2]])),
            ],
            vec![
                Arc::new(StringArray::from(vec![
                    "result.1",
                    "result.2",
                    "replacement.empty.3",
                ])),
                Arc::new(BinaryArray::from(vec![SOURCES[0], SOURCES[1], SOURCES[0]])),
                Arc::new(BooleanArray::from(vec![true, false, false])),
                Arc::new(
                    TimestampNanosecondArray::from(vec![
                        WINDOW_START,
                        WINDOW_START,
                        WINDOW_START + 10,
                    ])
                    .with_timezone("UTC"),
                ),
                Arc::new(
                    TimestampNanosecondArray::from(vec![
                        WINDOW_START + 9,
                        WINDOW_START + 9,
                        WINDOW_START + 19,
                    ])
                    .with_timezone("UTC"),
                ),
            ],
        ]
    }

    pub(super) fn new() -> Self {
        let package = Self::package();
        let inputs = package.exports[0].inputs.clone();
        let fixture = Fixture {
            implementation: "selected-rust.1".into(),
            revision: "bounded-graph.1".into(),
            evaluation: Evaluation {
                export: "select".into(),
                inputs: inputs
                    .into_iter()
                    .zip(Self::columns())
                    .map(|(port, columns)| Input {
                        data: Dataset {
                            name: port.name,
                            batches: vec![RecordBatch::try_new(Arc::new(port.schema), columns)
                                .expect("graph fixture schema")],
                        },
                        revision: Revision {
                            owner: "AnalysisStore".into(),
                            id: "read.revision.7".into(),
                            window: Some(SourceWindow {
                                source: b"tenant.1/selected-graph".to_vec(),
                                start_utc_ns: WINDOW_START,
                                end_utc_ns: WINDOW_START + 19,
                            }),
                        },
                        coverage: Coverage {
                            state: CoverageState::Gapped,
                            limits: vec!["MISSING_SOURCE_INTERVAL".into()],
                        },
                    })
                    .collect(),
                parameters: None,
                context: EvaluationContext {
                    id: "selected.1".into(),
                    time_utc_ns: WINDOW_START + 19,
                    seed: None,
                    limits: Limits {
                        max_batches: 3,
                        max_rows: 9,
                        max_bytes: 16_384,
                        max_checkpoint_bytes: 1024,
                    },
                },
                checkpoint: None,
            },
        };
        Self { package, fixture }
    }

    pub(super) fn column<A: Array + 'static>(batch: &RecordBatch, index: usize) -> &A {
        batch
            .column(index)
            .as_any()
            .downcast_ref()
            .expect("graph column")
    }

    pub(super) fn evaluate(&self, input: &Evaluation) -> Result<Output> {
        assert_eq!(input.context, self.fixture.evaluation.context);
        for selected in &input.inputs {
            assert_eq!(
                selected.revision,
                self.fixture.evaluation.inputs[0].revision
            );
            assert_eq!(
                selected.coverage,
                self.fixture.evaluation.inputs[0].coverage
            );
        }
        let summary = self.summary(input)?;
        let mut output = Output::default();
        for selected in &input.inputs {
            let batch = if selected.data.name == "selection" {
                summary.clone()
            } else {
                selected.data.batches[0].clone()
            };
            for row in 0..batch.num_rows() {
                let reference = RowRef {
                    dataset: selected.data.name.clone(),
                    row: row as u64,
                };
                output.evidence.push(EvidenceLink {
                    output: reference.clone(),
                    input: reference,
                });
            }
            output.datasets.push(Dataset {
                name: selected.data.name.clone(),
                batches: vec![batch],
            });
        }
        Ok(output)
    }

    fn summary(&self, input: &Evaluation) -> Result<RecordBatch> {
        let subjects = &input.input("subjects")?.data.batches[0];
        let subject_versions = Self::column::<StringArray>(subjects, 0);
        let keys = Self::column::<BinaryArray>(subjects, 1);
        let relationships = &input.input("relationships")?.data.batches[0];
        let relationship_versions = Self::column::<StringArray>(relationships, 0);
        let from = Self::column::<BinaryArray>(relationships, 1);
        let to = Self::column::<BinaryArray>(relationships, 2);
        let selection = &input.input("selection")?.data.batches[0];
        let versions = Self::column::<StringArray>(selection, 0);
        let mut subject_counts = Vec::new();
        let mut relationship_counts = Vec::new();
        for version in versions.iter().flatten() {
            let subjects = (0..subject_versions.len())
                .filter(|row| subject_versions.value(*row) == version)
                .collect::<Vec<_>>();
            let edges = (0..relationship_versions.len())
                .filter(|row| relationship_versions.value(*row) == version)
                .collect::<Vec<_>>();
            for row in &edges {
                for endpoint in [from.value(*row), to.value(*row)] {
                    assert!(subjects.iter().any(|row| keys.value(*row) == endpoint));
                }
            }
            subject_counts.push(subjects.len() as u64);
            relationship_counts.push(edges.len() as u64);
        }
        let mut columns = selection.columns().to_vec();
        columns.extend([
            Arc::new(UInt64Array::from(subject_counts)) as ArrayRef,
            Arc::new(UInt64Array::from(relationship_counts)),
        ]);
        Ok(RecordBatch::try_new(
            Arc::new(self.package.exports[0].outputs[2].schema.clone()),
            columns,
        )?)
    }
}
