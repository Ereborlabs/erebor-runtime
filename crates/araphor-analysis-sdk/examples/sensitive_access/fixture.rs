use super::*;

impl SensitiveAccess {
    pub fn fixture() -> Result<Fixture> {
        let package = Self::package();
        let ports = &package.exports[0].inputs;
        let events = RecordBatch::try_new(
            Arc::new(ports[0].schema.clone()),
            vec![
                Arc::new(StringArray::from(vec![
                    "subject.1",
                    "subject.1",
                    "subject.2",
                ])),
                Arc::new(StringArray::from(vec![
                    "model.weights",
                    "hf.token",
                    "model.weights",
                ])),
                Arc::new(UInt64Array::from(vec![1, 2, 3])),
            ],
        )?;
        let baseline = RecordBatch::try_new(
            Arc::new(ports[1].schema.clone()),
            vec![
                Arc::new(StringArray::from(vec!["subject.1"])),
                Arc::new(StringArray::from(vec!["model.weights"])),
            ],
        )?;
        let inputs = [
            ("sensitive_reads", "reads.1", events),
            ("baseline", "audited-baseline.4", baseline),
        ]
        .into_iter()
        .map(|(name, revision, batch)| Input {
            data: Dataset {
                name: name.into(),
                batches: vec![batch],
            },
            revision: Revision {
                owner: "fixture".into(),
                id: revision.into(),
                window: Some(SourceWindow {
                    source: name.as_bytes().to_vec(),
                    start_utc_ns: 0,
                    end_utc_ns: 10,
                }),
            },
            coverage: Coverage {
                state: CoverageState::Complete,
                limits: vec![],
            },
        })
        .collect();
        Ok(Fixture {
            implementation: "portable-rust.1".into(),
            revision: "sensitive-access.1".into(),
            evaluation: Evaluation {
                export: "access.detect".into(),
                inputs,
                parameters: None,
                context: EvaluationContext {
                    id: "access.run.1".into(),
                    time_utc_ns: 10,
                    seed: None,
                    limits: Limits::default(),
                },
                checkpoint: None,
            },
        })
    }
}
