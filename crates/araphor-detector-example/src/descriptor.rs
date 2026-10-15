use super::*;

impl BurstDetector {
    pub fn package() -> sdk::Package {
        Self::declaration().clone()
    }

    pub(super) fn declaration() -> &'static sdk::Package {
        static PACKAGE: std::sync::OnceLock<sdk::Package> = std::sync::OnceLock::new();
        PACKAGE.get_or_init(Self::build_package)
    }

    fn build_package() -> sdk::Package {
        let inputs = vec![
            Rows::port::<Observation>("records", "graph.observation.v1"),
            Rows::port::<Fact>("facts", "graph.fact.v1"),
            Rows::port::<Manifest>("manifest", "graph.manifest.v1"),
        ];
        let mut subjects = Rows::port::<Subject>("subjects", "graph.subject-selection.v1");
        subjects.kind = sdk::OutputKind::Subjects;
        let mut relationships =
            Rows::port::<Relationship>("relationships", "graph.relationship-candidate.v1");
        relationships.kind = sdk::OutputKind::Relationships;
        let mut findings = Rows::port::<Finding>("findings", "graph.finding-candidate.v1");
        findings.kind = sdk::OutputKind::Findings;
        findings.evidence_required = true;
        let mut model = sdk::Model::new("detect", inputs, vec![subjects, relationships, findings]);
        model.parameters = sdk::Schema::new(vec![sdk::Field::new(
            "threshold",
            sdk::DataType::UInt64,
            false,
        )]);
        model.reasons = vec![sdk::Reason {
            code: "example-burst.THRESHOLD".into(),
            details: sdk::Schema::new(vec![
                sdk::Field::new("threshold", sdk::DataType::UInt64, false),
                sdk::Field::new("count", sdk::DataType::UInt64, false),
            ]),
        }];
        model.checkpoint = Some(sdk::CheckpointSpec {
            version: 1,
            datasets: vec![Rows::port::<State>("state", "graph.state.v1")],
        });
        sdk::Package::new("example-burst", "1", vec![model])
    }
}
