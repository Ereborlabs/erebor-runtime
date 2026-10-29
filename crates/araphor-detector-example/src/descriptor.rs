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
        let inputs = Detector::inputs().to_vec();
        let mut subjects = SubjectChange::port();
        subjects.kind = sdk::OutputKind::Subjects;
        let mut relationships = RelationshipChange::port();
        relationships.kind = sdk::OutputKind::Relationships;
        let mut findings = FindingChange::port();
        findings.kind = sdk::OutputKind::Findings;
        findings.evidence_required = true;
        let mut model = sdk::Model::new(
            "detect",
            inputs,
            vec![
                subjects,
                SubjectRemoval::port(),
                relationships,
                RelationshipRemoval::port(),
                findings,
                FindingRemoval::port(),
                Progress::port(),
                ProgressRemoval::port(),
            ],
        );
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
            resume_input_changes: false,
            version: 1,
            datasets: vec![GraphPackageStateV1::port()],
        });
        sdk::Package::new("example-burst", "1", vec![model])
    }
}
