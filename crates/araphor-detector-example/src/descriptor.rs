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
        let mut subjects = SubjectChange::port();
        subjects.kind = sdk::OutputKind::Subjects;
        let mut model = sdk::Model::new(
            "detect",
            vec![
                Unit::port(),
                Unit::removals_port(),
                sdk::ChangeInputs::reset_port("reset"),
                Observation::port(),
                Fact::port(),
                Unit::affected_port(),
                Unit::window_port(),
            ],
            vec![subjects],
        );
        model.input_mode = sdk::InputMode::Resolved;
        model.graph = Some(sdk::GraphSpec {
            access: sdk::GraphAccess::ReadWrite,
            relations: araphor_analysis_types::DomainRelations::declarations(),
        });
        model.inputs[1].source = sdk::InputSource::Query(
            include_str!("units.sql").replace("__graph_roots", "before.__graph_roots"),
        );
        model.inputs[3].source = sdk::InputSource::Lookup(
            "SELECT records.* FROM graph_records records JOIN units ON records.id = units.record ORDER BY records.id".into(),
        );
        model.inputs[4].source = sdk::InputSource::Lookup(
            "SELECT arrow_cast(records.__row_index, 'UInt32') AS record, fact.key, fact.sensitivity, fact.value FROM graph_facts fact JOIN records ON records.id = fact.record ORDER BY fact.key".into(),
        );
        model.inputs[5].source = sdk::InputSource::Query("SELECT record FROM graph_dirty".into());
        model.inputs[6].source =
            sdk::InputSource::Table(sdk::TableRef::Named("graph_window".into()));
        model.change_inputs = Some(sdk::ChangeInputs {
            reset: "reset".into(),
            ports: vec![sdk::ChangeInput {
                affected: "affected".into(),
                before: "unit_removals".into(),
                after: "units".into(),
                current: None,
            }],
        });
        model.inputs[0].source = sdk::InputSource::Query(include_str!("units.sql").into());
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
        sdk::Package::new("example-burst", "1", vec![model])
    }
}
