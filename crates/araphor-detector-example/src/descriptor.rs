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
        let mut model = Detector::Process.descriptor().exports.remove(0);
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
