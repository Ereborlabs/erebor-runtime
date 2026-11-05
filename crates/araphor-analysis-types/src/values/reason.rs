use super::*;
use araphor_analysis_sdk as sdk;
impl FindingReasonV1 {
    pub fn label(&self) -> sdk::Result<String> {
        match self {
            Self::Declared(reason) => Ok(reason.code.clone()),
            _ => serde_json::to_value(self)
                .map_err(|source| sdk::Error::Encoding {
                    source,
                    location: snafu::location!(),
                })?
                .as_str()
                .map(str::to_owned)
                .ok_or_else(|| {
                    sdk::Error::contract(sdk::ErrorCode::Invalid, "finding reason label")
                }),
        }
    }
}
impl DeclaredFindingReasonV1 {
    pub fn from_value(value: &sdk::ReasonValue) -> sdk::Result<Self> {
        Self::from_details(value.code.clone(), &value.details)
    }

    pub fn from_details(code: String, details: &sdk::RecordBatch) -> sdk::Result<Self> {
        let schema = details.schema().as_ref().clone();
        let encoded = sdk::wire::Dataset::encode(
            &sdk::Dataset {
                name: "details".into(),
                batches: vec![details.clone()],
            },
            &schema,
        )?;
        Ok(Self {
            code,
            schema,
            ipc: encoded.arrow_ipc,
        })
    }
}

impl DeclaredFindingReasonV1 {
    pub fn validate(&self, package: &str) -> sdk::Result<()> {
        if self
            .code
            .strip_prefix(&format!("{package}."))
            .is_none_or(str::is_empty)
        {
            return Err(sdk::Error::contract(
                sdk::ErrorCode::Invalid,
                "finding reason namespace",
            ));
        }
        let data = sdk::wire::Dataset::decode_ipc("details", &self.ipc, Some(&self.schema))?;
        if data.batches.len() != 1 || data.batches[0].num_rows() != 1 {
            return Err(sdk::Error::contract(
                sdk::ErrorCode::Invalid,
                "finding reason details",
            ));
        }
        sdk::Package::new(
            package,
            "1",
            vec![sdk::Model::new(
                "reason",
                Vec::new(),
                vec![sdk::Port::new("details", self.schema.clone())],
            )],
        )
        .validate()
    }
}
