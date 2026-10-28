use araphor_analysis_sdk as sdk;

use super::{DeclaredFindingReasonV1, FindingReasonV1, FindingV1};

impl FindingReasonV1 {
    pub fn analysis_code(&self, package_id: &str) -> sdk::Result<String> {
        if let Self::Declared(reason) = self {
            reason.validate(package_id)?;
            return Ok(reason.code.clone());
        }
        if !FindingV1::PACKAGES.contains(&package_id) {
            return Err(sdk::Error::contract(
                sdk::ErrorCode::Invalid,
                "analysis package identity",
            ));
        }
        Ok(format!("{package_id}.{}", self.label()?))
    }

    pub fn from_analysis_code(package_id: &str, code: &str) -> sdk::Result<Self> {
        if !FindingV1::PACKAGES.contains(&package_id) {
            return Err(sdk::Error::contract(
                sdk::ErrorCode::Invalid,
                "analysis package identity",
            ));
        }
        let local = code
            .strip_prefix(&format!("{package_id}."))
            .ok_or_else(|| {
                sdk::Error::contract(sdk::ErrorCode::Invalid, "analysis reason namespace")
            })?;
        serde_json::from_value(serde_json::Value::String(local.into()))
            .map_err(|_| sdk::Error::contract(sdk::ErrorCode::Invalid, "analysis reason code"))
    }

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
        let schema = value.details.schema().as_ref().clone();
        let encoded = sdk::wire::Dataset::encode(
            &sdk::Dataset {
                name: "details".into(),
                batches: vec![value.details.clone()],
            },
            &schema,
        )?;
        Ok(Self {
            code: value.code.clone(),
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
