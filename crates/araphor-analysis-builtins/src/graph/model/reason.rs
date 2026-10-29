use araphor_analysis_sdk as sdk;
use std::collections::BTreeMap;

use super::{DeclaredFindingReasonV1, Finding, FindingReasonV1, FindingV1};
use crate::discovery::DiscoveryRecordIdV1;
use crate::graph::ReasonDetails;

impl FindingReasonV1 {
    pub fn from_output(
        package_id: &str,
        finding: &Finding,
        records: &BTreeMap<&DiscoveryRecordIdV1, u32>,
        value: &sdk::ReasonValue,
    ) -> sdk::Result<Self> {
        if value.code != finding.reason_code
            || value
                .code
                .strip_prefix(&format!("{package_id}."))
                .is_none_or(str::is_empty)
        {
            return Err(sdk::Error::contract(
                sdk::ErrorCode::Invalid,
                "graph candidate reason",
            ));
        }
        if let Some(known) = FindingV1::PACKAGES
            .contains(&package_id)
            .then(|| Self::from_analysis_code(package_id, &value.code).ok())
            .flatten()
            .filter(|_| value.details.schema().as_ref() == &ReasonDetails::port().schema)
        {
            let details = ReasonDetails::decode(&sdk::Dataset {
                name: ReasonDetails::port().name,
                batches: vec![value.details.clone()],
            })?;
            if details != [ReasonDetails::from_finding(finding, records)?] {
                return Err(sdk::Error::contract(
                    sdk::ErrorCode::Invalid,
                    "graph candidate reason",
                ));
            }
            Ok(known)
        } else {
            Ok(Self::Declared(DeclaredFindingReasonV1::from_value(value)?))
        }
    }

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
