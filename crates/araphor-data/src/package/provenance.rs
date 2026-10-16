use std::collections::BTreeSet;

use snafu::ResultExt as _;

use crate::{AnalysisContextVersionV1, ContextSensitivityV1, PackageEncodingSnafu, Result};

use super::InstalledRefV1;
use super::PackageErrorCodeV1 as Code;

impl InstalledRefV1 {
    pub fn context_refs(context: &AnalysisContextVersionV1) -> Result<Option<Vec<Self>>> {
        let required = match context.key.owner_id.as_str() {
            "discovery-source-v1" => false,
            "graph-packages-v1" => true,
            _ => return Ok(None),
        };
        let body: serde_json::Value =
            serde_json::from_slice(&context.body).context(PackageEncodingSnafu)?;
        let body = body
            .as_object()
            .ok_or_else(|| Code::Invalid.error("installed context object"))?;
        let Some(value) = body.get("installed_packages") else {
            return if required {
                Err(Code::Invalid.error("missing installed context references"))
            } else {
                Ok(None)
            };
        };
        let values = value
            .as_array()
            .ok_or_else(|| Code::Invalid.error("installed context references"))?;
        if context.sensitivity != ContextSensitivityV1::Tenant
            || values.is_empty()
            || values.len() > crate::analysis::MAX_PACKAGE_ROWS
            || values.iter().any(|value| value.get("parameters").is_none())
        {
            return Err(Code::Invalid.error("installed context reference fields"));
        }
        let references: Vec<Self> =
            serde_json::from_value(value.clone()).context(PackageEncodingSnafu)?;
        let mut seen = BTreeSet::new();
        for reference in &references {
            if reference.generation == 0
                || reference
                    .parameters
                    .as_ref()
                    .is_some_and(|value| !value.is_object())
                || !seen.insert((&reference.package_id, &reference.export))
            {
                return Err(Code::Invalid.error("installed context reference identity"));
            }
            for name in [
                &reference.package_id,
                &reference.export,
                &reference.revision,
                &reference.root.package_id,
                &reference.root.revision,
            ] {
                super::validate_package_name(name)?;
            }
        }
        Ok(Some(references))
    }

    pub fn validate_parameters(&self, model: &araphor_analysis_sdk::Model) -> Result<()> {
        super::decode_parameters(
            &model.parameters,
            super::parameter_values(self.parameters.as_ref(), &self.package_id, &self.export),
        )?;
        Ok(())
    }
}
