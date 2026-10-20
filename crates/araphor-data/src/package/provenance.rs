use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use snafu::ResultExt as _;

use crate::{
    AnalysisContextKeyV1, AnalysisContextVersionV1, ContextSensitivityV1, PackageEncodingSnafu,
    Result,
};

use super::PackageErrorCodeV1 as Code;
use super::{InstalledRefV1, PackageBundleRef, PackageRefV1};

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct NativePackageContext {
    pub(crate) root: PackageRefV1,
    digest: String,
    export: String,
    output: String,
}

impl PackageBundleRef<'_> {
    pub fn context(
        &self,
        tenant: [u8; 16],
        export: &str,
        output: &str,
    ) -> Result<AnalysisContextVersionV1> {
        if tenant == [0; 16] {
            return Err(Code::Invalid.error("native package context tenant"));
        }
        self.check_output(export, output)?;
        let body = serde_json::to_vec(&NativePackageContext {
            root: self.bundle().root.clone(),
            digest: self.digest().into(),
            export: export.into(),
            output: output.into(),
        })
        .context(PackageEncodingSnafu)?;
        Ok(AnalysisContextVersionV1 {
            key: AnalysisContextKeyV1 {
                tenant_id: tenant,
                owner_id: "native-package-v1".into(),
                entity_key: super::native::Qualification::digest(&body).into_bytes(),
                lifetime_key: self.digest().as_bytes().to_vec(),
                owner_revision: 1,
            },
            valid_from_utc_ns: None,
            valid_until_utc_ns: None,
            sensitivity: ContextSensitivityV1::Tenant,
            body,
        })
    }

    pub(crate) fn provenance(
        context: &AnalysisContextVersionV1,
    ) -> Result<Option<NativePackageContext>> {
        if context.key.owner_id != "native-package-v1" {
            return Ok(None);
        }
        let reference: NativePackageContext =
            serde_json::from_slice(&context.body).context(PackageEncodingSnafu)?;
        if context.sensitivity != ContextSensitivityV1::Tenant
            || context.valid_from_utc_ns.is_some()
            || context.valid_until_utc_ns.is_some()
            || context.key.owner_revision != 1
            || context.key.entity_key
                != super::native::Qualification::digest(&context.body).as_bytes()
            || context.key.lifetime_key != reference.digest.as_bytes()
        {
            return Err(Code::Invalid.error("native package context identity"));
        }
        Ok(Some(reference))
    }

    pub(crate) fn validate_context(&self, context: &AnalysisContextVersionV1) -> Result<()> {
        let reference = Self::provenance(context)?
            .ok_or_else(|| Code::Invalid.error("native package context owner"))?;
        if reference.root != self.bundle().root || reference.digest != self.digest() {
            return Err(Code::Invalid.error("native package bundle digest"));
        }
        self.check_output(&reference.export, &reference.output)
    }

    fn check_output(&self, export: &str, output: &str) -> Result<()> {
        self.bundle().validate()?;
        let artifact = self.bundle().artifact(&self.bundle().root)?;
        let model = artifact
            .descriptor
            .exports
            .iter()
            .find(|model| model.name == export)
            .ok_or_else(|| Code::Missing.error("native package context export"))?;
        artifact.implementation(export)?;
        if !model.outputs.iter().any(|port| port.name == output) {
            return Err(Code::Missing.error("native package context output"));
        }
        Ok(())
    }
}

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
