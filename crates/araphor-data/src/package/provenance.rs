use serde::{Deserialize, Serialize};
use snafu::ResultExt as _;

use crate::{
    AnalysisContextKeyV1, AnalysisContextVersionV1, ContextSensitivityV1, PackageEncodingSnafu,
    Result,
};

use super::PackageErrorCodeV1 as Code;
use super::{PackageArtifactV1, PackageBundleRef, PackageBundleV1, PackageRefV1};

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct NativePackageContext {
    pub(crate) root: PackageRefV1,
    digest: String,
    package: PackageRefV1,
    export: String,
    output: String,
}

impl NativePackageContext {
    pub(crate) fn validate(self, artifacts: Vec<PackageArtifactV1>) -> Result<()> {
        let bundle = PackageBundleV1 {
            schema_version: 1,
            root: self.root,
            artifacts,
        };
        if bundle.checked_layout(&self.digest)?.is_none() {
            return Err(Code::Invalid.error("native package bundle digest"));
        }
        PackageBundleRef::check_output(&bundle, &self.package, &self.export, &self.output)
    }
}

impl PackageBundleRef<'_> {
    pub fn context(
        &self,
        tenant: [u8; 16],
        package: &PackageRefV1,
        export: &str,
        output: &str,
    ) -> Result<AnalysisContextVersionV1> {
        if tenant == [0; 16] {
            return Err(Code::Invalid.error("native package context tenant"));
        }
        self.bundle().validate()?;
        Self::check_output(self.bundle(), package, export, output)?;
        let body = serde_json::to_vec(&NativePackageContext {
            root: self.bundle().root.clone(),
            digest: self.digest().into(),
            package: package.clone(),
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

    fn check_output(
        bundle: &PackageBundleV1,
        package: &PackageRefV1,
        export: &str,
        output: &str,
    ) -> Result<()> {
        let artifact = bundle.artifact(package)?;
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
