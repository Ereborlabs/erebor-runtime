use serde::{Deserialize, Serialize};
use snafu::ResultExt as _;

use crate::{
    AnalysisContextKeyV1, AnalysisContextVersionV1, ContextSensitivityV1,
    PackageContextDecodeSnafu, PackageContextEncodeSnafu, Result,
};

use super::PackageErrorCodeV1 as Code;
use super::{PackageArtifactV1, PackageBundle, PackageBundleV1, PackageRefV1};

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
        Self::check_output(&bundle, &self.package, &self.export, &self.output)
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

impl AnalysisContextVersionV1 {
    pub fn from_package(
        value: &PackageBundle,
        tenant: [u8; 16],
        package: &PackageRefV1,
        export: &str,
        output: &str,
    ) -> Result<Self> {
        if tenant == [0; 16] {
            return Err(Code::Invalid.error("native package context tenant"));
        }
        NativePackageContext::check_output(value.bundle(), package, export, output)?;
        let body = rmp_serde::to_vec_named(&NativePackageContext {
            root: value.bundle().root.clone(),
            digest: value.digest().into(),
            package: package.clone(),
            export: export.into(),
            output: output.into(),
        })
        .context(PackageContextEncodeSnafu)?;
        Ok(Self {
            key: AnalysisContextKeyV1 {
                tenant_id: tenant,
                owner_id: "native-package-v1".into(),
                entity_key: super::native::Qualification::digest(&body).into_bytes(),
                lifetime_key: value.digest().as_bytes().to_vec(),
                owner_revision: 1,
            },
            valid_from_utc_ns: None,
            valid_until_utc_ns: None,
            sensitivity: ContextSensitivityV1::Tenant,
            body,
        })
    }

    pub(crate) fn package_provenance(&self) -> Result<Option<NativePackageContext>> {
        if self.key.owner_id != "native-package-v1" {
            return Ok(None);
        }
        let mut decoder = rmp_serde::Deserializer::new(std::io::Cursor::new(&self.body));
        let reference =
            NativePackageContext::deserialize(&mut decoder).context(PackageContextDecodeSnafu)?;
        if decoder.position() != self.body.len() as u64 {
            return Err(Code::Invalid.error("native package context trailing bytes"));
        }
        if self.sensitivity != ContextSensitivityV1::Tenant
            || self.valid_from_utc_ns.is_some()
            || self.valid_until_utc_ns.is_some()
            || self.key.owner_revision != 1
            || self.key.entity_key != super::native::Qualification::digest(&self.body).as_bytes()
            || self.key.lifetime_key != reference.digest.as_bytes()
        {
            return Err(Code::Invalid.error("native package context identity"));
        }
        Ok(Some(reference))
    }
}
