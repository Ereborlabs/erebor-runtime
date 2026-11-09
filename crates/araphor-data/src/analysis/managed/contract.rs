use araphor_discovery_definition::ImagePin;

use super::{ManagedCall, ManagedSpec};
use crate::{PackageBundle, PackageErrorCodeV1 as Code, Result};
use snafu::ResultExt as _;

impl ManagedSpec {
    pub(in crate::analysis) fn check_images(
        &self,
        definition: Option<&[u8]>,
        mut image: impl FnMut(&ImagePin) -> Result<Option<PackageBundle>>,
    ) -> Result<()> {
        let expected = self.definition.encode()?;
        if definition != Some(expected.as_slice()) {
            return Err(Code::Missing.error("managed definition pin"));
        }
        for pin in &self.definition.images {
            let bundle = image(pin)?.ok_or_else(|| Code::Missing.error("managed image"))?;
            if bundle.digest() != pin.digest {
                return Err(Code::Conflict.error("managed image digest"));
            }
            for call in self
                .manifest
                .calls
                .values()
                .filter(|call| call.image == *pin)
            {
                let artifact = bundle.bundle().artifact(&call.package)?;
                if !artifact
                    .descriptor
                    .exports
                    .iter()
                    .any(|model| model.name == call.export)
                {
                    return Err(Code::Missing.error("managed export"));
                }
                let implementation = artifact.implementation(&call.export)?;
                if call.target != implementation.target()
                    || call.artifact != implementation.identity()?
                {
                    return Err(Code::Invalid.error("managed implementation pin"));
                }
            }
        }
        Ok(())
    }
}

impl ManagedCall {
    pub(in crate::analysis) fn contract(
        &self,
        bytes: &[u8],
    ) -> Result<araphor_analysis_sdk::Package> {
        let descriptor: araphor_analysis_sdk::Package =
            serde_json::from_slice(bytes).context(crate::PackageEncodingSnafu)?;
        if descriptor.id != self.package.package_id || descriptor.revision != self.package.revision
        {
            return Err(Code::Invalid.error("managed SDK descriptor pin"));
        }
        Ok(descriptor)
    }
}
