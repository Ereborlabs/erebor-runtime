use super::*;
use crate::{InstalledAnalysis, InstalledRefV1, Result};

impl DiscoveryOwner {
    pub fn installed_refs(
        &self,
        profile: &DiscoveryProfileV1,
    ) -> Result<Option<Vec<InstalledRefV1>>> {
        profile.validate()?;
        let mut packages = None;
        for reference in profile
            .context_refs
            .iter()
            .filter(|reference| reference.key.owner_id == "discovery-source-v1")
        {
            let Some(context) = self.store.context_version(&reference.key)? else {
                return Ok(None);
            };
            if packages.is_some()
                || context.key.lifetime_key != profile.scope.identity.key()
                || context.sensitivity != crate::ContextSensitivityV1::Tenant
            {
                return Ok(None);
            }
            let Some(refs) = InstalledRefV1::context_refs(&context)? else {
                return Ok(None);
            };
            if !Self::complete_refs(&refs) {
                return Ok(None);
            }
            packages = Some(refs);
        }
        Ok(packages)
    }

    pub(super) fn analysis_refs(execution: &InstalledAnalysis) -> Result<Vec<InstalledRefV1>> {
        let refs: Vec<_> = execution
            .refs()?
            .into_iter()
            .filter(|reference| reference.package_id == DISCOVERY_PROCESSOR)
            .collect();
        if !Self::complete_refs(&refs) {
            return Err(
                crate::PackageErrorCodeV1::Missing.error("required installed discovery exports")
            );
        }
        Ok(refs)
    }

    pub(super) fn package_revisions(refs: &[InstalledRefV1]) -> Vec<(String, String)> {
        refs.iter()
            .map(|reference| (reference.package_id.clone(), reference.revision.clone()))
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect()
    }

    fn complete_refs(refs: &[InstalledRefV1]) -> bool {
        let expected: std::collections::BTreeSet<_> =
            araphor_analysis_builtins::discovery::Discovery::package()
                .exports
                .into_iter()
                .map(|model| model.name)
                .collect();
        refs.len() == expected.len()
            && refs
                .iter()
                .all(|reference| reference.package_id == DISCOVERY_PROCESSOR)
            && refs
                .iter()
                .map(|reference| reference.export.clone())
                .collect::<std::collections::BTreeSet<_>>()
                == expected
    }
}
