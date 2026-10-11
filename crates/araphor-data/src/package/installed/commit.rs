use std::collections::BTreeSet;
use std::sync::Arc;

use crate::Result;

use super::super::owner::InstalledContext;
use super::super::{
    AnalysisPackageOwner, PackageActionV1 as Action, PackageErrorCodeV1 as Code, PackageGrantV1,
};
use super::snapshot::InstalledBundle;
use super::InstalledAnalysis;

impl InstalledAnalysis {
    pub fn authorize<T>(
        &self,
        tenant: [u8; 16],
        expected: &[(String, String)],
        operation: impl FnOnce() -> Result<T>,
    ) -> Result<T> {
        if self.historical {
            return Err(Code::Denied.error("historical package commit"));
        }
        let snapshot = self.snapshot(tenant)?;
        let _lifecycle = self
            .owner
            .lifecycle
            .lock()
            .map_err(|_| Code::Conflict.error("package lifecycle lock"))?;
        let expected: BTreeSet<_> = expected.iter().collect();
        let mut grants = Vec::<(PackageGrantV1, Arc<InstalledBundle>)>::new();
        for pin in snapshot
            .pins()
            .iter()
            .filter(|pin| expected.contains(&(pin.key.package_id.clone(), pin.revision.clone())))
        {
            let current = self
                .owner
                .store
                .package_activation(&pin.key)?
                .ok_or_else(|| Code::Conflict.error("installed commit activation"))?;
            if !current.active
                || current.generation != pin.generation
                || current.revision != pin.revision
                || current.metadata != pin.metadata
            {
                return Err(Code::Conflict.error("installed commit revision"));
            }
            let context: InstalledContext = AnalysisPackageOwner::decode(&current.metadata)?;
            if !grants
                .iter()
                .any(|(grant, bundle)| grant == &context.grant && bundle.value.root == context.root)
            {
                let bundle = snapshot.bundle(tenant, &context.root)?;
                grants.push((context.grant, bundle));
            }
        }
        let actual: BTreeSet<_> = snapshot.revisions().into_iter().collect();
        if expected.is_empty() || expected.iter().any(|item| !actual.contains(*item)) {
            return Err(Code::Conflict.error("installed commit manifest"));
        }
        let mut callback = Some(operation);
        let mut result = None;
        let grants: Vec<_> = grants
            .iter()
            .map(|(grant, bundle)| (grant, &bundle.value))
            .collect();
        self.owner
            .authority
            .commit_many(&grants, Action::Run, &mut || {
                let operation = callback
                    .take()
                    .ok_or_else(|| Code::Invalid.error("commit callback"))?;
                result = Some(operation()?);
                Ok(())
            })?;
        result.ok_or_else(|| Code::Denied.error("installed commit authority"))
    }
}

#[cfg(test)]
mod tests;
