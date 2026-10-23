use std::collections::BTreeSet;
use std::sync::Arc;

use araphor_data::{
    DiscoveryProfileV1, EvidenceIntakeIdentityV1, PackageErrorCodeV1 as Code, ProcessorScopeV1,
    DISCOVERY_PROCESSOR, DISCOVERY_SCHEMA_VERSION,
};

use crate::{InstanceHost, Package, Result};

mod feed;
mod output;
mod publication;
mod replay;

pub struct DiscoveryOwner {
    packages: Vec<Arc<Package>>,
    host: Arc<InstanceHost>,
}

impl DiscoveryOwner {
    pub fn new(packages: Vec<Package>, host: Arc<InstanceHost>) -> Result<Self> {
        if packages.is_empty() {
            return Err(Code::Invalid.error("discovery packages").into());
        }
        let mut tenants = BTreeSet::new();
        for package in &packages {
            package.check()?;
            if !tenants.insert(package.grant.selection.tenant_id) {
                return Err(Code::Invalid.error("duplicate discovery tenant").into());
            }
            if !Arc::ptr_eq(&package.query, &packages[0].query) {
                return Err(Code::Invalid.error("discovery query owner").into());
            }
        }
        host.check_query(&packages[0].query)?;
        packages[0].query.store().register_discovery_owner();
        Ok(Self {
            packages: packages.into_iter().map(Arc::new).collect(),
            host,
        })
    }

    fn package(&self, tenant: [u8; 16]) -> Result<&Arc<Package>> {
        self.packages
            .iter()
            .find(|package| package.grant.selection.tenant_id == tenant)
            .ok_or_else(|| Code::Denied.error("discovery package tenant").into())
    }

    pub fn profile(&self, source: &EvidenceIntakeIdentityV1) -> Result<Option<DiscoveryProfileV1>> {
        let package = self.package(source.tenant_id)?;
        package.selection(Some(source))?;
        package.check()?;
        let scope = ProcessorScopeV1 {
            processor_id: DISCOVERY_PROCESSOR.into(),
            method_version: u64::from(DISCOVERY_SCHEMA_VERSION),
            identity: source.clone(),
        };
        let profile = package
            .query
            .store()
            .processor_result(&scope)?
            .map(|result| DiscoveryProfileV1::try_from(result.body.as_slice()))
            .transpose()?;
        if profile
            .as_ref()
            .is_some_and(|profile| profile.scope != scope)
        {
            return Err(Code::Invalid.error("discovery profile source").into());
        }
        package.check()?;
        Ok(profile)
    }
}

impl Drop for DiscoveryOwner {
    fn drop(&mut self) {
        self.packages[0].query.store().release_discovery_owner();
    }
}

#[cfg(test)]
mod tests;
