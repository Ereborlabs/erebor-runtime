use std::{collections::BTreeMap, sync::Arc};

use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tonic::Status;

pub(crate) struct EvidenceAdmission {
    global: Arc<Semaphore>,
    tenants: BTreeMap<[u8; 16], Arc<Semaphore>>,
}

pub(crate) struct EvidencePermit {
    _global: OwnedSemaphorePermit,
    _tenant: OwnedSemaphorePermit,
}

impl From<&[crate::AllowedNodeIdentity]> for EvidenceAdmission {
    fn from(nodes: &[crate::AllowedNodeIdentity]) -> Self {
        Self {
            global: Arc::new(Semaphore::new(8)),
            tenants: nodes
                .iter()
                .filter_map(|node| {
                    uuid::Uuid::parse_str(&node.tenant_id)
                        .ok()
                        .map(|tenant| (*tenant.as_bytes(), Arc::new(Semaphore::new(2))))
                })
                .collect(),
        }
    }
}

impl EvidenceAdmission {
    #[allow(clippy::result_large_err)]
    pub(crate) fn acquire(&self, tenant: &[u8; 16]) -> Result<EvidencePermit, Status> {
        let tenant = self
            .tenants
            .get(tenant)
            .ok_or_else(|| Status::permission_denied("evidence tenant is not configured"))?;
        let global = self
            .global
            .clone()
            .try_acquire_owned()
            .map_err(|_| Status::resource_exhausted("global evidence admission is full"))?;
        let tenant = tenant
            .clone()
            .try_acquire_owned()
            .map_err(|_| Status::resource_exhausted("tenant evidence admission is full"))?;
        Ok(EvidencePermit {
            _global: global,
            _tenant: tenant,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn admission_releases_exact_capacity() -> Result<(), Box<dyn std::error::Error>> {
        let mut nodes: Vec<_> = (0..5)
            .map(|index| crate::AllowedNodeIdentity {
                node_id: index.to_string(),
                tenant_id: uuid::Uuid::from_bytes([index; 16]).to_string(),
                certificate_sha256: "a".repeat(64),
            })
            .collect();
        nodes.push(crate::AllowedNodeIdentity {
            node_id: "alias".into(),
            tenant_id: uuid::Uuid::from_bytes([0; 16]).simple().to_string(),
            certificate_sha256: "b".repeat(64),
        });
        let owner = EvidenceAdmission::from(nodes.as_slice());
        assert_eq!(owner.tenants.len(), 5);
        let first = owner.acquire(&[0; 16])?;
        let second = owner.acquire(&[0; 16])?;
        assert_eq!(
            owner
                .acquire(&[0; 16])
                .err()
                .ok_or("tenant limit absent")?
                .code(),
            tonic::Code::ResourceExhausted
        );
        let mut permits = vec![first, second];
        for tenant in [1, 1, 2, 2, 3, 3] {
            permits.push(owner.acquire(&[tenant; 16])?);
        }
        assert_eq!(
            owner
                .acquire(&[4; 16])
                .err()
                .ok_or("global limit absent")?
                .code(),
            tonic::Code::ResourceExhausted
        );
        permits.pop();
        let replacement = owner.acquire(&[4; 16])?;
        assert_eq!(
            owner
                .acquire(&[5; 16])
                .err()
                .ok_or("foreign tenant accepted")?
                .code(),
            tonic::Code::PermissionDenied
        );
        drop(permits);
        drop(replacement);
        let _first = owner.acquire(&[0; 16])?;
        let _second = owner.acquire(&[0; 16])?;
        assert_eq!(owner.global.available_permits(), 6);
        Ok(())
    }
}
