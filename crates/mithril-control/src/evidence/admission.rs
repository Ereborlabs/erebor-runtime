use std::{collections::BTreeMap, sync::Arc};

use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tonic::Status;

pub(crate) struct EvidenceAdmission {
    global: Arc<Semaphore>,
    nodes: BTreeMap<String, Arc<Semaphore>>,
}

pub(crate) struct EvidencePermit {
    _global: OwnedSemaphorePermit,
    _node: OwnedSemaphorePermit,
}

impl EvidenceAdmission {
    pub(crate) fn new<'a>(
        nodes: impl IntoIterator<Item = &'a crate::AllowedNodeIdentity>,
        limits: crate::EvidenceAdmissionLimits,
    ) -> Self {
        Self {
            global: Arc::new(Semaphore::new(limits.total_slots)),
            nodes: nodes
                .into_iter()
                .map(|node| {
                    (
                        node.node_id.clone(),
                        Arc::new(Semaphore::new(limits.slots_per_node)),
                    )
                })
                .collect(),
        }
    }
    pub(crate) async fn acquire(&self, node_id: &str) -> Result<EvidencePermit, Status> {
        let node = self
            .nodes
            .get(node_id)
            .ok_or_else(|| Status::permission_denied("evidence Node is not configured"))?
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| Status::unavailable("Node evidence admission is closed"))?;
        // A Node that waits for its own slot must not hold a global slot.
        let global = self
            .global
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| Status::unavailable("global evidence admission is closed"))?;
        Ok(EvidencePermit {
            _global: global,
            _node: node,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::{
        future::Future as _,
        task::{Context, Waker},
    };

    use super::*;

    #[tokio::test]
    async fn admission_waits_and_releases() -> Result<(), Box<dyn std::error::Error>> {
        let nodes: Vec<_> = (0..4)
            .map(|index| crate::AllowedNodeIdentity {
                node_id: index.to_string(),
                tenant_id: uuid::Uuid::from_bytes([1; 16]).to_string(),
                certificate_sha256: "a".repeat(64),
            })
            .collect();
        let owner = EvidenceAdmission::new(
            &nodes,
            crate::EvidenceAdmissionLimits {
                total_slots: 2,
                slots_per_node: 1,
            },
        );
        let mut context = Context::from_waker(Waker::noop());
        let first = owner.acquire("0").await?;
        let mut same_node = Box::pin(owner.acquire("0"));
        assert!(same_node.as_mut().poll(&mut context).is_pending());
        assert_eq!(owner.global.available_permits(), 1);
        let second = owner.acquire("1").await?;
        let mut third = Box::pin(owner.acquire("2"));
        let mut fourth = Box::pin(owner.acquire("3"));
        assert!(third.as_mut().poll(&mut context).is_pending());
        assert!(fourth.as_mut().poll(&mut context).is_pending());
        drop(second);
        assert!(fourth.as_mut().poll(&mut context).is_pending());
        let third = third.await?;
        drop(fourth);
        assert_eq!(owner.nodes["3"].available_permits(), 1);
        drop(same_node);
        drop(first);
        drop(third);
        assert_eq!(owner.global.available_permits(), 2);
        assert!(owner
            .nodes
            .values()
            .all(|node| node.available_permits() == 1));
        let first = owner.acquire("0").await?;
        let mut replacement = Box::pin(owner.acquire("0"));
        assert!(replacement.as_mut().poll(&mut context).is_pending());
        drop(first);
        drop(replacement.await?);
        assert_eq!(
            owner
                .acquire("unknown")
                .await
                .err()
                .ok_or("unknown Node accepted")?
                .code(),
            tonic::Code::PermissionDenied
        );
        let owner = EvidenceAdmission::new(
            &nodes,
            crate::EvidenceAdmissionLimits {
                total_slots: 12,
                slots_per_node: 3,
            },
        );
        let mut permits = Vec::new();
        for node in &nodes {
            for _ in 0..3 {
                permits.push(owner.acquire(&node.node_id).await?);
            }
        }
        assert_eq!(owner.global.available_permits(), 0);
        drop(permits);
        assert_eq!(owner.global.available_permits(), 12);
        Ok(())
    }
}
