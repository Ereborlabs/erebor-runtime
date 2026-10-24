use std::{collections::BTreeMap, sync::Arc};

use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tonic::Status;

pub(crate) struct EvidenceAdmission {
    global: Option<Arc<Semaphore>>,
    nodes: BTreeMap<String, Option<Arc<Semaphore>>>,
}

pub(crate) struct EvidencePermit {
    _global: Option<OwnedSemaphorePermit>,
    _node: Option<OwnedSemaphorePermit>,
}

impl EvidenceAdmission {
    pub(crate) fn new<'a>(
        nodes: impl IntoIterator<Item = &'a crate::AllowedNodeIdentity>,
        limits: crate::EvidenceAdmissionLimits,
    ) -> Self {
        Self {
            global: limits
                .total_slots
                .map(|slots| Arc::new(Semaphore::new(slots))),
            nodes: nodes
                .into_iter()
                .map(|node| {
                    (
                        node.node_id.clone(),
                        limits
                            .slots_per_node
                            .map(|slots| Arc::new(Semaphore::new(slots))),
                    )
                })
                .collect(),
        }
    }
    pub(crate) async fn acquire(&self, node_id: &str) -> Result<EvidencePermit, Status> {
        let node = self
            .nodes
            .get(node_id)
            .ok_or_else(|| Status::permission_denied("evidence Node is not configured"))?;
        let node = match node {
            Some(node) => Some(
                Arc::clone(node)
                    .acquire_owned()
                    .await
                    .map_err(|_| Status::unavailable("Node evidence admission is closed"))?,
            ),
            None => None,
        };
        // A Node that waits for its own slot must not hold a global slot.
        let global = match &self.global {
            Some(global) => Some(
                Arc::clone(global)
                    .acquire_owned()
                    .await
                    .map_err(|_| Status::unavailable("global evidence admission is closed"))?,
            ),
            None => None,
        };
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
                total_slots: Some(2),
                slots_per_node: Some(1),
            },
        );
        let global = owner.global.as_ref().ok_or("global gate absent")?;
        let mut context = Context::from_waker(Waker::noop());
        let first = owner.acquire("0").await?;
        let mut same_node = Box::pin(owner.acquire("0"));
        assert!(same_node.as_mut().poll(&mut context).is_pending());
        assert_eq!(global.available_permits(), 1);
        let second = owner.acquire("1").await?;
        let mut third = Box::pin(owner.acquire("2"));
        let mut fourth = Box::pin(owner.acquire("3"));
        assert!(third.as_mut().poll(&mut context).is_pending());
        assert!(fourth.as_mut().poll(&mut context).is_pending());
        drop(second);
        assert!(fourth.as_mut().poll(&mut context).is_pending());
        let third = third.await?;
        drop(fourth);
        assert_eq!(
            owner.nodes["3"]
                .as_ref()
                .ok_or("node gate absent")?
                .available_permits(),
            1
        );
        drop(same_node);
        drop(first);
        drop(third);
        assert_eq!(global.available_permits(), 2);
        assert!(owner.nodes.values().all(|node| node
            .as_ref()
            .is_some_and(|node| node.available_permits() == 1)));
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
                total_slots: Some(12),
                slots_per_node: Some(3),
            },
        );
        let global = owner.global.as_ref().ok_or("global gate absent")?;
        let mut permits = Vec::new();
        for node in &nodes {
            for _ in 0..3 {
                permits.push(owner.acquire(&node.node_id).await?);
            }
        }
        assert_eq!(global.available_permits(), 0);
        drop(permits);
        assert_eq!(global.available_permits(), 12);
        Ok(())
    }

    #[tokio::test]
    async fn admission_optional_gates() -> Result<(), Box<dyn std::error::Error>> {
        let nodes: Vec<_> = (0..2)
            .map(|index| crate::AllowedNodeIdentity {
                node_id: index.to_string(),
                tenant_id: uuid::Uuid::from_bytes([1; 16]).to_string(),
                certificate_sha256: "a".repeat(64),
            })
            .collect();
        let owner = EvidenceAdmission::new(&nodes, crate::EvidenceAdmissionLimits::default());
        assert!(owner.global.is_none());
        assert!(owner.nodes.values().all(Option::is_none));
        let mut context = Context::from_waker(Waker::noop());
        let mut permits = Vec::new();
        for _ in 0..12 {
            let mut pending = Box::pin(owner.acquire("0"));
            let std::task::Poll::Ready(permit) = pending.as_mut().poll(&mut context) else {
                return Err("disabled evidence gates waited".into());
            };
            permits.push(permit?);
        }
        assert_eq!(
            owner
                .acquire("unknown")
                .await
                .err()
                .ok_or("unknown Node accepted")?
                .code(),
            tonic::Code::PermissionDenied
        );
        drop(permits);
        for limits in [
            crate::EvidenceAdmissionLimits {
                total_slots: Some(1),
                slots_per_node: None,
            },
            crate::EvidenceAdmissionLimits {
                total_slots: None,
                slots_per_node: Some(1),
            },
        ] {
            let owner = EvidenceAdmission::new(&nodes, limits);
            assert_eq!(owner.global.is_none(), limits.total_slots.is_none());
            assert!(owner
                .nodes
                .values()
                .all(|node| node.is_none() == limits.slots_per_node.is_none()));
            let first = owner.acquire("0").await?;
            let mut waiting = Box::pin(owner.acquire("0"));
            assert!(waiting.as_mut().poll(&mut context).is_pending());
            let mut other = Box::pin(owner.acquire("1"));
            let other_permit = match other.as_mut().poll(&mut context) {
                std::task::Poll::Ready(permit) => Some(permit?),
                std::task::Poll::Pending => None,
            };
            assert_eq!(other_permit.is_some(), limits.total_slots.is_none());
            drop(other);
            drop(first);
            drop(waiting.await?);
            drop(other_permit);
            assert!(owner
                .global
                .as_ref()
                .is_none_or(|gate| gate.available_permits() == 1));
            assert!(owner.nodes.values().all(|node| node
                .as_ref()
                .is_none_or(|gate| gate.available_permits() == 1)));
        }
        Ok(())
    }
}
