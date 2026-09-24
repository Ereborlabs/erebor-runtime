use std::collections::BTreeSet;

use serde::{de::DeserializeOwned, Deserialize, Serialize};

use crate::{
    error::ObservabilitySnafu, ControlStore, DiscoveryArtifactRefV1, DiscoveryArtifactV1,
    DiscoveryDigestV1, DiscoveryHeadKeyV1, DiscoveryHeadV1, Result, TraceFrameV1, TraceRecipeV1,
    TraceRequestV1, TraceTerminalV1, MAX_TRACE_OUTPUT_BYTES,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TraceErrorCodeV1 {
    Denied,
    Conflict,
    Expired,
    Missing,
    Capacity,
    Invalid,
    Integrity,
}

impl TraceErrorCodeV1 {
    pub(crate) fn require(self, condition: bool, reason: &'static str) -> Result<()> {
        if condition {
            Ok(())
        } else {
            ObservabilitySnafu { code: self, reason }.fail()
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TraceExecutionGrantV1 {
    pub tenant_id: [u8; 16],
    pub grant_id: [u8; 16],
    pub principal: String,
    pub namespace_uids: BTreeSet<String>,
    pub node_ids: BTreeSet<String>,
    pub recipe_digests: BTreeSet<DiscoveryDigestV1>,
    pub host_diagnostic: bool,
    pub valid_until_unix_ns: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TraceApprovalV1 {
    pub approval_id: [u8; 16],
    pub request_digest: DiscoveryDigestV1,
    pub grant_digest: DiscoveryDigestV1,
    pub valid_until_unix_ns: u64,
}

// The authenticated caller supplies current read authority, not request JSON.
#[derive(Clone, Debug)]
pub struct TraceReadAccessV1 {
    pub tenant_id: [u8; 16],
    pub namespace_uids: BTreeSet<String>,
    pub node_ids: BTreeSet<String>,
    pub host_sensitive: bool,
    pub valid_until_unix_ns: u64,
    pub revoked: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TraceAcceptedV1 {
    pub request: TraceRequestV1,
    pub grant: TraceExecutionGrantV1,
    pub approval: Option<TraceApprovalV1>,
    pub accepted_unix_ns: u64,
    pub deadline_unix_ns: u64,
    pub recipe: Option<TraceRecipeV1>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TraceBatchV1 {
    pub execution_id: [u8; 16],
    pub frames: Vec<TraceFrameV1>,
    pub terminal: Option<TraceTerminalV1>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TraceRevisionV1 {
    pub trace_schema_version: u32,
    pub accepted: DiscoveryArtifactRefV1,
    pub target_index: Option<u16>,
    pub previous: Option<DiscoveryHeadV1>,
    pub batch: Option<DiscoveryArtifactRefV1>,
    pub last_sequence: u64,
    pub output_bytes: u64,
    pub terminal: Option<TraceTerminalV1>,
    pub cancel_requested: bool,
    pub read_revoked: bool,
}

#[derive(Clone)]
pub struct TraceOwner {
    store: ControlStore,
}

pub(crate) struct TraceNodeWorkV1 {
    pub pending: Option<(TraceAcceptedV1, u16)>,
    pub cancel: Vec<[u8; 16]>,
}

impl TraceOwner {
    pub fn new(store: ControlStore) -> Self {
        Self { store }
    }

    pub(crate) fn node_work(
        &self,
        tenant: [u8; 16],
        node: &str,
        boot: [u8; 16],
        now: u64,
        retained: &[[u8; 16]],
    ) -> Result<TraceNodeWorkV1> {
        let mut pending = None;
        let mut cancel = Vec::new();
        // ponytail: scan bounded tenant heads; use the SQLite projection if this exceeds the poll budget.
        for head in self.store.discovery_heads(tenant)? {
            let artifact = self.store.read_discovery_artifact(&head.artifact)?;
            let Ok(candidate) = Self::decode::<TraceRevisionV1>(&artifact.payload) else {
                continue;
            };
            if candidate.target_index.is_some() {
                continue;
            }
            let (revision, accepted) = TraceRevisionV1::read(&self.store, &head)?;
            for (index, target) in accepted.request.targets.iter().enumerate() {
                if target.fact.node_id != node || target.node_boot_id != boot {
                    continue;
                }
                let index = index as u16;
                let execution = self.store.discovery_head(&TraceRevisionV1::key(
                    tenant,
                    accepted.request.request_id,
                    Some(index),
                )?)?;
                if execution
                    .as_ref()
                    .map(|head| TraceRevisionV1::read(&self.store, head))
                    .transpose()?
                    .is_some_and(|(revision, _)| revision.terminal.is_some())
                {
                    continue;
                }
                if revision.cancel_requested || now >= accepted.deadline_unix_ns {
                    if cancel.len() < 16 {
                        cancel.push(accepted.execution_id(index)?);
                    }
                } else if pending.is_none() && !retained.contains(&accepted.execution_id(index)?) {
                    pending = Some((accepted.clone(), index));
                }
            }
        }
        Ok(TraceNodeWorkV1 { pending, cancel })
    }

    pub fn accept(
        &self,
        request: TraceRequestV1,
        grant: TraceExecutionGrantV1,
        approval: Option<TraceApprovalV1>,
        now: u64,
    ) -> Result<DiscoveryHeadV1> {
        request.validate()?;
        let recipe = grant.authorize(&request, now)?;
        let key = TraceRevisionV1::key(request.tenant_id, request.request_id, None)?;
        if let Some(head) = self.store.discovery_head(&key)? {
            let (_, accepted) = TraceRevisionV1::read(&self.store, &head)?;
            TraceErrorCodeV1::Conflict.require(
                accepted.request == request
                    && accepted.grant == grant
                    && accepted.approval == approval,
                "trace request ID names different inputs",
            )?;
            return Ok(head);
        }
        let deadline = now
            .checked_add((u64::from(request.collection_seconds) + 15) * 1_000_000_000)
            .ok_or_else(|| {
                ObservabilitySnafu {
                    code: TraceErrorCodeV1::Invalid,
                    reason: "trace deadline overflowed",
                }
                .build()
            })?;
        let accepted = TraceAcceptedV1 {
            request,
            grant,
            approval,
            recipe,
            accepted_unix_ns: now,
            deadline_unix_ns: deadline,
        };
        accepted.validate()?;
        let accepted = self.put(&accepted, key.tenant_id, Vec::new())?;
        let revision = TraceRevisionV1 {
            trace_schema_version: 1,
            accepted,
            target_index: None,
            previous: None,
            batch: None,
            last_sequence: 0,
            output_bytes: 0,
            terminal: None,
            cancel_requested: false,
            read_revoked: false,
        };
        self.commit(key, revision)
    }

    pub fn read(
        &self,
        tenant: [u8; 16],
        request: [u8; 16],
        access: &TraceReadAccessV1,
        now: u64,
    ) -> Result<(DiscoveryHeadV1, TraceAcceptedV1)> {
        let head = self.request_head(tenant, request)?;
        let (revision, accepted) = TraceRevisionV1::read(&self.store, &head)?;
        accepted.authorize_read(access, now)?;
        TraceErrorCodeV1::Denied
            .require(!revision.read_revoked, "trace read authority was revoked")?;
        Ok((head, accepted))
    }

    pub fn request_head(&self, tenant: [u8; 16], request: [u8; 16]) -> Result<DiscoveryHeadV1> {
        self.store
            .discovery_head(&TraceRevisionV1::key(tenant, request, None)?)?
            .ok_or_else(|| {
                ObservabilitySnafu {
                    code: TraceErrorCodeV1::Missing,
                    reason: "trace request is absent",
                }
                .build()
            })
    }

    pub fn cancel(
        &self,
        tenant: [u8; 16],
        request: [u8; 16],
        principal: &str,
        revoke_read: bool,
    ) -> Result<DiscoveryHeadV1> {
        let head = self.request_head(tenant, request)?;
        let (mut revision, accepted) = TraceRevisionV1::read(&self.store, &head)?;
        TraceErrorCodeV1::Denied.require(
            accepted.grant.principal == principal,
            "trace cancellation requires the execution principal",
        )?;
        if revision.cancel_requested && (!revoke_read || revision.read_revoked) {
            return Ok(head);
        }
        revision.previous = Some(head.clone());
        revision.cancel_requested = true;
        revision.read_revoked |= revoke_read;
        self.commit(head.key, revision)
    }

    pub fn append(
        &self,
        tenant: [u8; 16],
        request: [u8; 16],
        target_index: u16,
        node_id: &str,
        node_boot_id: [u8; 16],
        mut batch: TraceBatchV1,
    ) -> Result<DiscoveryHeadV1> {
        batch.validate()?;
        let request_head = self.request_head(tenant, request)?;
        let (request_revision, accepted) = TraceRevisionV1::read(&self.store, &request_head)?;
        let execution = accepted.execution_id(target_index)?;
        let target = &accepted.request.targets[target_index as usize];
        TraceErrorCodeV1::Denied.require(
            target.fact.node_id == node_id
                && target.node_boot_id == node_boot_id
                && execution == batch.execution_id,
            "trace output does not match the authenticated execution",
        )?;
        let key = TraceRevisionV1::key(tenant, request, Some(target_index))?;
        let previous = self.store.discovery_head(&key)?;
        let mut revision = if let Some(head) = &previous {
            TraceRevisionV1::read(&self.store, head)?.0
        } else {
            TraceRevisionV1 {
                trace_schema_version: 1,
                accepted: request_revision.accepted,
                target_index: Some(target_index),
                previous: None,
                batch: None,
                last_sequence: 0,
                output_bytes: 0,
                terminal: None,
                cancel_requested: false,
                read_revoked: false,
            }
        };
        // Compare source frames. A reconnect can change batch boundaries.
        let overlap = batch
            .frames
            .iter()
            .take_while(|frame| frame.sequence <= revision.last_sequence)
            .count();
        let mut matched = 0;
        let mut cursor = previous.clone();
        while matched < overlap {
            let Some(head) = cursor else { break };
            let (prior, _) = TraceRevisionV1::read(&self.store, &head)?;
            if let Some(reference) = &prior.batch {
                let stored: TraceBatchV1 = Self::read_artifact(&self.store, reference)?;
                for frame in stored.frames {
                    if let Some(retry) = batch.frames[..overlap]
                        .iter()
                        .find(|retry| retry.sequence == frame.sequence)
                    {
                        TraceErrorCodeV1::Conflict
                            .require(*retry == frame, "trace retry changed a committed frame")?;
                        matched += 1;
                    }
                }
            }
            cursor = prior.previous;
        }
        TraceErrorCodeV1::Integrity
            .require(matched == overlap, "trace replay history is incomplete")?;
        batch.frames.drain(..overlap);
        if batch.frames.is_empty()
            && (batch.terminal.is_none() || batch.terminal == revision.terminal)
        {
            return previous.ok_or_else(|| {
                ObservabilitySnafu {
                    code: TraceErrorCodeV1::Integrity,
                    reason: "trace replay has no committed head",
                }
                .build()
            });
        }
        TraceErrorCodeV1::Conflict.require(
            revision.terminal.is_none(),
            "trace execution already has a terminal result",
        )?;
        if let Some(first) = batch.frames.first() {
            TraceErrorCodeV1::Conflict.require(
                first.sequence == revision.last_sequence + 1,
                "trace output has a gap or changed duplicate",
            )?;
        }
        let next_sequence = batch
            .frames
            .last()
            .map_or(revision.last_sequence, |frame| frame.sequence);
        let output_bytes = revision.output_bytes
            + batch
                .frames
                .iter()
                .map(|frame| frame.bytes.len() as u64)
                .sum::<u64>();
        TraceErrorCodeV1::Capacity.require(
            output_bytes <= MAX_TRACE_OUTPUT_BYTES,
            "trace retained output is full",
        )?;
        if let Some(terminal) = &batch.terminal {
            TraceErrorCodeV1::Conflict.require(
                terminal.last_sequence == next_sequence && terminal.output_bytes == output_bytes,
                "trace terminal does not close its retained output",
            )?;
        }
        revision.batch = Some(self.put(&batch, tenant, Vec::new())?);
        revision.previous = previous;
        revision.last_sequence = next_sequence;
        revision.output_bytes = output_bytes;
        revision.terminal = batch.terminal;
        self.commit(key, revision)
    }

    pub fn output(
        &self,
        tenant: [u8; 16],
        request: [u8; 16],
        target_index: u16,
        access: &TraceReadAccessV1,
        now: u64,
        after: u64,
    ) -> Result<Vec<TraceBatchV1>> {
        let (_, accepted) = self.read(tenant, request, access, now)?;
        accepted.execution_id(target_index)?;
        let mut cursor = self.store.discovery_head(&TraceRevisionV1::key(
            tenant,
            request,
            Some(target_index),
        )?)?;
        let mut refs = Vec::new();
        while let Some(head) = cursor {
            let (revision, _) = TraceRevisionV1::read(&self.store, &head)?;
            if revision.last_sequence < after {
                break;
            }
            if let Some(reference) = revision.batch {
                refs.push(reference);
            }
            cursor = revision.previous;
        }
        let mut result = Vec::new();
        let mut bytes = 0;
        let mut frames = 0;
        for reference in refs.into_iter().rev() {
            let mut batch: TraceBatchV1 = Self::read_artifact(&self.store, &reference)?;
            batch.validate()?;
            batch.frames.retain(|frame| frame.sequence > after);
            let count = batch
                .frames
                .iter()
                .map(|frame| frame.bytes.len())
                .sum::<usize>();
            if bytes + count > 1024 * 1024 || frames + batch.frames.len() > 200 {
                break;
            }
            bytes += count;
            frames += batch.frames.len();
            if !batch.frames.is_empty() || batch.terminal.is_some() {
                result.push(batch);
            }
        }
        Ok(result)
    }

    fn commit(
        &self,
        key: DiscoveryHeadKeyV1,
        revision: TraceRevisionV1,
    ) -> Result<DiscoveryHeadV1> {
        let reference = self.put(&revision, key.tenant_id, revision.dependencies())?;
        self.store
            .commit_discovery_head(key, revision.previous.as_ref(), reference)
    }

    fn put(
        &self,
        value: &impl Serialize,
        tenant: [u8; 16],
        dependencies: Vec<DiscoveryArtifactRefV1>,
    ) -> Result<DiscoveryArtifactRefV1> {
        let payload = rmp_serde::to_vec_named(value).map_err(|error| {
            ObservabilitySnafu {
                code: TraceErrorCodeV1::Invalid,
                reason: error.to_string(),
            }
            .build()
        })?;
        self.store.put_discovery_artifact(&DiscoveryArtifactV1 {
            schema_version: 1,
            tenant_id: tenant,
            dependencies,
            payload,
        })
    }

    pub(crate) fn decode<T: DeserializeOwned>(bytes: &[u8]) -> Result<T> {
        rmp_serde::from_slice(bytes).map_err(|error| {
            ObservabilitySnafu {
                code: TraceErrorCodeV1::Integrity,
                reason: error.to_string(),
            }
            .build()
        })
    }

    pub(crate) fn read_artifact<T: DeserializeOwned>(
        store: &ControlStore,
        reference: &DiscoveryArtifactRefV1,
    ) -> Result<T> {
        Self::decode(&store.read_discovery_artifact(reference)?.payload)
    }
}

impl TraceExecutionGrantV1 {
    fn authorize(&self, request: &TraceRequestV1, now: u64) -> Result<Option<TraceRecipeV1>> {
        use TraceErrorCodeV1 as Code;
        Code::Denied.require(
            self.tenant_id == request.tenant_id
                && self.grant_id != [0; 16]
                && !self.principal.is_empty()
                && self.principal.len() <= 256
                && self.namespace_uids.len() <= 256
                && self.node_ids.len() <= 256
                && self.recipe_digests.len() <= 16
                && self
                    .namespace_uids
                    .iter()
                    .chain(&self.node_ids)
                    .all(|id| !id.is_empty() && id.len() <= 256),
            "trace execution grant is invalid",
        )?;
        Code::Expired.require(
            now < self.valid_until_unix_ns,
            "trace execution grant expired",
        )?;
        let recipe = TraceRecipeV1::identify(&request.source)?;
        for target in &request.targets {
            Code::Denied.require(
                self.node_ids.contains(&target.fact.node_id)
                    && (self.host_diagnostic
                        || self.namespace_uids.contains(&target.fact.namespace_uid)),
                "trace execution target is outside the grant",
            )?;
        }
        if !self.host_diagnostic {
            Code::Denied.require(
                recipe
                    .map(|recipe| recipe.digest())
                    .transpose()?
                    .is_some_and(|digest| self.recipe_digests.contains(&digest)),
                "changed source requires host-diagnostic authority",
            )?;
        }
        Ok(recipe)
    }
}

impl TraceAcceptedV1 {
    pub fn validate(&self) -> Result<()> {
        use TraceErrorCodeV1 as Code;
        self.request.validate()?;
        let recipe = self.grant.authorize(&self.request, self.accepted_unix_ns)?;
        Code::Integrity.require(
            recipe == self.recipe
                && self.accepted_unix_ns > 0
                && self.deadline_unix_ns > self.accepted_unix_ns
                && self.deadline_unix_ns - self.accepted_unix_ns
                    == (u64::from(self.request.collection_seconds) + 15) * 1_000_000_000
                && self.deadline_unix_ns <= self.grant.valid_until_unix_ns,
            "trace accepted bounds changed",
        )?;
        if recipe.is_none() {
            let approval = self.approval.as_ref().ok_or_else(|| {
                ObservabilitySnafu {
                    code: Code::Denied,
                    reason: "host source requires exact approval",
                }
                .build()
            })?;
            Code::Denied.require(
                approval.approval_id != [0; 16]
                    && approval.request_digest == self.request.digest()?
                    && approval.grant_digest == DiscoveryDigestV1::of(&self.grant)?
                    && self.deadline_unix_ns <= approval.valid_until_unix_ns,
                "trace approval is stale or names different inputs",
            )?;
        }
        Ok(())
    }

    pub fn execution_id(&self, target_index: u16) -> Result<[u8; 16]> {
        TraceErrorCodeV1::Invalid.require(
            (target_index as usize) < self.request.targets.len(),
            "trace target index is invalid",
        )?;
        let digest = DiscoveryDigestV1::of(&(
            "ARAPHOR-TRACE-EXECUTION-V1",
            self.request.digest()?,
            target_index,
        ))?;
        let mut id = [0; 16];
        id.copy_from_slice(&digest.0[..16]);
        Ok(id)
    }

    pub fn authorize_read(&self, access: &TraceReadAccessV1, now: u64) -> Result<()> {
        TraceErrorCodeV1::Denied.require(
            !access.revoked
                && access.valid_until_unix_ns > now
                && access.tenant_id == self.request.tenant_id
                && (self.recipe.is_some() || access.host_sensitive)
                && self.request.targets.iter().all(|target| {
                    access.node_ids.contains(&target.fact.node_id)
                        && (access.host_sensitive
                            || access.namespace_uids.contains(&target.fact.namespace_uid))
                }),
            "trace output is outside current read authority",
        )
    }
}

impl TraceBatchV1 {
    pub fn validate(&self) -> Result<()> {
        use TraceErrorCodeV1 as Code;
        Code::Invalid.require(
            self.execution_id != [0; 16]
                && self.frames.len() <= 200
                && (!self.frames.is_empty() || self.terminal.is_some()),
            "trace batch is empty or too large",
        )?;
        let mut bytes = 0;
        for (index, frame) in self.frames.iter().enumerate() {
            frame.validate()?;
            bytes += frame.bytes.len();
            Code::Invalid.require(
                frame.execution_id == self.execution_id
                    && frame.sequence <= 4096
                    && (index == 0 || self.frames[index - 1].sequence + 1 == frame.sequence),
                "trace batch identity or sequence changed",
            )?;
        }
        Code::Invalid.require(bytes <= 1024 * 1024, "trace batch exceeds 1 MiB")?;
        if let Some(terminal) = &self.terminal {
            terminal.validate()?;
            Code::Invalid.require(
                terminal.execution_id == self.execution_id,
                "trace terminal names another execution",
            )?;
        }
        Ok(())
    }
}

impl TraceRevisionV1 {
    pub fn key(
        tenant_id: [u8; 16],
        request_id: [u8; 16],
        target_index: Option<u16>,
    ) -> Result<DiscoveryHeadKeyV1> {
        Ok(DiscoveryHeadKeyV1 {
            tenant_id,
            id: DiscoveryDigestV1::of(&("ARAPHOR-TRACE-HEAD-V1", request_id, target_index))?,
        })
    }

    fn dependencies(&self) -> Vec<DiscoveryArtifactRefV1> {
        let mut refs = vec![self.accepted.clone()];
        refs.extend(self.previous.as_ref().map(|head| head.artifact.clone()));
        refs.extend(self.batch.clone());
        refs.sort();
        refs.dedup();
        refs
    }

    pub fn read(store: &ControlStore, head: &DiscoveryHeadV1) -> Result<(Self, TraceAcceptedV1)> {
        use TraceErrorCodeV1 as Code;
        let artifact = store.read_discovery_artifact(&head.artifact)?;
        let revision: Self = TraceOwner::decode(&artifact.payload)?;
        let accepted: TraceAcceptedV1 = TraceOwner::read_artifact(store, &revision.accepted)?;
        accepted.validate()?;
        Code::Integrity.require(
            revision.trace_schema_version == 1
                && head.key
                    == Self::key(
                        accepted.request.tenant_id,
                        accepted.request.request_id,
                        revision.target_index,
                    )?
                && revision.dependencies() == artifact.dependencies
                && revision.last_sequence <= 4096
                && revision.output_bytes <= MAX_TRACE_OUTPUT_BYTES
                && match &revision.previous {
                    Some(previous) => {
                        previous.key == head.key
                            && previous.revision.checked_add(1) == Some(head.revision)
                            && previous.commit_index < head.commit_index
                    }
                    None => head.revision == 1,
                },
            "trace revision identity or chain is invalid",
        )?;
        let prior = revision
            .previous
            .as_ref()
            .map(|previous| TraceOwner::read_artifact::<Self>(store, &previous.artifact))
            .transpose()?;
        if let Some(prior) = &prior {
            Code::Integrity.require(
                prior.trace_schema_version == 1
                    && prior.accepted == revision.accepted
                    && prior.target_index == revision.target_index
                    && (!prior.cancel_requested || revision.cancel_requested)
                    && (!prior.read_revoked || revision.read_revoked),
                "trace predecessor changed its immutable inputs",
            )?;
        }
        if let Some(index) = revision.target_index {
            let execution = accepted.execution_id(index)?;
            let reference = revision.batch.as_ref().ok_or_else(|| {
                ObservabilitySnafu {
                    code: Code::Integrity,
                    reason: "trace output revision has no batch",
                }
                .build()
            })?;
            let batch: TraceBatchV1 = TraceOwner::read_artifact(store, reference)?;
            batch.validate()?;
            let first = prior.as_ref().map_or(0, |prior| prior.last_sequence);
            let bytes = prior.as_ref().map_or(0, |prior| prior.output_bytes);
            Code::Integrity.require(
                batch.execution_id == execution
                    && prior.as_ref().is_none_or(|prior| prior.terminal.is_none())
                    && batch
                        .frames
                        .first()
                        .is_none_or(|frame| frame.sequence == first + 1)
                    && batch.frames.last().map_or(first, |frame| frame.sequence)
                        == revision.last_sequence
                    && bytes.checked_add(
                        batch
                            .frames
                            .iter()
                            .map(|frame| frame.bytes.len() as u64)
                            .sum(),
                    ) == Some(revision.output_bytes)
                    && revision.terminal == batch.terminal
                    && batch.terminal.as_ref().is_none_or(|terminal| {
                        terminal.last_sequence == revision.last_sequence
                            && terminal.output_bytes == revision.output_bytes
                    })
                    && !revision.cancel_requested
                    && !revision.read_revoked,
                "trace output revision does not match its batch",
            )?;
        } else {
            Code::Integrity.require(
                revision.batch.is_none()
                    && revision.terminal.is_none()
                    && revision.last_sequence == 0
                    && revision.output_bytes == 0,
                "trace request head contains execution output",
            )?;
        }
        Ok((revision, accepted))
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::{
        ContainerKindV1, TraceFrameKindV1, TraceSourceV1, TraceTargetV1, WorkloadTargetFactV1,
    };

    pub(crate) fn request() -> Result<TraceRequestV1> {
        let fact = WorkloadTargetFactV1 {
            node_id: "node-a".into(),
            workload_binding_generation_digest: "revision-a".into(),
            execution_set_id: "execution-set".into(),
            cluster_uid: "cluster".into(),
            namespace_uid: "namespace".into(),
            controller_uid: "controller".into(),
            service_account_uid: "account".into(),
            pod_uid: "pod".into(),
            container_id: "container".into(),
            container_name: "worker".into(),
            container_kind: ContainerKindV1::Application,
            image_digest: "image".into(),
            pod_labels: Default::default(),
            kubernetes: None,
        };
        let target = TraceTargetV1 {
            runtime_container_id: "container".into(),
            fact_digest: DiscoveryDigestV1::of(&fact)?,
            fact,
            node_boot_id: [2; 16],
            cgroup_id: 17,
            binding_id: [3; 16],
            binding_nonce: [4; 16],
            root_cgroup_live_interval_id: [5; 16],
            container_generation: 1,
            label_epoch: 2,
        };
        Ok(TraceRequestV1 {
            unresolved: Vec::new(),
            tenant_id: [1; 16],
            request_id: [6; 16],
            source: TraceRecipeV1::SyscallErrors.manifest()?.source,
            targets: vec![target],
            collection_seconds: 1,
        })
    }

    pub(crate) fn grant() -> Result<TraceExecutionGrantV1> {
        Ok(TraceExecutionGrantV1 {
            tenant_id: [1; 16],
            grant_id: [7; 16],
            principal: "operator".into(),
            namespace_uids: ["namespace".into()].into(),
            node_ids: ["node-a".into()].into(),
            recipe_digests: [TraceRecipeV1::SyscallErrors.digest()?].into(),
            host_diagnostic: false,
            valid_until_unix_ns: 100_000_000_000,
        })
    }

    pub(crate) fn access() -> TraceReadAccessV1 {
        TraceReadAccessV1 {
            tenant_id: [1; 16],
            namespace_uids: ["namespace".into()].into(),
            node_ids: ["node-a".into()].into(),
            host_sensitive: false,
            valid_until_unix_ns: 100_000_000_000,
            revoked: false,
        }
    }

    #[test]
    fn observability_target_partial_cohort_never_widens_on_retry(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let owner = TraceOwner::new(ControlStore::open(directory.path())?);
        let mut request = request()?;
        let mut unavailable = request.targets[0].clone();
        unavailable.fact.pod_uid = "replacement".into();
        unavailable.fact_digest = DiscoveryDigestV1::of(&unavailable.fact)?;
        unavailable.binding_nonce = [9; 16];
        request.unresolved.push(crate::TraceParticipantV1 {
            fact_digest: unavailable.fact_digest.clone(),
            state: crate::TraceParticipantStateV1::Disappeared,
            target: None,
        });
        owner.accept(request.clone(), grant()?, None, 1)?;
        let (_, accepted) = owner.read([1; 16], [6; 16], &access(), 2)?;
        assert_eq!(accepted.request, request);
        assert!(accepted.execution_id(1).is_err());
        request.unresolved.clear();
        request.targets.push(unavailable);
        assert!(owner.accept(request, grant()?, None, 3).is_err());
        assert_eq!(owner.read([1; 16], [6; 16], &access(), 4)?.1, accepted);
        Ok(())
    }

    #[test]
    fn observability_target_grants_pin_source_namespace_and_approval(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let owner = TraceOwner::new(ControlStore::open(directory.path())?);
        let mut request = request()?;
        let grant = grant()?;
        request.tenant_id = [9; 16];
        assert!(owner
            .accept(request.clone(), grant.clone(), None, 1)
            .is_err());
        request.tenant_id = grant.tenant_id;
        request.targets[0].fact.namespace_uid = "foreign".into();
        request.targets[0].fact_digest = DiscoveryDigestV1::of(&request.targets[0].fact)?;
        assert!(owner
            .accept(request.clone(), grant.clone(), None, 1)
            .is_err());
        request.targets[0].fact.namespace_uid = "namespace".into();
        request.targets[0].fact_digest = DiscoveryDigestV1::of(&request.targets[0].fact)?;
        request.source = TraceSourceV1::new(b"BEGIN { printf(\"host\"); }".to_vec())?;
        assert!(owner
            .accept(request.clone(), grant.clone(), None, 1)
            .is_err());
        let mut host = grant;
        host.host_diagnostic = true;
        assert!(owner
            .accept(request.clone(), host.clone(), None, 1)
            .is_err());
        let approval = TraceApprovalV1 {
            approval_id: [8; 16],
            request_digest: request.digest()?,
            grant_digest: DiscoveryDigestV1::of(&host)?,
            valid_until_unix_ns: host.valid_until_unix_ns,
        };
        let mut changed = request.clone();
        changed.source = TraceSourceV1::new(b"BEGIN { printf(\"other\"); }".to_vec())?;
        assert!(owner
            .accept(changed, host.clone(), Some(approval.clone()), 1)
            .is_err());
        owner.accept(request, host, Some(approval), 1)?;
        assert!(owner.read([1; 16], [6; 16], &access(), 2).is_err());
        let mut wide = access();
        wide.host_sensitive = true;
        owner.read([1; 16], [6; 16], &wide, 2)?;
        wide.revoked = true;
        assert!(owner.read([1; 16], [6; 16], &wide, 2).is_err());
        Ok(())
    }

    #[test]
    fn observability_recovery_accepts_regrouped_frames_and_late_terminal(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let store = ControlStore::open(directory.path())?;
        let owner = TraceOwner::new(store.clone());
        owner.accept(request()?, grant()?, None, 1)?;
        let (_, accepted) = owner.read([1; 16], [6; 16], &access(), 2)?;
        let id = accepted.execution_id(0)?;
        let frames: Vec<_> = (1..=3)
            .map(|sequence| TraceFrameV1 {
                execution_id: id,
                sequence,
                kind: TraceFrameKindV1::Data,
                bytes: vec![sequence as u8],
            })
            .collect();
        let append = |frames, terminal| {
            owner.append(
                [1; 16],
                [6; 16],
                0,
                "node-a",
                [2; 16],
                TraceBatchV1 {
                    execution_id: id,
                    frames,
                    terminal,
                },
            )
        };
        append(frames[..2].to_vec(), None)?;
        append(frames[1..].to_vec(), None)?;
        let terminal = TraceTerminalV1 {
            execution_id: id,
            reason: crate::TraceTerminalReasonV1::Completed,
            last_sequence: 3,
            output_bytes: 3,
            output_incomplete: false,
            kernel_lost_events: None,
            ready_at_unix_ns: None,
            exit_code: Some(0),
            forced_kill: false,
            cleanup: crate::TraceCleanupV1::Unknown,
        };
        let head = append(frames.clone(), Some(terminal.clone()))?;
        assert_eq!(head, append(frames.clone(), Some(terminal))?);
        assert_eq!(head, append(frames[..1].to_vec(), None)?);
        let (revision, _) = TraceRevisionV1::read(&store, &head)?;
        assert_eq!((revision.last_sequence, revision.output_bytes), (3, 3));
        let mut changed = frames;
        changed[1].bytes = vec![99];
        assert!(append(changed, None).is_err());
        Ok(())
    }

    #[test]
    fn observability_recovery_commits_once_and_rejects_changed_output(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let store = ControlStore::open(directory.path())?;
        let owner = TraceOwner::new(store.clone());
        let request = request()?;
        let head = owner.accept(request.clone(), grant()?, None, 1)?;
        assert_eq!(head, owner.accept(request.clone(), grant()?, None, 2)?);
        let (_, accepted) = owner.read([1; 16], [6; 16], &access(), 2)?;
        let execution_id = accepted.execution_id(0)?;
        let batch = TraceBatchV1 {
            execution_id,
            frames: vec![TraceFrameV1 {
                execution_id,
                sequence: 1,
                kind: TraceFrameKindV1::Data,
                bytes: b"raw\n".to_vec(),
            }],
            terminal: None,
        };
        let committed = owner.append([1; 16], [6; 16], 0, "node-a", [2; 16], batch.clone())?;
        assert_eq!(
            committed,
            owner.append([1; 16], [6; 16], 0, "node-a", [2; 16], batch.clone())?
        );
        let mut changed = batch.clone();
        changed.frames[0].bytes = b"changed\n".to_vec();
        assert!(owner
            .append([1; 16], [6; 16], 0, "node-a", [2; 16], changed)
            .is_err());
        assert!(owner
            .append([1; 16], [6; 16], 0, "foreign", [2; 16], batch.clone())
            .is_err());
        assert!(owner
            .append([1; 16], [6; 16], 0, "node-a", [9; 16], batch.clone())
            .is_err());
        drop(owner);
        drop(store);
        let store = ControlStore::open(directory.path())?;
        let owner = TraceOwner::new(store.clone());
        assert_eq!(
            owner.output([1; 16], [6; 16], 0, &access(), 3, 0)?,
            vec![batch]
        );
        let mut changed = request;
        changed.targets[0].binding_nonce = [8; 16];
        assert!(owner.accept(changed, grant()?, None, 3).is_err());
        let discovery = crate::DiscoveryOwner::open(store.clone())?;
        while !discovery.project_revisions()? {}
        let page = discovery.read_revisions([1; 16].into(), None)?;
        assert_eq!(page.events.len(), 2);
        assert!(page
            .events
            .iter()
            .all(|event| matches!(event.change, crate::DiscoveryRevisionKindV1::Trace { .. })));
        assert!(owner.cancel([1; 16], [6; 16], "foreign", true).is_err());
        owner.cancel([1; 16], [6; 16], "operator", true)?;
        assert!(owner.output([1; 16], [6; 16], 0, &access(), 4, 0).is_err());
        Ok(())
    }
}
