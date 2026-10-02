use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use araphor_data::{
    AnalysisReadControl, AnalysisStore, TraceBindingV1, TraceIntentV1, TraceOutputReceiptV1,
    TraceStateV1,
};
use serde::{Deserialize, Serialize};
use snafu::ResultExt as _;

use crate::{
    error::ObservabilitySnafu, DiscoveryDigestV1, Result, TraceBatchV1, TraceIdentityV1,
    TraceParticipantV1, TraceRecipeV1, TraceRequestV1, TraceTargetV1,
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

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct StoredTrace {
    targets: Vec<TraceTargetV1>,
    unresolved: Vec<TraceParticipantV1>,
    collection_seconds: u16,
    grant: TraceExecutionGrantV1,
    approval: Option<TraceApprovalV1>,
    recipe: Option<TraceRecipeV1>,
}

#[derive(Clone)]
pub struct TraceOwner {
    store: Arc<AnalysisStore>,
}

pub(crate) struct TraceNodeWorkV1 {
    pub pending: Option<(TraceAcceptedV1, u16)>,
    pub cancel: Vec<[u8; 16]>,
}

impl TraceOwner {
    pub fn new(store: Arc<AnalysisStore>) -> Self {
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
        let mut after = None;
        loop {
            let page = self.store.trace_intents(tenant, after)?;
            for (state, intent) in page.intents {
                let accepted = TraceAcceptedV1::try_from(intent)?;
                for (index, target) in accepted.request.targets.iter().enumerate() {
                    if target.fact.node_id != node || target.node_boot_id != boot {
                        continue;
                    }
                    let index = index as u16;
                    let identity = accepted.binding(index)?.identity;
                    if self
                        .store
                        .trace_receipt(&identity)?
                        .is_some_and(|receipt| receipt.terminal.is_some())
                    {
                        continue;
                    }
                    if state.cancel_requested || now >= accepted.deadline_unix_ns {
                        if retained.contains(&identity.execution_id) && cancel.len() < 16 {
                            cancel.push(identity.execution_id);
                        }
                    } else if pending.is_none() && !retained.contains(&identity.execution_id) {
                        pending = Some((accepted.clone(), index));
                    }
                }
            }
            after = page.next_request;
            if after.is_none() {
                break;
            }
        }
        if let Some((accepted, index)) = &pending {
            let identity = accepted.binding(*index)?.identity;
            let terminal = self
                .store
                .trace_receipt(&identity)?
                .is_some_and(|receipt| receipt.terminal.is_some());
            let state = self.request_state(tenant, accepted.request.request_id)?;
            if terminal || state.cancel_requested || state.read_revoked {
                pending = None;
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
    ) -> Result<TraceStateV1> {
        request.validate()?;
        let recipe = grant.authorize(&request, now)?;
        if let Some((state, intent)) = self
            .store
            .trace_intent(request.tenant_id, request.request_id)?
        {
            let accepted = TraceAcceptedV1::try_from(intent)?;
            TraceErrorCodeV1::Conflict.require(
                accepted.request == request
                    && accepted.grant == grant
                    && accepted.approval == approval,
                "trace request ID names different inputs",
            )?;
            return Ok(state);
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
        let intent = TraceIntentV1::try_from(&accepted)?;
        match self.store.accept_trace(&intent) {
            Ok(state) => Ok(state),
            Err(araphor_data::Error::AnalysisConflict { .. }) => {
                let (state, stored) = self.accepted(intent.tenant_id, intent.request_id)?;
                TraceErrorCodeV1::Conflict.require(
                    stored.request == accepted.request
                        && stored.grant == accepted.grant
                        && stored.approval == accepted.approval,
                    "trace request ID names different inputs",
                )?;
                Ok(state)
            }
            Err(error) => Err(error.into()),
        }
    }

    pub fn read(
        &self,
        tenant: [u8; 16],
        request: [u8; 16],
        access: &TraceReadAccessV1,
        now: u64,
    ) -> Result<(TraceStateV1, TraceAcceptedV1)> {
        let (state, accepted) = self.accepted(tenant, request)?;
        accepted.authorize_read(access, now)?;
        TraceErrorCodeV1::Denied
            .require(!state.read_revoked, "trace read authority was revoked")?;
        Ok((state, accepted))
    }

    pub fn request_state(&self, tenant: [u8; 16], request: [u8; 16]) -> Result<TraceStateV1> {
        self.accepted(tenant, request).map(|(state, _)| state)
    }

    fn accepted(
        &self,
        tenant: [u8; 16],
        request: [u8; 16],
    ) -> Result<(TraceStateV1, TraceAcceptedV1)> {
        let (state, intent) = self.store.trace_intent(tenant, request)?.ok_or_else(|| {
            ObservabilitySnafu {
                code: TraceErrorCodeV1::Missing,
                reason: "trace request is absent",
            }
            .build()
        })?;
        Ok((state, TraceAcceptedV1::try_from(intent)?))
    }

    pub fn cancel(
        &self,
        tenant: [u8; 16],
        request: [u8; 16],
        principal: &str,
        revoke_read: bool,
    ) -> Result<TraceStateV1> {
        let (mut state, accepted) = self.accepted(tenant, request)?;
        TraceErrorCodeV1::Denied.require(
            accepted.grant.principal == principal,
            "trace cancellation requires the execution principal",
        )?;
        if state.cancel_requested && (!revoke_read || state.read_revoked) {
            return Ok(state);
        }
        state.cancel_requested = true;
        state.read_revoked |= revoke_read;
        self.store.update_trace(&state).map_err(Into::into)
    }

    pub fn append(
        &self,
        tenant: [u8; 16],
        request: [u8; 16],
        target_index: u16,
        node_id: &str,
        node_boot_id: [u8; 16],
        batch: TraceBatchV1,
    ) -> Result<TraceOutputReceiptV1> {
        batch.validate()?;
        let (_, accepted) = self.accepted(tenant, request)?;
        let identity = accepted.binding(target_index)?.identity;
        TraceErrorCodeV1::Denied.require(
            identity.node_id == node_id
                && identity.node_boot_id == node_boot_id
                && identity.execution_id == batch.execution_id,
            "trace output does not match the authenticated execution",
        )?;
        let intake = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()
            .and_then(|elapsed| u64::try_from(elapsed.as_nanos()).ok())
            .filter(|now| *now > 0)
            .ok_or_else(|| {
                ObservabilitySnafu {
                    code: TraceErrorCodeV1::Integrity,
                    reason: "trace intake time is outside the supported range",
                }
                .build()
            })?;
        self.store
            .append_trace(&identity, &batch, intake)
            .map_err(Into::into)
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
        let started = Instant::now();
        TraceErrorCodeV1::Invalid.require(after <= 4096, "trace cursor exceeds the frame bound")?;
        let (_, accepted) = self.read(tenant, request, access, now)?;
        let identity = accepted.binding(target_index)?.identity;
        let page = self
            .store
            .read_trace(&identity, after + 1, &AnalysisReadControl::default())?;
        let checked_now = u64::try_from(started.elapsed().as_nanos())
            .ok()
            .and_then(|elapsed| now.checked_add(elapsed))
            .ok_or_else(|| {
                ObservabilitySnafu {
                    code: TraceErrorCodeV1::Denied,
                    reason: "trace read time exceeds its supported range",
                }
                .build()
            })?;
        self.read(tenant, request, access, checked_now)?;
        if page.frames.is_empty() && page.terminal.is_none() {
            return Ok(Vec::new());
        }
        Ok(vec![TraceBatchV1 {
            execution_id: identity.execution_id,
            frames: page.frames,
            terminal: page.terminal,
        }])
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

    fn binding(&self, index: u16) -> Result<TraceBindingV1> {
        let execution_id = self.execution_id(index)?;
        let target = &self.request.targets[index as usize];
        Ok(TraceBindingV1 {
            identity: TraceIdentityV1 {
                tenant_id: self.request.tenant_id,
                node_id: target.fact.node_id.clone(),
                node_boot_id: target.node_boot_id,
                request_id: self.request.request_id,
                execution_id,
                source_sha256: self.request.source.sha256,
            },
            namespace_uid: target.fact.namespace_uid.clone(),
        })
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

impl TryFrom<&TraceAcceptedV1> for TraceIntentV1 {
    type Error = crate::Error;

    fn try_from(accepted: &TraceAcceptedV1) -> Result<Self> {
        accepted.validate()?;
        let stored = StoredTrace {
            targets: accepted.request.targets.clone(),
            unresolved: accepted.request.unresolved.clone(),
            collection_seconds: accepted.request.collection_seconds,
            grant: accepted.grant.clone(),
            approval: accepted.approval.clone(),
            recipe: accepted.recipe,
        };
        let authority =
            rmp_serde::to_vec_named(&stored).context(crate::error::TraceEncodingSnafu)?;
        let bindings = (0..accepted.request.targets.len())
            .map(|index| accepted.binding(index as u16))
            .collect::<Result<Vec<_>>>()?;
        let intent = Self {
            tenant_id: accepted.request.tenant_id,
            request_id: accepted.request.request_id,
            source: accepted.request.source.clone(),
            bindings,
            authority,
            accepted_unix_ns: accepted.accepted_unix_ns,
            deadline_unix_ns: accepted.deadline_unix_ns,
            host_sensitive: accepted.recipe.is_none(),
        };
        intent.validate()?;
        Ok(intent)
    }
}

impl TryFrom<TraceIntentV1> for TraceAcceptedV1 {
    type Error = crate::Error;

    fn try_from(intent: TraceIntentV1) -> Result<Self> {
        intent.validate()?;
        let stored: StoredTrace =
            rmp_serde::from_slice(&intent.authority).context(crate::error::TraceDecodingSnafu)?;
        let accepted = Self {
            request: TraceRequestV1 {
                tenant_id: intent.tenant_id,
                request_id: intent.request_id,
                source: intent.source,
                targets: stored.targets,
                unresolved: stored.unresolved,
                collection_seconds: stored.collection_seconds,
            },
            grant: stored.grant,
            approval: stored.approval,
            recipe: stored.recipe,
            accepted_unix_ns: intent.accepted_unix_ns,
            deadline_unix_ns: intent.deadline_unix_ns,
        };
        accepted.validate()?;
        TraceErrorCodeV1::Integrity.require(
            intent.host_sensitive == accepted.recipe.is_none()
                && intent.bindings.len() == accepted.request.targets.len(),
            "trace intent changed its disclosure or target count",
        )?;
        for (index, binding) in intent.bindings.iter().enumerate() {
            TraceErrorCodeV1::Integrity.require(
                accepted.binding(index as u16)? == *binding,
                "trace intent changed its frozen execution binding",
            )?;
        }
        Ok(accepted)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::{
        ContainerKindV1, TraceFrameKindV1, TraceFrameV1, TraceSourceV1, TraceTerminalV1,
        WorkloadTargetFactV1,
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
    fn observability_recovery_source_once() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let store = Arc::new(AnalysisStore::open(directory.path().join("data"))?);
        let owner = TraceOwner::new(store.clone());
        let state = owner.accept(request()?, grant()?, None, 1)?;
        let (_, accepted) = owner.read([1; 16], [6; 16], &access(), 2)?;
        let (stored, intent) = store
            .trace_intent([1; 16], [6; 16])?
            .ok_or("missing intent")?;
        assert_eq!(stored, state);
        assert_eq!(intent.source, accepted.request.source);
        let authority: serde_json::Value = rmp_serde::from_slice(&intent.authority)?;
        let fields: BTreeSet<_> = authority
            .as_object()
            .ok_or("authority is not a record")?
            .keys()
            .map(String::as_str)
            .collect();
        assert_eq!(
            fields,
            BTreeSet::from([
                "approval",
                "collection_seconds",
                "grant",
                "recipe",
                "targets",
                "unresolved"
            ])
        );
        assert!(!intent
            .authority
            .windows(intent.source.bytes.len())
            .any(|bytes| bytes == intent.source.bytes.as_slice()));
        assert_eq!(TraceAcceptedV1::try_from(intent.clone())?, accepted);
        assert_eq!(TraceIntentV1::try_from(&accepted)?, intent);

        let mut changed = intent.clone();
        changed.bindings[0].identity.execution_id = [9; 16];
        assert!(TraceAcceptedV1::try_from(changed).is_err());
        let mut changed = intent.clone();
        changed.bindings[0].namespace_uid = "foreign".into();
        assert!(TraceAcceptedV1::try_from(changed).is_err());
        let mut changed = intent.clone();
        changed.host_sensitive = true;
        assert!(TraceAcceptedV1::try_from(changed).is_err());
        let mut changed = intent;
        changed.authority = vec![0xc1];
        assert!(matches!(
            TraceAcceptedV1::try_from(changed),
            Err(crate::Error::TraceDecoding { .. })
        ));
        Ok(())
    }

    #[test]
    fn observability_recovery_retained_cancellations(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let owner = TraceOwner::new(Arc::new(AnalysisStore::open(
            directory.path().join("data"),
        )?));
        let mut retained = [0; 16];
        for key in 1..=17 {
            let mut request = request()?;
            request.request_id = [key; 16];
            owner.accept(request, grant()?, None, 1)?;
            if key == 17 {
                retained = owner
                    .read([1; 16], [key; 16], &access(), 2)?
                    .1
                    .execution_id(0)?;
            }
            owner.cancel([1; 16], [key; 16], "operator", false)?;
        }
        let work = owner.node_work([1; 16], "node-a", [2; 16], 3, &[retained])?;
        assert!(work.pending.is_none());
        assert_eq!(work.cancel, vec![retained]);
        let work = owner.node_work([1; 16], "node-a", [2; 16], 3, &[])?;
        assert!(work.pending.is_none());
        assert!(work.cancel.is_empty());
        Ok(())
    }

    #[cfg(feature = "test-fixtures")]
    #[test]
    fn observability_recovery_read_revocation(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        use std::sync::mpsc;
        use std::time::Duration;

        let directory = tempfile::tempdir()?;
        let store = Arc::new(AnalysisStore::open(directory.path().join("data"))?);
        let owner = TraceOwner::new(store.clone());
        owner.accept(request()?, grant()?, None, 1)?;
        let execution_id = owner
            .read([1; 16], [6; 16], &access(), 2)?
            .1
            .execution_id(0)?;
        owner.append(
            [1; 16],
            [6; 16],
            0,
            "node-a",
            [2; 16],
            TraceBatchV1 {
                execution_id,
                frames: vec![TraceFrameV1 {
                    execution_id,
                    sequence: 1,
                    kind: TraceFrameKindV1::Data,
                    bytes: b"private output".to_vec(),
                }],
                terminal: None,
            },
        )?;
        let (frozen, ready) = mpsc::sync_channel(0);
        let (release, resume) = mpsc::sync_channel(0);
        store.set_commit_hook(
            araphor_data::AnalysisCommitStage::AfterTraceFreeze,
            move || {
                assert!(frozen.send(()).is_ok(), "the read observer remains live");
                assert!(
                    resume.recv_timeout(Duration::from_secs(5)).is_ok(),
                    "the read is released"
                );
                Ok(())
            },
        )?;
        std::thread::scope(
            |scope| -> std::result::Result<(), Box<dyn std::error::Error>> {
                let reader = scope.spawn(|| owner.output([1; 16], [6; 16], 0, &access(), 3, 0));
                ready.recv_timeout(Duration::from_secs(5))?;
                let cancelled = owner.cancel([1; 16], [6; 16], "operator", true);
                release.send(())?;
                let result = reader
                    .join()
                    .map_err(|_| "the read thread must not panic")?;
                cancelled?;
                assert!(matches!(
                    result,
                    Err(crate::Error::Observability {
                        code: TraceErrorCodeV1::Denied,
                        ..
                    })
                ));
                Ok(())
            },
        )?;
        Ok(())
    }

    #[test]
    fn observability_recovery_read_expiry() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let owner = TraceOwner::new(Arc::new(AnalysisStore::open(
            directory.path().join("data"),
        )?));
        owner.accept(request()?, grant()?, None, 1)?;
        for now in [2, u64::MAX - 1] {
            let mut access = access();
            access.valid_until_unix_ns = now + 1;
            owner.read([1; 16], [6; 16], &access, now)?;
            assert!(matches!(
                owner.output([1; 16], [6; 16], 0, &access, now, 0),
                Err(crate::Error::Observability {
                    code: TraceErrorCodeV1::Denied,
                    ..
                })
            ));
        }
        Ok(())
    }

    #[test]
    fn observability_projection_reopen_grants(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let store = Arc::new(AnalysisStore::open(directory.path().join("data"))?);
        let owner = TraceOwner::new(store.clone());
        owner.accept(request()?, grant()?, None, 1)?;
        let (_, accepted) = owner.read([1; 16], [6; 16], &access(), 2)?;
        let execution_id = accepted.execution_id(0)?;
        let frames: Vec<_> = (1..=2)
            .map(|sequence| TraceFrameV1 {
                execution_id,
                sequence,
                kind: TraceFrameKindV1::Data,
                bytes: br#"{"type":"map","data":{"@errors":{"257,-2":7}}}"#.to_vec(),
            })
            .collect();
        let batch = TraceBatchV1 {
            execution_id,
            frames: frames.clone(),
            terminal: None,
        };
        owner.append([1; 16], [6; 16], 0, "node-a", [2; 16], batch.clone())?;
        assert_eq!(
            owner.output([1; 16], [6; 16], 0, &access(), 2, 0)?,
            vec![batch.clone()]
        );
        drop(owner);
        drop(store);
        let store = Arc::new(AnalysisStore::open(directory.path().join("data"))?);
        let owner = TraceOwner::new(store);
        let batches = owner.output([1; 16], [6; 16], 0, &access(), 3, 0)?;
        assert_eq!(batches, vec![batch]);
        let (_, accepted) = owner.read([1; 16], [6; 16], &access(), 3)?;
        let recipe = accepted.recipe.ok_or("reviewed recipe is absent")?;
        let measurements: Vec<_> = batches
            .iter()
            .flat_map(|batch| &batch.frames)
            .flat_map(|frame| recipe.measurements(frame).unwrap_or_default())
            .collect();
        assert_eq!(measurements.len(), 2);
        assert_eq!(
            measurements
                .iter()
                .map(|row| row.sequence)
                .collect::<Vec<_>>(),
            vec![1, 2]
        );
        assert!(measurements.iter().all(|row| row.count == 7
            && row.cumulative
            && !row.atomic_snapshot
            && row.unit == "count"
            && row.execution_id == execution_id
            && row.syscall_id == Some(257)));
        assert_eq!(
            owner.output([1; 16], [6; 16], 0, &access(), 3, 1)?[0].frames,
            frames[1..]
        );
        assert!(owner
            .output([1; 16], [6; 16], 0, &access(), 3, 4097)
            .is_err());
        let mut revoked = access();
        revoked.revoked = true;
        assert!(owner.read([1; 16], [6; 16], &revoked, 3).is_err());
        assert!(owner.output([1; 16], [6; 16], 0, &revoked, 3, 0).is_err());
        let cancelled = owner.cancel([1; 16], [6; 16], "operator", true)?;
        assert_eq!(owner.cancel([1; 16], [6; 16], "operator", true)?, cancelled);
        assert!(owner.output([1; 16], [6; 16], 0, &access(), 4, 0).is_err());
        assert!(!directory.path().join("discovery-index.sqlite").exists());
        Ok(())
    }

    #[test]
    fn observability_target_partial_cohort_never_widens_on_retry(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let owner = TraceOwner::new(Arc::new(AnalysisStore::open(
            directory.path().join("data"),
        )?));
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
        let owner = TraceOwner::new(Arc::new(AnalysisStore::open(
            directory.path().join("data"),
        )?));
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
        let store = Arc::new(AnalysisStore::open(directory.path().join("data"))?);
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
        assert_eq!((head.last_sequence, head.output_bytes), (3, 3));
        let mut changed = frames;
        changed[1].bytes = vec![99];
        assert!(append(changed, None).is_err());
        Ok(())
    }

    #[test]
    fn observability_recovery_commits_once_and_rejects_changed_output(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let store = Arc::new(AnalysisStore::open(directory.path().join("data"))?);
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
        let store = Arc::new(AnalysisStore::open(directory.path().join("data"))?);
        let owner = TraceOwner::new(store.clone());
        assert_eq!(
            owner.output([1; 16], [6; 16], 0, &access(), 3, 0)?,
            vec![batch]
        );
        let mut changed = request;
        changed.targets[0].binding_nonce = [8; 16];
        assert!(owner.accept(changed, grant()?, None, 3).is_err());
        assert!(!directory.path().join("discovery-index.sqlite").exists());
        assert!(owner.cancel([1; 16], [6; 16], "foreign", true).is_err());
        owner.cancel([1; 16], [6; 16], "operator", true)?;
        assert!(owner.output([1; 16], [6; 16], 0, &access(), 4, 0).is_err());
        Ok(())
    }
}
