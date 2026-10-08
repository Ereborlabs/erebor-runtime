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
    Unsupported,
}

impl TraceErrorCodeV1 {
    pub fn require(self, condition: bool, reason: &'static str) -> Result<()> {
        if condition {
            Ok(())
        } else {
            ObservabilitySnafu { code: self, reason }.fail()
        }
    }
}

// Control supplies the current tenant permission, not request JSON.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TraceAccessV1 {
    pub tenant_id: [u8; 16],
    pub principal: String,
    pub valid_until_unix_ns: u64,
    pub revoked: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TraceAcceptedV1 {
    pub request: TraceRequestV1,
    pub access: TraceAccessV1,
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
    access: TraceAccessV1,
    recipe: Option<TraceRecipeV1>,
    selection: Option<crate::TraceSelectionV1>,
    finding_reference: Option<String>,
}

#[derive(Clone)]
pub struct TraceOwner {
    store: Arc<AnalysisStore>,
}

pub struct TraceNodeWorkV1 {
    pub pending: Option<(TraceAcceptedV1, u16)>,
    pub cancel: Vec<[u8; 16]>,
}

impl TraceOwner {
    pub fn new(store: Arc<AnalysisStore>) -> Self {
        Self { store }
    }

    pub fn node_work(
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
        access: TraceAccessV1,
        now: u64,
    ) -> Result<TraceStateV1> {
        request.validate()?;
        access.validate(request.tenant_id, now)?;
        if let Some((state, intent)) = self
            .store
            .trace_intent(request.tenant_id, request.request_id)?
        {
            let accepted = TraceAcceptedV1::try_from(intent)?;
            TraceErrorCodeV1::Conflict.require(
                accepted.request == request
                    && accepted.access.tenant_id == access.tenant_id
                    && accepted.access.principal == access.principal,
                "trace request ID names different inputs",
            )?;
            return Ok(state);
        }
        let recipe = request.recipe()?;
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
            access,
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
                        && stored.access.tenant_id == accepted.access.tenant_id
                        && stored.access.principal == accepted.access.principal,
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
        access: &TraceAccessV1,
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
        access: &TraceAccessV1,
        now: u64,
        revoke_read: bool,
    ) -> Result<TraceStateV1> {
        let (mut state, accepted) = self.accepted(tenant, request)?;
        access.validate(accepted.request.tenant_id, now)?;
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
        self.append_at(
            tenant,
            request,
            target_index,
            node_id,
            node_boot_id,
            batch,
            SystemTime::now(),
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn append_at(
        &self,
        tenant: [u8; 16],
        request: [u8; 16],
        target_index: u16,
        node_id: &str,
        node_boot_id: [u8; 16],
        batch: TraceBatchV1,
        intake_time: SystemTime,
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
        let intake = intake_time
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
        access: &TraceAccessV1,
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

impl TraceAccessV1 {
    pub fn validate(&self, tenant: [u8; 16], now: u64) -> Result<()> {
        use TraceErrorCodeV1 as Code;
        Code::Denied.require(
            self.tenant_id == tenant
                && tenant != [0; 16]
                && !self.revoked
                && !self.principal.is_empty()
                && self.principal.len() <= 256
                && !self.principal.chars().any(char::is_control),
            "trace tenant permission is invalid or revoked",
        )?;
        Code::Expired.require(
            now < self.valid_until_unix_ns,
            "trace tenant permission expired",
        )?;
        Ok(())
    }
}

impl TraceAcceptedV1 {
    pub fn validate(&self) -> Result<()> {
        use TraceErrorCodeV1 as Code;
        self.request.validate()?;
        self.access
            .validate(self.request.tenant_id, self.accepted_unix_ns)?;
        let recipe = self.request.recipe()?;
        Code::Integrity.require(
            recipe == self.recipe
                && self.accepted_unix_ns > 0
                && self.deadline_unix_ns > self.accepted_unix_ns
                && self.deadline_unix_ns - self.accepted_unix_ns
                    == (u64::from(self.request.collection_seconds) + 15) * 1_000_000_000
                && self.deadline_unix_ns <= self.access.valid_until_unix_ns,
            "trace accepted bounds changed",
        )?;
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

    pub fn binding(&self, index: u16) -> Result<TraceBindingV1> {
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
            binding_id: target.binding_id,
        })
    }

    pub fn authorize_read(&self, access: &TraceAccessV1, now: u64) -> Result<()> {
        access.validate(self.request.tenant_id, now)
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
            access: accepted.access.clone(),
            recipe: accepted.recipe,
            selection: accepted.request.selection.clone(),
            finding_reference: accepted.request.finding_reference.clone(),
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
                selection: stored.selection,
                finding_reference: stored.finding_reference,
            },
            access: stored.access,
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

#[cfg(any(test, feature = "test-support"))]
pub mod test_support {
    use super::*;
    use crate::{ContainerKindV1, WorkloadTargetFactV1};

    pub fn request() -> Result<TraceRequestV1> {
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
            selection: None,
            finding_reference: None,
            tenant_id: [1; 16],
            request_id: [6; 16],
            source: TraceRecipeV1::SyscallErrors.manifest()?.source,
            targets: vec![target],
            collection_seconds: 1,
        })
    }

    pub fn access() -> TraceAccessV1 {
        TraceAccessV1 {
            tenant_id: [1; 16],
            principal: "operator".into(),
            valid_until_unix_ns: 100_000_000_000,
            revoked: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::{access, request};
    use super::*;
    use crate::{TraceFrameKindV1, TraceFrameV1, TraceSourceV1, TraceTerminalV1};
    use std::collections::BTreeSet;

    #[test]
    fn observability_intake_clock() -> std::result::Result<(), Box<dyn std::error::Error>> {
        use araphor_data::{EvidenceRetentionOwner, RetentionLimitsV1};
        use std::time::Duration;

        let directory = tempfile::tempdir()?;
        let store = Arc::new(AnalysisStore::open_with_limits(
            directory.path().join("data"),
            RetentionLimitsV1 {
                raw_max_age_ns: 1,
                ..Default::default()
            },
            Default::default(),
        )?);
        let owner = TraceOwner::new(store.clone());
        owner.accept(request()?, access(), 1)?;
        let (_, accepted) = owner.read([1; 16], [6; 16], &access(), 2)?;
        let identity = accepted.binding(0)?.identity;
        let batch = TraceBatchV1 {
            execution_id: identity.execution_id,
            frames: vec![TraceFrameV1 {
                execution_id: identity.execution_id,
                sequence: 1,
                kind: TraceFrameKindV1::Data,
                bytes: vec![1],
            }],
            terminal: None,
        };
        let append =
            |time| owner.append_at([1; 16], [6; 16], 0, "node-a", [2; 16], batch.clone(), time);
        assert!(append(UNIX_EPOCH).is_err());
        assert!(append(UNIX_EPOCH - Duration::from_nanos(1)).is_err());
        assert_eq!(
            append(UNIX_EPOCH + Duration::from_nanos(100))?.last_sequence,
            1
        );
        let retention = EvidenceRetentionOwner::new(&store);
        assert_eq!(retention.retain_trace(&identity, 100)?.removed_records, 0);
        assert_eq!(retention.retain_trace(&identity, 101)?.removed_records, 1);
        assert!(matches!(
            store.read_trace(&identity, 1, &AnalysisReadControl::default()),
            Err(araphor_data::Error::RetainedRangeExpired {
                first_cursor: 1,
                last_cursor: 1,
                ..
            })
        ));
        Ok(())
    }

    #[test]
    fn observability_recovery_source_once() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let store = Arc::new(AnalysisStore::open(directory.path().join("data"))?);
        let owner = TraceOwner::new(store.clone());
        let state = owner.accept(request()?, access(), 1)?;
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
                "collection_seconds",
                "access",
                "recipe",
                "targets",
                "unresolved",
                "selection",
                "finding_reference"
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
            owner.accept(request, access(), 1)?;
            if key == 17 {
                retained = owner
                    .read([1; 16], [key; 16], &access(), 2)?
                    .1
                    .execution_id(0)?;
            }
            owner.cancel([1; 16], [key; 16], &access(), 2, false)?;
        }
        let work = owner.node_work([1; 16], "node-a", [2; 16], 3, &[retained])?;
        assert!(work.pending.is_none());
        assert_eq!(work.cancel, vec![retained]);
        let work = owner.node_work([1; 16], "node-a", [2; 16], 3, &[])?;
        assert!(work.pending.is_none());
        assert!(work.cancel.is_empty());
        Ok(())
    }

    #[cfg(feature = "test-support")]
    #[test]
    fn observability_recovery_read_revocation(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        use std::sync::mpsc;
        use std::time::Duration;

        let directory = tempfile::tempdir()?;
        let store = Arc::new(AnalysisStore::open(directory.path().join("data"))?);
        let owner = TraceOwner::new(store.clone());
        owner.accept(request()?, access(), 1)?;
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
                let cancelled = owner.cancel([1; 16], [6; 16], &access(), 3, true);
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
        owner.accept(request()?, access(), 1)?;
        for now in [2, u64::MAX - 1] {
            let mut access = access();
            access.valid_until_unix_ns = now + 1;
            owner.read([1; 16], [6; 16], &access, now)?;
            assert!(matches!(
                owner.output([1; 16], [6; 16], 0, &access, now, 0),
                Err(crate::Error::Observability {
                    code: TraceErrorCodeV1::Denied | TraceErrorCodeV1::Expired,
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
        owner.accept(request()?, access(), 1)?;
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
        let cancelled = owner.cancel([1; 16], [6; 16], &access(), 3, true)?;
        assert_eq!(
            owner.cancel([1; 16], [6; 16], &access(), 3, true)?,
            cancelled
        );
        assert!(owner.output([1; 16], [6; 16], 0, &access(), 4, 0).is_err());
        assert!(!directory.path().join("discovery-index.sqlite").exists());
        Ok(())
    }

    #[test]
    fn observability_partial_cohort_retry() -> std::result::Result<(), Box<dyn std::error::Error>> {
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
        owner.accept(request.clone(), access(), 1)?;
        let (_, accepted) = owner.read([1; 16], [6; 16], &access(), 2)?;
        assert_eq!(accepted.request, request);
        assert!(accepted.execution_id(1).is_err());
        request.unresolved.clear();
        request.targets.push(unavailable);
        assert!(owner.accept(request, access(), 3).is_err());
        assert_eq!(owner.read([1; 16], [6; 16], &access(), 4)?.1, accepted);
        Ok(())
    }

    #[test]
    fn observability_tenant_access() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let owner = TraceOwner::new(Arc::new(AnalysisStore::open(
            directory.path().join("data"),
        )?));
        let mut request = request()?;
        let permission = access();
        request.tenant_id = [9; 16];
        assert!(owner
            .accept(request.clone(), permission.clone(), 1)
            .is_err());
        request.tenant_id = permission.tenant_id;
        request.targets[0].fact.namespace_uid = "another-namespace".into();
        request.targets[0].fact.node_id = "another-node".into();
        request.targets[0].fact_digest = DiscoveryDigestV1::of(&request.targets[0].fact)?;
        request.source = TraceRecipeV1::FailedOpens.manifest()?.source;
        let mut denied = permission.clone();
        denied.revoked = true;
        assert!(owner.accept(request.clone(), denied, 1).is_err());
        let mut denied = permission.clone();
        denied.valid_until_unix_ns = 1;
        assert!(owner.accept(request.clone(), denied, 1).is_err());
        for principal in [String::new(), "invalid\nprincipal".into(), "x".repeat(257)] {
            let mut denied = permission.clone();
            denied.principal = principal;
            assert!(owner.accept(request.clone(), denied, 1).is_err());
        }
        owner.accept(request, permission, 1)?;
        let mut other = access();
        other.principal = "another-investigator".into();
        owner.read([1; 16], [6; 16], &other, 2)?;
        let mut denied = other.clone();
        denied.tenant_id = [9; 16];
        assert!(owner.read([1; 16], [6; 16], &denied, 2).is_err());
        assert!(owner.cancel([1; 16], [6; 16], &denied, 2, false).is_err());
        let mut denied = other.clone();
        denied.valid_until_unix_ns = 2;
        assert!(owner.read([1; 16], [6; 16], &denied, 2).is_err());
        assert!(owner.cancel([1; 16], [6; 16], &denied, 2, false).is_err());
        let mut denied = other.clone();
        denied.revoked = true;
        assert!(owner.read([1; 16], [6; 16], &denied, 2).is_err());
        assert!(owner.cancel([1; 16], [6; 16], &denied, 2, false).is_err());
        owner.cancel([1; 16], [6; 16], &other, 2, false)?;
        owner.read([1; 16], [6; 16], &other, 3)?;
        assert_eq!(
            owner.read([1; 16], [6; 16], &other, 3)?.1.access.principal,
            "operator"
        );
        Ok(())
    }

    #[test]
    fn observability_source_capability() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let owner = TraceOwner::new(Arc::new(AnalysisStore::open(
            directory.path().join("data"),
        )?));
        for (index, source) in [
            b"BEGIN { $i = 0; while ($i < 8192) { @full[$i] = 1; $i++; } } interval:s:2 { exit(); }".as_slice(),
            b"interval:hz:10000 { printf(\"bounded diagnostic output\\n\"); }".as_slice(),
        ].into_iter().enumerate() {
            let mut request = request()?;
            request.request_id = [index as u8 + 7; 16];
            request.source = TraceSourceV1::new(source.to_vec())?;
            owner.accept(request.clone(), access(), 1)?;
            let accepted = owner.read([1; 16], request.request_id, &access(), 2)?.1;
            assert_eq!(accepted.request.source, request.source);
            assert!(accepted.recipe.is_none());
        }
        for source in [
            b"BEGIN { printf(\"host\"); }".as_slice(),
            b"tracepoint:syscalls:sys_exit_openat { @errors[args.ret] = count(); }".as_slice(),
            b"interval:hz:10000 { printf(\"%s\", comm); }".as_slice(),
        ] {
            let mut request = request()?;
            request.source = TraceSourceV1::new(source.to_vec())?;
            assert!(matches!(
                owner.accept(request, access(), 1),
                Err(crate::Error::Observability {
                    code: TraceErrorCodeV1::Unsupported,
                    ..
                })
            ));
        }
        Ok(())
    }

    #[test]
    fn observability_renewed_retry() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let owner = TraceOwner::new(Arc::new(AnalysisStore::open(
            directory.path().join("data"),
        )?));
        let request = request()?;
        let state = owner.accept(request.clone(), access(), 1)?;
        let accepted = owner.read([1; 16], [6; 16], &access(), 2)?.1;
        let mut renewed = access();
        renewed.valid_until_unix_ns += 10_000_000_000;
        assert_eq!(state, owner.accept(request.clone(), renewed.clone(), 3)?);
        assert_eq!(accepted, owner.read([1; 16], [6; 16], &renewed, 4)?.1);
        let mut other = renewed.clone();
        other.principal = "another-investigator".into();
        assert!(matches!(
            owner.accept(request.clone(), other, 3),
            Err(crate::Error::Observability {
                code: TraceErrorCodeV1::Conflict,
                ..
            })
        ));
        for field in 0..3 {
            let mut changed = request.clone();
            match field {
                0 => changed.source = TraceRecipeV1::FailedOpens.manifest()?.source,
                1 => changed.targets[0].binding_nonce = [9; 16],
                _ => changed.collection_seconds += 1,
            }
            assert!(matches!(
                owner.accept(changed, renewed.clone(), 3),
                Err(crate::Error::Observability {
                    code: TraceErrorCodeV1::Conflict,
                    ..
                })
            ));
        }
        renewed.revoked = true;
        assert!(owner.accept(request, renewed, 3).is_err());
        Ok(())
    }

    #[test]
    fn observability_regrouped_late_terminal() -> std::result::Result<(), Box<dyn std::error::Error>>
    {
        let directory = tempfile::tempdir()?;
        let store = Arc::new(AnalysisStore::open(directory.path().join("data"))?);
        let owner = TraceOwner::new(store.clone());
        owner.accept(request()?, access(), 1)?;
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
    fn observability_replay_integrity() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let store = Arc::new(AnalysisStore::open(directory.path().join("data"))?);
        let owner = TraceOwner::new(store.clone());
        let request = request()?;
        let head = owner.accept(request.clone(), access(), 1)?;
        assert_eq!(head, owner.accept(request.clone(), access(), 2)?);
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
        assert!(owner.accept(changed, access(), 3).is_err());
        assert!(!directory.path().join("discovery-index.sqlite").exists());
        let mut denied = access();
        denied.tenant_id = [9; 16];
        assert!(owner.cancel([1; 16], [6; 16], &denied, 3, true).is_err());
        owner.cancel([1; 16], [6; 16], &access(), 3, true)?;
        assert!(owner.output([1; 16], [6; 16], 0, &access(), 4, 0).is_err());
        Ok(())
    }
}
