use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, OnceLock};

use araphor_analysis_types::{
    arrow::{
        self,
        views::{ContextKeyRow, RecordIdRow},
    },
    source::DiscoveryRecordIdV1,
    values::*,
    DomainRelations, FindingMember,
};
use erebor_interceptor_abi::{KernelEffectFamilyV1, KernelEffectOperationV1};
use sdk::arrow_array::{ArrayRef, BinaryArray, StructArray, UInt8Array};
use serde::{Deserialize, Serialize};

use super::{
    io::{Context, ContextRow, Control, FrontierRow, Summary},
    model::{Action, Audit, Credential, Outcome, Pod},
    sdk, Causal,
};

#[derive(Deserialize, Serialize)]
pub(super) struct Details {
    acquisition: RecordIdRow,
    issuance: RecordIdRow,
    creation: RecordIdRow,
    scheduling: RecordIdRow,
    admission: RecordIdRow,
    contexts: Vec<ContextKeyRow>,
}

impl Details {
    pub(super) fn port() -> sdk::Port {
        static PORT: OnceLock<sdk::Port> = OnceLock::new();
        arrow::port::<Self>("causal_reason", &PORT)
    }
}

pub(super) struct Verified<'a> {
    context: &'a Context,
    event: &'a Observation,
}

pub(super) type Actor = (GraphSubjectKeyV1, [u8; 16]);
type CredentialKey = (Actor, Credential);
type RuntimeKey = (Pod, String, String);

pub(super) struct Detect;

impl Detect {
    pub(super) fn compute(checked: &sdk::CheckedEvaluation<'_>) -> sdk::Result<sdk::Output> {
        let control = Control::read(checked)?;
        let frontier = FrontierRow::read(checked)?;
        let events = Observation::read(checked)?;
        let audits = ContextRow::read(checked, "audits")?;
        let records = events
            .iter()
            .map(|event| (&event.id, event))
            .collect::<BTreeMap<_, _>>();
        if records.len() != events.len() {
            return Err(Audit::invalid("causal canonical event duplicate"));
        }
        let mut verified = Vec::new();
        for context in &audits {
            let Some(event) = records.get(&context.audit.record) else {
                continue;
            };
            if Self::bind(&context.audit, event) {
                verified.push(Verified { context, event });
            }
        }
        let conflicts = super::claims::Claims::capture(&verified).conflicts();
        let graph = checked.graph()?;
        if control.reset {
            graph.clear_scope().map_err(sdk::Error::backend)?;
        } else {
            let owners = frontier
                .iter()
                .map(|reference| DomainRelations::key(&reference.record))
                .collect::<sdk::Result<BTreeSet<_>>>()?;
            if !owners.is_empty() {
                graph
                    .clear_owners(BinaryArray::from_iter_values(
                        owners.iter().map(Vec::as_slice),
                    ))
                    .map_err(sdk::Error::backend)?;
            }
        }
        let mut acquisitions: BTreeMap<CredentialKey, Vec<usize>> = BTreeMap::new();
        let mut schedules: BTreeMap<Pod, Vec<usize>> = BTreeMap::new();
        let mut runtimes: BTreeMap<RuntimeKey, Vec<usize>> = BTreeMap::new();
        for (index, value) in verified
            .iter()
            .enumerate()
            .filter(|(_, value)| value.succeeded())
        {
            match &value.audit().action {
                Action::CredentialAccess { credential, .. } => {
                    acquisitions
                        .entry((value.actor(), credential.clone()))
                        .or_default()
                        .push(index);
                }
                Action::PodScheduled { pod, .. } => {
                    schedules.entry(pod.clone()).or_default().push(index);
                }
                Action::ContainerAdmitted { runtime } => {
                    runtimes
                        .entry((
                            runtime.pod.clone(),
                            runtime.binding.clone(),
                            runtime.node.clone(),
                        ))
                        .or_default()
                        .push(index);
                }
                _ => {}
            }
        }
        let mut issuances: BTreeMap<CredentialKey, Vec<(usize, usize)>> = BTreeMap::new();
        for (issue, value) in verified
            .iter()
            .enumerate()
            .filter(|(_, value)| value.succeeded())
        {
            let Action::TokenRequest {
                request,
                issued: Some(issued),
            } = &value.audit().action
            else {
                continue;
            };
            if issued.authority == request.credential.authority
                && issued.principal == request.credential.principal
            {
                continue;
            }
            for &acquisition in acquisitions
                .get(&(value.actor(), request.credential.clone()))
                .into_iter()
                .flatten()
            {
                let Action::CredentialAccess { completion, .. } =
                    &verified[acquisition].audit().action
                else {
                    continue;
                };
                if request.credential_origin.record != verified[acquisition].event.id
                    || request.credential_origin.proof != *completion
                {
                    continue;
                }
                issuances
                    .entry((value.actor(), issued.clone()))
                    .or_default()
                    .push((acquisition, issue));
            }
        }
        let mut findings = BTreeMap::new();
        for (creation, value) in verified
            .iter()
            .enumerate()
            .filter(|(_, value)| value.succeeded())
        {
            let Action::PodCreate {
                request,
                pod: Some(pod),
                containers,
            } = &value.audit().action
            else {
                continue;
            };
            if !containers.iter().any(|container| {
                container.privileged
                    && container
                        .host_mounts
                        .iter()
                        .any(|mount| mount.host_path == "/" && !mount.read_only)
            }) {
                continue;
            }
            for &(acquisition, issuance) in issuances
                .get(&(value.actor(), request.credential.clone()))
                .into_iter()
                .flatten()
            {
                let Action::TokenRequest {
                    request: issuer, ..
                } = &verified[issuance].audit().action
                else {
                    continue;
                };
                if request.credential_origin.record != verified[issuance].event.id
                    || request.credential_origin.proof != issuer.audit
                {
                    continue;
                }
                for &scheduling in schedules.get(pod).into_iter().flatten() {
                    let Action::PodScheduled {
                        binding,
                        node,
                        created_by,
                        ..
                    } = &verified[scheduling].audit().action
                    else {
                        continue;
                    };
                    if created_by.record != value.event.id || created_by.proof != request.audit {
                        continue;
                    }
                    for &admission in runtimes
                        .get(&(pod.clone(), binding.clone(), node.clone()))
                        .into_iter()
                        .flatten()
                    {
                        let Action::ContainerAdmitted { runtime } =
                            &verified[admission].audit().action
                        else {
                            continue;
                        };
                        if runtime.scheduled_by.record != verified[scheduling].event.id
                            || runtime.scheduled_by.proof != *binding
                        {
                            continue;
                        }
                        if !containers.iter().any(|container| {
                            container.name == runtime.container_name
                                && container.privileged
                                && container
                                    .host_mounts
                                    .iter()
                                    .any(|mount| mount.host_path == "/" && !mount.read_only)
                        }) {
                            continue;
                        }
                        if verified[acquisition].event.id.stream.node_id == *node {
                            continue;
                        }
                        let path = [acquisition, issuance, creation, scheduling, admission];
                        let member =
                            Self::finding(&verified, path, &conflicts, control.restricted)?;
                        let owner = DomainRelations::key(&value.event.id)?;
                        let key = DomainRelations::key(&member.value.finding_id)?;
                        match findings.entry((owner, key)) {
                            std::collections::btree_map::Entry::Vacant(entry) => {
                                entry.insert(member);
                            }
                            std::collections::btree_map::Entry::Occupied(mut entry) => {
                                if entry.get().value.state != FindingStateV1::Confirmed
                                    && member.value.state == FindingStateV1::Confirmed
                                {
                                    entry.insert(member);
                                }
                            }
                        }
                    }
                }
            }
        }
        let count =
            u64::try_from(findings.len()).map_err(|_| Audit::invalid("causal finding count"))?;
        if !findings.is_empty() {
            let (keys, members): (Vec<_>, Vec<_>) = findings.into_iter().unzip();
            let data = FindingMember::encode(&members)?;
            let [batch] = data.batches.as_slice() else {
                return Err(Audit::invalid("causal finding properties"));
            };
            let properties: ArrayRef = Arc::new(StructArray::new(
                batch.schema().fields().clone(),
                batch.columns().to_vec(),
                None,
            ));
            let relation = &checked
                .model()
                .graph
                .as_ref()
                .ok_or_else(|| Audit::invalid("causal graph contract"))?
                .relations[0];
            graph
                .stage_nodes(
                    DomainRelations::FINDINGS,
                    sdk::RecordBatch::try_new(
                        Arc::new(relation.engine().command_schema()),
                        vec![
                            Arc::new(BinaryArray::from_iter_values(
                                keys.iter().map(|key| key.0.as_slice()),
                            )),
                            Arc::new(BinaryArray::from_iter_values(
                                keys.iter().map(|key| key.1.as_slice()),
                            )),
                            Arc::new(UInt8Array::from(vec![
                                araphor_graph::Write::Add as u8;
                                keys.len()
                            ])),
                            properties,
                        ],
                    )?,
                )
                .map_err(sdk::Error::backend)?;
        }
        Ok(sdk::Output {
            datasets: vec![Summary::encode(count)?],
            ..Default::default()
        })
    }

    fn bind(audit: &Audit, event: &Observation) -> bool {
        if audit.record != event.id
            || audit.task != event.effect.task_cookie
            || Some(audit.process) != event.process_instance_id
            || !audit.qualified()
            || !matches!(
                audit.proof.local_subject_binding,
                LocalSubjectBindingV1::ExactTask | LocalSubjectBindingV1::ExactProcess
            )
            || audit.outcome == Outcome::Succeeded && event.denied()
        {
            return false;
        }
        match &audit.action {
            Action::CredentialAccess { object, .. } => {
                let file = event.effect.effect_family == KernelEffectFamilyV1::File as u32
                    && (event.effect.operation == KernelEffectOperationV1::Read as u32
                        || audit.outcome != Outcome::Succeeded
                            && event.effect.operation == KernelEffectOperationV1::OpenRead as u32);
                let network = event.network()
                    && event.effect.operation == KernelEffectOperationV1::Receive as u32;
                (file || network)
                    && event.effect.exact_object_id == *object
                    && audit.proof.remote_subject_binding == RemoteSubjectBindingV1::ExactObject
            }
            Action::TokenRequest { request, .. } | Action::PodCreate { request, .. } => {
                event.network()
                    && event.effect.exact_object_id == request.socket
                    && matches!(
                        audit.proof.remote_subject_binding,
                        RemoteSubjectBindingV1::ExactRequest | RemoteSubjectBindingV1::ExactSession
                    )
            }
            Action::PodScheduled { .. } | Action::ContainerAdmitted { .. } => {
                audit.proof.remote_subject_binding == RemoteSubjectBindingV1::ExactObject
            }
        }
    }

    fn finding(
        verified: &[Verified<'_>],
        path: [usize; 5],
        conflicts: &BTreeMap<DiscoveryRecordIdV1, BTreeSet<DiscoveryRecordIdV1>>,
        restricted: bool,
    ) -> sdk::Result<FindingMember> {
        let [acquisition, issuance, creation, scheduling, admission] =
            path.map(|index| &verified[index]);
        let mut evidence = path.into_iter().collect::<BTreeSet<_>>();
        let disputed = path
            .iter()
            .filter_map(|index| conflicts.get(&verified[*index].event.id))
            .flatten()
            .collect::<BTreeSet<_>>();
        evidence.extend(
            verified
                .iter()
                .enumerate()
                .filter(|(_, value)| disputed.contains(&value.event.id))
                .map(|(index, _)| index),
        );
        let credentials =
            [&acquisition.audit().action, &creation.audit().action].map(|action| match action {
                Action::CredentialAccess { credential, .. } => credential,
                Action::PodCreate { request, .. } => &request.credential,
                _ => unreachable!(),
            });
        for (index, value) in verified.iter().enumerate() {
            if value.actor() != acquisition.actor() || value.audit().outcome == Outcome::Succeeded {
                continue;
            }
            let credential = match &value.audit().action {
                Action::CredentialAccess { credential, .. } => Some(credential),
                Action::TokenRequest { request, .. } | Action::PodCreate { request, .. } => {
                    Some(&request.credential)
                }
                _ => None,
            };
            if credential.is_some_and(|value| credentials.contains(&value)) {
                evidence.insert(index);
            }
        }
        let mut events = BTreeMap::new();
        let mut contexts = BTreeSet::new();
        for index in evidence {
            let value = &verified[index];
            events.insert(value.event.id.clone(), value.event);
            contexts.insert(value.context.reference.context.clone());
        }
        let mut limits = BTreeSet::new();
        if events.values().any(|event| !event.complete()) {
            limits.insert("CANONICAL_COVERAGE_INCOMPLETE".to_owned());
        }
        if events.keys().any(|id| conflicts.contains_key(id)) {
            limits.insert("AUDIT_CONTRADICTED".to_owned());
        }
        let coverage = events
            .values()
            .map(|event| {
                <[u8; 16]>::try_from(event.coverage_interval_id.as_slice())
                    .map_err(|_| Audit::invalid("causal finding coverage"))
            })
            .collect::<sdk::Result<BTreeSet<_>>>()?;
        let details = Details {
            acquisition: RecordIdRow::from(&acquisition.event.id),
            issuance: RecordIdRow::from(&issuance.event.id),
            creation: RecordIdRow::from(&creation.event.id),
            scheduling: RecordIdRow::from(&scheduling.event.id),
            admission: RecordIdRow::from(&admission.event.id),
            contexts: contexts.iter().map(ContextKeyRow::from).collect(),
        };
        let data = arrow::encode(Details::port(), &[details], |row| row)?;
        let reason = DeclaredFindingReasonV1::from_details(
            format!("{}.CROSS_NODE_PRIVILEGED_WORKLOAD", Causal::ID),
            data.batches
                .first()
                .ok_or_else(|| Audit::invalid("causal reason details"))?,
        )?;
        let subject = creation.event.task_subject();
        Ok(FindingMember {
            anchor: Anchor {
                record: creation.event.id.clone(),
                fact: None,
            },
            value: FindingV1 {
                tenant_id: creation.event.id.stream.tenant_id,
                finding_id: FindingV1::identity(Causal::ID, &creation.event.id, &subject)?,
                package_id: Causal::ID.into(),
                package_version: 1,
                subject_id: subject,
                state: if limits.is_empty() {
                    FindingStateV1::Confirmed
                } else {
                    FindingStateV1::CoverageInsufficient
                },
                window_start_utc_ns: events
                    .values()
                    .map(|event| event.ingested_utc_ns)
                    .min()
                    .unwrap_or(0),
                window_end_utc_ns: events
                    .values()
                    .map(|event| event.ingested_utc_ns)
                    .max()
                    .unwrap_or(0),
                evidence: events.keys().cloned().collect(),
                required_coverage_interval_ids: coverage.into_iter().collect(),
                policy_provenance: Vec::new(),
                effects: events
                    .values()
                    .map(|event| event.resolved_effect())
                    .collect(),
                reason: FindingReasonV1::Declared(reason),
                severity: FindingSeverityV1::Critical,
                sensitivity: if restricted {
                    ContextSensitivityV1::HostRestricted
                } else {
                    ContextSensitivityV1::Tenant
                },
                required_action: Some("investigate-privileged-workload-expansion".into()),
                limits: limits.into_iter().collect(),
            },
        })
    }
}

impl Verified<'_> {
    pub(super) fn audit(&self) -> &Audit {
        &self.context.audit
    }
    pub(super) fn actor(&self) -> Actor {
        (self.audit().actor(), self.audit().process)
    }
    fn succeeded(&self) -> bool {
        self.audit().outcome == Outcome::Succeeded
    }
}
