use std::collections::{BTreeMap, BTreeSet};

use araphor_analysis_types::source::DiscoveryRecordIdV1;

use super::{
    detect::{Actor, Verified},
    model::{Action, Container, Credential, Origin, Outcome, Pod, Runtime},
};

#[derive(Eq, Ord, PartialEq, PartialOrd)]
enum Key {
    Record(DiscoveryRecordIdV1),
    Request([u8; 16], String, String),
    Carried([u8; 16], Actor, String),
    Lease([u8; 16], String, String),
    Completion([u8; 16], Actor, String),
    Pod([u8; 16], Pod),
    Binding([u8; 16], String, String),
    Admission([u8; 16], String),
    Container([u8; 16], String, String),
}

#[derive(PartialEq)]
enum Value<'a> {
    Action(&'a Action, Outcome, Actor),
    Principal(&'a str),
    Pod(&'a [Container]),
    Binding(&'a Pod, &'a Origin, &'a str, Outcome),
    Runtime(&'a Runtime, Outcome),
}

struct Claim<'a> {
    value: Value<'a>,
    records: BTreeSet<&'a DiscoveryRecordIdV1>,
    contradicted: bool,
}

#[derive(Default)]
pub(super) struct Claims<'a> {
    values: BTreeMap<Key, Claim<'a>>,
}

impl<'a> Claims<'a> {
    pub(super) fn capture(values: &'a [Verified<'a>]) -> Self {
        let mut claims = Self::default();
        for value in values {
            let audit = value.audit();
            let tenant = audit.record.stream.tenant_id;
            let action = || Value::Action(&audit.action, audit.outcome, value.actor());
            claims.add(Key::Record(audit.record.clone()), action(), &audit.record);
            match &audit.action {
                Action::CredentialAccess {
                    credential,
                    completion,
                    ..
                } => {
                    claims.credential(tenant, credential, &audit.record);
                    claims.add(
                        Key::Completion(tenant, value.actor(), completion.clone()),
                        action(),
                        &audit.record,
                    );
                }
                Action::TokenRequest { request, .. } | Action::PodCreate { request, .. } => {
                    claims.credential(tenant, &request.credential, &audit.record);
                    claims.add(
                        Key::Request(tenant, request.cluster.clone(), request.audit.clone()),
                        action(),
                        &audit.record,
                    );
                    claims.add(
                        Key::Carried(tenant, value.actor(), request.carried.clone()),
                        action(),
                        &audit.record,
                    );
                    if let Action::TokenRequest {
                        issued: Some(issued),
                        ..
                    } = &audit.action
                    {
                        claims.credential(tenant, issued, &audit.record);
                    }
                    if let Action::PodCreate {
                        pod: Some(pod),
                        containers,
                        ..
                    } = &audit.action
                    {
                        claims.add(
                            Key::Pod(tenant, pod.clone()),
                            Value::Pod(containers),
                            &audit.record,
                        );
                    }
                }
                Action::PodScheduled {
                    pod,
                    created_by,
                    binding,
                    node,
                } => {
                    claims.add(
                        Key::Binding(tenant, pod.cluster.clone(), binding.clone()),
                        Value::Binding(pod, created_by, node, audit.outcome),
                        &audit.record,
                    );
                }
                Action::ContainerAdmitted { runtime } => {
                    claims.add(
                        Key::Admission(tenant, runtime.admission.clone()),
                        Value::Runtime(runtime, audit.outcome),
                        &audit.record,
                    );
                    claims.add(
                        Key::Container(
                            tenant,
                            runtime.pod.cluster.clone(),
                            runtime.container.clone(),
                        ),
                        Value::Runtime(runtime, audit.outcome),
                        &audit.record,
                    );
                }
            }
        }
        claims
    }

    fn credential(
        &mut self,
        tenant: [u8; 16],
        credential: &'a Credential,
        record: &'a DiscoveryRecordIdV1,
    ) {
        self.add(
            Key::Lease(
                tenant,
                credential.authority.clone(),
                credential.lease.clone(),
            ),
            Value::Principal(&credential.principal),
            record,
        );
    }

    fn add(&mut self, key: Key, value: Value<'a>, record: &'a DiscoveryRecordIdV1) {
        match self.values.entry(key) {
            std::collections::btree_map::Entry::Vacant(entry) => {
                entry.insert(Claim {
                    value,
                    records: BTreeSet::from([record]),
                    contradicted: false,
                });
            }
            std::collections::btree_map::Entry::Occupied(mut entry) => {
                let claim = entry.get_mut();
                claim.contradicted |= claim.value != value;
                claim.records.insert(record);
            }
        }
    }

    pub(super) fn conflicts(&self) -> BTreeMap<DiscoveryRecordIdV1, BTreeSet<DiscoveryRecordIdV1>> {
        let mut conflicts: BTreeMap<DiscoveryRecordIdV1, BTreeSet<DiscoveryRecordIdV1>> =
            BTreeMap::new();
        for claim in self.values.values().filter(|claim| claim.contradicted) {
            for record in &claim.records {
                conflicts
                    .entry((*record).clone())
                    .or_default()
                    .extend(claim.records.iter().map(|record| (*record).clone()));
            }
        }
        conflicts
    }
}
