use std::collections::BTreeSet;

use sdk::arrow_array::BinaryArray;

use super::{
    coverage::Coverage,
    io::{Context, ContextRow, Control, FrontierRow},
    model::{Action, Audit, Outcome},
    sdk,
    state::{Edits, Entity, Reference},
};

pub(super) struct Index;

impl Index {
    pub(super) fn compute(checked: &sdk::CheckedEvaluation<'_>) -> sdk::Result<sdk::Output> {
        let graph = checked.graph()?;
        let reset = checked
            .model()
            .change_inputs
            .as_ref()
            .ok_or_else(|| Audit::invalid("causal change contract"))?
            .is_reset(checked.evaluation())?;
        let before = ContextRow::read(checked, "audit_before")?;
        let after = ContextRow::read(checked, "audit_after")?;
        let current = Coverage::read(checked, "coverage_after")?;
        let previous = Coverage::read(checked, "coverage_before")?;
        let expired =
            |record: &araphor_analysis_types::source::DiscoveryRecordIdV1| current.expired(record);
        let mut edits = Edits::default();
        for context in after
            .iter()
            .filter(|context| !expired(&context.audit.record))
        {
            Self::add(&mut edits, context)?;
        }
        let mut seeds = edits.seeds();
        let mut old = Edits::default();
        for context in &before {
            Self::add(&mut old, context)?;
        }
        seeds.extend(old.seeds());
        for source in previous.sources().chain(current.sources()) {
            seeds.insert(Entity::Source(source.clone()).key()?);
        }
        let mut references = if reset {
            BTreeSet::new()
        } else {
            Edits::frontier(&graph, seeds)?
        };
        let owners = before
            .iter()
            .chain(&after)
            .map(|context| &context.reference)
            .chain(
                references
                    .iter()
                    .filter(|reference| expired(&reference.record)),
            )
            .map(Reference::owner)
            .collect::<sdk::Result<BTreeSet<_>>>()?;
        references.extend(
            before
                .iter()
                .chain(&after)
                .map(|context| context.reference.clone()),
        );
        let restricted = references.iter().any(|reference| reference.restricted);
        if reset {
            graph.clear_scope().map_err(sdk::Error::backend)?;
        } else if !owners.is_empty() {
            graph
                .clear_owners(BinaryArray::from_iter_values(
                    owners.iter().map(Vec::as_slice),
                ))
                .map_err(sdk::Error::backend)?;
        }
        edits.restrict(restricted);
        edits.stage(&graph)?;
        Ok(sdk::Output {
            datasets: vec![
                FrontierRow::encode(&references.into_iter().collect::<Vec<_>>())?,
                Control { reset, restricted }.encode()?,
            ],
            ..Default::default()
        })
    }

    fn add(edits: &mut Edits, context: &Context) -> sdk::Result<()> {
        let audit = &context.audit;
        let reference = &context.reference;
        let tenant = audit.record.stream.tenant_id;
        let actor = || Entity::Actor(audit.actor(), audit.process);
        let credential =
            |value: &super::model::Credential| Entity::Credential(tenant, value.clone());
        let request = |value: &super::model::Request| {
            Entity::Request(
                tenant,
                value.cluster.clone(),
                value.carried.clone(),
                value.audit.clone(),
            )
        };
        edits.link(
            reference,
            Entity::Source(audit.record.stream.clone()),
            Entity::Record(audit.record.clone()),
            b"source",
        )?;
        edits.link(
            reference,
            Entity::Record(audit.record.clone()),
            actor(),
            b"actor",
        )?;
        match &audit.action {
            Action::CredentialAccess {
                credential: value, ..
            } => {
                edits.link(
                    reference,
                    actor(),
                    credential(value),
                    if audit.outcome == Outcome::Succeeded {
                        b"obtained"
                    } else {
                        b"attempted"
                    },
                )?;
            }
            Action::TokenRequest {
                request: value,
                issued,
            } => {
                edits.link(
                    reference,
                    Entity::Record(value.credential_origin.record.clone()),
                    request(value),
                    b"authorization",
                )?;
                edits.link(reference, actor(), request(value), b"requested")?;
                edits.link(
                    reference,
                    request(value),
                    credential(&value.credential),
                    b"authenticated",
                )?;
                if let Some(issued) = issued {
                    edits.link(reference, request(value), credential(issued), b"issued")?;
                }
            }
            Action::PodCreate {
                request: value,
                pod,
                ..
            } => {
                edits.link(
                    reference,
                    Entity::Record(value.credential_origin.record.clone()),
                    request(value),
                    b"authorization",
                )?;
                edits.link(reference, actor(), request(value), b"requested")?;
                edits.link(
                    reference,
                    request(value),
                    credential(&value.credential),
                    b"authenticated",
                )?;
                if let Some(pod) = pod {
                    edits.link(
                        reference,
                        request(value),
                        Entity::Pod(tenant, pod.clone()),
                        b"created",
                    )?;
                }
            }
            Action::PodScheduled {
                pod,
                created_by,
                binding,
                node,
            } => {
                edits.link(
                    reference,
                    Entity::Record(created_by.record.clone()),
                    Entity::Pod(tenant, pod.clone()),
                    b"creation",
                )?;
                edits.link(
                    reference,
                    Entity::Pod(tenant, pod.clone()),
                    Entity::Binding(tenant, pod.cluster.clone(), binding.clone(), node.clone()),
                    b"scheduled",
                )?;
            }
            Action::ContainerAdmitted { runtime } => {
                edits.link(
                    reference,
                    Entity::Record(runtime.scheduled_by.record.clone()),
                    actor(),
                    b"placement",
                )?;
                edits.link(
                    reference,
                    Entity::Binding(
                        tenant,
                        runtime.pod.cluster.clone(),
                        runtime.binding.clone(),
                        runtime.node.clone(),
                    ),
                    actor(),
                    b"admitted",
                )?;
                edits.link(
                    reference,
                    Entity::Pod(tenant, runtime.pod.clone()),
                    actor(),
                    b"runtime",
                )?;
            }
        }
        Ok(())
    }
}
