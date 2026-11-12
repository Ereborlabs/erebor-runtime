use std::collections::BTreeMap;

use super::*;
use crate::analysis::native::managed::references::References;
use crate::{
    AnalysisContextKeyV1, AnalysisContextRefV1, GraphCoverageKeyV1, GraphRevisionV1, ManagedAttempt,
};

#[derive(Deserialize)]
struct Projection<R, P> {
    tenant: [u8; 16],
    id: String,
    revision: u64,
    body: Body<R, P>,
}

#[derive(Deserialize)]
enum Body<R, P> {
    Selected(Selected<R, P>),
}

#[derive(Deserialize)]
struct Selected<R, P> {
    instance: String,
    attempt: String,
    proofs: P,
    source: Source<R>,
}

#[derive(Deserialize)]
struct Source<R> {
    expired: bool,
    coverage: Vec<GraphCoverageKeyV1>,
    first: u64,
    last: u64,
    deadline: u64,
    base: Option<PackageResultRefV1>,
    records: R,
}

pub(in crate::analysis::native) struct SourceRead<
    R = serde::de::IgnoredAny,
    P = serde::de::IgnoredAny,
> {
    pub(in crate::analysis::native) id: u64,
    pub(in crate::analysis::native) header: SourceRecord,
    result: Projection<R, P>,
    owner: ManagedAttempt,
}

impl SourceRead {
    pub(in crate::analysis::native) fn load(
        view: &DataView,
        tenant: [u8; 16],
        name: &str,
        control: &AnalysisReadControl,
        charge: &mut dyn FnMut(usize) -> Result<()>,
    ) -> Result<Option<Self>> {
        control.check()?;
        let Some(id) = Records::find(&StoredResult::identity(tenant, name)?, |key| {
            Records::read(key, &view.snapshot)
        })?
        else {
            return Ok(None);
        };
        if Records::read(
            &SourceRecord::key(SourceRecord::PREFIX, &[id]),
            &view.snapshot,
        )?
        .is_none()
        {
            let (_, result, owner) = view.result_owner(tenant, name, control, charge)?;
            if matches!(
                &owner.instance().spec.destination,
                ManagedDestination::Graph { .. }
            ) && matches!(&result.body, ResultBody::Selected(step) if step.source.is_some())
            {
                return Err(Code::Missing.error("source publication header"));
            }
            return Ok(None);
        }
        let source = Self::load_id(view, id, control, charge)?;
        if source.result.tenant != tenant || source.result.id != name {
            return Err(Code::Denied.error("source publication identity"));
        }
        Ok(Some(source))
    }
}

impl<R: serde::de::DeserializeOwned, P: serde::de::DeserializeOwned> SourceRead<R, P> {
    fn load_id(
        view: &DataView,
        id: u64,
        control: &AnalysisReadControl,
        charge: &mut dyn FnMut(usize) -> Result<()>,
    ) -> Result<Self> {
        control.check()?;
        let header = SourceRecord::header(id, |key| Records::read(key, &view.snapshot), charge)?;
        header.check_ranges()?;
        let bytes = Records::charged_payload(
            &Records::key(b'X', id),
            |key| Records::read(key, &view.snapshot),
            charge,
        )?
        .ok_or_else(|| Code::Missing.error("source selected result"))?;
        charge(bytes.len().saturating_mul(4))?;
        let result: Projection<R, P> = Records::decode(&bytes)?;
        let Body::Selected(selected) = &result.body;
        let owner = view
            .managed_attempt_charged(
                result.tenant,
                &selected.instance,
                &selected.attempt,
                control,
                charge,
            )?
            .ok_or_else(|| Code::Missing.error("source selected attempt"))?;
        StoredResult::check_owner(
            result.tenant,
            result.revision,
            &selected.instance,
            &selected.attempt,
            &owner.0,
            &owner.instance().spec,
        )?;
        let reference = PackageResultRefV1 {
            result_id: result.id.clone(),
            commit_revision: result.revision,
        };
        header.check_capture(owner.captured_revision(), result.revision)?;
        if result.revision == 0
            || result.revision > view.metadata_revision
            || result.tenant == [0; 16]
            || owner.receipt().is_none_or(|receipt| {
                receipt.selected != reference || receipt.graph.as_ref() != Some(&reference)
            })
            || Records::find(&StoredResult::identity(result.tenant, &result.id)?, |key| {
                Records::read(key, &view.snapshot)
            })? != Some(id)
            || selected.source.first == 0
            || selected.source.last < selected.source.first
        {
            return Err(Code::Invalid.error("source selected authority"));
        }
        let source = Self {
            id,
            header,
            result,
            owner,
        };
        if source.identity()?.tenant_id != source.result.tenant {
            return Err(Code::Denied.error("source selected tenant"));
        }
        Ok(source)
    }

    pub(in crate::analysis::native) fn identity(&self) -> Result<&EvidenceIntakeIdentityV1> {
        match &self.owner.instance().spec.destination {
            ManagedDestination::Graph { source, .. } => Ok(source),
            _ => Err(Code::Invalid.error("source selected destination")),
        }
    }

    fn selected(&self) -> &Selected<R, P> {
        let Body::Selected(selected) = &self.result.body;
        selected
    }

    pub(in crate::analysis::native) fn reference(&self) -> PackageResultRefV1 {
        PackageResultRefV1 {
            result_id: self.result.id.clone(),
            commit_revision: self.result.revision,
        }
    }

    pub(in crate::analysis::native) fn name(&self) -> &str {
        &self.result.id
    }

    pub(in crate::analysis::native) fn publication(
        &self,
        view: &DataView,
        charge: &mut dyn FnMut(usize) -> Result<()>,
    ) -> Result<Option<crate::analysis::native::GraphPublication>> {
        let publication = crate::analysis::native::GraphPublication::read(
            self.id,
            view.metadata_revision,
            |key| Records::read(key, &view.snapshot),
            charge,
        )?;
        if let Some(publication) = &publication {
            let graph = Records::find(
                &InstanceRecord::identity(self.result.tenant, &self.selected().instance)?,
                |key| Records::read(key, &view.snapshot),
            )?;
            if publication.tenant != self.result.tenant
                || publication.instance != self.selected().instance
                || publication.reference != self.reference()
                || Some(publication.graph) != graph
            {
                return Err(Code::Invalid.error("source Graph publication owner"));
            }
        }
        Ok(publication)
    }

    pub(in crate::analysis::native) fn expired(&self) -> bool {
        self.selected().source.expired
    }

    pub(in crate::analysis::native) fn restricted(&self) -> u64 {
        self.header.restricted
    }

    pub(in crate::analysis::native) fn manifest(
        &self,
        charge: &mut dyn FnMut(usize) -> Result<()>,
    ) -> Result<crate::GraphManifest> {
        let source = &self.selected().source;
        charge(
            source
                .coverage
                .iter()
                .map(|key| {
                    size_of_val(key)
                        + key.source.node_id.len()
                        + key
                            .gap_reasons
                            .iter()
                            .map(|reason| size_of::<String>() + reason.len())
                            .sum::<usize>()
                })
                .sum::<usize>()
                .saturating_mul(4)
                + self
                    .header
                    .gaps
                    .len()
                    .saturating_mul(4 * size_of::<(u64, u64)>())
                + self.identity()?.node_id.len(),
        )?;
        self.header.manifest_values(
            self.identity()?,
            (source.first, source.last, source.deadline),
            &source.coverage,
            source.base.as_ref(),
        )
    }
}

type Origin = SourceRead<
    Vec<(DiscoveryRecordIdV1, StorePositionV1)>,
    Vec<(DiscoveryRecordIdV1, AnalysisContextRefV1)>,
>;

pub(in crate::analysis::native) struct SourceContents {
    pub(in crate::analysis::native) complete: bool,
    pub(in crate::analysis::native) manifest: crate::GraphManifest,
    pub(in crate::analysis::native) contexts: Vec<AnalysisContextRefV1>,
    pub(in crate::analysis::native) observed: u64,
    pub(in crate::analysis::native) facts: BTreeMap<AnalysisContextKeyV1, DiscoveryRecordIdV1>,
}

impl SourceRead {
    pub(in crate::analysis::native) fn revision(
        &self,
        store: &NativeStore,
        control: &AnalysisReadControl,
        charge: &mut dyn FnMut(usize) -> Result<()>,
    ) -> Result<(GraphRevisionV1, Vec<AnalysisContextRefV1>)> {
        self.read_members(store, control, charge, None, false)
            .map(|(revision, references, _, _)| (revision, references))
    }

    pub(in crate::analysis::native) fn contents(
        &self,
        store: &NativeStore,
        control: &AnalysisReadControl,
        charge: &mut dyn FnMut(usize) -> Result<()>,
        fact_bodies: bool,
    ) -> Result<SourceContents> {
        let mut manifest = self.manifest(charge)?;
        let (revision, contexts, observed, facts) =
            self.read_members(store, control, charge, Some(&mut manifest), fact_bodies)?;
        manifest.input_manifest = revision;
        Ok(SourceContents {
            complete: fact_bodies,
            manifest,
            contexts,
            observed,
            facts,
        })
    }

    fn read_members(
        &self,
        store: &NativeStore,
        control: &AnalysisReadControl,
        charge: &mut dyn FnMut(usize) -> Result<()>,
        mut details: Option<&mut crate::GraphManifest>,
        fact_bodies: bool,
    ) -> Result<(
        GraphRevisionV1,
        Vec<AnalysisContextRefV1>,
        u64,
        BTreeMap<AnalysisContextKeyV1, DiscoveryRecordIdV1>,
    )> {
        let at = store.read_at(self.result.revision)?;
        let source = self.identity()?;
        let mut observed = 0;
        let mut fact_values = BTreeMap::new();
        let mut fact_owners = BTreeMap::new();
        let mut verified = crate::analysis::context::VerifiedPackages::default();
        let prefix = at.source_members(&self.owner)?;
        let mut evidence = Vec::new();
        let mut contexts = BTreeMap::<AnalysisContextKeyV1, AnalysisContextRefV1>::new();
        let mut origins = BTreeMap::<u64, Origin>::new();
        for entry in at.snapshot.prefix(&prefix) {
            control.check()?;
            charge(0)?;
            let (key, _) = entry.context(crate::NativeStorageSnafu {
                operation: "read source revision members",
            })?;
            let record = at.source_record(&prefix, &key, source)?;
            let bytes =
                Records::charged_payload(&key, |key| Records::read(key, &at.snapshot), charge)?
                    .ok_or_else(|| Code::Missing.error("source revision member"))?;
            let member: Member = Records::decode(&bytes)?;
            if !origins.contains_key(&member.origin) {
                let origin = Origin::load_id(&at, member.origin, control, charge)?;
                if origin.result.tenant != self.result.tenant
                    || origin.selected().instance != self.selected().instance
                    || origin.identity()? != source
                    || origin.result.revision > self.result.revision
                {
                    return Err(Code::Denied.error("source revision origin"));
                }
                if origin
                    .selected()
                    .source
                    .records
                    .windows(2)
                    .any(|pair| pair[0].0 >= pair[1].0)
                    || origin
                        .selected()
                        .proofs
                        .windows(2)
                        .any(|pair| (&pair[0].0, &pair[0].1.key) >= (&pair[1].0, &pair[1].1.key))
                {
                    return Err(Code::Invalid.error("source revision origin order"));
                }
                charge(12 * size_of::<Origin>())?;
                origins.insert(member.origin, origin);
            }
            let origin = &origins[&member.origin];
            if origin
                .selected()
                .source
                .records
                .binary_search_by(|(wanted, _)| wanted.cmp(&record))
                .ok()
                .map(|index| origin.selected().source.records[index].1)
                != Some(member.position)
                || member.position.commit_revision == 0
                || member.position > origin.header.captured
                || !(self.selected().source.first..=self.selected().source.last)
                    .contains(&record.durable_cursor)
            {
                return Err(Code::Invalid.error("source revision member origin"));
            }
            charge(record.allocated_bytes().saturating_mul(4))?;
            evidence.push(record.clone());
            if let Some(details) = &mut details {
                charge(
                    record.allocated_bytes() + size_of::<(DiscoveryRecordIdV1, StorePositionV1)>(),
                )?;
                details
                    .input_positions
                    .push((record.clone(), member.position));
                observed = observed.max(member.observed);
            }
            for (kind, facts) in [(SourceRecord::FACT, true), (SourceRecord::PROOF, false)] {
                let prefix =
                    SourceRecord::member_key(&SourceRecord::key(kind, &[member.origin]), &record);
                for entry in at.snapshot.prefix(&prefix) {
                    control.check()?;
                    charge(0)?;
                    let (key, revision) = entry.context(crate::NativeStorageSnafu {
                        operation: "read source revision context postings",
                    })?;
                    if key.len() != prefix.len() + 8 {
                        return Err(Code::Invalid.error("source context posting key"));
                    }
                    charge(key.len() + revision.len())?;
                    let id = NativeStore::number(&key[prefix.len()..])?;
                    let revision = NativeStore::number(&revision)?;
                    if revision > origin.result.revision {
                        return Err(Code::Invalid.error("source context posting revision"));
                    }
                    let reference = at.context_reference(source.tenant_id, id, revision, charge)?;
                    if Records::read(
                        &References::key(References::CONTEXT, &[member.origin, id]),
                        &at.snapshot,
                    )?
                    .map(|value| NativeStore::number(&value))
                    .transpose()?
                        != Some(revision)
                    {
                        return Err(Code::Denied.error("source revision context pin"));
                    }
                    if facts {
                        let bytes = Records::charged_payload(
                            &Records::key(b'K', id),
                            |key| Records::read(key, &at.snapshot),
                            charge,
                        )?
                        .ok_or_else(|| Code::Missing.error("source revision fact index"))?;
                        let fact: crate::analysis::context::FactRecord = Records::decode(&bytes)?;
                        if fact.cursor != record.durable_cursor
                            || fact.stream != record.stream.key()
                            || fact.record
                                != araphor_analysis_types::DomainRelations::key(&record)
                                    .context(crate::AnalysisContractSnafu)?
                        {
                            return Err(Code::Invalid.error("source revision fact association"));
                        }
                        if details.is_some() {
                            charge(
                                reference.key.allocated_bytes()
                                    + record.allocated_bytes()
                                    + 12 * size_of::<(AnalysisContextKeyV1, DiscoveryRecordIdV1)>(),
                            )?;
                            fact_owners.insert(reference.key.clone(), record.clone());
                        }
                        if fact_bodies {
                            let (context, actual) = at
                                .context_record(&reference.key, id, charge)?
                                .ok_or_else(|| Code::Missing.error("source snapshot fact"))?;
                            if actual != revision {
                                return Err(Code::Conflict.error("source snapshot fact revision"));
                            }
                            let mut failed = false;
                            let checked =
                                verified.check_context(&context, |tenant, package, revision| {
                                    let mut bound = |bytes: usize| {
                                        let checked = charge(bytes.saturating_mul(12));
                                        failed |= checked.is_err();
                                        checked
                                    };
                                    let value = at.package_revision_charged(
                                        tenant, package, revision, control, &mut bound,
                                    )?;
                                    if let Some(value) = &value {
                                        bound(
                                            value
                                                .descriptor
                                                .len()
                                                .saturating_add(value.artifact.len()),
                                        )?;
                                    }
                                    Ok(value)
                                });
                            if failed {
                                checked?;
                            } else {
                                checked.map_err(crate::Error::stored_artifact)?;
                            }
                            DataView::fact_record(
                                id,
                                &context,
                                |key| Records::read(key, &at.snapshot),
                                charge,
                            )?
                            .ok_or_else(|| Code::Invalid.error("source snapshot fact index"))?;
                            charge(
                                context.body.len().saturating_mul(8)
                                    + 12 * size_of::<crate::GraphFactV1>(),
                            )?;
                            let fact = crate::GraphFactV1::try_from(&context)?;
                            if fact.record_id != record {
                                return Err(Code::Denied.error("source snapshot fact record"));
                            }
                            charge(reference.key.allocated_bytes())?;
                            fact_values.insert(reference.key.clone(), fact);
                        }
                    } else if !origin
                        .selected()
                        .proofs
                        .iter()
                        .any(|(wanted, proof)| wanted == &record && proof == &reference)
                    {
                        return Err(Code::Denied.error("source revision proof association"));
                    }
                    if let Some(prior) = contexts.get(&reference.key) {
                        if prior != &reference {
                            return Err(Code::Conflict.error("source revision context identity"));
                        }
                    } else {
                        charge(
                            reference.key.allocated_bytes().saturating_mul(4)
                                + 12 * size_of::<AnalysisContextRefV1>(),
                        )?;
                        contexts.insert(reference.key.clone(), reference);
                    }
                }
            }
        }
        evidence.sort_unstable();
        if evidence.len() as u64 != self.header.count
            || evidence.windows(2).any(|pair| pair[0] >= pair[1])
        {
            return Err(Code::Invalid.error("source revision member count"));
        }
        let (coverage, missing_ranges) = if let Some(details) = &mut details {
            (
                std::mem::take(&mut details.input_manifest.coverage),
                std::mem::take(&mut details.input_manifest.missing_ranges),
            )
        } else {
            let manifest = self.manifest(charge)?;
            (manifest.input_manifest.coverage, manifest.missing_ranges)
        };
        charge(
            contexts
                .keys()
                .map(|key| key.allocated_bytes())
                .sum::<usize>()
                .saturating_mul(2),
        )?;
        let revision = GraphRevisionV1 {
            evidence,
            coverage,
            context: contexts.keys().cloned().collect(),
            missing_ranges,
        };
        revision.validate(source.tenant_id)?;
        if let Some(details) = &mut details {
            details.facts = fact_values.into_values().collect();
            details
                .input_positions
                .sort_unstable_by(|left, right| left.0.cmp(&right.0));
        }
        Ok((
            revision,
            contexts.into_values().collect(),
            observed,
            fact_owners,
        ))
    }
}

impl DataView {
    pub(in crate::analysis::native) fn visit_source_winners(
        &self,
        tenant: [u8; 16],
        sources: Option<&[EvidenceIntakeIdentityV1]>,
        control: &AnalysisReadControl,
        charge: &mut dyn FnMut(usize) -> Result<()>,
        mut visit: impl FnMut(SourceRead, &mut dyn FnMut(usize) -> Result<()>) -> Result<()>,
    ) -> Result<()> {
        let base = SourceRecord::winner_prefix(tenant);
        let mut prefixes = Vec::new();
        if let Some(sources) = sources {
            for source in sources {
                control.check()?;
                charge(0)?;
                if let Some(id) = Records::find(&SourceRecord::identity(source)?, |key| {
                    Records::read(key, &self.snapshot)
                })? {
                    charge(base.len() + 8 + 12 * size_of::<Vec<u8>>())?;
                    prefixes.push(SourceRecord::key(&base, &[id]));
                }
            }
        } else {
            charge(base.len() + 12 * size_of::<Vec<u8>>())?;
            prefixes.push(base.clone());
        }
        for prefix in prefixes {
            for entry in self.snapshot.prefix(&prefix) {
                control.check()?;
                charge(0)?;
                let (key, value) = entry.context(crate::NativeStorageSnafu {
                    operation: "read source window winners",
                })?;
                if key.len() != base.len() + 24 {
                    return Err(Code::Invalid.error("source winner key"));
                }
                charge(key.len() + value.len())?;
                let source: SourceRead =
                    SourceRead::load_id(self, NativeStore::number(&value)?, control, charge)?;
                let owner = Records::find(
                    &InstanceRecord::identity(tenant, &source.selected().instance)?,
                    |key| Records::read(key, &self.snapshot),
                )?
                .ok_or_else(|| Code::Missing.error("source winner instance"))?;
                let identity =
                    Records::find(&SourceRecord::identity(source.identity()?)?, |key| {
                        Records::read(key, &self.snapshot)
                    })?
                    .ok_or_else(|| Code::Missing.error("source winner identity"))?;
                if source.result.tenant != tenant
                    || SourceRecord::winner_key(
                        tenant,
                        owner,
                        identity,
                        source.selected().source.first,
                    ) != key.as_ref()
                {
                    return Err(Code::Invalid.error("source winner identity"));
                }
                visit(source, charge)?;
            }
        }
        Ok(())
    }
}
