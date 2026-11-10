use super::*;
use crate::analysis::native::managed::source::SourceRecord;

impl FindingRead<'_> {
    pub(super) fn scalar_owner(&mut self, result: &str) -> Result<Option<Arc<ScalarOwner>>> {
        if let Some(owner) = self.scalar_owners.get(result) {
            return Ok(owner.clone());
        }
        let owner = self.read_scalar_owner(result)?.map(Arc::new);
        self.charge(result.len() + 12 * size_of::<(String, Option<Arc<ScalarOwner>>)>())?;
        self.scalar_owners.insert(result.to_owned(), owner.clone());
        Ok(owner)
    }

    fn read_scalar_owner(&self, result: &str) -> Result<Option<ScalarOwner>> {
        let Some(id) = Records::find(&StoredResult::identity(self.tenant, result)?, |key| {
            Records::read(key, &self.view.snapshot)
        })?
        else {
            return Ok(None);
        };
        let source = Records::read(
            &SourceRecord::key(SourceRecord::PREFIX, &[id]),
            &self.view.snapshot,
        )?
        .is_some();
        let publication = Records::read(
            &GraphPublication::key(GraphPublication::PREFIX, id),
            &self.view.snapshot,
        )?
        .is_some();
        if !source && !publication {
            if let Some((_, stored)) = StoredResult::read(
                self.tenant,
                result,
                self.view.metadata_revision,
                |key| Records::read(key, &self.view.snapshot),
                &mut |bytes| self.charge(bytes),
            )? {
                if matches!(stored.body, ResultBody::Selected(ref step) if step.source.is_some()) {
                    return Err(Code::Missing.error("source publication header"));
                }
            }
            return Ok(None);
        }
        if source {
            let source =
                SourceRead::load(self.view, self.tenant, result, self.control, &mut |bytes| {
                    self.charge(bytes)
                })?
                .ok_or_else(|| Code::Missing.error("source scalar owner"))?;
            source.publication(self.view, &mut |bytes| self.charge(bytes))?;
            let identity = source.identity()?;
            self.charge(identity.node_id.len() + 12 * size_of::<ScalarOwner>())?;
            return Ok(Some(ScalarOwner {
                revision: source.reference().commit_revision,
                scope: ScalarScope::Source(identity.clone()),
            }));
        }
        let (publication, owner) =
            self.view
                .managed_graph_owner(self.tenant, result, self.control, &mut |bytes| {
                    self.charge(bytes)
                })?;
        if matches!(
            owner.instance().spec.destination,
            crate::ManagedDestination::Graph { .. }
        ) {
            return Err(Code::Missing.error("source publication header"));
        }
        let publication =
            publication.ok_or_else(|| Code::Missing.error("finding scalar publication"))?;
        let grant = &owner.instance().grant;
        self.charge(
            grant.selection.allocation_bytes()
                + grant.principal.len()
                + grant.authorization_id.as_ref().map_or(0, String::len)
                + 12 * size_of::<ScalarOwner>(),
        )?;
        Ok(Some(ScalarOwner {
            revision: publication.reference.commit_revision,
            scope: ScalarScope::Definition(grant.clone()),
        }))
    }

    pub(in crate::analysis) fn scalar(
        &mut self,
        reference: &NotificationFindingRefV1,
        selection: &crate::AnalysisSelectionV1,
        scope: &crate::AnalysisSelectionV1,
    ) -> Result<Option<FindingScalar>> {
        let Some(owner) = self.scalar_owner(&reference.result_id)? else {
            return Ok(None);
        };
        let mut allowed = match &owner.scope {
            ScalarScope::Source(source) => selection.sources.as_slice().contains(source),
            ScalarScope::Definition(grant) => grant.permitted_by(scope).is_ok(),
        };
        if !allowed {
            return Ok(Some(FindingScalar {
                revision: owner.revision,
                value: None,
                allowed,
            }));
        }
        let source = matches!(owner.scope, ScalarScope::Source(_));
        if source && !selection.binding_ids.is_empty() {
            allowed &= self.source_bound(&reference.result_id, selection)?;
        }
        if !allowed {
            return Ok(Some(FindingScalar {
                revision: owner.revision,
                value: None,
                allowed,
            }));
        }
        let rows = self.cached_rows(&reference.result_id, &reference.finding_id)?;
        if !source {
            if let Some(row) = rows.first() {
                allowed = self
                    .producer(row.member.writer, row.member.revision)?
                    .origin
                    .grant
                    .permitted_by(scope)
                    .is_ok();
            }
        }
        if !selection.binding_ids.is_empty() {
            allowed &= rows.first().is_some_and(|row| {
                !row.finding.value.effects.is_empty()
                    && row.finding.value.effects.iter().all(|effect| {
                        effect
                            .binding_id
                            .is_some_and(|binding| selection.binding_ids.contains(&binding))
                    })
            });
        }
        Ok(Some(FindingScalar {
            revision: owner.revision,
            value: if allowed {
                self.canonical(&rows)?
            } else {
                None
            },
            allowed,
        }))
    }
}

impl FindingRead<'_> {
    fn source_bound(
        &mut self,
        result: &str,
        selection: &crate::AnalysisSelectionV1,
    ) -> Result<bool> {
        self.charge(
            result.len()
                + selection.binding_ids.len().saturating_mul(16)
                + 12 * size_of::<(String, Vec<[u8; 16]>)>(),
        )?;
        let key = (result.to_owned(), selection.binding_ids.clone());
        if let Some(allowed) = self.source_bounds.get(&key) {
            return Ok(*allowed);
        }
        let source = crate::analysis::native::managed::source::SourceRead::load(
            self.view,
            self.tenant,
            result,
            self.control,
            &mut |bytes| self.charge(bytes),
        )?
        .ok_or_else(|| Code::Missing.error("source binding publication"))?;
        let publication = source
            .publication(self.view, &mut |bytes| self.charge(bytes))?
            .ok_or_else(|| Code::Missing.error("source binding Graph"))?;
        let graph = crate::analysis::native::PublicationRead::open(
            self.store,
            &publication,
            self.control,
            &mut |bytes| self.charge(bytes),
        )?;
        let revision = if let Some(revision) = self.source_revisions.get(result) {
            Arc::clone(revision)
        } else {
            let (revision, _) =
                source.revision(self.store, self.control, &mut |bytes| self.charge(bytes))?;
            let revision = Arc::new(revision);
            self.source_revisions
                .insert(result.to_owned(), Arc::clone(&revision));
            revision
        };
        self.charge(
            revision
                .evidence
                .iter()
                .map(|record| record.allocated_bytes() + 12 * size_of::<DiscoveryRecordIdV1>())
                .sum(),
        )?;
        let mut missing = revision.evidence.iter().cloned().collect::<BTreeSet<_>>();
        let keys = sdk::RecordBatch::new_empty(Arc::new(sdk::Schema::empty()));
        let mut rows = Vec::new();
        for (relation, _) in graph
            .mapping
            .relations
            .values()
            .filter(|(_, declaration)| DomainRelations::findings(declaration))
        {
            for writer in publication.heads.keys() {
                graph.graph.visit(
                    *relation,
                    araphor_graph::Read::Owned(*writer),
                    &keys,
                    &|writer, bytes, total| self.reserve(writer, bytes, total),
                    |member| {
                        self.charge(12 * size_of::<Member>())
                            .map_err(araphor_graph::Error::backend)?;
                        rows.push(member);
                        Ok(())
                    },
                )?;
            }
        }
        rows.sort_unstable_by(|left, right| {
            (left.relation, left.property, left.writer, &left.owner).cmp(&(
                right.relation,
                right.property,
                right.writer,
                &right.owner,
            ))
        });
        let mut seen = BTreeSet::new();
        for member in rows {
            let producer = self.producer(member.writer, member.revision)?;
            if producer.origin.graph != publication.graph
                || producer.origin.instance != publication.instance
                || graph.mapping.writers.get(&producer.origin.call) != Some(&member.writer)
            {
                return Err(Code::Denied.error("source binding producer authority"));
            }
            let finding = self.decode(&member)?;
            if finding.value.tenant_id != self.tenant
                || DomainRelations::key(&finding.value.finding_id)
                    .context(crate::AnalysisContractSnafu)?
                    != member.key
            {
                return Err(Code::Denied.error("source binding finding identity"));
            }
            revision.validate_finding(&finding.value)?;
            if !seen.insert(finding.value.finding_id.clone()) {
                continue;
            }
            self.charge(finding.value.finding_id.len() + 12 * size_of::<String>())?;
            let effects = &finding.value.effects;
            for effect in effects {
                if effect
                    .binding_id
                    .is_some_and(|binding| selection.binding_ids.contains(&binding))
                {
                    missing.remove(&effect.evidence);
                }
            }
        }
        let allowed = missing.is_empty();
        self.source_bounds.insert(key, allowed);
        Ok(allowed)
    }
}
