use super::*;
use crate::analysis::native::managed::source::SourceRecord;

impl FindingRead<'_> {
    fn scalar_owner(&mut self, result: &str) -> Result<Option<Arc<ScalarOwner>>> {
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
            return Err(Code::Unsupported.error("native source Graph snapshot"));
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
