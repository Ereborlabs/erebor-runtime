use super::*;

impl Instance {
    pub(super) fn current_lifecycle(
        &self,
        expected: u64,
        control: &AnalysisReadControl,
    ) -> araphor_data::Result<ManagedInstance> {
        self.query
            .store()
            .managed_instance(self.admitted.spec.tenant, &self.admitted.spec.id, control)?
            .filter(|current| {
                current.spec == self.admitted.spec
                    && current.grant == self.admitted.grant
                    && current.generation == self.admitted.generation
                    && current.lifecycle == expected
            })
            .ok_or_else(|| Code::Conflict.error("managed lifecycle owner"))
    }

    pub(super) async fn set_running(
        self: &Arc<Self>,
        authority: Arc<dyn PackageAuthorization>,
        expected: u64,
        running: bool,
        caller: Option<PackageGrantV1>,
        control: &AnalysisReadControl,
    ) -> Result<Arc<Self>> {
        let read = Arc::new(control.within(self.admitted.grant.remaining()?)?);
        let stage = Arc::clone(&read);
        let owner = Arc::clone(self);
        let memory = self.query.memory().scope();
        let replacement = Engine::blocking(read, (), move || {
            let current = owner.current_lifecycle(expected, &stage)?;
            let prepared = owner.prepared.clone();
            let calls = owner.calls.clone();
            let metadata = memory
                .reserve_input(Self::metadata_bytes(&current, &calls)?)
                .map_err(|source| araphor_query::Error::Sql { source })?;
            let admitted = Self::authorize_actions_for(
                authority.as_ref(),
                &current.grant,
                &prepared,
                &[PackageActionV1::Run],
                caller
                    .as_ref()
                    .map(|grant| (grant, PackageActionV1::Run, stage.as_ref())),
                || {
                    if running {
                        owner.query.store().set_managed_running(
                            current.spec.tenant,
                            &current.spec.id,
                            expected,
                            true,
                            || stage.check(),
                        )
                    } else {
                        owner.query.store().stop_managed(&current, || stage.check())
                    }
                },
            )?;
            Ok(Self {
                query: Arc::clone(&owner.query),
                authority,
                admitted,
                prepared,
                session: owner.session.clone(),
                graph: owner.graph.clone(),
                calls,
                _metadata: metadata,
            })
        })
        .await?;
        Ok(Arc::new(replacement))
    }
}
