use super::*;

impl Instance {
    /// Stop and join the original execution before this call.
    pub async fn renew(
        self: &Arc<Self>,
        expected_lifecycle: u64,
        grant: PackageGrantV1,
        control: &AnalysisReadControl,
    ) -> Result<Arc<Self>> {
        control.check()?;
        let read = Arc::new(control.within(grant.remaining()?)?);
        let owner = Arc::clone(self);
        let stage = Arc::clone(&read);
        let memory = self.query.memory().scope();
        let replacement = Engine::blocking(read, (), move || {
            let mut admitted = owner
                .query
                .store()
                .managed_instance(owner.admitted.spec.tenant, &owner.admitted.spec.id, &stage)?
                .filter(|current| {
                    current.spec == owner.admitted.spec
                        && current.generation == owner.admitted.generation
                        && current.lifecycle == expected_lifecycle
                })
                .ok_or_else(|| Code::Conflict.error("managed renewal lifecycle"))?;
            let expected = admitted.clone();
            admitted.grant = grant;
            let prepared = owner.prepared.clone();
            let calls = owner.calls.clone();
            let metadata = memory
                .reserve_input(Self::metadata_bytes(&admitted, &calls)?)
                .map_err(|source| araphor_query::Error::Sql { source })?;
            let renewed =
                Self::authorize(owner.authority.as_ref(), &admitted.grant, &prepared, || {
                    owner
                        .query
                        .store()
                        .renew_managed(&expected, &admitted.grant, || stage.check())
                })?;
            admitted.lifecycle = renewed.lifecycle;
            Ok(Self {
                query: Arc::clone(&owner.query),
                authority: Arc::clone(&owner.authority),
                admitted,
                prepared,
                calls,
                _metadata: metadata,
            })
        })
        .await?;
        Ok(Arc::new(replacement))
    }
}
