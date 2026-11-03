use super::*;

impl SourceSnapshot {
    pub(crate) fn capture_before(
        &self,
        reference: &araphor_data::ManagedAttempt,
        current: &Self,
        requests: &AnalysisTableRequests,
        bounds: ScanBounds,
        call: u64,
    ) -> Result<Arc<ArrowSnapshot>> {
        let control = self
            .control
            .within(self.extract_timeout)
            .map_err(Self::data_error)?;
        control.check().map_err(Self::data_error)?;
        if std::ptr::eq(self, current) || self.now != reference.request().time_utc_ns {
            return Err(DataFusionError::Execution(
                "the before source capture differs".into(),
            ));
        }
        let view = current.source_view()?.ok_or_else(|| {
            DataFusionError::Execution("the current source view is absent".into())
        })?;
        let view = if reference
            .receipt()
            .is_some_and(|receipt| receipt.commit_revision == view.version())
        {
            view.check_before(reference)?;
            view
        } else {
            view.call_before(call, reference)?
        };
        let requests = requests
            .iter()
            .filter(|(_, columns)| columns.is_some())
            .map(|(name, columns)| (name.clone(), columns.clone()))
            .collect::<AnalysisTableRequests>();
        let requests = &requests;
        let active = current.snapshot()?;
        for (name, columns) in requests {
            let admitted = view.frame().projection().get(name).ok_or_else(|| {
                DataFusionError::Execution("the before source namespace was not admitted".into())
            })?;
            if columns.as_ref().is_some_and(|columns| {
                admitted
                    .as_ref()
                    .is_none_or(|admitted| !columns.is_subset(admitted))
            }) {
                return Err(DataFusionError::Execution(
                    "the before source columns were not admitted".into(),
                ));
            }
        }
        let contexts = requests
            .get("context_versions")
            .is_some_and(Option::is_some);
        if if contexts {
            active.requests().context_owners().is_some_and(|owners| {
                bounds
                    .context_owners
                    .as_ref()
                    .is_none_or(|selected| !selected.is_subset(owners))
            })
        } else {
            bounds.context_owners.is_some()
        } {
            return Err(DataFusionError::Execution(
                "the before context owners were not admitted".into(),
            ));
        }
        let selection = reference
            .instance()
            .spec
            .destination
            .selection(&reference.instance().grant.selection)
            .and_then(|selection| selection.project(requests))
            .map_err(Self::data_error)?;
        let captured = self
            .captured
            .lock()
            .map_err(|_| DataFusionError::Internal("source snapshot lock is poisoned".into()))?;
        if captured.is_some()
            || self
                .index
                .lock()
                .map_err(|_| DataFusionError::Internal("source index lock is poisoned".into()))?
                .is_some()
        {
            return Err(DataFusionError::Execution(
                "the before source capture has already started".into(),
            ));
        }
        drop(captured);
        self.bind_reference(reference.clone())?;
        {
            let mut bound = self
                .view
                .lock()
                .map_err(|_| DataFusionError::Internal("source view lock is poisoned".into()))?;
            if bound.is_some() {
                return Err(DataFusionError::Execution(
                    "the before source capture has already started".into(),
                ));
            }
            *bound = Some(view);
        }
        let snapshot =
            self.read_selected(requests, &bounds, ReadMode::Metadata, &control, selection)?;
        control.check().map_err(Self::data_error)?;
        let mut captured = self
            .captured
            .lock()
            .map_err(|_| DataFusionError::Internal("source snapshot lock is poisoned".into()))?;
        if captured.is_some() {
            return Err(DataFusionError::Execution(
                "the before source capture has already started".into(),
            ));
        }
        let receipt = Arc::clone(&snapshot.receipt);
        *captured = Some(snapshot);
        Ok(receipt)
    }
}
