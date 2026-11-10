use super::*;

pub(crate) struct MetadataRead {
    store: Arc<crate::storage::AnalysisStore>,
    selection: AnalysisSelectionV1,
    requests: AnalysisTableRequests,
    limits: araphor_data::AnalysisExtractLimits,
    control: AnalysisReadControl,
    now: u64,
    memory: Arc<crate::memory::Memory>,
    _scope: MemoryReservation,
}

impl MetadataRead {
    pub(crate) fn new(
        session: &crate::execution::Session,
        demands: &AnalysisTableRequests,
        now: u64,
        window: Option<&crate::follow::Window>,
        control: AnalysisReadControl,
    ) -> Result<Self> {
        control.check().map_err(SourceSnapshot::data_error)?;
        let limits = session.engine().limits();
        let bytes = size_of::<Self>()
            .checked_add(session.selection().metadata_bytes(demands))
            .and_then(|bytes| bytes.checked_add(CapturedRequests::metadata_bytes(demands)?))
            .filter(|bytes| *bytes <= limits.input_bytes)
            .ok_or_else(|| {
                DataFusionError::ResourcesExhausted(
                    "subscription metadata input scope memory".into(),
                )
            })?;
        let reservation = session.memory().reserve_input(bytes)?;
        let mut selection = session.selection().metadata_projection(demands);
        if let Some(window) = window {
            window.apply_selection(&mut selection, now);
        }
        Ok(Self {
            store: Arc::clone(session.engine().store()),
            selection,
            requests: demands.keys().map(|name| (name.clone(), None)).collect(),
            limits: araphor_data::AnalysisExtractLimits {
                scan_bytes: limits.scan_bytes,
                input_bytes: limits.input_bytes,
                keys: limits.extract_keys,
                ..Default::default()
            },
            control,
            now,
            memory: Arc::clone(session.memory()),
            _scope: reservation,
        })
    }

    pub(crate) fn capture(self) -> Result<Arc<ArrowSnapshot>> {
        self.control.check().map_err(SourceSnapshot::data_error)?;
        let bounded =
            self.memory.input_capacity().is_some() || self.limits.input_bytes != usize::MAX;
        let available = self.limits.input_bytes.saturating_sub(self._scope.size());
        let memory = if bounded {
            self.memory
                .prepare_input(if self.limits.input_bytes == usize::MAX {
                    usize::MAX
                } else {
                    available
                })?
        } else {
            self.memory.reserve_input(0)?
        };
        let mut limits = self.limits;
        limits.input_bytes = if bounded { memory.size() } else { available };
        let ceiling = self
            .limits
            .input_bytes
            .min(self.memory.input_capacity().unwrap_or(usize::MAX))
            .saturating_sub(self._scope.size());
        let constrained = bounded && limits.input_bytes < ceiling;
        let (selection, mut page) = self
            .store
            .subscription_metadata(
                &self.selection,
                &self.requests,
                self.now,
                limits,
                &self.control,
            )
            .map_err(|error| SourceSnapshot::input_error(error, constrained))?;
        if !page.tables.is_empty()
            || !page.removals.is_empty()
            || !page.extraction.witnesses.is_empty()
        {
            return Err(DataFusionError::Internal(
                "subscription metadata contains row authority".into(),
            ));
        }
        let overflow = || {
            let source =
                DataFusionError::ResourcesExhausted("subscription metadata input memory".into());
            if constrained {
                DataFusionError::External(Box::new(crate::Error::Capacity {
                    resource: "shared input",
                    source,
                }))
            } else {
                source
            }
        };
        let bytes = size_of::<ArrowSnapshot>()
            .saturating_add(
                page.extraction
                    .allocation_bytes()
                    .saturating_sub(size_of::<araphor_data::AnalysisExtractionV1>()),
            )
            .checked_add(selection.allocation_bytes())
            .filter(|bytes| *bytes <= limits.input_bytes)
            .ok_or_else(overflow)?;
        memory.try_resize(bytes)?;
        let request_bytes = CapturedRequests::allocation_bytes(None).ok_or_else(overflow)?;
        let requests = Arc::new(CapturedRequests {
            context_owners: None,
            _memory: self._scope.split(request_bytes),
        });
        self.control.check().map_err(SourceSnapshot::data_error)?;
        Ok(Arc::new(ArrowSnapshot {
            mutable_discovery: std::mem::take(&mut page.mutable_discovery),
            received_min: page.received_min.take(),
            next_change: page.next_change.take(),
            windows: Vec::new(),
            now: self.now,
            page,
            selection,
            witnesses: Vec::new(),
            requests,
            managed: None,
            
            notification: None,
            _metadata: memory,
        }))
    }
}
