use super::*;
use crate::{DiscoveryRecordIdV1, EvidenceIntakeIdentityV1, GraphReplayInputV1, ManagedCapture};

#[derive(Debug)]
pub struct ManagedInputSelection {
    pub(in crate::analysis) scope: Arc<SourceScope>,
    pub(in crate::analysis) proof: Arc<OnceLock<Arc<PackageResultRefV1>>>,
    pub(in crate::analysis) source: EvidenceIntakeIdentityV1,
    pub(in crate::analysis) parent: Option<ManagedSourceRef>,
    pub(in crate::analysis) base: Option<PackageResultRefV1>,
    pub(in crate::analysis) first: u64,
    pub(in crate::analysis) last: u64,
    pub(in crate::analysis) deadline: u64,
    pub(in crate::analysis) append: bool,
    pub(in crate::analysis) expired: bool,
    pub(in crate::analysis) coverage: Vec<crate::GraphCoverageKeyV1>,
    pub(in crate::analysis) records: Vec<(DiscoveryRecordIdV1, StorePositionV1)>,
    pub(in crate::analysis) prefix: Option<Arc<crate::InputProof>>,
    pub(in crate::analysis::managed) derived: Arc<ManagedDerivedSource>,
    pub(in crate::analysis) restricted: BTreeMap<DiscoveryRecordIdV1,u64>,
    _lease: SelectionLease,
}

struct SelectionLease(Arc<dyn std::any::Any + Send + Sync>);

impl std::fmt::Debug for SelectionLease {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let _ = &self.0;
        formatter.write_str("SelectionLease")
    }
}

impl ManagedInputSelection {
    fn same(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.scope, &other.scope)
            && Arc::ptr_eq(&self.proof, &other.proof)
            && self.source == other.source && self.parent == other.parent
            && self.base == other.base && self.first == other.first && self.last == other.last
            && self.deadline == other.deadline && self.append == other.append && self.expired==other.expired
            && self.records == other.records && self.prefix == other.prefix
            && self.coverage == other.coverage
            && self.restricted == other.restricted
            && self.derived.contexts == other.derived.contexts
            && self.derived.references == other.derived.references
            && self.derived.proofs == other.derived.proofs
            && self.derived.history.as_ref().map(|history| &history.result)
                == other.derived.history.as_ref().map(|history| &history.result)
    }

    pub fn expired(&self) -> bool { self.expired }

    pub fn prefix(&self) -> Option<&Arc<crate::InputProof>> {
        self.prefix.as_ref()
    }

    pub fn parent(&self) -> Option<&ManagedSourceRef> {
        self.parent.as_ref()
    }

    pub fn records(&self) -> &[(DiscoveryRecordIdV1, StorePositionV1)] {
        &self.records
    }
}

impl ManagedSourceFrame {
    pub fn selection_bytes(
        input: &GraphReplayInputV1, prefix: Option<&crate::InputProof>,
    ) -> Option<usize> {
        let bytes = input.input_positions.iter().try_fold(
            std::mem::size_of::<ManagedInputSelection>()
                .checked_add(input.source.node_id.len())?
                .checked_add(prefix.map_or(0, crate::InputProof::metadata_bytes))?,
            |bytes, (record, _)| bytes.checked_add(record.allocated_bytes())?
                .checked_add(4 * std::mem::size_of::<(DiscoveryRecordIdV1, StorePositionV1)>())
                .and_then(|bytes| bytes.checked_add(16 * std::mem::size_of::<usize>())),
        )?;
        let bytes = input.coverage_keys.iter().try_fold(bytes,|bytes,key| bytes
            .checked_add(std::mem::size_of_val(key))?
            .checked_add(key.source.node_id.len())?
            .checked_add(key.gap_reasons.iter().try_fold(0usize,|bytes,reason| bytes
                .checked_add(std::mem::size_of::<String>())?.checked_add(reason.len()))?))?;
        let bytes = bytes.checked_add(prefix.map_or(0,|proof| proof.boundaries().count()).checked_mul(
            std::mem::size_of::<crate::GraphCoverageKeyV1>().checked_add(input.source.node_id.len())?)?)?;
        bytes.checked_mul(2)
    }

    pub fn select_graph_input(
        &self,
        capture: &ManagedCapture,
        reference: Option<&super::super::model::ManagedAttempt>,
        input: &GraphReplayInputV1,
        derived: &Arc<ManagedDerivedSource>,
        base: Option<&PackageResultRefV1>,
        window: (u64, u64, u64),
        mode: (bool, bool, bool),
        lease: Arc<dyn std::any::Any + Send + Sync>,
    ) -> Result<Arc<ManagedInputSelection>> {
        let (first, last, deadline) = window;
        let (append, eligible, expired) = mode;
        if reference.is_some()
            || !capture.source().is_some_and(|frame| std::ptr::eq(self, frame.as_ref()))
            || !input.source.valid() || input.source.tenant_id != self.scope.tenant
            || !self.scope.selection.includes_source(&input.source)
            || first == 0 || last < first
            || expired!=self.expired_window(&input.source,first,deadline,capture.time_utc_ns())?
            || expired && (append || base.is_none() || !input.records.is_empty())
            || input.records.iter().any(|record| record.id.stream != input.source
                || !(first..=last).contains(&record.id.durable_cursor))
        {
            return Err(Code::Denied.error("native source selection owner"));
        }
        if input.records.len() != input.input_positions.len()
            || input.records.windows(2).any(|pair| pair[0].id >= pair[1].id)
            || input.records.iter().zip(&input.input_positions)
                .any(|(record, (id, _))| &record.id != id)
        {
            return Err(Code::Invalid.error("native source position bijection"));
        }
        self.check_coverage(input)?;
        let parent = match &self.scope.read {
            ManagedSourceRead::Initial => None,
            ManagedSourceRead::Changes(parent) => Some(parent.clone()),
        };
        if append && base.is_some_and(|base| parent.as_ref().is_none_or(|parent| &parent.result != base)) {
            return Err(Code::Conflict.error("native source selection parent"));
        }
        let prior = base.and_then(|base| capture.graph_input(base));
        if append && (!eligible || base.is_none() || parent.is_none()
            || !self.removals.is_empty()
            || input.input_positions.iter().any(|(_, position)|
                parent.as_ref().is_none_or(|parent| *position <= parent.position))
            || !prior.is_some_and(|proof| proof.scope(&input.source, first, last)
                && self.prefix_coverage(&input.source, first, proof)))
        {
            return Err(Code::Conflict.error("native source append basis"));
        }
        let mut selected = self.selected.lock()
            .map_err(|_| Code::Conflict.error("native source selection lock"))?;
        if selected.frozen { return Err(Code::Conflict.error("frozen native source selection")); }
        if !Arc::ptr_eq(&derived.scope, &self.scope) || !Arc::ptr_eq(&derived.proof, &self.proof)
            || derived.records != input.input_positions || derived.contexts != input.facts
        { return Err(Code::Denied.error("native source selection handle")); }
        let mut restricted = BTreeMap::<DiscoveryRecordIdV1,u64>::new();
        for context in &derived.contexts {
            if context.sensitivity == crate::ContextSensitivityV1::HostRestricted {
                let fact = crate::GraphFactV1::try_from(context)?;
                let count = restricted.entry(fact.record_id).or_default();
                *count = count.checked_add(1).ok_or_else(|| Code::Limit.error("native source disclosure count"))?;
            }
        }
        let mut prefix = if !expired && eligible && input.missing_ranges.is_empty()
            && input.facts.iter().all(|value| crate::GraphFactV1::try_from(value)
                .is_ok_and(|fact| crate::InputProof::check_local(&fact).is_ok()))
        {
            if append { prior.map(|proof| proof.as_ref().clone()) }
            else { Some(crate::InputProof::new(input.source.clone(), first, last)) }
        } else { None };
        if let Some(proof) = &mut prefix { proof.extend_window(last); }
        if prefix.is_some() {
            let coverage = input.coverage.iter().map(|range|
                ((range.cpu_id, range.first_cursor), range)).collect::<BTreeMap<_, _>>();
            for record in &input.records {
                let range = coverage.get(&(record.id.cpu_id, record.id.durable_cursor));
                if !prefix.as_mut().zip(range).is_some_and(|(proof, range)|
                    proof.add_position(&record.id, record.original_kernel_sequence,
                        matches!(range.state, crate::DiscoveryCoverageStateV1::Healthy
                            | crate::DiscoveryCoverageStateV1::Closed), range.coverage_interval_id))
                {
                    prefix = None;
                    break;
                }
            }
        }
        let coverage = self.selection_coverage(input,if append { prior.map(Arc::as_ref) } else { None })?;
        let value = Arc::new(ManagedInputSelection {
            scope: Arc::clone(&self.scope), proof: Arc::clone(&self.proof),
            source: input.source.clone(), parent, base: base.cloned(), first, last, deadline,
            append, expired, coverage, records: input.input_positions.clone(), prefix: prefix.map(Arc::new),
            derived:Arc::clone(derived),restricted,
            _lease: SelectionLease(lease),
        });
        if let Some(prior) = &selected.input {
            if !prior.same(&value) { return Err(Code::Conflict.error("native source selection repeated")); }
            return Ok(Arc::clone(prior));
        }
        selected.input = Some(Arc::clone(&value));
        Ok(value)
    }

    pub fn input_selection(&self) -> Result<Option<Arc<ManagedInputSelection>>> {
        let selected = self.selected.lock()
            .map_err(|_| Code::Conflict.error("native source selection lock"))?;
        Ok(selected.input.as_ref().map(Arc::clone))
    }
}
