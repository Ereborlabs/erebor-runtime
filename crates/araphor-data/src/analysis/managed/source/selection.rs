use std::ops::RangeBounds as _;

use sdk::arrow_array::{Array, BinaryArray, StringArray, UInt32Array, UInt64Array};

use super::*;
use crate::{
    AnalysisContextKeyV1, AnalysisContextRefV1, AnalysisWitnessV1, EvidenceIntakeIdentityV1,
};

impl SourceScope {
    pub(super) fn new(capture: &super::super::model::Capture, contract: SourceContract) -> Self {
        Self {
            tenant: capture.tenant,
            instance: capture.instance.clone(),
            generation: capture.generation,
            store: capture.store,
            schema: capture.schema,
            recovery: capture.recovery,
            contract,
        }
    }

    fn same_owner(&self, other: &Self) -> bool {
        self.tenant == other.tenant
            && self.instance == other.instance
            && self.generation == other.generation
            && self.store == other.store
            && self.schema == other.schema
            && self.recovery == other.recovery
            && self.contract.selection == other.contract.selection
            && self.contract.tables == other.contract.tables
            && self.contract.event_ranges == other.contract.event_ranges
    }
}

impl ManagedSourceFrame {
    pub(super) fn new(
        record: RecordSource,
        tables: Vec<sdk::Dataset>,
        scope: Arc<SourceScope>,
    ) -> Self {
        Self {
            scope,
            record,
            tables,
            proof: Arc::default(),
            selected: Arc::default(),
        }
    }

    pub fn row_handles(&self, table: &str, batch: usize) -> Result<ManagedSourceBlock> {
        let batch = self
            .tables
            .iter()
            .find(|data| data.name == table)
            .and_then(|data| data.batches.get(batch))
            .ok_or_else(|| Code::Invalid.error("managed source row block"))?;
        let rows = (0..batch.num_rows())
            .map(|row| {
                let position = StorePositionV1 {
                    commit_revision: SourceRow::array::<UInt64Array>(batch, "commit_revision")?
                        .value(row),
                    ordinal: if table == "events" {
                        SourceRow::array::<UInt32Array>(batch, "ordinal")?.value(row)
                    } else {
                        u32::MAX
                    },
                };
                if position.commit_revision == 0
                    || position > self.position()
                    || self.read().after().is_some_and(|after| position <= after)
                {
                    return Err(Code::Invalid.error("managed source row position"));
                }
                let value = SourceRow::decode(table, batch, row)?;
                value.check_scope(&self.record.contract.selection)?;
                if table == "events" {
                    let received =
                        SourceRow::array::<UInt64Array>(batch, "received_utc_ns")?.value(row);
                    let selection = &self.record.contract.selection;
                    if !(selection.received_from, selection.received_until).contains(&received)
                        || self
                            .record
                            .contract
                            .event_ranges
                            .as_ref()
                            .is_some_and(|ranges| {
                                !ranges
                                    .iter()
                                    .any(|(first, last)| (*first..=*last).contains(&received))
                            })
                    {
                        return Err(Code::Invalid.error("managed source row time"));
                    }
                }
                Ok(value)
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(ManagedSourceBlock {
            scope: Arc::clone(&self.scope),
            proof: Arc::clone(&self.proof),
            rows: Arc::new(rows),
        })
    }

    pub fn record_rows(&self, rows: &ManagedSourceRows) -> Result<()> {
        if !self.scope.same_owner(&rows.scope) {
            return Err(Code::Conflict.error("managed source row scope"));
        }
        let mut support = None;
        if !Arc::ptr_eq(&self.proof, &rows.proof) {
            let parent = match &self.record.contract.read {
                ManagedSourceRead::Changes(parent) => parent,
                ManagedSourceRead::Initial => {
                    return Err(Code::Conflict.error("managed source row basis"));
                }
            };
            let proof = rows
                .proof
                .get()
                .filter(|proof| proof.result.commit_revision <= parent.result.commit_revision)
                .ok_or_else(|| Code::Conflict.error("managed source row proof"))?;
            if rows.scope.contract.position > parent.position {
                return Err(Code::Conflict.error("managed source row basis"));
            }
            let mut selected = SourceSupport {
                origin: ManagedSourceRef {
                    result: proof.result.clone(),
                    position: rows.scope.contract.position,
                },
                witnesses: Vec::with_capacity(rows.witnesses.len()),
                contexts: Vec::with_capacity(rows.contexts.len()),
            };
            for witness in &rows.witnesses {
                selected.witnesses.push(
                    proof
                        .witnesses
                        .binary_search_by(|saved| {
                            saved
                                .identity
                                .cmp(&witness.identity)
                                .then(saved.cursor.cmp(&witness.cursor))
                        })
                        .map_err(|_| Code::Invalid.error("managed source row witness"))?,
                );
            }
            for context in &rows.contexts {
                selected.contexts.push(
                    proof
                        .contexts
                        .binary_search_by(|saved| {
                            saved
                                .key
                                .cmp(&context.key)
                                .then(saved.commit_revision.cmp(&context.commit_revision))
                        })
                        .map_err(|_| Code::Invalid.error("managed source row context"))?,
                );
            }
            if !selected.witnesses.is_empty() || !selected.contexts.is_empty() {
                support = Some(selected);
            }
        }
        for witness in &rows.witnesses {
            if self
                .record
                .removals
                .get(&witness.identity)
                .is_some_and(|ranges| {
                    ranges.iter().any(|range| {
                        (range.first_cursor..=range.last_cursor).contains(&witness.cursor)
                    })
                })
            {
                return Err(Code::Conflict.error("retired managed source row"));
            }
        }
        let mut selected = self
            .selected
            .lock()
            .map_err(|_| Code::Conflict.error("managed source selection lock"))?;
        if selected.frozen {
            return Err(Code::Conflict.error("frozen managed source selection"));
        }
        if let Some(support) = support {
            let saved = selected
                .support
                .entry(support.origin.result.result_id.clone())
                .or_insert_with(|| SourceSupport {
                    origin: support.origin.clone(),
                    witnesses: Vec::new(),
                    contexts: Vec::new(),
                });
            if saved.origin != support.origin {
                return Err(Code::Conflict.error("managed source support origin"));
            }
            saved.witnesses.extend(support.witnesses);
            saved.witnesses.sort_unstable();
            saved.witnesses.dedup();
            saved.contexts.extend(support.contexts);
            saved.contexts.sort_unstable();
            saved.contexts.dedup();
        }
        for witness in &rows.witnesses {
            selected
                .witnesses
                .entry((witness.identity.clone(), witness.cursor))
                .or_insert_with(|| witness.clone());
        }
        for context in &rows.contexts {
            selected
                .contexts
                .entry((context.key.clone(), context.commit_revision))
                .or_insert_with(|| context.clone());
        }
        Ok(())
    }

    pub(in crate::analysis::managed) fn freeze_evidence(
        &self,
        capture: &super::super::model::Capture,
        expiry: u64,
    ) -> Result<SourceEvidence> {
        if self.scope.as_ref() != &SourceScope::new(capture, self.record.contract.clone()) {
            return Err(Code::Conflict.error("managed source selection owner"));
        }
        let mut selected = self
            .selected
            .lock()
            .map_err(|_| Code::Conflict.error("managed source selection lock"))?;
        selected.frozen = true;
        let mut witnesses = selected.witnesses.clone();
        for witness in witnesses.values_mut() {
            witness.expires_utc_ns = expiry;
        }
        for witness in &capture.witnesses {
            witnesses.insert((witness.identity.clone(), witness.cursor), witness.clone());
        }
        let mut contexts = selected.contexts.clone();
        for context in &capture.contexts {
            contexts.insert(
                (context.key.clone(), context.commit_revision),
                context.clone(),
            );
        }
        Ok(SourceEvidence {
            witnesses: witnesses.into_values().collect(),
            contexts: contexts.into_values().collect(),
            support: selected.support.values().cloned().collect(),
        })
    }
}

impl ManagedSourceBlock {
    pub fn witness(&self, row: usize) -> Option<&AnalysisWitnessV1> {
        match self.rows.get(row)? {
            SourceRow::Event(witness) => Some(witness),
            SourceRow::Context(_) => None,
        }
    }

    pub fn select(&self, indices: &[usize]) -> Result<ManagedSourceRows> {
        let mut witnesses = BTreeMap::new();
        let mut contexts = BTreeMap::new();
        for index in indices {
            match self
                .rows
                .get(*index)
                .ok_or_else(|| Code::Invalid.error("managed source row index"))?
            {
                SourceRow::Event(witness) => {
                    witnesses.insert((witness.identity.clone(), witness.cursor), witness.clone());
                }
                SourceRow::Context(context) => {
                    contexts.insert(
                        (context.key.clone(), context.commit_revision),
                        context.clone(),
                    );
                }
            }
        }
        Ok(ManagedSourceRows {
            scope: Arc::clone(&self.scope),
            proof: Arc::clone(&self.proof),
            witnesses: witnesses.into_values().collect(),
            contexts: contexts.into_values().collect(),
        })
    }
}

impl ManagedSourceRows {
    pub fn witnesses(&self) -> &[AnalysisWitnessV1] {
        &self.witnesses
    }

    pub fn contexts(&self) -> &[AnalysisContextRefV1] {
        &self.contexts
    }

    pub fn position(&self) -> StorePositionV1 {
        self.scope.contract.position
    }
}

impl SourceRow {
    fn check_scope(&self, selection: &AnalysisSelectionV1) -> Result<()> {
        let valid = match self {
            Self::Event(witness) => match &witness.identity {
                AnalysisStreamIdentityV1::Evidence(source) => {
                    source.valid()
                        && selection.includes_source(source)
                        && witness.cursor != 0
                        && (selection.cursor_from, selection.cursor_until).contains(&witness.cursor)
                }
                AnalysisStreamIdentityV1::Diagnostic(_) => false,
            },
            Self::Context(context) => {
                context.key.valid()
                    && context.key.tenant_id == selection.tenant_id
                    && (selection.contexts.is_all()
                        || selection.contexts.as_slice().contains(&context.key))
                    && context.commit_revision != 0
            }
        };
        if !valid {
            return Err(Code::Invalid.error("managed source row selection"));
        }
        Ok(())
    }

    fn decode(table: &str, batch: &sdk::RecordBatch, row: usize) -> Result<Self> {
        let bytes = |name| -> Result<Vec<u8>> {
            Ok(Self::array::<BinaryArray>(batch, name)?.value(row).to_vec())
        };
        let number =
            |name| -> Result<u64> { Ok(Self::array::<UInt64Array>(batch, name)?.value(row)) };
        let text = |name| -> Result<String> {
            Ok(Self::array::<StringArray>(batch, name)?
                .value(row)
                .to_owned())
        };
        let identity = |name| -> Result<[u8; 16]> {
            bytes(name)?
                .try_into()
                .map_err(|_| Code::Invalid.error("managed source identity"))
        };
        match table {
            "events" => Ok(Self::Event(AnalysisWitnessV1 {
                identity: EvidenceIntakeIdentityV1 {
                    tenant_id: identity("tenant_id")?,
                    node_id: text("node_id")?,
                    node_boot_id: identity("node_boot_id")?,
                    label_epoch: number("label_epoch")?,
                    source_id: identity("source_id")?,
                    source_epoch: number("source_epoch")?,
                }
                .into(),
                cursor: number("source_cursor")?,
                expires_utc_ns: 0,
            })),
            "context_versions" => Ok(Self::Context(AnalysisContextRefV1 {
                key: AnalysisContextKeyV1 {
                    tenant_id: identity("tenant_id")?,
                    owner_id: text("owner_id")?,
                    entity_key: bytes("entity_key")?,
                    lifetime_key: bytes("lifetime_key")?,
                    owner_revision: number("owner_revision")?,
                },
                commit_revision: number("commit_revision")?,
            })),
            _ => Err(Code::Unsupported.error("managed source row relation")),
        }
    }

    fn array<'a, T: Array + 'static>(batch: &'a sdk::RecordBatch, name: &str) -> Result<&'a T> {
        batch
            .column_by_name(name)
            .and_then(|array| array.as_any().downcast_ref::<T>())
            .filter(|array| array.null_count() == 0)
            .ok_or_else(|| Code::Invalid.error("managed source row field"))
    }
}

impl AnalysisStore {
    pub(in crate::analysis::managed) fn check_source_evidence(
        reader: &Connection,
        attempt: &Attempt,
        step: &Step,
    ) -> Result<()> {
        let capture = &attempt.capture;
        if step.source.as_ref().map(|source| &source.contract) != capture.source.as_ref() {
            return Err(Code::Invalid.error("managed selected source contract"));
        }
        let mut witnesses = BTreeMap::new();
        let mut contexts = BTreeMap::new();
        if let Some(source) = &step.source {
            let scope = SourceScope::new(capture, source.contract.clone());
            let mut previous = None;
            for support in &source.support {
                let parent = match &source.contract.read {
                    ManagedSourceRead::Changes(parent) => parent,
                    ManagedSourceRead::Initial => {
                        return Err(Code::Invalid.error("initial source support"))
                    }
                };
                let id = &support.origin.result.result_id;
                if previous.is_some_and(|old| old >= id)
                    || support.origin.position > parent.position
                    || support.origin.result.commit_revision > parent.result.commit_revision
                    || support.origin.result.commit_revision >= attempt.registered
                    || support.witnesses.windows(2).any(|pair| pair[0] >= pair[1])
                    || support.contexts.windows(2).any(|pair| pair[0] >= pair[1])
                    || (support.witnesses.is_empty() && support.contexts.is_empty())
                {
                    return Err(Code::Invalid.error("managed source support indices"));
                }
                previous = Some(id);
                let (metadata, revision): (Vec<u8>, u64) = reader.query_row(
                    "SELECT request_meta, commit_revision FROM analysis_results
                     WHERE tenant_id = ? AND result_id = ? AND processor_id = 'managed-definition-v1'",
                    params![capture.tenant.as_slice(), id],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                ).context(AnalysisDatabaseSnafu { operation: "read selected source support" })?;
                let origin: Step =
                    ManagedCodec::decode(&metadata).context(crate::ManagedDecodingSnafu)?;
                Self::check_source_header(reader, capture.tenant, id, &origin, revision)?;
                let record = origin
                    .source
                    .as_ref()
                    .ok_or_else(|| Code::Missing.error("managed source support record"))?;
                let saved = Self::managed_attempt_from(
                    reader,
                    capture.tenant,
                    &origin.instance,
                    &origin.attempt,
                )?
                .ok_or_else(|| Code::Missing.error("managed source support attempt"))?;
                if revision != support.origin.result.commit_revision
                    || record.contract.position != support.origin.position
                    || origin.instance != capture.instance
                    || saved.capture.source.as_ref() != Some(&record.contract)
                    || !scope.same_owner(&SourceScope::new(&saved.capture, record.contract.clone()))
                    || saved.terminal.is_some()
                    || saved.registered >= revision
                    || saved.receipt.as_ref().is_none_or(|receipt| {
                        receipt.selected != support.origin.result
                            || receipt.commit_revision != revision
                            || receipt.instance != origin.instance
                            || receipt.attempt != origin.attempt
                    })
                {
                    return Err(Code::Invalid.error("managed source support authority"));
                }
                for index in &support.witnesses {
                    let mut witness = origin
                        .witnesses
                        .get(*index)
                        .cloned()
                        .ok_or_else(|| Code::Invalid.error("managed source support witness"))?;
                    SourceRow::Event(witness.clone()).check_scope(&source.contract.selection)?;
                    if source
                        .removals
                        .get(&witness.identity)
                        .is_some_and(|ranges| {
                            ranges.iter().any(|range| {
                                (range.first_cursor..=range.last_cursor).contains(&witness.cursor)
                            })
                        })
                    {
                        return Err(Code::Invalid.error("retired managed source support"));
                    }
                    witness.expires_utc_ns = attempt.request.witness_expiry;
                    witnesses.insert((witness.identity.clone(), witness.cursor), witness);
                }
                for index in &support.contexts {
                    let context = origin
                        .contexts
                        .get(*index)
                        .cloned()
                        .ok_or_else(|| Code::Invalid.error("managed source support context"))?;
                    SourceRow::Context(context.clone()).check_scope(&source.contract.selection)?;
                    if context.commit_revision > record.contract.position.commit_revision {
                        return Err(Code::Invalid.error("managed source support context cut"));
                    }
                    contexts.insert((context.key.clone(), context.commit_revision), context);
                }
            }
        }
        for witness in &capture.witnesses {
            witnesses.insert((witness.identity.clone(), witness.cursor), witness.clone());
        }
        for context in &capture.contexts {
            contexts.insert(
                (context.key.clone(), context.commit_revision),
                context.clone(),
            );
        }
        if !witnesses.into_values().eq(step.witnesses.iter().cloned())
            || !contexts.into_values().eq(step.contexts.iter().cloned())
        {
            return Err(Code::Invalid.error("managed selected source evidence"));
        }
        Ok(())
    }
}
