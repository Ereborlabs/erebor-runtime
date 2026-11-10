use std::ops::RangeBounds as _;


use sdk::arrow_array::{Array, BinaryArray, StringArray, UInt32Array, UInt64Array};

use super::*;
use crate :: { AnalysisContextKeyV1 , AnalysisContextRefV1 , AnalysisWitnessV1 , EvidenceIntakeIdentityV1 } ;

impl SourceScope {
    pub fn check_basis(&self, prior: &Self) -> Result<()> {
        if self.tenant != prior.tenant
            || self.instance != prior.instance
            || self.generation != prior.generation
            || self.store != prior.store
            || self.schema != prior.schema
            || self.recovery != prior.recovery
            || self.read.after() != Some(prior.position)
        {
            return Err(Code::Conflict.error("managed source index basis"));
        }
        for name in ["events", "context_versions"] {
            if !self.tables.get(name).is_some_and(Option::is_some) {
                continue;
            }
            if !prior.tables.get(name).is_some_and(Option::is_some) {
                return Err(Code::Conflict.error("managed source index gap"));
            }
            let request = BTreeMap::from([(name.to_owned(), Some(BTreeSet::new()))]);
            if self.selection.project(&request)? != prior.selection.project(&request)? {
                return Err(Code::Conflict.error("managed source index selection"));
            }
            if name == "context_versions" && self.context_owners != prior.context_owners {
                return Err(Code::Conflict.error("managed source index owners"));
            }
            if name == "events" && self.event_ranges != prior.event_ranges {
                return Err(Code::Conflict.error("managed source index ranges"));
            }
        }
        Ok(())
    }

    fn same_owner(&self, other: &Self) -> bool {
        self.tenant == other.tenant
            && self.instance == other.instance
            && self.generation == other.generation
            && self.store == other.store
            && self.schema == other.schema
            && self.recovery == other.recovery
    }
}

impl ManagedSourceFrame {
    pub fn attribute_rows(
        &self,
        call: u64,
        rows: &[Arc<ManagedSourceRows>],
        lease: Arc<dyn std::any::Any + Send + Sync>,
    ) -> Result<()> {
        self.attribute_input(call, rows, &[], lease)
    }

    pub fn attribute_input(
        &self,
        call: u64,
        rows: &[Arc<ManagedSourceRows>],
        derived: &[Arc<ManagedDerivedSource>],
        lease: Arc<dyn std::any::Any + Send + Sync>,
    ) -> Result<()> {
        for rows in rows {
            self.check_rows(rows)?;
        }
        self.check_derived_lineage(rows, derived)?;
        let mut selected = self
            .selected
            .lock()
            .map_err(|_| Code::Conflict.error("managed source selection lock"))?;
        if selected.frozen {
            return Err(Code::Conflict.error("frozen source call attribution"));
        }
        let source = selected.calls.entry(call).or_default();
        source
            .cells
            .extend(rows.iter().map(|rows| Arc::clone(&rows.cells)));
        for value in derived {
            if !source.derived.iter().any(|prior| Arc::ptr_eq(prior, value)) {
                source.derived.push(Arc::clone(value));
            }
        }
        source.leases.push(lease);
        Ok(())
    }

    pub(super) fn new(
        tables: Vec<sdk::Dataset>,
        removals: BTreeMap<AnalysisStreamIdentityV1, Vec<AnalysisGapV1>>,
        scope: Arc<SourceScope>,
    ) -> Self {
        Self {
            scope,
            tables,
            removals,
            proof: Arc::default(),
            selected: Arc::default(),
            coverage: Vec::new(),
            
            complete: false,
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
                let value = SourceRow::decode(table, batch, row, position)?;
                value.check_scope(&self.scope)?;
                if table == "events" {
                    let received =
                        SourceRow::array::<UInt64Array>(batch, "received_utc_ns")?.value(row);
                    let selection = &self.scope.selection;
                    if !(selection.received_from, selection.received_until).contains(&received)
                        || self.scope.event_ranges.as_ref().is_some_and(|ranges| {
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
            table: table.into(),
            batch: Arc::new(batch.clone()),
        })
    }

    fn check_rows(&self, rows: &ManagedSourceRows) -> Result<()> {
        if !self.scope.same_owner(&rows.scope) {
            return Err(Code::Conflict.error("managed source row scope"));
        }
        if rows.selected_position > rows.scope.position {
            return Err(Code::Invalid.error("managed source row position"));
        }
        if !Arc::ptr_eq(&self.proof, &rows.proof) {
            let parent = match &self.scope.read {
                ManagedSourceRead::Changes(parent) => parent,
                ManagedSourceRead::Initial => {
                    return Err(Code::Conflict.error("managed source row basis"));
                }
            };
            let proof = rows
                .proof
                .get()
                .filter(|proof| proof.commit_revision <= parent.result.commit_revision)
                .ok_or_else(|| Code::Conflict.error("managed source row proof"))?;
            if proof.commit_revision == 0 || rows.scope.position > parent.position {
                return Err(Code::Conflict.error("managed source row basis"));
            }
        }
        for witness in &rows.witnesses {
            self.scope.check_witness(witness)?;
            if self.removals.get(&witness.identity).is_some_and(|ranges| {
                ranges
                    .iter()
                    .any(|range| (range.first_cursor..=range.last_cursor).contains(&witness.cursor))
            }) {
                return Err(Code::Conflict.error("retired managed source row"));
            }
        }
        for context in &rows.contexts {
            self.scope.check_context(context)?;
        }
        Ok(())
    }

    pub fn record_rows(&self, rows: &ManagedSourceRows) -> Result<()> {
        self.check_rows(rows)?;
        let mut selected = self
            .selected
            .lock()
            .map_err(|_| Code::Conflict.error("managed source selection lock"))?;
        if selected.frozen {
            return Err(Code::Conflict.error("frozen managed source selection"));
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
        selected.cells.push(Arc::clone(&rows.cells));
        Ok(())
    }

    pub(in crate::analysis) fn freeze_evidence(
        &self,
        capture: &super::super::model::Capture,
        expiry: u64,
        memory: &mut super::super::budget::PreparedMemory<'_>,
    ) -> Result<SourceEvidence> {
        if self.scope.tenant != capture.tenant
            || self.scope.instance != capture.instance
            || self.scope.generation != capture.generation
            || self.scope.store != capture.store
            || self.scope.schema != capture.schema
            || self.scope.recovery != capture.recovery
            || self.scope.position
                != (StorePositionV1 {
                    commit_revision: capture.revision,
                    ordinal: u32::MAX,
                })
        {
            return Err(Code::Conflict.error("managed source selection owner"));
        }
        let mut selected = self
            .selected
            .lock()
            .map_err(|_| Code::Conflict.error("managed source selection lock"))?;
        memory.charge(SourceEvidence::metadata_bytes(
            selected.witnesses.values().chain(&capture.witnesses),
            selected.contexts.values().chain(&capture.contexts),
        )?)?;
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
        })
    }
}

impl ManagedSourceBlock {
    pub fn witness(&self, row: usize) -> Option<&AnalysisWitnessV1> {
        match self.rows.get(row)? {
            SourceRow::Event(witness, _) => Some(witness),
            SourceRow::Context(_) => None,
        }
    }

    pub fn select(
        &self,
        indices: &[usize],
        lease: Arc<dyn std::any::Any + Send + Sync>,
    ) -> Result<ManagedSourceRows> {
        let mut witnesses = BTreeMap::new();
        let mut contexts = BTreeMap::new();
        let mut selected_position = StorePositionV1 {
            commit_revision: 0,
            ordinal: 0,
        };
        for index in indices {
            match self
                .rows
                .get(*index)
                .ok_or_else(|| Code::Invalid.error("managed source row index"))?
            {
                SourceRow::Event(witness, position) => {
                    selected_position = selected_position.max(*position);
                    witnesses.insert((witness.identity.clone(), witness.cursor), witness.clone());
                }
                SourceRow::Context(context) => {
                    selected_position = selected_position.max(StorePositionV1 {
                        commit_revision: context.commit_revision,
                        ordinal: u32::MAX,
                    });
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
            selected_position,
            cells: Arc::new(SourceCells {
                table: Arc::clone(&self.table),
                batch: Arc::clone(&self.batch),
                rows: Arc::clone(&self.rows),
                indices: indices.to_vec(),
                _lease: lease,
            }),
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
}

impl SourceRow {
    fn check_scope(&self, contract: &SourceScope) -> Result<()> {
        match self {
            Self::Event(witness, _) => contract.check_witness(witness),
            Self::Context(context) => contract.check_context(context),
        }
    }

    fn decode(
        table: &str,
        batch: &sdk::RecordBatch,
        row: usize,
        position: StorePositionV1,
    ) -> Result<Self> {
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
            "events" => Ok(Self::Event(
                AnalysisWitnessV1 {
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
                },
                position,
            )),
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

    pub(super) fn array<'a, T: Array + 'static>(
        batch: &'a sdk::RecordBatch,
        name: &str,
    ) -> Result<&'a T> {
        batch
            .column_by_name(name)
            .and_then(|array| array.as_any().downcast_ref::<T>())
            .filter(|array| array.null_count() == 0)
            .ok_or_else(|| Code::Invalid.error("managed source row field"))
    }
}


