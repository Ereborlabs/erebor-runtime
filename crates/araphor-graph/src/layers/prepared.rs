use super::scratch::Lease;
use super::*;

pub struct WriterCut {
    pub writer: u64,
    pub parent: Option<u64>,
    pub revision: u64,
}

pub struct PreparedLayers {
    pub(super) parents: BTreeMap<u64, Option<u64>>,
    pub(super) base: BaseRows,
    pub(super) rows: Vec<PreparedRows>,
    declarations: BTreeMap<(u64, u64), Endpoints>,
    shapes: BTreeMap<u64, Relation>,
    cuts: BTreeMap<u64, u64>,
    _leases: Vec<Lease>,
}

impl PreparedLayers {
    pub(super) fn check_current(&self, graph: &PendingGraph<'_>) -> Result<()> {
        if self.parents.len() != graph.heads.len() {
            return InvalidSnafu {
                field: "Graph prepared writers",
            }
            .fail();
        }
        for (writer, parent) in &self.parents {
            let layer = graph.heads.get(writer).ok_or_else(|| {
                InvalidSnafu {
                    field: "Graph prepared writer",
                }
                .build()
            })?;
            let stored: (Option<u64>, Option<u64>) = graph
                .connection
                .query_row(
                    "SELECT layer.parent_id,parent.revision FROM graph_layers layer
                 LEFT JOIN graph_layers parent ON parent.writer_id=layer.writer_id
                    AND parent.layer_id=layer.parent_id
                 WHERE layer.writer_id=? AND layer.layer_id=? AND layer.revision=?",
                    params![writer, layer, graph.revision],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .context(DatabaseSnafu {
                    operation: "check prepared Graph parent",
                })?;
            if stored.0 != *parent
                || stored.0.is_some() != stored.1.is_some()
                || stored
                    .1
                    .is_some_and(|revision| revision > self.cuts[writer])
            {
                return ConflictSnafu {
                    resource: "prepared Graph parent",
                }
                .fail();
            }
        }
        let connection = graph.connection;
        let validator = StoredDeclarations { connection };
        for ((writer, relation), endpoints) in &self.declarations {
            if validator.check_relation(*writer, *relation, &self.shapes[relation])? != *endpoints {
                return ConflictSnafu {
                    resource: "Graph prepared declaration",
                }
                .fail();
            }
        }
        for (relation, shape) in &self.shapes {
            let mut statement = connection
                .prepare(&format!(
                    "SELECT properties FROM graph_properties_{relation} WHERE false"
                ))
                .context(DatabaseSnafu {
                    operation: "prepare Graph stored shape",
                })?;
            let schema = statement
                .query_arrow([])
                .context(DatabaseSnafu {
                    operation: "read Graph stored shape",
                })?
                .get_schema();
            if schema.fields().len() != 1
                || !GraphStore::storage_compatible(
                    schema.field(0).data_type(),
                    &DataType::Struct(shape.properties.fields().clone()),
                )
            {
                return InvalidSnafu {
                    field: "Graph stored shape",
                }
                .fail();
            }
        }
        Ok(())
    }
}

pub(super) struct Preparation<'a> {
    views: &'a BTreeMap<u64, &'a crate::GraphReadView>,
    parents: &'a BTreeMap<u64, Option<u64>>,
}

struct StoredDeclarations<'a> {
    connection: &'a Connection,
}

pub(super) struct PreparedRows {
    pub(super) writer: u64,
    pub(super) relation: u64,
    pub(super) shape: Relation,
    pub(super) endpoints: Endpoints,
    pub(super) properties: RecordBatch,
    pub(super) owners: Vec<Vec<u8>>,
    pub(super) keys: Vec<Vec<u8>>,
    pub(super) edge_keys: Option<(Vec<Vec<u8>>, Vec<Vec<u8>>, Vec<Vec<u8>>)>,
}

impl GraphStore {
    pub fn prepare_layers(
        views: &BTreeMap<u64, &crate::GraphReadView>,
        cuts: &[WriterCut],
        journals: &[&Journal],
        relations: &BTreeMap<u64, Relation>,
        reserve: impl Fn(u64, usize, usize) -> Result<Option<Lease>>,
    ) -> Result<PreparedLayers> {
        let mut scratch = Scratch::new(&reserve);
        let mut parents = BTreeMap::new();
        for cut in cuts {
            scratch.check(cut.writer)?;
            if cut.writer == 0 || cut.revision == 0 || parents.contains_key(&cut.writer) {
                return InvalidSnafu {
                    field: "Graph prepared cut",
                }
                .fail();
            }
            scratch.charge(cut.writer, 12 * std::mem::size_of::<(u64, Option<u64>)>())?;
            let view = views.get(&cut.writer).ok_or_else(|| {
                InvalidSnafu {
                    field: "Graph prepared view",
                }
                .build()
            })?;
            if view.revision != cut.revision || !view.writers.contains(&cut.writer) {
                return InvalidSnafu {
                    field: "Graph prepared cut",
                }
                .fail();
            }
            parents.insert(cut.writer, cut.parent);
        }
        let validator = Preparation {
            views,
            parents: &parents,
        };
        let declarations = validator.check_journals(journals, relations, &mut scratch)?;
        let mut shapes = BTreeMap::new();
        for ((writer, relation), _) in &declarations {
            if !shapes.contains_key(relation) {
                let shape = &relations[relation];
                let bytes = shape
                    .properties
                    .fields()
                    .size()
                    .saturating_add(
                        shape
                            .properties
                            .metadata()
                            .iter()
                            .map(|(key, value)| {
                                key.capacity()
                                    .saturating_add(value.capacity())
                                    .saturating_add(4 * size_of::<(String, String)>())
                            })
                            .sum::<usize>(),
                    )
                    .saturating_add(12 * size_of::<(u64, Relation)>());
                scratch.charge(*writer, bytes)?;
                shapes.insert(*relation, shape.clone());
            }
        }
        let base = BaseRows::load(cuts, journals, views, &mut scratch)?;
        base.check(journals, &scratch)?;
        let mut rows = Vec::new();
        for journal in journals {
            let mut selected = BTreeMap::<u64, Selected<'_>>::new();
            for (relation, batch, row) in journal.final_rows() {
                scratch.check(journal.writer())?;
                if !selected
                    .get(&relation)
                    .is_some_and(|batches| batches.contains_key(&(Arc::as_ptr(batch) as usize)))
                {
                    let bytes = batch
                        .get_array_memory_size()
                        .checked_mul(4)
                        .and_then(|bytes| {
                            bytes.checked_add(batch.schema().fields().size().checked_mul(8)?)
                        })
                        .and_then(|bytes| {
                            bytes.checked_add(batch.num_rows().checked_mul(
                                10 * std::mem::size_of::<u64>()
                                    + 2 * std::mem::size_of::<Vec<u8>>(),
                            )?)
                        })
                        .and_then(|bytes| {
                            bytes.checked_add(
                                std::mem::size_of::<(usize, (&RecordBatch, Vec<u64>))>() * 12
                                    + std::mem::size_of::<(u64, Selected<'_>)>() * 12,
                            )
                        })
                        .ok_or_else(|| {
                            InvalidSnafu {
                                field: "Graph reduction memory",
                            }
                            .build()
                        })?;
                    scratch.charge(journal.writer(), bytes)?;
                }
                selected
                    .entry(relation)
                    .or_default()
                    .entry(Arc::as_ptr(batch) as usize)
                    .or_insert_with(|| (batch.as_ref(), Vec::new()))
                    .1
                    .push(row as u64);
            }
            for (relation, batches) in selected {
                let shape = &relations[&relation];
                let batches = batches
                    .into_values()
                    .map(|(batch, rows)| -> Result<_> {
                        scratch.check(journal.writer())?;
                        Ok(arrow_select::take::take_record_batch(
                            batch,
                            &UInt64Array::from(rows),
                        )?)
                    })
                    .collect::<Result<Vec<_>>>()?;
                let batch = arrow_select::concat::concat_batches(
                    &Arc::new(shape.command_schema()),
                    &batches,
                )?;
                scratch.check(journal.writer())?;
                let metadata = shape.properties.metadata();
                let schema = shape
                    .properties
                    .fields()
                    .size()
                    .checked_mul(4)
                    .and_then(|bytes| {
                        bytes.checked_add(
                            metadata
                                .capacity()
                                .checked_mul(4 * (std::mem::size_of::<(String, String)>() + 1))?,
                        )
                    })
                    .and_then(|bytes| {
                        metadata.iter().try_fold(bytes, |bytes, (key, value)| {
                            bytes
                                .checked_add(key.capacity())?
                                .checked_add(value.capacity())
                        })
                    })
                    .and_then(|bytes| bytes.checked_mul(4))
                    .and_then(|bytes| bytes.checked_add(2 * std::mem::size_of::<PreparedRows>()))
                    .ok_or_else(|| {
                        InvalidSnafu {
                            field: "Graph prepared schema memory",
                        }
                        .build()
                    })?;
                scratch.charge(journal.writer(), schema)?;
                let endpoints = declarations[&(journal.writer(), relation)];
                rows.push(PreparedRows::new(
                    journal.writer(),
                    relation,
                    shape,
                    endpoints,
                    batch,
                )?);
            }
        }

        for writer in parents.keys() {
            scratch.check(*writer)?;
        }
        Ok(PreparedLayers {
            parents,
            base,
            rows,
            declarations,
            shapes,
            cuts: cuts.iter().map(|cut| (cut.writer, cut.revision)).collect(),
            _leases: scratch.into_leases(),
        })
    }
}

impl PreparedRows {
    fn new(
        writer: u64,
        relation: u64,
        shape: &Relation,
        endpoints: Endpoints,
        batch: RecordBatch,
    ) -> Result<Self> {
        let properties = batch
            .column_by_name("properties")
            .and_then(|array| array.as_any().downcast_ref::<StructArray>())
            .filter(|array| array.null_count() == 0)
            .ok_or_else(|| {
                InvalidSnafu {
                    field: "Graph final properties",
                }
                .build()
            })?;
        let properties = RecordBatch::try_new(
            Arc::new(shape.properties.clone()),
            properties.columns().to_vec(),
        )?;
        Ok(Self {
            writer,
            relation,
            shape: shape.clone(),
            endpoints,
            properties,
            owners: PendingGraph::keys(&batch, "owner")?,
            keys: PendingGraph::keys(&batch, "key")?,
            edge_keys: endpoints
                .map(|_| -> Result<_> {
                    Ok((
                        PendingGraph::keys(&batch, "from")?,
                        PendingGraph::keys(&batch, "to")?,
                        PendingGraph::keys(&batch, "label")?,
                    ))
                })
                .transpose()?,
        })
    }
}

impl Preparation<'_> {
    pub(super) fn check_journals(
        &self,
        journals: &[&Journal],
        relations: &BTreeMap<u64, Relation>,
        scratch: &mut Scratch<'_>,
    ) -> Result<BTreeMap<(u64, u64), Endpoints>> {
        let mut writers = BTreeSet::new();
        let mut declarations = BTreeMap::new();
        for journal in journals {
            scratch.check(journal.writer())?;
            scratch.charge(
                journal.writer(),
                12 * (std::mem::size_of::<(u64, (u64, u64))>() + std::mem::size_of::<u64>()),
            )?;
            if !self.parents.contains_key(&journal.writer()) || !writers.insert(journal.writer()) {
                return InvalidSnafu {
                    field: "Graph journal writer",
                }
                .fail();
            }
            for staged in journal.batches() {
                scratch.check(journal.writer())?;
                let (relation, batch) = match staged {
                    Staged::Clear { batch, .. } => {
                        if batch.schema().as_ref() != &Relation::clear_schema() {
                            return InvalidSnafu {
                                field: "Graph clear schema",
                            }
                            .fail();
                        }
                        continue;
                    }
                    Staged::Edits {
                        relation, batch, ..
                    } => (*relation, batch),
                };
                let shape = relations.get(&relation).ok_or_else(|| {
                    InvalidSnafu {
                        field: "Graph journal relation",
                    }
                    .build()
                })?;
                if batch.schema().as_ref() != &shape.command_schema() {
                    return InvalidSnafu {
                        field: "Graph journal schema",
                    }
                    .fail();
                }
                Commands::check(batch, shape.kind == EntityKind::Edge)?;
                if let std::collections::btree_map::Entry::Vacant(entry) =
                    declarations.entry((journal.writer(), relation))
                {
                    scratch.charge(
                        journal.writer(),
                        12 * (std::mem::size_of::<((u64, u64), Endpoints)>()
                            + std::mem::size_of::<u64>()),
                    )?;
                    entry.insert(self.check_relation(journal.writer(), relation, shape)?);
                }
            }
        }
        if writers.len() != self.parents.len() {
            return InvalidSnafu {
                field: "Graph journal heads",
            }
            .fail();
        }
        Ok(declarations)
    }

    fn check_relation(&self, writer: u64, relation: u64, shape: &Relation) -> Result<Endpoints> {
        let view = self.views.get(&writer).ok_or_else(|| {
            InvalidSnafu {
                field: "Graph journal writer",
            }
            .build()
        })?;
        if !view.writers.contains(&writer) {
            return InvalidSnafu {
                field: "Graph journal namespace",
            }
            .fail();
        }
        match view.relations.get(&relation) {
            Some((0, None, None)) if shape.kind == EntityKind::Node => Ok(None),
            Some((1, Some(from @ 1..), Some(to @ 1..))) if shape.kind == EntityKind::Edge => {
                if [from, to]
                    .into_iter()
                    .any(|relation| !matches!(view.relations.get(relation), Some((0, None, None))))
                {
                    return InvalidSnafu {
                        field: "Graph journal endpoint declaration",
                    }
                    .fail();
                }
                Ok(Some((*from, *to, view.graph)))
            }
            _ => InvalidSnafu {
                field: "Graph journal namespace",
            }
            .fail(),
        }
    }
}

impl StoredDeclarations<'_> {
    fn check_relation(&self, writer: u64, relation: u64, shape: &Relation) -> Result<Endpoints> {
        let declared: Option<(u8, Option<u64>, Option<u64>, u64)> = self
            .connection
            .query_row(
                "SELECT r.entity_kind,r.from_relation,r.to_relation,r.graph_id
             FROM graph_relations r JOIN graph_writers w ON w.graph_id=r.graph_id
             WHERE w.writer_id=? AND r.relation_id=?",
                params![writer, relation],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .optional()
            .context(DatabaseSnafu {
                operation: "check Graph journal namespace",
            })?;
        match declared {
            Some((0, None, None, 1..)) if shape.kind == EntityKind::Node => Ok(None),
            Some((1, Some(from @ 1..), Some(to @ 1..), graph @ 1..))
                if shape.kind == EntityKind::Edge =>
            {
                let count: u64 = self
                    .connection
                    .query_row(
                        "SELECT count(*) FROM graph_relations WHERE graph_id=? AND entity_kind=0
                     AND relation_id IN (?,?)",
                        params![graph, from, to],
                        |row| row.get(0),
                    )
                    .context(DatabaseSnafu {
                        operation: "check Graph journal endpoint declarations",
                    })?;
                if count != if from == to { 1 } else { 2 } {
                    return InvalidSnafu {
                        field: "Graph journal endpoint declaration",
                    }
                    .fail();
                }
                Ok(Some((from, to, graph)))
            }
            _ => InvalidSnafu {
                field: "Graph journal namespace",
            }
            .fail(),
        }
    }
}
