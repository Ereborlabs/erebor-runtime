use super::*;
use crate::{EntityKind, Journal, Read};
use arrow_array::{ArrayRef, BinaryArray, RecordBatch, StructArray, UInt64Array, UInt8Array};
use arrow_schema::{DataType, Field, Schema};
use snafu::IntoError as _;
use std::sync::Arc;

type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;

struct Fixture {
    graph: Graph,
    db: fjall::SingleWriterTxDatabase,
    branch: fjall::Branch,
    shapes: BTreeMap<u64, Relation>,
    _dir: tempfile::TempDir,
}

impl Fixture {
    fn new() -> std::result::Result<Self, Box<dyn std::error::Error>> {
        let dir = tempfile::tempdir()?;
        let db = fjall::SingleWriterTxDatabase::builder(dir.path())
            .versioned()
            .open()?;
        let branch = db.create_branch("data")?;
        branch.retain_history(branch.info()?.head..)?;
        let graph = Graph::new(71)?;
        let properties = Schema::new(vec![Field::new("number", DataType::UInt64, false)]);
        let shapes = BTreeMap::from([
            (
                11,
                Relation {
                    kind: EntityKind::Node,
                    properties: properties.clone(),
                },
            ),
            (
                12,
                Relation {
                    kind: EntityKind::Node,
                    properties: properties.clone(),
                },
            ),
            (
                13,
                Relation {
                    kind: EntityKind::Edge,
                    properties,
                },
            ),
        ]);
        let mut tx = branch.write_tx()?;
        graph.install(
            &mut tx,
            &[17, 19],
            &shapes
                .iter()
                .map(|(relation, shape)| Declaration {
                    relation: *relation,
                    shape: shape.clone(),
                    endpoints: (*relation == 13).then_some((11, 12)),
                })
                .collect::<Vec<_>>(),
        )?;
        tx.commit()?;
        Ok(Self {
            graph,
            db,
            branch,
            shapes,
            _dir: dir,
        })
    }

    fn view(&self) -> Result<View> {
        self.graph.view(
            self.branch.snapshot().map_err(|source| {
                NativeSnafu {
                    operation: "test snapshot",
                }
                .into_error(source)
            })?,
            BTreeMap::new(),
            &|_, _, _| Ok(None),
        )
    }

    fn commands(
        &self,
        relation: u64,
        owner: &[u8],
        keys: &[&[u8]],
        operation: u8,
    ) -> Result<RecordBatch> {
        let mut columns: Vec<ArrayRef> = vec![
            Arc::new(BinaryArray::from_iter_values(keys.iter().map(|_| owner))),
            Arc::new(BinaryArray::from_iter_values(keys.iter().copied())),
            Arc::new(UInt8Array::from_iter_values(keys.iter().map(|_| operation))),
        ];
        if relation == 13 {
            for key in [b"source".as_slice(), b"target", b"label"] {
                columns.push(Arc::new(BinaryArray::from_iter_values(
                    keys.iter().map(|_| key),
                )));
            }
        }
        columns.push(Arc::new(StructArray::new(
            self.shapes[&relation].properties.fields().clone(),
            vec![Arc::new(UInt64Array::from_iter_values(
                keys.iter().map(|_| 42),
            ))],
            None,
        )));
        Ok(RecordBatch::try_new(
            Arc::new(self.shapes[&relation].command_schema()),
            columns,
        )?)
    }

    fn edit(
        &self,
        view: &View,
        journal: &mut Journal,
        relation: u64,
        owner: &[u8],
        keys: &[&[u8]],
        operation: u8,
    ) -> Result<()> {
        let commands = self.commands(relation, owner, keys, operation)?;
        let present = view.presence(journal.writer(), relation, &commands, &|_, _, _| Ok(None))?;
        let stage = journal.prepare(relation, &self.shapes[&relation], commands, &present)?;
        journal.publish(stage)
    }

    fn stage(
        &self,
        view: &View,
        journals: &[&Journal],
        revision: u64,
        commit: bool,
    ) -> std::result::Result<Option<fjall::Commit>, Box<dyn std::error::Error>> {
        let prepared = view.prepare(journals, &|_, _, _| Ok(None))?;
        let requests = journals
            .iter()
            .map(|journal| {
                Ok(LayerRequest {
                    writer: journal.writer(),
                    layer: revision * 100 + journal.writer(),
                    parent: view.head(journal.writer())?,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let mut tx = self.branch.write_tx()?;
        let pending = self
            .graph
            .stage(&mut tx, revision, &requests, prepared, &|_, _, _| Ok(None))?;
        tx.insert(b"state", revision.to_be_bytes());
        tx.insert(b"progress", revision.to_be_bytes());
        if commit {
            Ok(tx.commit_stamped(pending.stamps)?)
        } else {
            tx.rollback();
            Ok(None)
        }
    }

    fn keys(keys: &[&[u8]]) -> Result<RecordBatch> {
        Ok(RecordBatch::try_new(
            Arc::new(Relation::key_schema()),
            vec![Arc::new(BinaryArray::from_iter_values(
                keys.iter().copied(),
            ))],
        )?)
    }

    fn count(view: &View, relation: u64, read: Read, keys: &[&[u8]]) -> Result<usize> {
        let input = if matches!(read, Read::Owned(_)) {
            RecordBatch::new_empty(Arc::new(Schema::empty()))
        } else {
            Self::keys(keys)?
        };
        let mut count = 0;
        view.visit(relation, read, &input, &|_, _, _| Ok(None), |_| {
            count += 1;
            Ok(())
        })?;
        Ok(count)
    }
}

#[test]
fn native_delta_history_and_rollback() -> TestResult {
    let fixture = Fixture::new()?;
    let empty = fixture.view()?;
    let mut journal = Journal::new(17)?;
    fixture.edit(&empty, &mut journal, 11, b"owner", &[b"source"], 0)?;
    fixture.edit(&empty, &mut journal, 12, b"owner", &[b"target"], 0)?;
    fixture.edit(&empty, &mut journal, 13, b"owner", &[b"edge"], 0)?;
    fixture.stage(&empty, &[&journal], 100, false)?;
    assert_eq!(
        Fixture::count(&fixture.view()?, 11, Read::Nodes, &[b"source"])?,
        0
    );
    assert!(fixture.branch.snapshot()?.get(b"progress")?.is_none());
    let first = fixture
        .stage(&empty, &[&journal], 100, true)?
        .ok_or("missing commit")?;
    let current = fixture.view()?;
    assert_eq!(
        Fixture::count(&current, 13, Read::Outgoing, &[b"source"])?,
        1
    );
    assert_eq!(
        Fixture::count(&current, 13, Read::Incoming, &[b"target"])?,
        1
    );
    assert_eq!(
        Fixture::count(
            &current,
            13,
            Read::Neighbors,
            &[b"source", b"target", b"source"]
        )?,
        1
    );
    assert_eq!(Fixture::count(&empty, 13, Read::Owned(17), &[])?, 0);
    let mut remove = Journal::new(17)?;
    remove.publish(remove.prepare_clear(RecordBatch::try_new(
        Arc::new(Relation::clear_schema()),
        vec![Arc::new(BinaryArray::from(vec![Some(b"owner".as_slice())]))],
    )?)?)?;
    fixture.stage(&current, &[&remove], 101, true)?;
    assert_eq!(
        Fixture::count(&fixture.view()?, 13, Read::Owned(17), &[])?,
        0
    );
    assert_eq!(Fixture::count(&current, 13, Read::Owned(17), &[])?, 1);
    fixture.db.inner().flush_memtables()?;
    let old = fixture.graph.view(
        fixture.branch.read_at(first.revision)?,
        BTreeMap::new(),
        &|_, _, _| Ok(None),
    )?;
    assert_eq!(Fixture::count(&old, 13, Read::Owned(17), &[])?, 1);
    assert_eq!(
        fixture.branch.snapshot()?.get(b"progress")?.as_deref(),
        Some(101u64.to_be_bytes().as_slice())
    );
    assert_eq!(
        fixture
            .branch
            .read_at(first.revision)?
            .get(Key::record(b'q', &[10017]))?
            .as_deref(),
        Some(first.revision.to_bytes().as_slice())
    );
    Ok(())
}

#[test]
fn point_members_preserve_selected_history_and_leases() -> TestResult {
    use std::sync::atomic::{AtomicUsize, Ordering};
    struct Charge(Arc<AtomicUsize>, usize);
    impl Drop for Charge {
        fn drop(&mut self) {
            self.0.fetch_sub(self.1, Ordering::AcqRel);
        }
    }
    let fixture = Fixture::new()?;
    let empty = fixture.view()?;
    let mut journal = Journal::new(17)?;
    fixture.edit(&empty, &mut journal, 11, b"owner", &[b"source"], 0)?;
    fixture.edit(&empty, &mut journal, 12, b"owner", &[b"target"], 0)?;
    fixture.edit(&empty, &mut journal, 13, b"owner", &[b"edge"], 0)?;
    let first = fixture
        .stage(&empty, &[&journal], 100, true)?
        .ok_or("commit")?;
    let current = fixture.view()?;
    for (relation, key) in [(11, b"source".as_slice()), (13, b"edge")] {
        let point = current
            .member(17, relation, b"owner", key, &|_, _, _| Ok(None))?
            .ok_or("point")?;
        let mut visited = None;
        current.visit(
            relation,
            Read::Owned(17),
            &RecordBatch::new_empty(Arc::new(Schema::empty())),
            &|_, _, _| Ok(None),
            |row| {
                visited = Some(row);
                Ok(())
            },
        )?;
        let visited = visited.ok_or("visited")?;
        assert_eq!(
            (
                point.writer,
                point.relation,
                &point.owner,
                &point.key,
                &point.endpoints,
                point.property,
                point.revision,
                point.row
            ),
            (
                visited.writer,
                visited.relation,
                &visited.owner,
                &visited.key,
                &visited.endpoints,
                visited.property,
                visited.revision,
                visited.row
            )
        );
        assert_eq!(point.properties(), visited.properties());
    }
    assert!(current
        .member(0, 11, b"owner", b"source", &|_, _, _| Ok(None))
        .is_err());
    assert!(current
        .member(17, 999, b"owner", b"source", &|_, _, _| Ok(None))
        .is_err());
    assert!(current
        .member(999, 11, b"owner", b"source", &|_, _, _| Ok(None))?
        .is_none());
    assert!(current
        .member(17, 11, b"missing", b"source", &|_, _, _| Ok(None))?
        .is_none());
    let mut remove = Journal::new(17)?;
    remove.publish(remove.prepare_clear(RecordBatch::try_new(
        Arc::new(Relation::clear_schema()),
        vec![Arc::new(BinaryArray::from_iter_values([
            b"owner".as_slice(),
        ]))],
    )?)?)?;
    fixture.stage(&current, &[&remove], 101, true)?;
    let latest = fixture.view()?;
    assert!(latest.member_key(17, 13, b"owner", b"edge")?.is_some());
    assert!(latest
        .member(17, 13, b"owner", b"edge", &|_, _, _| Ok(None))?
        .is_none());
    fixture.db.inner().flush_memtables()?;
    fixture.db.inner().major_compact()?;
    let held = Arc::new(AtomicUsize::new(0));
    let reserve = |_, bytes, _| -> Result<Option<Lease>> {
        held.fetch_add(bytes, Ordering::AcqRel);
        Ok(Some(Box::new(Charge(Arc::clone(&held), bytes))))
    };
    let selected = fixture.graph.view(
        fixture.branch.snapshot()?,
        BTreeMap::from([(17, fixture.branch.read_at(first.revision)?)]),
        &reserve,
    )?;
    let point = selected
        .member(17, 13, b"owner", b"edge", &reserve)?
        .ok_or("historical point")?;
    assert_eq!(point.revision, 100);
    drop(selected);
    assert!(held.load(Ordering::Acquire) > 0);
    assert_eq!(
        point
            .properties()
            .column(0)
            .as_any()
            .downcast_ref::<UInt64Array>()
            .ok_or("properties")?
            .value(point.row),
        42
    );
    drop(point);
    assert_eq!(held.load(Ordering::Acquire), 0);
    Ok(())
}

#[test]
fn point_missing_members_do_not_hide_invalid_indexes() -> TestResult {
    for remove in [true, false] {
        let fixture = Fixture::new()?;
        let empty = fixture.view()?;
        let mut journal = Journal::new(17)?;
        fixture.edit(&empty, &mut journal, 11, b"owner", &[b"source"], 0)?;
        fixture.stage(&empty, &[&journal], 100, true)?;
        let key = fixture
            .view()?
            .member_key(17, 11, b"owner", b"source")?
            .ok_or("member key")?;
        let mut tx = fixture.branch.write_tx()?;
        if remove {
            tx.remove(key);
        } else {
            tx.insert(key, [255]);
        }
        tx.commit()?;
        let view = fixture.view()?;
        let point = view.member(17, 11, b"owner", b"source", &|_, _, _| Ok(None));
        if remove {
            assert!(point?.is_none());
        } else {
            assert!(point.is_err());
        }
        assert!(Fixture::count(&view, 11, Read::Owned(17), &[]).is_err());
    }
    Ok(())
}

#[test]
fn shared_endpoints_and_full_delta() -> TestResult {
    let fixture = Fixture::new()?;
    let empty = fixture.view()?;
    let mut first = Journal::new(17)?;
    for (relation, key) in [(11, b"source".as_slice()), (12, b"target")] {
        fixture.edit(&empty, &mut first, relation, b"owner", &[key], 0)?;
    }
    fixture.edit(&empty, &mut first, 13, b"owner", &[b"edge"], 0)?;
    let mut shared = Journal::new(19)?;
    fixture.edit(&empty, &mut shared, 11, b"other", &[b"source"], 0)?;
    fixture.stage(&empty, &[&first, &shared], 100, true)?;
    let current = fixture.view()?;
    let mut remove = Journal::new(17)?;
    fixture.edit(&current, &mut remove, 11, b"owner", &[b"source"], 2)?;
    fixture.stage(&current, &[&remove], 101, true)?;
    let current = fixture.view()?;
    let mut last = Journal::new(19)?;
    fixture.edit(&current, &mut last, 11, b"other", &[b"source"], 2)?;
    assert!(fixture.stage(&current, &[&last], 102, true).is_err());
    assert_eq!(
        Fixture::count(&fixture.view()?, 11, Read::Nodes, &[b"source"])?,
        1
    );
    let mut edge = Journal::new(17)?;
    fixture.edit(&current, &mut edge, 13, b"owner", &[b"edge"], 2)?;
    fixture.stage(&current, &[&last, &edge], 102, true)?;
    assert_eq!(
        Fixture::count(&fixture.view()?, 11, Read::Nodes, &[b"source"])?,
        0
    );
    Ok(())
}

#[test]
fn old_writer_selection_and_conflict() -> TestResult {
    let fixture = Fixture::new()?;
    let empty = fixture.view()?;
    let mut journal = Journal::new(17)?;
    fixture.edit(&empty, &mut journal, 11, b"owner", &[b"old"], 0)?;
    let first = fixture
        .stage(&empty, &[&journal], 100, true)?
        .ok_or("missing first commit")?;
    let old = fixture.view()?;
    let mut next = Journal::new(17)?;
    fixture.edit(&old, &mut next, 11, b"owner", &[b"old"], 2)?;
    fixture.edit(&old, &mut next, 11, b"owner", &[b"new"], 0)?;
    fixture.stage(&old, &[&next], 101, true)?;
    assert!(fixture.stage(&old, &[&next], 102, true).is_err());
    let selected = fixture.graph.view(
        fixture.branch.snapshot()?,
        BTreeMap::from([(17, fixture.branch.read_at(first.revision)?)]),
        &|_, _, _| Ok(None),
    )?;
    assert_eq!(Fixture::count(&selected, 11, Read::Nodes, &[b"old"])?, 1);
    assert_eq!(Fixture::count(&selected, 11, Read::Nodes, &[b"new"])?, 0);
    Ok(())
}

#[test]
fn dictionary_width_scope_and_corruption() -> TestResult {
    use crate::scratch::Scratch;
    use record::Dictionary;
    let fixture = Fixture::new()?;
    let mut tx = fixture.branch.write_tx()?;
    let mut memory = Scratch::new(&|_, _, _| Ok(None));
    let long = vec![173; 2 * u16::MAX as usize];
    let id = Dictionary::intern(&mut tx, 1, 11, &long, 17, &mut memory)?;
    let empty = Dictionary::intern(&mut tx, 1, 11, b"", 17, &mut memory)?;
    let other = Dictionary::intern(&mut tx, 1, 12, &long, 17, &mut memory)?;
    assert_ne!(id, other);
    tx.commit()?;
    let view = fixture.branch.snapshot()?;
    assert_eq!(Dictionary::find(&view, 1, 11, &long)?, Some(id));
    assert_eq!(
        Dictionary::resolve(&view, 1, 11, id, 17, &mut memory)?,
        long
    );
    assert_eq!(
        Dictionary::resolve(&view, 1, 11, empty, 17, &mut memory)?,
        b""
    );
    assert!(Dictionary::resolve(&view, 1, 12, id, 17, &mut memory).is_err());
    let mut tx = fixture.branch.write_tx()?;
    tx.remove(Key::record(b'V', &[id]));
    tx.commit()?;
    assert!(Dictionary::resolve(&fixture.branch.snapshot()?, 1, 11, id, 17, &mut memory).is_err());
    assert!(Dictionary::find(&fixture.branch.snapshot()?, 1, 11, &long).is_err());
    Ok(())
}

#[test]
fn ordered_reads_keep_memory_leases() -> TestResult {
    use std::sync::atomic::{AtomicUsize, Ordering};
    struct Charge(Arc<AtomicUsize>, usize);
    impl Drop for Charge {
        fn drop(&mut self) {
            self.0.fetch_sub(self.1, Ordering::SeqCst);
        }
    }
    let fixture = Fixture::new()?;
    let empty = fixture.view()?;
    let mut journal = Journal::new(17)?;
    fixture.edit(&empty, &mut journal, 11, b"z-owner", &[b"z", b"a"], 0)?;
    fixture.edit(&empty, &mut journal, 11, b"a-owner", &[b"z", b"a"], 0)?;
    fixture.stage(&empty, &[&journal], 100, true)?;
    let held = Arc::new(AtomicUsize::new(0));
    let reserve = |_, bytes, _| -> Result<Option<Lease>> {
        held.fetch_add(bytes, Ordering::SeqCst);
        Ok(Some(Box::new(Charge(Arc::clone(&held), bytes))))
    };
    let view = fixture
        .graph
        .view(fixture.branch.snapshot()?, BTreeMap::new(), &reserve)?;
    let mut output = Vec::new();
    view.read(
        11,
        Read::Nodes,
        &Fixture::keys(&[b"z", b"a", b"z"])?,
        &reserve,
        |batch| {
            output.push(batch);
            Ok(())
        },
    )?;
    let mut actual = Vec::new();
    for output in &output {
        let owners = View::binary(output.batch(), "owner")?;
        let keys = View::binary(output.batch(), "key")?;
        for row in 0..output.batch().num_rows() {
            actual.push((owners.value(row).to_vec(), keys.value(row).to_vec()));
        }
        assert!(output.origins().iter().all(|origin| *origin
            == crate::ReadOrigin {
                writer: 17,
                revision: 100
            }));
    }
    assert_eq!(
        actual,
        vec![
            (b"a-owner".to_vec(), b"a".to_vec()),
            (b"a-owner".to_vec(), b"z".to_vec()),
            (b"z-owner".to_vec(), b"a".to_vec()),
            (b"z-owner".to_vec(), b"z".to_vec())
        ]
    );
    let mut properties = Vec::new();
    view.visit_properties(11, &reserve, |batch| {
        properties.push(batch);
        Ok(())
    })?;
    assert_eq!(
        properties
            .iter()
            .map(|batch| batch.batch().num_rows())
            .sum::<usize>(),
        4
    );
    drop(view);
    assert!(held.load(Ordering::SeqCst) > 0);
    assert_eq!(
        output
            .iter()
            .map(|batch| batch.batch().num_rows())
            .sum::<usize>(),
        4
    );
    drop(output);
    assert!(held.load(Ordering::SeqCst) > 0);
    drop(properties);
    assert_eq!(held.load(Ordering::SeqCst), 0);
    Ok(())
}

#[test]
fn duplicate_layers_and_fork_isolation() -> TestResult {
    let fixture = Fixture::new()?;
    let empty = fixture.view()?;
    let mut one = Journal::new(17)?;
    let mut two = Journal::new(19)?;
    fixture.edit(&empty, &mut one, 11, b"owner", &[b"main"], 0)?;
    fixture.edit(&empty, &mut two, 11, b"owner", &[b"second"], 0)?;
    let prepared = empty.prepare(&[&one, &two], &|_, _, _| Ok(None))?;
    let mut tx = fixture.branch.write_tx()?;
    assert!(fixture
        .graph
        .stage(
            &mut tx,
            100,
            &[
                LayerRequest {
                    writer: 17,
                    layer: 5,
                    parent: None
                },
                LayerRequest {
                    writer: 19,
                    layer: 5,
                    parent: None
                }
            ],
            prepared,
            &|_, _, _| Ok(None)
        )
        .is_err());
    tx.rollback();
    let committed = fixture
        .stage(&empty, &[&one, &two], 100, true)?
        .ok_or("missing commit")?;
    let child = fixture.branch.fork("child", committed.revision)?;
    child.retain_history(child.info()?.head..)?;
    let view = fixture
        .graph
        .view(child.snapshot()?, BTreeMap::new(), &|_, _, _| Ok(None))?;
    let mut journal = Journal::new(17)?;
    fixture.edit(&view, &mut journal, 11, b"owner", &[b"main"], 2)?;
    fixture.edit(&view, &mut journal, 11, b"owner", &[b"child"], 0)?;
    let prepared = view.prepare(&[&journal], &|_, _, _| Ok(None))?;
    let mut tx = child.write_tx()?;
    let pending = fixture.graph.stage(
        &mut tx,
        101,
        &[LayerRequest {
            writer: 17,
            layer: 10117,
            parent: view.head(17)?,
        }],
        prepared,
        &|_, _, _| Ok(None),
    )?;
    tx.commit_stamped(pending.stamps)?;
    let child = fixture
        .graph
        .view(child.snapshot()?, BTreeMap::new(), &|_, _, _| Ok(None))?;
    assert_eq!(Fixture::count(&child, 11, Read::Nodes, &[b"main"])?, 0);
    assert_eq!(Fixture::count(&child, 11, Read::Nodes, &[b"child"])?, 1);
    assert_eq!(
        Fixture::count(&fixture.view()?, 11, Read::Nodes, &[b"main"])?,
        1
    );
    assert_eq!(
        Fixture::count(&fixture.view()?, 11, Read::Nodes, &[b"child"])?,
        0
    );
    Ok(())
}

#[test]
fn installation_checks_are_read_only_and_exact() -> TestResult {
    let records = [
        (b'f', vec![11]),
        (b'f', vec![12]),
        (b'f', vec![13]),
        (b'g', vec![71, 11]),
        (b'g', vec![71, 12]),
        (b'g', vec![71, 13]),
        (b'w', vec![17]),
        (b'w', vec![19]),
        (b'v', vec![71, 17]),
        (b'v', vec![71, 19]),
        (b'g', vec![71, 999]),
        (b'v', vec![71, 999]),
    ];
    for (kind, fields) in records {
        for remove in [true, false] {
            if remove && fields.last() == Some(&999) {
                continue;
            }
            let fixture = Fixture::new()?;
            let declarations = fixture
                .shapes
                .iter()
                .map(|(id, shape)| Declaration {
                    relation: *id,
                    shape: shape.clone(),
                    endpoints: (*id == 13).then_some((11, 12)),
                })
                .collect::<Vec<_>>();
            let before = fixture.branch.snapshot()?;
            fixture
                .graph
                .check_installation(&before, &[17, 19], &declarations)?;
            let mut tx = fixture.branch.write_tx()?;
            let key = Key::record(kind, &fields);
            if remove {
                tx.remove(key);
            } else {
                tx.insert(key, 999u64.to_be_bytes());
            }
            tx.commit()?;
            let cursor = fixture.db.inner().journal_head()?;
            assert!(fixture
                .graph
                .check_installation(&fixture.branch.snapshot()?, &[17, 19], &declarations)
                .is_err());
            assert_eq!(fixture.db.inner().journal_head()?, cursor);
            fixture
                .graph
                .check_installation(&before, &[17, 19], &declarations)?;
        }
    }
    Ok(())
}
