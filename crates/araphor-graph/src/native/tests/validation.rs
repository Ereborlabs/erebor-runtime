use super::super::record::{Dictionary, Fragment, Head, Properties, StoredMember};
use super::*;

#[test]
fn snapshot_validation_keeps_closed_properties_and_unused_dictionary_history() -> TestResult {
    let fixture = Fixture::new()?;
    Graph::validate(&fixture.branch.snapshot()?, &|_, _, _| Ok(None))?;
    let empty = fixture.view()?;
    let mut journal = Journal::new(17)?;
    for (relation, key) in [(11, b"source".as_slice()), (12, b"target"), (13, b"edge")] {
        fixture.edit(&empty, &mut journal, relation, b"owner", &[key], 0)?;
    }
    let first = fixture
        .stage(&empty, &[&journal], 100, true)?
        .ok_or("first commit")?;
    assert_eq!(
        Graph::layers(&fixture.branch.snapshot()?).collect::<Result<Vec<_>>>()?,
        vec![(17, 10017, None, 100)]
    );
    Graph::validate(&fixture.branch.snapshot()?, &|_, _, _| Ok(None))?;
    let current = fixture.view()?;
    let mut clear = Journal::new(17)?;
    clear.publish(clear.prepare_clear(RecordBatch::try_new(
        Arc::new(Relation::clear_schema()),
        vec![Arc::new(BinaryArray::from(vec![None::<&[u8]>]))],
    )?)?)?;
    fixture.stage(&current, &[&clear], 101, true)?;
    let mut tx = fixture.branch.write_tx()?;
    let mut memory = crate::scratch::Scratch::new(&|_, _, _| Ok(None));
    Dictionary::intern(&mut tx, 1, 11, b"", 17, &mut memory)?;
    Dictionary::intern(
        &mut tx,
        1,
        11,
        &vec![91; 2 * u16::MAX as usize],
        17,
        &mut memory,
    )?;
    tx.commit()?;
    Graph::validate(&fixture.branch.snapshot()?, &|_, _, _| Ok(None))?;
    Graph::validate(&fixture.branch.read_at(first.revision)?, &|_, _, _| {
        Ok(None)
    })?;
    fixture.db.inner().flush_memtables()?;
    fixture.db.inner().major_compact()?;
    Graph::validate(&fixture.branch.snapshot()?, &|_, _, _| Ok(None))?;
    assert!(
        Graph::validate(&fixture.branch.snapshot()?, &|_, _, _| Err(InvalidSnafu {
            field: "cancelled"
        }
        .build()))
        .is_err()
    );
    Ok(())
}

#[test]
fn snapshot_validation_accepts_empty_properties_and_self_loop_indexes() -> TestResult {
    let mut fixture = Fixture::new()?;
    let edge = fixture.shapes[&13].clone();
    let empty = Relation {
        kind: EntityKind::Node,
        properties: Schema::empty(),
    };
    fixture.shapes.insert(14, edge.clone());
    fixture.shapes.insert(15, empty.clone());
    let mut tx = fixture.branch.write_tx()?;
    fixture.graph.install(
        &mut tx,
        &[17],
        &[
            Declaration {
                relation: 14,
                shape: edge,
                endpoints: Some((11, 11)),
            },
            Declaration {
                relation: 15,
                shape: empty.clone(),
                endpoints: None,
            },
        ],
    )?;
    tx.commit()?;
    let view = fixture.view()?;
    let mut journal = Journal::new(17)?;
    fixture.edit(&view, &mut journal, 11, b"owner", &[b"source"], 0)?;
    let mut batch = fixture.commands(14, b"owner", &[b"loop"], 0)?;
    let mut columns = batch.columns().to_vec();
    columns[4] = Arc::clone(&columns[3]);
    batch = RecordBatch::try_new(batch.schema(), columns)?;
    let present = view.presence(17, 14, &batch, &|_, _, _| Ok(None))?;
    journal.publish(journal.prepare(14, &fixture.shapes[&14], batch, &present)?)?;
    let batch = RecordBatch::try_new(
        Arc::new(empty.command_schema()),
        vec![
            Arc::new(BinaryArray::from_iter_values([b"owner".as_slice()])),
            Arc::new(BinaryArray::from_iter_values([b"empty".as_slice()])),
            Arc::new(UInt8Array::from(vec![0])),
            Arc::new(StructArray::new_empty_fields(1, None)),
        ],
    )?;
    let present = view.presence(17, 15, &batch, &|_, _, _| Ok(None))?;
    journal.publish(journal.prepare(15, &empty, batch, &present)?)?;
    fixture.stage(&view, &[&journal], 100, true)?;
    Graph::validate(&fixture.branch.snapshot()?, &|_, _, _| Ok(None))?;
    Ok(())
}

#[test]
fn snapshot_validation_rejects_corrupt_native_owners_and_indexes() -> TestResult {
    let fixture = Fixture::new()?;
    let empty = fixture.view()?;
    let mut journal = Journal::new(17)?;
    for (relation, key) in [(11, b"source".as_slice()), (12, b"target"), (13, b"edge")] {
        fixture.edit(&empty, &mut journal, relation, b"owner", &[key], 0)?;
    }
    fixture.stage(&empty, &[&journal], 100, true)?;
    let current = fixture.view()?;
    let mut update = Journal::new(17)?;
    fixture.edit(&current, &mut update, 11, b"owner", &[b"source"], 1)?;
    let committed = fixture
        .stage(&current, &[&update], 101, true)?
        .ok_or("second commit")?;
    let snapshot = fixture.branch.snapshot()?;
    let mut edge = None;
    for entry in snapshot.prefix(Key::record(b'M', &[17])) {
        let (_, value) = entry?;
        let member: StoredMember = Key::decode(&value)?;
        if member.endpoints.is_some() {
            edge = Some(member);
            break;
        }
    }
    let edge = edge.ok_or("edge member")?;
    let cases = [
        "layer-parent",
        "layer-identity",
        "short-layer-key",
        "head",
        "layer-cut",
        "member-key",
        "member-opening",
        "dictionary-link",
        "dictionary-short-parent",
        "property-reference",
        "property-tuple",
        "property-schema",
        "property-fragment",
        "extra-fragment",
        "allocator",
        "unknown-key",
        "short-key",
        "missing-R",
        "missing-K",
        "missing-O",
        "missing-I",
        "missing-E",
        "extra-R",
        "extra-K",
        "extra-O",
        "extra-I",
        "extra-E",
    ];
    for case in cases {
        let child = fixture.branch.fork(case, committed.revision)?;
        let mut tx = child.write_tx()?;
        match case {
            "layer-identity" => {
                let (writer, mut head): (u64, Head) =
                    Key::decode(&tx.get(Key::record(b'l', &[10117]))?.ok_or("layer")?)?;
                head.layer += 1;
                tx.insert(Key::record(b'l', &[10117]), Key::encode(&(writer, head))?);
            }
            "short-layer-key" => tx.insert(b"\0graph/l", b"bad"),
            "layer-parent" => {
                let (writer, mut head): (u64, Head) =
                    Key::decode(&tx.get(Key::record(b'l', &[10117]))?.ok_or("layer")?)?;
                head.parent = None;
                tx.insert(Key::record(b'l', &[10117]), Key::encode(&(writer, head))?);
            }
            "head" => {
                let mut head: Head =
                    Key::decode(&tx.get(Key::record(b'h', &[17]))?.ok_or("head")?)?;
                head.revision += 1;
                tx.insert(Key::record(b'h', &[17]), Key::encode(&head)?);
            }
            "layer-cut" => tx.remove(Key::record(b'q', &[10117])),
            "member-key" => tx.insert(
                Key::record(b'M', &[17, edge.owner, 13, edge.entity + 1]),
                Key::encode(&edge)?,
            ),
            "member-opening" => {
                let mut bad = edge.clone();
                bad.revision = 1;
                tx.insert(edge.key(), Key::encode(&bad)?);
            }
            "dictionary-link" => tx.remove(Key::record(b'V', &[edge.owner])),
            "dictionary-short-parent" => {
                let parent = edge.owner;
                let id = Key::allocate(&mut tx)?;
                let fragment = Fragment {
                    kind: 0,
                    scope: 17,
                    parent,
                    bytes: vec![9],
                };
                tx.insert(
                    Dictionary::key(0, 17, parent, &fragment.bytes),
                    id.to_be_bytes(),
                );
                tx.insert(Key::record(b'V', &[id]), Key::encode(&fragment)?);
            }
            "property-reference" => tx.remove(Key::record(b'L', &[13, 17, edge.property])),
            "property-tuple" => tx.insert(
                Key::record(b'L', &[13, 17, edge.property]),
                Key::encode(&(edge.chunk, usize::MAX, 100u64))?,
            ),
            "property-schema" => {
                let batch = RecordBatch::try_new(
                    Arc::new(Schema::new(vec![Field::new(
                        "other",
                        DataType::UInt64,
                        false,
                    )])),
                    vec![Arc::new(UInt64Array::from(vec![1]))],
                )?;
                Properties::stage(&mut tx, edge.chunk, &Properties::encode(&batch)?);
            }
            "property-fragment" => tx.remove(Key::record(b'P', &[edge.chunk, 0])),
            "extra-fragment" => tx.insert(Key::record(b'P', &[edge.chunk, 1]), b"extra"),
            "allocator" => tx.insert(b"\0graph/next", 1u64.to_be_bytes()),
            "unknown-key" => tx.insert(b"\0graph/unknown", b"bad"),
            "short-key" => tx.insert(b"\0graph/M", b"bad"),
            _ => {
                let kind = *case.as_bytes().last().ok_or("index kind")?;
                let key = edge
                    .indexes(71, Some((11, 12)))
                    .into_iter()
                    .find(|key| key[7] == kind)
                    .ok_or("index")?;
                if case.starts_with("missing") {
                    tx.remove(key);
                } else {
                    let mut extra = key;
                    let last = extra.len() - 8;
                    let id = Key::number(&extra[last..])?;
                    extra[last..].copy_from_slice(&(id + 1).to_be_bytes());
                    tx.insert(extra, edge.key());
                }
            }
        }
        tx.commit()?;
        if matches!(case, "layer-identity" | "short-layer-key") {
            assert!(Graph::layers(&child.snapshot()?)
                .collect::<Result<Vec<_>>>()
                .is_err());
        }
        assert!(
            Graph::validate(&child.snapshot()?, &|_, _, _| Ok(None)).is_err(),
            "{case}"
        );
    }
    Graph::validate(&fixture.branch.snapshot()?, &|_, _, _| Ok(None))?;
    Ok(())
}
