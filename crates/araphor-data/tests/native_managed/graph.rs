use super::*;
use araphor_data::{analysis::native::ManagedGraphTransaction, ManagedBudget};
use sdk::arrow_array::{ArrayRef, BinaryArray, StructArray, UInt64Array, UInt8Array};

pub(super) struct Budget;
impl ManagedBudget for Budget {
    fn limit(&self) -> usize {
        usize::MAX
    }
    fn check(&self) -> araphor_data::Result<()> {
        Ok(())
    }
    fn reserve(&self, _: usize) -> araphor_data::Result<Box<dyn std::any::Any + Send + Sync>> {
        Ok(Box::new(()))
    }
}

pub(super) fn fixture(
    store: &NativeStore,
) -> Result<(ManagedInstance, sdk::Model), Box<dyn std::error::Error>> {
    let mut fixture = Fixture::new(store, [1; 16], "native-journals", true)?;
    let mut dependent = fixture.spec.manifest.calls[&10].clone();
    dependent.dependencies.insert(10);
    fixture.spec.manifest.calls.insert(20, dependent);
    let sql = r#"WITH first AS (SELECT * FROM "managed-graph"."1".count()) SELECT * FROM "managed-graph"."1".count()"#.to_owned();
    fixture.spec.definition = ResolvedDefinition::new(
        Definition {
            name: "native-journals".into(),
            description: String::new(),
            labels: BTreeMap::new(),
            program: Program::Sql {
                source: Source::Inline {
                    inline: sql.clone(),
                },
            },
        },
        sql,
        vec![fixture.spec.manifest.calls[&10].image.clone()],
    )?;
    fixture.spec.manifest.definition =
        store.admit_definition([1; 16], &fixture.spec.definition, || Ok(()))?;
    let admitted = fixture.admit(store)?;
    let instance =
        store.set_managed_running([1; 16], &admitted.spec.id, admitted.lifecycle, true, || {
            Ok(())
        })?;
    let reference = &instance.spec.manifest.calls[&10].package;
    let row = store
        .view()?
        .package_revision(
            [1; 16],
            &reference.package_id,
            &reference.revision,
            &AnalysisReadControl::default(),
        )?
        .ok_or("package")?;
    let descriptor: sdk::Package = serde_json::from_slice(&row.descriptor)?;
    Ok((instance, descriptor.exports[0].clone()))
}

#[test]
fn contract_reads_metadata() -> TestResult {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("data");
    let store = NativeStore::open(&root)?;
    let (instance, model) = fixture(&store)?;
    let page = super::attempts::capture(&store, &instance, false)?;
    let attempt = Arc::new(store.register_managed_attempt(
        &page.state,
        &super::attempts::request("header", false),
        || Ok(()),
    )?);
    let call = &instance.spec.manifest.calls[&10];
    let held = store.view()?;
    let row = held
        .package_revision(
            [1; 16],
            &call.package.package_id,
            &call.package.revision,
            &AnalysisReadControl::default(),
        )?
        .ok_or("package")?;
    let prefix = b"\0data/@package-body/";
    let bodies = held
        .snapshot()
        .prefix(prefix)
        .collect::<Result<Vec<_>, _>>()?;
    assert_eq!(bodies.len(), 1);
    let (key, bytes) = &bodies[0];
    assert_eq!(bytes[0], 0);
    assert_eq!(&bytes[1..], row.artifact.as_slice());
    let journals = super::publication::journals(&store, &attempt, &model, false)?;
    let mut tx = store.write()?;
    tx.native().remove(key.clone());
    tx.commit([])?;
    let changed = store.view()?;
    let producer = ManagedGraphTransaction::new(
        &store,
        Arc::clone(&attempt),
        10,
        &model,
        Vec::new(),
        Arc::new(Budget),
        &AnalysisReadControl::default(),
    )?;
    assert_eq!(
        producer.spec(),
        model.graph.as_ref().ok_or("Graph contract")?
    );
    assert_eq!(read_nodes(&producer, &store)?.data.rows(), 0);
    let before = store.meta()?;
    let head = store.database().inner().journal_head()?;
    let error = super::publication::publish(&store, &attempt, &model, &journals, true)
        .err()
        .ok_or("publication guard did not run")?;
    assert!(
        matches!(
            error.downcast_ref::<araphor_data::Error>(),
            Some(araphor_data::Error::Package {
                code: Code::Denied,
                field: "guard",
                ..
            })
        ),
        "{error}"
    );
    assert_eq!(store.meta()?, before);
    assert_eq!(store.database().inner().journal_head()?, head);
    assert!(changed
        .package_revision(
            [1; 16],
            &call.package.package_id,
            &call.package.revision,
            &AnalysisReadControl::default()
        )
        .is_err());
    assert_eq!(
        held.package_revision(
            [1; 16],
            &call.package.package_id,
            &call.package.revision,
            &AnalysisReadControl::default()
        )?,
        Some(row)
    );
    drop(changed);
    drop(held);
    drop(journals);
    drop(producer);
    drop(attempt);
    drop(store);
    assert!(NativeStore::open(&root).is_err());
    Ok(())
}

pub(super) fn node(
    transaction: &ManagedGraphTransaction,
    key: &[u8],
) -> Result<sdk::RecordBatch, Box<dyn std::error::Error>> {
    let columns: Vec<ArrayRef> = vec![
        Arc::new(BinaryArray::from_iter_values([b"owner".as_slice()])),
        Arc::new(BinaryArray::from_iter_values([key])),
        Arc::new(UInt8Array::from(vec![araphor_graph::Write::Add as u8])),
        Arc::new(StructArray::new(
            transaction
                .spec()
                .relation("task")?
                .properties
                .fields()
                .clone(),
            vec![Arc::new(UInt64Array::from(vec![42]))],
            None,
        )),
    ];
    Ok(sdk::RecordBatch::try_new(
        Arc::new(transaction.spec().command_schema("task")?),
        columns,
    )?)
}

pub(super) fn read_nodes(
    transaction: &ManagedGraphTransaction,
    store: &NativeStore,
) -> Result<sdk::Input, Box<dyn std::error::Error>> {
    let arguments = sdk::RecordBatch::try_new(
        Arc::new(transaction.spec().argument_schema("nodes")?),
        vec![Arc::new(BinaryArray::from_iter_values([
            b"task-a".as_slice()
        ]))],
    )?;
    Ok(transaction.read(
        store,
        "nodes",
        "task",
        &arguments,
        |_| Ok(Arc::new(())),
        &AnalysisReadControl::default(),
    )?)
}

#[test]
fn dependent_package_journals_read_staged_graph_without_a_storage_commit() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = NativeStore::open(&directory.path().join("data"))?;
    let (instance, model) = fixture(&store)?;
    let page = super::attempts::capture(&store, &instance, false)?;
    let attempt = Arc::new(store.register_managed_attempt(
        &page.state,
        &super::attempts::request("journals", false),
        || Ok(()),
    )?);
    let cursor = store.database().inner().journal_head()?;
    let revision = store.view()?.revision();
    let producer = ManagedGraphTransaction::new(
        &store,
        Arc::clone(&attempt),
        10,
        &model,
        Vec::new(),
        Arc::new(Budget),
        &AnalysisReadControl::default(),
    )?;
    assert_eq!(read_nodes(&producer, &store)?.data.rows(), 0);
    producer.stage(
        &store,
        "task",
        node(&producer, b"task-a")?,
        Arc::new(()),
        &AnalysisReadControl::default(),
    )?;
    assert_eq!(read_nodes(&producer, &store)?.data.rows(), 1);
    let journal = producer.freeze(&store, &AnalysisReadControl::default())?;
    assert!(read_nodes(&producer, &store).is_err());
    let consumer = ManagedGraphTransaction::new(
        &store,
        Arc::clone(&attempt),
        20,
        &model,
        vec![Arc::clone(&journal)],
        Arc::new(Budget),
        &AnalysisReadControl::default(),
    )?;
    let read = read_nodes(&consumer, &store)?;
    assert_eq!(read.data.rows(), 1);
    let value = read
        .data
        .batches
        .iter()
        .find(|batch| batch.num_rows() != 0)
        .ok_or("member row")?
        .column_by_name("properties")
        .ok_or("properties")?
        .as_any()
        .downcast_ref::<StructArray>()
        .ok_or("property struct")?
        .column_by_name("count")
        .ok_or("count")?
        .as_any()
        .downcast_ref::<UInt64Array>()
        .ok_or("count array")?
        .value(0);
    assert_eq!(value, 42);
    consumer.freeze(&store, &AnalysisReadControl::default())?;
    assert_eq!(store.view()?.revision(), revision);
    assert_eq!(store.database().inner().journal_head()?, cursor);
    let mapping = store
        .view()?
        .managed_graph([1; 16], &instance.spec.id, &AnalysisReadControl::default())?
        .ok_or("mapping")?;
    let view = araphor_graph::native::Graph::new(mapping.graph)?.view(
        store.view()?.snapshot().clone(),
        BTreeMap::new(),
        &|_, _, _| Ok(None),
    )?;
    assert_eq!(view.head(mapping.writers[&10])?, None);
    assert_eq!(view.head(mapping.writers[&20])?, None);
    Ok(())
}

#[test]
fn graph_journal_predecessor_must_belong_to_the_actual_attempt() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = NativeStore::open(&directory.path().join("data"))?;
    let (instance, model) = fixture(&store)?;
    let page = super::attempts::capture(&store, &instance, false)?;
    let first = Arc::new(store.register_managed_attempt(
        &page.state,
        &super::attempts::request("first", false),
        || Ok(()),
    )?);
    let second = Arc::new(store.register_managed_attempt(
        &page.state,
        &super::attempts::request("second", false),
        || Ok(()),
    )?);
    let producer = ManagedGraphTransaction::new(
        &store,
        first,
        10,
        &model,
        Vec::new(),
        Arc::new(Budget),
        &AnalysisReadControl::default(),
    )?;
    let journal = producer.freeze(&store, &AnalysisReadControl::default())?;
    assert!(ManagedGraphTransaction::new(
        &store,
        second,
        20,
        &model,
        vec![journal],
        Arc::new(Budget),
        &AnalysisReadControl::default()
    )
    .is_err());
    Ok(())
}
