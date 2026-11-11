use super::*;
use araphor_data::analysis::AnalysisStore;

type TestResult<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

fn resolved(name: &str, sql: &str) -> TestResult<ResolvedDefinition> {
    Ok(ResolvedDefinition::new(
        Definition {
            name: name.into(),
            description: "Count retained records.".into(),
            labels: BTreeMap::from([("team".into(), "security".into())]),
            program: Program::Sql {
                source: Source::Inline { inline: sql.into() },
            },
        },
        sql.into(),
        Vec::new(),
    )?)
}

fn sql_image() -> araphor_data::PackageBundleV1 {
    use araphor_analysis_sdk as sdk;

    let artifact = araphor_data::PackageArtifactV1 {
        descriptor: sdk::Package::new(
            "definition-image",
            "1",
            vec![sdk::Model::new(
                "count",
                Vec::new(),
                vec![sdk::Port::new(
                    "rows",
                    sdk::Schema::new(vec![sdk::Field::new("count", sdk::DataType::UInt64, false)]),
                )],
            )],
        ),
        implementations: vec![araphor_data::PackageImplementationV1::Sql {
            export: "count".into(),
            program: araphor_data::SqlModelV1 {
                outputs: BTreeMap::from([(
                    "rows".into(),
                    "SELECT 1::BIGINT UNSIGNED AS count".into(),
                )]),
                ..Default::default()
            },
        }],
        fixtures: Vec::new(),
    };
    araphor_data::PackageBundleV1 {
        schema_version: 1,
        root: artifact.reference(),
        artifacts: vec![artifact],
    }
}

fn inspect(
    store: &AnalysisStore,
    tenant: [u8; 16],
    name: &str,
    revision: Option<u64>,
) -> araphor_data::Result<Option<ResolvedDefinition>> {
    Ok(store
        .definition(tenant, name, revision, &AnalysisReadControl::default())?
        .map(|(definition, _)| definition))
}

#[test]
fn definition_retains_captured_source() -> TestResult {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("store");
    let source = directory.path().join("query.sql");
    let path = directory.path().join("definition.yaml");
    let sql = "SELECT 1 AS count\n";
    std::fs::write(&source, sql)?;
    let definition = Definition {
        name: "observed".into(),
        description: "Count retained records.".into(),
        labels: BTreeMap::from([
            ("owner".into(), "analysis".into()),
            ("team".into(), "security".into()),
        ]),
        program: Program::Sql {
            source: Source::File {
                file: "query.sql".into(),
            },
        },
    };
    std::fs::write(&path, "name: observed\ndescription: Count retained records.\nlabels:\n  owner: analysis\n  team: security\nsql:\n  file: query.sql\n")?;
    let captured = Definition::read(&path)?;
    let compiled = captured.program.sql()?;
    let captured = ResolvedDefinition::new(captured, compiled, Vec::new())?;
    std::fs::write(&source, "SELECT 99 AS count")?;
    std::fs::remove_file(&source)?;
    let store = AnalysisStore::open(&root)?;
    let notices = store.subscribe_activations()?;
    let committed = store.admit_definition([1; 16], &captured, || Ok(()))?;
    assert_eq!(committed, store.meta()?.commit_revision);
    let saved = store.meta()?;
    let revision = committed;
    let retained = inspect(&store, [1; 16], "observed", None)?.ok_or("definition is absent")?;
    assert_eq!(retained, captured);
    assert_eq!(retained.sql, sql);
    assert_eq!(retained.definition.description, definition.description);
    assert_eq!(retained.definition.labels, definition.labels);
    assert_eq!(
        retained.definition.program,
        Program::Sql {
            source: Source::Inline { inline: sql.into() },
        }
    );
    let mut checked = false;
    assert_eq!(
        store.admit_definition([1; 16], &captured, || {
            checked = true;
            Ok(())
        })?,
        committed
    );
    assert!(checked);
    assert_eq!(store.meta()?, saved);
    assert_eq!(
        inspect(&store, [1; 16], "observed", Some(revision))?,
        Some(captured.clone())
    );
    assert_no_execution(&store)?;
    assert!(!notices.has_changed()?);
    drop((notices, store));
    let reopened = AnalysisStore::open(&root)?;
    let notices = reopened.subscribe_activations()?;
    assert_eq!(
        reopened.admit_definition([1; 16], &captured, || Ok(()))?,
        committed
    );
    assert!(!notices.has_changed()?);
    assert_eq!(reopened.meta()?, saved);
    assert_eq!(
        inspect(&reopened, [1; 16], "observed", Some(revision))?,
        Some(captured)
    );
    assert_no_execution(&reopened)?;
    Ok(())
}

#[test]
fn definition_revisions_and_tenants() -> TestResult {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("store");
    let store = AnalysisStore::open(&root)?;
    let first = resolved("counts", "SELECT 1 AS count")?;
    let mut second = resolved("counts", "SELECT 2 AS count")?;
    second.definition.description = "Count the selected records.".into();
    second
        .definition
        .labels
        .insert("revision".into(), "2".into());
    let first_commit = store.admit_definition([1; 16], &first, || Ok(()))?;
    let second_commit = store.admit_definition([1; 16], &second, || Ok(()))?;
    assert!(second_commit > first_commit);
    assert_eq!(
        inspect(&store, [1; 16], "counts", None)?,
        Some(second.clone())
    );
    assert_eq!(
        inspect(&store, [1; 16], "counts", Some(first_commit))?,
        Some(first.clone())
    );
    let before = store.meta()?;
    assert_eq!(
        store.admit_definition([1; 16], &first, || Ok(()))?,
        first_commit
    );
    assert_eq!(store.meta()?, before);
    assert_eq!(
        inspect(&store, [1; 16], "counts", None)?,
        Some(second.clone())
    );
    assert!(inspect(&store, [2; 16], "counts", None)?.is_none());
    assert!(inspect(
        &store,
        [1; 16],
        "counts",
        Some(store.meta()?.commit_revision + 1)
    )?
    .is_none());
    store.admit_definition([2; 16], &first, || Ok(()))?;
    let saved = store.meta()?;
    let cancelled = AnalysisReadControl::default();
    cancelled.cancel()?;
    assert!(matches!(
        store.definition([1; 16], "counts", None, &cancelled),
        Err(araphor_data::Error::AnalysisReadCancelled { .. })
    ));
    drop(store);
    let reopened = AnalysisStore::open(&root)?;
    assert_eq!(reopened.meta()?, saved);
    assert_eq!(inspect(&reopened, [1; 16], "counts", None)?, Some(second));
    assert_eq!(inspect(&reopened, [2; 16], "counts", None)?, Some(first));
    assert_no_execution(&reopened)?;
    Ok(())
}

#[test]
fn definition_check_is_atomic() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = AnalysisStore::open(directory.path().join("store"))?;
    let definition = resolved("counts", "SELECT 1 AS count")?;
    let before = store.meta()?;
    let mut checked = false;
    assert!(matches!(
        store.admit_definition([1; 16], &definition, || {
            checked = true;
            Err(araphor_data::Error::AnalysisReadDenied {
                location: snafu::location!(),
            })
        }),
        Err(araphor_data::Error::AnalysisReadDenied { .. })
    ));
    assert!(checked);
    assert_eq!(store.meta()?, before);
    assert!(inspect(&store, [1; 16], "counts", None)?.is_none());
    let committed = store.admit_definition([1; 16], &definition, || Ok(()))?;
    let before = store.meta()?;
    let mut checked = false;
    assert!(matches!(
        store.admit_definition([1; 16], &definition, || {
            checked = true;
            Err(araphor_data::Error::AnalysisReadDenied {
                location: snafu::location!(),
            })
        }),
        Err(araphor_data::Error::AnalysisReadDenied { .. })
    ));
    assert!(checked);
    assert_eq!(store.meta()?, before);
    assert_eq!(
        store.admit_definition([1; 16], &definition, || Ok(()))?,
        committed
    );
    assert_eq!(inspect(&store, [1; 16], "counts", None)?, Some(definition));
    assert_no_execution(&store)?;
    Ok(())
}

#[test]
fn definition_requires_exact_image() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = AnalysisStore::open(directory.path().join("store"))?;
    let image = araphor_data::PackageBundle::try_from(sql_image())?;
    let sql = "SELECT * FROM \"definition-image\".\"1\".count()";
    let definition = Definition {
        name: "package-counts".into(),
        description: String::new(),
        labels: BTreeMap::new(),
        program: Program::Sql {
            source: Source::Inline { inline: sql.into() },
        },
    };
    let resolved = ResolvedDefinition::new(
        definition,
        sql.into(),
        vec![ImagePin {
            image: image.bundle().root.clone(),
            digest: image.digest().into(),
        }],
    )?;
    for tenant in [None, Some([2; 16])] {
        if let Some(tenant) = tenant {
            store.install_package_image(tenant, &image, || Ok(()))?;
        }
        let before = store.meta()?;
        assert!(matches!(
            store.admit_definition([1; 16], &resolved, || Ok(())),
            Err(araphor_data::Error::Package {
                code: Code::Missing,
                field: "definition image",
                ..
            })
        ));
        assert_eq!(store.meta()?, before);
        assert!(inspect(&store, [1; 16], "package-counts", None)?.is_none());
    }
    store.install_package_image([1; 16], &image, || Ok(()))?;
    let mut changed = resolved.clone();
    changed.images[0].digest = format!("sha256:{}", "0".repeat(64));
    let before = store.meta()?;
    assert!(matches!(
        store.admit_definition([1; 16], &changed, || Ok(())),
        Err(araphor_data::Error::Package {
            code: Code::Missing,
            field: "definition image",
            ..
        })
    ));
    assert_eq!(store.meta()?, before);
    store.admit_definition([1; 16], &resolved, || Ok(()))?;
    store.collect_package_admissions()?;
    assert_eq!(
        inspect(&store, [1; 16], "package-counts", None)?,
        Some(resolved)
    );
    assert_no_execution(&store)?;
    Ok(())
}

#[test]
fn definition_recovery_checks_identity() -> TestResult {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("store");
    let store = AnalysisStore::open(&root)?;
    let mut definition = resolved("counts", "SELECT 1 AS count")?;
    store.admit_definition([1; 16], &definition, || Ok(()))?;
    definition.definition.name = "modified-counts".into();
    let view = store.view()?;
    let rows = view
        .snapshot()
        .prefix(b"\0data/D")
        .map(|row| row.map(|(key, value)| (key.to_vec(), value.to_vec())))
        .collect::<fjall::Result<Vec<_>>>()?;
    let rows = rows
        .into_iter()
        .filter(|(key, _)| key.len() == 23)
        .collect::<Vec<_>>();
    assert_eq!(rows.len(), 1);
    let (key, bytes) = &rows[0];
    let (tenant, _, revision): ([u8; 16], Vec<u8>, u64) =
        rmp_serde::from_slice(bytes.strip_prefix(&[0]).ok_or("definition envelope")?)?;
    assert_eq!(tenant, [1; 16]);
    assert_eq!(revision, 1);
    let heads = view
        .snapshot()
        .prefix(b"\0data/F")
        .collect::<fjall::Result<Vec<_>>>()?;
    drop(view);
    let mut bytes = vec![0];
    bytes.extend(rmp_serde::to_vec(&(
        tenant,
        definition.encode()?,
        revision,
    ))?);
    let mut transaction = store.write()?;
    transaction.native().insert(key, bytes);
    transaction.commit([])?;
    assert_eq!(
        store
            .view()?
            .snapshot()
            .prefix(b"\0data/F")
            .collect::<fjall::Result<Vec<_>>>()?,
        heads
    );
    assert!(matches!(
        inspect(&store, [1; 16], "counts", None),
        Err(araphor_data::Error::Package {
            code: Code::Invalid,
            field: "retained definition identity",
            ..
        })
    ));
    drop(store);
    assert!(matches!(
        AnalysisStore::open(&root),
        Err(araphor_data::Error::NativeState {
            field: "definition record identity",
            ..
        })
    ));
    Ok(())
}
