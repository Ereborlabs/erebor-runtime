use super::*;

fn check_catalogue_history(package: bool) -> TestResult {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("data");
    let store = NativeStore::open(&root)?;
    let bundle = package
        .then(|| image("1", "SELECT 1::BIGINT UNSIGNED AS count"))
        .transpose()?;
    let definition = if package {
        None
    } else {
        Some(ResolvedDefinition::new(
            Definition {
                name: "history".into(),
                description: String::new(),
                labels: BTreeMap::new(),
                program: Program::Sql {
                    source: Source::Inline {
                        inline: "SELECT 1".into(),
                    },
                },
            },
            "SELECT 1".into(),
            Vec::new(),
        )?)
    };
    let revision = if let Some(bundle) = &bundle {
        store.install_package_image([1; 16], bundle, || Ok(()))?
    } else {
        store.admit_definition([1; 16], definition.as_ref().ok_or("definition")?, || Ok(()))?
    };
    for value in [1, 2] {
        let mut tx = store.write()?;
        tx.native().insert(b"history-point", [value]);
        tx.commit([])?;
    }
    store.checkpoint()?;
    store.database().inner().major_compact()?;
    drop(store);
    let store = NativeStore::open(&root)?;
    let historical = store.read_at(revision)?;
    if let Some(bundle) = bundle {
        assert_eq!(
            historical
                .package_image(
                    [1; 16],
                    "native-counts",
                    None,
                    &AnalysisReadControl::default()
                )?
                .ok_or("historical package")?
                .digest(),
            bundle.digest()
        );
    } else {
        assert_eq!(
            historical.definition([1; 16], "history", None, &AnalysisReadControl::default())?,
            Some((definition.ok_or("definition")?, revision))
        );
    }
    assert!(store.read_at(0).is_err());
    Ok(())
}

#[test]
fn package_cut_keeps_history() -> TestResult {
    check_catalogue_history(true)
}

#[test]
fn definition_cut_keeps_history() -> TestResult {
    check_catalogue_history(false)
}
