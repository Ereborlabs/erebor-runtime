use std::collections::BTreeMap;

use araphor_analysis_sdk as sdk;
use araphor_data::analysis::PackageRevisionV1;
use araphor_data::{
    analysis::native::NativeStore, AnalysisReadControl, Error, PackageArtifactV1, PackageBundle,
    PackageBundleV1, PackageErrorCodeV1 as Code, PackageImplementationV1, SqlModelV1,
};
use araphor_discovery_definition::{Definition, ImagePin, Program, ResolvedDefinition, Source};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn artifact(name: &str, revision: &str, sql: &str) -> PackageArtifactV1 {
    PackageArtifactV1 {
        descriptor: sdk::Package::new(
            name,
            revision,
            vec![sdk::Model::new(
                "count",
                Vec::new(),
                vec![sdk::Port::new(
                    "rows",
                    sdk::Schema::new(vec![sdk::Field::new("count", sdk::DataType::UInt64, false)]),
                )],
            )],
        ),
        implementations: vec![PackageImplementationV1::Sql {
            export: "count".into(),
            program: SqlModelV1 {
                outputs: BTreeMap::from([("rows".into(), sql.into())]),
                ..Default::default()
            },
        }],
        fixtures: Vec::new(),
    }
}

fn image(revision: &str, sql: &str) -> araphor_data::Result<PackageBundle> {
    let artifact = artifact("native-counts", revision, sql);
    Ok(PackageBundle::try_from(PackageBundleV1 {
        schema_version: 1,
        root: artifact.reference(),
        artifacts: vec![artifact],
    })?)
}

#[test]
fn artifact_body_ownership() -> TestResult {
    for fault in 0..4 {
        let directory = tempfile::tempdir()?;
        let root = directory.path().join("store");
        let store = NativeStore::open(&root)?;
        let bundle = image("1", "SELECT 1::BIGINT UNSIGNED AS count")?;
        store.install_package_image([1; 16], &bundle, || Ok(()))?;
        let view = store.view()?;
        let (key, bytes) = view
            .snapshot()
            .prefix(b"\0data/@package-body/")
            .next()
            .ok_or("body")??;
        let mut tx = store.write()?;
        match fault {
            0 => tx.native().remove(key.clone()),
            1 => tx.native().insert(key.clone(), &bytes[..bytes.len() - 1]),
            2 => tx.native().insert(
                [b"\0data/@package-body/".as_slice(), &u64::MAX.to_be_bytes()].concat(),
                bytes.clone(),
            ),
            3 => tx.native().insert(
                [key.as_ref(), &0u64.to_be_bytes()].concat(),
                b"extra fragment",
            ),
            _ => unreachable!(),
        }
        tx.commit([])?;
        drop(view);
        drop(store);
        assert!(NativeStore::open(&root).is_err(), "fault {fault}");
    }
    Ok(())
}

#[test]
fn artifact_collection_keeps_history() -> TestResult {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("store");
    let store = NativeStore::open(&root)?;
    let bundle = image("1", "SELECT 1::BIGINT UNSIGNED AS count")?;
    let installed = store.install_package_image([1; 16], &bundle, || Ok(()))?;
    let held = store.view()?;
    let pin = ImagePin {
        image: bundle.bundle().root.clone(),
        digest: bundle.digest().into(),
    };
    assert!(store.uninstall_package_image([1; 16], &pin, || Ok(()))?);
    let view = store.view()?;
    assert_eq!(view.snapshot().prefix(b"\0data/P").count(), 0);
    assert_eq!(view.snapshot().prefix(b"\0data/@package/").count(), 0);
    assert_eq!(view.snapshot().prefix(b"\0data/@package-body/").count(), 0);
    assert!(view
        .package_image(
            [1; 16],
            "native-counts",
            None,
            &AnalysisReadControl::default()
        )?
        .is_none());
    assert_eq!(
        held.package_image(
            [1; 16],
            "native-counts",
            None,
            &AnalysisReadControl::default()
        )?
        .ok_or("historical image")?
        .digest(),
        bundle.digest()
    );
    drop(view);
    drop(held);
    store.database().inner().flush_memtables()?;
    store.database().inner().major_compact()?;
    drop(store);
    let store = NativeStore::open(&root)?;
    assert_eq!(
        store
            .read_at(installed)?
            .package_image(
                [1; 16],
                "native-counts",
                None,
                &AnalysisReadControl::default()
            )?
            .ok_or("retained image")?
            .digest(),
        bundle.digest()
    );
    Ok(())
}

fn definition(
    name: &str,
    sql: &str,
    image: Option<&PackageBundle>,
) -> araphor_data::Result<ResolvedDefinition> {
    Ok(ResolvedDefinition::new(
        Definition {
            name: name.into(),
            description: String::new(),
            labels: BTreeMap::new(),
            program: Program::Sql {
                source: Source::Inline { inline: sql.into() },
            },
        },
        sql.into(),
        image
            .map(|image| ImagePin {
                image: image.bundle().root.clone(),
                digest: image.digest().into(),
            })
            .into_iter()
            .collect(),
    )?)
}

#[test]
fn catalogue_retries_history_and_reopen() -> TestResult {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("store");
    let store = NativeStore::open(&root)?;
    let control = AnalysisReadControl::default();
    let first = image("1", "SELECT 1::BIGINT UNSIGNED AS count")?;
    let second = image("2", "SELECT 2::BIGINT UNSIGNED AS count")?;
    let before = store.view()?;
    let installed = store.install_package_image([1; 16], &first, || Ok(()))?;
    let initial = store.view()?;
    assert!(before
        .package_image([1; 16], "native-counts", None, &control)?
        .is_none());
    let cursor = store.database().inner().journal_head()?;
    let mut checked = false;
    assert_eq!(
        store.install_package_image([1; 16], &first, || {
            checked = true;
            Ok(())
        })?,
        installed
    );
    assert!(checked);
    assert_eq!(store.database().inner().journal_head()?, cursor);
    let one = definition("counts", "SELECT 1", Some(&first))?;
    let two = definition("counts", "SELECT 2", Some(&second))?;
    let admitted = store.admit_definition([1; 16], &one, || Ok(()))?;
    store.install_package_image([1; 16], &second, || Ok(()))?;
    let latest = store.admit_definition([1; 16], &two, || Ok(()))?;
    let cursor = store.database().inner().journal_head()?;
    for (definition, revision) in [(&one, admitted), (&two, latest)] {
        let mut checked = false;
        assert_eq!(
            store.admit_definition([1; 16], definition, || {
                checked = true;
                Ok(())
            })?,
            revision
        );
        assert!(checked);
        assert_eq!(
            store
                .view()?
                .definition_revision([1; 16], definition, &control)?,
            Some(revision)
        );
    }
    assert_eq!(store.database().inner().journal_head()?, cursor);
    assert_eq!(store.view()?.revision(), latest);
    assert_eq!(
        store
            .view()?
            .definition([1; 16], "counts", None, &control)?,
        Some((two.clone(), latest))
    );
    assert_eq!(
        store
            .view()?
            .definition([1; 16], "counts", Some(admitted), &control)?,
        Some((one.clone(), admitted))
    );
    assert!(store
        .view()?
        .definition([2; 16], "counts", None, &control)?
        .is_none());
    assert!(store
        .view()?
        .definition([1; 16], "counts", Some(latest + 1), &control)?
        .is_none());
    assert_eq!(
        initial
            .package_image([1; 16], "native-counts", None, &control)?
            .ok_or("initial image")?
            .digest(),
        first.digest()
    );
    assert_eq!(
        store
            .view()?
            .package_image([1; 16], "native-counts", None, &control)?
            .ok_or("latest image")?
            .digest(),
        second.digest()
    );
    assert_eq!(
        store.install_package_image([1; 16], &first, || Ok(()))?,
        installed
    );
    assert_eq!(
        store
            .view()?
            .package_image([1; 16], "native-counts", None, &control)?
            .ok_or("latest after retry")?
            .digest(),
        second.digest()
    );
    store.database().inner().flush_memtables()?;
    store.database().inner().major_compact()?;
    drop((before, initial));
    drop(store);
    let store = NativeStore::open(&root)?;
    assert_eq!(
        store
            .view()?
            .definition([1; 16], "counts", None, &control)?,
        Some((two, latest))
    );
    assert_eq!(
        store
            .read_at(admitted)?
            .definition([1; 16], "counts", None, &control)?,
        Some((one, admitted))
    );
    assert_eq!(
        store
            .read_at(installed)?
            .package_image([1; 16], "native-counts", None, &control)?
            .ok_or("historical image")?
            .digest(),
        first.digest()
    );
    assert!(!root.join("analysis.duckdb").exists());
    Ok(())
}

#[test]
fn admission_denials_and_pins_are_atomic() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = NativeStore::open(&directory.path().join("store"))?;
    let control = AnalysisReadControl::default();
    let image = image("1", "SELECT 1::BIGINT UNSIGNED AS count")?;
    let requested = definition("counts", "SELECT 1", Some(&image))?;
    let denied = || Err(Code::Denied.error("admission test"));
    assert!(store
        .install_package_image([1; 16], &image, denied)
        .is_err());
    assert_eq!(store.view()?.revision(), 0);
    assert!(store
        .view()?
        .package_revision([1; 16], "native-counts", "1", &control)?
        .is_none());
    store.install_package_image([2; 16], &image, || Ok(()))?;
    let before = store.view()?.revision();
    assert!(matches!(
        store.admit_definition([1; 16], &requested, || Ok(())),
        Err(Error::Package {
            code: Code::Missing,
            ..
        })
    ));
    assert_eq!(store.view()?.revision(), before);
    store.install_package_image([1; 16], &image, || Ok(()))?;
    let before = store.view()?.revision();
    assert!(store
        .install_package_image([1; 16], &image, denied)
        .is_err());
    assert!(store.admit_definition([1; 16], &requested, denied).is_err());
    assert_eq!(store.view()?.revision(), before);
    assert!(store
        .view()?
        .definition([1; 16], "counts", None, &control)?
        .is_none());
    store.admit_definition([1; 16], &requested, || Ok(()))?;
    let before = store.view()?.revision();
    assert!(store.admit_definition([1; 16], &requested, denied).is_err());
    let mut wrong = requested.clone();
    wrong.images[0].digest = format!("sha256:{}", "0".repeat(64));
    assert!(matches!(
        store.admit_definition([1; 16], &wrong, || Ok(())),
        Err(Error::Package {
            code: Code::Missing,
            ..
        })
    ));
    assert!(matches!(
        store
            .view()?
            .retained_package_image([1; 16], &wrong.images[0], &control),
        Err(Error::Package {
            code: Code::Conflict,
            ..
        })
    ));
    let conflict = self::image("1", "SELECT 9::BIGINT UNSIGNED AS count")?;
    assert!(matches!(
        store.install_package_image([1; 16], &conflict, || Ok(())),
        Err(Error::AnalysisConflict { .. })
    ));
    assert_eq!(store.view()?.revision(), before);
    let cancelled = AnalysisReadControl::default();
    cancelled.cancel()?;
    assert!(matches!(
        store
            .view()?
            .definition([1; 16], "counts", None, &cancelled),
        Err(Error::AnalysisReadCancelled { .. })
    ));
    assert!(matches!(
        store
            .view()?
            .package_image([1; 16], "native-counts", None, &cancelled),
        Err(Error::AnalysisReadCancelled { .. })
    ));
    Ok(())
}

#[test]
fn dependency_closure_is_required() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = NativeStore::open(&directory.path().join("store"))?;
    let dependency = artifact("dependency", "1", "SELECT 1::BIGINT UNSIGNED AS count");
    let mut root = artifact("root", "1", "SELECT 1::BIGINT UNSIGNED AS count");
    root.descriptor.exports[0].input_mode = sdk::InputMode::Resolved;
    root.descriptor.exports[0].inputs.push(sdk::InputPort {
        port: sdk::Port::new(
            "source",
            dependency.descriptor.exports[0].outputs[0].schema.clone(),
        ),
        source: sdk::InputSource::Table(sdk::TableRef::Output(sdk::OutputRef {
            package: "dependency".into(),
            revision: "1".into(),
            export: "count".into(),
            output: "rows".into(),
        })),
    });
    let bundle = PackageBundle::try_from(PackageBundleV1 {
        schema_version: 1,
        root: root.reference(),
        artifacts: vec![root, dependency],
    })?;
    let mut rows = PackageRevisionV1::from_bundle(&bundle, [1; 16])?;
    rows.sort_by_key(|row| row.package_id != "root");
    let root = rows
        .iter()
        .find(|row| row.package_id == "root")
        .ok_or("root row")?;
    assert!(store
        .install_package(std::slice::from_ref(root), || Ok(()))
        .is_err());
    assert_eq!(store.view()?.revision(), 0);
    let cursor = store.database().inner().journal_head()?;
    assert!(store
        .install_package(&rows, || Err(Code::Denied.error("manual admission test")))
        .is_err());
    assert_eq!(store.view()?.revision(), 0);
    assert_eq!(store.database().inner().journal_head()?, cursor);
    for row in &rows {
        assert!(store
            .view()?
            .package_revision(
                [1; 16],
                &row.package_id,
                &row.revision,
                &AnalysisReadControl::default()
            )?
            .is_none());
    }
    store.install_package(&rows, || Ok(()))?;
    let installed = store.view()?.revision();
    let cursor = store.database().inner().journal_head()?;
    let mut checked = false;
    store.install_package(&rows, || {
        checked = true;
        Ok(())
    })?;
    assert!(checked);
    assert_eq!(store.view()?.revision(), installed);
    assert_eq!(store.database().inner().journal_head()?, cursor);
    for row in &rows {
        assert_eq!(
            store.view()?.package_revision(
                [1; 16],
                &row.package_id,
                &row.revision,
                &AnalysisReadControl::default()
            )?,
            Some(row.clone())
        );
    }
    store.install_package_image([1; 16], &bundle, || Ok(()))?;
    let saved = store
        .view()?
        .package_image([1; 16], "root", None, &AnalysisReadControl::default())?
        .ok_or("closure")?;
    assert_eq!(saved.digest(), bundle.digest());
    assert_eq!(saved.bundle().artifacts.len(), 2);
    let before = store.view()?.revision();
    let mut conflict = root.clone();
    conflict.artifact.push(255);
    assert!(store.install_package(&[conflict], || Ok(())).is_err());
    assert_eq!(store.view()?.revision(), before);
    Ok(())
}

#[test]
fn names_use_fragmented_identities() -> TestResult {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("store");
    let store = NativeStore::open(&root)?;
    let artifact = artifact(
        &"p".repeat(257),
        &"r".repeat(4097),
        "SELECT 1::BIGINT UNSIGNED AS count",
    );
    let image = PackageBundle::try_from(PackageBundleV1 {
        schema_version: 1,
        root: artifact.reference(),
        artifacts: vec![artifact],
    })?;
    assert!(store
        .install_package(&PackageRevisionV1::from_bundle(&image, [255; 16])?, || Ok(
            ()
        ))
        .is_err());
    store.install_package_image([255; 16], &image, || Ok(()))?;
    let name = "n".repeat(u16::MAX as usize * 2);
    let definition = definition(&name, "SELECT 1", None)?;
    let committed = store.admit_definition([255; 16], &definition, || Ok(()))?;
    assert_eq!(
        store
            .view()?
            .definition([255; 16], &name, None, &AnalysisReadControl::default())?,
        Some((definition.clone(), committed))
    );
    drop(store);
    let store = NativeStore::open(&root)?;
    assert_eq!(
        store.admit_definition([255; 16], &definition, || Ok(()))?,
        committed
    );
    Ok(())
}

#[test]
fn native_bytes_and_raw_positions_survive_reopen() -> TestResult {
    use araphor_data::{
        AnalysisContextKeyV1, AnalysisContextVersionV1, ContextSensitivityV1, CoverageReportRef,
        EvidenceIntakeIdentityV1, ValidatedCoverageV1, ValidatedEvidenceBatchV1,
    };

    let directory = tempfile::tempdir()?;
    let root = directory.path().join("store");
    let store = NativeStore::open(&root)?;
    let uuid = store.view()?.store_uuid();
    let source = EvidenceIntakeIdentityV1 {
        tenant_id: [255; 16],
        node_id: "node-a".into(),
        node_boot_id: [254; 16],
        label_epoch: 1,
        source_id: [253; 16],
        source_epoch: 1,
    };
    let batch = |cursor| ValidatedEvidenceBatchV1 {
        cpu_id: 7,
        first_cursor: cursor,
        last_cursor: cursor,
        intake_utc_ns: 100,
        framed_records: vec![255].into(),
        frame_ends: vec![1],
    };
    store.accept_validated_batch(source.clone(), batch(1))?;
    let image = image("1", "SELECT 1::BIGINT UNSIGNED AS count")?;
    let installed = store.install_package_image(source.tenant_id, &image, || Ok(()))?;
    assert_eq!(installed, 2);
    store.accept_validated_batch(source.clone(), batch(2))?;
    let definition = definition("counts", "SELECT 1", Some(&image))?;
    let admitted = store.admit_definition(source.tenant_id, &definition, || Ok(()))?;
    assert_eq!(admitted, 4);
    let context = AnalysisContextVersionV1 {
        key: AnalysisContextKeyV1 {
            tenant_id: source.tenant_id,
            owner_id: "binary-test".into(),
            entity_key: vec![255; 16],
            lifetime_key: vec![254; 16],
            owner_revision: 1,
        },
        valid_from_utc_ns: None,
        valid_until_utc_ns: None,
        sensitivity: ContextSensitivityV1::Tenant,
        body: vec![255; 4096],
    };
    let mut tx = store.write()?;
    let reference = tx.context(&context, Some(0))?;
    tx.commit([])?;
    store.accept_validated_coverage(ValidatedCoverageV1 {
        identity: source.clone(),
        cpu_id: 7,
        revision: 1,
        encoded_report: vec![254; 4096],
    })?;
    let view = store.view()?;
    let mut old = Vec::new();
    for entry in view.snapshot().prefix(b"\0data/C") {
        let (key, value) = entry?;
        assert!(value
            .windows(context.body.len())
            .any(|bytes| bytes == context.body));
        assert_eq!(
            rmp_serde::from_slice::<(AnalysisContextVersionV1, u64)>(&value[1..])?,
            (context.clone(), reference.commit_revision)
        );
        old.push((
            key,
            [
                vec![0],
                rmp_serde::to_vec(&(&context, reference.commit_revision))?,
            ]
            .concat(),
        ));
    }
    for entry in view.snapshot().prefix(b"\0data/P") {
        let (key, value) = entry?;
        let row: (PackageRevisionV1, u64, u64) = rmp_serde::from_slice(&value[1..])?;
        assert!(row.0.dependencies.is_empty());
        assert!(row.0.artifact.is_empty());
        let body_key = [b"\0data/@package-body/".as_slice(), &key[7..]].concat();
        let body = view.snapshot().get(&body_key)?.ok_or("package body")?;
        let artifact = image.bundle().artifacts[0].encode()?;
        assert_eq!(body[0], 0);
        assert_eq!(row.2, artifact.len() as u64);
        assert_eq!(&body[1..], artifact.as_slice());
        old.push((body_key.into(), body.to_vec()));
        old.push((key, [vec![0], rmp_serde::to_vec(&row)?].concat()));
    }
    for entry in view.snapshot().prefix(b"\0data/coverage/report/") {
        let (key, value) = entry?;
        let row: (CoverageReportRef, Vec<u8>) = rmp_serde::from_slice(&value[1..])?;
        assert_eq!(row.0.source, source);
        assert_eq!(row.1, vec![254; 4096]);
        assert!(value.windows(row.1.len()).any(|bytes| bytes == row.1));
        old.push((key, [vec![0], rmp_serde::to_vec(&row)?].concat()));
    }
    assert_eq!(old.len(), 4);
    let mut tx = store.write()?;
    for (key, value) in old {
        tx.native().insert(key, value);
    }
    tx.commit([])?;
    store.accept_validated_batch(source.clone(), batch(3))?;
    let end = store.view()?.revision();
    drop(view);
    drop(store);
    let store = NativeStore::open(&root)?;
    assert_eq!(store.view()?.store_uuid(), uuid);
    assert_eq!(store.view()?.revision(), end);
    assert_eq!(
        store.view()?.context(&context.key)?,
        Some((context, reference.commit_revision))
    );
    assert_eq!(
        store
            .view()?
            .source_status(&source)?
            .ok_or("source")?
            .latest_coverage_report,
        Some(vec![254; 4096])
    );
    assert_eq!(
        store
            .read_at(3)?
            .source_receipt(&source)?
            .ok_or("historical source")?
            .contiguous_cursor,
        2
    );
    assert!(store
        .read_at(3)?
        .definition(
            source.tenant_id,
            "counts",
            None,
            &AnalysisReadControl::default()
        )?
        .is_none());
    assert_eq!(
        store.admit_definition(source.tenant_id, &definition, || Ok(()))?,
        admitted
    );
    assert_eq!(store.view()?.revision(), end);
    Ok(())
}

#[test]
fn recovery_rejects_missing_or_stale_heads() -> TestResult {
    for (kind, stale) in [(b'A', false), (b'A', true), (b'F', false), (b'F', true)] {
        let directory = tempfile::tempdir()?;
        let root = directory.path().join("store");
        let store = NativeStore::open(&root)?;
        let first = image("1", "SELECT 1::BIGINT UNSIGNED AS count")?;
        let second = image("2", "SELECT 2::BIGINT UNSIGNED AS count")?;
        store.install_package_image([1; 16], &first, || Ok(()))?;
        store.admit_definition(
            [1; 16],
            &definition("counts", "SELECT 1", Some(&first))?,
            || Ok(()),
        )?;
        let prefix = [b"\0data/".as_slice(), &[kind]].concat();
        let (key, old) = store
            .view()?
            .snapshot()
            .prefix(&prefix)
            .next()
            .ok_or("head")??;
        store.install_package_image([1; 16], &second, || Ok(()))?;
        store.admit_definition(
            [1; 16],
            &definition("counts", "SELECT 2", Some(&second))?,
            || Ok(()),
        )?;
        let mut tx = store.write()?;
        if stale {
            tx.native().insert(key, old);
        } else {
            tx.native().remove(key);
        }
        tx.commit([])?;
        drop(store);
        assert!(matches!(
            NativeStore::open(&root),
            Err(Error::NativeState {
                field: "catalogue head",
                ..
            })
        ));
    }
    Ok(())
}

#[test]
fn raw_tail_cannot_validate_future_metadata() -> TestResult {
    use araphor_data::{EvidenceIntakeIdentityV1, ValidatedEvidenceBatchV1};

    let directory = tempfile::tempdir()?;
    let root = directory.path().join("store");
    let store = NativeStore::open(&root)?;
    store.install_package_image(
        [1; 16],
        &image("1", "SELECT 1::BIGINT UNSIGNED AS count")?,
        || Ok(()),
    )?;
    let (key, value) = store
        .view()?
        .snapshot()
        .prefix(b"\0data/P")
        .next()
        .ok_or("package")??;
    let (row, _, body_bytes): (PackageRevisionV1, u64, u64) = rmp_serde::from_slice(&value[1..])?;
    let mut tx = store.write()?;
    let future = tx.revision() + 1;
    tx.native().insert(
        key,
        [vec![0], rmp_serde::to_vec(&(row, future, body_bytes))?].concat(),
    );
    tx.commit([])?;
    let source = EvidenceIntakeIdentityV1 {
        tenant_id: [1; 16],
        node_id: "node-a".into(),
        node_boot_id: [2; 16],
        label_epoch: 1,
        source_id: [3; 16],
        source_epoch: 1,
    };
    store.accept_validated_batch(
        source,
        ValidatedEvidenceBatchV1 {
            cpu_id: 7,
            first_cursor: 1,
            last_cursor: 1,
            intake_utc_ns: 100,
            framed_records: vec![255].into(),
            frame_ends: vec![1],
        },
    )?;
    assert_eq!(store.view()?.revision(), future);
    assert!(store
        .view()?
        .package_revision(
            [1; 16],
            "native-counts",
            "1",
            &AnalysisReadControl::default()
        )
        .is_err());
    drop(store);
    assert!(matches!(
        NativeStore::open(&root),
        Err(Error::NativeState {
            field: "package record identity",
            ..
        })
    ));
    Ok(())
}

#[test]
fn recovery_rejects_duplicate_definition() -> TestResult {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("store");
    let store = NativeStore::open(&root)?;
    let definition = definition("counts", "SELECT 1", None)?;
    store.admit_definition([1; 16], &definition, || Ok(()))?;
    let (key, _) = store
        .view()?
        .snapshot()
        .prefix(b"\0data/D")
        .next()
        .ok_or("definition")??;
    let mut tx = store.write()?;
    let revision = tx.revision();
    let mut duplicate = key[..15].to_vec();
    duplicate.extend_from_slice(&revision.to_be_bytes());
    tx.native().insert(
        duplicate,
        [
            vec![0],
            rmp_serde::to_vec(&([1u8; 16], definition.encode()?, revision))?,
        ]
        .concat(),
    );
    let mut head = key[..15].to_vec();
    head[6] = b'F';
    tx.native().insert(head, revision.to_be_bytes());
    tx.commit([])?;
    drop(store);
    assert!(matches!(
        NativeStore::open(&root),
        Err(Error::NativeState {
            field: "duplicate definition",
            ..
        })
    ));
    Ok(())
}
