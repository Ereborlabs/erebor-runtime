#![cfg(feature = "native-store")]

use std::{collections::BTreeMap, sync::Arc};

use araphor_analysis_sdk as sdk;
use araphor_data::{
    analysis::native::NativeStore, AnalysisReadControl, AnalysisSelectionV1, Error, ManagedCall,
    ManagedDestination, ManagedInstance, ManagedManifest, ManagedSpec, PackageArtifactV1,
    PackageBundle, PackageBundleV1, PackageErrorCodeV1 as Code, PackageGrantV1,
    PackageImplementationV1, SqlModelV1,
};
use araphor_discovery_definition::{Definition, ImagePin, Program, ResolvedDefinition, Source};

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[path = "native_managed/attempts.rs"]
mod attempts;
#[path = "native_managed/domain.rs"]
mod domain;
#[path = "native_managed/graph.rs"]
mod graph;
#[path = "native_managed/publication.rs"]
mod publication;

struct Fixture {
    spec: ManagedSpec,
    grant: PackageGrantV1,
}

impl Fixture {
    fn new(
        store: &NativeStore,
        tenant: [u8; 16],
        id: &str,
        graph: bool,
    ) -> araphor_data::Result<Self> {
        let schema = sdk::Schema::new(vec![sdk::Field::new("count", sdk::DataType::UInt64, false)]);
        let mut model = sdk::Model::new(
            "count",
            Vec::new(),
            vec![sdk::Port::new("rows", schema.clone())],
        );
        if graph {
            model.graph = Some(sdk::GraphSpec {
                access: sdk::GraphAccess::ReadWrite,
                relations: vec![
                    sdk::GraphRelation {
                        name: "task".into(),
                        kind: sdk::GraphKind::Node,
                        properties: schema.clone(),
                    },
                    sdk::GraphRelation {
                        name: "host".into(),
                        kind: sdk::GraphKind::Node,
                        properties: schema.clone(),
                    },
                    sdk::GraphRelation {
                        name: "runs_on".into(),
                        kind: sdk::GraphKind::Edge {
                            from: "task".into(),
                            to: "host".into(),
                        },
                        properties: schema.clone(),
                    },
                ],
            });
        }
        Self::with_model(store, tenant, id, model)
    }

    fn with_model(
        store: &NativeStore,
        tenant: [u8; 16],
        id: &str,
        model: sdk::Model,
    ) -> araphor_data::Result<Self> {
        let graph = model.graph.is_some();
        let schema = model.outputs[0].schema.clone();
        let artifact = PackageArtifactV1 {
            descriptor: sdk::Package::new(
                if graph {
                    "managed-graph"
                } else {
                    "managed-count"
                },
                "1",
                vec![model],
            ),
            implementations: vec![PackageImplementationV1::Sql {
                export: "count".into(),
                program: SqlModelV1 {
                    outputs: BTreeMap::from([(
                        "rows".into(),
                        "SELECT 1::BIGINT UNSIGNED AS count".into(),
                    )]),
                    ..Default::default()
                },
            }],
            fixtures: Vec::new(),
        };
        let image = PackageBundle::try_from(PackageBundleV1 {
            schema_version: 1,
            root: artifact.reference(),
            artifacts: vec![artifact],
        })?;
        store.install_package_image(tenant, &image, || Ok(()))?;
        let pin = ImagePin {
            image: image.bundle().root.clone(),
            digest: image.digest().into(),
        };
        let sql = format!("SELECT * FROM \"{}\".\"1\".count()", pin.image.package_id);
        let definition = ResolvedDefinition::new(
            Definition {
                name: "managed".into(),
                description: String::new(),
                labels: BTreeMap::new(),
                program: Program::Sql {
                    source: Source::Inline {
                        inline: sql.clone(),
                    },
                },
            },
            sql,
            vec![pin.clone()],
        )?;
        let revision = store.admit_definition(tenant, &definition, || Ok(()))?;
        Ok(Self {
            spec: ManagedSpec {
                tenant,
                id: id.into(),
                definition,
                manifest: ManagedManifest {
                    format: 1,
                    planner: "datafusion-55/sql-call-1".into(),
                    definition: revision,
                    calls: BTreeMap::from([(
                        10,
                        ManagedCall {
                            image: pin.clone(),
                            package: pin.image,
                            export: "count".into(),
                            arguments: Vec::new(),
                            target: "sql".into(),
                            artifact: None,
                            dependencies: Default::default(),
                        },
                    )]),
                    selected_schema: schema,
                },
                destination: ManagedDestination::Selected,
            },
            grant: PackageGrantV1 {
                principal: "managed-test".into(),
                revision: 1,
                selection: AnalysisSelectionV1::new(tenant, Vec::new()),
                expires_utc_ns: None,
                authorization_id: Some("managed-admission".into()),
            },
        })
    }

    fn admit(&self, store: &NativeStore) -> araphor_data::Result<ManagedInstance> {
        store.admit_managed(&self.spec, &self.grant, || Ok(()))
    }
}

#[test]
fn admission_lifecycle_history_and_reopen() -> TestResult {
    let dir = tempfile::tempdir()?;
    let root = dir.path().join("store");
    let store = NativeStore::open(&root)?;
    let control = AnalysisReadControl::default();
    let fixture = Fixture::new(&store, [1; 16], "counts", true)?;
    let before = store.view()?;
    let admitted = fixture.admit(&store)?;
    assert!(!admitted.running);
    assert_eq!(admitted.generation, admitted.lifecycle);
    assert_eq!(admitted.progress, 0);
    assert!(before
        .managed_instance([1; 16], "counts", &control)?
        .is_none());
    let initial = store.view()?;
    let graph = initial
        .managed_graph([1; 16], "counts", &control)?
        .ok_or("Graph")?;
    let engine = araphor_graph::native::Graph::new(graph.graph)?;
    let view = engine.view(initial.snapshot().clone(), BTreeMap::new(), &|_, _, _| {
        Ok(None)
    })?;
    assert_eq!(
        view.writers().collect::<Vec<_>>(),
        graph.writers.values().copied().collect::<Vec<_>>()
    );
    assert_eq!(view.head(graph.writers[&10])?, None);
    assert_eq!(graph.relations.len(), 3);
    let cursor = store.database().inner().journal_head()?;
    let mut checked = false;
    assert_eq!(
        store.admit_managed(&fixture.spec, &fixture.grant, || {
            checked = true;
            Ok(())
        })?,
        admitted
    );
    assert!(checked);
    assert_eq!(store.database().inner().journal_head()?, cursor);
    assert_eq!(
        initial.managed_version([1; 16], "counts", admitted.generation, &control)?,
        fixture.spec
    );
    let started =
        store.set_managed_running([1; 16], "counts", admitted.lifecycle, true, || Ok(()))?;
    assert!(started.running);
    let active = store.view()?;
    assert_eq!(active.active_managed(&control)?.1.len(), 1);
    let stopped = store.stop_managed(&started, || Ok(()))?;
    assert!(!stopped.running);
    assert_eq!(stopped.generation, admitted.generation);
    assert!(store.view()?.active_managed(&control)?.1.is_empty());
    assert_eq!(fixture.admit(&store)?, stopped);
    assert_eq!(
        initial.managed_instance([1; 16], "counts", &control)?,
        Some(admitted.clone())
    );
    assert_eq!(
        active.managed_instance([1; 16], "counts", &control)?,
        Some(started.clone())
    );
    store.database().inner().flush_memtables()?;
    store.database().inner().major_compact()?;
    drop((before, initial, active, view));
    drop(store);
    let store = NativeStore::open(&root)?;
    assert_eq!(fixture.admit(&store)?, stopped);
    assert_eq!(
        store
            .read_at(admitted.generation)?
            .managed_instance([1; 16], "counts", &control)?,
        Some(admitted)
    );
    assert_eq!(
        store
            .read_at(started.lifecycle)?
            .managed_instance([1; 16], "counts", &control)?,
        Some(started)
    );
    assert_eq!(
        store.view()?.managed_graph([1; 16], "counts", &control)?,
        Some(graph)
    );
    assert!(!root.join("analysis.duckdb").exists());
    Ok(())
}

#[test]
fn guarded_admission_and_joint_staging_roll_back() -> TestResult {
    use araphor_data::{AnalysisContextKeyV1, AnalysisContextVersionV1, ContextSensitivityV1};

    let dir = tempfile::tempdir()?;
    let store = NativeStore::open(&dir.path().join("store"))?;
    let fixture = Fixture::new(&store, [1; 16], "joint", true)?;
    let revision = store.view()?.revision();
    let cursor = store.database().inner().journal_head()?;
    let denied = || Err(Code::Denied.error("managed guard"));
    assert!(store
        .admit_managed(&fixture.spec, &fixture.grant, denied)
        .is_err());
    assert_eq!(store.view()?.revision(), revision);
    assert_eq!(store.database().inner().journal_head()?, cursor);
    assert!(store
        .view()?
        .snapshot()
        .prefix(b"\0graph/")
        .next()
        .is_none());
    let context = AnalysisContextVersionV1 {
        key: AnalysisContextKeyV1 {
            tenant_id: [1; 16],
            owner_id: "managed-test".into(),
            entity_key: vec![1],
            lifetime_key: vec![2],
            owner_revision: 1,
        },
        valid_from_utc_ns: None,
        valid_until_utc_ns: None,
        sensitivity: ContextSensitivityV1::Tenant,
        body: vec![3],
    };
    {
        let mut tx = store.write()?;
        let staged = tx.admit_managed(&fixture.spec, &fixture.grant)?;
        assert_eq!(staged.generation, revision + 1);
        assert!(store
            .view()?
            .managed_graph([1; 16], "joint", &AnalysisReadControl::default())?
            .is_none());
        tx.context(&context, Some(0))?;
        tx.rollback();
    }
    assert_eq!(store.database().inner().journal_head()?, cursor);
    {
        let (key, bytes) = store
            .view()?
            .snapshot()
            .prefix(b"\0data/I")
            .next()
            .ok_or("image")??;
        let (tenant, image, digest, revision, _): (
            [u8; 16],
            araphor_data::PackageRefV1,
            String,
            u64,
            bool,
        ) = rmp_serde::from_slice(&bytes[1..])?;
        let mut tx = store.write()?;
        tx.native().insert(
            key,
            [
                vec![0],
                rmp_serde::to_vec(&(tenant, image, digest, revision, false))?,
            ]
            .concat(),
        );
        assert!(matches!(
            tx.admit_managed(&fixture.spec, &fixture.grant),
            Err(Error::Package {
                code: Code::Missing,
                ..
            })
        ));
        tx.rollback();
    }
    assert_eq!(store.database().inner().journal_head()?, cursor);
    let mut feed = store.database().inner().journal_feed(cursor)?;
    let mut tx = store.write()?;
    let instance = tx.admit_managed(&fixture.spec, &fixture.grant)?;
    assert_eq!(tx.admit_managed(&fixture.spec, &fixture.grant)?, instance);
    let reference = tx.context(&context, Some(0))?;
    assert_eq!(reference.commit_revision, instance.generation);
    let receipt = tx.commit([])?.ok_or("managed commit")?;
    let batch = feed.next_batch()?.ok_or("managed journal batch")?;
    assert_eq!(batch.cursor, receipt.cursor);
    assert_eq!(batch.revision(), receipt.revision);
    assert!(feed.next_batch()?.is_none());
    for prefix in [
        b"\0data/Z".as_slice(),
        b"\0data/J",
        b"\0data/Q",
        b"\0data/G",
        b"\0data/C",
        b"\0graph/f",
        b"\0graph/w",
    ] {
        assert!(
            batch.items.iter().any(|item| item.key.starts_with(prefix)),
            "missing {prefix:?}"
        );
    }
    let published = store.view()?;
    assert_eq!(
        published.managed_instance([1; 16], "joint", &AnalysisReadControl::default())?,
        Some(instance)
    );
    assert_eq!(
        published.context(&context.key)?,
        Some((context, reference.commit_revision))
    );
    assert!(store
        .admit_managed(&fixture.spec, &fixture.grant, denied)
        .is_err());
    assert_eq!(store.view()?.revision(), published.revision());
    Ok(())
}

#[test]
fn lifecycle_preserves_cas_noops_and_stop_identity() -> TestResult {
    let dir = tempfile::tempdir()?;
    let store = NativeStore::open(&dir.path().join("store"))?;
    let fixture = Fixture::new(&store, [1; 16], "counts", false)?;
    let admitted = fixture.admit(&store)?;
    let cursor = store.database().inner().journal_head()?;
    let mut checked = false;
    assert_eq!(
        store.set_managed_running([1; 16], "counts", admitted.lifecycle, false, || {
            checked = true;
            Ok(())
        })?,
        admitted
    );
    assert!(checked);
    assert_eq!(store.database().inner().journal_head()?, cursor);
    assert!(store
        .set_managed_running([1; 16], "counts", admitted.lifecycle, true, || Err(
            Code::Denied.error("start guard")
        ))
        .is_err());
    assert_eq!(store.database().inner().journal_head()?, cursor);
    let fenced = store.stop_managed(&admitted, || Ok(()))?;
    assert!(fenced.lifecycle > admitted.lifecycle);
    assert!(store.stop_managed(&admitted, || Ok(())).is_err());
    let cursor = store.database().inner().journal_head()?;
    assert_eq!(store.stop_managed(&fenced, || Ok(()))?, fenced);
    assert_eq!(store.database().inner().journal_head()?, cursor);
    let running =
        store.set_managed_running([1; 16], "counts", fenced.lifecycle, true, || Ok(()))?;
    assert!(store
        .set_managed_running([1; 16], "counts", fenced.lifecycle, true, || Ok(()))
        .is_err());
    let cursor = store.database().inner().journal_head()?;
    assert_eq!(
        store.set_managed_running([1; 16], "counts", running.lifecycle, true, || Ok(()))?,
        running
    );
    assert_eq!(store.database().inner().journal_head()?, cursor);
    let mut unrelated = running.clone();
    unrelated.grant.principal = "other".into();
    assert!(store.stop_managed(&unrelated, || Ok(())).is_err());
    let mut captured = running.clone();
    captured.progress = 999;
    captured.running = false;
    let stopped = store.stop_managed(&captured, || Ok(()))?;
    assert!(!stopped.running);
    let control = AnalysisReadControl::default();
    control.cancel()?;
    assert!(matches!(
        store.view()?.active_managed(&control),
        Err(Error::AnalysisReadCancelled { .. })
    ));
    assert!(matches!(
        store.view()?.managed_instance([1; 16], "counts", &control),
        Err(Error::AnalysisReadCancelled { .. })
    ));
    assert!(matches!(
        store
            .view()?
            .managed_version([1; 16], "counts", admitted.generation, &control),
        Err(Error::AnalysisReadCancelled { .. })
    ));
    Ok(())
}

#[test]
fn exact_pins_and_installed_admission() -> TestResult {
    let dir = tempfile::tempdir()?;
    let store = NativeStore::open(&dir.path().join("store"))?;
    let fixture = Fixture::new(&store, [1; 16], "pins", false)?;
    let revision = store.view()?.revision();
    for change in 0..5 {
        let mut spec = fixture.spec.clone();
        let call = spec.manifest.calls.get_mut(&10).ok_or("call")?;
        match change {
            0 => spec.manifest.definition += 100,
            1 => call.target = "wasm".into(),
            2 => call.export = "missing".into(),
            3 => call.package.revision = "missing".into(),
            _ => spec.tenant = [2; 16],
        }
        assert!(store
            .admit_managed(&spec, &fixture.grant, || Ok(()))
            .is_err());
        assert_eq!(store.view()?.revision(), revision);
    }
    let admitted = fixture.admit(&store)?;
    let mut changed = fixture.spec.clone();
    changed
        .manifest
        .calls
        .get_mut(&10)
        .ok_or("call")?
        .arguments
        .push("changed".into());
    assert!(store
        .admit_managed(&changed, &fixture.grant, || Ok(()))
        .is_err());
    let view = store.view()?;
    let (key, bytes) = view
        .snapshot()
        .prefix(b"\0data/I")
        .next()
        .ok_or("image")??;
    let (tenant, root, digest, revision, _): (
        [u8; 16],
        araphor_data::PackageRefV1,
        String,
        u64,
        bool,
    ) = rmp_serde::from_slice(&bytes[1..])?;
    let mut tx = store.write()?;
    tx.native().insert(
        key,
        [
            vec![0],
            rmp_serde::to_vec(&(tenant, root, digest, revision, false))?,
        ]
        .concat(),
    );
    for entry in view.snapshot().prefix(b"\0data/A") {
        tx.native().remove(entry?.0);
    }
    tx.commit([])?;
    assert_eq!(fixture.admit(&store)?, admitted);
    let mut another = fixture.spec.clone();
    another.id = "new-instance".into();
    assert!(matches!(
        store.admit_managed(&another, &fixture.grant, || Ok(())),
        Err(Error::Package {
            code: Code::Missing,
            ..
        })
    ));
    drop(view);
    drop(store);
    let store = NativeStore::open(&dir.path().join("store"))?;
    assert_eq!(fixture.admit(&store)?, admitted);
    Ok(())
}

#[test]
fn long_names_tenant_isolation_and_raw_interleave() -> TestResult {
    use araphor_data::{EvidenceIntakeIdentityV1, ValidatedEvidenceBatchV1};

    let dir = tempfile::tempdir()?;
    let root = dir.path().join("store");
    let store = NativeStore::open(&root)?;
    let name = "instance".repeat(u16::MAX as usize / 3);
    let a = Fixture::new(&store, [2; 16], &name, false)?;
    let b = Fixture::new(&store, [1; 16], &name, false)?;
    let first = a.admit(&store)?;
    let second = b.admit(&store)?;
    let a = store.set_managed_running([2; 16], &name, first.lifecycle, true, || Ok(()))?;
    let b = store.set_managed_running([1; 16], &name, second.lifecycle, true, || Ok(()))?;
    let metadata = store.view()?.revision();
    store.accept_validated_batch(
        EvidenceIntakeIdentityV1 {
            tenant_id: [1; 16],
            node_id: "node-a".into(),
            node_boot_id: [2; 16],
            label_epoch: 1,
            source_id: [3; 16],
            source_epoch: 1,
        },
        ValidatedEvidenceBatchV1 {
            cpu_id: 0,
            first_cursor: 1,
            last_cursor: 1,
            intake_utc_ns: 10,
            framed_records: vec![1].into(),
            frame_ends: vec![1],
        },
    )?;
    let raw = store.view()?.revision();
    assert_eq!(raw, metadata + 1);
    let control = AnalysisReadControl::default();
    let (revision, active) = store.view()?.active_managed(&control)?;
    assert_eq!(revision, raw);
    assert_eq!(
        active.iter().map(|row| row.tenant).collect::<Vec<_>>(),
        vec![[1; 16], [2; 16]]
    );
    assert!(store
        .view()?
        .managed_instance([3; 16], &name, &control)?
        .is_none());
    assert_eq!(
        store
            .read_at(raw)?
            .managed_instance([1; 16], &name, &control)?,
        Some(b.clone())
    );
    drop(store);
    let store = NativeStore::open(&root)?;
    assert_eq!(store.view()?.revision(), raw);
    assert_eq!(
        store.view()?.managed_instance([2; 16], &name, &control)?,
        Some(a)
    );
    assert_eq!(
        store.view()?.managed_instance([1; 16], &name, &control)?,
        Some(b)
    );
    Ok(())
}

#[test]
fn host_lease_holds_the_store_directory() -> TestResult {
    let dir = tempfile::tempdir()?;
    let root = dir.path().join("store");
    let store = Arc::new(NativeStore::open(&root)?);
    let lease = store.lease_managed()?;
    assert!(store.lease_managed().is_err());
    drop(lease);
    let lease = store.lease_managed()?;
    let weak = Arc::downgrade(&store);
    drop(store);
    assert!(weak.upgrade().is_some());
    assert!(NativeStore::open(&root).is_err());
    drop(lease);
    assert!(weak.upgrade().is_none());
    drop(NativeStore::open(&root)?);
    Ok(())
}

#[test]
fn recovery_rejects_missing_managed_records() -> TestResult {
    for prefix in [
        b"\0data/J".as_slice(),
        b"\0data/Z",
        b"\0data/Q",
        b"\0data/B",
        b"\0data/G",
        b"\0graph/f",
        b"\0graph/v",
    ] {
        let dir = tempfile::tempdir()?;
        let root = dir.path().join("store");
        let store = NativeStore::open(&root)?;
        let fixture = Fixture::new(&store, [1; 16], "recovery", true)?;
        let instance = fixture.admit(&store)?;
        store.set_managed_running([1; 16], "recovery", instance.lifecycle, true, || Ok(()))?;
        let (key, _) = store
            .view()?
            .snapshot()
            .prefix(prefix)
            .next()
            .ok_or("record")??;
        let mut tx = store.write()?;
        tx.native().remove(key);
        tx.commit([])?;
        if prefix == b"\0data/G" {
            let cursor = store.database().inner().journal_head()?;
            assert!(fixture.admit(&store).is_err());
            assert_eq!(store.database().inner().journal_head()?, cursor);
        }
        drop(store);
        assert!(
            NativeStore::open(&root).is_err(),
            "accepted missing {prefix:?}"
        );
    }
    Ok(())
}

#[test]
fn current_owner_uses_the_shared_admission_checks() -> TestResult {
    let dir = tempfile::tempdir()?;
    let native = NativeStore::open(&dir.path().join("native"))?;
    let fixture = Fixture::new(&native, [1; 16], "shared", true)?;
    let image = native
        .view()?
        .package_image(
            [1; 16],
            "managed-graph",
            Some("1"),
            &AnalysisReadControl::default(),
        )?
        .ok_or("image")?;
    let store = araphor_data::AnalysisStore::open(dir.path().join("legacy"))?;
    store.install_package_image([1; 16], &image, || Ok(()))?;
    let mut spec = fixture.spec;
    spec.manifest.definition = store.admit_definition([1; 16], &spec.definition, || Ok(()))?;
    let instance = store.admit_managed(&spec, &fixture.grant, || Ok(()))?;
    assert_eq!(
        store.admit_managed(&spec, &fixture.grant, || Ok(()))?,
        instance
    );
    spec.id = "wrong".into();
    spec.manifest.calls.get_mut(&10).ok_or("call")?.target = "wasm".into();
    assert!(matches!(
        store.admit_managed(&spec, &fixture.grant, || Ok(())),
        Err(Error::Package {
            code: Code::Invalid,
            ..
        })
    ));
    Ok(())
}

#[test]
fn graph_mappings_preserve_distinct_writers_and_relations() -> TestResult {
    for writers in [true, false] {
        let dir = tempfile::tempdir()?;
        let root = dir.path().join("store");
        let store = NativeStore::open(&root)?;
        let mut fixture = Fixture::new(&store, [1; 16], "mapping", true)?;
        let call = fixture.spec.manifest.calls.get(&10).ok_or("call")?.clone();
        fixture.spec.manifest.calls.insert(11, call);
        fixture.admit(&store)?;
        let control = AnalysisReadControl::default();
        let mut graph = store
            .view()?
            .managed_graph([1; 16], "mapping", &control)?
            .ok_or("Graph")?;
        if writers {
            graph.writers.insert(11, graph.writers[&10]);
        } else {
            let duplicate = graph.relations["task"].0;
            graph.relations.get_mut("host").ok_or("host")?.0 = duplicate;
        }
        let (key, _) = store
            .view()?
            .snapshot()
            .prefix(b"\0data/G")
            .next()
            .ok_or("mapping")??;
        let mut tx = store.write()?;
        tx.native()
            .insert(key, [vec![0], rmp_serde::to_vec(&graph)?].concat());
        tx.commit([])?;
        assert!(matches!(
            store.view()?.managed_graph([1; 16], "mapping", &control),
            Err(Error::NativeState {
                field: "managed Graph mapping",
                ..
            })
        ));
        drop(store);
        assert!(NativeStore::open(&root).is_err());
    }
    Ok(())
}
