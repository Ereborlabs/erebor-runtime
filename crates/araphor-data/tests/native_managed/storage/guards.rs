use super::*;

#[path = "guards/current.rs"]
mod current;

#[test]
fn managed_images_reject_forged_implementation_pin() -> TestResult {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("store");
    let store = NativeStore::open(&root)?;
    let fixture = StorageFixture::new(&store, "counter", "Retain independent call state.".into())?;
    let before = store.view()?;
    let baseline = records(&before, b"")?;
    assert_eq!(
        store.admit_managed(&fixture.instance.spec, &fixture.instance.grant, || Ok(()))?,
        fixture.instance
    );
    let identity = PackageImplementationV1::Wasm {
        exports: vec!["evaluate".into()],
        artifact: araphor_analysis_builtins::components::RUNTIME.to_vec(),
    }
    .identity()?
    .ok_or("Wasm identity absent")?;
    for artifact in [false, true] {
        let mut spec = fixture.instance.spec.clone();
        let call = spec
            .manifest
            .calls
            .get_mut(&10)
            .ok_or("managed call absent")?;
        if artifact {
            call.artifact = Some(identity.clone());
        } else {
            call.target = "forged-target".into();
        }
        assert!(matches!(
            store.admit_managed(&spec, &fixture.instance.grant, || Ok(())),
            Err(Error::Package {
                code: Code::Invalid,
                field: "managed implementation pin",
                ..
            })
        ));
    }
    for field in ["body", "revision", "tenant"] {
        let mut spec = fixture.instance.spec.clone();
        let mut grant = fixture.instance.grant.clone();
        match field {
            "body" => spec.definition.definition.description.push_str(" changed"),
            "revision" => spec.manifest.definition = store.meta()?.commit_revision + 1,
            "tenant" => {
                spec.tenant = [2; 16];
                grant.selection.tenant_id = spec.tenant;
            }
            _ => unreachable!(),
        }
        assert!(
            matches!(
                store.admit_managed(&spec, &grant, || Ok(())),
                Err(Error::Package {
                    code: Code::Missing,
                    field: "managed definition pin",
                    ..
                })
            ),
            "{field}"
        );
    }
    let current = store.view()?;
    assert_eq!(current.meta(), before.meta());
    assert_eq!(current.snapshot().revision(), before.snapshot().revision());
    assert_eq!(records(&current, b"")?, baseline);
    let definitions = records(&current, b"\0data/D")?
        .into_iter()
        .filter(|(key, _)| key.len() == 23)
        .collect::<Vec<_>>();
    assert_eq!(definitions.len(), 1);
    let (key, bytes) = &definitions[0];
    let (tenant, body, revision): ([u8; 16], Vec<u8>, u64) =
        rmp_serde::from_slice(bytes.strip_prefix(&[0]).ok_or("definition envelope")?)?;
    assert_eq!(tenant, fixture.instance.spec.tenant);
    assert_eq!(revision, fixture.instance.spec.manifest.definition);
    assert_eq!(body, fixture.instance.spec.definition.encode()?);
    let heads = records(&current, b"\0data/F")?;
    drop(current);
    drop(before);
    let mut changed = fixture.instance.spec.definition.clone();
    changed.definition.description.push_str(" changed");
    let mut writer = store.write()?;
    writer.native().insert(
        key,
        [
            vec![0],
            rmp_serde::to_vec(&(tenant, changed.encode()?, revision))?,
        ]
        .concat(),
    );
    writer.commit([])?;
    assert_eq!(records(store.view()?.as_ref(), b"\0data/F")?, heads);
    assert!(matches!(
        store.admit_managed(&fixture.instance.spec, &fixture.instance.grant, || Ok(())),
        Err(Error::Package {
            code: Code::Missing,
            field: "managed definition pin",
            ..
        })
    ));
    drop(store);
    assert!(matches!(
        NativeStore::open(&root),
        Err(Error::Package {
            code: Code::Missing,
            field: "managed definition pin",
            ..
        })
    ));
    Ok(())
}

#[derive(Debug, PartialEq)]
struct GuardCut {
    meta: araphor_data::AnalysisStoreMetaV1,
    instance: ManagedInstance,
    prior: Vec<(u64, u64, String)>,
    heads: BTreeMap<Vec<u8>, Vec<u8>>,
    attempts: BTreeMap<Vec<u8>, Vec<u8>>,
    history: Vec<ManagedReceipt>,
    states: BTreeMap<Vec<u8>, Vec<u8>>,
    counts: [u64; 8],
    references: BTreeMap<Vec<u8>, Vec<u8>>,
    journal: Option<fjall::Cursor>,
}

impl GuardCut {
    fn read(
        store: &NativeStore,
        fixture: &StorageFixture,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let captured = fixture.capture(store)?;
        let prior = [10, 11]
            .into_iter()
            .filter_map(|call| {
                captured
                    .prior(call)
                    .map(|prior| (call, prior.revision, prior.result.clone()))
            })
            .collect();
        let view = store.view()?;
        let heads = records(&view, b"\0data/Q")?;
        let attempts = records(&view, b"\0data/a")?;
        let mut states = records(&view, b"\0data/X")?;
        states.extend(records(&view, b"\0data/U")?);
        let mut counts = [0; 8];
        for (index, (prefix, suffix)) in [
            (b"\0data/Z".as_slice(), 16),
            (b"\0data/J".as_slice(), 8),
            (b"\0data/Q".as_slice(), 16),
            (b"\0data/a".as_slice(), 8),
            (b"\0data/X".as_slice(), 8),
            (b"\0data/ref/dependency/".as_slice(), 16),
            (b"\0data/ref/evidence/".as_slice(), 24),
            (b"\0data/ref/context/".as_slice(), 16),
        ]
        .into_iter()
        .enumerate()
        {
            counts[index] = records(&view, prefix)?
                .keys()
                .filter(|key| key.len() == prefix.len() + suffix)
                .count() as u64;
        }
        Ok(Self {
            meta: store.meta()?,
            instance: captured.instance().clone(),
            prior,
            heads,
            attempts,
            history: store.managed_history(
                &captured.instance().grant.selection,
                &captured.instance().spec.id,
                &AnalysisReadControl::default(),
            )?,
            states,
            counts,
            references: records(&view, b"\0data/ref/")?,
            journal: store.database().inner().journal_head()?,
        })
    }
}

#[test]
fn capture_checks_store_identity() -> TestResult {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("source");
    let store = NativeStore::open(&root)?;
    let fixture = StorageFixture::new(&store, "counter", "Retain independent call state.".into())?;
    let foreign = NativeStore::open(directory.path().join("foreign"))?;
    let other = StorageFixture::new(&foreign, "counter", "Retain independent call state.".into())?;
    let mut receipts = Vec::new();
    for (store, fixture) in [(&store, &fixture), (&foreign, &other)] {
        let captured = fixture.capture(store)?;
        let input = request("seed");
        let attempt = store.register_managed_attempt(&captured, &input, || Ok(()))?;
        receipts.push(fixture.publish(
            store,
            &attempt,
            &[
                fixture.continued(&input, 10, Some(&captured))?,
                fixture.continued(&input, 11, Some(&captured))?,
            ],
            &[fixture.output(12)?, fixture.output(13)?],
        )?);
    }
    assert_eq!(receipts[0], receipts[1]);
    let captured = fixture.capture(&store)?;
    let original = GuardCut::read(&store, &fixture)?;
    let separate = GuardCut::read(&foreign, &other)?;
    assert_ne!(original.meta.store_uuid, separate.meta.store_uuid);
    assert_eq!(original.meta.schema_version, separate.meta.schema_version);
    assert_eq!(original.meta.recovery_epoch, separate.meta.recovery_epoch);
    assert_eq!(original.meta.commit_revision, separate.meta.commit_revision);
    assert_eq!(original.instance, separate.instance);
    assert_eq!(original.prior.len(), 2);
    assert_eq!(original.prior, separate.prior);
    assert_eq!(original.heads, separate.heads);
    assert_eq!(original.history, separate.history);
    assert_eq!(original.states, separate.states);
    assert_eq!(original.counts, separate.counts);
    let rejected = request("foreign-capture");
    assert!(matches!(
        foreign.register_managed_attempt(&captured, &rejected, || Ok(())),
        Err(Error::AnalysisConflict { .. })
    ));
    assert_eq!(GuardCut::read(&foreign, &other)?, separate);
    assert_eq!(GuardCut::read(&store, &fixture)?, original);

    let input = request("pending");
    let attempt = store.register_managed_attempt(&captured, &input, || Ok(()))?;
    let evaluations = [
        fixture.continued(&input, 10, Some(&captured))?,
        fixture.continued(&input, 11, Some(&captured))?,
    ];
    let outputs = [fixture.output(22)?, fixture.output(23)?];
    let pending = GuardCut::read(&store, &fixture)?;
    let backup = root.join("backups/identity");
    let manifest = store.backup(&backup)?;
    assert_eq!(GuardCut::read(&store, &fixture)?, pending);
    let restored = NativeStore::restore(&backup, &directory.path().join("restored"))?;
    let before = GuardCut::read(&restored, &fixture)?;
    assert_eq!(before.meta.store_uuid, pending.meta.store_uuid);
    assert_eq!(before.meta.schema_version, pending.meta.schema_version);
    assert_eq!(before.meta.commit_revision, pending.meta.commit_revision);
    assert_eq!(before.meta.recovery_epoch, manifest.recovery_epoch + 1);
    assert_eq!(manifest.recovery_epoch, pending.meta.recovery_epoch);
    assert_eq!(before.instance, pending.instance);
    assert_eq!(before.prior, pending.prior);
    assert_eq!(before.heads, pending.heads);
    assert_eq!(before.attempts, pending.attempts);
    assert_eq!(before.history, pending.history);
    assert_eq!(before.states, pending.states);
    assert_eq!(before.counts, pending.counts);
    let copied = restored
        .managed_attempt(
            [1; 16],
            "counter",
            &input.id,
            &AnalysisReadControl::default(),
        )?
        .ok_or("restored pending attempt")?;
    assert_eq!(copied.request(), attempt.request());
    assert_eq!(copied.instance(), attempt.instance());
    assert!(copied.receipt().is_none());
    assert!(copied.terminal().is_none());
    let rejected = request("stale-restore");
    assert!(restored
        .managed_attempt(
            [1; 16],
            "counter",
            &rejected.id,
            &AnalysisReadControl::default()
        )?
        .is_none());
    assert!(matches!(
        restored.register_managed_attempt(&captured, &rejected, || Ok(())),
        Err(Error::AnalysisConflict { .. })
    ));
    assert_eq!(GuardCut::read(&restored, &fixture)?, before);
    let error = fixture
        .publish(&restored, &attempt, &evaluations, &outputs)
        .err()
        .ok_or("source live attempt published after restore")?;
    assert!(matches!(
        error.downcast_ref::<Error>(),
        Some(Error::AnalysisConflict { .. })
    ));
    assert_eq!(GuardCut::read(&restored, &fixture)?, before);
    assert_eq!(GuardCut::read(&store, &fixture)?, pending);
    let receipt = fixture.publish(&store, &attempt, &evaluations, &outputs)?;
    assert_eq!(fixture.current(&store)?.progress, receipt.commit_revision);
    assert_eq!(GuardCut::read(&restored, &fixture)?, before);

    let fresh = fixture.capture(&restored)?;
    let input = request("after-restore");
    let attempt = restored.register_managed_attempt(&fresh, &input, || Ok(()))?;
    let receipt = fixture.publish(
        &restored,
        &attempt,
        &[
            fixture.continued(&input, 10, Some(&fresh))?,
            fixture.continued(&input, 11, Some(&fresh))?,
        ],
        &[fixture.output(32)?, fixture.output(33)?],
    )?;
    assert_eq!(
        fixture.current(&restored)?.progress,
        receipt.commit_revision
    );
    assert_eq!(
        restored.managed_history(
            &fixture.instance.grant.selection,
            "counter",
            &AnalysisReadControl::default()
        )?,
        vec![receipts.remove(0), receipt]
    );
    assert!(restored
        .managed_attempt(
            [1; 16],
            "counter",
            "pending",
            &AnalysisReadControl::default()
        )?
        .ok_or("preserved restored pending attempt")?
        .receipt()
        .is_none());
    Ok(())
}
