use super::*;
use araphor_data::{
    analysis::native::{ManagedCommit, ManagedReturn},
    AnalysisExtractLimits, AnalysisReadModeV1, AnalysisTableRead, AnalysisTableRequests,
    ManagedAttempt, ManagedExit, ManagedPage, ManagedRead, ManagedReceipt, PackageReadinessV1,
};
use serde::Deserialize as _;

#[path = "lifecycle/activation.rs"]
mod activation;
#[path = "lifecycle/faults.rs"]
mod faults;
#[path = "lifecycle/recovery.rs"]
mod recovery;

fn fixture(store: &NativeStore, id: &str) -> araphor_data::Result<Fixture> {
    let mut fixture = Fixture::new(store, [1; 16], id, false)?;
    fixture.grant.selection = AnalysisSelectionV1::tenant([1; 16]);
    Ok(fixture)
}

fn capture(
    store: &NativeStore,
    target: &ManagedInstance,
    expected: Option<&ManagedInstance>,
) -> araphor_data::Result<ManagedPage> {
    let requests = AnalysisTableRequests::new();
    let selection = target.grant.selection.project(&requests)?;
    store.read_managed_tables_filtered(
        &selection,
        &ManagedRead {
            instance: target.clone(),
            expected: expected.cloned(),
            rebuild: false,
            follow: false,
            source: None,
            completed: None,
            execution: None,
        },
        AnalysisTableRead {
            requests: &requests,
            event_ranges: None,
            mode: AnalysisReadModeV1::Complete,
            now: 1000,
        },
        AnalysisExtractLimits::default(),
        &AnalysisReadControl::default(),
        None,
    )
}

fn publish(
    store: &NativeStore,
    attempt: &ManagedAttempt,
    reject: bool,
) -> Result<ManagedReceipt, Box<dyn std::error::Error>> {
    let evaluation = super::publication::evaluation(attempt);
    let schema = attempt.instance().spec.manifest.selected_schema.clone();
    let model = sdk::Model::new(
        "count",
        Vec::new(),
        vec![sdk::Port::new("rows", schema.clone())],
    );
    let output = super::publication::output(&model)?;
    let returns = attempt
        .instance()
        .spec
        .manifest
        .calls
        .keys()
        .map(|call| ManagedReturn {
            call: *call,
            evaluation: &evaluation,
            output: &output,
            changes: None,
            graph: None,
            retained: None,
        })
        .collect::<Vec<_>>();
    let control = AnalysisReadControl::default();
    let input = ManagedCommit {
        control: &control,
        budget: &super::graph::Budget,
        attempt,
        completed: true,
        now_utc_ns: 1000,
        returns: &returns,
        selected: &output.datasets[0],
        selected_schema: &schema,
    };
    Ok(store.commit_managed(store.prepare_managed(&input)?, || {
        if reject {
            Err(Code::Denied.error("test publication guard"))
        } else {
            Ok(())
        }
    })?)
}

#[test]
fn renewal_and_admission_authority() -> TestResult {
    let dir = tempfile::tempdir()?;
    let root = dir.path().join("data");
    let store = NativeStore::open(&root)?;
    let fixture = fixture(&store, "authority")?;
    let admitted = fixture.admit(&store)?;
    let cursor = store.database().inner().journal_head()?;
    let mut checked = false;
    assert_eq!(
        store.renew_managed(&admitted, &admitted.grant, || {
            checked = true;
            Ok(())
        })?,
        admitted
    );
    assert!(checked);
    assert_eq!(store.database().inner().journal_head()?, cursor);
    let mut grant = admitted.grant.clone();
    grant.principal = "renewed".into();
    grant.revision += 1;
    assert!(store
        .renew_managed(&admitted, &grant, || Err(Code::Denied.error("renew guard")))
        .is_err());
    assert_eq!(store.database().inner().journal_head()?, cursor);
    let mut wrong = grant.clone();
    wrong.selection = AnalysisSelectionV1::new([1; 16], Vec::new());
    assert!(store.renew_managed(&admitted, &wrong, || Ok(())).is_err());
    let renewed = store.renew_managed(&admitted, &grant, || Ok(()))?;
    assert_eq!(renewed.generation, admitted.generation);
    assert!(renewed.lifecycle > admitted.lifecycle);
    assert!(store.renew_managed(&admitted, &grant, || Ok(())).is_err());
    let running =
        store.set_managed_running([1; 16], "authority", renewed.lifecycle, true, || Ok(()))?;
    assert!(store.renew_managed(&running, &grant, || Ok(())).is_err());
    let control = AnalysisReadControl::default();
    let resume = store.managed_resume([1; 16], "authority", &control)?;
    assert_eq!(
        store.fail_managed(&resume, Code::Invalid, || Ok(()))?,
        running
    );
    let revision = store.view()?.revision();
    assert!(revision > running.lifecycle);
    assert_eq!(
        store.fail_managed(&resume, Code::Invalid, || Ok(()))?,
        running
    );
    assert_eq!(store.view()?.revision(), revision);
    drop(store);
    let store = NativeStore::open(&root)?;
    assert!(matches!(
        store
            .managed_status(&grant.selection, "authority", &control)?
            .readiness,
        PackageReadinessV1::Failed {
            code: Code::Invalid,
            ..
        }
    ));
    let page = capture(&store, &running, None)?;
    let attempt = store.register_managed_attempt(
        &page.state,
        &super::attempts::request("pending", false),
        || Ok(()),
    )?;
    assert!(matches!(
        store.fail_managed(&resume, Code::Denied, || Ok(())),
        Err(Error::AnalysisBusy {
            resource: "managed attempt",
            ..
        })
    ));
    assert!(store.remove_managed(&running, || Ok(())).is_err());
    store.finish_managed(&attempt, ManagedExit::Cancelled, || Ok(()))?;
    assert!(store
        .fail_managed(&resume, Code::Denied, || Ok(()))
        .is_err());
    let resume = store.managed_resume([1; 16], "authority", &control)?;
    let stopped = store.fail_managed(&resume, Code::Denied, || Ok(()))?;
    assert!(!stopped.running);
    assert!(stopped.lifecycle > running.lifecycle);
    drop((page, attempt, store));
    let store = NativeStore::open(&root)?;
    assert_eq!(
        store.managed_instance([1; 16], "authority", &control)?,
        Some(stopped.clone())
    );
    assert!(matches!(
        store
            .managed_status(&grant.selection, "authority", &control)?
            .readiness,
        PackageReadinessV1::Failed {
            code: Code::Denied,
            ..
        }
    ));
    let removed = store.remove_managed(&stopped, || Ok(()))?;
    assert!(removed.removed);
    drop(store);
    NativeStore::open(&root)?;
    Ok(())
}

#[test]
fn retired_inputs_preserve_revival() -> TestResult {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("data");
    let store = Arc::new(NativeStore::open(&root)?);
    let fixture = fixture(&store, "retired-inputs")?;
    let admitted = fixture.admit(&store)?;
    let requests = [("events".into(), None)].into();
    let control = AnalysisReadControl::default();
    let original = store.subscribe_managed_inputs(
        &admitted,
        &admitted.grant.selection,
        &requests,
        None,
        &control,
        &super::graph::Budget,
    )?;
    super::attempts::append(&store, 1)?;
    let first = store.view()?;
    let first_anchor = (
        first.revision(),
        first.snapshot().cursor()?.ok_or("first anchor")?,
    );
    drop(first);
    store.database().inner().flush_memtables()?;
    store.database().inner().rotate_journal()?;
    let mut updated = admitted.spec.clone();
    let call = updated.manifest.calls.remove(&10).ok_or("call")?;
    updated.manifest.calls.insert(11, call);
    let candidate = store.prepare_managed_version(&admitted, &updated, || Ok(()))?;
    let page = capture(&store, &candidate, Some(&admitted))?;
    let attempt = store.register_managed_attempt(
        &page.state,
        &super::attempts::request("promote", false),
        || Ok(()),
    )?;
    publish(&store, &attempt, false)?;
    let current = store
        .managed_instance([1; 16], "retired-inputs", &control)?
        .ok_or("promoted instance")?;
    let promoted = store.subscribe_managed_inputs(
        &current,
        &current.grant.selection,
        &requests,
        None,
        &control,
        &super::graph::Budget,
    )?;
    super::attempts::append(&store, 2)?;
    let second = store.view()?;
    let second_anchor = (
        second.revision(),
        second.snapshot().cursor()?.ok_or("second anchor")?,
    );
    drop(second);
    store.database().inner().flush_memtables()?;
    store.database().inner().rotate_journal()?;
    let check = |store: &NativeStore| -> TestResult {
        for (revision, cursor) in [first_anchor, second_anchor] {
            assert_eq!(store.read_at(revision)?.snapshot().cursor()?, Some(cursor));
        }
        Ok(())
    };
    store.checkpoint()?;
    check(&store)?;
    let removed = store.remove_managed(&current, || Ok(()))?;
    store.checkpoint()?;
    check(&store)?;
    drop((page, attempt, original, promoted, store));
    let store = Arc::new(NativeStore::open(&root)?);
    check(&store)?;
    let recreated = store.recreate_managed(&removed, &fixture.spec, &fixture.grant, || Ok(()))?;
    store.checkpoint()?;
    check(&store)?;
    let revived = store.prepare_managed_version(&recreated, &updated, || Ok(()))?;
    assert_eq!(revived.generation, candidate.generation);
    let page = capture(&store, &revived, Some(&recreated))?;
    let attempt = store.register_managed_attempt(
        &page.state,
        &super::attempts::request("revive", false),
        || Ok(()),
    )?;
    publish(&store, &attempt, false)?;
    let current = store
        .managed_instance([1; 16], "retired-inputs", &control)?
        .ok_or("revived instance")?;
    assert_eq!(current.generation, candidate.generation);
    let input = store.subscribe_managed_inputs(
        &current,
        &current.grant.selection,
        &requests,
        None,
        &control,
        &super::graph::Budget,
    )?;
    assert_eq!(input.position().commit_revision, second_anchor.0);
    store.checkpoint()?;
    check(&store)?;
    drop((page, attempt, input, store));
    let store = Arc::new(NativeStore::open(&root)?);
    check(&store)?;
    assert_eq!(
        store.managed_instance([1; 16], "retired-inputs", &control)?,
        Some(current)
    );
    Ok(())
}

#[test]
fn version_lifecycle_keeps_history() -> TestResult {
    let dir = tempfile::tempdir()?;
    let root = dir.path().join("data");
    let store = NativeStore::open(&root)?;
    let fixture = fixture(&store, "versions")?;
    let admitted = fixture.admit(&store)?;
    let page = capture(&store, &admitted, None)?;
    let first = store.register_managed_attempt(
        &page.state,
        &super::attempts::request("first", false),
        || Ok(()),
    )?;
    let receipt = publish(&store, &first, false)?;
    let control = AnalysisReadControl::default();
    let current = store
        .managed_instance([1; 16], "versions", &control)?
        .ok_or("instance")?;
    let mut updated = current.spec.clone();
    let call = updated.manifest.calls.remove(&10).ok_or("call")?;
    updated.manifest.calls.insert(11, call);
    let revision = store.view()?.revision();
    assert!(store
        .prepare_managed_version(&current, &updated, || Err(
            Code::Denied.error("version guard")
        ))
        .is_err());
    assert_eq!(store.view()?.revision(), revision);
    let candidate = store.prepare_managed_version(&current, &updated, || Ok(()))?;
    assert!(candidate.generation > current.generation);
    assert_eq!(
        store.managed_instance([1; 16], "versions", &control)?,
        Some(current.clone())
    );
    let cursor = store.database().inner().journal_head()?;
    assert_eq!(
        store.prepare_managed_version(&current, &updated, || Ok(()))?,
        candidate
    );
    assert_eq!(store.database().inner().journal_head()?, cursor);
    let page = capture(&store, &candidate, Some(&current))?;
    let attempt = store.register_managed_attempt(
        &page.state,
        &super::attempts::request("switch", false),
        || Ok(()),
    )?;
    assert!(store
        .prepare_managed_version(&current, &updated, || Ok(()))
        .is_err());
    assert!(store.remove_managed(&current, || Ok(())).is_err());
    assert!(publish(&store, &attempt, true).is_err());
    assert_eq!(
        store.managed_instance([1; 16], "versions", &control)?,
        Some(current.clone())
    );
    let switched = publish(&store, &attempt, false)?;
    let current = store
        .managed_instance([1; 16], "versions", &control)?
        .ok_or("switched")?;
    assert_eq!(current.generation, candidate.generation);
    assert_eq!(current.progress, switched.commit_revision);
    assert_eq!(current.lifecycle, switched.commit_revision);
    let selection = current.grant.selection.clone();
    assert_eq!(
        store.managed_history(&selection, "versions", &control)?,
        vec![receipt.clone(), switched.clone()]
    );
    drop((page, first, attempt, store));
    let store = NativeStore::open(&root)?;
    let rollback = store.prepare_managed_version(&current, &fixture.spec, || Ok(()))?;
    assert_eq!(rollback.generation, admitted.generation);
    let page = capture(&store, &rollback, Some(&current))?;
    let attempt = store.register_managed_attempt(
        &page.state,
        &super::attempts::request("rollback", false),
        || Ok(()),
    )?;
    let rolled = publish(&store, &attempt, false)?;
    let current = store
        .managed_instance([1; 16], "versions", &control)?
        .ok_or("rollback")?;
    assert_eq!(current.generation, admitted.generation);
    assert_eq!(current.progress, rolled.commit_revision);
    assert_eq!(current.lifecycle, rolled.commit_revision);
    assert!(current.lifecycle > candidate.generation);
    drop((page, attempt, store));
    let store = NativeStore::open(&root)?;
    assert_eq!(
        store.managed_instance([1; 16], "versions", &control)?,
        Some(current.clone())
    );
    let before = store.view()?;
    assert!(store
        .remove_managed(&current, || Err(Code::Denied.error("remove guard")))
        .is_err());
    assert_eq!(store.view()?.revision(), before.revision());
    let removed = store.remove_managed(&current, || Ok(()))?;
    let cursor = store.database().inner().journal_head()?;
    assert_eq!(store.remove_managed(&removed, || Ok(()))?, removed);
    assert_eq!(store.database().inner().journal_head()?, cursor);
    assert!(store.managed_resume([1; 16], "versions", &control).is_err());
    drop((before, store));
    let store = NativeStore::open(&root)?;
    let view = store.view()?;
    assert_eq!(
        view.managed_instance([1; 16], "versions", &control)?,
        Some(removed.clone())
    );
    assert!(store
        .recreate_managed(&removed, &fixture.spec, &fixture.grant, || Err(
            Code::Denied.error("recreate guard")
        ))
        .is_err());
    assert_eq!(store.view()?.revision(), view.revision());
    let recreated = store.recreate_managed(&removed, &fixture.spec, &fixture.grant, || Ok(()))?;
    assert!(!recreated.running && !recreated.removed);
    assert_eq!(recreated.progress, 0);
    assert!(recreated.generation > candidate.generation);
    assert!(store
        .recreate_managed(&removed, &fixture.spec, &fixture.grant, || Ok(()))
        .is_err());
    assert_eq!(
        store.managed_version([1; 16], "versions", admitted.generation, &control)?,
        fixture.spec
    );
    assert_eq!(
        store.managed_version([1; 16], "versions", candidate.generation, &control)?,
        updated
    );
    assert_eq!(
        view.managed_instance([1; 16], "versions", &control)?,
        Some(removed)
    );
    drop((view, store));
    let store = NativeStore::open(&root)?;
    assert_eq!(
        store.managed_instance([1; 16], "versions", &control)?,
        Some(recreated)
    );
    assert_eq!(
        store.managed_history(&selection, "versions", &control)?,
        vec![receipt, switched, rolled]
    );
    Ok(())
}

#[test]
fn history_uses_captured_grants() -> TestResult {
    let dir = tempfile::tempdir()?;
    let root = dir.path().join("data");
    let store = NativeStore::open(&root)?;
    let fixture = Fixture::new(&store, [1; 16], "history", false)?;
    let narrow = fixture.grant.selection.clone();
    let admitted = fixture.admit(&store)?;
    let page = capture(&store, &admitted, None)?;
    let attempt = store.register_managed_attempt(
        &page.state,
        &super::attempts::request("old", false),
        || Ok(()),
    )?;
    store.finish_managed(&attempt, ManagedExit::Cancelled, || Ok(()))?;
    let removed = store.remove_managed(&admitted, || Ok(()))?;
    let mut grant = fixture.grant.clone();
    grant.selection = AnalysisSelectionV1::tenant([1; 16]);
    store.recreate_managed(&removed, &fixture.spec, &grant, || Ok(()))?;
    let control = AnalysisReadControl::default();
    assert!(grant.permitted_by(&narrow).is_err());
    assert!(store
        .managed_history(&narrow, "history", &control)?
        .is_empty());
    // This stored-record fixture checks pending-only history authorization.
    let (key, bytes) = store
        .view()?
        .snapshot()
        .prefix(b"\0data/a")
        .find_map(|row| row.ok().filter(|(key, _)| key.len() == 15))
        .ok_or("attempt")?;
    let mut saved: serde_value::Value = rmp_serde::from_slice(&bytes[1..])?;
    *super::attempts::field(&mut saved, &["terminal"])? = serde_value::Value::Option(None);
    let registered =
        u64::deserialize(super::attempts::field(&mut saved, &["registered"])?.clone())?;
    let mut tx = store.write()?;
    tx.native()
        .insert(key, [vec![0], rmp_serde::to_vec_named(&saved)?].concat());
    let (ended, id) = store
        .view()?
        .snapshot()
        .prefix(b"\0data/E")
        .next()
        .ok_or("outcome")??;
    let (outcome, _) = store
        .view()?
        .snapshot()
        .prefix(b"\0data/o")
        .next()
        .ok_or("head")??;
    tx.native().remove(ended);
    let pending = [b"\0data/p".as_slice(), &outcome[7..], id.as_ref()].concat();
    tx.native().remove(outcome);
    tx.native().insert(pending, registered.to_be_bytes());
    tx.commit([])?;
    assert!(store
        .managed_history(&narrow, "history", &control)?
        .is_empty());
    let cancelled = AnalysisReadControl::default();
    cancelled.cancel()?;
    assert!(store
        .managed_history(&narrow, "history", &cancelled)
        .is_err());
    Ok(())
}
