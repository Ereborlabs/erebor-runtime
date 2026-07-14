use std::{
    env, fs, io,
    path::{Path, PathBuf},
    process::{Child, Command},
    time::Instant,
};

use erebor_runtime_context::{
    test_support::{self, WriteBoundary},
    CommitMetadata, CommitMetadataSource, CommitMetadataSourceError, CommitSignature, CommitTime,
    ContextRepository, ContextRepositoryError, ForkParentAppend, ForkTarget, ScopeRef, ScopeStart,
    Snapshot, TreeEdit,
};

type TestResult<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

const CHILD_MODE: &str = "EREBOR_CONTEXT_RECOVERY_CHILD_MODE";
const REPOSITORY_PATH: &str = "EREBOR_CONTEXT_RECOVERY_REPOSITORY_PATH";
const WRITER_SCOPE: &str = "EREBOR_CONTEXT_RECOVERY_WRITER_SCOPE";
const WRITER_EXPECTED: &str = "EREBOR_CONTEXT_RECOVERY_WRITER_EXPECTED";
const SESSION_ID: &str = "session-8421";
const ABRUPT_EXIT: i32 = 70;
const STALE_WRITER_EXIT: i32 = 71;

#[derive(Clone)]
struct FixedMetadataSource {
    metadata: CommitMetadata,
}

impl FixedMetadataSource {
    fn new() -> TestResult<Self> {
        let time = CommitTime::new(1_700_000_000, 0)?;
        let signature = CommitSignature::new("Erebor Context", "context@erebor.dev", time)?;
        Ok(Self {
            metadata: CommitMetadata::new(signature.clone(), signature),
        })
    }
}

impl CommitMetadataSource for FixedMetadataSource {
    fn metadata(&self) -> std::result::Result<CommitMetadata, CommitMetadataSourceError> {
        Ok(self.metadata.clone())
    }
}

fn snapshot(path: &str, bytes: &[u8]) -> TestResult<Snapshot> {
    Ok(Snapshot::new(vec![TreeEdit::blob(path, bytes)?])?)
}

fn open(path: &Path) -> TestResult<ContextRepository> {
    Ok(ContextRepository::open(path, FixedMetadataSource::new()?)?)
}

fn initialize(
    path: &Path,
) -> TestResult<(ContextRepository, erebor_runtime_context::ContextObjectId)> {
    let repository = ContextRepository::init(path, FixedMetadataSource::new()?)?;
    let root =
        repository.initialize_root(SESSION_ID, snapshot("base", b"base")?, "Initialize root")?;
    Ok((repository, root))
}

#[test]
fn context_repository_recovery_cross_process_contract() -> TestResult<()> {
    match env::var(CHILD_MODE).ok().as_deref() {
        Some(mode) => run_child(mode),
        None => {
            crash_boundaries_leave_only_observable_git_facts()?;
            writers_observe_single_ref_cas_and_independent_scope_progress()?;
            stale_lock_is_not_deleted_by_a_restarted_writer()?;
            Ok(())
        }
    }
}

fn crash_boundaries_leave_only_observable_git_facts() -> TestResult<()> {
    for (mode, expected_scopes, expected_parent_count) in [
        ("blob", 0, None),
        ("tree", 0, None),
        ("commit", 0, None),
        ("single-ref-before", 2, Some(0)),
        ("single-ref-after", 2, Some(1)),
        ("multi-ref-before", 2, Some(0)),
        ("multi-ref-after", 3, Some(1)),
    ] {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("context.git");
        let status = child(&path, mode)?.wait()?;
        assert_eq!(status.code(), Some(ABRUPT_EXIT), "child mode `{mode}`");

        let repository = open(&path)?;
        let scopes = repository.scope_refs()?;
        assert_eq!(scopes.len(), expected_scopes, "child mode `{mode}`");
        assert_eq!(repository.verify_full()?.scope_count(), expected_scopes);
        if let Some(expected_parent_count) = expected_parent_count {
            let parent = ScopeRef::scope(SESSION_ID, "parent")?;
            let parent_head = repository.scope_head(&parent)?;
            assert_eq!(
                repository.read_commit(parent_head)?.parents().len(),
                expected_parent_count,
                "child mode `{mode}`"
            );
        }
    }
    Ok(())
}

fn writers_observe_single_ref_cas_and_independent_scope_progress() -> TestResult<()> {
    let same_directory = tempfile::tempdir()?;
    let same_path = same_directory.path().join("context.git");
    let (same_repository, same_root) = initialize(&same_path)?;
    let same_scope = ScopeRef::scope(SESSION_ID, "same")?;
    same_repository.create_scope(same_scope.clone(), ScopeStart::existing_commit(same_root))?;
    let mut first = writer(&same_path, &same_scope, same_root)?;
    let mut second = writer(&same_path, &same_scope, same_root)?;
    let same_statuses = [first.wait()?, second.wait()?];
    assert_eq!(
        same_statuses
            .iter()
            .filter(|status| status.success())
            .count(),
        1,
        "exactly one writer may advance a checked scope head"
    );
    assert!(same_statuses
        .iter()
        .any(|status| status.code() == Some(STALE_WRITER_EXIT)));
    let recovered_same = open(&same_path)?;
    assert_eq!(
        recovered_same
            .read_commit(recovered_same.scope_head(&same_scope)?)?
            .parents()
            .len(),
        1
    );

    let distinct_directory = tempfile::tempdir()?;
    let distinct_path = distinct_directory.path().join("context.git");
    let (distinct_repository, distinct_root) = initialize(&distinct_path)?;
    let first_scope = ScopeRef::scope(SESSION_ID, "first")?;
    let second_scope = ScopeRef::scope(SESSION_ID, "second")?;
    for scope in [&first_scope, &second_scope] {
        distinct_repository
            .create_scope(scope.clone(), ScopeStart::existing_commit(distinct_root))?;
    }
    let mut first = writer(&distinct_path, &first_scope, distinct_root)?;
    let mut second = writer(&distinct_path, &second_scope, distinct_root)?;
    assert!(first.wait()?.success());
    assert!(second.wait()?.success());
    let recovered = open(&distinct_path)?;
    assert_eq!(
        recovered.scope_head(&first_scope)?,
        recovered.scope_head(&second_scope)?
    );
    assert_eq!(
        recovered
            .read_commit(recovered.scope_head(&first_scope)?)?
            .parents(),
        &[distinct_root]
    );
    assert_eq!(recovered.verify_full()?.scope_count(), 3);
    Ok(())
}

fn stale_lock_is_not_deleted_by_a_restarted_writer() -> TestResult<()> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("context.git");
    let status = child(&path, "stale-lock")?.wait()?;
    assert!(status.success());
    let lock = path.join(format!("{}.lock", ScopeRef::root(SESSION_ID)?.as_str()));
    assert!(lock.exists());
    let recovered = open(&path)?;
    let root = ScopeRef::root(SESSION_ID)?;
    assert_eq!(
        recovered
            .read_commit(recovered.scope_head(&root)?)?
            .parents()
            .len(),
        0
    );
    Ok(())
}

fn child(path: &Path, mode: &str) -> TestResult<Child> {
    Ok(Command::new(env::current_exe()?)
        .arg("context_repository_recovery_cross_process_contract")
        .arg("--exact")
        .arg("--nocapture")
        .env(CHILD_MODE, mode)
        .env(REPOSITORY_PATH, path)
        .spawn()?)
}

fn writer(
    path: &Path,
    scope: &ScopeRef,
    expected: erebor_runtime_context::ContextObjectId,
) -> TestResult<Child> {
    Ok(Command::new(env::current_exe()?)
        .arg("context_repository_recovery_cross_process_contract")
        .arg("--exact")
        .arg("--nocapture")
        .env(CHILD_MODE, "writer")
        .env(REPOSITORY_PATH, path)
        .env(WRITER_SCOPE, scope.as_str())
        .env(WRITER_EXPECTED, expected.to_string())
        .spawn()?)
}

fn run_child(mode: &str) -> TestResult<()> {
    let path = env::var_os(REPOSITORY_PATH)
        .map(PathBuf::from)
        .ok_or_else(|| io::Error::other("missing child repository path"))?;
    match mode {
        "blob" | "tree" | "commit" | "single-ref-before" | "single-ref-after"
        | "multi-ref-before" | "multi-ref-after" => run_crash_boundary(&path, mode),
        "writer" => run_writer(&path),
        "stale-lock" => run_stale_lock(&path),
        _ => Err(io::Error::other(format!("unknown child mode `{mode}`")).into()),
    }
}

fn run_crash_boundary(path: &Path, mode: &str) -> TestResult<()> {
    test_support::clear_exit_after();
    let repository = ContextRepository::init(path, FixedMetadataSource::new()?)?;
    let boundary = match mode {
        "blob" => {
            test_support::exit_after(WriteBoundary::Blob);
            repository.create_tree(snapshot("payload", b"blob")?)?;
            return Err(io::Error::other("blob boundary did not terminate the child").into());
        }
        "tree" => {
            test_support::exit_after(WriteBoundary::Tree);
            repository.create_tree(snapshot("payload", b"tree")?)?;
            return Err(io::Error::other("tree boundary did not terminate the child").into());
        }
        "commit" => {
            test_support::exit_after(WriteBoundary::Commit);
            repository.initialize_root(SESSION_ID, snapshot("payload", b"commit")?, "Commit")?;
            return Err(io::Error::other("commit boundary did not terminate the child").into());
        }
        "single-ref-before" => WriteBoundary::BeforeSingleRefEdit,
        "single-ref-after" => WriteBoundary::AfterSingleRefEdit,
        "multi-ref-before" => WriteBoundary::BeforeMultiRefEdit,
        "multi-ref-after" => WriteBoundary::AfterMultiRefEdit,
        _ => return Err(io::Error::other(format!("unknown crash boundary `{mode}`")).into()),
    };
    let root =
        repository.initialize_root(SESSION_ID, snapshot("base", b"base")?, "Initialize root")?;
    let parent = ScopeRef::scope(SESSION_ID, "parent")?;
    repository.create_scope(parent.clone(), ScopeStart::existing_commit(root))?;
    test_support::exit_after(boundary);
    if mode.starts_with("single-ref") {
        repository.append_snapshot(
            parent,
            root,
            snapshot("single/result", b"single")?,
            "Single append",
        )?;
    } else {
        let child = ScopeRef::scope(SESSION_ID, "child")?;
        let child_tree = repository.create_tree(snapshot("child/result", b"child")?)?;
        let parent_tree = repository.create_tree(snapshot("parent/result", b"parent")?)?;
        repository.fork_scope(
            root,
            child,
            ForkTarget::selected_tree(child_tree, "Child fork"),
            Some(ForkParentAppend::new(
                parent,
                root,
                parent_tree,
                "Parent fork append",
            )),
        )?;
    }
    Err(io::Error::other("ref transaction boundary did not terminate the child").into())
}

fn run_writer(path: &Path) -> TestResult<()> {
    let scope = env::var(WRITER_SCOPE)?;
    let scope = scope_ref(&scope)?;
    let expected = env::var(WRITER_EXPECTED)?.parse()?;
    let repository = open(path)?;
    match repository.append_snapshot(
        scope,
        expected,
        snapshot("writer/result", b"writer")?,
        "Concurrent writer append",
    ) {
        Ok(_) => Ok(()),
        Err(
            ContextRepositoryError::StaleScopeHead { .. }
            | ContextRepositoryError::UpdateScopeRef { .. },
        ) => {
            std::process::exit(STALE_WRITER_EXIT);
        }
        Err(source) => Err(source.into()),
    }
}

fn run_stale_lock(path: &Path) -> TestResult<()> {
    let (repository, root) = initialize(path)?;
    let scope = ScopeRef::root(SESSION_ID)?;
    let lock = path.join(format!("{}.lock", scope.as_str()));
    fs::write(&lock, "foreign lock\n")?;
    assert!(matches!(
        repository.append_snapshot(
            scope,
            root,
            snapshot("blocked", b"blocked")?,
            "Blocked append",
        ),
        Err(ContextRepositoryError::UpdateScopeRef { .. })
    ));
    assert!(lock.exists());
    Ok(())
}

fn scope_ref(full_name: &str) -> TestResult<ScopeRef> {
    let suffix = full_name
        .strip_prefix(&format!("refs/scopes/{SESSION_ID}/scope/"))
        .ok_or_else(|| io::Error::other("writer scope is outside its session namespace"))?;
    Ok(ScopeRef::scope(SESSION_ID, suffix)?)
}

#[test]
#[ignore = "manual development-machine baseline; run this test explicitly"]
fn context_repository_scale_baseline() -> TestResult<()> {
    const SHARED_REFS: usize = 10_000;
    const RETAINED_COMMITS: usize = 100_000;

    let directory = tempfile::tempdir()?;
    let path = directory.path().join("context.git");
    let (repository, root) = initialize(&path)?;
    let start_refs = Instant::now();
    let shared_ref_directory = path.join("refs/scopes").join(SESSION_ID).join("scope");
    fs::create_dir_all(&shared_ref_directory)?;
    for number in 0..SHARED_REFS {
        fs::write(
            shared_ref_directory.join(format!("shared-{number:05}")),
            format!("{root}\n"),
        )?;
    }
    let refs_elapsed = start_refs.elapsed();
    eprintln!(
        "context repository scale baseline: created {SHARED_REFS} direct refs in {refs_elapsed:?}"
    );
    let retained = ScopeRef::scope(SESSION_ID, "retained")?;
    repository.create_scope(retained.clone(), ScopeStart::existing_commit(root))?;
    let history_snapshot = snapshot("retained/marker", b"retained")?;
    let start_history = Instant::now();
    let mut head = root;
    for _ in 0..RETAINED_COMMITS {
        head = repository.append_snapshot(
            retained.clone(),
            head,
            history_snapshot.clone(),
            "Retained history append",
        )?;
    }
    let history_elapsed = start_history.elapsed();
    eprintln!(
        "context repository scale baseline: created {RETAINED_COMMITS} retained commits in {history_elapsed:?}"
    );
    let start_open = Instant::now();
    let reopened = open(&path)?;
    let open_elapsed = start_open.elapsed();
    let start_enumeration = Instant::now();
    let scope_count = reopened.scope_refs()?.len();
    let enumeration_elapsed = start_enumeration.elapsed();
    let start_append = Instant::now();
    reopened.append_snapshot(
        retained,
        head,
        history_snapshot,
        "Measured append after reopen",
    )?;
    let append_elapsed = start_append.elapsed();
    let start_verification = Instant::now();
    let verification = reopened.verify_full()?;
    let verification_elapsed = start_verification.elapsed();
    let bytes = repository_bytes(&path)?;

    assert_eq!(scope_count, SHARED_REFS + 2);
    assert_eq!(verification.scope_count(), scope_count);
    eprintln!(
        "context repository scale baseline: refs={scope_count}, commits={}, trees={}, blobs={}, bytes={bytes}, create_refs={refs_elapsed:?}, append_history={history_elapsed:?}, open={open_elapsed:?}, enumerate_refs={enumeration_elapsed:?}, append_after_open={append_elapsed:?}, verify_full={verification_elapsed:?}",
        verification.commit_count(),
        verification.tree_count(),
        verification.blob_count(),
    );
    Ok(())
}

fn repository_bytes(path: &Path) -> io::Result<u64> {
    let mut bytes = 0;
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        let metadata = entry.metadata()?;
        if metadata.is_dir() {
            bytes += repository_bytes(&entry.path())?;
        } else {
            bytes += metadata.len();
        }
    }
    Ok(bytes)
}
