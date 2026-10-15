use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use araphor_analysis_sdk as sdk;
use tokio::sync::watch;

use crate::package::*;
use crate::{
    AnalysisReadControl, AnalysisSelectionV1, AnalysisStore, QueryLimits, QueryOwner, Result,
    SqlModelV1,
};

pub(crate) type TestResult<T = ()> =
    std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

type CommitObserver = Box<dyn FnMut() -> Result<()> + Send>;

pub(crate) struct Authority {
    revision: AtomicU64,
    changes: watch::Sender<u64>,
    pub before_admit: Mutex<Option<CommitObserver>>,
    pub after_commit: Mutex<Option<CommitObserver>>,
}

impl Authority {
    pub fn set_revision(&self, revision: u64) {
        self.revision.store(revision, Ordering::SeqCst);
        self.changes.send_replace(revision);
    }
}

impl PackageAuthorization for Authority {
    fn check(&self, grant: &PackageGrantV1, _: PackageActionV1) -> Result<()> {
        let revision = self.revision.load(Ordering::SeqCst);
        if revision == 0 || grant.revision != revision {
            return Err(PackageErrorCodeV1::Denied.error("fixture grant"));
        }
        Ok(())
    }

    fn admit(
        &self,
        grant: &PackageGrantV1,
        _: &crate::package::PackageBundleRef<'_>,
    ) -> Result<()> {
        let observer = self
            .before_admit
            .lock()
            .map_err(|_| PackageErrorCodeV1::Incomplete.error("fixture admission observer"))?
            .take();
        if let Some(mut observer) = observer {
            observer()?;
        }
        self.check(grant, PackageActionV1::Run)
    }

    fn commit(
        &self,
        grant: &PackageGrantV1,
        action: PackageActionV1,
        bundle: &crate::package::PackageBundleRef<'_>,
        operation: &mut dyn FnMut() -> Result<()>,
    ) -> Result<()> {
        self.check(grant, action)?;
        self.admit(grant, bundle)?;
        operation()?;
        if let Some(observer) = self
            .after_commit
            .lock()
            .map_err(|_| PackageErrorCodeV1::Incomplete.error("fixture commit observer"))?
            .as_mut()
        {
            observer()?;
        }
        Ok(())
    }

    fn changes(&self) -> watch::Receiver<u64> {
        self.changes.subscribe()
    }
}

pub(crate) struct Fixture {
    pub store: Arc<AnalysisStore>,
    pub owner: Arc<AnalysisPackageOwner>,
    pub grant: PackageGrantV1,
    pub authority: Arc<Authority>,
    limits: QueryLimits,
    root: std::path::PathBuf,
    _directory: Option<tempfile::TempDir>,
}

impl Fixture {
    pub fn new() -> TestResult<Self> {
        Self::new_limits(QueryLimits {
            extract_timeout: Duration::from_secs(30),
            evaluate_timeout: Duration::from_secs(30),
            ..Default::default()
        })
    }

    pub fn new_limits(limits: QueryLimits) -> TestResult<Self> {
        let directory = tempfile::tempdir()?;
        Self::open_resources(directory.path().to_path_buf(), limits, Some(directory))
    }

    pub fn open(root: std::path::PathBuf) -> TestResult<Self> {
        Self::open_resources(
            root,
            QueryLimits {
                extract_timeout: Duration::from_secs(30),
                evaluate_timeout: Duration::from_secs(30),
                ..Default::default()
            },
            None,
        )
    }

    fn open_resources(
        root: std::path::PathBuf,
        limits: QueryLimits,
        directory: Option<tempfile::TempDir>,
    ) -> TestResult<Self> {
        let store = Arc::new(AnalysisStore::open(root.join("analysis"))?);
        let authority = Arc::new(Authority {
            revision: AtomicU64::new(1),
            changes: watch::channel(1).0,
            before_admit: Mutex::new(None),
            after_commit: Mutex::new(None),
        });
        let owner = Self::owner(store.clone(), authority.clone(), limits.clone())?;
        Ok(Self {
            store,
            owner,
            authority,
            limits,
            root,
            _directory: directory,
            grant: PackageGrantV1 {
                principal: "fixture".into(),
                revision: 1,
                selection: AnalysisSelectionV1::tenant([1; 16]),
                expires_utc_ns: Some(u64::MAX),
                authorization_id: None,
            },
        })
    }

    fn owner(
        store: Arc<AnalysisStore>,
        authority: Arc<Authority>,
        limits: QueryLimits,
    ) -> TestResult<Arc<AnalysisPackageOwner>> {
        let query = Arc::new(QueryOwner::new(store.clone(), limits)?);
        let mut owner = AnalysisPackageOwner::new(store, query, authority)?;
        owner.prepare_test_code()?;
        Ok(Arc::new(owner))
    }

    pub fn reopen(self) -> TestResult<Self> {
        let Self {
            store,
            owner,
            grant,
            authority,
            limits,
            root,
            _directory,
        } = self;
        drop(owner);
        drop(store);
        let store = Arc::new(AnalysisStore::open(root.join("analysis"))?);
        let owner = Self::owner(store.clone(), authority.clone(), limits.clone())?;
        Ok(Self {
            store,
            owner,
            grant,
            authority,
            limits,
            root,
            _directory,
        })
    }

    pub async fn execute(&self, request: PackageRequestV1) -> Result<PackageResponseV1> {
        self.owner
            .execute(
                self.grant.clone(),
                request,
                Arc::new(AnalysisReadControl::with_timeout(Duration::from_secs(30))?),
            )
            .await
    }

    pub async fn install(
        &self,
        bundle: PackageBundleV1,
        parameters: Option<serde_json::Value>,
    ) -> Result<PackageResponseV1> {
        self.execute(PackageRequestV1::Install {
            scope_id: "test".into(),
            bundle,
            parameters,
        })
        .await
    }

    pub fn renew(&mut self) {
        self.grant.revision += 1;
        self.authority.set_revision(self.grant.revision);
    }
}

pub(in crate::package) fn bundle(revision: &str, sql: &str) -> PackageBundleV1 {
    let mut descriptor = sdk::Package::new(
        "test.model",
        revision,
        vec![sdk::Model::new(
            "count",
            Vec::new(),
            vec![sdk::Port::new(
                "rows",
                sdk::Schema::new(vec![sdk::Field::new("count", sdk::DataType::UInt64, false)]),
            )],
        )],
    );
    descriptor.exports[0].input_mode = sdk::InputMode::Resolved;
    PackageBundleV1 {
        schema_version: 1,
        root: PackageRefV1 {
            package_id: descriptor.id.clone(),
            revision: revision.into(),
        },
        artifacts: vec![PackageArtifactV1 {
            descriptor,
            implementations: vec![PackageImplementationV1::Sql {
                export: "count".into(),
                program: SqlModelV1 {
                    outputs: BTreeMap::from([("rows".into(), sql.into())]),
                    ..Default::default()
                },
            }],
            fixtures: Vec::new(),
        }],
    }
}

pub(in crate::package) fn run(id: &str) -> PackageRequestV1 {
    PackageRequestV1::Run {
        scope_id: "test".into(),
        package_id: "test.model".into(),
        export: None,
        evaluation_id: id.into(),
        parameters: None,
    }
}
