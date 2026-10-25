use std::time::{SystemTime, UNIX_EPOCH};

use super::*;
use araphor_data::AnalysisStore;

mod sql;
mod subscriptions;

type TestResult<T = ()> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

struct Authority(tokio::sync::watch::Sender<u64>);

impl PackageAuthorization for Authority {
    fn check(&self, _: &PackageGrantV1, _: PackageActionV1) -> araphor_data::Result<()> {
        Ok(())
    }
    fn admit(&self, _: &PackageGrantV1, _: &PackageBundle) -> araphor_data::Result<()> {
        Ok(())
    }
    fn commit(
        &self,
        _: &PackageGrantV1,
        _: PackageActionV1,
        _: &PackageBundle,
        operation: &mut dyn FnMut() -> araphor_data::Result<()>,
    ) -> araphor_data::Result<()> {
        operation()
    }
    fn changes(&self) -> tokio::sync::watch::Receiver<u64> {
        self.0.subscribe()
    }
}

fn fixture() -> TestResult<(tempfile::TempDir, Package)> {
    let directory = tempfile::tempdir()?;
    let store = Arc::new(AnalysisStore::open(directory.path().join("data"))?);
    let bundle = Arc::new(PackageBundle::try_from(Package::discovery_bundle()?)?);
    store.install_package_image([1; 16], &bundle, || Ok(()))?;
    let query = Engine::new(store, Default::default())?;
    let grant = PackageGrantV1 {
        principal: "fixture".into(),
        revision: 1,
        selection: AnalysisSelectionV1::tenant([1; 16]),
        expires_utc_ns: None,
        authorization_id: None,
    };
    let package = Package::new(
        query,
        Arc::new(Authority(tokio::sync::watch::channel(0).0)),
        grant,
        bundle,
        "live",
        "snapshot",
    )?;
    Ok((directory, package))
}

#[test]
fn grant_shape_and_expiry() -> TestResult {
    let (_directory, mut package) = fixture()?;
    assert_eq!(package.control()?.remaining()?, None);
    let original = package.grant.clone();
    for case in 0..5 {
        package.grant = original.clone();
        match case {
            0 => package.grant.principal.clear(),
            1 => package.grant.principal = "x".repeat(257),
            2 => package.grant.revision = 0,
            3 => package.grant.selection.tenant_id = [0; 16],
            _ => package.grant.expires_utc_ns = Some(1),
        }
        assert!(package.check().is_err());
        let mut called = false;
        assert!(package
            .commit(|| {
                called = true;
                Ok(())
            })
            .is_err());
        assert!(!called);
    }
    Ok(())
}

#[tokio::test]
async fn explicit_expiry_reaches_query() -> TestResult {
    let (_directory, mut package) = fixture()?;
    let now = u64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos())?;
    package.grant.expires_utc_ns = Some(now.checked_add(50_000_000).ok_or("expiry overflow")?);
    let control = package.control()?;
    assert!(control.remaining()?.is_some());
    assert!(matches!(
        control
            .query_async(std::future::pending::<araphor_data::Result<()>>())
            .await,
        Err(araphor_data::Error::AnalysisReadDeadline { .. })
    ));
    Ok(())
}
