use crate::identity::retained::RetainedHost;
use crate::platform::{platform_test, Platform, TestResult};

#[platform_test(host)]
#[scope = "retained-host"]
fn retained_maps_recover<P: Platform>() -> TestResult<()> {
    let mut env = P::setup("retained-host")?;
    let pin = env.maps().0.to_owned();
    let mut host = RetainedHost::start(&pin)?;
    let first = host.map_ids()?;

    assert!(host.reject_live_owner()?);
    host.shutdown()?;
    assert!(host.reject_other_root()?);
    assert!(host.reject_displaced()?);

    host.restart()?;
    assert_eq!(host.map_ids()?, first);
    assert!(host.reject_missing_link()?);

    host.stop()?;
    env.stop()
}
