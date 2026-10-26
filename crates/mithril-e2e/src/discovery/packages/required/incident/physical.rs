use std::{env, fs, path::PathBuf};

use serde_json::json;

use super::Incident;
use crate::platform::{platform_test, Platform, TestResult};

mod input;
mod observed;

#[platform_test(kubernetes)]
#[lifecycle = package_incident]
fn protected_read_package<P: Platform + 'static>() -> TestResult<()> {
    let expected: serde_json::Value = serde_json::from_slice(&fs::read(
        env::var_os("MITHRIL_GRAPH_NOTIFICATION_EXPECTED").ok_or("paired lightweight input")?,
    )?)?;
    let output = PathBuf::from(
        env::var_os("MITHRIL_GRAPH_NOTIFICATION_OUTPUT").ok_or("physical evidence output")?,
    );
    if !output.is_absolute() || output.exists() {
        return Err("physical output must be a new absolute directory".into());
    }
    fs::create_dir(&output)?;
    let mut platform = P::setup("graph-notification")?;
    platform.configure_control(input::configure)?;
    platform.start_control()?;
    platform.start_node()?;
    let labels = platform.install_policy("multi_policy_deny.json")?;
    platform.node_ready()?;
    let mut actor = platform.start_actor("read_path.py", &[], &labels)?;
    let task = platform.task(actor.id(), "package incident actor")?;
    let work = platform.work().to_owned();
    let since = input::monotonic()?;
    let cookie = task.snapshot.task_cookie;
    let result = {
        let actor = &mut actor;
        let work = &work;
        let expected = &expected;
        platform.client_operation(
            "00000000-0000-0001-0000-000000000002",
            |profile| async move {
                let client = input::checked_client(profile).await?;
                let observed = Incident::subscribe(&client, cookie, since).await?;
                actor.send(b"/fixtures/policy_replace.py\n")?;
                let denied: (i32, usize) = serde_json::from_str(
                    &actor.wait_text(&work.join("0.json"), "protected file read")?,
                )?;
                assert_eq!(denied, (libc::EACCES, 0));
                actor.send(b"/fixtures/read_path.py\n")?;
                let allowed: (i32, usize) = serde_json::from_str(
                    &actor.wait_text(&work.join("1.json"), "benign file read")?,
                )?;
                assert_eq!(allowed.0, 0);
                assert!(allowed.1 > 0);
                assert_eq!(
                    allowed.1,
                    include_bytes!(concat!(
                        env!("CARGO_MANIFEST_DIR"),
                        "/fixtures/process/read_path.py"
                    ))
                    .len()
                );
                actor.ensure_running("physical file read controls")?;
                let observed = observed.wait().await?;
                assert_eq!(observed.decision, expected["decision"]);
                let identity = observed.identity(&client).await?;
                Ok((observed, denied, allowed, identity))
            },
        )
    };
    let result = result.and_then(|(observed, denied, allowed, identity)| {
        observed.check_physical(&task, &platform.snapshot()?, &expected)?;
        Ok((observed, denied, allowed, identity))
    });
    let stopped = [
        actor.stop().map_err(Into::into),
        platform.stop_node(),
        platform.stop(),
    ];
    for error in stopped.iter().filter_map(|result| result.as_ref().err()) {
        eprintln!("physical cleanup failed: {error}");
    }
    let (observed, denied, allowed, identity) = result?;
    for stopped in stopped {
        stopped?;
    }
    fs::write(
        output.join("result.json"),
        serde_json::to_vec_pretty(&json!({
            "result": "PASS", "qualification": "KUBERNETES", "observed": observed,
            "denied": denied, "allowed": allowed, "identity": identity,
            "full_hugging_face_incident_reproduced": false,
            "external_notification_delivered": false,
        }))?,
    )?;
    Ok(())
}
