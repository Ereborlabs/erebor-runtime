use std::{cell::RefCell, fs, time::Duration};

use crate::error::InvalidInputSnafu;
use crate::physical::wait_for;
use crate::platform::{platform_test, Platform, TestResult};

#[platform_test(host)]
#[lifecycle = mount_late]
fn bind_refreshes_cache<P: Platform>() -> TestResult<()> {
    let mut env = P::setup("mount-cache")?;
    env.start_control()?;
    env.start_node()?;
    let labels = env.install_policy("mount_alias_policy.json")?;
    env.node_ready()?;
    let mut actor = env.start_actor("mount_alias.py", &["runtime"], &labels)?;
    env.task(actor.id(), "mount-cache actor")?;

    let key = 0_u32.to_ne_bytes();
    let epoch = env
        .state::<u64>("mount_global_mutation_epoch", &key, "mount epoch")?
        .ok_or("mount epoch is missing")?;
    actor.send(b"mount\n")?;
    let result_path = env.work().join("mount-result.json");
    let mounted = wait_for(
        &result_path,
        "protected bind mount",
        Duration::from_secs(30),
        || {
            Ok(fs::read(&result_path)
                .ok()
                .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok())
                .filter(|value| value["phase"] == "mounted"))
        },
        || {
            format!(
                "result: {:?}; exit: {:?}; stderr: {:?}",
                fs::read_to_string(&result_path),
                actor.try_wait(),
                actor.stderr()
            )
        },
    )?;
    assert_eq!(mounted["mount"], 0);
    assert_eq!(mounted["allowed_mount"], 0);

    let pin = env.maps().0.to_owned();
    let last = RefCell::new(String::from("<none>"));
    wait_for(
        &pin,
        "dirty mount security view",
        Duration::from_secs(30),
        || {
            let count = |name| -> crate::Result<u64> {
                env.state(name, &key, name)
                    .map_err(|error| {
                        InvalidInputSnafu {
                            path: &pin,
                            reason: error.to_string(),
                        }
                        .build()
                    })?
                    .ok_or_else(|| {
                        InvalidInputSnafu {
                            path: &pin,
                            reason: format!("{name} is missing"),
                        }
                        .build()
                    })
            };
            let current = count("mount_global_mutation_epoch")?;
            let clean = count("mount_global_clean_epoch")?;
            let pending = count("mount_global_pending_mutations")?;
            *last.borrow_mut() =
                format!("epoch={epoch}->{current}, clean={clean}, pending={pending}");
            Ok((current > epoch && (current != clean || pending != 0)).then_some(()))
        },
        || last.borrow().clone(),
    )?;

    actor.send(b"read\n")?;
    actor.close();
    let status = actor.wait_exit("bind-cache reads", Duration::from_secs(5))?;
    assert!(status.success(), "{status}; stderr: {:?}", actor.stderr()?);
    let result: serde_json::Value = serde_json::from_slice(&fs::read(&result_path)?)?;
    assert_eq!(result["denied"], libc::EACCES);
    assert_eq!(result["allowed"], "allowed bind source\n");
    actor.stop()?;
    env.stop()
}
