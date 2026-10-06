use std::{env, ffi::OsStr, fs, os::unix::process::ExitStatusExt as _, path::Path};

use rustix::process::{kill_process, Pid, Signal};

use super::{Shared, NODE_START_LIMIT, READY_LIMIT};
use crate::platform::{test_lifecycle, CriFixture, Host, TestResult};
use crate::process::ProcessFixture;

#[test]
#[ignore = "requires root, BPF LSM, and a prepared MITHRIL_TEST_NODE executable"]
fn interrupted_start_is_closed() -> TestResult<()> {
    test_lifecycle::<Host, _>("interrupted_start", || {
        let mut env = Shared::setup("interrupted-start")?;
        env.start_control()?;
        env.cri = Some(CriFixture::start(&env.cri_path)?);
        let config = env.output().join("startup-node.json");
        fs::write(&config, serde_json::to_vec_pretty(&env.node_config()?)?)?;
        let executable = env::var_os("MITHRIL_TEST_NODE").ok_or("MITHRIL_TEST_NODE is not set")?;
        env.move_out(std::process::id())?;
        let mut node = ProcessFixture::held_cgroup(
            Path::new(&executable),
            [OsStr::new("--config"), config.as_os_str()],
            &env.node_path,
            Path::new("/"),
            std::process::id(),
        )?;
        node.release()?;
        let maps = env.pin_path.join("maps");
        let links = env.pin_path.join("links");
        node.wait_path(
            &maps,
            "Node kernel startup",
            NODE_START_LIMIT,
            || Ok((maps.is_dir() && links.is_dir()).then_some(())),
            || format!("admission socket exists={}", env.admit_path.exists()),
        )?;
        assert!(!env.admit_path.exists());
        let pid = Pid::from_raw(i32::try_from(node.id())?).ok_or("invalid Node PID")?;
        kill_process(pid, Signal::KILL)?;
        let status = node.wait_exit("interrupted Node exit", READY_LIMIT)?;
        assert_eq!(status.signal(), Some(libc::SIGKILL));
        assert!(maps.is_dir());
        assert!(fs::read_dir(&maps)?.next().transpose()?.is_none());
        assert!(!env.admit_path.exists());

        env.node_cgroup
            .as_ref()
            .ok_or("the Node cgroup is missing")?
            .move_in(std::process::id())?;
        let error = match env.start_node() {
            Err(error) => error,
            Ok(()) => return Err("Node accepted an incomplete pin root".into()),
        };
        let reason = error.to_string();
        assert!(reason.contains("contains stale state"), "{reason}");
        assert!(!env.admit_path.exists());
        assert!(env.ready.is_none());
        node.stop()?;
        env.stop()
    })
}
