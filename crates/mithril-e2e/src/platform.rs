use erebor_interceptor_abi::TaskCoordinateV1;
use mithril_node::NativeTaskSnapshotV1;
use std::path::Path;

mod cri;
mod host;
mod runc;

pub(crate) use self::cri::CriFixture;
pub(crate) use self::host::Host;
pub(crate) use self::runc::Runc;
pub(crate) use mithril_e2e_macros::platform_test;
pub(crate) type TestResult<T> = Result<T, Box<dyn std::error::Error>>;

pub(crate) struct Task {
    pub(crate) pid: u32,
    pub(crate) ns_pid: u32,
    pub(crate) snapshot: NativeTaskSnapshotV1,
    pub(crate) coordinate: TaskCoordinateV1,
}

pub(crate) trait Platform: Sized {
    fn setup(_name: &str) -> TestResult<Self> {
        pending("setup")
    }
    fn start_control(&mut self) -> TestResult<()> {
        pending("start Control")
    }
    fn start_node(&mut self) -> TestResult<()> {
        pending("start Node")
    }
    fn install_policy(&mut self) -> TestResult<()> {
        pending("install policy")
    }
    fn node_ready(&mut self) -> TestResult<()> {
        pending("wait for Node")
    }
    fn start_actor(
        &mut self,
        _name: &str,
        _args: &[&str],
    ) -> TestResult<crate::process::ProcessFixture> {
        pending("start actor")
    }
    fn place(&mut self, _pid: u32) -> TestResult<()> {
        pending("place actor")
    }
    fn stage(&mut self) -> TestResult<()> {
        pending("stage actor")
    }
    fn admit(&mut self, _pid: u32) -> TestResult<()> {
        pending("admit actor")
    }
    fn task(&mut self, _pid: u32, _name: &str) -> TestResult<Task> {
        pending("read task")
    }
    fn work(&self) -> &Path {
        Path::new(".")
    }
    fn output(&self) -> &Path {
        Path::new(".")
    }
    fn stop(&mut self) -> TestResult<()> {
        pending("stop fixture")
    }
}

fn pending<T>(name: &str) -> TestResult<T> {
    Err(format!("{name} is not implemented for this platform").into())
}
