use std::path::Path;
use std::process::Command;

use crate::process::ProcessFixture;
use crate::Result;

pub(super) struct NativeProcessFixture {
    outer: ProcessFixture,
}

impl NativeProcessFixture {
    pub(super) fn start() -> Result<Self> {
        Self::start_with_script(
            "read _; (read child_pid _ < /proc/self/stat; kill -STOP \"$child_pid\"; exec /bin/sleep 300) & wait \"$!\"",
        )
    }

    pub(super) fn start_with_script(script: &str) -> Result<Self> {
        let mut command = Command::new("/bin/sh");
        let script = format!("printf 'native-fixture-ready\\n'; {script}");
        command.args(["-c", &script]);
        Self::start_command(&mut command, Path::new("/bin/sh"))
    }

    fn start_command(command: &mut Command, program: &Path) -> Result<Self> {
        let outer = ProcessFixture::start(command, program)?;
        Ok(Self { outer })
    }

    pub(super) fn outer_pid(&self) -> u32 {
        self.outer.id()
    }

    pub(super) fn stop(&mut self) -> Result<()> {
        self.outer.stop()
    }
}
