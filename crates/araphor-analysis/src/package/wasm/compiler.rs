use std::path::Path;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::Duration;

use snafu::ResultExt as _;
use wasmtime::component::Component;

use crate::{AnalysisReadControl, Result};

use super::{Code, WasmExecution};

mod image;
mod input;
mod worker;

#[cfg(test)]
mod tests;

const WORKER_ARG: &str = "--araphor-component-compiler";
const MAX_ADDRESS_BYTES: u64 = 1024 * 1024 * 1024;
const MAX_CPU_SECONDS: u64 = 30;
const MAX_WALL_TIME: Duration = Duration::from_secs(45);
const POLL_TIME: Duration = Duration::from_millis(5);

#[cfg(test)]
const TEST_ENTRY: &str = "package::wasm::compiler::tests::araphor_component_compiler";
#[cfg(not(test))]
const TEST_ENTRY: &str = "araphor_component_compiler";

struct CompilerChild<'a> {
    child: Child,
    reaped: bool,
    failed: &'a mut bool,
}

#[derive(Debug, snafu::Snafu)]
#[snafu(display("component compiler process: {status}"))]
struct CompilerProcessFailure {
    status: ExitStatus,
}

impl CompilerChild<'_> {
    fn command(entry: &str) -> Result<Command> {
        let executable = std::env::current_exe()
            .map_err(wasmtime::Error::new)
            .context(crate::PackageWasmSnafu {
                code: Code::Incomplete,
                operation: "component compiler executable",
            })?;
        let mut command = Command::new(&executable);
        command
            .env_clear()
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped());
        if Self::test_executable(&executable) {
            command.args(["--quiet", "--exact", entry, "--ignored", "--nocapture"]);
        } else {
            command.arg(WORKER_ARG);
        }
        Self::restrict(&mut command)?;
        Ok(command)
    }

    fn test_executable(executable: &Path) -> bool {
        executable.parent().and_then(Path::file_name) == Some(std::ffi::OsStr::new("deps"))
            && executable
                .file_stem()
                .and_then(|name| name.to_str())
                .and_then(|name| name.rsplit_once('-'))
                .is_some_and(|(_, digest)| {
                    digest.len() == 16 && digest.bytes().all(|byte| byte.is_ascii_hexdigit())
                })
    }

    #[cfg(unix)]
    #[allow(unsafe_code)]
    fn restrict(command: &mut Command) -> Result<()> {
        use rustix::process::{setrlimit, Resource, Rlimit};
        use std::os::unix::process::CommandExt as _;

        // Set limits with system calls before exec. Do not allocate in this closure.
        unsafe {
            command.pre_exec(|| {
                for (resource, maximum) in [
                    (Resource::As, MAX_ADDRESS_BYTES),
                    (Resource::Cpu, MAX_CPU_SECONDS),
                    (Resource::Core, 0),
                ] {
                    setrlimit(
                        resource,
                        Rlimit {
                            current: Some(if resource == Resource::Cpu {
                                maximum - 1
                            } else {
                                maximum
                            }),
                            maximum: Some(maximum),
                        },
                    )
                    .map_err(std::io::Error::from)?;
                }
                Ok(())
            });
        }
        Ok(())
    }

    #[cfg(not(unix))]
    fn restrict(_command: &mut Command) -> Result<()> {
        Err(Code::Unsupported
            .error("component compiler process limits")
            .into())
    }

    fn capture(
        entry: &str,
        bytes: &[u8],
        fuel: bool,
        control: &AnalysisReadControl,
        failed: &mut bool,
        #[cfg(test)] entered: Option<std::sync::mpsc::Sender<u32>>,
    ) -> Result<image::CompilerImage> {
        let control = control.within(MAX_WALL_TIME)?;
        control.check()?;
        let mut command = Self::command(entry)?;
        std::thread::scope(|scope| {
            let child =
                command
                    .spawn()
                    .map_err(wasmtime::Error::new)
                    .context(crate::PackageWasmSnafu {
                        code: Code::Incomplete,
                        operation: "component compiler start",
                    })?;
            let mut worker = CompilerChild {
                child,
                reaped: false,
                failed,
            };
            let input = worker
                .child
                .stdin
                .take()
                .ok_or_else(|| Code::Incomplete.error("component compiler input"))?;
            let output = worker
                .child
                .stderr
                .take()
                .ok_or_else(|| Code::Incomplete.error("component compiler output"))?;
            let sender = std::thread::Builder::new()
                .name("component-compiler-input".into())
                .spawn_scoped(scope, move || {
                    input::CompilerInput::write(fuel, bytes, input)
                })
                .map_err(wasmtime::Error::new)
                .context(crate::PackageWasmSnafu {
                    code: Code::Incomplete,
                    operation: "component compiler input thread",
                })?;
            let receiver = std::thread::Builder::new()
                .name("component-compiler-output".into())
                .spawn_scoped(scope, move || image::CompilerImage::read(output))
                .map_err(wasmtime::Error::new)
                .context(crate::PackageWasmSnafu {
                    code: Code::Incomplete,
                    operation: "component compiler output thread",
                })?;
            #[cfg(test)]
            if let Some(entered) = entered {
                entered
                    .send(worker.child.id())
                    .map_err(|_| Code::Incomplete.error("component compiler test signal"))?;
            }
            let status = worker.wait(&control)?;
            let sent = sender
                .join()
                .map_err(|_| Code::Incomplete.error("component compiler input thread"))?;
            let image = receiver
                .join()
                .map_err(|_| Code::Incomplete.error("component compiler output thread"))?;
            if !status.success() {
                #[cfg(unix)]
                let code = {
                    use std::os::unix::process::ExitStatusExt as _;
                    match status.signal() {
                        Some(6 | 9 | 24) => Code::Limit,
                        _ => Code::Incomplete,
                    }
                };
                #[cfg(not(unix))]
                let code = Code::Incomplete;
                return Err(wasmtime::Error::new(CompilerProcessFailure { status })).context(
                    crate::PackageWasmSnafu {
                        code,
                        operation: "component compiler process",
                    },
                );
            }
            sent?;
            control.check()?;
            image
        })
    }

    fn wait(&mut self, control: &AnalysisReadControl) -> Result<ExitStatus> {
        loop {
            control.check()?;
            if let Some(status) = self
                .child
                .try_wait()
                .map_err(wasmtime::Error::new)
                .context(crate::PackageWasmSnafu {
                    code: Code::Incomplete,
                    operation: "component compiler wait",
                })?
            {
                self.reaped = true;
                return Ok(status);
            }
            std::thread::sleep(POLL_TIME);
        }
    }
}

impl Drop for CompilerChild<'_> {
    fn drop(&mut self) {
        if !self.reaped {
            let _ = self.child.kill();
            if self.child.wait().is_err() {
                *self.failed = true;
            }
        }
    }
}

impl WasmExecution {
    pub(super) fn compile<T>(
        &self,
        bytes: &[u8],
        control: &AnalysisReadControl,
        failed: &mut bool,
        reserve: impl FnOnce(usize) -> Result<T>,
    ) -> Result<(Component, T)> {
        CompilerChild::capture(
            TEST_ENTRY,
            bytes,
            self.limits.fuel.is_some(),
            control,
            failed,
            #[cfg(test)]
            None,
        )?
        .component_reserved(&self.engine, reserve)
    }
}
