use std::path::Path;
use std::process::{Command, ExitStatus, Stdio};
use std::time::Duration;

use futures_util::FutureExt as _;
use snafu::ResultExt as _;
use wasmtime::component::Component;

use crate::{AnalysisReadControl, Result, WasmLimits};

use super::{Code, WasmExecution};

mod image;
mod input;
mod worker;

#[cfg(test)]
mod tests;

const WORKER_ARG: &str = "--araphor-component-compiler";
const MAX_CPU_SECONDS: u64 = 30;
const MAX_WALL_TIME: Duration = Duration::from_secs(45);

#[cfg(test)]
const TEST_ENTRY: &str = "package::wasm::compiler::tests::araphor_component_compiler";
#[cfg(not(test))]
const TEST_ENTRY: &str = "araphor_component_compiler";

struct CompilerChild {
    child: tokio::process::Child,
}

#[derive(Debug, snafu::Snafu)]
#[snafu(display("component compiler process: {status}"))]
struct CompilerProcessFailure {
    status: ExitStatus,
}

impl CompilerChild {
    fn command(entry: &str, address: Option<u64>) -> Result<Command> {
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
        Self::restrict(&mut command, address)?;
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
    fn restrict(command: &mut Command, address: Option<u64>) -> Result<()> {
        use rustix::process::{setrlimit, Resource, Rlimit};
        use std::os::unix::process::CommandExt as _;

        // Set limits with system calls before exec. Do not allocate in this closure.
        unsafe {
            command.pre_exec(move || {
                for (resource, maximum) in [
                    (Resource::As, address),
                    (Resource::Cpu, Some(MAX_CPU_SECONDS)),
                    (Resource::Core, Some(0)),
                ] {
                    let Some(maximum) = maximum else { continue };
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
    fn restrict(_command: &mut Command, _address: Option<u64>) -> Result<()> {
        Err(Code::Unsupported
            .error("component compiler process limits")
            .into())
    }

    fn capture(
        entry: &str,
        bytes: &[u8],
        limits: WasmLimits,
        control: &AnalysisReadControl,
        failed: &mut bool,
        #[cfg(test)] entered: Option<std::sync::mpsc::Sender<u32>>,
    ) -> Result<image::CompilerImage> {
        let control = control.within(MAX_WALL_TIME)?;
        control.check()?;
        let command = Self::command(entry, limits.compiler_bytes)?;
        std::thread::scope(|scope| {
            std::thread::Builder::new()
                .name("component-compiler-io".into())
                .spawn_scoped(scope, || {
                    let runtime = tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()
                        .map_err(wasmtime::Error::new)
                        .context(crate::PackageWasmSnafu {
                            code: Code::Incomplete,
                            operation: "component compiler I/O runtime",
                        })?;
                    runtime.block_on(async {
                        control.check()?;
                        let child = tokio::process::Command::from(command)
                            .kill_on_drop(true)
                            .spawn()
                            .map_err(wasmtime::Error::new)
                            .context(crate::PackageWasmSnafu {
                                code: Code::Incomplete,
                                operation: "component compiler start",
                            })?;
                        let mut worker = Self { child };
                        *failed = true;
                        let result = std::panic::AssertUnwindSafe(worker.run(
                            bytes,
                            limits,
                            &control,
                            #[cfg(test)]
                            entered,
                        ))
                        .catch_unwind()
                        .await
                        .unwrap_or_else(|_| {
                            Err(Code::Incomplete.error("component compiler I/O task").into())
                        });
                        *failed = if result.is_err() {
                            let _killed = worker.child.start_kill();
                            worker.child.wait().await.is_err()
                        } else {
                            false
                        };
                        result
                    })
                })
                .map_err(wasmtime::Error::new)
                .context(crate::PackageWasmSnafu {
                    code: Code::Incomplete,
                    operation: "component compiler I/O thread",
                })?
                .join()
                .map_err(|_| Code::Incomplete.error("component compiler I/O thread"))?
        })
    }

    async fn run(
        &mut self,
        bytes: &[u8],
        limits: WasmLimits,
        control: &AnalysisReadControl,
        #[cfg(test)] entered: Option<std::sync::mpsc::Sender<u32>>,
    ) -> Result<image::CompilerImage> {
        let input = self
            .child
            .stdin
            .take()
            .ok_or_else(|| Code::Incomplete.error("component compiler input"))?;
        let output = self
            .child
            .stderr
            .take()
            .ok_or_else(|| Code::Incomplete.error("component compiler output"))?;
        #[cfg(test)]
        if let Some(entered) = entered {
            entered
                .send(
                    self.child
                        .id()
                        .ok_or_else(|| Code::Incomplete.error("component compiler pid"))?,
                )
                .map_err(|_| Code::Incomplete.error("component compiler test signal"))?;
        }
        let (sent, image, status) = control
            .query_async(async {
                Ok::<_, crate::Error>(tokio::join!(
                    input::CompilerInput::write(limits.fuel.is_some(), bytes, input),
                    image::CompilerImage::read(output),
                    self.child.wait(),
                ))
            })
            .await?;
        let status = status
            .map_err(wasmtime::Error::new)
            .context(crate::PackageWasmSnafu {
                code: Code::Incomplete,
                operation: "component compiler wait",
            })?;
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
            self.limits,
            control,
            failed,
            #[cfg(test)]
            None,
        )?
        .component_reserved(&self.engine, reserve)
    }
}
