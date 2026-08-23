use std::{
    io::{self, Read},
    sync::{mpsc, Arc},
    thread,
};

use crate::{DurableStreamStore, SessionControllerError};

use super::output::unix_time_ms;

#[derive(Clone, Copy, Debug)]
pub(crate) struct WorkloadExit {
    pub(crate) exit_code: Option<i32>,
    pub(crate) signal: Option<i32>,
}

pub(super) struct OutputFailureMonitor {
    receiver: mpsc::Receiver<SessionControllerError>,
}

impl OutputFailureMonitor {
    pub(super) fn new() -> (Self, mpsc::Sender<SessionControllerError>) {
        let (sender, receiver) = mpsc::channel();
        (Self { receiver }, sender)
    }

    pub(super) fn take_failure(&self) -> Option<SessionControllerError> {
        self.receiver.try_recv().ok()
    }
}

pub(super) fn pump_output(
    mut source: impl Read + Send + 'static,
    sink: Arc<DurableStreamStore>,
    source_name: &'static str,
    source_is_terminal_master: bool,
    failure_sender: mpsc::Sender<SessionControllerError>,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        let required = sink.required();
        let mut buffer = [0_u8; 8192];
        loop {
            match source.read(&mut buffer) {
                Ok(0) => return,
                // On Linux, closing the last slave file descriptor makes a
                // pseudoterminal master report EIO rather than EOF.  It is
                // the normal end of an interactive workload, not a failure
                // to record its output.  Do not extend this exception to
                // ordinary pipes, where EIO remains an actionable error.
                Err(source) if source_is_terminal_master && is_pty_eof(&source) => return,
                Err(source) => {
                    if required {
                        let _result = failure_sender.send(SessionControllerError::Io {
                            action: "reading governed workload output",
                            path: std::path::PathBuf::from(format!("<{source_name}>")),
                            source,
                            location: snafu::Location::default(),
                        });
                    }
                    return;
                }
                Ok(bytes) => {
                    if let Err(source) =
                        sink.append(unix_time_ms(), source_name, buffer[..bytes].to_vec())
                    {
                        if required {
                            let _result = failure_sender.send(SessionControllerError::Output {
                                source,
                                location: snafu::Location::default(),
                            });
                        }
                        return;
                    }
                }
            }
        }
    })
}

fn is_pty_eof(error: &io::Error) -> bool {
    error.raw_os_error() == Some(rustix::io::Errno::IO.raw_os_error())
}

pub(super) fn child_exit(status: std::process::ExitStatus) -> WorkloadExit {
    use std::os::unix::process::ExitStatusExt;

    WorkloadExit {
        exit_code: status.code(),
        signal: status.signal(),
    }
}

#[cfg(test)]
mod tests {
    use std::{
        io::{self, Cursor, Read},
        sync::Arc,
    };

    use tempfile::TempDir;

    use crate::{DurableStreamStore, StreamKind};

    use super::{pump_output, OutputFailureMonitor};

    #[test]
    fn required_stream_write_failure_reaches_the_controller_monitor(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let temporary = TempDir::new()?;
        let sink = Arc::new(DurableStreamStore::open(
            temporary.path(),
            StreamKind::Stdout,
            128,
            128,
            true,
        )?);
        let (monitor, sender) = OutputFailureMonitor::new();
        let pump = pump_output(Cursor::new(vec![b'x'; 256]), sink, "stdout", false, sender);

        pump.join().map_err(|_panic| "output pump panicked")?;
        let failure = monitor
            .take_failure()
            .ok_or("required output failure was not reported")?;
        assert!(matches!(
            failure,
            crate::SessionControllerError::Output { .. }
        ));
        Ok(())
    }

    #[test]
    fn optional_stream_write_failure_does_not_fail_the_controller(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let temporary = TempDir::new()?;
        let sink = Arc::new(DurableStreamStore::open(
            temporary.path(),
            StreamKind::Stdout,
            128,
            128,
            false,
        )?);
        let (monitor, sender) = OutputFailureMonitor::new();
        let pump = pump_output(Cursor::new(vec![b'x'; 256]), sink, "stdout", false, sender);

        pump.join().map_err(|_panic| "output pump panicked")?;
        assert!(monitor.take_failure().is_none());
        Ok(())
    }

    #[test]
    fn terminal_master_eio_is_a_normal_end_of_stream() -> Result<(), Box<dyn std::error::Error>> {
        struct EioReader;

        impl Read for EioReader {
            fn read(&mut self, _buffer: &mut [u8]) -> io::Result<usize> {
                Err(io::Error::from_raw_os_error(
                    rustix::io::Errno::IO.raw_os_error(),
                ))
            }
        }

        let temporary = TempDir::new()?;
        let sink = Arc::new(DurableStreamStore::open(
            temporary.path(),
            StreamKind::Stdout,
            128,
            128,
            true,
        )?);
        let (monitor, sender) = OutputFailureMonitor::new();
        let pump = pump_output(EioReader, sink, "stdout", true, sender);

        pump.join().map_err(|_panic| "output pump panicked")?;
        assert!(monitor.take_failure().is_none());
        Ok(())
    }
}
