use std::{
    fs::File,
    io::{self, Write},
    os::fd::AsFd,
};

/// The hook result channel captured before broker authentication. The managed
/// hook always writes its result through this descriptor, even if fd 1 is
/// replaced after the broker has accepted the hook peer.
pub struct CodexHookResultOutput(File);

impl CodexHookResultOutput {
    pub fn capture() -> Result<Self, String> {
        let stdout = io::stdout();
        let descriptor = rustix::io::dup(stdout.as_fd())
            .map_err(|error| format!("failed to preserve original hook stdout: {error}"))?;
        Ok(Self(File::from(descriptor)))
    }

    pub fn write_result(&mut self, bytes: &[u8]) -> Result<(), String> {
        self.0
            .write_all(bytes)
            .map_err(|error| format!("failed to write hook result: {error}"))
    }
}
