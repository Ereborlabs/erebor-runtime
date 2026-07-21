use std::{
    io::{self, IsTerminal, Read},
    sync::mpsc::{self, Receiver, TryRecvError},
    thread,
};

use rustix::termios::{tcgetattr, tcsetattr, OptionalActions, Termios};

use crate::error::CliError;

const DETACH_PREFIX: u8 = 0x10;
const DETACH_SUFFIX: u8 = 0x11;

pub(super) struct InteractiveTerminal {
    stdin: io::Stdin,
    original: Termios,
    receiver: Receiver<InteractiveInput>,
}

pub(super) enum InteractiveInput {
    Bytes(Vec<u8>),
    Detach,
    Closed,
    Failed(io::Error),
}

impl InteractiveTerminal {
    pub(super) fn open() -> Result<Self, CliError> {
        let stdin = io::stdin();
        if !stdin.is_terminal() {
            return Err(CliError::InvalidSessionCommand {
                reason: String::from("interactive attachment requires a terminal standard input"),
                location: snafu::Location::default(),
            });
        }
        let original = tcgetattr(&stdin).map_err(|source| CliError::Terminal {
            source: source.into(),
            location: snafu::Location::default(),
        })?;
        let mut raw = original.clone();
        raw.make_raw();
        tcsetattr(&stdin, OptionalActions::Now, &raw).map_err(|source| CliError::Terminal {
            source: source.into(),
            location: snafu::Location::default(),
        })?;

        let (sender, receiver) = mpsc::channel();
        thread::spawn(move || read_terminal_input(sender));
        Ok(Self {
            stdin,
            original,
            receiver,
        })
    }

    pub(super) fn try_input(&self) -> Option<InteractiveInput> {
        match self.receiver.try_recv() {
            Ok(input) => Some(input),
            Err(TryRecvError::Empty) => None,
            Err(TryRecvError::Disconnected) => Some(InteractiveInput::Closed),
        }
    }
}

impl Drop for InteractiveTerminal {
    fn drop(&mut self) {
        let _result = tcsetattr(&self.stdin, OptionalActions::Now, &self.original);
    }
}

fn read_terminal_input(sender: mpsc::Sender<InteractiveInput>) {
    let mut stdin = io::stdin();
    let mut pending_detach_prefix = false;
    loop {
        let mut buffer = [0_u8; 1024];
        match stdin.read(&mut buffer) {
            Ok(0) => {
                if pending_detach_prefix
                    && sender
                        .send(InteractiveInput::Bytes(vec![DETACH_PREFIX]))
                        .is_err()
                {
                    return;
                }
                let _result = sender.send(InteractiveInput::Closed);
                return;
            }
            Ok(length) => {
                let outcome = split_terminal_input(&buffer[..length], &mut pending_detach_prefix);
                if !outcome.bytes.is_empty()
                    && sender.send(InteractiveInput::Bytes(outcome.bytes)).is_err()
                {
                    return;
                }
                if outcome.detach {
                    let _result = sender.send(InteractiveInput::Detach);
                    return;
                }
            }
            Err(source) => {
                let _result = sender.send(InteractiveInput::Failed(source));
                return;
            }
        }
    }
}

struct TerminalInputOutcome {
    bytes: Vec<u8>,
    detach: bool,
}

fn split_terminal_input(input: &[u8], pending_detach_prefix: &mut bool) -> TerminalInputOutcome {
    let mut bytes = Vec::with_capacity(input.len());
    for byte in input {
        if *pending_detach_prefix {
            *pending_detach_prefix = false;
            if *byte == DETACH_SUFFIX {
                return TerminalInputOutcome {
                    bytes,
                    detach: true,
                };
            }
            bytes.push(DETACH_PREFIX);
        }
        if *byte == DETACH_PREFIX {
            *pending_detach_prefix = true;
        } else {
            bytes.push(*byte);
        }
    }
    TerminalInputOutcome {
        bytes,
        detach: false,
    }
}

#[cfg(test)]
mod tests {
    use super::{split_terminal_input, DETACH_PREFIX, DETACH_SUFFIX};

    #[test]
    fn detach_escape_is_local_and_other_bytes_are_preserved() {
        let mut pending = false;
        let outcome =
            split_terminal_input(&[b'a', DETACH_PREFIX, DETACH_SUFFIX, b'b'], &mut pending);

        assert_eq!(outcome.bytes, b"a");
        assert!(outcome.detach);
        assert!(!pending);
    }

    #[test]
    fn incomplete_or_nonmatching_escape_reaches_the_workload() {
        let mut pending = false;
        let first = split_terminal_input(&[DETACH_PREFIX], &mut pending);
        let second = split_terminal_input(b"x", &mut pending);

        assert!(first.bytes.is_empty());
        assert!(!first.detach);
        assert_eq!(second.bytes, [DETACH_PREFIX, b'x']);
        assert!(!second.detach);
    }
}
