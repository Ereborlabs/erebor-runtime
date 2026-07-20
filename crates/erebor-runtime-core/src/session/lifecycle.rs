use serde::{Deserialize, Serialize};
use snafu::ensure;

use crate::{error::session_spec::InvalidTransitionSnafu, SessionSpecError};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionLifecycleState {
    Created,
    Starting,
    Running,
    Stopping,
    ControlLost,
    Succeeded,
    Failed,
    Interrupted,
    Removed,
}

impl SessionLifecycleState {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Created => "created",
            Self::Starting => "starting",
            Self::Running => "running",
            Self::Stopping => "stopping",
            Self::ControlLost => "control_lost",
            Self::Succeeded => "succeeded",
            Self::Failed => "failed",
            Self::Interrupted => "interrupted",
            Self::Removed => "removed",
        }
    }

    pub fn transition(self, next: Self) -> Result<(), SessionSpecError> {
        let allowed = matches!(
            (self, next),
            (Self::Created, Self::Starting | Self::Removed)
                | (
                    Self::Starting,
                    Self::Running
                        | Self::Stopping
                        | Self::Succeeded
                        | Self::Failed
                        | Self::Interrupted
                        | Self::ControlLost
                )
                | (
                    Self::Running,
                    Self::Stopping | Self::Succeeded | Self::Failed | Self::ControlLost
                )
                | (
                    Self::Stopping,
                    Self::Succeeded | Self::Failed | Self::Interrupted | Self::ControlLost
                )
                | (
                    Self::ControlLost,
                    Self::Running
                        | Self::Stopping
                        | Self::Succeeded
                        | Self::Failed
                        | Self::Interrupted
                )
                | (
                    Self::Succeeded | Self::Failed | Self::Interrupted,
                    Self::Removed
                )
        );
        ensure!(
            allowed,
            InvalidTransitionSnafu {
                from: self.as_str(),
                to: next.as_str()
            }
        );
        Ok(())
    }

    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Succeeded | Self::Failed | Self::Interrupted | Self::Removed
        )
    }
}

#[cfg(test)]
mod tests {
    use super::SessionLifecycleState;

    #[test]
    fn lifecycle_table_accepts_every_documented_edge_and_no_other_edge() {
        use SessionLifecycleState::{
            ControlLost, Created, Failed, Interrupted, Removed, Running, Starting, Stopping,
            Succeeded,
        };

        let states = [
            Created,
            Starting,
            Running,
            Stopping,
            ControlLost,
            Succeeded,
            Failed,
            Interrupted,
            Removed,
        ];
        let allowed = [
            (Created, Starting),
            (Created, Removed),
            (Starting, Running),
            (Starting, Stopping),
            (Starting, Succeeded),
            (Starting, Failed),
            (Starting, Interrupted),
            (Starting, ControlLost),
            (Running, Stopping),
            (Running, Succeeded),
            (Running, Failed),
            (Running, ControlLost),
            (Stopping, Succeeded),
            (Stopping, Failed),
            (Stopping, Interrupted),
            (Stopping, ControlLost),
            (ControlLost, Running),
            (ControlLost, Stopping),
            (ControlLost, Succeeded),
            (ControlLost, Failed),
            (ControlLost, Interrupted),
            (Succeeded, Removed),
            (Failed, Removed),
            (Interrupted, Removed),
        ];

        for from in states {
            for to in states {
                assert_eq!(
                    from.transition(to).is_ok(),
                    allowed.contains(&(from, to)),
                    "unexpected transition result for {} -> {}",
                    from.as_str(),
                    to.as_str()
                );
            }
        }
    }
}
