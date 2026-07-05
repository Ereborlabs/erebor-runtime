use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditCommandLogLevel {
    All,
    #[default]
    Signal,
    NonAllow,
}
