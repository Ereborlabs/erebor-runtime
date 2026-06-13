use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "type")]
pub enum Decision {
    Allow {
        rule_id: Option<String>,
    },
    Deny {
        reason: String,
        rule_id: Option<String>,
    },
    RequireApproval {
        reason: String,
        rule_id: Option<String>,
        approval_id: Option<String>,
    },
    Mediate {
        reason: String,
        rule_id: Option<String>,
        mediation: Option<serde_json::Value>,
    },
}

impl Decision {
    #[must_use]
    pub fn rule_id(&self) -> Option<&str> {
        match self {
            Self::Allow { rule_id }
            | Self::Deny { rule_id, .. }
            | Self::RequireApproval { rule_id, .. }
            | Self::Mediate { rule_id, .. } => rule_id.as_deref(),
        }
    }
}
