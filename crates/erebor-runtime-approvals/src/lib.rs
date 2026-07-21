//! Exact-effect durable approval domain model and repository contract.

mod error;

use serde::{Deserialize, Serialize};
use snafu::ensure;

pub use error::{ApprovalError, Result};

use error::{
    BindingMismatchSnafu, ExpiredSnafu, InvalidBindingSnafu, NotApprovedSnafu, NotPendingSnafu,
};

/// Facts that must remain exact from the approval request to the physical effect.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalBinding {
    owner_uid: u32,
    session_id: String,
    session_generation: u64,
    effect_digest: String,
    process_identity: String,
    policy_set_digest: String,
    policy_rule_id: String,
}

impl ApprovalBinding {
    pub fn new(
        owner_uid: u32,
        session_id: impl Into<String>,
        session_generation: u64,
        effect_digest: impl Into<String>,
        process_identity: impl Into<String>,
        policy_set_digest: impl Into<String>,
        policy_rule_id: impl Into<String>,
    ) -> Result<Self> {
        let binding = Self {
            owner_uid,
            session_id: session_id.into(),
            session_generation,
            effect_digest: effect_digest.into(),
            process_identity: process_identity.into(),
            policy_set_digest: policy_set_digest.into(),
            policy_rule_id: policy_rule_id.into(),
        };
        binding.validate()?;
        Ok(binding)
    }

    pub fn validate(&self) -> Result<()> {
        ensure!(
            !self.session_id.trim().is_empty()
                && self.session_generation > 0
                && Self::is_sha256(&self.effect_digest)
                && !self.process_identity.trim().is_empty()
                && Self::is_sha256(&self.policy_set_digest)
                && !self.policy_rule_id.trim().is_empty(),
            InvalidBindingSnafu {
                reason: String::from(
                    "session, generation, effect, process, policy-set, and rule identity must be present"
                )
            }
        );
        Ok(())
    }

    #[must_use]
    pub const fn owner_uid(&self) -> u32 {
        self.owner_uid
    }

    #[must_use]
    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    #[must_use]
    pub const fn session_generation(&self) -> u64 {
        self.session_generation
    }

    #[must_use]
    pub fn effect_digest(&self) -> &str {
        &self.effect_digest
    }

    #[must_use]
    pub fn process_identity(&self) -> &str {
        &self.process_identity
    }

    #[must_use]
    pub fn policy_set_digest(&self) -> &str {
        &self.policy_set_digest
    }

    #[must_use]
    pub fn policy_rule_id(&self) -> &str {
        &self.policy_rule_id
    }

    fn is_sha256(value: &str) -> bool {
        value.len() == 64
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalState {
    Pending,
    Approved,
    Denied,
    Expired,
    Cancelled,
    Consumed,
}

impl ApprovalState {
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        !matches!(self, Self::Pending | Self::Approved)
    }
}

/// A durable record whose state transitions are deliberately single-use.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalRecord {
    id: String,
    binding: ApprovalBinding,
    state: ApprovalState,
    created_at_unix_ms: u64,
    expires_at_unix_ms: u64,
    resolved_at_unix_ms: Option<u64>,
    reason: Option<String>,
}

impl ApprovalRecord {
    pub fn pending(
        id: impl Into<String>,
        binding: ApprovalBinding,
        created_at_unix_ms: u64,
        expires_at_unix_ms: u64,
    ) -> Result<Self> {
        let record = Self {
            id: id.into(),
            binding,
            state: ApprovalState::Pending,
            created_at_unix_ms,
            expires_at_unix_ms,
            resolved_at_unix_ms: None,
            reason: None,
        };
        record.validate_new()?;
        Ok(record)
    }

    pub fn approve(&mut self, now_unix_ms: u64) -> Result<()> {
        self.require_pending(now_unix_ms)?;
        self.state = ApprovalState::Approved;
        self.resolved_at_unix_ms = Some(now_unix_ms);
        self.reason = None;
        Ok(())
    }

    pub fn deny(&mut self, now_unix_ms: u64, reason: impl Into<String>) -> Result<()> {
        self.require_pending(now_unix_ms)?;
        self.state = ApprovalState::Denied;
        self.resolved_at_unix_ms = Some(now_unix_ms);
        self.reason = Some(reason.into());
        Ok(())
    }

    pub fn cancel(&mut self, now_unix_ms: u64, reason: impl Into<String>) -> Result<()> {
        if !matches!(self.state, ApprovalState::Pending | ApprovalState::Approved) {
            return NotPendingSnafu {
                approval_id: self.id.clone(),
            }
            .fail();
        }
        self.state = ApprovalState::Cancelled;
        self.resolved_at_unix_ms = Some(now_unix_ms);
        self.reason = Some(reason.into());
        Ok(())
    }

    pub fn expire_if_due(&mut self, now_unix_ms: u64) -> bool {
        if matches!(self.state, ApprovalState::Pending | ApprovalState::Approved)
            && now_unix_ms >= self.expires_at_unix_ms
        {
            self.state = ApprovalState::Expired;
            self.resolved_at_unix_ms = Some(now_unix_ms);
            self.reason = Some(String::from("approval expired"));
            return true;
        }
        false
    }

    pub fn consume(&mut self, now_unix_ms: u64, binding: &ApprovalBinding) -> Result<()> {
        if self.expire_if_due(now_unix_ms) {
            return ExpiredSnafu {
                approval_id: self.id.clone(),
            }
            .fail();
        }
        if self.state != ApprovalState::Approved {
            return NotApprovedSnafu {
                approval_id: self.id.clone(),
            }
            .fail();
        }
        if &self.binding != binding {
            return BindingMismatchSnafu {
                approval_id: self.id.clone(),
            }
            .fail();
        }
        self.state = ApprovalState::Consumed;
        self.resolved_at_unix_ms = Some(now_unix_ms);
        self.reason = None;
        Ok(())
    }

    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    #[must_use]
    pub fn binding(&self) -> &ApprovalBinding {
        &self.binding
    }

    #[must_use]
    pub const fn state(&self) -> ApprovalState {
        self.state
    }

    #[must_use]
    pub const fn expires_at_unix_ms(&self) -> u64 {
        self.expires_at_unix_ms
    }

    fn validate_new(&self) -> Result<()> {
        self.binding.validate()?;
        ensure!(
            !self.id.is_empty()
                && self
                    .id
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
                && self.expires_at_unix_ms > self.created_at_unix_ms,
            InvalidBindingSnafu {
                reason: String::from(
                    "approval id must be path-safe and expiry must follow creation"
                )
            }
        );
        Ok(())
    }

    fn require_pending(&mut self, now_unix_ms: u64) -> Result<()> {
        if self.expire_if_due(now_unix_ms) {
            return ExpiredSnafu {
                approval_id: self.id.clone(),
            }
            .fail();
        }
        if self.state != ApprovalState::Pending {
            return NotPendingSnafu {
                approval_id: self.id.clone(),
            }
            .fail();
        }
        Ok(())
    }
}

/// The daemon-owned durable store contract. A repository must atomically
/// persist a transition before it exposes the resulting record to a guard.
pub trait ApprovalRepository {
    fn create(&self, record: ApprovalRecord) -> Result<ApprovalRecord>;
    fn inspect(&self, owner_uid: u32, approval_id: &str) -> Result<ApprovalRecord>;
    fn list_pending(&self, owner_uid: u32) -> Result<Vec<ApprovalRecord>>;
    fn replace(&self, record: ApprovalRecord) -> Result<ApprovalRecord>;
}

#[cfg(test)]
mod tests {
    use super::{ApprovalBinding, ApprovalRecord, ApprovalState};

    const DIGEST: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    fn binding() -> Result<ApprovalBinding, Box<dyn std::error::Error>> {
        Ok(ApprovalBinding::new(
            1000,
            "session-1",
            2,
            DIGEST,
            "pidfd:7",
            DIGEST,
            "rule-1",
        )?)
    }

    #[test]
    fn approval_is_single_use_and_exact_effect_bound() -> Result<(), Box<dyn std::error::Error>> {
        let mut record = ApprovalRecord::pending("approval-1", binding()?, 10, 20)?;
        record.approve(11)?;
        record.consume(12, &binding()?)?;
        assert_eq!(record.state(), ApprovalState::Consumed);
        assert!(record.consume(13, &binding()?).is_err());
        Ok(())
    }

    #[test]
    fn approval_expires_before_any_late_transition() -> Result<(), Box<dyn std::error::Error>> {
        let mut record = ApprovalRecord::pending("approval-1", binding()?, 10, 20)?;
        assert!(record.approve(20).is_err());
        assert_eq!(record.state(), ApprovalState::Expired);
        Ok(())
    }

    #[test]
    fn mismatched_process_cannot_consume_an_approved_effect(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut record = ApprovalRecord::pending("approval-1", binding()?, 10, 20)?;
        record.approve(11)?;
        let other =
            ApprovalBinding::new(1000, "session-1", 2, DIGEST, "pidfd:8", DIGEST, "rule-1")?;
        assert!(record.consume(12, &other).is_err());
        assert_eq!(record.state(), ApprovalState::Approved);
        Ok(())
    }
}
