use crate::authority::AuthorityStateV1;
use crate::{AuthorityErrorCodeV1, Result};

use super::{commit, ControlStore, ControlTransactionV1};

impl ControlStore {
    pub(crate) fn authority_state(&self) -> Result<AuthorityStateV1> {
        Ok(self.evidence_lock()?.state.authority.clone())
    }

    pub(crate) fn update_authority(
        &self,
        update: impl FnOnce(&mut AuthorityStateV1) -> Result<bool>,
    ) -> Result<()> {
        let mut inner = self.lock()?;
        let mut next = inner.state.authority.clone();
        if !update(&mut next)? {
            return Ok(());
        }
        let expected_revision = next.revision;
        next.revision = expected_revision
            .checked_add(1)
            .ok_or_else(|| AuthorityErrorCodeV1::Unavailable.error("authority state revision"))?;
        commit(
            &mut inner,
            ControlTransactionV1::AuthorityUpdated {
                expected_revision,
                state: Box::new(next),
            },
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use sha2::{Digest as _, Sha256};

    #[test]
    fn control_authority_prior_control_store_schema_is_rejected(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let dir = tempfile::tempdir()?;
        #[derive(serde::Serialize)]
        struct PriorState {
            schema_version: u32,
            state: std::collections::BTreeMap<String, String>,
        }
        let encoded = rmp_serde::to_vec_named(&PriorState {
            schema_version: super::super::STORE_SCHEMA_VERSION - 1,
            state: Default::default(),
        })?;
        let mut bytes = Sha256::digest(&encoded).to_vec();
        bytes.extend_from_slice(&encoded);
        std::fs::write(dir.path().join("state.bin"), bytes)?;
        assert!(
            matches!(crate::ControlStore::open(dir.path()), Err(crate::Error::ControlStore { reason, .. }) if reason.contains("schema"))
        );
        Ok(())
    }
}
