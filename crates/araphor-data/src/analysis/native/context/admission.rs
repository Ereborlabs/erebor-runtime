use super::{ContextRecord, DataView, DataWrite, NativeStore, Records};
use crate::{
    AnalysisContextRefV1, AnalysisContextVersionV1, ApprovedNotificationRouteV1,
    DiscoveryContextRevisionV1, NativeStateSnafu, Result,
};

impl NativeStore {
    pub fn commit_contexts_checked(
        &self,
        inputs: &[(AnalysisContextVersionV1, u64)],
        mut check: impl FnMut() -> Result<()>,
    ) -> Result<Vec<AnalysisContextRefV1>> {
        if inputs.is_empty() {
            check()?;
            return Ok(Vec::new());
        }
        let mut tx = self.write()?;
        let references = inputs
            .iter()
            .map(|(input, expected)| tx.context(input, Some(*expected)))
            .collect::<Result<Vec<_>>>()?;
        check()?;
        #[cfg(any(test, feature = "test-fixtures"))]
        self.run_commit_hook(crate::AnalysisCommitStage::BeforeContextCommit)?;
        tx.commit([])?;
        Ok(references)
    }

    pub fn commit_contexts(
        &self,
        inputs: &[AnalysisContextVersionV1],
    ) -> Result<Vec<AnalysisContextRefV1>> {
        self.commit_contexts_guarded(inputs, || Ok(()))
    }

    pub fn commit_contexts_guarded(
        &self,
        inputs: &[AnalysisContextVersionV1],
        mut check: impl FnMut() -> Result<()>,
    ) -> Result<Vec<AnalysisContextRefV1>> {
        self.commit_context_values(inputs, false, None, &mut check)
    }

    pub fn commit_context(&self, input: &AnalysisContextVersionV1) -> Result<u64> {
        self.commit_context_checked_inner(input, None)
    }

    pub fn commit_context_checked(
        &self,
        input: &AnalysisContextVersionV1,
        expected: u64,
    ) -> Result<u64> {
        self.commit_context_checked_inner(input, Some(expected))
    }

    fn commit_context_checked_inner(
        &self,
        input: &AnalysisContextVersionV1,
        expected: Option<u64>,
    ) -> Result<u64> {
        self.commit_context_values(std::slice::from_ref(input), false, expected, &mut || Ok(()))?
            .pop()
            .map(|reference| reference.commit_revision)
            .ok_or_else(|| {
                NativeStateSnafu {
                    field: "committed context reference",
                }
                .build()
            })
    }

    pub fn intern_context(&self, input: &AnalysisContextVersionV1) -> Result<AnalysisContextRefV1> {
        self.intern_context_guarded(input, || Ok(()))
    }

    pub fn intern_context_guarded(
        &self,
        input: &AnalysisContextVersionV1,
        check: impl FnMut() -> Result<()>,
    ) -> Result<AnalysisContextRefV1> {
        self.intern_contexts_guarded(std::slice::from_ref(input), check)?
            .pop()
            .ok_or_else(|| {
                NativeStateSnafu {
                    field: "committed context reference",
                }
                .build()
            })
    }

    pub fn intern_contexts_guarded(
        &self,
        inputs: &[AnalysisContextVersionV1],
        mut check: impl FnMut() -> Result<()>,
    ) -> Result<Vec<AnalysisContextRefV1>> {
        if inputs.iter().any(|input| !ContextRecord::internable(input)) {
            return crate::Error::reject_path(&self.root, "the qualified context owner is invalid");
        }
        self.commit_context_values(inputs, true, None, &mut check)
    }

    fn commit_context_values(
        &self,
        inputs: &[AnalysisContextVersionV1],
        intern: bool,
        expected: Option<u64>,
        check: &mut dyn FnMut() -> Result<()>,
    ) -> Result<Vec<AnalysisContextRefV1>> {
        if inputs.is_empty() {
            check()?;
            return Ok(Vec::new());
        }
        if inputs.iter().any(|input| !input.valid()) {
            return crate::Error::reject_path(
                &self.root,
                "the context version identity or bounds are invalid",
            );
        }
        let mut tx = self.write()?;
        let references = inputs
            .iter()
            .map(|input| tx.admit_context(input, intern, expected))
            .collect::<Result<Vec<_>>>()?;
        check()?;
        #[cfg(any(test, feature = "test-fixtures"))]
        self.run_commit_hook(crate::AnalysisCommitStage::BeforeContextCommit)?;
        tx.commit([])?;
        Ok(references)
    }
}

impl ContextRecord {
    pub(super) fn internable(input: &AnalysisContextVersionV1) -> bool {
        matches!(
            input.key.owner_id.as_str(),
            "discovery-facts-v1" | "discovery-source-v1" | "native-package-v1"
        )
    }
}

impl DataWrite<'_> {
    /// Discard this transaction if context staging returns an error.
    pub fn context(
        &mut self,
        input: &AnalysisContextVersionV1,
        expected: Option<u64>,
    ) -> Result<AnalysisContextRefV1> {
        self.admit_context(input, false, expected)
    }

    /// Discard this transaction if batch staging returns an error.
    pub fn contexts(
        &mut self,
        inputs: &[AnalysisContextVersionV1],
    ) -> Result<Vec<AnalysisContextRefV1>> {
        inputs
            .iter()
            .map(|input| self.admit_context(input, false, None))
            .collect()
    }

    pub(in crate::analysis::native) fn verify_context(
        &mut self,
        input: &AnalysisContextVersionV1,
    ) -> Result<()> {
        let mut verified = std::mem::take(&mut self.verified);
        let result = verified.check_context(input, |tenant, package, revision| {
            self.package_revision(tenant, package, revision)
        });
        self.verified = verified;
        result
    }

    fn admit_context(
        &mut self,
        input: &AnalysisContextVersionV1,
        intern: bool,
        expected: Option<u64>,
    ) -> Result<AnalysisContextRefV1> {
        if !input.valid() {
            return NativeStateSnafu {
                field: "context input",
            }
            .fail();
        }
        let notification = (input.key.owner_id == crate::NOTIFICATION_STATE_OWNER)
            .then(|| crate::analysis::notification::NotificationKeys::from_context(input))
            .transpose()?;
        if input.key.owner_id == crate::NOTIFICATION_ROUTE_OWNER {
            ApprovedNotificationRouteV1::try_from(input)?;
        }
        let imported = (input.key.owner_id == "discovery-context-v1")
            .then(|| DiscoveryContextRevisionV1::try_from(input))
            .transpose()?;
        let current = if intern {
            None
        } else {
            ContextRecord::id(&input.key, |key| Records::staged(key, &self.transaction))?
                .map(|id| {
                    ContextRecord::load(id, |key| Records::staged(key, &self.transaction))
                        .map(|row| (id, row))
                })
                .transpose()?
        };
        if let Some((id, row)) = &current {
            ContextRecord::check(row, &input.key)?;
            if row.version == *input {
                DataView::check_fact(*id, input, |key| Records::staged(key, &self.transaction))?;
                self.verify_context(&row.version)
                    .map_err(crate::Error::stored_artifact)?;
                return Ok(AnalysisContextRefV1 {
                    key: input.key.clone(),
                    commit_revision: row.revision,
                });
            }
        }
        self.verify_context(input)?;
        if intern {
            if let Some((id, row)) = self.interned(input)? {
                DataView::check_fact(id, &row.version, |key| {
                    Records::staged(key, &self.transaction)
                })?;
                return Ok(AnalysisContextRefV1 {
                    key: row.version.key,
                    commit_revision: row.revision,
                });
            }
        } else if let Some((_, row)) = current {
            self.verify_context(&row.version)
                .map_err(crate::Error::stored_artifact)?;
            return crate::AnalysisConflictSnafu.fail();
        }
        let fact = crate::analysis::context::FactRecord::from_context(input)?;
        let document = if let Some(imported) = imported {
            let identity = ContextRecord::document(&input.key)?;
            let prior = Records::find(&identity, |key| Records::staged(key, &self.transaction))?
                .map(|id| Records::staged(&Records::key(b'M', id), &self.transaction))
                .transpose()?
                .flatten()
                .map(|id| {
                    ContextRecord::load(NativeStore::number(&id)?, |key| {
                        Records::staged(key, &self.transaction)
                    })
                })
                .transpose()?;
            let prior = prior
                .map(|row| DiscoveryContextRevisionV1::try_from(&row.version))
                .transpose()?;
            imported.validate_history(prior.as_ref())?;
            Some(identity)
        } else {
            None
        };
        let reference = self.record(input, expected, notification)?;
        let id = ContextRecord::id(&input.key, |key| Records::staged(key, &self.transaction))?
            .ok_or_else(|| {
                NativeStateSnafu {
                    field: "staged context identity",
                }
                .build()
            })?;
        if let Some(fact) = fact {
            let bytes = Records::encode(&fact)?;
            Records::stage(&mut self.transaction, Records::key(b'K', id), bytes);
        }
        if ContextRecord::internable(input) {
            let scope = Records::intern(&mut self.transaction, &ContextRecord::scope(input)?)?;
            self.transaction.insert(
                [Records::key(b'V', scope), id.to_be_bytes().to_vec()].concat(),
                [],
            );
        }
        if let Some(identity) = document {
            let scope = Records::intern(&mut self.transaction, &identity)?;
            self.transaction
                .insert(Records::key(b'M', scope), id.to_be_bytes());
        }
        Ok(reference)
    }

    fn interned(
        &mut self,
        input: &AnalysisContextVersionV1,
    ) -> Result<Option<(u64, ContextRecord)>> {
        if let Some(scope) = Records::find(&ContextRecord::scope(input)?, |key| {
            Records::staged(key, &self.transaction)
        })? {
            let mut selected: Option<(u64, ContextRecord)> = None;
            let prefix = Records::key(b'V', scope);
            for entry in self.transaction.prefix(&prefix) {
                use snafu::ResultExt as _;
                let (key, _) = entry.context(crate::NativeStorageSnafu {
                    operation: "read qualified context scope",
                })?;
                let id = NativeStore::number(&key[prefix.len()..])?;
                let row = ContextRecord::load(id, |key| Records::staged(key, &self.transaction))?;
                if row.version.key.tenant_id != input.key.tenant_id
                    || row.version.key.owner_id != input.key.owner_id
                    || row.version.key.lifetime_key != input.key.lifetime_key
                {
                    return NativeStateSnafu {
                        field: "qualified context scope",
                    }
                    .fail();
                }
                if row.version.body == input.body
                    && row.version.sensitivity == input.sensitivity
                    && row.version.valid_from_utc_ns == input.valid_from_utc_ns
                    && row.version.valid_until_utc_ns == input.valid_until_utc_ns
                    && selected.as_ref().is_none_or(|(_, prior)| {
                        row.version.key.entity_key < prior.version.key.entity_key
                    })
                {
                    selected = Some((id, row));
                }
            }
            if selected.is_some() {
                return Ok(selected);
            }
        }
        let Some(id) =
            ContextRecord::id(&input.key, |key| Records::staged(key, &self.transaction))?
        else {
            return Ok(None);
        };
        let row = ContextRecord::load(id, |key| Records::staged(key, &self.transaction))?;
        ContextRecord::check(&row, &input.key)?;
        if row.version != *input {
            self.verify_context(&row.version)
                .map_err(crate::Error::stored_artifact)?;
            return crate::AnalysisConflictSnafu.fail();
        }
        Ok(Some((id, row)))
    }
}
