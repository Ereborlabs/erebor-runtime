use snafu::ResultExt as _;

use super::{attempts::Attempts, InstanceRecord, Records, VersionRecord};
use crate :: analysis :: { managed :: Attempt , native :: { DataView , NativeStore } } ;
use crate :: { AnalysisReadControl , AnalysisSelectionV1 , ManagedReceipt , NativeStorageSnafu , PackageErrorCodeV1 as Code , Result } ;

impl NativeStore {
    pub fn managed_history(
        &self,
        selection: &AnalysisSelectionV1,
        id: &str,
        control: &AnalysisReadControl,
    ) -> Result<Vec<ManagedReceipt>> {
        self.view()?.managed_history(selection, id, control)
    }
}

impl DataView {
    pub fn managed_history(
        &self,
        selection: &AnalysisSelectionV1,
        id: &str,
        control: &AnalysisReadControl,
    ) -> Result<Vec<ManagedReceipt>> {
        let instance = self
            .managed_instance(selection.tenant_id, id, control)?
            .ok_or_else(|| Code::Missing.error("managed history instance"))?;
        let mut authorized = instance.grant.permitted_by(selection).is_ok();
        let owner = Records::find(&InstanceRecord::identity(selection.tenant_id, id)?, |key| {
            Records::read(key, &self.snapshot)
        })?
        .ok_or_else(|| Code::Missing.error("managed history instance"))?;
        let mut history = Vec::new();
        for kind in [b'p', b'E'] {
            let prefix = Records::key(kind, owner);
            for row in self.snapshot.prefix(&prefix) {
                control.check()?;
                let (key, value) = row.context(NativeStorageSnafu {
                    operation: "read managed history",
                })?;
                if key.len() != prefix.len() + if kind == b'p' { 16 } else { 8 } {
                    return Err(Code::Invalid.error("managed history key"));
                }
                let (attempt_id, completed) = if kind == b'p' {
                    (NativeStore::number(&key[prefix.len() + 8..])?, 0)
                } else {
                    (
                        NativeStore::number(&value)?,
                        NativeStore::number(&key[prefix.len()..])?,
                    )
                };
                let bytes = Records::payload(&Records::key(b'a', attempt_id), |key| {
                    Records::read(key, &self.snapshot)
                })?
                .ok_or_else(|| Code::Missing.error("managed history attempt"))?;
                let attempt: Attempt = Records::decode(&bytes)?;
                let capture = &attempt.capture;
                if capture.tenant != selection.tenant_id
                    || capture.instance != id
                    || Records::find(
                        &Attempts::identity(capture.tenant, id, &attempt.request.id)?,
                        |key| Records::read(key, &self.snapshot),
                    )? != Some(attempt_id)
                    || capture.generation == 0
                    || capture.generation > capture.revision
                    || attempt.registered == 0
                    || attempt.registered > self.metadata_revision
                    || kind == b'p'
                        && NativeStore::number(&key[prefix.len()..prefix.len() + 8])?
                            != capture.generation
                {
                    return Err(Code::Invalid.error("managed history generation"));
                }
                let version = VersionRecord::read(
                    owner,
                    capture.tenant,
                    id,
                    capture.generation,
                    self.metadata_revision,
                    |key| Records::read(key, &self.snapshot),
                )?;
                capture.grant.validate()?;
                if capture.grant.selection != version.scope {
                    return Err(Code::Invalid.error("managed history scope"));
                }
                let permitted = capture.grant.permitted_by(selection).is_ok();
                authorized |= permitted;
                match (attempt.receipt, attempt.terminal) {
                    (Some(receipt), None) => {
                        if receipt.instance != id
                            || receipt.attempt != attempt.request.id
                            || receipt.commit_revision != completed
                            || completed <= attempt.registered
                            || completed > self.metadata_revision
                            || !receipt.matches_frontier(&attempt.request.frontier)
                            || receipt.selected.result_id.is_empty()
                            || receipt.selected.commit_revision != completed
                            || receipt.results.iter().any(|(call, reference)| {
                                !version.spec.manifest.calls.contains_key(call)
                                    || reference.result_id.is_empty()
                                    || reference.commit_revision != completed
                            })
                        {
                            return Err(Code::Invalid.error("managed history receipt"));
                        }
                        if permitted {
                            history.push(receipt);
                        }
                    }
                    (None, Some(terminal))
                        if terminal.instance == id
                            && terminal.attempt == attempt.request.id
                            && terminal.revision == completed
                            && completed > attempt.registered
                            && completed <= self.metadata_revision => {}
                    (None, None) if completed == 0 => {}
                    _ => return Err(Code::Invalid.error("managed history outcome")),
                }
            }
        }
        if !authorized {
            return Err(Code::Denied.error("managed history scope"));
        }
        history.sort_by(|left, right| {
            (left.commit_revision, &left.attempt).cmp(&(right.commit_revision, &right.attempt))
        });
        control.check()?;
        Ok(history)
    }
}
