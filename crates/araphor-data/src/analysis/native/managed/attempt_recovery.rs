use std::collections::{BTreeMap, BTreeSet};

use snafu::ResultExt as _;

use super::super::{DataView, NativeStore};
use super::{attempts::Attempts, InstanceRecord, Records, VersionRecord};
use crate::analysis::managed::{Attempt, Failure};
use crate::{
    AnalysisReadControl, ManagedExit, NativeStateSnafu, NativeStorageSnafu,
    PackageErrorCodeV1 as Code, Result,
};

impl DataView {
    pub(in crate::analysis::native) fn validate_attempts(&self) -> Result<()> {
        let control = AnalysisReadControl::default();
        let mut pending = BTreeMap::new();
        let mut completed = BTreeMap::<Vec<u8>, (u64, u64)>::new();
        let mut ended = BTreeMap::new();
        let mut history = BTreeMap::<(u64, u64), BTreeSet<u64>>::new();
        let mut successes = BTreeMap::<(u64, u64), BTreeSet<u64>>::new();
        let mut captures = Vec::new();
        let mut inputs = BTreeMap::<(u64, u64, u64), u64>::new();
        for row in self.snapshot.prefix(b"\0data/a") {
            let (key, _) = row.context(NativeStorageSnafu {
                operation: "validate managed attempts",
            })?;
            if key.len() == 23 {
                continue;
            }
            if key.len() != 15 {
                return NativeStateSnafu {
                    field: "managed attempt key",
                }
                .fail();
            }
            let id = NativeStore::number(&key[7..])?;
            let bytes = Records::payload(&key, |key| Records::read(key, &self.snapshot))?
                .ok_or_else(|| Code::Missing.error("managed attempt"))?;
            let attempt: Attempt = Records::decode(&bytes)?;
            let capture = &attempt.capture;
            Attempts::validate_request(&attempt.request)?;
            capture.grant.validate()?;
            self.check_input_token(capture)?;
            let owner = Records::find(
                &InstanceRecord::identity(capture.tenant, &capture.instance)?,
                |key| Records::read(key, &self.snapshot),
            )?
            .ok_or_else(|| Code::Missing.error("managed attempt instance"))?;
            let instance = self
                .managed_instance(capture.tenant, &capture.instance, &control)?
                .ok_or_else(|| Code::Missing.error("managed attempt instance"))?;
            let version = VersionRecord::read(
                owner,
                capture.tenant,
                &capture.instance,
                capture.generation,
                self.metadata_revision,
                |key| Records::read(key, &self.snapshot),
            )?;
            VersionRecord::read(
                owner,
                capture.tenant,
                &capture.instance,
                capture.expected_generation,
                self.metadata_revision,
                |key| Records::read(key, &self.snapshot),
            )?;
            let spec = &version.spec;
            if Records::find(
                &Attempts::identity(capture.tenant, &capture.instance, &attempt.request.id)?,
                |key| Records::read(key, &self.snapshot),
            )? != Some(id)
                || capture.tenant != capture.grant.selection.tenant_id
                || capture.store != self.store_uuid
                || capture.schema != self.schema_version
                || capture.recovery == 0
                || capture.recovery > self.recovery_epoch
                || capture.revision >= attempt.registered
                || attempt.registered > self.metadata_revision
                || capture.generation > capture.revision
                || capture.expected_generation > capture.revision
                || capture.grant.selection != version.scope
                || capture.lifecycle == instance.lifecycle && capture.grant != instance.grant
                || capture.lifecycle < capture.expected_generation
                || capture.lifecycle > instance.lifecycle
                || capture.lifecycle > capture.revision
                || capture.lifecycle == capture.expected_generation && capture.running
                || capture.lifecycle == instance.lifecycle && capture.running != instance.running
                || capture.progress > capture.completed
                || capture.completed > capture.revision
                || capture.prior.keys().ne(spec.manifest.calls.keys())
                || capture.time_utc_ns != attempt.request.time_utc_ns
                || capture.rebuild != attempt.request.rebuild
                || capture
                    .sources
                    .windows(2)
                    .any(|pair| pair[0].0 >= pair[1].0)
                || capture
                    .sources
                    .iter()
                    .any(|(name, revision)| name.is_empty() || *revision > capture.revision)
                || capture
                    .contexts
                    .windows(2)
                    .any(|pair| pair[0].key >= pair[1].key)
                || capture.contexts.iter().any(|reference| {
                    !reference.key.valid()
                        || reference.key.tenant_id != capture.tenant
                        || reference.commit_revision == 0
                        || reference.commit_revision > capture.revision
                })
                || capture.witnesses.windows(2).any(|pair| {
                    (&pair[0].identity, pair[0].cursor) >= (&pair[1].identity, pair[1].cursor)
                })
                || capture.witnesses.iter().any(|witness| {
                    !witness.identity.valid()
                        || witness.identity.tenant() != capture.tenant
                        || witness.cursor == 0
                        || witness.expires_utc_ns < attempt.request.time_utc_ns
                })
            {
                return NativeStateSnafu {
                    field: "managed attempt contract",
                }
                .fail();
            }
            capture.check_follow_mode(spec)?;
            captures.push((
                owner,
                capture.expected_generation,
                capture.revision,
                capture.completed,
                capture.progress,
            ));
            let outcome = if let Some(receipt) = &attempt.receipt {
                if attempt.terminal.is_some() {
                    return Err(Code::Invalid.error("managed attempt outcome"));
                }
                self.validate_success(&attempt)?;
                if let Some(input) = capture.input.as_ref().filter(|input| {
                    input.exhaustive
                        && receipt
                            .frontier
                            .as_ref()
                            .is_none_or(|frontier| !frontier.pending)
                }) {
                    let completed = inputs
                        .entry((owner, input.generation, input.version))
                        .or_default();
                    *completed = (*completed).max(capture.revision);
                }
                successes
                    .entry((owner, capture.generation))
                    .or_default()
                    .insert(receipt.commit_revision);
                Some(receipt.commit_revision)
            } else if let Some(terminal) = &attempt.terminal {
                if terminal.instance != capture.instance
                    || terminal.attempt != attempt.request.id
                    || terminal.revision <= attempt.registered
                    || terminal.revision > self.metadata_revision
                    || terminal.suspended
                        && (terminal.exit != ManagedExit::Failed(Code::Denied)
                            || !capture.running
                            || instance.lifecycle < terminal.revision
                            || instance.lifecycle == terminal.revision && instance.running)
                {
                    return NativeStateSnafu {
                        field: "managed terminal contract",
                    }
                    .fail();
                }
                if matches!(terminal.exit, ManagedExit::Failed(_))
                    && capture.generation == instance.generation
                    && capture.expected_generation == capture.generation
                    && capture.progress == instance.progress
                    && (capture.lifecycle == instance.lifecycle
                        || terminal.suspended && terminal.revision == instance.lifecycle)
                {
                    let bytes = Records::payload(&Records::key(b'Y', owner), |key| {
                        Records::read(key, &self.snapshot)
                    })?;
                    if Failure::decode(bytes, &instance, self.metadata_revision)?
                        .is_none_or(|failure| failure.revision < terminal.revision)
                    {
                        return NativeStateSnafu {
                            field: "managed failure status",
                        }
                        .fail();
                    }
                }
                Some(terminal.revision)
            } else {
                None
            };
            if let Some(revision) = outcome {
                history
                    .entry((owner, capture.generation))
                    .or_default()
                    .insert(revision);
                let outcome = Attempts::outcome(owner, capture.generation);
                let latest = completed.entry(outcome).or_default();
                if revision > latest.0 {
                    *latest = (revision, id);
                }
                if ended.insert(Attempts::ended(owner, revision), id).is_some() {
                    return NativeStateSnafu {
                        field: "managed outcome identity",
                    }
                    .fail();
                }
            } else {
                pending.insert(
                    [
                        Attempts::pending(owner, capture.generation),
                        id.to_be_bytes().to_vec(),
                    ]
                    .concat(),
                    attempt.registered,
                );
            }
            if instance.spec.tenant != capture.tenant {
                return NativeStateSnafu {
                    field: "managed attempt owner",
                }
                .fail();
            }
        }
        for (owner, generation, revision, completed, progress) in captures {
            let actual = history
                .get(&(owner, generation))
                .and_then(|revisions| revisions.range(..=revision).next_back())
                .copied()
                .unwrap_or(0);
            let successful = successes
                .get(&(owner, generation))
                .and_then(|revisions| revisions.range(..=revision).next_back())
                .copied()
                .unwrap_or(0);
            if completed != actual || progress != successful {
                return NativeStateSnafu {
                    field: "managed captured progress and completion",
                }
                .fail();
            }
        }
        self.check_input_completions(&inputs)?;
        self.validate_heads(b"\0data/p", pending)?;
        self.validate_heads(b"\0data/E", ended)?;
        for row in self.snapshot.prefix(b"\0data/o") {
            let (key, value) = row.context(NativeStorageSnafu {
                operation: "validate managed outcome heads",
            })?;
            let Some((revision, id)) = completed.remove(key.as_ref()) else {
                return NativeStateSnafu {
                    field: "managed outcome set",
                }
                .fail();
            };
            if value.as_ref() != [revision.to_be_bytes(), id.to_be_bytes()].concat() {
                return NativeStateSnafu {
                    field: "managed outcome head",
                }
                .fail();
            }
        }
        if !completed.is_empty() {
            return NativeStateSnafu {
                field: "managed outcome set",
            }
            .fail();
        }
        for row in self.snapshot.prefix(b"\0data/J") {
            let (key, _) = row.context(NativeStorageSnafu {
                operation: "validate managed current progress",
            })?;
            if key.len() != 15 {
                continue;
            }
            let owner = NativeStore::number(&key[7..])?;
            let bytes = Records::payload(&key, |key| Records::read(key, &self.snapshot))?
                .ok_or_else(|| Code::Missing.error("managed current instance"))?;
            let row: InstanceRecord = Records::decode(&bytes)?;
            let instance = self
                .managed_instance(row.tenant, &row.id, &control)?
                .ok_or_else(|| Code::Missing.error("managed current instance"))?;
            let successful = successes
                .get(&(owner, instance.generation))
                .and_then(|revisions| revisions.last())
                .copied()
                .unwrap_or(0);
            if instance.progress != successful {
                return Err(Code::Invalid.error("managed current progress"));
            }
            let attempt = if successful != 0 && !instance.removed {
                Some(self.outcome_attempt(owner, successful)?)
            } else {
                None
            };
            for call in instance.spec.manifest.calls.keys() {
                let expected = attempt.as_ref().and_then(|attempt| {
                    attempt
                        .receipt
                        .as_ref()
                        .and_then(|receipt| receipt.results.get(call))
                        .or_else(|| attempt.capture.prior.get(call).and_then(Option::as_ref))
                });
                let bytes = Records::payload(&InstanceRecord::call_key(owner, *call), |key| {
                    Records::read(key, &self.snapshot)
                })?
                .ok_or_else(|| Code::Missing.error("managed current call head"))?;
                let head: super::CallHead = Records::decode(&bytes)?;
                if head.revision != expected.map_or(0, |reference| reference.commit_revision)
                    || head.result.as_deref()
                        != expected.map(|reference| reference.result_id.as_str())
                {
                    return Err(Code::Invalid.error("managed current call head"));
                }
            }
        }
        for row in self.snapshot.prefix(b"\0data/Y") {
            let (key, _) = row.context(NativeStorageSnafu {
                operation: "validate managed failures",
            })?;
            if key.len() == 23 {
                continue;
            }
            if key.len() != 15 {
                return NativeStateSnafu {
                    field: "managed failure key",
                }
                .fail();
            }
            let owner = NativeStore::number(&key[7..])?;
            let bytes = Records::payload(&Records::key(b'J', owner), |key| {
                Records::read(key, &self.snapshot)
            })?
            .ok_or_else(|| Code::Missing.error("managed failure instance"))?;
            let row: InstanceRecord = Records::decode(&bytes)?;
            let instance = self
                .managed_instance(row.tenant, &row.id, &control)?
                .ok_or_else(|| Code::Missing.error("managed failure instance"))?;
            self.managed_failure(owner, &instance)?
                .ok_or_else(|| Code::Missing.error("managed failure record"))?;
        }
        Ok(())
    }
}
