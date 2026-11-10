use std::collections::{BTreeMap, BTreeSet};

use snafu::ResultExt as _;

use super::super::{DataView, NativeStore};
use super::{attempts::Attempts, InstanceRecord, Records, VersionRecord};
use crate::analysis::managed::{Attempt, Failure, FailureOrigin};
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
        let mut captures = Vec::new();
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
            if capture.progress != 0
                || capture.prior.values().any(Option::is_some)
                || !capture.dependencies.is_empty()
                || attempt.receipt.is_some()
            {
                return Err(Code::Unsupported.error("native managed result recovery"));
            }
            capture.check_follow_mode(spec)?;
            captures.push((
                owner,
                capture.expected_generation,
                capture.revision,
                capture.completed,
            ));
            if let Some(terminal) = &attempt.terminal {
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
                history
                    .entry((owner, capture.generation))
                    .or_default()
                    .insert(terminal.revision);
                let outcome = Attempts::outcome(owner, capture.generation);
                let latest = completed.entry(outcome).or_default();
                if terminal.revision > latest.0 {
                    *latest = (terminal.revision, id);
                }
                if ended
                    .insert(Attempts::ended(owner, terminal.revision), id)
                    .is_some()
                {
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
        for (owner, generation, revision, completed) in captures {
            let actual = history
                .get(&(owner, generation))
                .and_then(|revisions| revisions.range(..=revision).next_back())
                .copied()
                .unwrap_or(0);
            if completed != actual {
                return NativeStateSnafu {
                    field: "managed captured completion",
                }
                .fail();
            }
        }
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
            let bytes = Records::payload(&key, |key| Records::read(key, &self.snapshot))?;
            let failure = Failure::decode(bytes, &instance, self.metadata_revision)?
                .ok_or_else(|| Code::Missing.error("managed failure record"))?;
            let attempt = self.outcome_attempt(owner, failure.revision)?;
            if failure.origin != FailureOrigin::Attempt
                || attempt.capture.generation != instance.generation
                || attempt.capture.progress != failure.progress
                || attempt.terminal.is_none_or(|terminal| {
                    terminal.exit != ManagedExit::Failed(failure.code)
                        || terminal.revision != failure.revision
                })
            {
                return NativeStateSnafu {
                    field: "managed failure outcome",
                }
                .fail();
            }
        }
        Ok(())
    }
}
