use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};
use snafu::ResultExt as _;

use super::super::{records::Records, DataView, NativeStore};
use crate::analysis::raw::{RawEntry, RawIdentity, RawIndex, RawJournal, RawKind, RawReceipt};
use crate::{NativeStateSnafu, NativeStorageSnafu, Result, TraceOutputReceiptV1};

#[derive(Deserialize, Serialize)]
pub(in crate::analysis::native) struct ExpiredSegment {
    pub id: u64,
    pub end: u64,
    pub revision: u64,
    pub time: u64,
    pub entries: Vec<RawEntry>,
    pub terminal: Option<crate::TraceTerminalV1>,
}

impl ExpiredSegment {
    pub(in crate::analysis::native) const PREFIX: &'static [u8] = b"\0data/@retention/expired/";
    pub(in crate::analysis::native) const DELETING: &'static [u8] = b"\0data/@retention/deleting/";
    pub(in crate::analysis::native) const FLOOR: &'static [u8] = b"\0data/@retention/floor/";

    pub(in crate::analysis::native) fn key(prefix: &[u8], id: u64) -> Vec<u8> {
        [prefix, &id.to_be_bytes()].concat()
    }

    pub(in crate::analysis::native) fn read(
        snapshot: &fjall::BranchSnapshot,
        id: u64,
    ) -> Result<Self> {
        Self::read_charged(snapshot, id, &mut |_| Ok(()))
    }

    pub(in crate::analysis::native) fn read_charged(
        snapshot: &fjall::BranchSnapshot,
        id: u64,
        charge: &mut dyn FnMut(usize) -> Result<()>,
    ) -> Result<Self> {
        let key = Self::key(Self::PREFIX, id);
        let bytes = Records::charged_payload(&key, |key| Records::read(key, snapshot), charge)?
            .ok_or_else(|| {
                NativeStateSnafu {
                    field: "expired segment authority",
                }
                .build()
            })?;
        let record: Self = Records::decode(&bytes)?;
        record.check(id)?;
        let head = NativeStore::number(&NativeStore::required(snapshot, super::super::HEAD)?)?;
        if record.revision > head {
            return NativeStateSnafu {
                field: "expired segment revision",
            }
            .fail();
        }
        Ok(record)
    }

    fn check(&self, id: u64) -> Result<()> {
        let first = self.entries.first().ok_or_else(|| {
            NativeStateSnafu {
                field: "expired segment entries",
            }
            .build()
        })?;
        let mut end = crate::analysis::SegmentFile::encode_raw(&first.identity)?.len() as u64;
        let mut revision = 0;
        for entry in &self.entries {
            if entry.identity.evidence().is_some()
                || entry.identity != first.identity
                || !entry.identity.valid()
                || entry.reference.id != id
                || entry.commit.revision <= revision
                || entry.commit.revision >= self.revision
                || entry.commit.intake == 0
                || entry.commit.spans.is_empty()
                || entry.frame_bytes < 8
                || Some(entry.reference.offset) != end.checked_add(entry.frame_bytes as u64)
                || entry.body_start < end
                || entry
                    .body_start
                    .checked_add(entry.body_bytes as u64)
                    .is_none_or(|end| end > entry.reference.offset)
                || entry
                    .reference
                    .offset
                    .checked_sub(4)
                    .and_then(|end| end.checked_sub(entry.body_bytes as u64))
                    != Some(entry.body_start)
            {
                return NativeStateSnafu {
                    field: "expired original commit metadata",
                }
                .fail();
            }
            let mut ordinal = 0u64;
            let mut prior = 0;
            for span in &entry.commit.spans {
                if span.first == 0
                    || span.last < span.first
                    || span.first <= prior
                    || u64::from(span.ordinal) != ordinal
                    || u64::from(span.start) + u64::from(span.bytes) > entry.body_bytes as u64
                {
                    return NativeStateSnafu {
                        field: "expired original span metadata",
                    }
                    .fail();
                }
                ordinal = ordinal
                    .checked_add(span.last - span.first + 1)
                    .filter(|count| *count <= u32::MAX as u64 + 1)
                    .ok_or_else(|| {
                        NativeStateSnafu {
                            field: "expired span ordinal",
                        }
                        .build()
                    })?;
                prior = span.last;
            }
            revision = entry.commit.revision;
            end = entry.reference.offset;
        }
        if self.id != id || id == 0 || self.end != end || self.time == 0 {
            return NativeStateSnafu {
                field: "expired segment bounds",
            }
            .fail();
        }
        Ok(())
    }

    fn file(&self, root: &Path) -> Result<Option<PathBuf>> {
        self.check(self.id)?;
        let kind = "d";
        let path = root
            .join("segments")
            .join(format!("{:016x}.{kind}.{:016x}.seg", self.id, self.end));
        match fs::symlink_metadata(&path) {
            Ok(meta) if meta.is_file() && meta.len() == self.end => {
                let file = crate::analysis::SegmentFile::reader(&path)?;
                let header = crate::analysis::SegmentFile::encode_raw(&self.entries[0].identity)?;
                if file.read(0, header.len())? != header {
                    return crate::Error::reject_path(
                        &path,
                        "the deleting segment identity differs from its authority",
                    );
                }
                for entry in &self.entries {
                    let commit = crate::analysis::raw::RawCommit::read(
                        &file,
                        entry.reference.offset - entry.frame_bytes as u64,
                        entry.frame_bytes,
                    )?;
                    if commit.revision != entry.commit.revision
                        || commit.kind.as_ref() != Some(&entry.commit.kind)
                        || commit.intake != entry.commit.intake
                        || commit
                            .spans
                            .iter()
                            .map(crate::analysis::raw::RawRange::from)
                            .collect::<Vec<_>>()
                            != entry.commit.spans
                        || commit.body.len() != entry.body_bytes
                    {
                        return crate::Error::reject_path(
                            &path,
                            "the deleting segment commits differ from their authority",
                        );
                    }
                    if matches!(&entry.commit.kind, RawKind::Diagnostic(progress) if progress.terminal)
                    {
                        let terminal = commit
                            .records()
                            .last()
                            .ok_or_else(|| {
                                NativeStateSnafu {
                                    field: "expired trace terminal",
                                }
                                .build()
                            })?
                            .1;
                        let crate::analysis::raw::TracePayload::Terminal(bytes) =
                            crate::analysis::raw::TraceRecord::read(terminal, root)?
                        else {
                            return NativeStateSnafu {
                                field: "expired trace terminal",
                            }
                            .fail();
                        };
                        if Some(crate::analysis::raw::TraceRecord::terminal(&bytes, root)?)
                            != self.terminal
                        {
                            return NativeStateSnafu {
                                field: "expired trace terminal",
                            }
                            .fail();
                        }
                    }
                }
                Ok(Some(path))
            }
            Ok(_) => {
                crate::Error::reject_path(&path, "the deleting segment differs from its authority")
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(source) => Err(source).context(crate::IoSnafu { path }),
        }
    }

    pub(super) fn remove_files(
        root: &Path,
        records: impl IntoIterator<Item = Result<Self>>,
    ) -> Result<Vec<u64>> {
        let mut completed = Vec::new();
        let mut paths = Vec::new();
        for record in records {
            let record = record?;
            if let Some(path) = record.file(root)? {
                paths.push(path);
            }
            completed.push(record.id);
        }
        for path in paths {
            fs::remove_file(&path).context(crate::IoSnafu { path: &path })?;
        }
        if !completed.is_empty() {
            Self::sync(root)?;
        }
        Ok(completed)
    }

    pub(in crate::analysis::native) fn finish_files(
        root: &Path,
        snapshot: &fjall::BranchSnapshot,
    ) -> Result<Vec<u64>> {
        let records = snapshot.prefix(Self::DELETING).map(|row| {
            let (key, value) = row.context(NativeStorageSnafu {
                operation: "recover segment deletion",
            })?;
            if key.len() != Self::DELETING.len() + 8 {
                return NativeStateSnafu {
                    field: "segment deletion key",
                }
                .fail();
            }
            let id = NativeStore::number(&key[Self::DELETING.len()..])?;
            let record = Self::read(snapshot, id)?;
            if NativeStore::number(&value)? != record.revision {
                return NativeStateSnafu {
                    field: "segment deletion revision",
                }
                .fail();
            }
            Ok(record)
        });
        Self::remove_files(root, records)
    }

    pub(super) fn sync(root: &Path) -> Result<()> {
        let path = root.join("segments");
        fs::File::open(&path)
            .and_then(|file| file.sync_all())
            .context(crate::IoSnafu { path })
    }

    pub(in crate::analysis::native) fn restore(
        raw: &mut RawJournal,
        snapshot: &fjall::BranchSnapshot,
    ) -> Result<()> {
        let mut entries = BTreeMap::new();
        for (revision, entry) in raw.index.entries.iter() {
            let terminal = match &entry.commit.kind {
                RawKind::Diagnostic(progress) if progress.terminal => {
                    match &raw.index.sources[&entry.identity.key()].receipt {
                        RawReceipt::Diagnostic(receipt) => receipt.terminal.clone(),
                        RawReceipt::Evidence(_) => {
                            return NativeStateSnafu {
                                field: "expired source kind",
                            }
                            .fail();
                        }
                    }
                }
                _ => None,
            };
            entries.insert(*revision, (entry.clone(), terminal));
        }
        let mut expired = rpds::RedBlackTreeMapSync::new_sync();
        let mut loaded = false;
        for row in snapshot.prefix(Self::PREFIX) {
            let (key, _) = row.context(NativeStorageSnafu {
                operation: "restore expired commit metadata",
            })?;
            if key.len() != Self::PREFIX.len() + 8 {
                continue;
            }
            let id = NativeStore::number(&key[Self::PREFIX.len()..])?;
            let record = Self::read(snapshot, id)?;
            if raw.segments.contains_key(&id) {
                return NativeStateSnafu {
                    field: "expired segment remains live",
                }
                .fail();
            }
            expired.insert_mut(
                id,
                crate::analysis::raw::RawExpiry {
                    revision: record.revision,
                    identity: record.entries[0].identity.clone(),
                },
            );
            for entry in record.entries {
                let terminal = match &entry.commit.kind {
                    RawKind::Diagnostic(progress) if progress.terminal => record.terminal.clone(),
                    _ => None,
                };
                if entries
                    .insert(entry.commit.revision, (entry, terminal))
                    .is_some()
                {
                    return NativeStateSnafu {
                        field: "duplicate expired original revision",
                    }
                    .fail();
                }
            }
            loaded = true;
        }
        if !loaded {
            return Ok(());
        }
        let active = raw.index.sources.clone();
        let mut index = RawIndex::default();
        for (_, (entry, terminal)) in entries {
            let receipt = match (&entry.identity, &entry.commit.kind) {
                (RawIdentity::Diagnostic(identity), RawKind::Diagnostic(progress)) => {
                    if progress.terminal != terminal.is_some() {
                        return NativeStateSnafu {
                            field: "expired trace terminal",
                        }
                        .fail();
                    }
                    RawReceipt::Diagnostic(TraceOutputReceiptV1 {
                        identity: identity.clone(),
                        last_sequence: progress.last_sequence,
                        output_bytes: progress.output_bytes,
                        terminal,
                        retained_floor: 0,
                        commit_revision: entry.commit.revision,
                    })
                }
                _ => {
                    return NativeStateSnafu {
                        field: "expired source kind",
                    }
                    .fail()
                }
            };
            index = index.prepare(entry, receipt, &raw.root)?;
        }
        index.expired = expired;
        for (key, source) in active.iter() {
            if let Some(saved) = index.sources.get_mut(key) {
                saved.active = source.active;
            }
        }
        raw.index = index;
        raw.publish_expiry()?;
        Ok(())
    }
}

impl RawJournal {
    pub(in crate::analysis::native) fn publish_expiry(&mut self) -> Result<()> {
        for entry in self.index.entries.values() {
            if self.index.expired.contains_key(&entry.reference.id) {
                for span in &entry.commit.spans {
                    self.budget
                        .expired
                        .insert((entry.identity.key(), span.first), span.last);
                }
            }
        }
        Ok(())
    }
}

impl DataView {
    pub fn replay_floor(&self, tenant: [u8; 16]) -> Result<Option<crate::StorePositionV1>> {
        let key = [ExpiredSegment::FLOOR, &tenant].concat();
        Records::payload(&key, |key| Records::read(key, &self.snapshot))?
            .map(|bytes| Records::decode(&bytes))
            .transpose()
    }

    pub(in crate::analysis::native) fn expired_ranges(
        &self,
        identity: &crate::EvidenceIntakeIdentityV1,
        output: &mut crate::AnalysisExtractionV1,
        control: &crate::AnalysisReadControl,
    ) -> Result<Vec<crate::AnalysisGapV1>> {
        let events = super::super::events::Events::new(self);
        let mut gaps = Vec::new();
        for row in events.spans(identity, 0, u64::MAX)? {
            control.check()?;
            let (key, value) = row.context(NativeStorageSnafu {
                operation: "read expired source spans",
            })?;
            let (first, index) = super::super::events::Events::decode_span(identity, &key, &value)?;
            let entry = events.batch(index.revision)?;
            entry.check_span(identity, first, &index)?;
            let Some(expired) = events.expiry(index.revision)? else {
                continue;
            };
            let span = &entry.meta.spans[index.slot];
            let added = crate::AnalysisExtractionV1::grow(
                &mut gaps,
                output.input_bytes,
                output.limits.input_bytes,
            )?;
            output.charge(added)?;
            gaps.push(crate::AnalysisGapV1 {
                first_cursor: span.first,
                last_cursor: span.last,
                commit_revision: expired.revision,
            });
        }
        Ok(gaps)
    }
}

impl NativeStore {
    pub fn replay_floor(&self, tenant: [u8; 16]) -> Result<Option<crate::StorePositionV1>> {
        if tenant == [0; 16] {
            return crate::Error::reject_path(&self.root, "the replay floor tenant is invalid");
        }
        self.view()?.replay_floor(tenant)
    }
}

impl DataView {
    pub(in crate::analysis::native) fn input_expiry_key(key: &[u8]) -> bool {
        key.starts_with(ExpiredSegment::PREFIX) && key.len() == ExpiredSegment::PREFIX.len() + 8
            || key.starts_with(super::super::events::Events::EXPIRED)
                && key.len() == super::super::events::Events::EXPIRED.len() + 8
    }

    pub(in crate::analysis::native) fn input_expiry(
        &self,
        key: &[u8],
        readers: &crate::analysis::inputs::InputChanges,
        position: crate::StorePositionV1,
    ) -> Result<()> {
        if let Some(suffix) = key.strip_prefix(super::super::events::Events::EXPIRED) {
            let id = NativeStore::number(suffix)?;
            let events = super::super::events::Events::new(self);
            let expiry = events.expiry(id)?.ok_or_else(|| {
                NativeStateSnafu {
                    field: "input evidence expiry",
                }
                .build()
            })?;
            if expiry.revision != position.commit_revision
                || expiry.revision != self.metadata_revision
            {
                return NativeStateSnafu {
                    field: "input evidence expiry revision",
                }
                .fail();
            }
            let batch = events.batch(id)?;
            let identity = batch.source.into();
            for span in &batch.meta.spans {
                readers.publish(
                    position,
                    crate::analysis::inputs::InputChange::Removal {
                        identity: &identity,
                        range: Some((span.first, span.last, Some(batch.meta.intake))),
                    },
                );
            }
            return Ok(());
        }
        let id = NativeStore::number(&key[ExpiredSegment::PREFIX.len()..])?;
        let record = ExpiredSegment::read(&self.snapshot, id)?;
        if record.revision != position.commit_revision || record.revision != self.metadata_revision
        {
            return NativeStateSnafu {
                field: "input expiry revision",
            }
            .fail();
        }
        for entry in &record.entries {
            for span in &entry.commit.spans {
                readers.publish(
                    position,
                    crate::analysis::inputs::InputChange::Removal {
                        identity: &entry.identity,
                        range: Some((span.first, span.last, Some(entry.commit.intake))),
                    },
                );
            }
        }
        Ok(())
    }
}
