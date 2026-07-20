use std::{
    fs::{self, File, OpenOptions},
    io::{BufRead, BufReader, Write},
    path::{Path, PathBuf},
    sync::Mutex,
};

use erebor_runtime_core::OutputPlan;
use rustix::fs::{flock, FlockOperation};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use snafu::ResultExt;

use crate::{
    error::session_output::{
        DecodeSnafu, IntegritySnafu, IoSnafu, RequiredSinkFullSnafu, StateLockSnafu,
    },
    SessionOutputError,
};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum StreamKind {
    Stdout,
    Stderr,
    Events,
    Evidence,
    Continuity,
}

impl StreamKind {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Stdout => "stdout",
            Self::Stderr => "stderr",
            Self::Events => "events",
            Self::Evidence => "evidence",
            Self::Continuity => "continuity",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub struct DurableStreamRecord {
    sequence: u64,
    timestamp_unix_ms: u64,
    source: String,
    data: Vec<u8>,
    previous_sha256: String,
    sha256: String,
}

impl DurableStreamRecord {
    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    #[must_use]
    pub const fn timestamp_unix_ms(&self) -> u64 {
        self.timestamp_unix_ms
    }

    #[must_use]
    pub fn source(&self) -> &str {
        &self.source
    }

    #[must_use]
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    #[must_use]
    pub fn previous_sha256(&self) -> &str {
        &self.previous_sha256
    }

    #[must_use]
    pub fn sha256(&self) -> &str {
        &self.sha256
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DurableStreamCursor {
    records: Vec<DurableStreamRecord>,
    durable_cursor: u64,
    truncated_before_cursor: bool,
}

impl DurableStreamCursor {
    #[must_use]
    pub fn records(&self) -> &[DurableStreamRecord] {
        &self.records
    }

    #[must_use]
    pub const fn durable_cursor(&self) -> u64 {
        self.durable_cursor
    }

    #[must_use]
    pub const fn truncated_before_cursor(&self) -> bool {
        self.truncated_before_cursor
    }
}

struct StreamState {
    next_sequence: u64,
    segment: u64,
    segment_bytes: u64,
    total_bytes: u64,
    first_sequence: u64,
    last_sha256: String,
}

pub struct DurableStreamStore {
    directory: PathBuf,
    kind: StreamKind,
    maximum_bytes: u64,
    rotation_bytes: u64,
    required: bool,
    state: Mutex<StreamState>,
}

impl DurableStreamStore {
    pub fn open(
        directory: impl Into<PathBuf>,
        kind: StreamKind,
        maximum_bytes: u64,
        rotation_bytes: u64,
        required: bool,
    ) -> Result<Self, SessionOutputError> {
        let directory = directory.into();
        fs::create_dir_all(&directory).context(IoSnafu {
            action: "creating stream directory",
            path: &directory,
        })?;
        let state = inspect_segments(&directory, kind)?;
        Ok(Self {
            directory,
            kind,
            maximum_bytes,
            rotation_bytes,
            required,
            state: Mutex::new(state),
        })
    }

    pub fn append(
        &self,
        timestamp_unix_ms: u64,
        source: impl Into<String>,
        data: impl Into<Vec<u8>>,
    ) -> Result<DurableStreamRecord, SessionOutputError> {
        let mut state = self.state.lock().map_err(|_error| {
            StateLockSnafu {
                stream: self.kind.as_str().to_owned(),
            }
            .build()
        })?;
        let mut record = DurableStreamRecord {
            sequence: state.next_sequence,
            timestamp_unix_ms,
            source: source.into(),
            data: data.into(),
            previous_sha256: state.last_sha256.clone(),
            sha256: String::new(),
        };
        record.sha256 = record_digest(&record)?;
        let mut encoded = serde_json::to_vec(&record).context(DecodeSnafu {
            path: self.segment_path(state.segment),
        })?;
        encoded.push(b'\n');
        let encoded_len = encoded.len() as u64;
        if encoded_len > self.maximum_bytes
            || (self.required && state.total_bytes.saturating_add(encoded_len) > self.maximum_bytes)
        {
            return RequiredSinkFullSnafu {
                stream: self.kind.as_str().to_owned(),
                maximum_bytes: self.maximum_bytes,
            }
            .fail();
        }
        if state.segment_bytes > 0
            && state.segment_bytes.saturating_add(encoded_len) > self.rotation_bytes
        {
            state.segment = state.segment.saturating_add(1);
            state.segment_bytes = 0;
        }
        if !self.required {
            self.prune_for_capacity(&mut state, encoded_len)?;
        }
        let path = self.segment_path(state.segment);
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .context(IoSnafu {
                action: "opening stream segment",
                path: &path,
            })?;
        flock(&file, FlockOperation::LockExclusive)
            .map_err(std::io::Error::from)
            .context(IoSnafu {
                action: "locking stream segment for append",
                path: &path,
            })?;
        file.write_all(&encoded).context(IoSnafu {
            action: "appending stream record",
            path: &path,
        })?;
        file.sync_data().context(IoSnafu {
            action: "syncing stream record",
            path: &path,
        })?;
        state.next_sequence = state.next_sequence.saturating_add(1);
        state.segment_bytes = state.segment_bytes.saturating_add(encoded_len);
        state.total_bytes = state.total_bytes.saturating_add(encoded_len);
        state.last_sha256.clone_from(&record.sha256);
        Ok(record)
    }

    #[must_use]
    pub const fn required(&self) -> bool {
        self.required
    }

    pub fn read_after(
        &self,
        after_sequence: u64,
        maximum_records: usize,
    ) -> Result<DurableStreamCursor, SessionOutputError> {
        let state = self.state.lock().map_err(|_error| {
            StateLockSnafu {
                stream: self.kind.as_str().to_owned(),
            }
            .build()
        })?;
        let mut records = Vec::new();
        let mut expected_previous = None;
        let mut expected_sequence = None;
        for path in segment_paths(&self.directory, self.kind)? {
            for line in locked_reader(&path)?.lines() {
                let line = line.context(IoSnafu {
                    action: "reading stream segment",
                    path: &path,
                })?;
                let record: DurableStreamRecord =
                    serde_json::from_str(&line).context(DecodeSnafu { path: &path })?;
                verify_record(
                    &path,
                    &record,
                    &mut expected_previous,
                    &mut expected_sequence,
                )?;
                if record.sequence > after_sequence && records.len() < maximum_records {
                    records.push(record);
                }
            }
        }
        let durable_cursor = records
            .last()
            .map_or(after_sequence, DurableStreamRecord::sequence);
        Ok(DurableStreamCursor {
            records,
            durable_cursor,
            truncated_before_cursor: state.first_sequence > after_sequence.saturating_add(1),
        })
    }

    fn prune_for_capacity(
        &self,
        state: &mut StreamState,
        incoming_bytes: u64,
    ) -> Result<(), SessionOutputError> {
        while state.total_bytes.saturating_add(incoming_bytes) > self.maximum_bytes {
            let paths = segment_paths(&self.directory, self.kind)?;
            let Some(oldest) = paths
                .into_iter()
                .find(|path| *path != self.segment_path(state.segment))
            else {
                return RequiredSinkFullSnafu {
                    stream: self.kind.as_str().to_owned(),
                    maximum_bytes: self.maximum_bytes,
                }
                .fail();
            };
            let metadata = oldest.metadata().context(IoSnafu {
                action: "inspecting old stream segment",
                path: &oldest,
            })?;
            let last_sequence = last_sequence(&oldest)?;
            fs::remove_file(&oldest).context(IoSnafu {
                action: "rotating old stream segment",
                path: &oldest,
            })?;
            state.total_bytes = state.total_bytes.saturating_sub(metadata.len());
            state.first_sequence = last_sequence.saturating_add(1);
        }
        Ok(())
    }

    fn segment_path(&self, segment: u64) -> PathBuf {
        self.directory
            .join(format!("{}-{segment:020}.jsonl", self.kind.as_str()))
    }
}

pub struct SessionOutputStores {
    stdout: DurableStreamStore,
    stderr: DurableStreamStore,
    events: DurableStreamStore,
    evidence: DurableStreamStore,
    continuity: DurableStreamStore,
}

impl SessionOutputStores {
    pub fn open(plan: &OutputPlan) -> Result<Self, SessionOutputError> {
        let root = plan.root();
        let per_stream = plan.maximum_bytes() / 5;
        let per_rotation = plan.rotation_bytes().min(per_stream);
        Ok(Self {
            stdout: DurableStreamStore::open(
                root.join("stdout"),
                StreamKind::Stdout,
                per_stream,
                per_rotation,
                plan.requirements().stdout_required(),
            )?,
            stderr: DurableStreamStore::open(
                root.join("stderr"),
                StreamKind::Stderr,
                per_stream,
                per_rotation,
                plan.requirements().stderr_required(),
            )?,
            events: DurableStreamStore::open(
                root.join("events"),
                StreamKind::Events,
                per_stream,
                per_rotation,
                true,
            )?,
            evidence: DurableStreamStore::open(
                root.join("evidence"),
                StreamKind::Evidence,
                per_stream,
                per_rotation,
                true,
            )?,
            continuity: DurableStreamStore::open(
                root.join("continuity"),
                StreamKind::Continuity,
                per_stream,
                per_rotation,
                true,
            )?,
        })
    }

    #[must_use]
    pub const fn stream(&self, kind: StreamKind) -> &DurableStreamStore {
        match kind {
            StreamKind::Stdout => &self.stdout,
            StreamKind::Stderr => &self.stderr,
            StreamKind::Events => &self.events,
            StreamKind::Evidence => &self.evidence,
            StreamKind::Continuity => &self.continuity,
        }
    }
}

fn inspect_segments(directory: &Path, kind: StreamKind) -> Result<StreamState, SessionOutputError> {
    let paths = segment_paths(directory, kind)?;
    let mut state = StreamState {
        next_sequence: 1,
        segment: 0,
        segment_bytes: 0,
        total_bytes: 0,
        first_sequence: 1,
        last_sha256: String::new(),
    };
    let mut expected_previous = None;
    let mut expected_sequence = None;
    for (index, path) in paths.iter().enumerate() {
        let metadata = path.metadata().context(IoSnafu {
            action: "inspecting stream segment",
            path,
        })?;
        state.total_bytes = state.total_bytes.saturating_add(metadata.len());
        if index == 0 {
            state.first_sequence = first_sequence(path)?.unwrap_or(1);
        }
        for line in locked_reader(path)?.lines() {
            let line = line.context(IoSnafu {
                action: "reading stream segment",
                path,
            })?;
            let record: DurableStreamRecord =
                serde_json::from_str(&line).context(DecodeSnafu { path })?;
            verify_record(
                path,
                &record,
                &mut expected_previous,
                &mut expected_sequence,
            )?;
            state.last_sha256.clone_from(&record.sha256);
        }
        if index + 1 == paths.len() {
            state.segment = segment_number(path).unwrap_or(0);
            state.segment_bytes = metadata.len();
            state.next_sequence = last_sequence(path)?.saturating_add(1);
        }
    }
    Ok(state)
}

fn verify_record(
    path: &Path,
    record: &DurableStreamRecord,
    expected_previous: &mut Option<String>,
    expected_sequence: &mut Option<u64>,
) -> Result<(), SessionOutputError> {
    if let Some(expected) = expected_previous.as_ref() {
        if record.previous_sha256 != *expected {
            return IntegritySnafu {
                path,
                reason: format!(
                    "record {} does not continue the previous checksum",
                    record.sequence
                ),
            }
            .fail();
        }
    }
    if let Some(expected) = *expected_sequence {
        if record.sequence != expected {
            return IntegritySnafu {
                path,
                reason: format!(
                    "record sequence is {}, expected {expected}",
                    record.sequence
                ),
            }
            .fail();
        }
    }
    let digest = record_digest(record)?;
    if record.sha256 != digest {
        return IntegritySnafu {
            path,
            reason: format!("record {} checksum does not match", record.sequence),
        }
        .fail();
    }
    *expected_previous = Some(record.sha256.clone());
    *expected_sequence = Some(record.sequence.saturating_add(1));
    Ok(())
}

fn record_digest(record: &DurableStreamRecord) -> Result<String, SessionOutputError> {
    #[derive(Serialize)]
    struct DigestInput<'a> {
        sequence: u64,
        timestamp_unix_ms: u64,
        source: &'a str,
        data: &'a [u8],
        previous_sha256: &'a str,
    }

    let encoded = serde_json::to_vec(&DigestInput {
        sequence: record.sequence,
        timestamp_unix_ms: record.timestamp_unix_ms,
        source: &record.source,
        data: &record.data,
        previous_sha256: &record.previous_sha256,
    })
    .context(DecodeSnafu {
        path: PathBuf::from("<stream-record>"),
    })?;
    let mut hasher = Sha256::new();
    hasher.update(b"erebor-session-stream-chain-v1\0");
    hasher.update(encoded);
    Ok(format!("{:x}", hasher.finalize()))
}

fn segment_paths(directory: &Path, kind: StreamKind) -> Result<Vec<PathBuf>, SessionOutputError> {
    let mut paths = Vec::new();
    for entry in fs::read_dir(directory).context(IoSnafu {
        action: "listing stream directory",
        path: directory,
    })? {
        let entry = entry.context(IoSnafu {
            action: "reading stream directory entry",
            path: directory,
        })?;
        let path = entry.path();
        if path
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| {
                name.starts_with(&format!("{}-", kind.as_str())) && name.ends_with(".jsonl")
            })
        {
            paths.push(path);
        }
    }
    paths.sort();
    Ok(paths)
}

fn segment_number(path: &Path) -> Option<u64> {
    path.file_stem()?.to_str()?.rsplit_once('-')?.1.parse().ok()
}

fn first_sequence(path: &Path) -> Result<Option<u64>, SessionOutputError> {
    let mut lines = locked_reader(path)?.lines();
    let Some(line) = lines.next() else {
        return Ok(None);
    };
    let line = line.context(IoSnafu {
        action: "reading stream segment",
        path,
    })?;
    let record: DurableStreamRecord = serde_json::from_str(&line).context(DecodeSnafu { path })?;
    Ok(Some(record.sequence))
}

fn last_sequence(path: &Path) -> Result<u64, SessionOutputError> {
    let mut last = 0;
    for line in locked_reader(path)?.lines() {
        let line = line.context(IoSnafu {
            action: "reading stream segment",
            path,
        })?;
        let record: DurableStreamRecord =
            serde_json::from_str(&line).context(DecodeSnafu { path })?;
        last = record.sequence;
    }
    Ok(last)
}

fn locked_reader(path: &Path) -> Result<BufReader<File>, SessionOutputError> {
    let file = File::open(path).context(IoSnafu {
        action: "opening stream segment",
        path,
    })?;
    flock(&file, FlockOperation::LockShared)
        .map_err(std::io::Error::from)
        .context(IoSnafu {
            action: "locking stream segment for read",
            path,
        })?;
    Ok(BufReader::new(file))
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        sync::{Arc, Barrier},
        thread,
    };

    use tempfile::TempDir;

    use super::{DurableStreamStore, SessionOutputError, StreamKind};

    #[test]
    fn durable_cursor_is_published_only_after_synced_append(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let temporary = TempDir::new()?;
        let stream =
            DurableStreamStore::open(temporary.path(), StreamKind::Stdout, 4096, 256, false)?;
        let first = stream.append(1, "workload", b"one".to_vec())?;
        let second = stream.append(2, "workload", b"two".to_vec())?;
        let page = stream.read_after(first.sequence(), 10)?;

        assert_eq!(page.records(), &[second]);
        assert_eq!(page.durable_cursor(), 2);
        assert!(!page.truncated_before_cursor());
        Ok(())
    }

    #[test]
    fn required_sink_fails_closed_at_its_limit() -> Result<(), Box<dyn std::error::Error>> {
        let temporary = TempDir::new()?;
        let stream =
            DurableStreamStore::open(temporary.path(), StreamKind::Evidence, 128, 128, true)?;

        assert!(stream.append(1, "audit", vec![7; 256]).is_err());
        Ok(())
    }

    #[test]
    fn reopening_rejects_tampered_checksummed_records() -> Result<(), Box<dyn std::error::Error>> {
        let temporary = TempDir::new()?;
        let stream =
            DurableStreamStore::open(temporary.path(), StreamKind::Continuity, 4096, 4096, true)?;
        stream.append(1, "helper", b"started".to_vec())?;
        drop(stream);

        let segment = temporary
            .path()
            .join("continuity-00000000000000000000.jsonl");
        let original = fs::read_to_string(&segment)?;
        fs::write(
            &segment,
            original.replace("\"timestamp_unix_ms\":1", "\"timestamp_unix_ms\":2"),
        )?;

        assert!(DurableStreamStore::open(
            temporary.path(),
            StreamKind::Continuity,
            4096,
            4096,
            true
        )
        .is_err());
        Ok(())
    }

    #[test]
    fn independent_stores_can_read_while_another_handle_appends(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let temporary = TempDir::new()?;
        let writer = DurableStreamStore::open(
            temporary.path(),
            StreamKind::Stdout,
            16 * 1024 * 1024,
            16 * 1024 * 1024,
            false,
        )?;
        let reader = DurableStreamStore::open(
            temporary.path(),
            StreamKind::Stdout,
            16 * 1024 * 1024,
            16 * 1024 * 1024,
            false,
        )?;
        let start = Arc::new(Barrier::new(2));
        let writer_start = Arc::clone(&start);
        let writer = thread::spawn(move || -> Result<(), SessionOutputError> {
            writer_start.wait();
            for sequence in 1..=128 {
                writer.append(sequence, "helper", vec![b'x'; 4096])?;
            }
            Ok(())
        });

        start.wait();
        while !writer.is_finished() {
            reader.read_after(0, 256)?;
            thread::yield_now();
        }
        writer
            .join()
            .map_err(|_| std::io::Error::other("writer thread panicked"))??;
        let page = reader.read_after(0, 256)?;

        assert_eq!(page.records().len(), 128);
        assert_eq!(page.durable_cursor(), 128);
        Ok(())
    }
}
