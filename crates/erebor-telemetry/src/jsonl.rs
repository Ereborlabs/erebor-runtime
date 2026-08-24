use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::{BufRead, BufReader, Write},
    path::{Path, PathBuf},
    sync::{Arc, Mutex, MutexGuard},
    time::{SystemTime, UNIX_EPOCH},
};

#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

use serde::{Deserialize, Serialize};
use snafu::ResultExt;
use tracing::{
    dispatcher::{self, Dispatch},
    field::{Field, Visit},
    Event, Subscriber,
};
use tracing_subscriber::{layer::Context, prelude::*, Layer, Registry};

use crate::{
    telemetry_error::{IoSnafu, StateLockSnafu},
    Result, TelemetryError,
};

const MAX_RENDERED_VALUE_BYTES: usize = 512;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct JsonlTelemetryRecord {
    pub sequence: u64,
    pub timestamp: String,
    pub level: String,
    #[serde(default)]
    pub target: String,
    pub message: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub fields: BTreeMap<String, String>,
}

impl JsonlTelemetryRecord {
    #[must_use]
    pub fn rendered_message(&self) -> String {
        if self.fields.is_empty() {
            return self.message.clone();
        }
        let fields = self
            .fields
            .iter()
            .map(|(name, value)| format!("{name}={value}"))
            .collect::<Vec<_>>()
            .join(" ");
        format!("{} {fields}", self.message)
    }
}

#[derive(Clone)]
pub struct JsonlTelemetry {
    inner: Arc<JsonlTelemetryInner>,
    dispatch: Dispatch,
}

struct JsonlTelemetryInner {
    path: PathBuf,
    maximum_bytes: u64,
    state: Mutex<JsonlTelemetryState>,
    failure: Mutex<Option<TelemetryError>>,
}

struct JsonlTelemetryState {
    file: File,
    next_sequence: u64,
}

struct JsonlTelemetryLayer {
    inner: Arc<JsonlTelemetryInner>,
}

#[derive(Default)]
struct FieldVisitor {
    fields: BTreeMap<String, String>,
}

impl JsonlTelemetry {
    pub fn open(path: impl Into<PathBuf>, maximum_bytes: u64) -> Result<Self> {
        let path = path.into();
        let next_sequence = JsonlTelemetryInner::next_sequence(&path)?;
        let file = JsonlTelemetryInner::open_append(&path)?;
        let inner = Arc::new(JsonlTelemetryInner {
            path,
            maximum_bytes,
            state: Mutex::new(JsonlTelemetryState {
                file,
                next_sequence,
            }),
            failure: Mutex::new(None),
        });
        let dispatch = Dispatch::new(Registry::default().with(JsonlTelemetryLayer {
            inner: Arc::clone(&inner),
        }));
        Ok(Self { inner, dispatch })
    }

    pub fn emit<T>(&self, event: impl FnOnce() -> T) -> Result<T> {
        let output = dispatcher::with_default(&self.dispatch, event);
        self.inner.take_failure()?;
        Ok(output)
    }

    pub fn records_after(
        &self,
        after_sequence: u64,
        maximum: usize,
    ) -> Result<Vec<JsonlTelemetryRecord>> {
        self.inner.records_after(after_sequence, maximum)
    }
}

impl JsonlTelemetryInner {
    fn record_event(&self, event: &Event<'_>) -> Result<()> {
        let mut visitor = FieldVisitor::default();
        event.record(&mut visitor);
        let message = visitor
            .fields
            .remove("message")
            .unwrap_or_else(|| event.metadata().name().to_owned());
        let mut record = JsonlTelemetryRecord {
            sequence: 0,
            timestamp: Self::timestamp(),
            level: event.metadata().level().to_string(),
            target: event.metadata().target().to_owned(),
            message,
            fields: visitor.fields,
        };
        Self::render(&mut record);

        let mut state = self.lock_state()?;
        record.sequence = state.next_sequence;
        let source = serde_json::to_vec(&record).map_err(|source| TelemetryError::Encode {
            path: self.path.clone(),
            source,
            location: snafu::Location::default(),
        })?;
        let current_bytes = state
            .file
            .metadata()
            .context(IoSnafu {
                action: "inspecting telemetry log",
                path: &self.path,
            })?
            .len();
        if current_bytes > 0
            && current_bytes.saturating_add(source.len() as u64 + 1) > self.maximum_bytes
        {
            self.rotate(&mut state)?;
        }
        state.file.write_all(&source).context(IoSnafu {
            action: "writing telemetry log",
            path: &self.path,
        })?;
        state.file.write_all(b"\n").context(IoSnafu {
            action: "terminating telemetry log record",
            path: &self.path,
        })?;
        state.file.sync_data().context(IoSnafu {
            action: "syncing telemetry log",
            path: &self.path,
        })?;
        state.next_sequence = state.next_sequence.saturating_add(1);
        Ok(())
    }

    fn records_after(
        &self,
        after_sequence: u64,
        maximum: usize,
    ) -> Result<Vec<JsonlTelemetryRecord>> {
        let _state = self.lock_state()?;
        let file = File::open(&self.path).context(IoSnafu {
            action: "opening telemetry log",
            path: &self.path,
        })?;
        let mut records = Vec::new();
        for line in BufReader::new(file).lines() {
            let line = line.context(IoSnafu {
                action: "reading telemetry log",
                path: &self.path,
            })?;
            let record = serde_json::from_str::<JsonlTelemetryRecord>(&line).map_err(|source| {
                TelemetryError::Decode {
                    path: self.path.clone(),
                    source,
                    location: snafu::Location::default(),
                }
            })?;
            if record.sequence > after_sequence {
                records.push(record);
            }
            if records.len() == maximum {
                break;
            }
        }
        Ok(records)
    }

    fn rotate(&self, state: &mut JsonlTelemetryState) -> Result<()> {
        state.file.sync_all().context(IoSnafu {
            action: "syncing telemetry log before rotation",
            path: &self.path,
        })?;
        let rotated = self.path.with_extension("jsonl.1");
        if rotated.exists() {
            fs::remove_file(&rotated).context(IoSnafu {
                action: "removing rotated telemetry log",
                path: &rotated,
            })?;
        }
        fs::rename(&self.path, &rotated).context(IoSnafu {
            action: "rotating telemetry log",
            path: &self.path,
        })?;
        state.file = Self::open_append(&self.path)?;
        Ok(())
    }

    fn open_append(path: &Path) -> Result<File> {
        let mut options = OpenOptions::new();
        options.create(true).append(true).read(true);
        #[cfg(unix)]
        options.mode(0o640);
        let file = options.open(path).context(IoSnafu {
            action: "opening telemetry log for append",
            path,
        })?;
        #[cfg(unix)]
        fs::set_permissions(path, fs::Permissions::from_mode(0o640)).context(IoSnafu {
            action: "setting telemetry log permissions",
            path,
        })?;
        Ok(file)
    }

    fn next_sequence(path: &Path) -> Result<u64> {
        if !path.exists() {
            return Ok(1);
        }
        let file = File::open(path).context(IoSnafu {
            action: "opening telemetry log for sequence recovery",
            path,
        })?;
        let mut sequence = 1;
        for line in BufReader::new(file).lines() {
            let line = line.context(IoSnafu {
                action: "reading telemetry log for sequence recovery",
                path,
            })?;
            let record = serde_json::from_str::<JsonlTelemetryRecord>(&line).map_err(|source| {
                TelemetryError::Decode {
                    path: path.to_path_buf(),
                    source,
                    location: snafu::Location::default(),
                }
            })?;
            sequence = sequence.max(record.sequence.saturating_add(1));
        }
        Ok(sequence)
    }

    fn render(record: &mut JsonlTelemetryRecord) {
        if Self::contains_sensitive_data(&record.message)
            || record.fields.iter().any(|(name, value)| {
                Self::is_sensitive_field(name) || Self::contains_sensitive_data(value)
            })
        {
            record.message = String::from("[redacted sensitive telemetry event]");
            record.fields.clear();
            return;
        }
        record.message = Self::truncate(&record.message);
        for value in record.fields.values_mut() {
            *value = Self::truncate(value);
        }
    }

    fn contains_sensitive_data(value: &str) -> bool {
        let value = value.to_ascii_lowercase();
        [
            "secret",
            "credential",
            "password",
            "token",
            "ticket",
            "payload",
        ]
        .iter()
        .any(|label| value.contains(&format!("{label}=")) || value.contains(&format!("{label}:")))
    }

    fn is_sensitive_field(name: &str) -> bool {
        let name = name.to_ascii_lowercase();
        [
            "secret",
            "credential",
            "password",
            "token",
            "ticket",
            "payload",
        ]
        .iter()
        .any(|label| name.contains(label))
    }

    fn truncate(value: &str) -> String {
        if value.len() <= MAX_RENDERED_VALUE_BYTES {
            return value.to_owned();
        }
        let end = value
            .char_indices()
            .take_while(|(index, _)| *index < MAX_RENDERED_VALUE_BYTES)
            .map(|(index, character)| index + character.len_utf8())
            .last()
            .unwrap_or_default();
        format!("{}…", &value[..end])
    }

    fn timestamp() -> String {
        let duration = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();
        format!("unix:{}.{}", duration.as_secs(), duration.subsec_nanos())
    }

    fn lock_state(&self) -> Result<MutexGuard<'_, JsonlTelemetryState>> {
        self.state.lock().map_err(|_error| StateLockSnafu.build())
    }

    fn remember_failure(&self, failure: TelemetryError) {
        if let Ok(mut remembered) = self.failure.lock() {
            if remembered.is_none() {
                *remembered = Some(failure);
            }
        }
    }

    fn take_failure(&self) -> Result<()> {
        let mut remembered = self
            .failure
            .lock()
            .map_err(|_error| StateLockSnafu.build())?;
        match remembered.take() {
            Some(failure) => Err(failure),
            None => Ok(()),
        }
    }
}

impl<S> Layer<S> for JsonlTelemetryLayer
where
    S: Subscriber,
{
    fn on_event(&self, event: &Event<'_>, _context: Context<'_, S>) {
        if let Err(failure) = self.inner.record_event(event) {
            self.inner.remember_failure(failure);
        }
    }
}

impl Visit for FieldVisitor {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        self.fields
            .insert(field.name().to_owned(), format!("{value:?}"));
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        self.fields
            .insert(field.name().to_owned(), value.to_owned());
    }
}

#[cfg(test)]
mod tests {
    use std::{fs, os::unix::fs::MetadataExt};

    use tempfile::TempDir;

    use super::JsonlTelemetry;

    #[test]
    fn jsonl_telemetry_redacts_sensitive_fields_and_is_not_world_readable(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let root = TempDir::new()?;
        let path = root.path().join("telemetry.jsonl");
        let telemetry = JsonlTelemetry::open(path.clone(), 4096)?;
        let token = "package-secret";
        telemetry.emit(|| crate::warn!("daemon diagnostic", token = %token))?;

        let record = telemetry.records_after(0, 1)?.remove(0);
        assert_eq!(record.message, "[redacted sensitive telemetry event]");
        assert!(record.fields.is_empty());
        assert!(!fs::read_to_string(&path)?.contains("package-secret"));
        assert_eq!(fs::metadata(path)?.mode() & 0o077, 0o040);
        Ok(())
    }

    #[test]
    fn jsonl_telemetry_preserves_structured_fields_and_sequence_after_reopen(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let root = TempDir::new()?;
        let path = root.path().join("telemetry.jsonl");
        let telemetry = JsonlTelemetry::open(path.clone(), 4096)?;
        let uid = 42;
        telemetry.emit(|| crate::info!("accepted daemon client", uid = %uid))?;
        drop(telemetry);

        let resumed = JsonlTelemetry::open(path, 4096)?;
        resumed.emit(|| crate::info!("daemon configuration reloaded"))?;
        let records = resumed.records_after(0, 2)?;
        assert_eq!(records[0].sequence, 1);
        assert_eq!(records[0].fields.get("uid"), Some(&String::from("42")));
        assert_eq!(
            records[0].rendered_message(),
            "accepted daemon client uid=42"
        );
        assert_eq!(records[1].sequence, 2);
        Ok(())
    }

    #[test]
    fn jsonl_telemetry_reads_existing_daemon_records_without_structured_fields(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let root = TempDir::new()?;
        let path = root.path().join("telemetry.jsonl");
        fs::write(
            &path,
            r#"{"sequence":7,"timestamp":"unix:1.0","level":"INFO","message":"existing daemon record"}
"#,
        )?;

        let telemetry = JsonlTelemetry::open(path, 4096)?;
        let record = telemetry.records_after(0, 1)?.remove(0);
        assert_eq!(record.sequence, 7);
        assert_eq!(record.target, "");
        assert_eq!(record.message, "existing daemon record");
        Ok(())
    }
}
