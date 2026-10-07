use std::{
    fmt::Write as _,
    io::{self, IsTerminal},
};

use erebor_runtime_ipc::araphor as wire;
use serde::Serialize;
use snafu::{OptionExt as _, ResultExt as _};
use tokio::io::AsyncWriteExt as _;

use super::{
    args::OutputMode,
    error::{EncodeSnafu, InvalidSnafu, OutputDeadlineSnafu, OutputSnafu, Result},
};

pub(super) struct Output {
    mode: OutputMode,
    columns: Vec<String>,
    stdout: tokio::io::Stdout,
}

#[derive(Serialize)]
struct Record<'a, T> {
    kind: &'static str,
    frame: &'a T,
}

struct AsciiJson;

impl serde_json::ser::Formatter for AsciiJson {
    fn write_string_fragment<W: ?Sized + io::Write>(
        &mut self,
        writer: &mut W,
        fragment: &str,
    ) -> io::Result<()> {
        for character in fragment.chars() {
            if character.is_ascii() {
                writer.write_all(&[character as u8])?;
            } else {
                for unit in character.encode_utf16(&mut [0; 2]).iter() {
                    write!(writer, "\\u{unit:04x}")?;
                }
            }
        }
        Ok(())
    }
}

impl Output {
    pub(super) fn new(mode: Option<OutputMode>, follow: bool) -> Self {
        Self {
            mode: mode.unwrap_or_else(|| {
                if follow || io::stdout().is_terminal() {
                    OutputMode::Table
                } else {
                    OutputMode::Jsonl
                }
            }),
            columns: Vec::new(),
            stdout: tokio::io::stdout(),
        }
    }

    pub(super) async fn write(&mut self, bytes: &[u8]) -> Result<()> {
        let write = async {
            self.stdout.write_all(bytes).await?;
            self.stdout.flush().await
        };
        tokio::time::timeout(std::time::Duration::from_secs(10), write)
            .await
            .map_err(|_| OutputDeadlineSnafu.build())?
            .context(OutputSnafu)
    }

    pub(super) fn receipt(&self, receipt: &wire::TraceReceipt) -> Result<Vec<u8>> {
        match self.mode {
            OutputMode::Jsonl => Self::json("trace_receipt", receipt),
            OutputMode::Table => Ok(format!(
                "trace_id\t{}\naccepted_unix_ns\t{}\ndeadline_unix_ns\t{}\nsource_sha256\t{}\ncancel_requested\t{}\n",
                Self::id(&receipt.trace_id),
                receipt.accepted_unix_ns,
                receipt.deadline_unix_ns,
                Self::bytes(&receipt.source_sha256),
                receipt.cancel_requested
            )
            .into_bytes()),
        }
    }

    pub(super) fn query(&mut self, frame: &wire::QueryFrame) -> Result<Vec<u8>> {
        use wire::query_frame::Payload;
        let payload = frame.payload.as_ref().context(InvalidSnafu {
            field: "query payload",
        })?;
        let kind = match payload {
            Payload::Metadata(_) => "query_metadata",
            Payload::Rows(_) if frame.operation == wire::QueryOperation::Append as i32 => {
                "query_append"
            }
            Payload::Rows(_) => "query_replace",
            Payload::Checkpoint(_) => "query_checkpoint",
            Payload::Health(_) => "query_health",
            Payload::Error(_) => "query_error",
            Payload::Terminal(_) => "query_terminal",
        };
        if matches!(self.mode, OutputMode::Jsonl) {
            if let Payload::Rows(rows) = payload {
                if rows.rows.iter().flat_map(|row| &row.values)
                    .any(|value| matches!(value.kind, Some(wire::query_value::Kind::Real(value)) if !value.is_finite()))
                {
                    let mut value = serde_json::to_value(frame).context(EncodeSnafu)?;
                    let values = value.get_mut("payload").and_then(|value| value.get_mut("Rows"))
                        .and_then(|value| value.get_mut("rows")).and_then(serde_json::Value::as_array_mut)
                        .context(InvalidSnafu { field: "query JSON row shape" })?;
                    for (wire, row) in values.iter_mut().zip(&rows.rows) {
                        let values = wire.get_mut("values").and_then(serde_json::Value::as_array_mut)
                            .context(InvalidSnafu { field: "query JSON value shape" })?;
                        for (wire, value) in values.iter_mut().zip(&row.values) {
                            if let Some(wire::query_value::Kind::Real(value)) = value.kind {
                                if !value.is_finite() {
                                    let real = wire.get_mut("kind").and_then(|value| value.get_mut("Real"))
                                        .context(InvalidSnafu { field: "query JSON real shape" })?;
                                    *real = serde_json::Value::String(if value.is_nan() { "NaN" }
                                        else if value.is_sign_positive() { "Infinity" } else { "-Infinity" }.into());
                                }
                            }
                        }
                    }
                    return Self::json(kind, &value);
                }
            }
            return Self::json(kind, frame);
        }
        let mut text = format!(
            "{kind}\tstore={}\tepoch={}\trevision={}\tclock_changed={}\n",
            Self::id(&frame.store_uuid),
            frame.recovery_epoch,
            frame.read_revision,
            frame.clock_changed
        );
        match payload {
            Payload::Metadata(metadata) => {
                self.columns = metadata
                    .columns
                    .iter()
                    .map(|column| Self::text(&column.name))
                    .collect();
                for column in &metadata.columns {
                    let _ = writeln!(
                        text,
                        "column\t{}\t{}\tunits={}\tnull={}\tjoin={}\towner={}\treadiness={}",
                        Self::text(&column.name),
                        Self::text(&column.data_type),
                        Self::text(&column.units),
                        Self::text(&column.null_meaning),
                        Self::text(&column.join_keys),
                        Self::text(&column.owner),
                        Self::text(&column.readiness)
                    );
                }
                let _ = writeln!(text, "limits\trows={}\tbytes={}\tevaluated_utc_ns={}\tdependency_revision={}\tresolution_ns={:?}\tresume={}", metadata.row_limit,
                    metadata.byte_limit, metadata.evaluated_utc_ns, metadata.dependency_revision,
                    metadata.moving_resolution_ns, Self::text(&metadata.resume_semantics));
            }
            Payload::Rows(rows) => {
                let mut table = crate::cli::output::table();
                table.set_header(&self.columns);
                for row in &rows.rows {
                    let values = row
                        .values
                        .iter()
                        .map(Self::value)
                        .collect::<Result<Vec<_>>>()?;
                    table.add_row(values);
                }
                let _ = writeln!(text, "{table}");
                let _ = writeln!(
                    text,
                    "rows\tlimited={}\tmissing_contexts={}\tevaluated_utc_ns={}",
                    rows.limited,
                    rows.missing_contexts.len(),
                    rows.evaluated_utc_ns
                );
            }
            Payload::Checkpoint(_) => {}
            Payload::Health(health) => Self::health(&mut text, health),
            Payload::Error(error) => Self::error(&mut text, error),
            Payload::Terminal(terminal) => {
                let _ = writeln!(text, "terminal\t{}", Self::text(&terminal.reason));
            }
        }
        Self::coverage(&mut text, &frame.coverage);
        Ok(text.into_bytes())
    }

    pub(super) fn trace(&self, frame: &wire::TraceFrame) -> Result<Vec<u8>> {
        use wire::trace_frame::Payload;
        let payload = frame.payload.as_ref().context(InvalidSnafu {
            field: "trace payload",
        })?;
        let kind = match payload {
            Payload::Metadata(_) => "trace_metadata",
            Payload::Output(_) => "trace_output",
            Payload::Terminal(_) => "trace_terminal",
            Payload::Result(_) => "trace_result",
            Payload::Checkpoint(_) => "trace_checkpoint",
            Payload::Error(_) => "trace_error",
            Payload::Health(_) => "trace_health",
        };
        if matches!(self.mode, OutputMode::Jsonl) {
            return Self::json(kind, frame);
        }
        let mut text = format!(
            "{kind}\ttrace={}\tstore={}\tepoch={}\tread_revision={}\ttarget={}\trevision={}\tordinal={}\tsequence={}\n",
            Self::id(&frame.trace_id),
            Self::id(&frame.store_uuid),
            frame.recovery_epoch,
            frame.read_revision,
            frame.target_index,
            frame.commit_revision,
            frame.ordinal,
            frame.sequence
        );
        match payload {
            Payload::Metadata(detail) => {
                let _ = writeln!(
                    text,
                    "source\t{}\nrecipe\t{}\nprincipal\t{}\nduration_seconds\t{}",
                    Self::bytes(&detail.source),
                    Self::text(&detail.recipe),
                    Self::text(&detail.principal),
                    detail.collection_seconds
                );
                if let Some(selection) = &detail.requested {
                    let _ = writeln!(
                        text,
                        "requested\ttarget={}\tcluster={}\tcontainer={}\tnodes={}",
                        Self::text(&selection.target),
                        Self::text(&selection.cluster),
                        Self::text(&selection.container),
                        selection
                            .node_ids
                            .iter()
                            .map(|node| Self::text(node))
                            .collect::<Vec<_>>()
                            .join(",")
                    );
                }
                let _ = writeln!(
                    text,
                    "finding_reference\t{}",
                    Self::text(&detail.finding_reference)
                );
                if let Some(limits) = &detail.limits {
                    let _ = writeln!(text, "limits\tsource_bytes={}\tframe_bytes={}\toutput_bytes={}\tframe_count={}\ttarget_count={}\tcollection_seconds={}",
                        limits.source_bytes, limits.frame_bytes, limits.output_bytes, limits.frame_count, limits.target_count,
                        limits.collection_seconds);
                }
                for target in &detail.targets {
                    let _ = writeln!(
                        text,
                        "target\t{}\tnode={}\tpod={}\tcontainer={}\tcgroup={}\tgeneration={}",
                        target.index,
                        Self::text(&target.node_id),
                        Self::text(&target.pod_uid),
                        Self::text(&target.container_id),
                        target.cgroup_id,
                        target.container_generation
                    );
                }
            }
            Payload::Output(output) => {
                let _ = writeln!(
                    text,
                    "{}\t{}",
                    Self::text(&output.kind),
                    Self::bytes(&output.bytes)
                );
            }
            Payload::Terminal(terminal) => {
                let _ = writeln!(text, "terminal\treason={}\toutput_incomplete={}\tkernel_lost_events={:?}\texit_code={:?}\tforced_kill={}\tcleanup={}\tlast_sequence={}\toutput_bytes={}",
                    Self::text(&terminal.reason), terminal.output_incomplete, terminal.kernel_lost_events, terminal.exit_code,
                    terminal.forced_kill, Self::text(&terminal.cleanup), terminal.last_sequence, terminal.output_bytes);
            }
            Payload::Result(result) => {
                let _ = writeln!(text, "result\tcomplete={}\toutput_incomplete={}\tcleanup_complete={}\tmissing_targets={:?}", result.complete,
                    result.output_incomplete, result.cleanup_complete, result.missing_targets);
            }
            Payload::Checkpoint(_) => {}
            Payload::Error(error) => Self::error(&mut text, error),
            Payload::Health(health) => Self::health(&mut text, health),
        }
        Self::coverage(&mut text, &frame.coverage);
        Ok(text.into_bytes())
    }

    fn error(text: &mut String, error: &wire::QueryError) {
        let _ = writeln!(
            text,
            "error\t{}\t{}\tposition={:?}\tfloor={:?}",
            Self::text(&error.code),
            Self::text(&error.reason),
            error.position,
            error.floor
        );
    }

    fn health(text: &mut String, health: &wire::QueryHealth) {
        let _ = writeln!(text, "health\twrite_ready={}\tretention_healthy={}\tintake_capacity={}\tmaintenance_capacity={}",
            health.write_ready, health.retention_healthy, health.intake_capacity, health.maintenance_capacity);
    }

    fn coverage(text: &mut String, items: &[wire::QueryCoverage]) {
        for coverage in items {
            let source = coverage.source.as_ref();
            let _ = writeln!(text, "coverage\tstate={}\tcpu={}\tnode={}\tsource={}\tcontiguous={}\tfloor={}\texpired={:?}\trecovery={:?}\tpending={:?}",
                Self::text(&coverage.state), coverage.cpu_id,
                source.map_or_else(String::new, |source| Self::text(&source.node_id)),
                source.map_or_else(String::new, |source| Self::id(&source.source_id)),
                coverage.contiguous_cursor, coverage.retained_floor,
                coverage.expired, coverage.recovery, coverage.pending);
        }
    }

    fn json<T: Serialize>(kind: &'static str, frame: &T) -> Result<Vec<u8>> {
        let mut bytes = Vec::new();
        Record { kind, frame }
            .serialize(&mut serde_json::Serializer::with_formatter(
                &mut bytes, AsciiJson,
            ))
            .context(EncodeSnafu)?;
        bytes.push(b'\n');
        Ok(bytes)
    }

    fn text(value: &str) -> String {
        value.chars().flat_map(char::escape_default).collect()
    }

    fn id(value: &[u8]) -> String {
        uuid::Uuid::from_slice(value).map_or_else(|_| Self::bytes(value), |id| id.to_string())
    }

    fn bytes(value: &[u8]) -> String {
        if let Ok(text) = std::str::from_utf8(value) {
            return Self::text(text);
        }
        let mut text = String::from("0x");
        for byte in value {
            let _ = write!(text, "{byte:02x}");
        }
        text
    }

    fn value(value: &wire::QueryValue) -> Result<String> {
        use wire::query_value::Kind;
        Ok(
            match value.kind.as_ref().context(InvalidSnafu {
                field: "query value",
            })? {
                Kind::Null(true) => "NULL".into(),
                Kind::Null(false) => {
                    return InvalidSnafu {
                        field: "query null value",
                    }
                    .fail()
                }
                Kind::Boolean(value) => value.to_string(),
                Kind::Signed(value) => value.to_string(),
                Kind::Unsigned(value) => value.to_string(),
                Kind::Real(value) => value.to_string(),
                Kind::Text(value) => Self::text(value),
                Kind::Binary(value) => Self::bytes(value),
                Kind::Integer128(value) | Kind::Unsigned128(value) => Self::text(value),
                Kind::Decimal(value) => format!(
                    "{}e-{} decimal({},{})",
                    Self::text(&value.unscaled),
                    value.scale,
                    value.width,
                    value.scale
                ),
                Kind::Timestamp(value) | Kind::Time(value) => {
                    format!("{} {}", value.value, Self::text(&value.unit))
                }
                Kind::Date(value) => format!("{value} days"),
                Kind::Interval(value) => format!(
                    "{} months {} days {} nanoseconds",
                    value.months, value.days, value.nanoseconds
                ),
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn query_batches_use_tables() -> Result<()> {
        let mut output = Output::new(None, true);
        assert!(matches!(output.mode, OutputMode::Table));
        assert!(matches!(
            Output::new(Some(OutputMode::Jsonl), true).mode,
            OutputMode::Jsonl
        ));
        let mut frame = wire::QueryFrame {
            operation: wire::QueryOperation::Replace as i32,
            payload: Some(wire::query_frame::Payload::Metadata(wire::QueryMetadata {
                columns: vec![wire::QueryColumn {
                    name: "count".into(),
                    ..Default::default()
                }],
                ..Default::default()
            })),
            ..Default::default()
        };
        output.query(&frame)?;
        for (operation, count) in [
            (wire::QueryOperation::Replace, u64::MAX),
            (wire::QueryOperation::Append, 42),
        ] {
            frame.operation = operation as i32;
            frame.payload = Some(wire::query_frame::Payload::Rows(wire::QueryRows {
                rows: vec![wire::QueryRow {
                    values: vec![wire::QueryValue {
                        kind: Some(wire::query_value::Kind::Unsigned(count)),
                    }],
                }],
                ..Default::default()
            }));
            let bytes = output.query(&frame)?;
            let text = std::str::from_utf8(&bytes).map_err(|_| {
                InvalidSnafu {
                    field: "test output",
                }
                .build()
            })?;
            assert!(text.contains("│ count"));
            assert!(text.contains(&count.to_string()));
            assert!(text.contains(if operation == wire::QueryOperation::Append {
                "query_append"
            } else {
                "query_replace"
            }));
        }
        frame.payload = Some(wire::query_frame::Payload::Rows(wire::QueryRows::default()));
        let bytes = output.query(&frame)?;
        let text = std::str::from_utf8(&bytes).map_err(|_| {
            InvalidSnafu {
                field: "test output",
            }
            .build()
        })?;
        assert!(text.contains("│ count"));
        assert!(!text.contains("│ 42"));
        Ok(())
    }

    #[test]
    fn observability_cli_output_escapes() -> Result<()> {
        let value = "<script>\u{1b}[2J\u{9b}2J\u{202e}x\n😀";
        let text = Output::text(value);
        assert!(!text.contains('\u{1b}'));
        assert!(!text.contains('\u{9b}'));
        assert!(!text.contains('\u{202e}'));
        let bytes = Output::json("text", &value)?;
        assert!(bytes.is_ascii());
        let decoded: serde_json::Value = serde_json::from_slice(&bytes).context(EncodeSnafu)?;
        assert_eq!(decoded["frame"], value);
        Ok(())
    }

    #[test]
    fn observability_cli_integer_precision() -> Result<()> {
        for kind in [
            wire::query_value::Kind::Unsigned(u64::MAX),
            wire::query_value::Kind::Integer128(i128::MIN.to_string()),
            wire::query_value::Kind::Unsigned128(u128::MAX.to_string()),
        ] {
            let value = wire::QueryValue { kind: Some(kind) };
            let text = Output::value(&value)?;
            assert!(!text.contains('e'));
            let bytes = Output::json("value", &value)?;
            assert!(bytes
                .windows(text.len())
                .any(|bytes| bytes == text.as_bytes()));
        }
        Ok(())
    }

    #[tokio::test]
    async fn observability_cli_nonfinite_json() -> Result<()> {
        let frame = wire::QueryFrame {
            operation: wire::QueryOperation::Replace as i32,
            payload: Some(wire::query_frame::Payload::Rows(wire::QueryRows {
                rows: vec![wire::QueryRow {
                    values: vec![wire::QueryValue {
                        kind: Some(wire::query_value::Kind::Real(f64::INFINITY)),
                    }],
                }],
                ..Default::default()
            })),
            ..Default::default()
        };
        let bytes = Output::new(Some(OutputMode::Jsonl), false).query(&frame)?;
        assert!(String::from_utf8_lossy(&bytes).contains("\"Real\":\"Infinity\""));
        Ok(())
    }

    #[tokio::test]
    async fn observability_cli_trace_metadata() -> Result<()> {
        let frame = wire::TraceFrame {
            schema_version: 1,
            trace_id: vec![1; 16],
            store_uuid: vec![2; 16],
            recovery_epoch: 3,
            read_revision: 4,
            payload: Some(wire::trace_frame::Payload::Metadata(
                wire::TraceDetail {
                    requested: Some(wire::InputSelection {
                        target: "pod/ns/name\n".into(),
                        ..Default::default()
                    }),
                    limits: Some(wire::TraceLimits {
                        output_bytes: 4096,
                        ..Default::default()
                    }),
                    ..Default::default()
                }
                .into(),
            )),
            ..Default::default()
        };
        let bytes = Output::new(Some(OutputMode::Table), false).trace(&frame)?;
        let text = std::str::from_utf8(&bytes).map_err(|_| {
            InvalidSnafu {
                field: "test output",
            }
            .build()
        })?;
        assert!(text.contains("epoch=3\tread_revision=4"));
        assert!(text.contains("target=pod/ns/name\\n\t"));
        assert!(text.contains("output_bytes=4096"));
        let bytes = Output::new(Some(OutputMode::Jsonl), false).trace(&frame)?;
        let value: serde_json::Value = serde_json::from_slice(&bytes).context(EncodeSnafu)?;
        assert_eq!(value["frame"]["recovery_epoch"], 3);
        assert_eq!(
            value["frame"]["payload"]["Metadata"]["requested"]["target"],
            "pod/ns/name\n"
        );
        let coverage = wire::QueryCoverage {
            source: Some(wire::SourceIdentity {
                node_id: "node\n".into(),
                source_id: vec![1; 16],
                ..Default::default()
            }),
            cpu_id: 7,
            contiguous_cursor: 11,
            retained_floor: 5,
            state: "Gap\n".into(),
            pending: vec![wire::SourceGap {
                first_cursor: 1,
                last_cursor: 3,
                commit_revision: 2,
            }],
            ..Default::default()
        };
        let suffix = "coverage\tstate=Gap\\n\tcpu=7\tnode=node\\n\tsource=01010101-0101-0101-0101-010101010101\tcontiguous=11\tfloor=5\texpired=[]\trecovery=[]\tpending=[SourceGap { first_cursor: 1, last_cursor: 3, commit_revision: 2 }]\n";
        let health = wire::QueryHealth {
            write_ready: true,
            intake_capacity: true,
            ..Default::default()
        };
        let error = wire::QueryError {
            code: "Busy\n".into(),
            reason: "wait\t".into(),
            position: Some(wire::StorePosition {
                commit_revision: 9,
                ordinal: 1,
            }),
            ..Default::default()
        };
        let mut output = Output::new(Some(OutputMode::Table), false);
        for (query, trace, line) in [
            (
                wire::query_frame::Payload::Health(health),
                wire::trace_frame::Payload::Health(health),
                "health\twrite_ready=true\tretention_healthy=false\tintake_capacity=true\tmaintenance_capacity=false\n",
            ),
            (
                wire::query_frame::Payload::Error(error.clone()),
                wire::trace_frame::Payload::Error(error),
                "error\tBusy\\n\twait\\t\tposition=Some(StorePosition { commit_revision: 9, ordinal: 1 })\tfloor=None\n",
            ),
        ] {
            let query = output.query(&wire::QueryFrame {
                payload: Some(query),
                coverage: vec![coverage.clone()],
                ..Default::default()
            })?;
            let trace = output.trace(&wire::TraceFrame {
                payload: Some(trace),
                coverage: vec![coverage.clone()],
                ..frame.clone()
            })?;
            for bytes in [query, trace] {
                let text = std::str::from_utf8(&bytes)
                    .map_err(|_| InvalidSnafu { field: "test output" }.build())?;
                let (_, quality) = text
                    .split_once('\n')
                    .context(InvalidSnafu { field: "test envelope" })?;
                assert_eq!(quality, format!("{line}{suffix}"));
            }
        }
        Ok(())
    }
}
