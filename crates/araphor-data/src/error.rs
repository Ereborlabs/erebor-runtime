use std::path::PathBuf;

use snafu::{Location, Snafu};

#[derive(Debug, Snafu)]
#[snafu(visibility(pub(crate)))]
pub enum Error {
    #[snafu(display("{reason}"))]
    EvidenceFrame {
        reason: &'static str,
        input_bytes: usize,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("evidence record protobuf is invalid"))]
    EvidenceDecode {
        frame_bytes: usize,
        source: prost::DecodeError,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Analysis extraction reached its {resource} limit"))]
    AnalysisInputTooLarge {
        resource: &'static str,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("The analysis read was cancelled"))]
    AnalysisReadCancelled {
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("The analysis read reached its deadline"))]
    AnalysisReadDeadline {
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Analysis storage reached its {resource} limit"))]
    StorageCapacity {
        resource: &'static str,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Analysis {resource} admission is full"))]
    AnalysisBusy {
        resource: &'static str,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Required security input reached its {resource} budget"))]
    ProtectedInputCapacity {
        resource: &'static str,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Analysis intake is unavailable until retention succeeds"))]
    RetentionUnavailable {
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Analysis database operation {operation} failed: {source}"))]
    AnalysisDatabase {
        operation: &'static str,
        source: duckdb::Error,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Analysis store `{}` is invalid: {reason}", path.display()))]
    AnalysisState {
        path: PathBuf,
        reason: String,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Analysis evidence range {first_cursor}..={last_cursor} has expired"))]
    RetainedRangeExpired {
        first_cursor: u64,
        last_cursor: u64,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Analysis progress or immutable result conflicts with committed state"))]
    AnalysisConflict {
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Analysis file `{}` failed: {source}", path.display()))]
    Io {
        path: PathBuf,
        source: std::io::Error,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Analysis JSON `{}` failed: {source}", path.display()))]
    Json {
        path: PathBuf,
        source: serde_json::Error,
        #[snafu(implicit)]
        location: Location,
    },
}

pub type Result<T> = std::result::Result<T, Error>;
