use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Identity {
    pub order: u64,
    pub value: String,
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Operation {
    pub family: u32,
    pub operation: u32,
    pub argument: u32,
    pub wildcard: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Lifetime {
    pub process: Vec<u8>,
    pub entry: Vec<u8>,
    pub binding: Vec<u8>,
    pub role: u32,
    pub state: u32,
    pub rule: u32,
    pub sequence: u64,
}

#[derive(Clone, Debug, Deserialize, JsonSchema, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Record {
    pub id: Identity,
    pub bytes: String,
    pub cursor: u64,
    pub range: u64,
    pub temporal: i32,
    pub operation: Operation,
    pub generation: Option<u64>,
    pub object: Vec<u8>,
    pub decision: u32,
    pub kernel_result: i32,
    pub original_sequence: Option<u64>,
    pub source: Option<Lifetime>,
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Context {
    pub record: String,
    pub operation: Operation,
    pub lifetime: Lifetime,
    pub atom_key: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Disposition {
    pub id: Identity,
    pub reason: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
pub enum CoverageState {
    Healthy,
    Gapped,
    Unknown,
    Closed,
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Coverage {
    pub source: String,
    pub cpu: u32,
    pub first: u64,
    pub last: u64,
    pub expected: u64,
    pub revision: u64,
    pub interval: [u8; 16],
    pub state: CoverageState,
    pub gaps: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(tag = "state", content = "value")]
pub enum LifecycleState {
    Recorded(Vec<Identity>),
    Declared(String),
    Missing,
    NotApplicable(String),
    Unsupported(String),
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Lifecycle {
    pub case: u8,
    pub state: LifecycleState,
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Atom {
    pub key: String,
    pub count: u64,
    pub first: u64,
    pub last: u64,
    pub samples: Vec<Identity>,
    pub prevented: bool,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Counts {
    pub duplicates: u64,
    pub accepted: u64,
    pub included: u64,
    pub unresolved: u64,
    pub excluded: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Snapshot {
    pub identity: String,
    pub counts: Counts,
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Side<T> {
    pub side: u8,
    pub value: T,
}

#[derive(Clone, Debug, Deserialize, JsonSchema, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GroupAtom {
    pub group: String,
    pub source: String,
    pub cpu: u32,
    pub interval: [u8; 16],
    pub atom: Atom,
}

#[derive(Clone, Debug, Deserialize, JsonSchema, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Group {
    pub key: String,
    pub count: u64,
    pub members: Vec<u64>,
    pub samples: Vec<Identity>,
    pub coverage: Vec<u64>,
}

#[derive(Clone, Debug, Deserialize, JsonSchema, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MatchGroup {
    pub side: u8,
    pub key: String,
    pub outcome: String,
    pub identity: String,
    pub revision: String,
    pub policy: String,
    pub count: u64,
}

#[derive(Clone, Debug, Deserialize, JsonSchema, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MatchState {
    pub coverage: String,
    pub lifecycle: String,
}

#[derive(Clone, Debug, Default, Deserialize, JsonSchema, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Comparison {
    pub added: Vec<u64>,
    pub removed: Vec<u64>,
    pub counts: Vec<(u64, u64)>,
    pub outcomes: Vec<(u64, u64)>,
    pub identities: Vec<(u64, u64)>,
    pub resources: Vec<u64>,
    pub forbidden: Vec<u64>,
    pub coverage_changed: bool,
    pub lifecycle_changed: bool,
}

#[derive(Clone, Debug, Deserialize, JsonSchema, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ContextSelection {
    pub selector_version: u32,
    pub from_utc_ns: u64,
    pub cutoff_utc_ns: u64,
    pub host_packet: String,
}
