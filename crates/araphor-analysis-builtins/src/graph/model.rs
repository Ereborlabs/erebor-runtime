use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

mod domain;
mod proof;

pub use domain::*;
pub use proof::*;

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Observation {
    pub lifetime: Vec<u8>,
    pub task: u64,
    pub process: Option<[u8; 16]>,
    pub execution: Vec<u8>,
    pub object: Vec<u8>,
    pub role: Option<u32>,
    pub state: Option<u32>,
    pub exact_identity: bool,
    pub policy_conflict: bool,
    pub complete: bool,
    pub network: bool,
    pub denied: bool,
    pub admitted: bool,
    pub operation: Operation,
    pub physical: Physical,
    pub boottime: u64,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, JsonSchema)]
pub enum Operation {
    OpenRead,
    Read,
    MmapRead,
    Other,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, JsonSchema)]
pub enum Physical {
    Prevented,
    PacketDropped,
    TerminationQueued,
    Unknown,
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Fact {
    pub identity: u64,
    pub record: u64,
    pub reviewed: bool,
    pub value: GraphFactValueV1,
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub window_ns: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Subject {
    pub record: u64,
    pub context: Option<u64>,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, JsonSchema)]
pub enum EdgeKind {
    Process,
    ExecutionSet,
    Object,
    Parent,
    Authority,
    Kubernetes,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, JsonSchema)]
pub enum Cause {
    Direct,
    Contextual,
    Contradicted,
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Relationship {
    pub record: u64,
    pub fact: Option<u64>,
    pub kind: EdgeKind,
    pub cause: Cause,
    pub evidence: Vec<u64>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Finding {
    pub record: u64,
    pub context: Option<u64>,
    pub reason: String,
    pub confirmed: bool,
    pub evidence: Vec<u64>,
    pub limits: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct State {
    pub value: String,
}
