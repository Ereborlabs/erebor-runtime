use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

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

#[derive(
    Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize, JsonSchema,
)]
pub enum ResultAuthority {
    Succeeded,
    Denied,
    Other,
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Fact {
    pub identity: u64,
    pub record: u64,
    pub value: FactValue,
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(tag = "kind", content = "value", deny_unknown_fields)]
pub enum FactValue {
    Other,
    Parent {
        child_task: Option<u64>,
        child_process: Option<[u8; 16]>,
        qualified: bool,
    },
    Baseline {
        role: u32,
        state: u32,
        outside: bool,
        reviewed: bool,
    },
    Context {
        classification: ContextClass,
    },
    Credential(Credential),
    Authority(Authority),
    Channel(Channel),
    Kubernetes(Kubernetes),
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, JsonSchema)]
pub enum ContextClass {
    OutsideAuthority,
    InMemory,
    PayloadUnobservable,
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Credential {
    pub object: [u8; 16],
    pub expected: bool,
    pub reviewed: bool,
    pub successful: bool,
    pub completion: Option<Completion>,
    pub principal: Option<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, JsonSchema)]
pub enum ReadPath {
    Read,
    Mmap,
    InheritedFd,
    IoUring,
    Memory,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Completion {
    pub owner: String,
    pub id: String,
    pub task: u64,
    pub process: [u8; 16],
    pub object: [u8; 16],
    pub file_description: String,
    pub path: ReadPath,
    pub result: i64,
    pub bytes: u64,
    pub lease: Option<String>,
    pub principal: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Authority {
    pub id: String,
    pub process: Option<[u8; 16]>,
    pub task: Option<u64>,
    pub credential: Option<[u8; 16]>,
    pub socket: Option<[u8; 16]>,
    pub request: Option<String>,
    pub lease: Option<String>,
    pub principal: String,
    pub operation: String,
    pub outside: bool,
    pub workload: Option<Vec<u8>>,
    pub contextual: bool,
    pub direct: bool,
    pub result: ResultAuthority,
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Channel {
    pub task: u64,
    pub process: [u8; 16],
    pub socket: [u8; 16],
    pub authority: String,
    pub request: String,
    pub lease: String,
    pub principal: String,
    pub operation: String,
    pub successful: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Kubernetes {
    pub qualified: bool,
    pub request: bool,
    pub audit: bool,
    pub object: bool,
    pub version: bool,
    pub owner: bool,
    pub pod: bool,
    pub node: bool,
    pub container: bool,
    pub admission: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub window_ns: u64,
    pub window_records: u64,
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
