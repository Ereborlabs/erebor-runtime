use serde::{Deserialize, Serialize};

use crate::Schema;

pub const CONTRACT_VERSION: u32 = 1;

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Package {
    pub contract_version: u32,
    pub id: String,
    pub revision: String,
    pub dependencies: Vec<Dependency>,
    pub exports: Vec<Model>,
}

impl Package {
    pub fn new(id: impl Into<String>, revision: impl Into<String>, exports: Vec<Model>) -> Self {
        Self {
            contract_version: CONTRACT_VERSION,
            id: id.into(),
            revision: revision.into(),
            dependencies: Vec::new(),
            exports,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Dependency {
    pub model: String,
    pub input: String,
    pub package: String,
    pub revision: String,
    pub export: String,
    pub output: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Model {
    pub name: String,
    pub inputs: Vec<Port>,
    pub parameters: Schema,
    pub outputs: Vec<Port>,
    pub checkpoint: Option<CheckpointSpec>,
    pub reasons: Vec<Reason>,
    pub limits: Limits,
    pub tolerance: NumericTolerance,
}

impl Model {
    pub fn new(name: impl Into<String>, inputs: Vec<Port>, outputs: Vec<Port>) -> Self {
        Self {
            name: name.into(),
            inputs,
            parameters: Schema::empty(),
            outputs,
            checkpoint: None,
            reasons: Vec::new(),
            limits: Limits::default(),
            tolerance: NumericTolerance::default(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Port {
    pub name: String,
    pub schema: Schema,
    pub kind: OutputKind,
    pub evidence_required: bool,
}

impl Port {
    pub fn new(name: impl Into<String>, schema: Schema) -> Self {
        Self {
            name: name.into(),
            schema,
            kind: OutputKind::Table,
            evidence_required: false,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OutputKind {
    Table,
    Discovery,
    Subjects,
    Relationships,
    Findings,
    PolicyCandidates,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CheckpointSpec {
    pub version: u32,
    pub datasets: Vec<Port>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Reason {
    pub code: String,
    pub details: Schema,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NumericTolerance {
    pub absolute: f64,
    pub relative: f64,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Limits {
    pub max_batches: u32,
    pub max_rows: u64,
    pub max_bytes: u64,
    pub max_checkpoint_bytes: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_batches: 1024,
            max_rows: 1_000_000,
            max_bytes: 64 * 1024 * 1024,
            max_checkpoint_bytes: 16 * 1024 * 1024,
        }
    }
}
