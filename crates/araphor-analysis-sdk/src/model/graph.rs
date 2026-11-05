use serde::{Deserialize, Serialize};

use crate::{Error, ErrorCode, GraphAccess, Model, Package, Result, Schema};

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GraphSpec {
    pub access: GraphAccess,
    pub relations: Vec<GraphRelation>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GraphRelation {
    pub name: String,
    pub kind: GraphKind,
    pub properties: Schema,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum GraphKind {
    Node,
    Edge { from: String, to: String },
}

impl GraphSpec {
    pub(crate) fn validate(&self) -> Result<()> {
        if self.relations.is_empty() {
            return Err(Error::contract(ErrorCode::Invalid, "Graph relations"));
        }
        Package::unique(self.relations.iter().map(|relation| relation.name.as_str()))?;
        for relation in &self.relations {
            if relation.name == "graph_clear" {
                return Err(Error::contract(ErrorCode::Invalid, "Graph relation name"));
            }
            Model::schema(&relation.properties)?;
            if let GraphKind::Edge { from, to } = &relation.kind {
                for name in [from, to] {
                    if !self
                        .relations
                        .iter()
                        .any(|node| &node.name == name && node.kind == GraphKind::Node)
                    {
                        return Err(Error::contract(
                            ErrorCode::Invalid,
                            "Graph endpoint relation",
                        ));
                    }
                }
            }
        }
        Ok(())
    }

    pub fn relation(&self, name: &str) -> Result<&GraphRelation> {
        self.relations
            .iter()
            .find(|relation| relation.name == name)
            .ok_or_else(|| Error::contract(ErrorCode::Unauthorized, "Graph relation"))
    }

    pub fn command_schema(&self, name: &str) -> Result<Schema> {
        if self.access != GraphAccess::ReadWrite {
            return Err(Error::contract(
                ErrorCode::Unauthorized,
                "Graph write capability",
            ));
        }
        if name == "graph_clear" {
            return Ok(araphor_graph::Relation::clear_schema());
        }
        Ok(self.relation(name)?.engine().command_schema())
    }

    pub fn read_schema(&self, operation: &str, name: &str) -> Result<Schema> {
        let relation = self.relation(name)?;
        match (&relation.kind, operation) {
            (_,"owned") => Ok(relation.engine().read_schema()),
            (GraphKind::Node, "nodes")
            | (GraphKind::Edge { .. }, "outgoing" | "incoming" | "neighbors") => {
                Ok(relation.engine().read_schema())
            }
            _ => Err(Error::contract(ErrorCode::Invalid, "Graph operation")),
        }
    }

    pub fn argument_schema(&self, operation: &str) -> Result<Schema> {
        match operation {
            "owned" => Ok(Schema::empty()),
            "nodes" | "outgoing" | "incoming" | "neighbors" => {
                Ok(araphor_graph::Relation::key_schema())
            }
            _ => Err(Error::contract(ErrorCode::Invalid, "Graph operation")),
        }
    }
}

impl GraphRelation {
    pub fn engine(&self) -> araphor_graph::Relation {
        araphor_graph::Relation {
            kind: match self.kind {
                GraphKind::Node => araphor_graph::EntityKind::Node,
                GraphKind::Edge { .. } => araphor_graph::EntityKind::Edge,
            },
            properties: self.properties.clone(),
        }
    }
}
