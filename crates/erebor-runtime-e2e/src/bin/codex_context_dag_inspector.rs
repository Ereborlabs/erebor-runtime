//! Read-only ContextRepository inspection used by the privileged Codex DAG
//! evidence lane. The workload never invokes this binary.

use std::{error::Error, io, path::PathBuf};

use clap::Parser;
use erebor_runtime_context::{
    CommitMetadata, CommitMetadataSource, CommitMetadataSourceError, ContextPin, ContextRepository,
    ScopeRef,
};
use serde_json::Value;

#[derive(Parser)]
struct Arguments {
    #[arg(long)]
    repository: PathBuf,
    #[arg(long)]
    session_id: String,
    /// One `parent-scope|child-scope|edge-path` assertion.
    #[arg(long)]
    edge: Vec<String>,
}

struct ReadOnlyMetadataSource;

impl CommitMetadataSource for ReadOnlyMetadataSource {
    fn metadata(&self) -> Result<CommitMetadata, CommitMetadataSourceError> {
        Err(Box::new(io::Error::other(
            "the Context DAG inspector must not write commits",
        )))
    }
}

struct ContextDagInspector {
    repository: ContextRepository,
    session_id: String,
}

impl ContextDagInspector {
    fn open(arguments: Arguments) -> Result<Self, Box<dyn Error>> {
        Ok(Self {
            repository: ContextRepository::open(arguments.repository, ReadOnlyMetadataSource)?,
            session_id: arguments.session_id,
        })
    }

    fn inspect(&self, edges: &[String]) -> Result<(), Box<dyn Error>> {
        let scopes = self.repository.scope_refs()?;
        if scopes.is_empty()
            || scopes
                .iter()
                .any(|scope| scope.session_id() != self.session_id)
        {
            return Err("ContextRepository contains a scope outside the expected session".into());
        }
        self.repository.verify_full()?;
        for edge in edges {
            self.inspect_edge(edge)?;
        }
        println!("context_dag_scopes={}", scopes.len());
        Ok(())
    }

    fn inspect_edge(&self, encoded: &str) -> Result<(), Box<dyn Error>> {
        let mut fields = encoded.splitn(3, '|');
        let parent = ScopeRef::parse(
            fields
                .next()
                .filter(|value| !value.is_empty())
                .ok_or("edge omitted parent scope")?,
        )?;
        let child = ScopeRef::parse(
            fields
                .next()
                .filter(|value| !value.is_empty())
                .ok_or("edge omitted child scope")?,
        )?;
        let path = fields
            .next()
            .filter(|value| !value.is_empty())
            .ok_or("edge omitted immutable edge path")?;
        if parent.session_id() != self.session_id || child.session_id() != self.session_id {
            return Err("Context DAG edge escaped the expected session namespace".into());
        }
        let parent_head = self.repository.scope_head(&parent)?;
        let blob = self
            .repository
            .read_commit_blob(parent_head, path)?
            .ok_or("expected Context DAG edge is absent from parent scope")?;
        let edge: Value = serde_json::from_slice(blob.bytes())?;
        if edge.get("child_scope").and_then(Value::as_str) != Some(child.as_str()) {
            return Err("Context DAG edge names a different child scope".into());
        }
        let pin: ContextPin = serde_json::from_value(
            edge.get("parent_context")
                .cloned()
                .ok_or("Context DAG edge omitted parent pin")?,
        )?;
        if pin.scope_ref() != parent.as_str() {
            return Err("Context DAG edge parent pin names a different scope".into());
        }
        self.repository.validate_pin(&pin)?;
        if !self
            .repository
            .is_ancestor(pin.commit()?, self.repository.scope_head(&child)?)?
        {
            return Err("Context DAG child ref is not causal from its parent pin".into());
        }
        Ok(())
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    let arguments = Arguments::parse();
    let edges = arguments.edge.clone();
    ContextDagInspector::open(arguments)?.inspect(&edges)
}

#[cfg(test)]
mod tests {
    use super::*;
    use erebor_runtime_context::{CommitSignature, CommitTime, Snapshot, TreeEdit};

    #[derive(Clone)]
    struct TestMetadataSource {
        metadata: CommitMetadata,
    }

    impl TestMetadataSource {
        fn new() -> Result<Self, Box<dyn Error>> {
            let time = CommitTime::new(1_700_000_000, 0)?;
            let signature = CommitSignature::new("Erebor Test", "test@erebor.dev", time)?;
            Ok(Self {
                metadata: CommitMetadata::new(signature.clone(), signature),
            })
        }
    }

    impl CommitMetadataSource for TestMetadataSource {
        fn metadata(&self) -> Result<CommitMetadata, CommitMetadataSourceError> {
            Ok(self.metadata.clone())
        }
    }

    #[test]
    fn inspector_reopens_and_validates_a_checked_same_session_edge() -> Result<(), Box<dyn Error>> {
        let temporary = tempfile::tempdir()?;
        let path = temporary.path().join("context.git");
        let repository = ContextRepository::init(&path, TestMetadataSource::new()?)?;
        let root = ScopeRef::root("session-fixture")?;
        let root_head = repository.initialize_root(
            "session-fixture",
            Snapshot::new(Vec::new())?,
            "Initialize root",
        )?;
        let child = ScopeRef::scope("session-fixture", "child")?;
        repository.create_scope(
            child.clone(),
            erebor_runtime_context::ScopeStart::existing_commit(root_head),
        )?;
        let parent_pin = repository.pin_scope_head(root.clone(), &[])?.pin().clone();
        let edge_path = "erebor/context-dag/edges/fixture.json";
        let edge = serde_json::json!({
            "parent_context": parent_pin,
            "child_scope": child.as_str(),
        });
        repository.append_snapshot(
            root.clone(),
            root_head,
            Snapshot::new(vec![TreeEdit::blob(edge_path, serde_json::to_vec(&edge)?)?])?,
            "Record child edge",
        )?;

        let inspector = ContextDagInspector {
            repository: ContextRepository::open(&path, TestMetadataSource::new()?)?,
            session_id: String::from("session-fixture"),
        };
        inspector.inspect(&[format!("{}|{}|{edge_path}", root, child)])
    }
}
