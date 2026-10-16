use super::super::graph::{REVISION, SOURCE};
use super::super::input::relation;
use araphor_analysis_sdk as sdk;

#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) enum GraphTable {
    Subjects,
    Relationships,
    Manifest,
}
relation! {
    pub(in crate::query) MANIFEST, manifest(sink; graph: &crate::GraphSnapshotV1, result_id: &str, revision: u64, sensitivity: crate::ContextSensitivityV1, source: &[u8], manifest: &[u8], max_hops: u32, boundary: bool) {
        name: "graph_manifest",
        join_keys: "tenant_id,graph_result_id,graph_revision",
        owner: "araphor-data.GraphAndFindingOwner",
        readiness: "available",
        description: "Selected graph version headers.",
        setup {
        }
        fields {
            tenant_id: Binary("16-byte ID", "") => Some(graph.scope.identity.tenant_id.as_slice());
            source_key: Binary(SOURCE, "") => Some(source);
            graph_result_id: Utf8("exact immutable result ID", "") => Some(result_id);
            commit_revision: UInt64("store commit revision", "") => Some(revision);
            graph_revision: Binary(REVISION, "") => Some(manifest);
            graph_sensitivity: Utf8("maximum retained input sensitivity; native evidence has a tenant floor", "") =>
                Some(<&str>::from(sensitivity));
            first_cursor: UInt64("first accepted source cursor", "") => Some(graph.first_cursor);
            last_cursor: UInt64("last accepted source cursor", "") => Some(graph.last_cursor);
            previous_result_id: Utf8("replaced graph result ID", "No prior result.") =>
                graph.previous_result_id.as_deref();
            subject_count: UInt64("selected subject rows in this version", "") =>
                Some(graph.graph.subjects.len() as u64);
            relationship_count: UInt64("selected relationship rows in this version", "") =>
                Some(graph.graph.edges.len() as u64);
            max_hops: UInt32("requested traversal depth", "") => Some(max_hops);
            hop_boundary: Boolean("the selected traversal reaches its hop limit", "") => Some(boundary);
        }
    }
}

impl GraphTable {
    pub(super) const ALL: [Self; 3] = [Self::Subjects, Self::Relationships, Self::Manifest];
    pub(super) fn index(self) -> usize {
        match self {
            Self::Subjects => 0,
            Self::Relationships => 1,
            Self::Manifest => 2,
        }
    }
    pub(super) fn source(self) -> &'static str {
        match self {
            Self::Subjects => "graph_subjects",
            Self::Relationships => "relationships",
            Self::Manifest => "graph_manifest",
        }
    }
    pub(super) fn input_bytes(
        revision: &sdk::Revision,
        coverage: &sdk::Coverage,
        batches: [usize; 3],
    ) -> usize {
        let limits = coverage.limits.iter().fold(0usize, |bytes, value| {
            bytes
                .saturating_add(std::mem::size_of::<String>())
                .saturating_add(value.len())
        });
        let metadata = std::mem::size_of::<sdk::Input>()
            .saturating_add(revision.owner.len())
            .saturating_add(revision.id.len())
            .saturating_add(limits)
            .saturating_add(32);
        batches
            .into_iter()
            .fold(metadata.saturating_mul(3), |bytes, count| {
                bytes.saturating_add(count.saturating_mul(std::mem::size_of::<sdk::RecordBatch>()))
            })
    }

    pub(super) fn inputs(
        revision: &sdk::Revision,
        coverage: &sdk::Coverage,
        _batches: [usize; 3],
    ) -> Vec<sdk::Input> {
        ["subjects", "relationships", "graph_manifest"]
            .into_iter()
            .map(|name| sdk::Input {
                data: sdk::Dataset {
                    name: name.into(),
                    batches: Vec::new(),
                },
                revision: revision.clone(),
                coverage: coverage.clone(),
            })
            .collect()
    }
}
