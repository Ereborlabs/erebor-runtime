





#[cfg(test)]
mod tests {
    use std::ops::Bound;

    use prost::Message as _;

    use super::*;
    use crate::analysis::{AnalysisStore, ProcessorScopeV1};
    use crate::{AnalysisReadControl, AnalysisSelectionV1, AnalysisTableRequests, Result};
    use std::collections::BTreeSet;
    use crate :: { AnalysisContextKeyV1 , AnalysisContextVersionV1 , ContextSensitivityV1 , CoverageReport , EvidenceIntakeIdentityV1 , EvidenceRecord , ValidatedCoverageV1 , ValidatedEvidenceBatchV1 } ;

    type TestResult<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

    fn identity(tenant: u8, source: u8) -> EvidenceIntakeIdentityV1 {
        EvidenceIntakeIdentityV1 {
            tenant_id: [tenant; 16],
            node_id: format!("node-{tenant}"),
            node_boot_id: [tenant; 16],
            source_id: [source; 16],
            ..crate::analysis::tests::identity()
        }
    }

    fn batch(first_cursor: u64, intake: u64) -> ValidatedEvidenceBatchV1 {
        let payload = EvidenceRecord {
            operation: 1,
            ..Default::default()
        }
        .encode_to_vec();
        let mut framed = (payload.len() as u32).to_be_bytes().to_vec();
        framed.extend(payload);
        framed.extend(crc32c::crc32c(&framed).to_be_bytes());
        let length = framed.len();
        ValidatedEvidenceBatchV1 {
            cpu_id: 0,
            first_cursor,
            last_cursor: first_cursor,
            intake_utc_ns: intake,
            framed_records: framed.into(),
            frame_ends: vec![length],
        }
    }

    fn read(store: &AnalysisStore, selection: &AnalysisSelectionV1) -> Result<(u64, u64)> {
        store
            .dependency_revision(selection, &AnalysisReadControl::default())
            .map(|(meta, revision)| (meta.commit_revision, revision))
    }

    #[test]
    fn query_tenant_dependencies() -> TestResult {
        let directory = tempfile::tempdir()?;
        let store = AnalysisStore::open(directory.path().join("analysis"))?;
        let first = identity(1, 1);
        let mut selection = AnalysisSelectionV1::tenant(first.tenant_id);
        assert_eq!(read(&store, &selection)?, (0, 0));
        store.accept_validated_batch(first.clone(), batch(1, 10))?;
        assert_eq!(read(&store, &selection)?, (1, 1));
        store.accept_validated_batch(identity(2, 2), batch(1, 10))?;
        assert_eq!(read(&store, &selection)?, (2, 1));
        let mut next = identity(1, 3);
        next.node_boot_id = [3; 16];
        next.node_id = "next-node".into();
        store.accept_validated_batch(next, batch(1, 20))?;
        assert_eq!(read(&store, &selection)?, (3, 3));
        selection.nodes.push(first.node_id.clone());
        assert_eq!(read(&store, &selection)?, (3, 1));
        let context = AnalysisContextVersionV1 {
            key: AnalysisContextKeyV1 {
                tenant_id: first.tenant_id,
                owner_id: "policy".into(),
                entity_key: vec![1],
                lifetime_key: vec![2],
                owner_revision: 1,
            },
            valid_from_utc_ns: None,
            valid_until_utc_ns: None,
            sensitivity: ContextSensitivityV1::Tenant,
            body: b"context".to_vec(),
        };
        store.commit_context(&context)?;
        assert_eq!(read(&store, &selection)?, (4, 4));
        selection.contexts = crate::Selection::Exact(Vec::new());
        assert_eq!(read(&store, &selection)?, (4, 1));
        selection.received_from = Bound::Included(11);
        assert_eq!(read(&store, &selection)?, (4, 0));
        let empty = AnalysisSelectionV1::new(first.tenant_id, vec![]);
        assert_eq!(read(&store, &empty)?, (4, 0));
        Ok(())
    }

    #[test]
    fn context_owner_dependency_tracks_new_matching_keys() -> TestResult {
        let directory = tempfile::tempdir()?;
        let store = AnalysisStore::open(directory.path().join("analysis"))?;
        let selection = AnalysisSelectionV1::tenant([1; 16]);
        let tables = AnalysisTableRequests::from([("context_versions".into(), None)]);
        let owners = BTreeSet::from(["policy".to_owned()]);
        let revision = |filter: Option<&BTreeSet<String>>| -> Result<u64> {
            store
                .dependency_revision_for_filtered(
                    &selection,
                    &tables,
                    filter,
                    &AnalysisReadControl::default(),
                )
                .map(|(_, revision)| revision)
        };
        let context = |owner: &str, entity: u8| AnalysisContextVersionV1 {
            key: AnalysisContextKeyV1 {
                tenant_id: selection.tenant_id,
                owner_id: owner.into(),
                entity_key: vec![entity],
                lifetime_key: vec![1],
                owner_revision: 1,
            },
            valid_from_utc_ns: None,
            valid_until_utc_ns: None,
            sensitivity: ContextSensitivityV1::Tenant,
            body: b"context".to_vec(),
        };
        assert_eq!(revision(Some(&owners))?, 0);
        store.commit_context(&context("unrelated", 1))?;
        assert_eq!(revision(Some(&owners))?, 0);
        assert_eq!(revision(None)?, 1);
        store.commit_context(&context("policy", 2))?;
        assert_eq!(revision(Some(&owners))?, 2);
        store.commit_context(&context("unrelated", 3))?;
        assert_eq!(revision(Some(&owners))?, 2);
        assert_eq!(revision(None)?, 3);
        Ok(())
    }

    #[test]
    fn query_state_dependencies() -> TestResult {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("analysis");
        let store = AnalysisStore::open(&path)?;
        let source = identity(1, 1);
        store.accept_validated_batch(source.clone(), batch(1, 10))?;
        let selection = AnalysisSelectionV1::new(source.tenant_id, vec![source.clone()]);
        let tables = AnalysisTableRequests::from([("discovery_state".into(), None)]);
        let state = |store: &AnalysisStore| -> Result<(u64, u64)> {
            store
                .dependency_revision_for(&selection, &tables, &AnalysisReadControl::default())
                .map(|(meta, revision)| (meta.commit_revision, revision))
        };
        assert_eq!(state(&store)?, (1, 1));
        let scope = ProcessorScopeV1 {
            identity: source,
            processor_id: DISCOVERY_PROCESSOR.into(),
            method_version: u64::from(DISCOVERY_SCHEMA_VERSION),
        };
        store.register_processor(&scope, crate::ProcessorClassV1::Required, 1)?;
        assert_eq!(read(&store, &selection)?, (2, 1));
        assert_eq!(state(&store)?, (2, 2));
        let retirement = crate::ProcessorRetirementV1 {
            scope,
            change_id: "native-state".into(),
            reason: "Stop this processor.".into(),
            expected_cursor: 0,
            cutoff_cursor: 1,
        };
        assert_eq!(store.retire_required(&retirement)?, 3);
        assert_eq!(read(&store, &selection)?, (3, 1));
        assert_eq!(state(&store)?, (3, 3));
        assert_eq!(store.retire_required(&retirement)?, 3);
        assert_eq!(state(&store)?, (3, 3));
        drop(store);
        let reopened = AnalysisStore::open(path)?;
        assert_eq!(state(&reopened)?, (3, 3));
        Ok(())
    }

    #[test]
    fn query_follow_scoped_dependencies() -> TestResult {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("analysis");
        let store = AnalysisStore::open(&path)?;
        let selected = identity(1, 1);
        let foreign = identity(2, 2);
        let unrelated = identity(1, 3);
        let context = AnalysisContextVersionV1 {
            key: AnalysisContextKeyV1 {
                tenant_id: selected.tenant_id,
                owner_id: "policy".into(),
                entity_key: vec![1],
                lifetime_key: vec![2],
                owner_revision: 1,
            },
            valid_from_utc_ns: None,
            valid_until_utc_ns: None,
            sensitivity: ContextSensitivityV1::Tenant,
            body: b"context".to_vec(),
        };
        let mut selection = AnalysisSelectionV1::new(selected.tenant_id, vec![selected.clone()]);
        selection.received_from = Bound::Included(10);
        selection.received_until = Bound::Excluded(20);
        selection.contexts = crate::Selection::Exact(vec![context.key.clone()]);
        assert_eq!(read(&store, &selection)?, (0, 0));
        store.accept_validated_batch(foreign, batch(1, 10))?;
        assert_eq!(read(&store, &selection)?, (1, 0));
        store.accept_validated_batch(unrelated, batch(1, 10))?;
        assert_eq!(read(&store, &selection)?, (2, 0));
        store.accept_validated_batch(selected.clone(), batch(11, 9))?;
        assert_eq!(read(&store, &selection)?, (3, 0));
        store.accept_validated_batch(selected.clone(), batch(12, 10))?;
        assert_eq!(read(&store, &selection)?, (4, 4));
        assert_eq!(
            store
                .source_receipt(&selected)?
                .ok_or("receipt absent")?
                .contiguous_cursor,
            0
        );
        store.accept_validated_batch(selected.clone(), batch(13, 20))?;
        assert_eq!(read(&store, &selection)?, (5, 4));
        let mut other = context.clone();
        other.key.owner_revision = 2;
        store.commit_context(&other)?;
        assert_eq!(read(&store, &selection)?, (6, 4));
        store.commit_context(&context)?;
        assert_eq!(read(&store, &selection)?, (7, 7));
        other.key = context.key.clone();
        other.key.lifetime_key = vec![3];
        store.commit_context(&other)?;
        assert_eq!(read(&store, &selection)?, (8, 7));
        for report_revision in 1..=2 {
            let report = CoverageReport {
                source_id: selected.source_id.to_vec(),
                cpu_id: 0,
                source_epoch: selected.source_epoch,
                revision: report_revision,
                intervals: Vec::new(),
            };
            store.accept_validated_coverage(ValidatedCoverageV1 {
                identity: selected.clone(),
                cpu_id: 0,
                revision: report_revision,
                encoded_report: report.encode_to_vec(),
            })?;
            assert_eq!(
                read(&store, &selection)?,
                (8 + report_revision, 8 + report_revision)
            );
        }
        store.record_recovery_floor(&selected, 5)?;
        assert_eq!(read(&store, &selection)?, (11, 11));
        let cancelled = AnalysisReadControl::default();
        cancelled.cancel()?;
        assert!(matches!(
            store.dependency_revision(&selection, &cancelled),
            Err(crate::Error::AnalysisReadCancelled { .. })
        ));
        let mut invalid = selection.clone();
        invalid
            .sources
            .exact_mut()
            .ok_or("exact sources absent")?
            .push(identity(2, 2));
        assert!(store
            .dependency_revision(&invalid, &AnalysisReadControl::default())
            .is_err());
        drop(store);
        let reopened = AnalysisStore::open(path)?;
        assert_eq!(read(&reopened, &selection)?, (11, 11));
        Ok(())
    }

    use crate::analysis::graph_rows::tests::fixture::CommitFixture;

    #[test]
    fn graph_result_follow_ignores_raw_progress() -> TestResult {
        let fixture = CommitFixture::new()?;
        let source = fixture.snapshot.scope.identity.clone();
        let mut selection = AnalysisSelectionV1::new(source.tenant_id, vec![source.clone()]);
        selection.select_graphs(crate::Selection::All, None)?;
        let columns = std::collections::BTreeSet::from([crate::AnalysisStore::table_schemas()
            ["graph_manifest"]
            .index_of("graph_result_id")?]);
        let graph = AnalysisTableRequests::from([("graph_manifest".into(), Some(columns.clone()))]);
        let mixed = AnalysisTableRequests::from([
            ("graph_manifest".into(), Some(columns)),
            ("events".into(), None),
        ]);
        let control = AnalysisReadControl::default();
        let revision = |tables: &AnalysisTableRequests| {
            fixture
                .store
                .dependency_revision_for(&selection, tables, &control)
                .map(|(_, revision)| revision)
        };
        let committed = fixture
            .store
            .commit_graph(&fixture.request, true, || Ok(()))?
            .commit_revision;
        assert_eq!(revision(&graph)?, committed);
        fixture
            .store
            .accept_validated_batch(source.clone(), batch(2, 11))?;
        assert_eq!(revision(&graph)?, committed);
        assert!(revision(&mixed)? > committed);
        fixture.store.record_recovery_floor(&source, 4)?;
        assert_eq!(revision(&graph)?, committed);
        Ok(())
    }

    #[test]
    fn graph_only_commit_wakes_native_findings() -> TestResult {
        let fixture = CommitFixture::new()?;
        let tenant = fixture.snapshot.scope.identity.tenant_id;
        let mut selection = AnalysisSelectionV1::tenant(tenant);
        selection.contexts = crate::Selection::Exact(Vec::new());
        selection.traces = crate::Selection::Exact(Vec::new());
        let mut graph_selection = selection.clone();
        graph_selection.select_graphs(crate::Selection::All, None)?;
        let control = AnalysisReadControl::default();
        let revision = |name: &str| -> Result<u64> {
            let tables = AnalysisTableRequests::from([(name.to_owned(), None)]);
            let selection = if matches!(name, "findings" | "graph_manifest") {
                &graph_selection
            } else {
                &selection
            };
            fixture
                .store
                .dependency_revision_for(selection, &tables, &control)
                .map(|(_, revision)| revision)
        };
        let before = revision("findings")?;
        let notification = revision("notifications")?;
        let committed = fixture
            .store
            .commit_graph(&fixture.request, true, || Ok(()))?
            .commit_revision;
        assert!(committed > before);
        for name in ["findings", "graph_manifest"] {
            assert_eq!(revision(name)?, committed, "{name}");
        }
        assert_eq!(revision("notifications")?, notification);

        let context = crate::AnalysisContextVersionV1 {
            key: crate::AnalysisContextKeyV1 {
                tenant_id: tenant,
                owner_id: "unrelated-context".into(),
                entity_key: vec![1],
                lifetime_key: vec![2],
                owner_revision: 1,
            },
            valid_from_utc_ns: None,
            valid_until_utc_ns: None,
            sensitivity: crate::ContextSensitivityV1::Tenant,
            body: b"context".to_vec(),
        };
        let context_revision = fixture.store.commit_context(&context)?;
        assert_eq!(revision("findings")?, committed);
        for name in ["notifications", "notification_routes"] {
            assert_eq!(revision(name)?, context_revision, "{name}");
        }
        Ok(())
    }

    #[test]
    fn graph_notice_changes_dependency() -> TestResult {
        let fixture = CommitFixture::new()?;
        let mut selection = AnalysisSelectionV1::new(
            fixture.snapshot.scope.identity.tenant_id,
            vec![fixture.snapshot.scope.identity.clone()],
        );
        selection.select_graphs(crate::Selection::All, None)?;
        let schemas = crate::AnalysisStore::table_schemas();
        let notices = AnalysisTableRequests::from([(
            "graph_manifest".into(),
            Some(std::collections::BTreeSet::from([
                schemas["graph_manifest"].index_of("notice_context_revision")?,
                schemas["graph_manifest"].index_of("notice_coverage_revision")?,
            ])),
        )]);
        let all = AnalysisTableRequests::from([("graph_manifest".into(), None)]);
        let immutable = AnalysisTableRequests::from([(
            "graph_manifest".into(),
            Some(std::collections::BTreeSet::from([schemas
                ["graph_manifest"]
                .index_of("graph_result_id")?])),
        )]);
        let control = AnalysisReadControl::default();
        let (_, before) = fixture
            .store
            .dependency_revision_for(&selection, &notices, &control)?;
        let receipt = fixture
            .store
            .commit_graph(&fixture.request, true, || Ok(()))?;
        let (_, first) = fixture
            .store
            .dependency_revision_for(&selection, &notices, &control)?;
        assert_eq!(first, receipt.commit_revision);
        assert!(first > before);
        let context = crate::AnalysisContextVersionV1 {
            key: crate::AnalysisContextKeyV1 {
                tenant_id: selection.tenant_id,
                owner_id: "notice-test".into(),
                entity_key: vec![1],
                lifetime_key: vec![2],
                owner_revision: 1,
            },
            valid_from_utc_ns: None,
            valid_until_utc_ns: None,
            sensitivity: crate::ContextSensitivityV1::Tenant,
            body: b"notice".to_vec(),
        };
        let current = fixture.store.commit_context(&context)?;
        assert!(current > first);
        assert_eq!(
            fixture
                .store
                .dependency_revision_for(&selection, &notices, &control)?
                .1,
            first
        );
        fixture.store.mark_graph_notice(
            &fixture.request.scope,
            &fixture.request.result_id,
            receipt.commit_revision,
            current,
            fixture.request.coverage_revision,
            || Ok(()),
        )?;
        let noticed = fixture.store.meta()?.commit_revision;
        assert_eq!(noticed, current + 1);
        assert_eq!(
            fixture
                .store
                .dependency_revision_for(&selection, &notices, &control)?
                .1,
            noticed
        );
        assert_eq!(
            fixture
                .store
                .dependency_revision_for(&selection, &all, &control)?
                .1,
            noticed
        );
        assert_eq!(
            fixture
                .store
                .dependency_revision_for(&selection, &immutable, &control)?
                .1,
            first
        );
        assert_eq!(
            fixture
                .store
                .graph_result(selection.tenant_id, &fixture.request.result_id)?,
            Some(fixture.snapshot)
        );
        Ok(())
    }

    #[test]
    fn graph_state_scoped_dependencies() -> TestResult {
        let mut fixture = CommitFixture::new()?;
        let source = fixture.snapshot.scope.identity.clone();
        let selection = AnalysisSelectionV1::new(source.tenant_id, vec![source.clone()]);
        drop(fixture._graph);
        fixture._graph = fixture.store.lease_graph(vec![selection.clone()])?;
        let mut other = source.clone();
        other.source_id[0] ^= 1;
        other.node_id = format!("{}-other", source.node_id);
        fixture
            .store
            .accept_validated_batch(other.clone(), batch(1, 10))?;
        let other_scope = ProcessorScopeV1 {
            identity: other.clone(),
            ..fixture.request.scope.clone()
        };
        assert!(fixture.store.processor_health(&other_scope)?.is_none());
        let first = fixture
            .store
            .commit_graph(&fixture.request, true, || Ok(()))?;
        let tables = AnalysisTableRequests::from([("graph_state".into(), None)]);
        let control = AnalysisReadControl::default();
        let before = fixture
            .store
            .dependency_revision_for(&selection, &tables, &control)?;
        assert_eq!(before.1, first.commit_revision);
        fixture.store.register_graph(&other)?;
        let after = fixture
            .store
            .dependency_revision_for(&selection, &tables, &control)?;
        assert!(after.0.commit_revision > before.0.commit_revision);
        assert_eq!(
            after.1, before.1,
            "An unrelated Graph registration changed the dependency."
        );

        let mut graph = fixture.snapshot.clone();
        graph.previous_result_id = Some(fixture.request.result_id.clone());
        assert_ne!(
            graph.packages[0].state,
            crate::GraphPackageStateV1::CoverageInsufficient
        );
        graph.packages[0].state = crate::GraphPackageStateV1::CoverageInsufficient;
        graph.validate()?;
        let mut replacement = fixture.request.clone();
        replacement.result_id = "graph:state-replacement".into();
        replacement.expected_cursor = first.consumed_cursor;
        replacement.created_utc_ns += 1;
        replacement.body = serde_json::to_vec(&graph)?;
        let head = fixture.store.commit_graph(&replacement, true, || Ok(()))?;
        assert_eq!(head.consumed_cursor, first.consumed_cursor);
        assert!(head.commit_revision > after.0.commit_revision);
        assert_eq!(fixture.store.graph_snapshot(&source)?, Some(graph));
        assert_eq!(
            fixture
                .store
                .dependency_revision_for(&selection, &tables, &control)?
                .1,
            head.commit_revision
        );

        let mut absent = source.clone();
        absent.source_id[0] ^= 2;
        let absent = AnalysisSelectionV1::new(source.tenant_id, vec![source.clone(), absent]);
        let mut optional = source.clone();
        optional.source_id[0] ^= 4;
        fixture.store.register_processor(
            &ProcessorScopeV1 {
                identity: optional.clone(),
                ..fixture.request.scope.clone()
            },
            crate::ProcessorClassV1::Optional,
            1,
        )?;
        let optional = AnalysisSelectionV1::new(source.tenant_id, vec![source.clone(), optional]);
        let unpublished =
            AnalysisSelectionV1::new(source.tenant_id, vec![source.clone(), other.clone()]);
        let mut all = selection.clone();
        all.sources = crate::Selection::All;
        all.nodes.push(source.node_id.clone());
        let empty = AnalysisSelectionV1::new(source.tenant_id, Vec::new());
        let mixed = AnalysisTableRequests::from([
            ("graph_state".into(), None),
            ("discovery_state".into(), None),
        ]);
        let changed = fixture.store.register_processor(
            &ProcessorScopeV1 {
                identity: other,
                processor_id: DISCOVERY_PROCESSOR.into(),
                method_version: u64::from(DISCOVERY_SCHEMA_VERSION),
            },
            crate::ProcessorClassV1::Required,
            1,
        )?;
        for (name, selection, tables) in [
            ("all", &all, &tables),
            ("empty", &empty, &tables),
            ("unpublished", &unpublished, &tables),
            ("absent", &absent, &tables),
            ("optional", &optional, &tables),
            ("mixed", &selection, &mixed),
        ] {
            let (meta, dependency) = fixture
                .store
                .dependency_revision_for(selection, tables, &control)?;
            assert_eq!(
                (meta.commit_revision, dependency),
                (changed, changed),
                "{name}"
            );
        }
        assert_eq!(
            fixture
                .store
                .dependency_revision_for(&selection, &tables, &control)?
                .1,
            head.commit_revision
        );

        let gap = fixture
            .store
            .retire_required(&crate::ProcessorRetirementV1 {
                scope: other_scope.clone(),
                change_id: "graph-state-gap".into(),
                reason: "Stop the unprocessed Graph source.".into(),
                expected_cursor: 0,
                cutoff_cursor: 1,
            })?;
        assert_eq!(
            fixture.store.processor_gaps(&other_scope, 0)?,
            [crate::AnalysisGapV1 {
                first_cursor: 1,
                last_cursor: 1,
                commit_revision: gap,
            }]
        );
        assert_eq!(
            fixture
                .store
                .dependency_revision_for(&selection, &tables, &control)?
                .1,
            gap
        );
        let retirement = crate::ProcessorRetirementV1 {
            scope: fixture.request.scope.clone(),
            change_id: "graph-state-stop".into(),
            reason: "Stop the completed Graph source.".into(),
            expected_cursor: head.consumed_cursor,
            cutoff_cursor: head.consumed_cursor,
        };
        let retired = fixture.store.retire_required(&retirement)?;
        assert!(fixture
            .store
            .processor_gaps(&retirement.scope, 0)?
            .is_empty());
        let stopped = fixture
            .store
            .dependency_revision_for(&selection, &tables, &control)?;
        assert_eq!((stopped.0.commit_revision, stopped.1), (retired, retired));
        assert_eq!(fixture.store.retire_required(&retirement)?, retired);
        let repeated = fixture
            .store
            .dependency_revision_for(&selection, &tables, &control)?;
        assert_eq!((repeated.0.commit_revision, repeated.1), (retired, retired));
        let path = fixture.store.root.clone();
        drop(fixture._graph);
        drop(fixture.store);
        let reopened = AnalysisStore::open(path)?;
        let restored = reopened.dependency_revision_for(&selection, &tables, &control)?;
        assert_eq!((restored.0.commit_revision, restored.1), (retired, retired));
        Ok(())
    }
}
