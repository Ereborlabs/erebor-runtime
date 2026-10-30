use super::*;

#[test]
fn canonical_graph_accepts_metadata() -> TestResult {
    let fixture = CommitFixture::new()?;
    let mut snapshot = fixture.snapshot;
    snapshot.previous_result_id = None;
    snapshot.context_notice_revision = 0;
    snapshot.witness_deadline_utc_ns = 0;
    snapshot.input_positions.clear();
    let body = serde_json::to_vec(&snapshot)?;
    let prepared = CanonicalGraph::new(snapshot.clone())?;
    assert_eq!(prepared.snapshot(), &snapshot);
    let before = fixture.store.meta()?;
    snapshot.previous_result_id = Some(format!("graph:{}", "x".repeat(128)));
    snapshot.context_notice_revision = u64::MAX;
    snapshot.witness_deadline_utc_ns = u64::MAX;
    snapshot.validate()?;
    let prepared = CanonicalGraph::new(snapshot.clone())?;
    assert_eq!(fixture.store.meta()?, before);
    let final_body = serde_json::to_vec(&snapshot)?;
    assert!(final_body.len() > body.len());
    assert_eq!(prepared.snapshot(), &snapshot);
    assert_eq!(prepared.into_snapshot(), snapshot);
    Ok(())
}

#[test]
fn graph_typed_commit_rejects_metadata() -> TestResult {
    let fixture = CommitFixture::new()?;
    let before = fixture.store.meta()?;
    assert!(fixture
        .store
        .commit_graph_snapshot(
            fixture.request.clone(),
            CanonicalGraph::new(fixture.snapshot.clone())?,
            &[],
            &[],
            &[],
            true,
            || Ok(()),
        )
        .is_err());
    for fault in [0, 1, 2] {
        let mut request = fixture.request.clone();
        request.body.clear();
        match fault {
            0 => request.scope.identity.tenant_id = [99; 16],
            1 => request.witnesses[0].expires_utc_ns += 1,
            _ => request.consumed_cursor += 1,
        }
        assert!(fixture
            .store
            .commit_graph_snapshot(
                request,
                CanonicalGraph::new(fixture.snapshot.clone())?,
                &[],
                &[],
                &[],
                true,
                || Ok(()),
            )
            .is_err());
        assert_eq!(fixture.store.meta()?, before);
        assert!(fixture
            .store
            .read_result(
                fixture.request.scope.identity.tenant_id,
                &fixture.request.result_id
            )?
            .is_none());
    }
    Ok(())
}

#[test]
fn request_metadata_rejects_trailing_bytes() -> TestResult {
    use crate::analysis::graph::GraphRequestMeta;
    let fixture = CommitFixture::new()?;
    let request = &fixture.request;
    let metadata = GraphRequestMeta {
        scope: request.scope.clone(),
        expected_cursor: request.expected_cursor,
        consumed_cursor: request.consumed_cursor,
        coverage_revision: request.coverage_revision,
        captured_context_revision: request.context_revision,
        result_id: request.result_id.clone(),
        created_utc_ns: request.created_utc_ns,
        witnesses: request.witnesses.clone(),
        captured_context_refs: request.context_refs.clone(),
        context_refs: request.context_refs.clone(),
        sources: Vec::new(),
        advance: true,
        captured_prefix: false,
    };
    let encoded = metadata.encode()?;
    assert_eq!(GraphRequestMeta::decode(&encoded)?, metadata);
    let mut trailing = encoded.clone();
    trailing.push(0);
    assert!(GraphRequestMeta::decode(&trailing).is_err());
    assert!(GraphRequestMeta::decode(&encoded[..encoded.len() - 1]).is_err());
    Ok(())
}

#[test]
fn publication_after_call_uses_fresh_base() -> TestResult {
    let fixture = CommitFixture::new()?;
    let metadata = GraphManifest::from_snapshot(&fixture.snapshot);
    let source = &metadata.scope.identity;
    let writer = Connection::open_in_memory()?;
    writer.execute_batch(&GraphRows::schema())?;
    writer.execute_batch(
        "CREATE TABLE source_receipts(stream_key BLOB,tenant_id BLOB,cpu_id UINTEGER)",
    )?;
    writer.execute(
        "INSERT INTO source_receipts VALUES(?,?,?)",
        params![
            source.key(),
            source.tenant_id.as_slice(),
            metadata.input_manifest.evidence[0].cpu_id
        ],
    )?;
    let source_ref = GraphRows::source_id(&writer, source)?;
    writer.execute("INSERT INTO graph_producer_scopes VALUES(9999,?,?,0,'instance',1,'package','revision','image',1,1)",params![source.tenant_id.as_slice(),source_ref])?;
    GraphRows::version(&writer, "call-result", 9999, 1, None)?;
    let (scope, base) = GraphRows::publication_scope(
        &writer,
        &metadata,
        source_ref,
        1,
        Some("managed-graph:publication"),
        2,
    )?;
    assert_ne!(scope, 9999);
    assert!(base.is_none());
    GraphRows::version(&writer, "direct-result", scope, 2, base.as_deref())?;
    assert!(GraphRows::version(&writer, "wrong-scope", scope, 3, Some("call-result")).is_err());
    assert!(GraphRows::version(&writer, "missing-base", scope, 3, None).is_err());
    GraphRows::version(&writer, "continued-direct", scope, 3, Some("direct-result"))?;
    assert!(GraphRows::version(&writer, "stale-base", scope, 4, Some("direct-result")).is_err());
    Ok(())
}

#[test]
fn native_input_values_reject_foreign_records() -> TestResult {
    let fixture = CommitFixture::new()?;
    let mut metadata = GraphManifest::from_snapshot(&fixture.snapshot);
    metadata.facts.push(crate::GraphFactV1 {
        record_id: metadata.input_manifest.evidence[0].clone(),
        value: crate::GraphFactValueV1::Baseline {
            role_id: 1,
            state_id: 1,
            outside_reviewed_baseline: true,
            reviewed_policy_revision: "policy:1".into(),
        },
    });
    metadata.validate()?;
    metadata.facts[0].record_id.cpu_id += 1;
    assert!(metadata.validate().is_err());
    metadata.facts[0].record_id = metadata.input_manifest.evidence[0].clone();
    metadata.facts[0].record_id.stream.tenant_id[0] ^= 1;
    assert!(metadata.validate().is_err());
    let mut branch = fixture.snapshot.graph.branches[0].clone();
    GraphRows::check_branch(&branch, fixture.snapshot.scope.identity.tenant_id)?;
    branch.evidence[0].stream.tenant_id[0] ^= 1;
    assert!(GraphRows::check_branch(&branch, fixture.snapshot.scope.identity.tenant_id).is_err());
    Ok(())
}

#[test]
fn sparse_subject_keeps_earliest_local_anchor() -> TestResult {
    use super::super::{calls::CallBasis, history::Member, stage::GraphStage};
    let fixture = CommitFixture::new()?;
    let mut metadata = GraphManifest::from_snapshot(&fixture.snapshot);
    let later_observed = metadata.input_manifest.evidence[0].clone();
    let mut earlier_observed = later_observed.clone();
    earlier_observed.durable_cursor += 1;
    metadata.input_manifest.evidence = vec![later_observed.clone(), earlier_observed.clone()];
    let observation = |id| Observation {
        id,
        position: Position {
            commit_revision: 1,
            ordinal: 0,
        },
        effect: crate::DiscoveryEffectKeyV1 {
            task_cookie: 0,
            target_task_cookie: None,
            process_lineage_id: Vec::new(),
            authority_domain_id: Vec::new(),
            execution_set_id: Vec::new(),
            exact_object_id: Vec::new(),
            destination_id: 0,
            policy_rule_id: 0,
            reason: 0,
            decision: 0,
            effect_family: 0,
            operation: 0,
            operation_argument: None,
            configured_errno: 0,
            kernel_result: 0,
            exact_file_object: None,
        },
        ingested_utc_ns: 1,
        observed_boottime_ns: 1,
        profile_generation_ref_id: None,
        original_kernel_sequence: None,
        coverage_interval_id: Vec::new(),
        process_instance_id: None,
        entry_instance_id: None,
        binding_id: None,
        role_id: None,
        state_id: None,
        entry_rule_id: None,
        proof_quality: fixture.snapshot.graph.edges[0].proof_quality,
    };
    let input = |data| sdk::Input {
        data,
        revision: sdk::Revision {
            owner: "graph".into(),
            id: "1".into(),
            window: None,
        },
        coverage: sdk::Coverage {
            state: sdk::CoverageState::Complete,
            limits: Vec::new(),
        },
    };
    let evaluation = sdk::Evaluation {
        export: "evaluate".into(),
        inputs: vec![
            input(Observation::encode(&[
                observation(earlier_observed.clone()),
                observation(later_observed.clone()),
            ])?),
            input(Fact::encode(&[])?),
        ],
        parameters: None,
        context: sdk::EvaluationContext {
            id: "anchor".into(),
            time_utc_ns: 1,
            seed: None,
        },
        checkpoint: None,
        previous_outputs: Vec::new(),
    };
    let basis = CallBasis::new(&evaluation)?;
    let writer = Connection::open_in_memory()?;
    writer.execute_batch(&GraphRows::schema())?;
    writer.execute_batch(
        "CREATE TABLE source_receipts(stream_key BLOB,tenant_id BLOB,cpu_id UINTEGER)",
    )?;
    writer.execute(
        "INSERT INTO source_receipts VALUES(?,?,?)",
        params![
            metadata.scope.identity.key(),
            metadata.scope.identity.tenant_id.as_slice(),
            later_observed.cpu_id
        ],
    )?;
    let source = GraphRows::source_id(&writer, &metadata.scope.identity)?;
    let scope = GraphRows::new_scope(&writer, &metadata, source, 1, None, 1)?;
    let records = GraphRows::intern_records(
        &writer,
        &metadata.scope.identity,
        &metadata.input_manifest.evidence,
    )?;
    let subject = fixture.snapshot.graph.subjects[0].clone();
    let value = GraphRows::intern_subjects(&writer, std::slice::from_ref(&subject))?[&subject];
    let member = |record| -> Result<Member> {
        Ok(Member {
            kind: MemberKind::Subject,
            key: GraphRows::member_key(&subject)?,
            value,
            anchor: Some(Anchor { record, fact: None }),
            reason: None,
            ordinal: 0,
        })
    };
    for (revision, result, base, anchor, sparse) in [
        (1, "first", None, later_observed.clone(), false),
        (2, "earlier", Some("first"), earlier_observed.clone(), true),
        (3, "later", Some("earlier"), later_observed, true),
    ] {
        GraphRows::version(&writer, result, scope, revision, base)?;
        GraphStage {
            writer: &writer,
            scope,
            revision,
            records: &records,
            basis: Some(&basis),
            sparse,
            full: false,
        }
        .apply(vec![member(anchor)?], Vec::new(), None)?;
    }
    let (anchor,count):(u64,u64)=writer.query_row("SELECT anchor_record_id,(SELECT count(*) FROM graph_producer_members WHERE scope_id=?) FROM graph_producer_members WHERE scope_id=? AND valid_to IS NULL",params![scope,scope],|row|Ok((row.get(0)?,row.get(1)?)))?;
    assert_eq!(anchor, records[&earlier_observed]);
    assert_eq!(count, 2);
    assert_eq!(
        writer.query_row(
            "SELECT subject_count FROM graph_producer_versions WHERE result_id='later'",
            [],
            |row| row.get::<_, u64>(0)
        )?,
        1
    );
    Ok(())
}

#[test]
fn expiry_metadata_and_selected_values_keep_exact_state() -> TestResult {
    let fixture = CommitFixture::new()?;
    let mut request = fixture.request.clone();
    request.body.clear();
    let receipt = fixture.store.commit_graph_snapshot(
        request,
        CanonicalGraph::new(fixture.snapshot.clone())?,
        &[],
        &[],
        &[],
        true,
        || Ok(()),
    )?;
    let tenant = fixture.snapshot.scope.identity.tenant_id;
    let mut writer = fixture.store.writer_access()?;
    let transaction = writer.get_mut()?.transaction()?;
    let mut gapped = fixture.snapshot.clone();
    gapped.previous_result_id = Some(fixture.request.result_id.clone());
    gapped.missing_ranges = vec![(gapped.first_cursor, gapped.last_cursor)];
    gapped.input_manifest.missing_ranges = gapped.missing_ranges.clone();
    let gapped_ref = PackageResultRefV1 {
        result_id: "gapped".into(),
        commit_revision: receipt.commit_revision + 1,
    };
    let insert = |id: &str, revision: u64| -> TestResult {
        transaction.execute("INSERT INTO analysis_results SELECT * REPLACE (? AS result_id,? AS commit_revision) FROM analysis_results WHERE result_id=?",params![id,revision,fixture.request.result_id])?;
        Ok(())
    };
    insert(&gapped_ref.result_id, gapped_ref.commit_revision)?;
    NativeRows::insert(&gapped, &transaction, &gapped_ref.result_id)?;
    let metadata =
        GraphRows::read_metadata_control(&transaction, tenant, &gapped_ref.result_id, None)?
            .ok_or("missing gapped header")?;
    assert!(!metadata.expired);
    assert!(metadata.snapshot.findings.is_empty());
    let expired_ref = PackageResultRefV1 {
        result_id: "expired".into(),
        commit_revision: gapped_ref.commit_revision + 1,
    };
    insert(&expired_ref.result_id, expired_ref.commit_revision)?;
    let mut expired = GraphManifest::from_snapshot(&gapped);
    expired.previous_result_id = Some(gapped_ref.result_id.clone());
    assert!(GraphRows::commit(
        &transaction,
        &expired_ref,
        &expired,
        GraphWrite::Expiry(&gapped_ref)
    )
    .is_err());
    for package in &mut expired.packages {
        package.state = GraphPackageStateV1::CoverageInsufficient;
    }
    let mut changed = expired.clone();
    changed.witness_deadline_utc_ns += 1;
    assert!(matches!(
        GraphRows::commit(
            &transaction,
            &expired_ref,
            &changed,
            GraphWrite::Expiry(&gapped_ref)
        ),
        Err(crate::Error::GraphInvalid {
            field: "graph expiry metadata",
            ..
        })
    ));
    assert!(!transaction.query_row(
        "SELECT EXISTS(SELECT 1 FROM graph_versions WHERE result_id=?)",
        params![expired_ref.result_id],
        |row| row.get::<_, bool>(0)
    )?);
    let body = GraphRows::commit(
        &transaction,
        &expired_ref,
        &expired,
        GraphWrite::Expiry(&gapped_ref),
    )?;
    transaction.execute(
        "UPDATE analysis_results SET body=? WHERE result_id=?",
        params![body, expired_ref.result_id],
    )?;
    let header =
        GraphRows::read_metadata_control(&transaction, tenant, &expired_ref.result_id, None)?
            .ok_or("missing expired header")?;
    assert!(header.expired);
    let full = GraphRows::read(&transaction, &expired_ref.result_id, &header)?;
    assert!(full.findings.iter().all(|finding| finding.state
        == FindingStateV1::CoverageInsufficient
        && finding
            .effects
            .iter()
            .all(|effect| effect.proof_quality.temporal_coverage == TemporalCoverageV1::Unknown)));
    assert!(full
        .graph
        .edges
        .iter()
        .all(|edge| edge.key.cause == GraphCauseV1::Superseded
            && edge.proof_quality.temporal_coverage == TemporalCoverageV1::Unknown));
    assert_eq!(full.graph.branches.len(), gapped.graph.branches.len());
    let finding = &gapped.findings[0].finding_id;
    let prior_value: u64 = transaction.query_row(
        "SELECT value_id FROM graph_findings WHERE result_id=? AND finding_id=?",
        params![gapped_ref.result_id, finding],
        |row| row.get(0),
    )?;
    transaction.execute("UPDATE graph_producer_members SET value_ref=? WHERE member_kind=4 AND scope_id IN (SELECT v.scope_id FROM graph_result_producers b JOIN graph_producer_versions v ON v.result_id=b.producer_result_id JOIN graph_producer_scopes s USING(scope_id) WHERE b.result_id=? AND s.producer_kind=1) AND member_key=?",params![prior_value,expired_ref.result_id,GraphRows::member_key(finding)?])?;
    assert!(matches!(
        GraphRows::read_finding(&transaction, &expired_ref.result_id, finding, &header, None),
        Err(crate::Error::GraphInvalid {
            field: "graph expired finding value",
            ..
        })
    ));
    Ok(())
}

#[test]
fn complete_producer_replacement_keeps_history_and_unchanged_rows() -> TestResult {
    use super::super::{history::Member, stage::GraphStage};
    let fixture = CommitFixture::new()?;
    let metadata = GraphManifest::from_snapshot(&fixture.snapshot);
    let mut writer = Connection::open_in_memory()?;
    writer.execute_batch(&GraphRows::schema())?;
    writer.execute_batch(
        "CREATE TABLE source_receipts(stream_key BLOB,tenant_id BLOB,cpu_id UINTEGER)",
    )?;
    writer.execute(
        "INSERT INTO source_receipts VALUES(?,?,?)",
        params![
            metadata.scope.identity.key(),
            metadata.scope.identity.tenant_id.as_slice(),
            metadata.input_manifest.evidence[0].cpu_id
        ],
    )?;
    let source = GraphRows::source_id(&writer, &metadata.scope.identity)?;
    let scope = GraphRows::new_scope(&writer, &metadata, source, 1, None, 1)?;
    let records = GraphRows::intern_records(
        &writer,
        &metadata.scope.identity,
        &metadata.input_manifest.evidence,
    )?;
    let keys = &fixture.snapshot.graph.subjects[..2];
    let subjects = GraphRows::intern_subjects(&writer, keys)?;
    let members = |keys: &[GraphSubjectKeyV1]| -> Result<Vec<Member>> {
        keys.iter()
            .map(|key| {
                Ok(Member {
                    kind: MemberKind::Subject,
                    key: GraphRows::member_key(key)?,
                    value: subjects[key],
                    anchor: Some(Anchor {
                        record: metadata.input_manifest.evidence[0].clone(),
                        fact: None,
                    }),
                    reason: None,
                    ordinal: 0,
                })
            })
            .collect()
    };
    for (revision, result, base, keys) in [
        (1, "complete-first", None, keys),
        (2, "complete-same", Some("complete-first"), keys),
        (3, "complete-removed", Some("complete-same"), &keys[..1]),
    ] {
        GraphRows::version(&writer, result, scope, revision, base)?;
        GraphStage {
            writer: &writer,
            scope,
            revision,
            records: &records,
            basis: None,
            sparse: false,
            full: true,
        }
        .apply(members(keys)?, Vec::new(), None)?;
    }
    assert_eq!(
        writer.query_row(
            "SELECT count(*) FROM graph_producer_members WHERE scope_id=?",
            params![scope],
            |row| row.get::<_, u64>(0)
        )?,
        2
    );
    for (revision, count) in [(1, 2), (2, 2), (3, 1)] {
        assert_eq!(writer.query_row("SELECT count(*) FROM graph_producer_members WHERE scope_id=? AND valid_from<=? AND (valid_to IS NULL OR valid_to>?)",params![scope,revision,revision],|row|row.get::<_,u64>(0))?,count);
    }
    assert_eq!(
        writer.query_row(
            "SELECT valid_from FROM graph_producer_members WHERE scope_id=? AND valid_to IS NULL",
            params![scope],
            |row| row.get::<_, u64>(0)
        )?,
        1
    );
    assert_eq!(
        writer.query_row(
            "SELECT subject_count FROM graph_producer_versions WHERE result_id='complete-removed'",
            [],
            |row| row.get::<_, u64>(0)
        )?,
        1
    );
    {
        let transaction = writer.transaction()?;
        GraphRows::version(
            &transaction,
            "complete-corrupt",
            scope,
            4,
            Some("complete-removed"),
        )?;
        transaction.execute(
            "UPDATE graph_producer_members SET member_key=? WHERE scope_id=? AND valid_to IS NULL",
            params![vec![0u8; 32], scope],
        )?;
        assert!(matches!(
            GraphStage {
                writer: &transaction,
                scope,
                revision: 4,
                records: &records,
                basis: None,
                sparse: false,
                full: true
            }
            .apply(members(&keys[..1])?, Vec::new(), None),
            Err(crate::Error::GraphInvalid {
                field: "graph member identity collision",
                ..
            })
        ));
    }
    assert_eq!(
        writer.query_row(
            "SELECT count(*) FROM graph_producer_members WHERE scope_id=?",
            params![scope],
            |row| row.get::<_, u64>(0)
        )?,
        2
    );
    Ok(())
}
