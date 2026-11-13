use araphor_data::{
    EvidenceIdV1, KernelEffectEvidenceV1, ObservationEnvelopeV1, TemporalCoverageV1,
};
use mithril_control::{
    AuthenticatedEvidenceNodeV1, EvidenceBatch, EvidenceIntakeIdentityV1, EvidenceIntakeOwner,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn authenticated() -> AuthenticatedEvidenceNodeV1 {
    AuthenticatedEvidenceNodeV1 {
        tenant_id: EvidenceIdV1::new(1, 2).to_be_bytes(),
        node_id: "node-a".into(),
        node_boot_id: EvidenceIdV1::new(6, 7).to_be_bytes(),
        label_epoch: 9,
    }
}

fn identity() -> EvidenceIntakeIdentityV1 {
    EvidenceIntakeIdentityV1 {
        tenant_id: authenticated().tenant_id,
        node_id: authenticated().node_id,
        node_boot_id: authenticated().node_boot_id,
        label_epoch: authenticated().label_epoch,
        source_id: EvidenceIdV1::new(3, 4).to_be_bytes(),
        source_epoch: 5,
    }
}

fn batch(cursor: u64) -> Result<EvidenceBatch, Box<dyn std::error::Error>> {
    let observation = ObservationEnvelopeV1 {
        tenant_id: EvidenceIdV1::from(identity().tenant_id),
        node_boot_id: EvidenceIdV1::from(identity().node_boot_id),
        source_id: EvidenceIdV1::from(identity().source_id),
        source_epoch: identity().source_epoch,
        source_sequence: cursor,
        cpu_id: 0,
        observed_boottime_ns: cursor,
        ingested_utc_ns: 10,
        coverage_interval_id: EvidenceIdV1::new(11, 12),
        profile_generation_ref_id: Some(8),
        temporal_coverage: TemporalCoverageV1::Complete,
        decision_context: None,
        effect: KernelEffectEvidenceV1 {
            task_cookie: 14,
            target_task_cookie: None,
            process_lineage_id: Some(EvidenceIdV1::new(15, 16)),
            authority_domain_id: Some(EvidenceIdV1::new(17, 18)),
            execution_set_id: Some(EvidenceIdV1::new(19, 20)),
            exact_object_id: Some(EvidenceIdV1::new(21, 22)),
            destination_id: None,
            policy_rule_id: Some(23),
            reason: 9,
            decision: 1,
            effect_family: 1,
            operation: 2,
            operation_argument: None,
            configured_errno: -13,
            kernel_result: -13,
        },
    };
    let framed = Vec::<u8>::try_from(&observation.to_wire_record()?)?;
    Ok(EvidenceBatch {
        node_boot_id: identity().node_boot_id.to_vec(),
        source_id: identity().source_id.to_vec(),
        source_epoch: identity().source_epoch,
        cpu_id: 0,
        first_cursor: cursor,
        framed_records: framed.into(),
        commit_group_tail: false,
    })
}

#[test]
fn collector_group_is_native_atomic_and_reopenable() -> TestResult {
    let directory = tempfile::tempdir()?;
    let intake = EvidenceIntakeOwner::open(directory.path())?;
    let batches = (1..=20)
        .map(|cursor| Ok((authenticated(), batch(cursor)?)))
        .collect::<Result<Vec<_>, Box<dyn std::error::Error>>>()?;
    let expected = batches
        .iter()
        .map(|(_, batch)| batch.framed_records.to_vec())
        .collect::<Vec<_>>();
    let ack = intake.receive_group(batches.clone())?;
    assert_eq!(ack.contiguous_cursor, 20);
    assert_eq!(intake.contiguous_cursor(&identity())?, 20);
    let data = intake.analysis_store();
    let page = data.read_page(&identity(), 1)?;
    assert_eq!(page.records.len(), 20);
    for (index, record) in page.records.iter().enumerate() {
        assert_eq!(record.cursor, index as u64 + 1);
        assert_eq!(record.framed_record, expected[index]);
        assert_eq!(
            record.position.commit_revision,
            page.records[0].position.commit_revision
        );
        assert_eq!(record.position.ordinal, index as u32);
    }
    assert_eq!(
        data.view()?
            .snapshot()
            .prefix(b"\0data/evidence/payload/")
            .count(),
        1
    );
    assert_eq!(
        std::fs::read_dir(directory.path().join("analysis/segments"))?.count(),
        0
    );
    let before = data.meta()?;
    let head = data.database().inner().journal_head()?;
    assert_eq!(intake.receive_group(batches)?.contiguous_cursor, 20);
    assert_eq!(data.meta()?, before);
    assert_eq!(data.database().inner().journal_head()?, head);
    drop((data, intake));
    let intake = EvidenceIntakeOwner::open(directory.path())?;
    assert_eq!(intake.contiguous_cursor(&identity())?, 20);
    assert_eq!(
        intake.analysis_store().read_page(&identity(), 1)?.records,
        page.records
    );
    assert_eq!(
        intake
            .analysis_store()
            .view()?
            .snapshot()
            .prefix(b"\0data/evidence/payload/")
            .count(),
        1
    );
    assert_eq!(
        std::fs::read_dir(directory.path().join("analysis/segments"))?.count(),
        0
    );
    Ok(())
}

#[test]
fn pending_group_is_durable_without_early_ack() -> TestResult {
    let directory = tempfile::tempdir()?;
    let intake = EvidenceIntakeOwner::open(directory.path())?;
    let pending = intake
        .receive(&authenticated(), batch(2)?)
        .err()
        .ok_or("pending input was acknowledged")?;
    assert_eq!(pending.code(), tonic::Code::Unavailable);
    assert_eq!(intake.contiguous_cursor(&identity())?, 0);
    let pending_payloads = intake
        .analysis_store()
        .view()?
        .snapshot()
        .prefix(b"\0data/evidence/payload/")
        .collect::<Result<Vec<_>, _>>()?;
    assert_eq!(pending_payloads.len(), 1);
    drop(intake);
    let intake = EvidenceIntakeOwner::open(directory.path())?;
    assert_eq!(intake.contiguous_cursor(&identity())?, 0);
    let reopened_payloads = intake
        .analysis_store()
        .view()?
        .snapshot()
        .prefix(b"\0data/evidence/payload/")
        .collect::<Result<Vec<_>, _>>()?;
    assert_eq!(reopened_payloads, pending_payloads);
    let ack = intake.receive(&authenticated(), batch(1)?)?;
    assert_eq!(ack.contiguous_cursor, 2);
    let page = intake.analysis_store().read_page(&identity(), 1)?;
    assert_eq!(
        page.records
            .iter()
            .map(|row| row.cursor)
            .collect::<Vec<_>>(),
        [1, 2]
    );
    assert_eq!(
        page.records[0].framed_record,
        batch(1)?.framed_records.as_ref()
    );
    assert_eq!(
        page.records[1].framed_record,
        batch(2)?.framed_records.as_ref()
    );
    assert!(page.records[0].position.commit_revision > page.records[1].position.commit_revision);
    assert_eq!(
        std::fs::read_dir(directory.path().join("analysis/segments"))?.count(),
        0
    );
    Ok(())
}
