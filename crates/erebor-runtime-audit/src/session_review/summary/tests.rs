use erebor_runtime_events::ActionKind;
use erebor_runtime_policy::Decision;

use crate::session_review::{
    test_support::{browser_record, process_record},
    SessionReviewArtifacts, SessionSummaryBuilder,
};

#[test]
fn session_list_groups_records_by_session() -> Result<(), Box<dyn std::error::Error>> {
    let records = vec![
        browser_record(
            "session-1",
            "allow-nav",
            ActionKind::BrowserNavigate,
            "https://example.test",
            Decision::Allow { rule_id: None },
            "2026-06-21T18:00:00Z",
        ),
        process_record(
            "session-1",
            "deny-process",
            "sh --remote-debugging-port=9222",
            Decision::Deny {
                reason: String::from("raw CDP denied"),
                rule_id: Some(String::from("deny-raw-cdp")),
            },
            "2026-06-21T18:00:01Z",
        ),
        process_record(
            "session-2",
            "allow-process",
            "grep oauth logs",
            Decision::Allow { rule_id: None },
            "2026-06-21T18:01:00Z",
        ),
    ];

    let artifacts = SessionReviewArtifacts::new(Some(String::from("linux-host")));
    let summaries = SessionSummaryBuilder::new(&records, &artifacts).build_all()?;

    assert_eq!(summaries.len(), 2);
    assert_eq!(summaries[0].session_id, "session-2");
    assert_eq!(summaries[1].session_id, "session-1");
    assert_eq!(summaries[1].allowed, 1);
    assert_eq!(summaries[1].denied, 1);
    assert_eq!(summaries[1].max_risk, "high");
    Ok(())
}
