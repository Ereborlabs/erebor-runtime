use erebor_runtime_policy::{Decision, LocalPolicy};

use super::support::{context, ApproveAll, RecordingAuditSink};
use crate::{CdpEnforcementAction, CdpEventDecoder, CdpEventEnforcer, CdpEventObserver};

#[test]
fn observes_fetch_request_paused_context() -> Result<(), Box<dyn std::error::Error>> {
    let event = CdpEventDecoder::decode(
        r#"{
          "method": "Fetch.requestPaused",
          "params": {
            "requestId": "fetch-1",
            "request": {
              "url": "https://example.com/sensitive",
              "method": "GET",
              "headers": {},
              "initialPriority": "Low",
              "referrerPolicy": "no-referrer"
            },
            "frameId": "frame-1",
            "resourceType": "Document"
          }
        }"#,
    )?
    .ok_or_else(|| std::io::Error::other("missing event"))?;

    let runtime_event = CdpEventObserver::observe(&context(), &event)?;

    assert_eq!(runtime_event.id.as_str(), "fetch-1");
    assert_eq!(
        runtime_event.target.and_then(|target| target.uri),
        Some(String::from("https://example.com/sensitive"))
    );
    Ok(())
}

#[test]
fn enforces_fetch_request_paused_context() -> Result<(), Box<dyn std::error::Error>> {
    let sink = RecordingAuditSink::default();
    let policy = LocalPolicy::from_json_str(
        r#"{ "rules": [{
          "id": "deny-callback-request",
          "match": {
            "surface": "browser_cdp",
            "action": "network_request",
            "target_contains": "127.0.0.1:5105/oauth/callback"
          },
          "decision": "deny",
          "reason": "callback request denied"
        }] }"#,
    )?;
    let engine =
        erebor_runtime_core::LocalEnforcementEngine::with_hooks(policy, ApproveAll, sink.clone());
    let event = CdpEventDecoder::decode(
        r#"{
          "method": "Fetch.requestPaused",
          "params": {
            "requestId": "fetch-1",
            "request": {
              "url": "http://127.0.0.1:5105/oauth/callback?code=redacted",
              "method": "GET",
              "headers": {},
              "initialPriority": "VeryHigh",
              "referrerPolicy": "no-referrer"
            },
            "frameId": "frame-1",
            "resourceType": "Document"
          }
        }"#,
    )?
    .ok_or_else(|| std::io::Error::other("missing event"))?;

    let action = CdpEventEnforcer::enforce(&engine, &context(), &event)?;
    let records = sink.records();

    assert_eq!(
        action,
        CdpEnforcementAction::Block {
            reason: String::from("callback request denied")
        }
    );
    assert_eq!(records.len(), 1);
    assert_eq!(
        records[0].final_decision,
        Decision::Deny {
            reason: String::from("callback request denied"),
            rule_id: Some(String::from("deny-callback-request"))
        }
    );
    Ok(())
}

#[test]
fn observes_network_context_without_command_id() -> Result<(), Box<dyn std::error::Error>> {
    let event = CdpEventDecoder::decode(
        r#"{
          "method": "Network.requestWillBeSent",
          "params": {
            "requestId": "network-1",
            "loaderId": "loader-1",
            "documentURL": "https://example.com/",
            "request": {
              "url": "https://example.com/",
              "method": "GET",
              "headers": {},
              "initialPriority": "Low",
              "referrerPolicy": "no-referrer"
            },
            "timestamp": 1.0,
            "wallTime": 1.0,
            "initiator": { "type": "other" },
            "redirectHasExtraInfo": false
          }
        }"#,
    )?
    .ok_or_else(|| std::io::Error::other("missing event"))?;

    let runtime_event = CdpEventObserver::observe(&context(), &event)?;

    assert_eq!(runtime_event.id.as_str(), "network-1");
    assert_eq!(
        runtime_event.risk.reasons,
        vec![String::from(
            "inspected CDP method `Network.requestWillBeSent`"
        )]
    );
    Ok(())
}
