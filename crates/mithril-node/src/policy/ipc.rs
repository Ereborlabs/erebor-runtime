use std::collections::BTreeMap;

use erebor_interceptor_abi::{IpcChannelKindV1, IpcOperationV1, IpcRelationshipDecisionKeyV1};
use mithril_control::{
    CompiledPhysicalResultV1, ErrnoV1, PolicyDispositionV1, PolicyDocumentV1, ProfileModeV1,
};
use snafu::ensure;
use zerocopy::IntoBytes as _;

use crate::error::IdentityStateSnafu;
use crate::Result;

use super::{insert_exact, physical_decision};

const UNIX_STREAM_OPERATIONS: [IpcOperationV1; 3] = [
    IpcOperationV1::Connect,
    IpcOperationV1::Send,
    IpcOperationV1::Receive,
];

pub(super) fn lower_ipc_relationships(
    document: &PolicyDocumentV1,
    profile_generation_ref_id: u64,
    role_handles: &BTreeMap<String, u32>,
    mode: ProfileModeV1,
) -> Result<BTreeMap<Vec<u8>, Vec<u8>>> {
    let mut rows = BTreeMap::new();
    for relationship in &document.ipc_relationship_rules {
        ensure!(
            relationship.channel_class_ids == ["UNIX_STREAM"]
                && relationship.operations == ["IPC_ACCESS"]
                && relationship.requested_disposition != PolicyDispositionV1::Reject
                && (relationship.requested_disposition == PolicyDispositionV1::Deny)
                    == relationship.errno.is_some(),
            IdentityStateSnafu {
                reason: format!(
                    "IPC relationship `{}` must use the UNIX_STREAM IPC_ACCESS surface and an errno only for DENY",
                    relationship.relationship_rule_id
                ),
            }
        );
        let decision = relationship_decision(
            relationship.requested_disposition,
            relationship.errno.map(mithril_control::ErrnoV1::negative),
            mode,
        )?;
        for source in &relationship.source_role_ids {
            let source = role_handle(role_handles, source)?;
            for peer in &relationship.peer_role_ids {
                let peer = role_handle(role_handles, peer)?;
                insert_relationship_rows(
                    &mut rows,
                    profile_generation_ref_id,
                    source,
                    peer,
                    decision,
                )?;
                if source != peer {
                    insert_relationship_rows(
                        &mut rows,
                        profile_generation_ref_id,
                        peer,
                        source,
                        decision,
                    )?;
                }
            }
        }
    }

    let unmatched = relationship_decision(
        document.unmatched_ipc_disposition,
        (document.unmatched_ipc_disposition == PolicyDispositionV1::Deny)
            .then_some(ErrnoV1::Eacces.negative()),
        mode,
    )?;
    for role in role_handles.values().copied() {
        insert_relationship_rows(&mut rows, profile_generation_ref_id, role, 0, unmatched)?;
    }
    Ok(rows)
}

fn role_handle(role_handles: &BTreeMap<String, u32>, role: &str) -> Result<u32> {
    role_handles.get(role).copied().ok_or_else(|| {
        IdentityStateSnafu {
            reason: format!("IPC relationship references unknown role `{role}`"),
        }
        .build()
    })
}

fn relationship_decision(
    disposition: PolicyDispositionV1,
    errno: Option<i16>,
    mode: ProfileModeV1,
) -> Result<erebor_interceptor_abi::PhysicalDecisionV1> {
    let result = match disposition {
        PolicyDispositionV1::Allow => CompiledPhysicalResultV1::AllowEffect,
        PolicyDispositionV1::Alert => CompiledPhysicalResultV1::AuditAllowEffect,
        PolicyDispositionV1::Deny => match mode {
            ProfileModeV1::Observe => CompiledPhysicalResultV1::SimulatablePolicyDeny,
            ProfileModeV1::Protect => CompiledPhysicalResultV1::DenyEffect,
        },
        PolicyDispositionV1::Reject => {
            return IdentityStateSnafu {
                reason: "IPC relationship cannot use a remote-admission REJECT result",
            }
            .fail()
        }
    };
    Ok(physical_decision(result, errno, 0))
}

fn insert_relationship_rows(
    rows: &mut BTreeMap<Vec<u8>, Vec<u8>>,
    profile_generation_ref_id: u64,
    actor_role_id: u32,
    peer_role_id: u32,
    decision: erebor_interceptor_abi::PhysicalDecisionV1,
) -> Result<()> {
    for operation in UNIX_STREAM_OPERATIONS {
        let key = IpcRelationshipDecisionKeyV1 {
            actor_profile_generation_ref_id: profile_generation_ref_id,
            actor_role_id,
            peer_role_id,
            channel_kind: IpcChannelKindV1::UnixStream,
            operation,
            reserved: [0; 6],
        };
        insert_exact(rows, key.as_bytes(), decision.as_bytes())?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use erebor_interceptor_abi::{
        IpcChannelKindV1, IpcOperationV1, IpcRelationshipDecisionKeyV1, PhysicalDecisionKindV1,
    };
    use mithril_control::{
        ErrnoV1, IpcRelationshipRuleV1, PolicyCompiler, PolicyDispositionV1, PolicyDocumentV1,
        ProfileModeV1,
    };
    use zerocopy::IntoBytes as _;

    use super::{super::handles, lower_ipc_relationships};

    #[test]
    fn one_denial_lowers_both_directions_and_a_deny_default() -> crate::Result<()> {
        let mut document = fixture()?;
        document.ipc_relationship_rules.push(relationship(
            PolicyDispositionV1::Deny,
            Some(ErrnoV1::Eacces),
        ));
        PolicyCompiler
            .compile(&document)
            .map_err(|source| crate::Error::Policy {
                source,
                location: snafu::Location::default(),
            })?;
        let roles = handles(document.roles.iter().map(|role| role.role_id.as_str()));
        let rows = lower_ipc_relationships(&document, 7, &roles, ProfileModeV1::Protect)?;

        assert_eq!(rows.len(), 12);
        for (actor, peer) in [(1, 2), (2, 1)] {
            let key = key(actor, peer, IpcOperationV1::Send);
            assert_eq!(rows[&key][0], PhysicalDecisionKindV1::Deny as u8);
        }
        let unmatched = &rows[&key(1, 0, IpcOperationV1::Connect)];
        assert_eq!(unmatched[0], PhysicalDecisionKindV1::Deny as u8);
        assert_eq!(
            i16::from_ne_bytes([unmatched[2], unmatched[3]]),
            ErrnoV1::Eacces.negative()
        );
        Ok(())
    }

    #[test]
    fn positive_relationships_lower_both_directions() -> crate::Result<()> {
        for (disposition, expected) in [
            (PolicyDispositionV1::Allow, PhysicalDecisionKindV1::Allow),
            (
                PolicyDispositionV1::Alert,
                PhysicalDecisionKindV1::AuditAllow,
            ),
        ] {
            let mut document = fixture()?;
            document
                .ipc_relationship_rules
                .push(relationship(disposition, None));
            PolicyCompiler
                .compile(&document)
                .map_err(|source| crate::Error::Policy {
                    source,
                    location: snafu::Location::default(),
                })?;
            let roles = handles(document.roles.iter().map(|role| role.role_id.as_str()));
            let rows = lower_ipc_relationships(&document, 7, &roles, ProfileModeV1::Protect)?;

            for (actor, peer) in [(1, 2), (2, 1)] {
                for operation in [
                    IpcOperationV1::Connect,
                    IpcOperationV1::Send,
                    IpcOperationV1::Receive,
                ] {
                    assert_eq!(rows[&key(actor, peer, operation)][0], expected as u8);
                }
            }
        }
        Ok(())
    }

    #[test]
    fn relationship_errno_is_present_only_for_deny() -> crate::Result<()> {
        for (disposition, errno) in [
            (PolicyDispositionV1::Allow, Some(ErrnoV1::Eacces)),
            (PolicyDispositionV1::Alert, Some(ErrnoV1::Eacces)),
            (PolicyDispositionV1::Deny, None),
            (PolicyDispositionV1::Reject, None),
        ] {
            let mut document = fixture()?;
            document
                .ipc_relationship_rules
                .push(relationship(disposition, errno));
            let roles = handles(document.roles.iter().map(|role| role.role_id.as_str()));

            assert!(PolicyCompiler.compile(&document).is_err());
            assert!(lower_ipc_relationships(&document, 7, &roles, ProfileModeV1::Protect).is_err());
        }
        Ok(())
    }

    #[test]
    fn one_role_relationship_is_inserted_once() -> crate::Result<()> {
        let mut document = fixture()?;
        let mut relationship = relationship(PolicyDispositionV1::Allow, None);
        relationship.peer_role_ids = relationship.source_role_ids.clone();
        document.ipc_relationship_rules.push(relationship);
        let roles = handles(document.roles.iter().map(|role| role.role_id.as_str()));

        let rows = lower_ipc_relationships(&document, 7, &roles, ProfileModeV1::Protect)?;
        assert_eq!(rows.len(), 9);
        assert_eq!(
            rows[&key(1, 1, IpcOperationV1::Connect)][0],
            PhysicalDecisionKindV1::Allow as u8
        );
        Ok(())
    }

    fn fixture() -> crate::Result<PolicyDocumentV1> {
        PolicyDocumentV1::parse(
            Path::new("policy-v1.yaml"),
            include_bytes!("../../../mithril-control/tests/fixtures/policy-v1.yaml"),
        )
        .map_err(|source| crate::Error::Policy {
            source,
            location: snafu::Location::default(),
        })
    }

    fn relationship(
        requested_disposition: PolicyDispositionV1,
        errno: Option<ErrnoV1>,
    ) -> IpcRelationshipRuleV1 {
        IpcRelationshipRuleV1 {
            relationship_rule_id: "worker-external-control".to_owned(),
            source_role_ids: vec!["converter".to_owned()],
            peer_role_ids: vec!["runtime-external".to_owned()],
            channel_class_ids: vec!["UNIX_STREAM".to_owned()],
            operations: vec!["IPC_ACCESS".to_owned()],
            requested_disposition,
            errno,
        }
    }

    fn key(actor_role_id: u32, peer_role_id: u32, operation: IpcOperationV1) -> Vec<u8> {
        IpcRelationshipDecisionKeyV1 {
            actor_profile_generation_ref_id: 7,
            actor_role_id,
            peer_role_id,
            channel_kind: IpcChannelKindV1::UnixStream,
            operation,
            reserved: [0; 6],
        }
        .as_bytes()
        .to_vec()
    }
}
