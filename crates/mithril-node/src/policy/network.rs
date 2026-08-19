use std::collections::BTreeMap;
use std::net::{Ipv4Addr, Ipv6Addr};

use erebor_interceptor_abi::{
    BindingLifecycleStateV1, NetworkDestinationClassV1, NetworkDestinationDecisionKeyV1,
    NetworkIpv4LpmKeyV1, NetworkIpv6LpmKeyV1, NetworkPortRangeV1,
    NetworkProtocolV1 as KernelNetworkProtocolV1, PhysicalDecisionV1, MAX_NETWORK_PORT_RANGES_V1,
};
use mithril_control::{
    DestinationPolicyRecordV1, EffectFamilyV1, NetworkProtocolV1, PolicyDocumentV1,
};
use snafu::ensure;
use zerocopy::IntoBytes as _;

use crate::error::IdentityStateSnafu;
use crate::Result;

use super::insert_exact;

const LPM_FIXED_PREFIX_BITS: u32 = 160;

#[derive(Default)]
pub(super) struct LoweredNetworkPolicy {
    pub(super) ipv4_classes: BTreeMap<Vec<u8>, Vec<u8>>,
    pub(super) ipv6_classes: BTreeMap<Vec<u8>, Vec<u8>>,
    pub(super) decisions: BTreeMap<Vec<u8>, Vec<u8>>,
}

pub(super) fn destination_handles(document: &PolicyDocumentV1) -> BTreeMap<String, u64> {
    document
        .network_policy
        .iter()
        .flat_map(|policy| &policy.destination_policies)
        .enumerate()
        .map(|(index, policy)| {
            (
                policy.destination_policy_id.clone(),
                u64::try_from(index).unwrap_or(u64::MAX - 1) + 1,
            )
        })
        .collect()
}

pub(super) fn lower_destination_classes(
    document: &PolicyDocumentV1,
    profile_generation_ref_id: u64,
    handles: &BTreeMap<String, u64>,
) -> Result<LoweredNetworkPolicy> {
    let mut tables = LoweredNetworkPolicy::default();
    for policy in document
        .network_policy
        .iter()
        .flat_map(|network| &network.destination_policies)
    {
        let value = destination_class(policy, handles[&policy.destination_policy_id])?;
        for protocol in &policy.protocols {
            let protocol = kernel_protocol(*protocol);
            for prefix in &policy.ipv4_prefixes {
                let (address, length) = parse_ipv4(prefix)?;
                let key = NetworkIpv4LpmKeyV1 {
                    prefix_length: LPM_FIXED_PREFIX_BITS + length,
                    reserved_alignment: 0,
                    profile_generation_ref_id,
                    protocol,
                    reserved: [0; 7],
                    address: address.octets(),
                    reserved_tail: [0; 4],
                };
                insert_exact(&mut tables.ipv4_classes, key.as_bytes(), value.as_bytes())?;
            }
            for prefix in &policy.ipv6_prefixes {
                let (address, length) = parse_ipv6(prefix)?;
                let key = NetworkIpv6LpmKeyV1 {
                    prefix_length: LPM_FIXED_PREFIX_BITS + length,
                    reserved_alignment: 0,
                    profile_generation_ref_id,
                    protocol,
                    reserved: [0; 7],
                    address: address.octets(),
                };
                insert_exact(&mut tables.ipv6_classes, key.as_bytes(), value.as_bytes())?;
            }
        }
    }
    Ok(tables)
}

#[allow(clippy::too_many_arguments)]
pub(super) fn lower_destination_decision(
    tables: &mut LoweredNetworkPolicy,
    object_selector: &str,
    family: EffectFamilyV1,
    profile_generation_ref_id: u64,
    active_role_id: u32,
    process_state_vector_id: u32,
    entry_kind: u16,
    operation: u16,
    binding_lifecycle_state: BindingLifecycleStateV1,
    handles: &BTreeMap<String, u64>,
    protocols: &[NetworkProtocolV1],
    decision: PhysicalDecisionV1,
) -> Result<bool> {
    let Some(destination_id) = object_selector.strip_prefix("DESTINATION:") else {
        return Ok(false);
    };
    ensure!(
        family == EffectFamilyV1::Network,
        IdentityStateSnafu {
            reason: "a destination selector lowered outside NETWORK".to_owned(),
        }
    );
    let destination_policy_handle = *handles.get(destination_id).ok_or_else(|| {
        IdentityStateSnafu {
            reason: format!("unknown destination policy `{destination_id}`"),
        }
        .build()
    })?;
    for protocol in protocols {
        let key = NetworkDestinationDecisionKeyV1 {
            profile_generation_ref_id,
            destination_policy_handle,
            active_role_id,
            process_state_vector_id,
            entry_kind,
            operation,
            protocol: kernel_protocol(*protocol),
            binding_lifecycle_state,
            reserved: [0; 2],
        };
        insert_exact(&mut tables.decisions, key.as_bytes(), decision.as_bytes())?;
    }
    Ok(true)
}

fn destination_class(
    policy: &DestinationPolicyRecordV1,
    destination_policy_handle: u64,
) -> Result<NetworkDestinationClassV1> {
    ensure!(
        policy.port_ranges.len() <= MAX_NETWORK_PORT_RANGES_V1,
        IdentityStateSnafu {
            reason: "network port ranges exceed the kernel ABI bound".to_owned(),
        }
    );
    let mut port_ranges = [NetworkPortRangeV1::default(); MAX_NETWORK_PORT_RANGES_V1];
    for (target, source) in port_ranges.iter_mut().zip(&policy.port_ranges) {
        *target = NetworkPortRangeV1 {
            first: source.first,
            last: source.last,
        };
    }
    Ok(NetworkDestinationClassV1 {
        destination_policy_handle,
        port_ranges,
        port_range_count: policy.port_ranges.len().try_into().map_err(|error| {
            IdentityStateSnafu {
                reason: format!("network port range count is invalid: {error}"),
            }
            .build()
        })?,
        final_address_required: u8::from(policy.final_address_required),
        reserved: [0; 6],
    })
}

const fn kernel_protocol(protocol: NetworkProtocolV1) -> KernelNetworkProtocolV1 {
    match protocol {
        NetworkProtocolV1::Tcp => KernelNetworkProtocolV1::Tcp,
        NetworkProtocolV1::Udp => KernelNetworkProtocolV1::Udp,
    }
}

fn parse_ipv4(prefix: &str) -> Result<(Ipv4Addr, u32)> {
    let (address, length) = prefix.split_once('/').ok_or_else(|| {
        IdentityStateSnafu {
            reason: format!("invalid IPv4 prefix `{prefix}`"),
        }
        .build()
    })?;
    Ok((
        address.parse().map_err(|error| {
            IdentityStateSnafu {
                reason: format!("invalid IPv4 prefix `{prefix}`: {error}"),
            }
            .build()
        })?,
        length.parse().map_err(|error| {
            IdentityStateSnafu {
                reason: format!("invalid IPv4 prefix `{prefix}`: {error}"),
            }
            .build()
        })?,
    ))
}

fn parse_ipv6(prefix: &str) -> Result<(Ipv6Addr, u32)> {
    let (address, length) = prefix.split_once('/').ok_or_else(|| {
        IdentityStateSnafu {
            reason: format!("invalid IPv6 prefix `{prefix}`"),
        }
        .build()
    })?;
    Ok((
        address.parse().map_err(|error| {
            IdentityStateSnafu {
                reason: format!("invalid IPv6 prefix `{prefix}`: {error}"),
            }
            .build()
        })?,
        length.parse().map_err(|error| {
            IdentityStateSnafu {
                reason: format!("invalid IPv6 prefix `{prefix}`: {error}"),
            }
            .build()
        })?,
    ))
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use erebor_interceptor_abi::{
        BindingLifecycleStateV1, NetworkDestinationClassV1, NetworkDestinationDecisionKeyV1,
        NetworkIpv4LpmKeyV1, PhysicalDecisionKindV1, PhysicalDecisionV1,
    };
    use mithril_control::{
        DestinationPolicyRecordV1, DnsPolicyModeV1, EffectFamilyV1, NetworkPolicyV1,
        NetworkPortRangeV1, NetworkProtocolV1, PolicyDocumentV1,
    };
    use zerocopy::TryFromBytes as _;

    use super::{
        destination_handles, lower_destination_classes, lower_destination_decision,
        LoweredNetworkPolicy,
    };

    fn network_document() -> crate::Result<PolicyDocumentV1> {
        let mut document = PolicyDocumentV1::parse(
            Path::new("policy-v1.yaml"),
            include_bytes!("../../../mithril-control/tests/fixtures/policy-v1.yaml"),
        )
        .map_err(|source| crate::Error::Policy {
            source,
            location: snafu::Location::default(),
        })?;
        document.network_policy = Some(NetworkPolicyV1 {
            dns_mode: DnsPolicyModeV1::DenyDnsAndUsePolicyResolvedAddresses,
            destination_policies: vec![DestinationPolicyRecordV1 {
                destination_policy_id: "result-service".to_owned(),
                protocols: vec![NetworkProtocolV1::Tcp],
                ipv4_prefixes: vec!["127.0.0.0/8".to_owned()],
                ipv6_prefixes: vec!["::1/128".to_owned()],
                port_ranges: vec![NetworkPortRangeV1 {
                    first: 8_443,
                    last: 8_443,
                }],
                required_network_namespace_ids: Vec::new(),
                service_identities: Vec::new(),
                final_address_required: true,
            }],
        });
        Ok(document)
    }

    #[test]
    fn destination_classes_are_generation_scoped_lpm_rows() -> crate::Result<()> {
        let document = network_document()?;
        let handles = destination_handles(&document);
        let lowered = lower_destination_classes(&document, 17, &handles)?;
        let (key, value) = lowered.ipv4_classes.first_key_value().ok_or_else(|| {
            crate::error::IdentityStateSnafu {
                reason: "network test has no IPv4 class".to_owned(),
            }
            .build()
        })?;
        let key = NetworkIpv4LpmKeyV1::try_read_from_bytes(key).map_err(|error| {
            crate::error::IdentityStateSnafu {
                reason: format!("network IPv4 key is invalid: {error}"),
            }
            .build()
        })?;
        let value = NetworkDestinationClassV1::try_read_from_bytes(value).map_err(|error| {
            crate::error::IdentityStateSnafu {
                reason: format!("network destination class is invalid: {error}"),
            }
            .build()
        })?;

        assert_eq!(key.prefix_length, 168);
        assert_eq!(key.profile_generation_ref_id, 17);
        assert_eq!(value.destination_policy_handle, 1);
        assert_eq!(value.port_ranges[0].first, 8_443);
        assert_eq!(value.final_address_required, 1);
        assert_eq!(lowered.ipv6_classes.len(), 1);
        Ok(())
    }

    #[test]
    fn destination_decisions_keep_protocol_and_actor_dimensions() -> crate::Result<()> {
        let document = network_document()?;
        let handles = destination_handles(&document);
        let mut lowered = LoweredNetworkPolicy::default();
        let decision = PhysicalDecisionV1 {
            decision: PhysicalDecisionKindV1::Deny,
            reserved: 0,
            errno: -13,
            evidence_class_id: 0,
            transition_id: 0,
            exception_numeric_handle: 0,
        };
        assert!(lower_destination_decision(
            &mut lowered,
            "DESTINATION:result-service",
            EffectFamilyV1::Network,
            17,
            19,
            23,
            2,
            26,
            BindingLifecycleStateV1::Active,
            &handles,
            &[NetworkProtocolV1::Tcp],
            decision,
        )?);
        let key = lowered.decisions.keys().next().ok_or_else(|| {
            crate::error::IdentityStateSnafu {
                reason: "network test has no destination decision".to_owned(),
            }
            .build()
        })?;
        let key = NetworkDestinationDecisionKeyV1::try_read_from_bytes(key).map_err(|error| {
            crate::error::IdentityStateSnafu {
                reason: format!("network destination decision key is invalid: {error}"),
            }
            .build()
        })?;
        assert_eq!(key.profile_generation_ref_id, 17);
        assert_eq!(key.active_role_id, 19);
        assert_eq!(key.process_state_vector_id, 23);
        assert_eq!(key.operation, 26);
        Ok(())
    }
}
