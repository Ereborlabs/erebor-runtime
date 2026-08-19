use std::net::{Ipv4Addr, Ipv6Addr};

use erebor_interceptor_abi::MAX_NETWORK_PORT_RANGES_V1;

use super::super::source::{DestinationPolicyRecordV1, DnsPolicyModeV1, NetworkPolicyV1};
use super::value::PolicyValue;
use super::{Validate, ValidationResult};

impl Validate for NetworkPolicyV1 {
    fn validate(&self) -> ValidationResult {
        require!(
            !self.destination_policies.is_empty()
                && self.destination_policies.len() <= 4_096
                && self
                    .destination_policies
                    .windows(2)
                    .all(|pair| { pair[0].destination_policy_id < pair[1].destination_policy_id }),
            "CFG_NETWORK_DESTINATION_SET",
            "network destination policies must be sorted, unique, and bounded"
        );
        for policy in &self.destination_policies {
            policy.validate()?;
        }
        require!(
            self.dns_mode != DnsPolicyModeV1::DenyDnsAndUsePolicyResolvedAddresses
                || self.destination_policies.iter().all(|policy| {
                    policy
                        .port_ranges
                        .iter()
                        .all(|range| !(range.first..=range.last).contains(&53))
                }),
            "CFG_NETWORK_DNS_MODE",
            "policy-resolved address mode cannot authorize DNS port 53"
        );
        Ok(())
    }
}

impl Validate for DestinationPolicyRecordV1 {
    fn validate(&self) -> ValidationResult {
        PolicyValue::LocalId(&self.destination_policy_id).validate()?;
        require!(
            !self.protocols.is_empty()
                && self.protocols.windows(2).all(|pair| pair[0] < pair[1])
                && (!self.ipv4_prefixes.is_empty() || !self.ipv6_prefixes.is_empty()),
            "CFG_NETWORK_DESTINATION_SHAPE",
            format!(
                "destination `{}` needs ordered protocols and an address prefix",
                self.destination_policy_id
            )
        );
        require!(
            ordered_prefixes(&self.ipv4_prefixes, canonical_ipv4)
                && ordered_prefixes(&self.ipv6_prefixes, canonical_ipv6),
            "CFG_NETWORK_PREFIX",
            format!(
                "destination `{}` has a non-canonical address prefix",
                self.destination_policy_id
            )
        );
        require!(
            !self.port_ranges.is_empty()
                && self.port_ranges.len() <= MAX_NETWORK_PORT_RANGES_V1
                && self
                    .port_ranges
                    .iter()
                    .all(|range| { range.first > 0 && range.first <= range.last })
                && self
                    .port_ranges
                    .windows(2)
                    .all(|pair| pair[0].last < pair[1].first),
            "CFG_NETWORK_PORT_RANGE",
            format!(
                "destination `{}` has invalid or overlapping port ranges",
                self.destination_policy_id
            )
        );
        require!(
            self.required_network_namespace_ids.is_empty(),
            "CFG_NETWORK_NAMESPACE_AUTHORITY",
            "network namespace selectors are not qualified for active policy"
        );
        require!(
            self.service_identities.is_empty(),
            "CFG_NETWORK_SERVICE_AUTHORITY",
            "service identity resolution is not qualified for active policy"
        );
        Ok(())
    }
}

fn ordered_prefixes(prefixes: &[String], canonical: impl Fn(&str) -> bool) -> bool {
    prefixes.windows(2).all(|pair| pair[0] < pair[1])
        && prefixes.iter().all(|prefix| canonical(prefix))
}

fn canonical_ipv4(value: &str) -> bool {
    let Some((address, length)) = value.split_once('/') else {
        return false;
    };
    let (Ok(address), Ok(length)) = (address.parse::<Ipv4Addr>(), length.parse::<u32>()) else {
        return false;
    };
    length <= 32 && u128::from(u32::from(address)) & host_mask(32, length) == 0
}

fn canonical_ipv6(value: &str) -> bool {
    let Some((address, length)) = value.split_once('/') else {
        return false;
    };
    let (Ok(address), Ok(length)) = (address.parse::<Ipv6Addr>(), length.parse::<u32>()) else {
        return false;
    };
    length <= 128 && u128::from(address) & host_mask(128, length) == 0
}

fn host_mask(bits: u32, prefix: u32) -> u128 {
    if prefix == 0 {
        if bits == 128 {
            u128::MAX
        } else {
            (1_u128 << bits) - 1
        }
    } else if prefix == bits {
        0
    } else {
        (1_u128 << (bits - prefix)) - 1
    }
}

#[cfg(test)]
mod tests {
    use super::{canonical_ipv4, canonical_ipv6};

    #[test]
    fn prefixes_must_name_the_canonical_network() {
        assert!(canonical_ipv4("10.0.0.0/24"));
        assert!(!canonical_ipv4("10.0.0.1/24"));
        assert!(canonical_ipv6("2001:db8::/32"));
        assert!(!canonical_ipv6("2001:db8::1/32"));
    }
}
