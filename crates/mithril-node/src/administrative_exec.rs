use std::fs;

use erebor_interceptor::{AdministrativeSlotCancelResult, KernelHost};
use erebor_interceptor_abi::{
    ApprovedExecSlotKeyV1, ApprovedExecSlotV1, BoundedAdministrativeArgvV1, ExternalRootClassV1,
    Id128V1,
};
use snafu::{ensure, ResultExt as _};
use zerocopy::TryFromBytes as _;

use crate::error::{AuthorizationSnafu, IoSnafu};
use crate::policy::{current_boottime_ns, current_utc_ns, ResolvedAdministrativePolicyV1};
use crate::{
    AdministrativeAuthorizationConfig, AdministrativeBindingTargetV1, AuthorizationProofOwner,
    AuthorizationTargetV1, IssuerTrustV1, NodePolicyGenerationOwner, Result, TrustBundleV1,
    WorkloadBindingOwner,
};

pub(crate) const ADMINISTRATIVE_EXEC_INTENT_KIND_V1: u8 = 8;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct AdministrativeResolveRequestV1 {
    pub namespace: Vec<u8>,
    pub pod_uid: Vec<u8>,
    pub container_name: Vec<u8>,
    pub full_container_id: Vec<u8>,
    pub container_generation: u64,
    pub argv: Vec<Vec<u8>>,
    pub stream_flags: u8,
    pub approved_role_id: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct AdministrativeResolutionV1 {
    pub target: AdministrativeBindingTargetV1,
    pub arguments: Vec<Vec<u8>>,
    pub stream_flags: u8,
    pub approved_role_id: String,
    pub policy: ResolvedAdministrativePolicyV1,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct AdministrativeSlotReceiptV1 {
    pub proof_id: Id128V1,
    pub claim_slot_id: Id128V1,
    pub binding_id: Id128V1,
}

pub(crate) struct AdministrativeExecOwner {
    node_id: Id128V1,
    cluster_uid: Id128V1,
    tenant_id: Id128V1,
    trust_domain_id: Id128V1,
    issuer_id: Id128V1,
    proof: AuthorizationProofOwner,
}

impl AdministrativeExecOwner {
    pub(crate) fn load(
        config: &AdministrativeAuthorizationConfig,
        state_directory: &std::path::Path,
        node_id: Id128V1,
        node_boot_id: Id128V1,
    ) -> Result<Self> {
        let tenant_id = parse_id("tenant_id", &config.tenant_id)?;
        let cluster_uid = parse_id("cluster_uid", &config.cluster_uid)?;
        let trust_domain_id = parse_id("trust_domain_id", &config.trust_domain_id)?;
        let issuer_id = parse_id("issuer_id", &config.issuer_id)?;
        let public_key = read_public_key(&config.public_key_path)?;
        let trust = TrustBundleV1 {
            trust_domain_id,
            bundle_generation: 1,
            maximum_clock_skew_ns: config.maximum_clock_skew_ns,
            replay_window_size: 4096,
            issuers: vec![IssuerTrustV1 {
                issuer_id,
                key_id: config.key_id.as_bytes().to_vec(),
                public_key,
                sequence_epoch: config.sequence_epoch,
                valid_from_utc_ns: config.valid_from_utc_ns,
                valid_until_utc_ns: config.valid_until_utc_ns,
                revoked_at_utc_ns: None,
                allowed_intent_kinds: vec![ADMINISTRATIVE_EXEC_INTENT_KIND_V1],
                allowed_tenant_ids: vec![tenant_id],
            }],
        };
        Ok(Self {
            node_id,
            cluster_uid,
            tenant_id,
            trust_domain_id,
            issuer_id,
            proof: AuthorizationProofOwner::load(state_directory, node_id, node_boot_id, trust)?,
        })
    }

    #[must_use]
    pub(crate) const fn node_id(&self) -> Id128V1 {
        self.node_id
    }

    pub(crate) fn resolve(
        &self,
        host: &KernelHost,
        bindings: &WorkloadBindingOwner,
        policy: &NodePolicyGenerationOwner,
        request: AdministrativeResolveRequestV1,
    ) -> Result<AdministrativeResolutionV1> {
        ensure!(
            request.stream_flags & !0x0f == 0,
            AuthorizationSnafu {
                reason: "administrative stream flags contain unallocated bits",
            }
        );
        BoundedAdministrativeArgvV1::from_arguments(&request.argv).ok_or_else(|| {
            AuthorizationSnafu {
                reason: "administrative argv is empty, truncated, over-limit, or contains NUL"
                    .to_owned(),
            }
            .build()
        })?;
        let target = bindings.administrative_target(
            &request.namespace,
            &request.pod_uid,
            &request.container_name,
            &request.full_container_id,
            request.container_generation,
        )?;
        let policy = policy.resolve_administrative_policy(
            host,
            &target,
            &request.argv[0],
            &request.approved_role_id,
        )?;
        Ok(AdministrativeResolutionV1 {
            target,
            arguments: request.argv,
            stream_flags: request.stream_flags,
            approved_role_id: request.approved_role_id,
            policy,
        })
    }

    pub(crate) fn verify_and_arm(
        &mut self,
        host: &KernelHost,
        bindings: &WorkloadBindingOwner,
        policy: &NodePolicyGenerationOwner,
        envelope: &[u8],
        body_sha256: [u8; 32],
    ) -> Result<AdministrativeSlotReceiptV1> {
        let proof = self.proof.verify_and_accept(
            envelope,
            AuthorizationTargetV1 {
                tenant_id: self.tenant_id,
                trust_domain_id: self.trust_domain_id,
                issuer_id: self.issuer_id,
                intent_kind: ADMINISTRATIVE_EXEC_INTENT_KIND_V1,
                body_sha256,
            },
            current_utc_ns()?,
            current_boottime_ns()?,
        )?;
        let signed = proof.administrative_exec();
        ensure!(
            signed.cluster_uid == self.cluster_uid
                && signed.authenticated_requester_principal_id
                    == signed.authenticated_approver_principal_id,
            AuthorizationSnafu {
                reason: "administrative approval must use this cluster and the authenticated self-approver",
            }
        );
        let target = bindings.administrative_target(
            &signed.namespace,
            &signed.pod_uid,
            &signed.container_name,
            &signed.full_container_id,
            signed.container_generation,
        )?;
        ensure!(
            target.profile_id == signed.profile.profile_id && target.profile_generation_ref_id > 0,
            AuthorizationSnafu {
                reason: "signed administrative profile differs from the live binding",
            }
        );
        let arguments = bounded_arguments(&signed.approved_argv)?;
        let live_policy = policy.resolve_administrative_policy(
            host,
            &target,
            &arguments[0],
            &signed.approved_role_id,
        )?;
        ensure!(
            signed.profile == live_policy.profile
                && signed.resolved_executable == live_policy.resolved_executable,
            AuthorizationSnafu {
                reason: "signed administrative executable or profile changed before arming",
            }
        );
        let key = ApprovedExecSlotKeyV1 {
            node_boot_id: self.proof.node_boot_id(),
            cgroup_binding_id: target.binding_id,
        };
        let slot = ApprovedExecSlotV1 {
            cgroup_binding_nonce: target.binding_nonce,
            container_generation: target.container_generation,
            expected_argv: signed.approved_argv,
            resolved_executable: live_policy.kernel_executable,
            approved_role_numeric_id: live_policy.approved_role_numeric_id,
            expected_root_class: ExternalRootClassV1::ExternalRuntimeRoot,
            profile_generation_ref_id: live_policy.profile_generation_ref_id,
            exception_numeric_handle: live_policy.exception_numeric_handle,
            ..ApprovedExecSlotV1::default()
        };
        let receipt = AdministrativeSlotReceiptV1 {
            proof_id: proof.proof_id,
            claim_slot_id: proof.claim_slot_id,
            binding_id: target.binding_id,
        };
        self.proof.arm_administrative_slot(host, key, slot, proof)?;
        Ok(receipt)
    }

    pub(crate) fn reconcile(&mut self, host: &KernelHost) -> Result<()> {
        self.proof.reconcile_administrative_slots(host)
    }

    pub(crate) fn cancel_armed_slots(&mut self, host: &mut KernelHost) -> Result<()> {
        for raw_key in host
            .map_keys("approved_exec_slots")
            .context(crate::error::InterceptorSnafu)?
        {
            let key = ApprovedExecSlotKeyV1::try_read_from_bytes(&raw_key).map_err(|error| {
                AuthorizationSnafu {
                    reason: format!("administrative slot key has the wrong ABI: {error}"),
                }
                .build()
            })?;
            let Some(raw_slot) = host
                .lookup_map("approved_exec_slots", &raw_key)
                .context(crate::error::InterceptorSnafu)?
            else {
                continue;
            };
            let slot = ApprovedExecSlotV1::try_read_from_bytes(&raw_slot).map_err(|error| {
                AuthorizationSnafu {
                    reason: format!("administrative slot has the wrong ABI: {error}"),
                }
                .build()
            })?;
            if slot.state != erebor_interceptor_abi::ApprovedExecSlotStateV1::Armed {
                continue;
            }
            ensure!(
                matches!(
                    host.cancel_administrative_slot(key, slot.proof_id, slot.claim_slot_id)
                        .context(crate::error::InterceptorSnafu)?,
                    AdministrativeSlotCancelResult::Cancelled
                        | AdministrativeSlotCancelResult::Consumed
                        | AdministrativeSlotCancelResult::Closed
                ),
                AuthorizationSnafu {
                    reason: "an armed administrative slot disappeared during cancellation",
                }
            );
        }
        self.proof.reconcile_administrative_slots(host)
    }
}

fn bounded_arguments(argv: &BoundedAdministrativeArgvV1) -> Result<Vec<Vec<u8>>> {
    ensure!(
        argv.is_valid(),
        AuthorizationSnafu {
            reason: "signed administrative argv is not canonical",
        }
    );
    let mut offset = 0;
    let mut arguments = Vec::with_capacity(usize::from(argv.argument_count));
    for length in &argv.argument_lengths[..usize::from(argv.argument_count)] {
        let end = offset + usize::from(*length);
        arguments.push(argv.argument_bytes[offset..end].to_vec());
        offset = end;
    }
    Ok(arguments)
}

fn parse_id(name: &str, value: &str) -> Result<Id128V1> {
    let uuid = uuid::Uuid::parse_str(value).map_err(|error| {
        AuthorizationSnafu {
            reason: format!("{name} is not a canonical UUID: {error}"),
        }
        .build()
    })?;
    ensure!(
        uuid.hyphenated().to_string() == value,
        AuthorizationSnafu {
            reason: format!("{name} is not a canonical UUID"),
        }
    );
    let value = u128::from_be_bytes(*uuid.as_bytes());
    Ok(Id128V1::new((value >> 64) as u64, value as u64))
}

fn read_public_key(path: &std::path::Path) -> Result<[u8; 32]> {
    let bytes = fs::read(path).context(IoSnafu { path })?;
    let value = std::str::from_utf8(&bytes)
        .map(str::trim)
        .map_err(|error| {
            AuthorizationSnafu {
                reason: format!("administrative public key is not UTF-8: {error}"),
            }
            .build()
        })?;
    let decoded = hex::decode(value).map_err(|error| {
        AuthorizationSnafu {
            reason: format!("administrative public key is not lowercase hex: {error}"),
        }
        .build()
    })?;
    decoded.try_into().map_err(|bytes: Vec<u8>| {
        AuthorizationSnafu {
            reason: format!(
                "administrative public key has {} bytes instead of 32",
                bytes.len()
            ),
        }
        .build()
    })
}
