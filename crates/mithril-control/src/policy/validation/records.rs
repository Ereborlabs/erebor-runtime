use super::super::compiler::CompiledOperationV1;
use super::super::{
    path::canonical_path_components, source::*, source_proof::ProofQualityPredicateV1,
    source_response::*,
};
use super::value::PolicyValue;
use super::{Validate, ValidationIssue, ValidationResult};

// Policy records validate the fields and invariants that they own.
impl Validate for EntryRoleAssignmentV1 {
    fn validate(&self) -> ValidationResult {
        PolicyValue::LocalId(&self.assignment_id).validate()?;
        let administrative_kind = self
            .entry_kinds
            .contains(&EntryKindV1::ApprovedAdministrativeExec);
        let administrative_classification = self
            .accepted_classifications
            .contains(&RootClassificationV1::ApprovedAdministrativeNextMatch);
        let complete = !self.workload_selector_ids.is_empty()
            && !self.entry_kinds.is_empty()
            && !self.container_kinds.is_empty()
            && !self.accepted_classifications.is_empty();
        let ordered = ordered!(
            &self.workload_selector_ids,
            &self.entry_kinds,
            &self.container_kinds,
            &self.immutable_definition_digests,
            &self.accepted_classifications
        );
        require!(
            complete && ordered,
            "CFG_ENTRY_ASSIGNMENT",
            format!(
                "entry `{}` has empty or unordered selectors",
                self.assignment_id
            )
        );
        let exact_administrative_binding = self.entry_kinds
            == [EntryKindV1::ApprovedAdministrativeExec]
            && self.accepted_classifications
                == [RootClassificationV1::ApprovedAdministrativeNextMatch]
            && self.required_administrative_exec_approval
            && self.required_purpose_source_capability_id.is_none()
            && self.unknown_restricted_role_id.is_none();
        require!(
            !(self.required_administrative_exec_approval
                || administrative_kind
                || administrative_classification)
                || exact_administrative_binding,
            "CFG_ADMINISTRATIVE_ENTRY",
            format!(
                "entry `{}` has an invalid administrative binding",
                self.assignment_id
            )
        );
        Ok(())
    }
}

impl Validate for StateBitDefinitionV1 {
    fn validate(&self) -> ValidationResult {
        require!(
            self.bit_index < 64 && self.monotonic,
            "CFG_STATE_BIT",
            "state bits must be in 0..63 and monotonic"
        );
        Ok(())
    }
}

impl Validate for ProcessStateDefinitionV1 {
    fn validate(&self) -> ValidationResult {
        PolicyValue::LocalId(&self.process_state_id).validate()?;
        require!(
            ordered_unique(&self.state_bits),
            "CFG_STATE_ORDER",
            "process state bits must be sorted and unique"
        );
        Ok(())
    }
}

impl Validate for IpcRelationshipRuleV1 {
    fn validate(&self) -> ValidationResult {
        PolicyValue::LocalId(&self.relationship_rule_id).validate()?;
        let roles = !self.source_role_ids.is_empty()
            && !self.peer_role_ids.is_empty()
            && ordered!(&self.source_role_ids, &self.peer_role_ids);
        let operation =
            self.channel_class_ids == ["UNIX_STREAM"] && self.operations == ["IPC_ACCESS"];
        let decision = self.requested_disposition != PolicyDispositionV1::Reject
            && (self.requested_disposition == PolicyDispositionV1::Deny) == self.errno.is_some();
        require!(
            roles && operation && decision,
            "CFG_IPC_RELATIONSHIP",
            format!(
                "IPC relationship `{}` is invalid",
                self.relationship_rule_id
            )
        );
        Ok(())
    }
}

impl EffectFamilyV1 {
    pub(super) fn accepts(self, operation: &str) -> bool {
        match self {
            Self::Exec => matches!(operation, "EXECUTE" | "MMAP_EXEC" | "MPROTECT"),
            Self::File => matches!(
                operation,
                "OPEN_READ"
                    | "OPEN_WRITE"
                    | "READ"
                    | "WRITE"
                    | "MMAP_READ"
                    | "MMAP_WRITE"
                    | "MPROTECT"
                    | "CREATE"
                    | "SETATTR"
                    | "UNLINK"
                    | "LINK"
                    | "RENAME"
            ),
            Self::Network => matches!(
                operation,
                "SOCKET_CREATE"
                    | "BIND"
                    | "LISTEN"
                    | "ACCEPT"
                    | "CONNECT"
                    | "SEND"
                    | "RECEIVE"
                    | "SHUTDOWN"
                    | "SETSOCKOPT"
            ),
            Self::Device => operation == "IOCTL",
            Self::Privilege => {
                matches!(
                    operation,
                    "CAPABILITY"
                        | "BPF"
                        | "IO_URING_SETUP"
                        | "IO_URING_REGISTER"
                        | "IO_URING_SQPOLL"
                        | "IO_URING_OVERRIDE_CREDS"
                        | "IO_URING_COMMAND"
                ) || CompiledOperationV1::try_from(operation)
                    .ok()
                    .and_then(CompiledOperationV1::process_control)
                    .is_some()
            }
            Self::Ipc => operation == "IPC_ACCESS",
            Self::Mount => matches!(operation, "MOUNT" | "UNMOUNT" | "PIVOT_ROOT" | "MOVE_MOUNT"),
        }
    }
}

impl Validate for ProofQualityPredicateV1 {
    fn validate(&self) -> ValidationResult {
        require!(
            ordered!(
                &self.source_authority,
                &self.local_subject_binding,
                &self.remote_subject_binding,
                &self.operation_result_authority,
                &self.temporal_coverage,
                &self.integrity
            ),
            "CFG_PROOF_ORDER",
            "proof predicates must be sorted and unique"
        );
        Ok(())
    }
}

impl Validate for FindingSpecV1 {
    fn validate(&self) -> ValidationResult {
        PolicyValue::RegistrySymbol(&self.reason_code).validate()?;
        if let Some(id) = &self.title_template_id {
            PolicyValue::LocalId(id).validate()?;
        }
        require!(
            ordered_unique(&self.route_ids),
            "CFG_FINDING",
            "finding routes must be sorted and unique"
        );
        Ok(())
    }
}

impl Validate for PathTreeDenyFloorV1 {
    fn validate(&self) -> ValidationResult {
        PolicyValue::LocalId(&self.rule_id).validate()?;
        canonical_path_components("<validation>", &self.canonical_path).map_err(|error| {
            ValidationIssue {
                code: "CFG_PATH_TREE_DENY",
                reason: error.to_string(),
            }
        })?;
        let shape = self.schema_version == 1
            && self.recursive
            && self.requested_disposition == PolicyDispositionV1::Deny
            && self.exception_ids.is_empty()
            && self.effect_families == [EffectFamilyV1::File];
        let operations = !self.operation_ids.is_empty()
            && ordered_unique(&self.operation_ids)
            && self
                .operation_ids
                .iter()
                .all(|operation| EffectFamilyV1::File.accepts(operation));
        require!(
            shape && operations,
            "CFG_PATH_TREE_DENY",
            format!(
                "path-tree rule `{}` is not an exact recursive FILE DENY",
                self.rule_id
            )
        );
        Ok(())
    }
}

impl Validate for FileExceptionGrantTemplateV1 {
    fn validate(&self) -> ValidationResult {
        PolicyValue::LocalId(&self.grant_id).validate()?;
        require!(
            !self.denied_file_rule_ids.is_empty()
                && ordered_unique(&self.denied_file_rule_ids)
                && self.maximum_duration_ns > 0
                && self.maximum_uses > 0,
            "CFG_EXCEPTION_GRANT",
            format!("exception grant `{}` is invalid", self.grant_id)
        );
        Ok(())
    }
}

impl Validate for PathSelectorV1 {
    fn validate(&self) -> ValidationResult {
        PolicyValue::LocalId(&self.path_selector_id).validate()?;
        PolicyValue::RegistrySymbol(&self.object_class_id).validate()?;
        if let Some(device_class_id) = &self.device_class_id {
            PolicyValue::RegistrySymbol(device_class_id).validate()?;
        }
        self.target
            .pattern_components("<validation>")
            .map_err(|error| ValidationIssue {
                code: "CFG_PATH_SELECTOR",
                reason: error.to_string(),
            })?;
        require!(
            self.schema_version == 1
                && (self.device_class_id.is_none() || self.requires_exact_object()),
            "CFG_PATH_SELECTOR",
            format!(
                "path selector `{}` is not a valid Version 1 selector",
                self.path_selector_id
            )
        );
        Ok(())
    }
}

impl Validate for NotificationRouteV1 {
    fn validate(&self) -> ValidationResult {
        PolicyValue::LocalId(&self.route_id).validate()?;
        PolicyValue::LocalId(&self.sink_binding_id).validate()?;
        PolicyValue::Duration(&self.dedupe_window, true).validate()?;
        require!(
            !self.grouping_fields.is_empty()
                && !self.allowed_evidence_fields.is_empty()
                && ordered!(&self.grouping_fields, &self.allowed_evidence_fields),
            "CFG_NOTIFICATION_ROUTE",
            format!("notification route `{}` is invalid", self.route_id)
        );
        Ok(())
    }
}

impl Validate for BlastRadiusLimitV1 {
    fn validate(&self) -> ValidationResult {
        let valid = match self {
            Self::Local {
                permitted_target_selector_ids: ids,
                process_count: a,
                execution_set_count: b,
                socket_count: c,
                node_count: d,
            } => bounded!(ids; a, b, c, d),
            Self::Kubernetes {
                permitted_namespace_uids: ids,
                object_count: a,
                controller_count: b,
                node_count: c,
            } => bounded!(ids; a, b, c),
            Self::Credential {
                permitted_provider_account_ids: ids,
                session_count: a,
                principal_count: b,
                role_count: c,
                account_count: d,
            } => bounded!(ids; a, b, c, d),
            Self::Mesh {
                permitted_tailnet_or_tenant_ids: ids,
                device_count: a,
                route_count: b,
                auth_key_count: c,
            } => bounded!(ids; a, b, c),
            Self::SourceControl {
                permitted_organization_ids: ids,
                installation_count: a,
                repository_count: b,
                ref_or_pr_count: c,
            } => bounded!(ids; a, b, c),
            Self::Artifact {
                permitted_store_ids: ids,
                artifact_count: a,
                consumer_count: b,
            } => ordered_unique(ids) && *a > 0 && *b > 0,
            Self::ProviderResources {
                permitted_provider_account_ids: a,
                permitted_resource_selector_ids: b,
                resource_count: c,
                principal_count: d,
            } => ordered_unique(a) && ordered_unique(b) && *c > 0 && *d > 0,
        };
        require!(
            valid,
            "CFG_BLAST_RADIUS",
            "blast radius must be ordered and bounded"
        );
        Ok(())
    }
}

impl Validate for ResponseBindingV1 {
    fn validate(&self) -> ValidationResult {
        use BlastRadiusLimitV1 as Blast;
        use PhysicalPostconditionV1 as Post;
        use ResponseActionSpecV1 as Action;
        use TargetRevalidationV1 as Target;
        PolicyValue::LocalId(&self.binding_id).validate()?;
        self.required_proof.validate()?;
        self.maximum_blast_radius.validate()?;
        PolicyValue::Duration(&self.watch_interval, false).validate()?;
        let contract = (
            &self.action_spec,
            self.target_revalidation,
            self.physical_postcondition,
            &self.maximum_blast_radius,
        );
        let compatible = matches!(
            contract,
            (
                Action::RestrictLineage,
                Target::LineageRootAndCompleteEffectiveResponseSet,
                Post::ResponseSetInstalledAndDescendantsReconciled,
                Blast::Local { .. }
            ) | (
                Action::FenceSockets,
                Target::SocketCookieProvenanceAndLiveBinding,
                Post::SocketSetFencedAndExistingFlowOraclePassed,
                Blast::Local { .. }
            ) | (
                Action::FreezeCgroup,
                Target::CgroupFdNonceAndMemberSet,
                Post::CgroupFrozenAndPacketFenceActive,
                Blast::Local { .. }
            ) | (
                Action::TerminateProcessPidfd,
                Target::ProcessPidfdTaskCookieStarttimeCgroupBinding,
                Post::ProcessStoppedViaPidfd,
                Blast::Local { .. }
            ) | (
                Action::RejectKubernetesReplacement { .. },
                Target::KubernetesUidResourceVersion,
                Post::ReplacementRejectedThroughWatchWatermark,
                Blast::Kubernetes { .. }
            ) | (
                Action::RevokeCredential { .. },
                Target::ProviderStableIdRevisionAndAuthority,
                Post::ProviderCredentialActionReadBack,
                Blast::Credential { .. }
            ) | (
                Action::DisableMeshDevice { .. },
                Target::ProviderStableIdRevisionAndAuthority,
                Post::MeshDeviceDisabledAndHandshakeRejected,
                Blast::Mesh { .. }
            ) | (
                Action::QuarantineArtifact { .. },
                Target::ArtifactImmutableDigestAndStoreRevision,
                Post::ArtifactQuarantinedAndConsumerLoadRejected,
                Blast::Artifact { .. }
            ) | (
                Action::SuspendInstallation { .. },
                Target::ProviderStableIdRevisionAndAuthority,
                Post::ProviderOperationSpecificPostcondition,
                Blast::SourceControl { .. }
            ) | (
                Action::ProviderSpecific { .. },
                Target::ProviderStableIdRevisionAndAuthority,
                Post::ProviderOperationSpecificPostcondition,
                Blast::ProviderResources { .. }
            )
        );
        require!(
            compatible,
            "CFG_RESPONSE_BINDING",
            format!(
                "response binding `{}` has an incompatible exact contract",
                self.binding_id
            )
        );
        Ok(())
    }
}
