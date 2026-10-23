use super::*;
use crate::{
    AnalysisContextVersionV1, CompiledPolicyContextV1, DiscoveryContextKindV1,
    DiscoveryContextRevisionV1, TargetContextV1,
};

impl Capture<'_> {
    pub(in crate::analysis::extraction) fn context(
        &mut self,
        context: &AnalysisContextVersionV1,
        revision: u64,
        budget: &mut ReadBudget<'_>,
    ) -> Result<bool> {
        let document = if self.read.projected("context").is_some()
            && context.key.owner_id == "discovery-context-v1"
        {
            budget.charge(context.body.len().saturating_mul(2))?;
            Some(DiscoveryContextRevisionV1::try_from(context)?)
        } else {
            None
        };
        for relation in ["context_versions", "context"] {
            if !self.context_row(relation, context, revision, document.as_ref(), budget)? {
                return Ok(false);
            }
        }
        if self.read.projected("notification_routes").is_some()
            && context.key.owner_id == crate::NOTIFICATION_ROUTE_OWNER
        {
            return self.notification_route(context, revision, budget);
        }
        if self.read.projected("compiled_policies").is_some()
            && context.key.owner_id == "mithril-control/compiled-policy"
        {
            return self.compiled(context, revision, budget);
        }
        if self.read.requests.contains_key("targets")
            && context.key.owner_id == "mithril-control/target"
        {
            budget.charge(context.body.len().saturating_mul(2))?;
            let target: TargetContextV1 =
                serde_json::from_slice(&context.body).map_err(|source| {
                    crate::Error::PackageEncoding {
                        source,
                        location: snafu::location!(),
                    }
                })?;
            self.target(context, &target, revision, budget)
        } else {
            Ok(true)
        }
    }

    fn compiled(
        &mut self,
        context: &AnalysisContextVersionV1,
        revision: u64,
        budget: &mut ReadBudget<'_>,
    ) -> Result<bool> {
        const NAMES: &[&str] = &[
            "tenant_id",
            "entity_key",
            "lifetime_key",
            "owner_revision",
            "commit_revision",
            "source_revision_id",
            "signed_profile_digest",
            "profile_id",
            "profile_version",
            "policy_document_digest",
            "execution_set_ids",
            "compiled_keys",
        ];
        use sdk::arrow_array::{BinaryArray, UInt64Array};

        let table = self.table("compiled_policies", NAMES, budget)?;
        let schema = Arc::clone(&table.schema);
        let projection = table.mapping[5..]
            .iter()
            .enumerate()
            .filter_map(|(index, selected)| selected.map(|_| index))
            .collect::<Vec<_>>();
        let proof = if projection.is_empty() {
            None
        } else {
            budget.charge(context.body.len())?;
            let trailer = context
                .body
                .len()
                .checked_sub(10)
                .ok_or_else(|| invalid("the compiled policy IPC trailer is absent"))?;
            let footer_len = arrow_ipc::reader::read_footer_length(
                context.body[trailer..]
                    .try_into()
                    .map_err(|_| invalid("the compiled policy IPC trailer differs"))?,
            )
            .map_err(arrow_error)?;
            let start = trailer
                .checked_sub(footer_len)
                .ok_or_else(|| invalid("the compiled policy IPC footer exceeds its body"))?;
            let footer = arrow_ipc::root_as_footer(&context.body[start..trailer])
                .map_err(|_| invalid("the compiled policy IPC footer is invalid"))?;
            if footer.schema().is_none() {
                return Err(invalid("the compiled policy IPC schema is absent"));
            }
            if footer
                .dictionaries()
                .is_some_and(|blocks| !blocks.is_empty())
                || footer
                    .recordBatches()
                    .is_none_or(|blocks| blocks.len() != 1)
            {
                return Err(invalid("the compiled policy IPC must have one plain batch"));
            }
            for block in footer.recordBatches().iter().flatten() {
                let offset = usize::try_from(block.offset())
                    .map_err(|_| invalid("the compiled policy IPC block exceeds its body"))?;
                let metadata = usize::try_from(block.metaDataLength())
                    .map_err(|_| invalid("the compiled policy IPC block exceeds its body"))?;
                let end = usize::try_from(block.bodyLength()).ok().and_then(|body| {
                    offset
                        .checked_add(metadata)
                        .and_then(|end| end.checked_add(body))
                });
                if metadata < 8 || end.is_none_or(|end| end > start) {
                    return Err(invalid("the compiled policy IPC block exceeds its body"));
                }
                if context.body[offset..offset + 4] != [0xff; 4] {
                    return Err(invalid("the compiled policy IPC frame differs"));
                }
                let message =
                    arrow_ipc::root_as_message(&context.body[offset + 8..offset + metadata])
                        .map_err(|_| invalid("the compiled policy IPC metadata is invalid"))?;
                let batch = message
                    .header_as_record_batch()
                    .ok_or_else(|| invalid("the compiled policy IPC has no record batch"))?;
                if batch.compression().is_some() || batch.length() != 1 {
                    return Err(invalid(
                        "the compiled policy IPC must have one uncompressed row",
                    ));
                }
            }
            let mut reader = arrow_ipc::reader::FileReader::try_new(
                std::io::Cursor::new(&context.body),
                Some(projection),
            )
            .map_err(arrow_error)?;
            if reader.schema().as_ref() != CompiledPolicyContextV1::schema()
                || reader.num_batches() != 1
            {
                return Err(invalid("the compiled policy proof schema differs"));
            }
            let batch = reader
                .next()
                .transpose()
                .map_err(arrow_error)?
                .ok_or_else(|| invalid("the compiled policy proof is absent"))?;
            if batch.num_rows() != 1 {
                return Err(invalid("the compiled policy proof must have one row"));
            }
            Some(batch)
        };
        budget.charge(
            schema.fields().len() * (size_of::<ArrayRef>() + 512)
                + context.key.entity_key.len()
                + context.key.lifetime_key.len(),
        )?;
        let mut columns = Vec::<ArrayRef>::with_capacity(schema.fields().len());
        for field in schema.fields() {
            let column: ArrayRef = match field.name().as_str() {
                "tenant_id" => Arc::new(BinaryArray::from_vec(vec![&context.key.tenant_id])),
                "entity_key" => Arc::new(BinaryArray::from_vec(vec![context
                    .key
                    .entity_key
                    .as_slice()])),
                "lifetime_key" => Arc::new(BinaryArray::from_vec(vec![context
                    .key
                    .lifetime_key
                    .as_slice()])),
                "owner_revision" => Arc::new(UInt64Array::from(vec![context.key.owner_revision])),
                "commit_revision" => Arc::new(UInt64Array::from(vec![revision])),
                name => proof
                    .as_ref()
                    .and_then(|batch| batch.column_by_name(name))
                    .cloned()
                    .ok_or_else(|| invalid("the compiled policy field is absent"))?,
            };
            columns.push(column);
        }
        let batch = RecordBatch::try_new_with_options(
            schema,
            columns,
            &sdk::arrow_array::RecordBatchOptions::new().with_row_count(Some(1)),
        )
        .map_err(arrow_error)?;
        self.table("compiled_policies", NAMES, budget)?
            .append_native(batch, budget)
    }

    pub(super) fn compiled_fields() -> Vec<sdk::Field> {
        use sdk::DataType::*;
        let mut fields = vec![
            sdk::Field::new("tenant_id", Binary, false),
            sdk::Field::new("entity_key", Binary, false),
            sdk::Field::new("lifetime_key", Binary, false),
            sdk::Field::new("owner_revision", UInt64, false),
            sdk::Field::new("commit_revision", UInt64, false),
        ];
        fields.extend(
            CompiledPolicyContextV1::schema()
                .fields()
                .iter()
                .map(|field| field.as_ref().clone()),
        );
        fields
    }

    table_row! {
        fn target(
            &mut self,
            context: &AnalysisContextVersionV1,
            target: &TargetContextV1,
            revision: u64,
            budget: &mut ReadBudget<'_>,
        );
        schema target_fields;
        row(self, "targets", budget);
        setup {
            let fact = &target.workload;
            let kube = fact.kubernetes.as_ref();
            let boot = kube.and_then(|value| uuid::Uuid::parse_str(&value.node_boot_id).ok());
            let binding = kube.and_then(|value| uuid::Uuid::parse_str(&value.binding_id).ok());
            if (!self.scope.nodes.is_empty() && !self.scope.nodes.contains(&fact.node_id))
                || (!self.scope.binding_ids.is_empty()
                    && binding
                        .as_ref()
                        .is_none_or(|binding| !self.scope.binding_ids.contains(binding.as_bytes())))
            {
                return Ok(true);
            }
        }
        fields {
            tenant_id => Binary(false):Some(&context.key.tenant_id),
            entity_key => Binary(false):Some(&context.key.entity_key),
            lifetime_key => Binary(false):Some(&context.key.lifetime_key),
            owner_revision => UInt64(false):Some(context.key.owner_revision),
            commit_revision => UInt64(false):Some(revision),
            node_id => Utf8(false):Some(&fact.node_id),
            node_boot_id => Binary(true):boot.as_ref().map(|value|value.as_bytes().as_slice()),
            node_boot_id_text => Utf8(true):kube.map(|value| value.node_boot_id.as_str()),
            label_epoch => UInt64(true):kube.map(|value|value.label_epoch),
            binding_id => Binary(true):binding.as_ref().map(|value|value.as_bytes().as_slice()),
            binding_id_text => Utf8(true):kube.map(|value| value.binding_id.as_str()),
            workload_binding_generation_digest => Utf8(false):Some(&fact.workload_binding_generation_digest),
            workload_digest_valid => Boolean(false):Some(target.workload_digest_valid),
            execution_set_id => Utf8(false):Some(&fact.execution_set_id),
            cluster_uid => Utf8(false):Some(&fact.cluster_uid),
            namespace_uid => Utf8(false):Some(&fact.namespace_uid),
            controller_uid => Utf8(false):Some(&fact.controller_uid),
            service_account_uid => Utf8(false):Some(&fact.service_account_uid),
            pod_uid => Utf8(false):Some(&fact.pod_uid),
            container_id => Utf8(false):Some(&fact.container_id),
            container_name => Utf8(false):Some(&fact.container_name),
            container_kind => Utf8(false):Some(match fact.container_kind {crate::ContainerKindV1::Init=>"INIT",crate::ContainerKindV1::Sidecar=>"SIDECAR",crate::ContainerKindV1::Application=>"APPLICATION",crate::ContainerKindV1::Ephemeral=>"EPHEMERAL"}),
            image_digest => Utf8(false):Some(&fact.image_digest),
            pod_labels => Json(false):Some(&fact.pod_labels),
            namespace_name => Utf8(true):kube.map(|value|value.namespace_name.as_str()),
            pod_name => Utf8(true):kube.map(|value|value.pod_name.as_str()),
            profile_id => Utf8(true):kube.map(|value|value.profile_id.as_str()),
            policy_source_revision_id => Utf8(true):kube.map(|value|value.policy_source_revision_id.as_str()),
            source_revision_id => Utf8(false):Some(&target.policy_source_revision_id),
            target_snapshot_digest => Utf8(false):Some(&target.target_snapshot_digest),
            signed_profile_digest => Utf8(false):Some(&target.signed_profile_digest),
            protected_scope_id => Utf8(true):kube.map(|value|value.protected_scope_id.as_str()),
            workload_selector_id => Utf8(true):kube.map(|value|value.workload_selector_id.as_str()),
            kubernetes_node_name => Utf8(true):kube.map(|value|value.kubernetes_node_name.as_str()),
            kubernetes_node_uid => Utf8(true):kube.map(|value|value.kubernetes_node_uid.as_str()),
        }
    }

    table_row! {
        fn context_row(
            &mut self,
            relation: &str,
            context: &AnalysisContextVersionV1,
            revision: u64,
            document: Option<&DiscoveryContextRevisionV1>,
            budget: &mut ReadBudget<'_>,
        );
        schema context_fields;
        prefix version_fields {
            tenant_id => Binary(false):Some(&context.key.tenant_id),
            owner_id => Utf8(false):Some(&context.key.owner_id),
            entity_key => Binary(false):Some(&context.key.entity_key),
            lifetime_key => Binary(false):Some(&context.key.lifetime_key),
            owner_revision => UInt64(false):Some(context.key.owner_revision),
            valid_from_utc_ns => UInt64(true):context.valid_from_utc_ns,
            valid_until_utc_ns => UInt64(true):context.valid_until_utc_ns,
            sensitivity => Utf8(false):Some(<&str>::from(context.sensitivity)),
            body => Binary(false):Some(&context.body),
            commit_revision => UInt64(false):Some(revision),
        }
        row(self, relation, budget);
        setup {
            let doc = document.map(|value| &value.document);
        }
        fields {
            kind => Utf8(true):doc.map(|value|match value.kind {
                DiscoveryContextKindV1::Runbook=>"RUNBOOK",
                DiscoveryContextKindV1::WorkloadOwnership=>"WORKLOAD_OWNERSHIP",
                DiscoveryContextKindV1::DeploymentChange=>"DEPLOYMENT_CHANGE",
                DiscoveryContextKindV1::ReviewedAssessment=>"REVIEWED_ASSESSMENT",
                DiscoveryContextKindV1::ThreatReference=>"THREAT_REFERENCE",
            }),
            subject_owner_id => Utf8(true):doc.map(|value|value.subject.owner_id.as_str()),
            subject_entity_key => Binary(true):doc.map(|value|value.subject.entity_key.as_slice()),
            subject_lifetime_key => Binary(true):doc.map(|value|value.subject.lifetime_key.as_slice()),
            subject_revision => UInt64(true):doc.map(|value|value.subject.owner_revision),
            method_id => Utf8(true):doc.map(|value|value.method.id.as_str()),
            method_revision => UInt64(true):doc.map(|value|value.method.revision),
            origin => Utf8(true):doc.map(|value|value.origin.as_str()),
            trust => Utf8(true):doc.map(|value|if value.approver.is_some(){"REVIEWED"}else{"UNREVIEWED"}),
            imported_utc_ns => UInt64(true):document.as_ref().map(|value|value.imported_utc_ns),
            approver => Utf8(true):doc.and_then(|value|value.approver.as_deref()),
            text => Utf8(true):doc.map(|value|value.text.as_str()),
        }
    }
}
