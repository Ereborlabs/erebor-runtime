use std::collections::BTreeSet;

use araphor_analysis_builtins::causal::{Causal, model::*};
use araphor_analysis_sdk as sdk;
use araphor_analysis_types::{
    arrow::views::{ContextKeyRow, RecordIdRow, SourceRow},
    source::*,
    values::*,
};
use erebor_interceptor_abi::{
    EffectPhysicalResultV1, KernelEffectFamilyV1 as Family, KernelEffectOperationV1 as Operation,
};
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;

use super::{Result, fixture::Spec};

#[derive(Clone, Serialize)]
struct Context {
    key: ContextKeyRow,
    commit_revision: u64,
    sensitivity: String,
    body: ByteBuf,
}
#[derive(Serialize)]
struct Coverage {
    source: SourceRow,
    cpu_id: u32,
    coverage_revision: u64,
    retained_floor: u64,
    kind: String,
    first_cursor: Option<u64>,
    last_cursor: Option<u64>,
}
#[derive(Serialize)]
struct Affected {
    key: ContextKeyRow,
}
#[derive(Deserialize)]
struct Frontier {
    record: RecordIdRow,
    context: ContextKeyRow,
    commit_revision: u64,
}

pub struct Incident {
    contexts: Vec<Context>,
    records: Vec<Observation>,
    sources: Vec<EvidenceIntakeIdentityV1>,
}

impl Incident {
    pub fn new() -> Result<Self> {
        let sources = (0..4)
            .map(|i| EvidenceIntakeIdentityV1 {
                tenant_id: [1; 16],
                node_id: if i == 3 { "node-b" } else { "node-a" }.into(),
                node_boot_id: if i == 3 { [17; 16] } else { [7; 16] },
                label_epoch: 1,
                source_id: [33 + i; 16],
                source_epoch: 1,
            })
            .collect::<Vec<_>>();
        let mut this = Self {
            contexts: Vec::new(),
            records: Vec::new(),
            sources,
        };
        for serial in 1..=3 {
            this.episode(serial)?;
        }
        Ok(this)
    }

    fn episode(&mut self, serial: u64) -> Result<()> {
        let credential = Credential {
            authority: "aws-imds-node-role".into(),
            lease: format!("node-session-{serial}"),
            principal: "system:node:worker-a".into(),
        };
        let issued = Credential {
            authority: "kubernetes-token-request".into(),
            lease: format!("csi-token-{serial}"),
            principal: "system:serviceaccount:kube-system:ebs-csi-controller-sa".into(),
        };
        let pod = Pod {
            cluster: "hf-evaluation".into(),
            uid: format!("privileged-pod-{serial}"),
            created_revision: format!("create-{serial}"),
        };
        let task = 7 + serial;
        let process = [8 + serial as u8; 16];
        let object = [20 + serial as u8; 16];
        let binding = format!("scheduling-{serial}");
        let ids = (0..6)
            .map(|i| {
                let source = [0, 0, 1, 1, 2, 3][i];
                let per = [2, 2, 1, 1][source];
                let cursor = if serial == 1 {
                    0
                } else {
                    4096 + (serial - 1) * per
                } + [1, 2, 1, 2, 1, 1][i];
                DiscoveryRecordIdV1 {
                    stream: self.sources[source].clone(),
                    cpu_id: 3,
                    durable_cursor: cursor,
                }
            })
            .collect::<Vec<_>>();
        let token_request = Request {
            cluster: pod.cluster.clone(),
            audit: format!("token-audit-{serial}"),
            carried: format!("token-request-{serial}"),
            credential: credential.clone(),
            socket: object,
            credential_origin: Origin {
                record: ids[1].clone(),
                proof: format!("imds-response-{serial}"),
            },
        };
        let mut create_request = token_request.clone();
        create_request.credential = issued.clone();
        create_request.audit = format!("create-audit-{serial}");
        create_request.carried = format!("create-request-{serial}");
        create_request.credential_origin = Origin {
            record: ids[2].clone(),
            proof: format!("token-audit-{serial}"),
        };
        let actions = vec![
            Action::CredentialAccess {
                credential: credential.clone(),
                object,
                completion: format!("denied-read-{serial}"),
                result: -13,
                bytes: 0,
            },
            Action::CredentialAccess {
                credential,
                object,
                completion: format!("imds-response-{serial}"),
                result: 2048,
                bytes: 2048,
            },
            Action::TokenRequest {
                request: token_request,
                issued: Some(issued),
            },
            Action::PodCreate {
                request: create_request,
                pod: Some(pod.clone()),
                containers: vec![Container {
                    name: "host-reader".into(),
                    privileged: true,
                    host_mounts: vec![HostMount {
                        host_path: "/".into(),
                        container_path: "/host".into(),
                        read_only: false,
                    }],
                }],
            },
            Action::PodScheduled {
                pod: pod.clone(),
                created_by: Origin {
                    record: ids[3].clone(),
                    proof: format!("create-audit-{serial}"),
                },
                binding: binding.clone(),
                node: "node-b".into(),
            },
            Action::ContainerAdmitted {
                runtime: Runtime {
                    pod,
                    binding: binding.clone(),
                    node: "node-b".into(),
                    boot: [17; 16],
                    label_epoch: 1,
                    container: format!("containerd://{serial:064x}"),
                    container_name: "host-reader".into(),
                    cgroup: 10_000 + serial,
                    admission: format!("runtime-admission-{serial}"),
                    task,
                    process,
                    scheduled_by: Origin {
                        record: ids[4].clone(),
                        proof: binding,
                    },
                },
            },
        ];
        for (index, action) in actions.into_iter().enumerate() {
            let denied = index == 0;
            let proof = ProofQualityV1 {
                source_authority: SourceAuthorityV1::AuthoritativeProvider,
                local_subject_binding: LocalSubjectBindingV1::ExactTask,
                remote_subject_binding: if matches!(index, 2 | 3) {
                    RemoteSubjectBindingV1::ExactRequest
                } else {
                    RemoteSubjectBindingV1::ExactObject
                },
                operation_result_authority: if denied {
                    OperationResultAuthorityV1::AuthoritativeDenied
                } else {
                    OperationResultAuthorityV1::AuthoritativeSucceeded
                },
                temporal_coverage: TemporalCoverageV1::Complete,
                integrity: ProofIntegrityV1::AuthenticatedChannel,
            };
            let audit = Audit {
                schema_version: 1,
                record: ids[index].clone(),
                task,
                process,
                outcome: if denied {
                    Outcome::Denied
                } else {
                    Outcome::Succeeded
                },
                status_code: matches!(index, 2 | 3).then_some(201),
                proof,
                action,
            };
            let version = if serial == 1 {
                if index == 5 { 27 } else { 24 }
            } else if serial == 2 {
                62
            } else {
                85
            };
            let key = AnalysisContextKeyV1 {
                tenant_id: [1; 16],
                owner_id: Audit::OWNER.into(),
                entity_key: araphor_analysis_types::DomainRelations::key(&audit.record)?,
                lifetime_key: audit.record.stream.node_boot_id.to_vec(),
                owner_revision: 1,
            };
            self.contexts.push(Context {
                key: ContextKeyRow::from(&key),
                commit_revision: version,
                sensitivity: "tenant".into(),
                body: ByteBuf::from(audit.encode()?),
            });
            self.records.push(Observation {
                id: ids[index].clone(),
                position: Position {
                    commit_revision: version,
                    ordinal: index as u32,
                },
                effect: DiscoveryEffectKeyV1 {
                    task_cookie: task,
                    target_task_cookie: None,
                    process_lineage_id: vec![1; 16],
                    authority_domain_id: vec![2; 16],
                    execution_set_id: vec![3; 16],
                    exact_object_id: object.to_vec(),
                    destination_id: 0,
                    policy_rule_id: 0,
                    reason: 0,
                    decision: if denied {
                        EffectPhysicalResultV1::DeniedBeforeEffect as u32
                    } else {
                        EffectPhysicalResultV1::UnknownAfterPreEffect as u32
                    },
                    effect_family: match index {
                        0 => Family::File,
                        5 => Family::Exec,
                        _ => Family::Network,
                    } as u32,
                    operation: match index {
                        0 => Operation::OpenRead,
                        1 => Operation::Receive,
                        5 => Operation::Execute,
                        _ => Operation::Send,
                    } as u32,
                    operation_argument: None,
                    configured_errno: if denied { 13 } else { 0 },
                    kernel_result: if denied { -13 } else { 0 },
                    exact_file_object: None,
                },
                ingested_utc_ns: 1_000_000 + serial as i64 * 100 + index as i64,
                observed_boottime_ns: ids[index].durable_cursor,
                profile_generation_ref_id: None,
                original_kernel_sequence: None,
                coverage_interval_id: vec![33 + [0, 0, 1, 1, 2, 3][index]; 16],
                process_instance_id: Some(process),
                entry_instance_id: Some([4; 16]),
                binding_id: Some([5; 16]),
                role_id: Some(1),
                state_id: Some(1),
                entry_rule_id: Some(1),
                proof_quality: proof,
            });
        }
        Ok(())
    }

    pub fn index_input(&self, step: usize, spec: Spec) -> Result<sdk::Evaluation> {
        let package = Causal::descriptor();
        let model = &package.exports[0];
        let range = match step {
            0 => 0..5,
            1 => 5..6,
            5 => 6..12,
            7 => 12..18,
            _ => 0..0,
        };
        let contexts = &self.contexts[range];
        let coverage = self
            .sources
            .iter()
            .map(|s| Coverage {
                source: SourceRow::from(s),
                cpu_id: 3,
                coverage_revision: spec.captured,
                retained_floor: 0,
                kind: "receipt".into(),
                first_cursor: None,
                last_cursor: None,
            })
            .collect::<Vec<_>>();
        let mut inputs = Vec::new();
        for input in &model.inputs {
            let port = &input.port;
            let data = match port.name.as_str() {
                "audit_after" => Self::encode(port, contexts)?,
                "audit_affected" => Self::encode(
                    port,
                    &contexts
                        .iter()
                        .map(|c| Affected { key: c.key.clone() })
                        .collect::<Vec<_>>(),
                )?,
                "coverage_after" => Self::encode(port, &coverage)?,
                "reset" => model
                    .change_inputs
                    .as_ref()
                    .ok_or("change contract absent")?
                    .reset_input(step == 0)?,
                _ => sdk::Dataset {
                    name: port.name.clone(),
                    batches: Vec::new(),
                },
            };
            inputs.push(Self::input(data, spec.captured));
        }
        Ok(Self::evaluation("index", inputs, spec))
    }

    pub fn detect_input(
        &self,
        index: &sdk::Output,
        spec: Spec,
    ) -> Result<(sdk::Evaluation, Vec<usize>)> {
        let package = Causal::descriptor();
        let model = &package.exports[1];
        let frontier = index
            .datasets
            .iter()
            .find(|d| d.name == "frontier")
            .ok_or("frontier absent")?;
        let mut selected = BTreeSet::new();
        for batch in &frontier.batches {
            for row in serde_arrow::from_record_batch::<Vec<Frontier>>(batch)? {
                let id: DiscoveryRecordIdV1 = row.record.try_into()?;
                let context: AnalysisContextKeyV1 = row.context.try_into()?;
                let i = self
                    .records
                    .iter()
                    .position(|r| r.id == id)
                    .ok_or("frontier record absent")?;
                let actual: AnalysisContextKeyV1 = self.contexts[i].key.clone().try_into()?;
                assert_eq!(context, actual);
                assert_eq!(row.commit_revision, self.contexts[i].commit_revision);
                selected.insert(i);
            }
        }
        assert_eq!(selected.len(), spec.expected_frontier);
        assert_eq!(selected, (0..spec.expected_frontier).collect());
        let records = selected
            .iter()
            .map(|i| self.records[*i].clone())
            .collect::<Vec<_>>();
        let contexts = selected
            .iter()
            .map(|i| self.contexts[*i].clone())
            .collect::<Vec<_>>();
        let mut inputs = Vec::new();
        for input in &model.inputs {
            let port = &input.port;
            let data = match port.name.as_str() {
                "frontier" | "control" => index
                    .datasets
                    .iter()
                    .find(|d| d.name == port.name)
                    .ok_or("index output absent")?
                    .clone(),
                "records" => Observation::encode(&records)?,
                "audits" => Self::encode(port, &contexts)?,
                _ => return Err("unknown detect input".into()),
            };
            inputs.push(Self::input(data, spec.captured));
        }
        Ok((
            Self::evaluation("detect", inputs, spec),
            selected.into_iter().collect(),
        ))
    }

    fn encode<T: Serialize>(port: &sdk::Port, rows: &[T]) -> Result<sdk::Dataset> {
        Ok(sdk::Dataset {
            name: port.name.clone(),
            batches: vec![serde_arrow::to_record_batch(port.schema.fields(), &rows)?],
        })
    }
    fn input(data: sdk::Dataset, revision: u64) -> sdk::Input {
        sdk::Input {
            data,
            revision: sdk::Revision {
                owner: "scenario".into(),
                id: revision.to_string(),
                window: None,
            },
            coverage: sdk::Coverage {
                state: sdk::CoverageState::Complete,
                limits: Vec::new(),
            },
        }
    }
    fn evaluation(export: &str, inputs: Vec<sdk::Input>, spec: Spec) -> sdk::Evaluation {
        sdk::Evaluation {
            export: export.into(),
            inputs,
            parameters: None,
            context: sdk::EvaluationContext {
                id: format!("scenario-{}", spec.revision),
                time_utc_ns: 1_000_000,
                seed: None,
            },
            checkpoint: None,
            previous_outputs: Vec::new(),
        }
    }
}
