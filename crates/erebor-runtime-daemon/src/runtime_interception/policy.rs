use std::str::Utf8Error;

use erebor_runtime_events::{
    ActionKind, ActorIdentity, ActorKind, EventId, ExecutionSurface, RiskLevel, RiskMetadata,
    RuntimeEvent, SessionId,
};
use erebor_runtime_packages::{ContentDigest, PolicyPackageRevision};
use erebor_runtime_policy::{
    LayeredDecision, LayeredPolicySet, LocalPolicy, PolicyError, PolicyLayer, PolicySet,
};
use snafu::Snafu;

const IMAGE_FORMAT: &[u8] = b"erebor-runtime-static-policy-image-v1";

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) enum PortableEffectClass {
    ProcessExec,
    FileOpen,
    FileRead,
    FileMutation,
    SocketConnect,
}

impl PortableEffectClass {
    const ORDERED: [Self; 5] = [
        Self::ProcessExec,
        Self::FileOpen,
        Self::FileRead,
        Self::FileMutation,
        Self::SocketConnect,
    ];

    const fn as_str(self) -> &'static str {
        match self {
            Self::ProcessExec => "process_exec",
            Self::FileOpen => "file_open",
            Self::FileRead => "file_read",
            Self::FileMutation => "file_mutation",
            Self::SocketConnect => "socket_connect",
        }
    }

    fn event(self) -> RuntimeEvent {
        let (surface, action, risk) = match self {
            Self::ProcessExec => (
                ExecutionSurface::Terminal,
                ActionKind::ProcessExec,
                RiskLevel::High,
            ),
            Self::FileOpen => (
                ExecutionSurface::Filesystem,
                ActionKind::FileOpen,
                RiskLevel::Low,
            ),
            Self::FileRead => (
                ExecutionSurface::Filesystem,
                ActionKind::FileRead,
                RiskLevel::Low,
            ),
            Self::FileMutation => (
                ExecutionSurface::Filesystem,
                ActionKind::FileMutation,
                RiskLevel::Medium,
            ),
            // Runtime classifies portable socket connects as medium risk.
            Self::SocketConnect => (
                ExecutionSurface::Network,
                ActionKind::NetworkRequest,
                RiskLevel::Medium,
            ),
        };

        RuntimeEvent {
            id: EventId::new(format!("static-{}", self.as_str())),
            session_id: SessionId::new("static-policy-image"),
            actor: ActorIdentity {
                id: String::from("runtime-policy-admission"),
                kind: ActorKind::System,
            },
            surface,
            action,
            target: None,
            payload: serde_json::Value::Null,
            risk: RiskMetadata {
                level: risk,
                reasons: vec![self.as_str().to_owned()],
            },
            timestamp: String::from("policy-admission"),
        }
    }
}

impl std::fmt::Display for PortableEffectClass {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum PolicyEffectDecision {
    Allow,
    Deny {
        rule_id: Option<String>,
        reason: String,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RuntimePolicyImage {
    decisions: [(PortableEffectClass, PolicyEffectDecision); 5],
    digest: ContentDigest,
}

impl RuntimePolicyImage {
    pub(crate) fn compile(
        policy_identity: impl Into<String>,
        revisions: Vec<PolicyPackageRevision>,
    ) -> Result<Self, RuntimePolicyImageError> {
        let policy_identity = policy_identity.into();
        if policy_identity.is_empty() {
            return Err(RuntimePolicyImageError::MissingPolicyIdentity);
        }
        if revisions.is_empty() {
            return Err(RuntimePolicyImageError::MissingPolicyPackages);
        }
        let policies = compile_layers(revisions)?;
        let [process_exec, file_open, file_read, file_mutation, socket_connect] =
            PortableEffectClass::ORDERED;
        let decisions = [
            evaluate(&policies, process_exec)?,
            evaluate(&policies, file_open)?,
            evaluate(&policies, file_read)?,
            evaluate(&policies, file_mutation)?,
            evaluate(&policies, socket_connect)?,
        ];
        let digest = image_digest(&policy_identity, &decisions);

        Ok(Self { decisions, digest })
    }

    #[must_use]
    pub(crate) const fn digest(&self) -> &ContentDigest {
        &self.digest
    }

    /// Returns all decisions in the stable image encoding order.
    pub(crate) fn decisions(
        &self,
    ) -> impl ExactSizeIterator<Item = (PortableEffectClass, &PolicyEffectDecision)> {
        self.decisions
            .iter()
            .map(|(effect_class, decision)| (*effect_class, decision))
    }
}

#[derive(Debug, Snafu)]
pub(crate) enum RuntimePolicyImageError {
    #[snafu(display("static policy image has no policy identity"))]
    MissingPolicyIdentity,
    #[snafu(display("static policy image has no policy packages"))]
    MissingPolicyPackages,
    #[snafu(display("policy package `{package}` rule `{rule}` is not UTF-8: {source}"))]
    RuleEncoding {
        package: String,
        rule: String,
        source: Utf8Error,
    },
    #[snafu(display("policy package `{package}` rule `{rule}` is invalid: {source}"))]
    InvalidRule {
        package: String,
        rule: String,
        #[snafu(source(from(PolicyError, Box::new)))]
        source: Box<PolicyError>,
    },
    #[snafu(display("{effect_class} rule `{rule_id}` cannot be lowered: {reason}"))]
    DynamicMatcher {
        effect_class: PortableEffectClass,
        rule_id: String,
        reason: String,
    },
    #[snafu(display("{effect_class} has no decision in mandatory layer `{layer}`: {reason}"))]
    MissingCoverage {
        effect_class: PortableEffectClass,
        layer: String,
        reason: String,
    },
    #[snafu(display("{effect_class} cannot use `{decision}` from rules {rule_ids:?}: {reason}"))]
    UnsupportedDecision {
        effect_class: PortableEffectClass,
        decision: &'static str,
        rule_ids: Vec<String>,
        reason: String,
    },
    #[snafu(display("{effect_class} static policy evaluation failed: {reason}"))]
    Evaluation {
        effect_class: PortableEffectClass,
        reason: String,
    },
}

fn compile_layers(
    revisions: Vec<PolicyPackageRevision>,
) -> Result<LayeredPolicySet, RuntimePolicyImageError> {
    let mut layers = Vec::with_capacity(revisions.len());
    for revision in revisions {
        let package = revision.manifest().name().to_owned();
        let mut policies = Vec::with_capacity(revision.rules().len());
        for (rule, source) in revision.rules() {
            let source = std::str::from_utf8(source).map_err(|source| {
                RuntimePolicyImageError::RuleEncoding {
                    package: package.clone(),
                    rule: rule.clone(),
                    source,
                }
            })?;
            policies.push(LocalPolicy::from_json_str(source).map_err(|source| {
                RuntimePolicyImageError::InvalidRule {
                    package: package.clone(),
                    rule: rule.clone(),
                    source: Box::new(source),
                }
            })?);
        }
        layers.push(PolicyLayer::mandatory(
            package,
            PolicySet::from_policies(policies),
        ));
    }
    Ok(LayeredPolicySet::new(layers))
}

fn evaluate(
    policies: &LayeredPolicySet,
    effect_class: PortableEffectClass,
) -> Result<(PortableEffectClass, PolicyEffectDecision), RuntimePolicyImageError> {
    let decision = match policies.evaluate_static(&effect_class.event()) {
        Ok(decision) => decision,
        Err(PolicyError::StaticEvaluationUnsupported {
            rule_id, reason, ..
        }) => {
            return Err(RuntimePolicyImageError::DynamicMatcher {
                effect_class,
                rule_id,
                reason,
            });
        }
        Err(PolicyError::MissingMandatoryCoverage { layer, .. }) => {
            return Err(RuntimePolicyImageError::MissingCoverage {
                effect_class,
                reason: format!("mandatory layer `{layer}` has no matching static rule"),
                layer,
            });
        }
        Err(error) => {
            return Err(RuntimePolicyImageError::Evaluation {
                effect_class,
                reason: error.to_string(),
            });
        }
    };

    let decision = match decision {
        LayeredDecision::Allow => PolicyEffectDecision::Allow,
        LayeredDecision::Deny { reason, rule_id } => PolicyEffectDecision::Deny { rule_id, reason },
        LayeredDecision::RequireApproval {
            reason, rule_ids, ..
        } => {
            return Err(RuntimePolicyImageError::UnsupportedDecision {
                effect_class,
                decision: "require_approval",
                rule_ids,
                reason: format!(
                    "{reason}; the static policy image cannot represent an approval flow"
                ),
            });
        }
        LayeredDecision::Mediate {
            reason, rule_ids, ..
        } => {
            return Err(RuntimePolicyImageError::UnsupportedDecision {
                effect_class,
                decision: "mediate",
                rule_ids,
                reason: format!(
                    "{reason}; the static policy image cannot represent a mediated effect"
                ),
            });
        }
    };
    Ok((effect_class, decision))
}

fn image_digest(
    policy_identity: &str,
    decisions: &[(PortableEffectClass, PolicyEffectDecision); 5],
) -> ContentDigest {
    let mut bytes = Vec::new();
    append_bytes(&mut bytes, IMAGE_FORMAT);
    append_bytes(&mut bytes, policy_identity.as_bytes());
    for (effect_class, decision) in decisions {
        append_bytes(&mut bytes, effect_class.as_str().as_bytes());
        match decision {
            PolicyEffectDecision::Allow => bytes.push(0),
            PolicyEffectDecision::Deny { rule_id, reason } => {
                bytes.push(1);
                match rule_id {
                    Some(rule_id) => {
                        bytes.push(1);
                        append_bytes(&mut bytes, rule_id.as_bytes());
                    }
                    None => bytes.push(0),
                }
                append_bytes(&mut bytes, reason.as_bytes());
            }
        }
    }
    ContentDigest::from_canonical_bytes(&bytes)
}

fn append_bytes(output: &mut Vec<u8>, value: &[u8]) {
    output.extend_from_slice(&(value.len() as u64).to_be_bytes());
    output.extend_from_slice(value);
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use erebor_runtime_packages::PolicyPackageRevision;

    use super::{
        PolicyEffectDecision, PortableEffectClass, RuntimePolicyImage, RuntimePolicyImageError,
    };

    const ALLOW_ALL_CLASSES: &str = r#"{
        "rules": [
            {"id":"exec","match":{"surface":"terminal","action":"process_exec","risk_at_least":"high"},"decision":"allow"},
            {"id":"open-higher-risk","match":{"surface":"filesystem","action":"file_open","risk_at_least":"medium"},"decision":"deny"},
            {"id":"open","match":{"surface":"filesystem","action":"file_open","risk_at_least":"low"},"decision":"allow"},
            {"id":"read-higher-risk","match":{"surface":"filesystem","action":"file_read","risk_at_least":"medium"},"decision":"deny"},
            {"id":"read","match":{"surface":"filesystem","action":"file_read","risk_at_least":"low"},"decision":"allow"},
            {"id":"mutation-higher-risk","match":{"surface":"filesystem","action":"file_mutation","risk_at_least":"high"},"decision":"deny"},
            {"id":"mutation","match":{"surface":"filesystem","action":"file_mutation","risk_at_least":"medium"},"decision":"allow"},
            {"id":"connect-higher-risk","match":{"surface":"network","action":"network_request","risk_at_least":"high"},"decision":"deny"},
            {"id":"connect","match":{"surface":"network","action":"network_request","risk_at_least":"medium"},"decision":"allow"}
        ]
    }"#;

    fn revision(
        name: &str,
        source: &str,
    ) -> Result<PolicyPackageRevision, Box<dyn std::error::Error>> {
        Ok(PolicyPackageRevision::new(
            name,
            format!("name = \"{name}\"\n").into_bytes(),
            BTreeMap::from([(String::from("effects.json"), source.as_bytes().to_vec())]),
            BTreeMap::new(),
            BTreeMap::from([(String::from("effects.json"), b"{}".to_vec())]),
            format!("# {name}\n").into_bytes(),
        )?)
    }

    fn compile_error(source: &str) -> Result<RuntimePolicyImageError, Box<dyn std::error::Error>> {
        match RuntimePolicyImage::compile("policy-set-1", vec![revision("host", source)?]) {
            Ok(_) => Err("policy image compilation unexpectedly succeeded".into()),
            Err(error) => Ok(error),
        }
    }

    #[test]
    fn compiles_all_portable_effect_classes() -> Result<(), Box<dyn std::error::Error>> {
        let image = RuntimePolicyImage::compile(
            "policy-set-1",
            vec![revision("host", ALLOW_ALL_CLASSES)?],
        )?;

        let decisions = image.decisions().collect::<Vec<_>>();
        assert_eq!(
            decisions
                .iter()
                .map(|(effect_class, _)| *effect_class)
                .collect::<Vec<_>>(),
            PortableEffectClass::ORDERED
        );
        assert!(decisions
            .iter()
            .all(|(_, decision)| matches!(decision, PolicyEffectDecision::Allow)));
        Ok(())
    }

    #[test]
    fn rejects_empty_policy_inputs() -> Result<(), Box<dyn std::error::Error>> {
        let identity_error =
            match RuntimePolicyImage::compile("", vec![revision("host", ALLOW_ALL_CLASSES)?]) {
                Ok(_) => return Err("an empty policy identity was accepted".into()),
                Err(error) => error,
            };
        let packages_error = match RuntimePolicyImage::compile("policy-set-1", Vec::new()) {
            Ok(_) => return Err("an empty policy package set was accepted".into()),
            Err(error) => error,
        };

        assert!(matches!(
            identity_error,
            RuntimePolicyImageError::MissingPolicyIdentity
        ));
        assert!(matches!(
            packages_error,
            RuntimePolicyImageError::MissingPolicyPackages
        ));
        Ok(())
    }

    #[test]
    fn mandatory_deny_overrides_another_layer_allow() -> Result<(), Box<dyn std::error::Error>> {
        let denying = r#"{
            "rules": [
                {"id":"deny-exec","match":{"surface":"terminal","action":"process_exec"},"decision":"deny","reason":"host minimum"},
                {"id":"remaining-effects","match":{"risk_at_least":"unknown"},"decision":"allow"}
            ]
        }"#;
        let image = RuntimePolicyImage::compile(
            "policy-set-1",
            vec![
                revision("workspace", ALLOW_ALL_CLASSES)?,
                revision("host", denying)?,
            ],
        )?;

        assert_eq!(
            image.decisions().next(),
            Some((
                PortableEffectClass::ProcessExec,
                &PolicyEffectDecision::Deny {
                    rule_id: Some(String::from("deny-exec")),
                    reason: String::from("host minimum"),
                },
            ))
        );
        Ok(())
    }

    #[test]
    fn rejects_each_reachable_dynamic_matcher() -> Result<(), Box<dyn std::error::Error>> {
        for field in ["target_contains", "payload_contains", "command_contains"] {
            let source = format!(
                r#"{{"rules":[{{"id":"dynamic","match":{{"surface":"terminal","{field}":"needle"}},"decision":"deny"}}]}}"#
            );
            let error = compile_error(&source)?;

            assert!(matches!(
                error,
                RuntimePolicyImageError::DynamicMatcher {
                    effect_class: PortableEffectClass::ProcessExec,
                    ref rule_id,
                    ref reason,
                } if rule_id == "dynamic" && reason.contains(field)
            ));
        }
        Ok(())
    }

    #[test]
    fn rejects_approval_and_mediation() -> Result<(), Box<dyn std::error::Error>> {
        for decision in ["require_approval", "mediate"] {
            let source = format!(
                r#"{{"rules":[{{"id":"unsupported","match":{{"surface":"terminal"}},"decision":"{decision}","reason":"needs another owner"}}]}}"#
            );
            let error = compile_error(&source)?;
            let expected_reason = match decision {
                "require_approval" => "needs another owner",
                "mediate" => "cannot represent a mediated effect",
                _ => return Err("test has an unsupported decision fixture".into()),
            };

            assert!(matches!(
                error,
                RuntimePolicyImageError::UnsupportedDecision {
                    effect_class: PortableEffectClass::ProcessExec,
                    decision: actual,
                    ref rule_ids,
                    ref reason,
                } if actual == decision
                    && rule_ids == &[String::from("unsupported")]
                    && reason.contains(expected_reason)
            ));
        }
        Ok(())
    }

    #[test]
    fn rejects_missing_mandatory_coverage() -> Result<(), Box<dyn std::error::Error>> {
        let source =
            r#"{"rules":[{"id":"exec","match":{"surface":"terminal"},"decision":"allow"}]}"#;
        let error = compile_error(source)?;

        assert!(matches!(
            error,
            RuntimePolicyImageError::MissingCoverage {
                effect_class: PortableEffectClass::FileOpen,
                ref layer,
                ref reason,
            } if layer == "host" && reason.contains("no matching static rule")
        ));
        Ok(())
    }

    #[test]
    fn image_digest_is_stable_and_binds_policy_identity() -> Result<(), Box<dyn std::error::Error>>
    {
        let first = RuntimePolicyImage::compile(
            "policy-set-1",
            vec![revision("host", ALLOW_ALL_CLASSES)?],
        )?;
        let second = RuntimePolicyImage::compile(
            "policy-set-1",
            vec![revision("host", ALLOW_ALL_CLASSES)?],
        )?;
        let different_identity = RuntimePolicyImage::compile(
            "policy-set-2",
            vec![revision("host", ALLOW_ALL_CLASSES)?],
        )?;
        let deny_exec = ALLOW_ALL_CLASSES.replacen(
            r#""id":"exec","match":{"surface":"terminal","action":"process_exec","risk_at_least":"high"},"decision":"allow""#,
            r#""id":"exec","match":{"surface":"terminal","action":"process_exec","risk_at_least":"high"},"decision":"deny""#,
            1,
        );
        let different_decision =
            RuntimePolicyImage::compile("policy-set-1", vec![revision("host", &deny_exec)?])?;

        assert_eq!(first.digest(), second.digest());
        assert_ne!(first.digest(), different_identity.digest());
        assert_ne!(first.digest(), different_decision.digest());
        assert_eq!(first.digest().as_str().len(), 64);
        Ok(())
    }
}
