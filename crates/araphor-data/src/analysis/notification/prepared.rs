use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use super::*;

use crate::analysis::managed::PreparedMemory;
use crate :: { AnalysisReadControl , ApprovedNotificationRouteV1 , FindingV1 , GraphRevisionV1 , ManagedBudget , NotificationErrorCodeV1 as Code , NotificationFindingRefV1 , NotificationKeyV1 , NotificationRouteRefV1 , NOTIFICATION_ROUTE_OWNER } ;


mod native;

type FindingKey = (String, String);

#[derive(Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
enum ReadOwner {
    Heads,
    Routes,
    Finding,
    Basis,
    Related,
    State,
    Subject,
    Route,
}

struct FindingValue {
    finding: FindingV1,
    revision: Option<Arc<GraphRevisionV1>>,
    canonical: Option<u64>,
}

pub struct PreparedNotificationBatch<'a> {
    memory: PreparedMemory<'a>,
    failed: bool,
    errors: BTreeMap<(ReadOwner, String, String), Arc<crate::Error>>,
    comparisons: BTreeMap<(FindingKey, FindingKey), bool>,
    comparison_errors: BTreeMap<(FindingKey, FindingKey), Arc<crate::Error>>,
    heads: BTreeMap<String, String>,
    findings: BTreeMap<FindingKey, FindingValue>,
    routes: Vec<ApprovedNotificationRouteV1>,
    versions: BTreeMap<String, BTreeMap<u64, ApprovedNotificationRouteV1>>,
    states: BTreeMap<NotificationKeyV1, (NotificationObligationV1, usize)>,
    subjects: BTreeMap<(NotificationKeyV1, u64), NotificationObligationV1>,
}

impl<'a> PreparedNotificationBatch<'a> {
    fn new(control: &'a AnalysisReadControl, budget: &'a dyn ManagedBudget) -> Result<Self> {
        Ok(Self {
            memory: PreparedMemory::new(control, budget)?,
            failed: false,
            errors: BTreeMap::new(),
            comparisons: BTreeMap::new(),
            comparison_errors: BTreeMap::new(),
            heads: BTreeMap::new(),
            findings: BTreeMap::new(),
            routes: Vec::new(),
            versions: BTreeMap::new(),
            states: BTreeMap::new(),
            subjects: BTreeMap::new(),
        })
    }

    fn charge_inputs(
        &mut self,
        references: &[NotificationFindingRefV1],
        keys: &[NotificationKeyV1],
    ) -> Result<()> {
        let bytes = references
            .iter()
            .try_fold(0usize, |bytes, reference| {
                bytes
                    .checked_add(
                        reference
                            .finding_id
                            .len()
                            .saturating_add(reference.result_id.len())
                            .saturating_mul(12),
                    )
                    .and_then(|bytes| bytes.checked_add(12 * size_of::<FindingKey>()))
            })
            .and_then(|bytes| {
                bytes.checked_add(
                    keys.len()
                        .saturating_mul(12 * size_of::<NotificationKeyV1>()),
                )
            })
            .ok_or_else(|| crate::PackageErrorCodeV1::Limit.error("notification request memory"))?;
        self.charge(bytes)
    }

    fn insert_state(&mut self, context: AnalysisContextVersionV1) -> Result<()> {
        let state = NotificationObligationV1::try_from(&context)?;
        self.states.insert(state.key, (state, context.body.len()));
        Ok(())
    }

    pub fn charge(&mut self, bytes: usize) -> Result<()> {
        let result = self.memory.charge(bytes);
        self.failed |= result.is_err();
        result
    }

    pub fn check_related(&self, reference: &NotificationFindingRefV1) -> Result<()> {
        self.failure(
            ReadOwner::Related,
            &reference.result_id,
            &reference.finding_id,
        )
    }

    pub fn check_state(&self, key: NotificationKeyV1) -> Result<()> {
        self.failure(
            ReadOwner::State,
            &uuid::Uuid::from_bytes(key.notification_id).to_string(),
            "",
        )
    }

    pub fn heads(&self) -> &BTreeMap<String, String> {
        &self.heads
    }

    fn failure(&self, kind: ReadOwner, owner: &str, id: &str) -> Result<()> {
        if let Some((_, error)) = self
            .errors
            .iter()
            .find(|((tag, key, value), _)| *tag == kind && key == owner && value == id)
        {
            return Err(crate::Error::PreparedNotification {
                source: Arc::clone(error),
            });
        }
        Ok(())
    }

    fn capture<T>(
        &mut self,
        result: Result<T>,
        kind: ReadOwner,
        owner: &str,
        id: &str,
    ) -> Result<Option<T>> {
        match result {
            Ok(value) => Ok(Some(value)),
            Err(error) => {
                let source = self.share(error, owner, id)?;
                self.errors.insert((kind, owner.into(), id.into()), source);
                Ok(None)
            }
        }
    }

    fn share(&mut self, error: crate::Error, owner: &str, id: &str) -> Result<Arc<crate::Error>> {
        self.memory.check()?;
        if self.failed
            || matches!(
                error.unprepared(),
                crate::Error::AnalysisReadCancelled { .. }
                    | crate::Error::AnalysisReadDeadline { .. }
                    | crate::Error::AnalysisInputTooLarge { .. }
                    | crate::Error::StorageCapacity { .. }
                    | crate::Error::ProtectedInputCapacity { .. }
                    | crate::Error::Package {
                        code: crate::PackageErrorCodeV1::Limit,
                        ..
                    }
                    | crate::Error::Notification {
                        code: Code::Limit,
                        ..
                    }
            )
        {
            return Err(error);
        }
        self.charge(
            owner
                .len()
                .saturating_add(id.len())
                .saturating_add(8 * size_of::<Arc<crate::Error>>()),
        )?;
        Ok(match error {
            crate::Error::PreparedNotification { source } => source,
            error => Arc::new(error),
        })
    }

    fn value(&self, reference: &NotificationFindingRefV1) -> Option<&FindingValue> {
        self.findings
            .iter()
            .find(|((result, id), _)| result == &reference.result_id && id == &reference.finding_id)
            .map(|(_, value)| value)
    }

    pub fn finding(&self, reference: &NotificationFindingRefV1) -> Result<&FindingV1> {
        Code::Invalid.require(
            NotificationGrantV1::identifier(&reference.finding_id, usize::MAX)
                && NotificationGrantV1::identifier(&reference.result_id, usize::MAX),
            "finding reference",
        )?;
        self.failure(ReadOwner::Heads, "", "")?;
        let current = self.heads.get(&reference.finding_id).ok_or_else(|| {
            crate::NotificationSnafu {
                code: Code::Denied,
                field: "current finding scope",
            }
            .build()
        })?;
        Code::Conflict.require(current == &reference.result_id, "current finding reference")?;
        self.failure(
            ReadOwner::Finding,
            &reference.result_id,
            &reference.finding_id,
        )?;
        self.value(reference)
            .map(|value| &value.finding)
            .ok_or_else(|| {
                crate::NotificationSnafu {
                    code: Code::Denied,
                    field: "current finding scope",
                }
                .build()
                .into()
            })
    }

    pub fn historical(
        &self,
        reference: &NotificationFindingRefV1,
    ) -> Result<Option<(&FindingV1, &GraphRevisionV1)>> {
        self.failure(
            ReadOwner::Finding,
            &reference.result_id,
            &reference.finding_id,
        )?;
        self.failure(
            ReadOwner::Basis,
            &reference.result_id,
            &reference.finding_id,
        )?;
        Ok(self.value(reference).and_then(|value| {
            value
                .revision
                .as_deref()
                .map(|revision| (&value.finding, revision))
        }))
    }

    pub fn changed(
        &self,
        reference: &NotificationFindingRefV1,
        prior: &NotificationFindingRefV1,
    ) -> Result<bool> {
        Code::Invalid.require(
            prior.finding_id == reference.finding_id
                && NotificationGrantV1::identifier(&prior.result_id, usize::MAX),
            "finding reference",
        )?;
        self.finding(reference)?;
        if prior.result_id == reference.result_id {
            return Ok(false);
        }
        let key = (
            (reference.result_id.clone(), reference.finding_id.clone()),
            (prior.result_id.clone(), prior.finding_id.clone()),
        );
        if let Some(error) = self.comparison_errors.get(&key) {
            return Err(crate::Error::PreparedNotification {
                source: Arc::clone(error),
            });
        }
        self.comparisons.get(&key).copied().ok_or_else(|| {
            crate::NotificationSnafu {
                code: Code::Denied,
                field: "prepared finding comparison",
            }
            .build()
            .into()
        })
    }

    pub fn routes(&self) -> Result<&[ApprovedNotificationRouteV1]> {
        self.failure(ReadOwner::Routes, "", "")?;
        Ok(&self.routes)
    }

    pub fn route(
        &self,
        reference: &NotificationRouteRefV1,
    ) -> Result<Option<&ApprovedNotificationRouteV1>> {
        self.failure(
            ReadOwner::Route,
            &reference.route_id,
            &reference.revision.to_string(),
        )?;
        Ok(self
            .versions
            .get(&reference.route_id)
            .and_then(|versions| versions.get(&reference.revision)))
    }

    pub fn states(&self) -> impl Iterator<Item = (&NotificationObligationV1, usize)> {
        self.states.values().map(|(state, bytes)| (state, *bytes))
    }

    pub fn subject(
        &self,
        key: NotificationKeyV1,
        revision: u64,
    ) -> Result<&NotificationObligationV1> {
        self.failure(
            ReadOwner::Subject,
            &uuid::Uuid::from_bytes(key.notification_id).to_string(),
            &revision.to_string(),
        )?;
        self.subjects.get(&(key, revision)).ok_or_else(|| {
            crate::NotificationSnafu {
                code: Code::Unavailable,
                field: "attempt finding revision",
            }
            .build()
            .into()
        })
    }
}


