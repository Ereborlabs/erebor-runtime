use std::sync::Arc;
use std::time::Duration;

use araphor_data::analysis::{PackageActivationV1, PackageResultRefV1};
use araphor_data::{
    AnalysisReadControl, InstalledContext, PackageErrorCodeV1, PackageGrantV1, ResultContext,
};
use snafu::ResultExt as _;

use super::{InputSet, Inputs};
use crate::execution::Engine;
use crate::follow::Clock;
use crate::memory::Memory;
use crate::stream::progress::{Progress, Wake};
use crate::Result;

pub struct InputOperation {
    inputs: Arc<Inputs>,
    engine: Arc<Engine>,
    memory: Arc<Memory>,
    active: PackageActivationV1,
    grant: PackageGrantV1,
    progress: Progress,
    control: Arc<AnalysisReadControl>,
    pending: Option<Arc<InputSet>>,
    model_clock: bool,
    offered: bool,
    ready: bool,
    ended: bool,
    now: u64,
    witness: u64,
    clock_changed: bool,
}

impl Drop for InputOperation {
    fn drop(&mut self) {
        let _cancelled = self.control.cancel();
    }
}

impl Inputs {
    pub fn watch(
        self: &Arc<Self>,
        engine: Arc<Engine>,
        active: PackageActivationV1,
        clock: Arc<dyn Clock>,
        model_clock: bool,
    ) -> Result<InputOperation> {
        let installed: InstalledContext =
            serde_json::from_slice(&active.metadata).context(araphor_data::PackageEncodingSnafu)?;
        if !active.active || installed.grant.selection.tenant_id != active.key.tenant_id {
            return Err(PackageErrorCodeV1::Denied
                .error("live input activation")
                .into());
        }
        let mut progress = Progress::new(engine.store(), clock, None);
        let now = progress.begin()?;
        let control = InputOperation::stage(&installed.grant, now, None)?;
        let memory = engine.memory().scope();
        Ok(InputOperation {
            inputs: Arc::clone(self),
            engine,
            memory,
            active,
            grant: installed.grant,
            progress,
            control,
            pending: None,
            model_clock,
            offered: false,
            ready: true,
            ended: false,
            now,
            witness: u64::MAX,
            clock_changed: false,
        })
    }
}

impl InputOperation {
    fn stage(
        grant: &PackageGrantV1,
        now: u64,
        parent: Option<&AnalysisReadControl>,
    ) -> Result<Arc<AnalysisReadControl>> {
        let timeout = grant
            .expires_utc_ns
            .map_or(Duration::from_secs(30), |expiry| {
                Duration::from_nanos(expiry.saturating_sub(now)).min(Duration::from_secs(30))
            });
        if timeout.is_zero() {
            return Err(PackageErrorCodeV1::Denied
                .error("live input grant expired")
                .into());
        }
        Ok(Arc::new(match parent {
            Some(parent) => parent.stage(timeout)?,
            None => AnalysisReadControl::with_timeout(timeout)?,
        }))
    }

    pub fn activation(&self) -> &PackageActivationV1 {
        &self.active
    }

    pub fn now(&self) -> u64 {
        self.now
    }

    pub fn control(&self) -> &Arc<AnalysisReadControl> {
        &self.control
    }

    pub fn memory(&self) -> &Arc<Memory> {
        &self.memory
    }

    pub fn retry(&mut self) {
        self.ready = true;
    }

    pub async fn changed(&mut self) -> Result<()> {
        let deadline = self
            .grant
            .expires_utc_ns
            .unwrap_or(u64::MAX)
            .min(self.witness);
        self.clock_changed |= matches!(
            self.progress
                .next(&self.control, (deadline != u64::MAX).then_some(deadline),)
                .await?,
            Wake::Clock
        );
        self.ready = true;
        Ok(())
    }

    async fn current(&mut self) -> Result<bool> {
        let store = Arc::clone(self.engine.store());
        let active = self.active.clone();
        let control = Arc::clone(&self.control);
        let current = Engine::blocking(Arc::clone(&control), (), move || {
            Ok(store.package_activation_until(&active.key, &control)? == Some(active))
        })
        .await?;
        self.ended = !current;
        Ok(current)
    }

    async fn saved(&self, now: u64, changed: bool) -> Result<Option<(ResultContext, u64)>> {
        let store = Arc::clone(self.engine.store());
        let active = self.active.clone();
        let control = Arc::clone(&self.control);
        Engine::blocking(Arc::clone(&control), (), move || {
            store
                .package_current(&active, now, changed, &control)?
                .map(|(body, deadline)| {
                    let saved = serde_json::from_slice(&body)
                        .context(araphor_data::PackageEncodingSnafu)?;
                    Ok((saved, deadline))
                })
                .transpose()
        })
        .await
    }

    async fn valid(&mut self, now: u64) -> Result<bool> {
        if self
            .grant
            .expires_utc_ns
            .is_some_and(|expiry| expiry <= now)
        {
            return Err(PackageErrorCodeV1::Denied
                .error("live input grant expired")
                .into());
        }
        self.progress.observe();
        let Some(input) = self.pending.as_ref() else {
            return Ok(false);
        };
        let Some(snapshot) = input.snapshot.as_ref() else {
            return Ok(true);
        };
        let captured = Arc::clone(input);
        let snapshot = Arc::clone(snapshot);
        let store = Arc::clone(self.engine.store());
        let active = self.active.clone();
        let control = Arc::clone(&self.control);
        let deadline = Engine::blocking(Arc::clone(&control), (), move || {
            store
                .package_input_current(
                    &active,
                    &snapshot.selection,
                    &snapshot.page.extraction,
                    captured.witnesses(),
                    now,
                    &control,
                )
                .map_err(crate::Error::from)
        })
        .await?;
        self.ready |= self.progress.pending();
        if let Some(deadline) = deadline {
            self.witness = deadline;
            return Ok(true);
        }
        Ok(false)
    }

    pub async fn next(&mut self) -> Result<Option<Arc<InputSet>>> {
        loop {
            if self.ended {
                return Ok(None);
            }
            if !self.ready {
                self.changed().await?;
            }
            self.ready = false;
            let now = self.progress.now()?;
            self.control = Self::stage(&self.grant, now, Some(&self.control))?;
            let clock_changed = !self.offered && self.clock_changed;
            if !self.offered
                && self.pending.is_some()
                && (self.progress.expired(now) || (self.inputs.clock && clock_changed))
            {
                self.pending = None;
                self.witness = u64::MAX;
                self.progress.clear();
            }
            if !self.offered && clock_changed && self.model_clock {
                self.now = now;
            }
            if self.pending.is_none() {
                if !self.current().await? {
                    return Ok(None);
                }
                self.progress.observe();
                if let Some((saved, deadline)) = self.saved(now, true).await? {
                    if !self.inputs.clock && (!clock_changed || !self.model_clock) {
                        self.now = saved.context.time_utc_ns as u64;
                        self.witness = deadline;
                        self.ready = self.progress.pending();
                        continue;
                    }
                }
                let now = self.progress.begin()?;
                let session = self.engine.session_on(
                    self.grant.selection.clone(),
                    &self.control,
                    now,
                    Arc::clone(&self.memory),
                )?;
                let input = self
                    .inputs
                    .execute(
                        Arc::clone(&self.engine),
                        session,
                        self.active.key.scope_id.clone(),
                        now,
                    )
                    .await?;
                self.now = now;
                if let Some(snapshot) = &input.snapshot {
                    self.progress
                        .captured(snapshot.page.extraction.meta.commit_revision, input.expiry);
                    self.ready |= self.progress.pending();
                }
                self.pending = Some(input);
            } else if self
                .pending
                .as_ref()
                .is_some_and(|input| input.snapshot.is_none())
                && !self.current().await?
            {
                return Ok(None);
            }
            if !self.offered {
                self.clock_changed = false;
            }
            let checked = self.progress.now()?;
            if !self.valid(checked).await? {
                if !self.current().await? {
                    return Ok(None);
                }
                self.pending = None;
                self.offered = false;
                self.witness = u64::MAX;
                self.progress.clear();
                self.ready = true;
                continue;
            }
            if self.offered {
                return Ok(self.pending.as_ref().map(Arc::clone));
            }
            if let Some((saved, deadline)) = self.saved(checked, false).await? {
                if self
                    .pending
                    .as_ref()
                    .is_some_and(|input| saved.matches(&input.inputs))
                    && (!self.model_clock || saved.context.time_utc_ns == self.now as i64)
                {
                    self.now = saved.context.time_utc_ns as u64;
                    self.witness = self.witness.min(deadline);
                    continue;
                }
            }
            self.offered = true;
            return Ok(self.pending.as_ref().map(Arc::clone));
        }
    }

    pub async fn complete(&mut self, receipt: &PackageResultRefV1) -> Result<()> {
        let input = self
            .pending
            .as_ref()
            .filter(|_| self.offered)
            .ok_or_else(|| {
                PackageErrorCodeV1::Conflict.error("live input completion without an offer")
            })?;
        self.control = Self::stage(&self.grant, self.progress.now()?, Some(&self.control))?;
        self.control.check()?;
        let store = Arc::clone(self.engine.store());
        let before = self.active.clone();
        let receipt = receipt.clone();
        let control = Arc::clone(&self.control);
        let completed = Engine::blocking(Arc::clone(&control), (), move || {
            store
                .package_completed(&before, &receipt, &control)
                .map_err(crate::Error::from)
        })
        .await?;
        let Some((active, body)) = completed else {
            return Err(PackageErrorCodeV1::Conflict
                .error("live input completion receipt")
                .into());
        };
        let saved: ResultContext =
            serde_json::from_slice(&body).context(araphor_data::PackageEncodingSnafu)?;
        if !saved.matches(&input.inputs) || saved.context.time_utc_ns != self.now as i64 {
            return Err(PackageErrorCodeV1::Conflict
                .error("live input completion metadata")
                .into());
        }
        self.active = active;
        self.offered = false;
        self.ready = true;
        Ok(())
    }
}

#[cfg(test)]
mod tests;
