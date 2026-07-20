use std::{
    sync::Mutex,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use sha2::{Digest, Sha256};

use crate::{
    error::session_output::{
        InvalidLeaseDurationSnafu, LeaseNotOwnedSnafu, LeaseUnavailableSnafu, StateLockSnafu,
    },
    SessionOutputError,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InputLease {
    lease_id: String,
    client_id: String,
    expires_unix_ms: u64,
}

impl InputLease {
    #[must_use]
    pub fn lease_id(&self) -> &str {
        &self.lease_id
    }

    #[must_use]
    pub fn client_id(&self) -> &str {
        &self.client_id
    }

    #[must_use]
    pub const fn expires_unix_ms(&self) -> u64 {
        self.expires_unix_ms
    }
}

pub struct InputLeaseManager {
    session_id: String,
    state: Mutex<Option<InputLease>>,
}

impl InputLeaseManager {
    #[must_use]
    pub fn new(session_id: impl Into<String>) -> Self {
        Self {
            session_id: session_id.into(),
            state: Mutex::new(None),
        }
    }

    pub fn acquire(
        &self,
        client_id: &str,
        duration: Duration,
    ) -> Result<InputLease, SessionOutputError> {
        let now = unix_time_ms();
        let expires_unix_ms = expiration(now, duration)?;
        let mut state = self.lock()?;
        if state
            .as_ref()
            .is_some_and(|lease| lease.expires_unix_ms > now && lease.client_id != client_id)
        {
            return LeaseUnavailableSnafu.fail();
        }
        if let Some(lease) = state
            .as_mut()
            .filter(|lease| lease.expires_unix_ms > now && lease.client_id == client_id)
        {
            lease.expires_unix_ms = expires_unix_ms;
            return Ok(lease.clone());
        }
        let lease = InputLease {
            lease_id: lease_id(&self.session_id, client_id, now),
            client_id: client_id.to_owned(),
            expires_unix_ms,
        };
        *state = Some(lease.clone());
        Ok(lease)
    }

    pub fn renew(
        &self,
        lease_id: &str,
        client_id: &str,
        duration: Duration,
    ) -> Result<InputLease, SessionOutputError> {
        let now = unix_time_ms();
        let expires_unix_ms = expiration(now, duration)?;
        let mut state = self.lock()?;
        let Some(lease) = state.as_mut().filter(|lease| {
            lease.expires_unix_ms > now
                && lease.lease_id == lease_id
                && lease.client_id == client_id
        }) else {
            return LeaseNotOwnedSnafu {
                lease_id: lease_id.to_owned(),
                client_id: client_id.to_owned(),
            }
            .fail();
        };
        lease.expires_unix_ms = expires_unix_ms;
        Ok(lease.clone())
    }

    pub fn release(&self, lease_id: &str, client_id: &str) -> Result<(), SessionOutputError> {
        let mut state = self.lock()?;
        let Some(lease) = state.as_ref() else {
            return LeaseNotOwnedSnafu {
                lease_id: lease_id.to_owned(),
                client_id: client_id.to_owned(),
            }
            .fail();
        };
        if lease.lease_id != lease_id || lease.client_id != client_id {
            return LeaseNotOwnedSnafu {
                lease_id: lease_id.to_owned(),
                client_id: client_id.to_owned(),
            }
            .fail();
        }
        *state = None;
        Ok(())
    }

    pub fn current(&self) -> Result<Option<InputLease>, SessionOutputError> {
        let now = unix_time_ms();
        let mut state = self.lock()?;
        if state
            .as_ref()
            .is_some_and(|lease| lease.expires_unix_ms <= now)
        {
            *state = None;
        }
        Ok(state.clone())
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, Option<InputLease>>, SessionOutputError> {
        self.state.lock().map_err(|_error| {
            StateLockSnafu {
                stream: format!("{}:input", self.session_id),
            }
            .build()
        })
    }
}

fn expiration(now: u64, duration: Duration) -> Result<u64, SessionOutputError> {
    let duration_ms = u64::try_from(duration.as_millis()).unwrap_or(u64::MAX);
    if duration_ms == 0 {
        InvalidLeaseDurationSnafu.fail()
    } else {
        Ok(now.saturating_add(duration_ms))
    }
}

fn lease_id(session_id: &str, client_id: &str, now: u64) -> String {
    let mut digest = Sha256::new();
    digest.update(b"erebor.session.input-lease.v1\0");
    digest.update(session_id.as_bytes());
    digest.update([0]);
    digest.update(client_id.as_bytes());
    digest.update(now.to_le_bytes());
    digest
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn unix_time_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(1, |duration| duration.as_millis() as u64)
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::InputLeaseManager;

    #[test]
    fn one_client_owns_the_renewable_input_lease() -> Result<(), Box<dyn std::error::Error>> {
        let manager = InputLeaseManager::new("session-1");
        let first = manager.acquire("client-a", Duration::from_secs(5))?;

        assert!(manager.acquire("client-b", Duration::from_secs(5)).is_err());
        let renewed =
            manager.renew(first.lease_id(), first.client_id(), Duration::from_secs(10))?;
        assert!(renewed.expires_unix_ms() >= first.expires_unix_ms());
        manager.release(first.lease_id(), first.client_id())?;
        assert!(manager.acquire("client-b", Duration::from_secs(5)).is_ok());
        Ok(())
    }
}
