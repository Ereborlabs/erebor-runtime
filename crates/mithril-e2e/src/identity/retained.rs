use std::collections::BTreeMap;
use std::fs;
use std::mem::size_of;
use std::path::{Path, PathBuf};

use erebor_interceptor::{
    Error as InterceptorError, KernelHost, KernelHostConfig, KernelHostOwner,
    KernelObjectManifestV1,
};
use libbpf_rs::{MapHandle, MapType};
use snafu::{ensure, ResultExt as _};

use super::invalid_state;
use crate::error::{InterceptorSnafu, InvalidInputSnafu, IoSnafu};
use crate::physical::{boot_identity, ProbeDirectory, ProbeFile};
use crate::Result;

pub(super) struct RetainedHost {
    host: Option<KernelHost>,
    config: KernelHostConfig,
    first: KernelObjectManifestV1,
    boot: String,
    pin: PathBuf,
    lease: PathBuf,
}

impl RetainedHost {
    pub(super) fn start(pin: &Path) -> Result<Self> {
        let lease = std::env::var_os("MITHRIL_TEST_LEASE")
            .map(PathBuf::from)
            .ok_or_else(|| invalid_state("MITHRIL_TEST_LEASE is not set"))?;
        let (boot, _) = boot_identity()?;
        let config = KernelHostConfig::identity(
            "/sys/kernel/btf/vmlinux",
            &lease,
            Some(pin.to_owned()),
            boot.clone(),
            1,
        );
        let host = KernelHostOwner::new(config.clone())
            .start()
            .context(InterceptorSnafu)?;
        let first = host.manifest().clone();
        Ok(Self {
            host: Some(host),
            config,
            first,
            boot,
            pin: pin.to_owned(),
            lease,
        })
    }

    fn host(&self) -> Result<&KernelHost> {
        self.host
            .as_ref()
            .ok_or_else(|| invalid_state("retained host is not running"))
    }

    pub(super) fn map_ids(&self) -> Result<BTreeMap<String, u32>> {
        Ok(self
            .host()?
            .manifest()
            .maps
            .iter()
            .map(|map| (map.name.clone(), map.id))
            .collect())
    }

    pub(super) fn reject_live_owner(&self) -> Result<bool> {
        let pin = self.pin.with_extension("alternate");
        let lease = self.lease.with_extension("alternate.lock");
        let result = KernelHostOwner::new(KernelHostConfig::identity(
            "/sys/kernel/btf/vmlinux",
            &lease,
            Some(pin.clone()),
            self.boot.clone(),
            1,
        ))
        .start();
        let rejected = match result {
            Err(InterceptorError::LeaseOwned { .. }) => true,
            Err(source) => {
                Self::clean_paths(&pin, &lease)?;
                return Err(crate::Error::from_interceptor(source));
            }
            Ok(host) => {
                host.shutdown().context(InterceptorSnafu)?;
                false
            }
        };
        Self::clean_paths(&pin, &lease)?;
        Ok(rejected)
    }

    pub(super) fn shutdown(&mut self) -> Result<()> {
        let host = self
            .host
            .take()
            .ok_or_else(|| invalid_state("retained host is not running"))?;
        host.shutdown().context(InterceptorSnafu)
    }

    pub(super) fn reject_other_root(&self) -> Result<bool> {
        let pin = self.pin.with_extension("retired");
        let lease = self.lease.with_extension("retired.lock");
        let result = KernelHostOwner::new(KernelHostConfig::identity(
            "/sys/kernel/btf/vmlinux",
            &lease,
            Some(pin.clone()),
            self.boot.clone(),
            1,
        ))
        .start();
        let rejected = match result {
            Err(InterceptorError::RetainedLsmLink { .. }) => true,
            Err(source) => {
                Self::clean_paths(&pin, &lease)?;
                return Err(crate::Error::from_interceptor(source));
            }
            Ok(host) => {
                host.shutdown().context(InterceptorSnafu)?;
                false
            }
        };
        Self::clean_paths(&pin, &lease)?;
        Ok(rejected)
    }

    pub(super) fn reject_displaced(&self) -> Result<bool> {
        let record = self
            .first
            .maps
            .iter()
            .find(|map| map.name == "active_profile_generations")
            .ok_or_else(|| invalid_state("live manifest has no active-profile map"))?;
        ensure!(
            record.map_type == "Hash",
            InvalidInputSnafu {
                path: Path::new(&record.name),
                reason: "active-profile map is not a hash map",
            }
        );
        let pin = record
            .pin_path
            .as_deref()
            .ok_or_else(|| invalid_state("active-profile map has no pin path"))?;
        let displaced = self
            .pin
            .join("recovery-original-active-profile-generations");
        ensure!(
            !displaced.exists(),
            InvalidInputSnafu {
                path: &displaced,
                reason: "recovery negative-fixture path already exists",
            }
        );
        fs::rename(pin, &displaced).context(IoSnafu { path: pin })?;

        let attempt = (|| {
            let options = libbpf_rs::libbpf_sys::bpf_map_create_opts {
                sz: size_of::<libbpf_rs::libbpf_sys::bpf_map_create_opts>() as _,
                ..Default::default()
            };
            let mut replacement = MapHandle::create(
                MapType::Hash,
                Some("recovery_map"),
                record.key_size,
                record.value_size,
                record.max_entries,
                &options,
            )
            .map_err(|source| invalid_state(format!("create replacement map: {source}")))?;
            replacement
                .pin(pin)
                .map_err(|source| invalid_state(format!("pin replacement map: {source}")))?;
            match KernelHostOwner::new(self.config.clone()).start() {
                Ok(host) => {
                    host.shutdown().context(InterceptorSnafu)?;
                    Ok(false)
                }
                Err(source) => {
                    let message = source.to_string();
                    ensure!(
                        message.contains("recovered maps")
                            || message.contains("does not use the recovered map set"),
                        InvalidInputSnafu {
                            path: pin,
                            reason: format!(
                                "displaced-map recovery failed for another reason: {message}"
                            ),
                        }
                    );
                    Ok(true)
                }
            }
        })();
        let remove = match fs::remove_file(pin) {
            Ok(()) => Ok(()),
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(source) => Err(source).context(IoSnafu { path: pin }),
        };
        let restore = fs::rename(&displaced, pin).context(IoSnafu { path: &displaced });
        let rejected = attempt?;
        remove?;
        restore?;
        Ok(rejected)
    }

    pub(super) fn restart(&mut self) -> Result<()> {
        ensure!(
            self.host.is_none(),
            InvalidInputSnafu {
                path: &self.pin,
                reason: "retained host is already running",
            }
        );
        self.host = Some(
            KernelHostOwner::new(self.config.clone())
                .start()
                .context(InterceptorSnafu)?,
        );
        Ok(())
    }

    pub(super) fn reject_missing_link(&self) -> Result<bool> {
        let host = self.host()?;
        host.verify_live_manifest().context(InterceptorSnafu)?;
        let pin = host
            .manifest()
            .links
            .first()
            .and_then(|link| link.pin_path.as_ref())
            .ok_or_else(|| invalid_state("live manifest has no pinned link"))?;
        fs::remove_file(pin).context(IoSnafu { path: pin })?;
        Ok(host.verify_live_manifest().is_err())
    }

    pub(super) fn stop(mut self) -> Result<()> {
        self.close()
    }

    fn clean_paths(pin: &Path, lease: &Path) -> Result<()> {
        if pin.exists() {
            ProbeDirectory::new(pin).cleanup()?;
        }
        ProbeFile::new(lease).cleanup()
    }

    fn close(&mut self) -> Result<()> {
        if let Some(host) = self.host.take() {
            host.shutdown().context(InterceptorSnafu)?;
        }
        Ok(())
    }
}

impl Drop for RetainedHost {
    fn drop(&mut self) {
        let _result = self.close();
    }
}
