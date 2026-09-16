#![allow(unsafe_code)]

use std::any::{Any, TypeId};
use std::cell::Cell;
use std::collections::HashMap;
use std::sync::{LazyLock, Mutex, MutexGuard, OnceLock};

use super::TestResult;

thread_local! {
    static CURRENT: Cell<Option<Current>> = const { Cell::new(None) };
}

type AnyLifecycle = dyn Any + Send + Sync;

#[derive(Clone, Copy)]
struct Resource {
    name: &'static str,
    lifecycle: &'static AnyLifecycle,
    tear_down: fn(&'static AnyLifecycle) -> TestResult<()>,
}

static RESOURCES: LazyLock<Mutex<HashMap<TypeId, Resource>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));
static CLEANUP: OnceLock<i32> = OnceLock::new();

#[derive(Clone, Copy)]
struct Current {
    name: &'static str,
    platform: TypeId,
}

struct Reset(Option<Current>);

impl Drop for Reset {
    fn drop(&mut self) {
        CURRENT.set(self.0);
    }
}

pub(crate) fn test_lifecycle<P: 'static, T>(name: &'static str, test: impl FnOnce() -> T) -> T {
    let previous = CURRENT.replace(Some(Current {
        name,
        platform: TypeId::of::<P>(),
    }));
    let _reset = Reset(previous);
    test()
}

pub(super) fn enter<T: Send + 'static>(
    finish: fn(&mut T) -> TestResult<()>,
) -> TestResult<LifecycleGuard<'static, T>> {
    register_cleanup()?;
    let current = CURRENT.get().ok_or("the platform test has no lifecycle")?;
    let resource = {
        let mut resources = RESOURCES
            .lock()
            .map_err(|_source| "the platform lifecycles are poisoned")?;
        if let Some(resource) = resources.get(&current.platform) {
            if resource.name != current.name {
                return Err(format!(
                    "platform lifecycle `{}` is active; run `{}` in a separate test process",
                    resource.name, current.name
                )
                .into());
            }
            *resource
        } else {
            let lifecycle: &'static Lifecycle<T> = Box::leak(Box::new(Lifecycle::new(finish)));
            let resource = Resource {
                name: current.name,
                lifecycle,
                tear_down: tear_down::<T>,
            };
            resources.insert(current.platform, resource);
            resource
        }
    };
    resource
        .lifecycle
        .downcast_ref::<Lifecycle<T>>()
        .ok_or("the platform lifecycle has the wrong resource type")?
        .enter()
}

struct Lifecycle<T> {
    state: Mutex<Option<T>>,
    tear_down: fn(&mut T) -> TestResult<()>,
}

impl<T> Lifecycle<T> {
    const fn new(tear_down: fn(&mut T) -> TestResult<()>) -> Self {
        Self {
            state: Mutex::new(None),
            tear_down,
        }
    }

    fn enter(&'static self) -> TestResult<LifecycleGuard<'static, T>> {
        Ok(LifecycleGuard {
            state: self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        })
    }

    fn tear_down(&self) -> TestResult<()> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(mut state) = state.take() {
            (self.tear_down)(&mut state)?;
        }
        Ok(())
    }
}

pub(super) struct LifecycleGuard<'a, T> {
    state: MutexGuard<'a, Option<T>>,
}

impl<T> LifecycleGuard<'_, T> {
    pub(super) fn get(&self) -> Option<&T> {
        self.state.as_ref()
    }

    pub(super) fn get_mut(&mut self) -> Option<&mut T> {
        self.state.as_mut()
    }

    pub(super) fn put(&mut self, value: T) {
        *self.state = Some(value);
    }
}

fn tear_down<T: Send + 'static>(lifecycle: &'static AnyLifecycle) -> TestResult<()> {
    lifecycle
        .downcast_ref::<Lifecycle<T>>()
        .ok_or("the platform lifecycle has the wrong resource type")?
        .tear_down()
}

fn register_cleanup() -> TestResult<()> {
    let status = *CLEANUP.get_or_init(|| {
        // SAFETY: `cleanup` has the process lifetime and C ABI required by `atexit`.
        unsafe { libc::atexit(cleanup) }
    });
    match status {
        0 => Ok(()),
        _ => Err("failed to register platform lifecycle teardown".into()),
    }
}

extern "C" fn cleanup() {
    let result = RESOURCES
        .lock()
        .map_err(|_source| "the platform lifecycles are poisoned".into())
        .and_then(|resources| {
            let mut failure = None;
            for resource in resources.values() {
                if let Err(source) = (resource.tear_down)(resource.lifecycle) {
                    failure = Some(source);
                }
            }
            match failure {
                Some(source) => Err(source),
                None => Ok(()),
            }
        });
    if let Err(source) = result {
        eprintln!("platform lifecycle teardown failed: {source}");
        // SAFETY: cleanup has failed and the test command must return failure.
        unsafe {
            libc::_exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::panic::{catch_unwind, AssertUnwindSafe};
    use std::sync::atomic::{AtomicBool, Ordering};

    use super::*;

    static CLOSED: AtomicBool = AtomicBool::new(false);

    struct TestPlatform;

    fn close_flag(value: &mut bool) -> TestResult<()> {
        CLOSED.store(*value, Ordering::SeqCst);
        Ok(())
    }

    #[test]
    #[allow(clippy::panic)]
    fn poisoned_lifecycle_tears_down() -> TestResult<()> {
        CLOSED.store(false, Ordering::SeqCst);
        let lifecycle = Box::leak(Box::new(Lifecycle::new(close_flag)));
        let panic = catch_unwind(AssertUnwindSafe(|| {
            let Ok(mut guard) = lifecycle.enter() else {
                return;
            };
            guard.put(true);
            panic!("test assertion");
        }));

        assert!(panic.is_err());
        lifecycle.tear_down()?;
        assert!(CLOSED.load(Ordering::SeqCst));
        Ok(())
    }

    #[test]
    fn mixed_lifecycle_is_rejected() -> TestResult<()> {
        test_lifecycle::<TestPlatform, _>("first", || {
            drop(enter::<bool>(close_flag)?);
            test_lifecycle::<TestPlatform, _>("second", || {
                let error = match enter::<bool>(close_flag) {
                    Ok(_) => return Err("the second lifecycle was accepted".into()),
                    Err(error) => error,
                };
                assert!(error.to_string().contains("separate test process"));
                Ok(())
            })
        })
    }
}
