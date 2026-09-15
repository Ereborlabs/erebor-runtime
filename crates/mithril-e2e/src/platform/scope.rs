#![allow(unsafe_code)]

use std::any::{Any, TypeId};
use std::cell::Cell;
use std::collections::HashMap;
use std::sync::{LazyLock, Mutex, MutexGuard, OnceLock};

use super::TestResult;

thread_local! {
    static CURRENT: Cell<Option<Current>> = const { Cell::new(None) };
}

type AnyScope = dyn Any + Send + Sync;

#[derive(Clone, Copy)]
struct Resource {
    scope: &'static AnyScope,
    close: fn(&'static AnyScope) -> TestResult<()>,
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

pub(crate) fn test_scope<P: 'static, T>(name: &'static str, test: impl FnOnce() -> T) -> T {
    let previous = CURRENT.replace(Some(Current {
        name,
        platform: TypeId::of::<P>(),
    }));
    let _reset = Reset(previous);
    test()
}

pub(super) fn current() -> TestResult<&'static str> {
    CURRENT
        .get()
        .map(|scope| scope.name)
        .ok_or_else(|| "the platform test has no scope".into())
}

pub(super) fn enter<T: Send + 'static>(
    close: fn(&mut T) -> TestResult<()>,
) -> TestResult<ScopeGuard<'static, T>> {
    register_cleanup()?;
    let platform = CURRENT
        .get()
        .map(|scope| scope.platform)
        .ok_or("the platform test has no scope")?;
    let resource = {
        let mut resources = RESOURCES
            .lock()
            .map_err(|_source| "the named platform scopes are poisoned")?;
        *resources.entry(platform).or_insert_with(|| {
            let scope: &'static Scope<T> = Box::leak(Box::new(Scope::new(close)));
            Resource {
                scope,
                close: close_scope::<T>,
            }
        })
    };
    resource
        .scope
        .downcast_ref::<Scope<T>>()
        .ok_or("the named platform scope has the wrong resource type")?
        .enter()
}

struct Scope<T> {
    state: Mutex<Option<T>>,
    close: fn(&mut T) -> TestResult<()>,
}

impl<T> Scope<T> {
    const fn new(close: fn(&mut T) -> TestResult<()>) -> Self {
        Self {
            state: Mutex::new(None),
            close,
        }
    }

    fn enter(&'static self) -> TestResult<ScopeGuard<'static, T>> {
        Ok(ScopeGuard {
            state: self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        })
    }

    fn close(&self) -> TestResult<()> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(mut state) = state.take() {
            (self.close)(&mut state)?;
        }
        Ok(())
    }
}

pub(super) struct ScopeGuard<'a, T> {
    state: MutexGuard<'a, Option<T>>,
}

impl<T> ScopeGuard<'_, T> {
    pub(super) fn get(&self) -> Option<&T> {
        self.state.as_ref()
    }

    pub(super) fn get_mut(&mut self) -> Option<&mut T> {
        self.state.as_mut()
    }

    pub(super) fn put(&mut self, value: T) {
        *self.state = Some(value);
    }

    pub(super) fn take(&mut self) -> Option<T> {
        self.state.take()
    }
}

fn close_scope<T: Send + 'static>(scope: &'static AnyScope) -> TestResult<()> {
    scope
        .downcast_ref::<Scope<T>>()
        .ok_or("the named platform scope has the wrong resource type")?
        .close()
}

fn register_cleanup() -> TestResult<()> {
    let status = *CLEANUP.get_or_init(|| {
        // SAFETY: `cleanup` has the process lifetime and C ABI required by `atexit`.
        unsafe { libc::atexit(cleanup) }
    });
    match status {
        0 => Ok(()),
        _ => Err("failed to register platform scope cleanup".into()),
    }
}

extern "C" fn cleanup() {
    let result = RESOURCES
        .lock()
        .map_err(|_source| "the named platform scopes are poisoned".into())
        .and_then(|resources| {
            let mut failure = None;
            for resource in resources.values() {
                if let Err(source) = (resource.close)(resource.scope) {
                    failure = Some(source);
                }
            }
            match failure {
                Some(source) => Err(source),
                None => Ok(()),
            }
        });
    if let Err(source) = result {
        eprintln!("platform scope cleanup failed: {source}");
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

    fn close_flag(value: &mut bool) -> TestResult<()> {
        CLOSED.store(*value, Ordering::SeqCst);
        Ok(())
    }

    #[test]
    #[allow(clippy::panic)]
    fn poisoned_scope_still_closes() -> TestResult<()> {
        CLOSED.store(false, Ordering::SeqCst);
        let scope = Box::leak(Box::new(Scope::new(close_flag)));
        let panic = catch_unwind(AssertUnwindSafe(|| {
            let Ok(mut guard) = scope.enter() else {
                return;
            };
            guard.put(true);
            panic!("test assertion");
        }));

        assert!(panic.is_err());
        scope.close()?;
        assert!(CLOSED.load(Ordering::SeqCst));
        Ok(())
    }
}
