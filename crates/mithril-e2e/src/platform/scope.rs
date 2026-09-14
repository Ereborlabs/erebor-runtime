use std::any::{Any, TypeId};
use std::cell::Cell;
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{LazyLock, Mutex, MutexGuard};

use super::TestResult;

thread_local! {
    static CURRENT: Cell<Option<Current>> = const { Cell::new(None) };
}

type Resource = &'static (dyn Any + Send + Sync);

static RESOURCES: LazyLock<Mutex<HashMap<TypeId, Resource>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

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

pub(super) fn enter<T: Send + 'static>() -> TestResult<ScopeGuard<'static, T>> {
    let platform = CURRENT
        .get()
        .map(|scope| scope.platform)
        .ok_or("the platform test has no scope")?;
    let resource = {
        let mut resources = RESOURCES
            .lock()
            .map_err(|_source| "the named platform scopes are poisoned")?;
        *resources.entry(platform).or_insert_with(|| {
            Box::leak(Box::new(Scope::<T>::new())) as &'static (dyn Any + Send + Sync)
        })
    };
    resource
        .downcast_ref::<Scope<T>>()
        .ok_or("the named platform scope has the wrong resource type")?
        .enter()
}

struct Scope<T> {
    users: AtomicUsize,
    state: Mutex<Option<T>>,
}

impl<T> Scope<T> {
    const fn new() -> Self {
        Self {
            users: AtomicUsize::new(0),
            state: Mutex::new(None),
        }
    }

    fn enter(&'static self) -> TestResult<ScopeGuard<'static, T>> {
        self.users.fetch_add(1, Ordering::SeqCst);
        match self.state.lock() {
            Ok(state) => Ok(ScopeGuard {
                scope: self,
                state,
                active: true,
            }),
            Err(_source) => {
                self.users.fetch_sub(1, Ordering::SeqCst);
                Err("the platform test scope is poisoned".into())
            }
        }
    }
}

pub(super) struct ScopeGuard<'a, T> {
    scope: &'a Scope<T>,
    state: MutexGuard<'a, Option<T>>,
    active: bool,
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

    pub(super) fn finish(&mut self) -> bool {
        if !self.active {
            return false;
        }
        self.active = false;
        self.scope.users.fetch_sub(1, Ordering::SeqCst) == 1
    }
}

impl<T> Drop for ScopeGuard<'_, T> {
    fn drop(&mut self) {
        if self.active {
            self.scope.users.fetch_sub(1, Ordering::SeqCst);
        }
    }
}
