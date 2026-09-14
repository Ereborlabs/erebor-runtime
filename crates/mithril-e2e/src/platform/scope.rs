use std::cell::Cell;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, MutexGuard};

use super::TestResult;

thread_local! {
    static CURRENT: Cell<Option<&'static str>> = const { Cell::new(None) };
}

struct Reset(Option<&'static str>);

impl Drop for Reset {
    fn drop(&mut self) {
        CURRENT.set(self.0);
    }
}

pub(crate) fn test_scope<T>(name: &'static str, test: impl FnOnce() -> T) -> T {
    let previous = CURRENT.replace(Some(name));
    let _reset = Reset(previous);
    test()
}

pub(super) fn current() -> TestResult<&'static str> {
    CURRENT
        .get()
        .ok_or_else(|| "the platform test has no scope".into())
}

pub(super) struct Scope<T> {
    users: AtomicUsize,
    state: Mutex<Option<T>>,
}

impl<T> Scope<T> {
    pub(super) const fn new() -> Self {
        Self {
            users: AtomicUsize::new(0),
            state: Mutex::new(None),
        }
    }

    pub(super) fn enter(&'static self) -> TestResult<ScopeGuard<'static, T>> {
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
