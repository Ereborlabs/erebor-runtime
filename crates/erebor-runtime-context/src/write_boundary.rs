#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum WriteBoundary {
    Blob = 1,
    Tree = 2,
    Commit = 3,
    BeforeSingleRefEdit = 4,
    AfterSingleRefEdit = 5,
    BeforeMultiRefEdit = 6,
    AfterMultiRefEdit = 7,
}

#[cfg(feature = "test-support")]
mod configured {
    use std::sync::atomic::{AtomicU8, Ordering};

    use super::WriteBoundary;

    static EXIT_AFTER: AtomicU8 = AtomicU8::new(0);

    pub(super) fn set_exit_after(boundary: WriteBoundary) {
        EXIT_AFTER.store(boundary as u8, Ordering::SeqCst);
    }

    pub(super) fn clear_exit_after() {
        EXIT_AFTER.store(0, Ordering::SeqCst);
    }

    pub(super) fn reach(boundary: WriteBoundary) {
        if EXIT_AFTER.load(Ordering::SeqCst) == boundary as u8 {
            std::process::exit(70);
        }
    }
}

#[cfg(not(feature = "test-support"))]
mod configured {
    use super::WriteBoundary;

    pub(super) fn reach(_: WriteBoundary) {}
}

pub(crate) fn reach(boundary: WriteBoundary) {
    configured::reach(boundary);
}

#[cfg(feature = "test-support")]
pub mod api {
    pub use super::WriteBoundary;

    /// Terminate the current process when it reaches the next requested write boundary.
    pub fn exit_after(boundary: WriteBoundary) {
        super::configured::set_exit_after(boundary);
    }

    /// Remove the subprocess-only write-boundary termination setting.
    pub fn clear_exit_after() {
        super::configured::clear_exit_after();
    }
}
