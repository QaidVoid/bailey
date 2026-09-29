//! Bailey: a layered, deny-by-default sandbox for running untrusted programs on
//! Linux.
//!
//! The crate is organized around a single mechanism-independent
//! [`policy::Policy`] that is produced by the cascading [`config`] resolver and
//! consumed by the execution [`backend`]s. Enforcement and audit are separate
//! backends over that shared policy, because Landlock has no permissive mode:
//! observing what a program needs and denying what it may not do are different
//! mechanisms.

pub mod backend;
pub mod cli;
pub mod config;
pub mod event;
pub mod hook;
pub mod hooks;
pub mod policy;
pub mod profiles;
pub mod reconcile;
pub mod strings;
pub mod trust;

/// Serialization for the tests that mutate the process environment.
///
/// A test that sets a variable races every test reading one, which is how a
/// run that passed alone fails beside its neighbours. Anything that touches
/// the environment holds this while it does.
#[cfg(test)]
pub(crate) mod test_support {
    use std::sync::{Mutex, MutexGuard, OnceLock};

    fn lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    /// Holds the environment steady until the guard is dropped.
    pub(crate) fn env_lock() -> MutexGuard<'static, ()> {
        lock()
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}
