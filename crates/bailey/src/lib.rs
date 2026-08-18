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
pub mod hooks;
pub mod policy;
pub mod profiles;
pub mod reconcile;
