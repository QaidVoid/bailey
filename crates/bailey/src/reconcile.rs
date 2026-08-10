//! Profile reconciliation.
//!
//! Diffs a recorded access trace against a [`crate::policy::Policy`], classifies
//! ungranted access by risk, and generates or tightens a deny-by-default
//! profile from confirmed access. Implemented in a later change.
