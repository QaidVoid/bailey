//! A canary for the skip log the kernel matrix reads.
//!
//! Both variant keys are logged whenever `BAILEY_TEST_SKIP_LOG` is set,
//! which is only under a kernel-matrix run, and each kernel's `.skips`
//! expectation names them. A run where the log was not wired up therefore
//! fails with two expected skips missing, rather than passing with an empty
//! log that looks like a clean kernel.

mod common;

#[test]
fn the_skip_log_receives_distinct_variant_keys() {
    let Some(_) = std::env::var_os("BAILEY_TEST_SKIP_LOG") else {
        return;
    };
    common::skip_variant("first", "the canary runs, so both keys are expected");
    common::skip_variant("second", "the canary runs, so both keys are expected");
}
