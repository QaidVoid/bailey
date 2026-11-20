//! Helpers shared by the integration test binaries.
//!
//! The kernel matrix asserts, per pinned kernel, exactly which tests skipped
//! and which ran, so a regression that turns a running test into a skip
//! fails that kernel's job instead of hiding inside a green run. The
//! assertion reads a skip log the helpers write when CI sets
//! `BAILEY_TEST_SKIP_LOG`; without it they only print what every skip has
//! always printed.

// Each integration binary includes this module and uses only the helpers it
// needs, so the rest register as dead code from that binary's view.
#![allow(dead_code)]

use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};

/// Report a test as skipped and record the skip where CI asks for it.
///
/// The printed line stays `skipping: <reason>`, so local output reads as it
/// did before. When `BAILEY_TEST_SKIP_LOG` names a file, the skip is
/// appended as `<crate>::<test>\t<reason>`. `<test>` is the current
/// thread's name, which libtest sets to the test's path: the bare test name
/// in an integration binary, and `module::test` inside the crate's unit
/// tests. Appends go through `O_APPEND`, which stays atomic for writes this
/// small even with the suite's tests running in parallel.
pub fn skip(reason: &str) {
    eprintln!("skipping: {reason}");
    record(test_name().as_deref(), reason);
}

/// Like [`skip`], for a test whose variants skip independently.
///
/// Keyed by the test's name alone, two skips inside one test would collapse
/// into one log line, and a variant that stopped running would hide behind
/// one that still skips. Naming the variant keeps the keys distinct, and the
/// expectation checker fails on any key logged twice, so a merged skip
/// surfaces as an error naming the test instead of a silent loss.
pub fn skip_variant(variant: &str, reason: &str) {
    eprintln!("skipping: {reason}");
    let named = match test_name() {
        Some(test) => format!("{test}[{variant}]"),
        None => "unknown".to_owned(),
    };
    record(Some(&named), reason);
}

/// The current thread's name, `None` when there is none to report.
///
/// A missing name means the check has no test to attribute the skip to, so
/// the log carries `unknown`, which the expectation checker refuses.
fn test_name() -> Option<String> {
    std::thread::current().name().map(str::to_owned)
}

fn record(test: Option<&str>, reason: &str) {
    let Some(path) = std::env::var_os("BAILEY_TEST_SKIP_LOG") else {
        return;
    };
    let Ok(mut log) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
    else {
        return;
    };
    // The whole line goes out in one write: a formatted `writeln!` issues one
    // write per piece, and pieces of concurrent skippers interleave into
    // lines no checker can read.
    let line = format!(
        "{}::{}\t{}\n",
        env!("CARGO_CRATE_NAME"),
        test.unwrap_or("unknown"),
        reason
    );
    let _ = log.write_all(line.as_bytes());
}

/// Remove the staging directories a killed run left behind.
///
/// A run that is killed rather than allowed to exit cannot unwind, so its
/// staging directory stays on the host and a later leak assertion would
/// count it as a leak. Tests that kill their runs call this with the run's
/// pid, so only what the harness itself killed is cleaned.
pub fn remove_staging_for(pid: u32) {
    let mine = format!("{}.", pid);
    for entry in std::fs::read_dir("/tmp").into_iter().flatten().flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        let Some(rest) = name.strip_prefix(".bailey-root.") else {
            continue;
        };
        if rest.starts_with(&mine) {
            let _ = std::fs::remove_dir_all(entry.path());
        }
    }
}

/// A probe that asks the kernel for a fresh user and network namespace
/// through clone3, clone, and unshare, and reports what happened on stdout.
/// Each route that creates a child prints the child's effective capabilities
/// so a caller can tell a real namespace creation from a refusal.
pub fn write_namespace_probe(dir: &Path) -> PathBuf {
    let probe = dir.join("probe.py");
    fs::write(
        &probe,
        r#"
import ctypes, os, platform
libc = ctypes.CDLL(None, use_errno=True)
flags = 0x10000000 | 0x40000000
SYS_CLONE3 = 435
SYS_CLONE = 56 if platform.machine() == 'x86_64' else 220

def capseff():
    with open('/proc/self/status') as status:
        for line in status:
            if line.startswith('CapEff'):
                return line.split()[1].strip()
    return '?'

buf = (ctypes.c_uint64 * 8)(flags, 0, 0, 0, 17, 0, 0, 0)
pid = libc.syscall(SYS_CLONE3, buf, 64)
if pid == 0:
    print('clone3 child CapEff', capseff(), flush=True)
    os._exit(0)
if pid > 0:
    os.waitpid(pid, 0)
    print('clone3 child-created', flush=True)
else:
    print('clone3 refused', ctypes.get_errno(), flush=True)

pid = libc.syscall(SYS_CLONE, flags, 0, 0, 0, 0)
if pid == 0:
    print('clone child CapEff', capseff(), flush=True)
    os._exit(0)
if pid > 0:
    os.waitpid(pid, 0)
    print('clone child-created', flush=True)
else:
    print('clone refused', ctypes.get_errno(), flush=True)

if libc.unshare(flags) == 0:
    print('unshare succeeded CapEff', capseff(), flush=True)
else:
    print('unshare refused', ctypes.get_errno(), flush=True)
"#,
    )
    .unwrap();
    probe
}

/// Assert that every route a probe took to a fresh user namespace was
/// refused, with the errno the kernel hands back for a real refusal: EPERM
/// from the seccomp filter, ENOSYS from the clone3 rule, or ENOSPC from the
/// guard's limit. No route may leave a child holding capabilities.
pub fn assert_every_namespace_route_refused(layout: &str, stdout: &str) {
    for route in ["clone3", "clone", "unshare"] {
        let line = stdout
            .lines()
            .find(|l| l.starts_with(route))
            .unwrap_or_else(|| panic!("{layout}: no {route} probe output: {stdout}"));
        let errno: i32 = line
            .rsplit(' ')
            .next()
            .unwrap()
            .parse()
            .unwrap_or_else(|_| panic!("{layout}: {route} probe did not report an errno: {line}"));
        assert!(
            [1, 28, 38].contains(&errno),
            "{layout}: {route} must be refused with EPERM, ENOSPC, or ENOSYS: {line}"
        );
    }
    assert!(
        !stdout.contains("CapEff") && !stdout.contains("child-created"),
        "{layout}: the target must not gain capabilities in a new user namespace: {stdout}"
    );
}
