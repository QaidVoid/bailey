//! Integration tests for the audit backend.
//!
//! The eBPF observer needs the privileged helper, because loading its
//! programs needs `CAP_BPF` and `CAP_PERFMON`. The seccomp fallback needs
//! only Linux 5.5+. Every scenario runs under whichever observers this host
//! can record with, and each observer skips on its own variant key, so a
//! host that can only record one way stays green while the kernel matrix
//! still asserts exactly what ran.
mod common;

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use serde_json::Value;

fn bailey() -> &'static str {
    env!("CARGO_BIN_EXE_bailey")
}

/// The helper, if one is configured and able to load its programs.
/// `doctor` and a run must agree about where the helper is. They looked
/// separately once, and disagreed: a helper installed on PATH was reported
/// missing by `doctor` while `bailey audit` used it happily.
#[test]
fn the_helper_is_found_on_path() {
    let dir = tempfile::tempdir().unwrap();
    let installed = dir.path().join("bailey-bpf-helper");
    fs::write(&installed, "#!/bin/sh\nexit 0\n").unwrap();
    fs::set_permissions(&installed, std::fs::Permissions::from_mode(0o755)).unwrap();

    // Somewhere with no helper beside it, so only PATH can answer.
    let elsewhere = dir.path().join("bin");
    fs::create_dir(&elsewhere).unwrap();
    let bailey_copy = elsewhere.join("bailey");
    fs::copy(bailey(), &bailey_copy).unwrap();

    // The copy was just written, and a test forking in parallel can hold its
    // descriptor for a moment, which the kernel answers with ETXTBSY.
    let output = (0..100)
        .find_map(|_| {
            match Command::new(&bailey_copy)
                .arg("doctor")
                .env("PATH", dir.path())
                .env_remove("BAILEY_BPF_HELPER")
                .output()
            {
                Err(error) if error.raw_os_error() == Some(libc::ETXTBSY) => {
                    std::thread::sleep(std::time::Duration::from_millis(10));
                    None
                }
                other => Some(other),
            }
        })
        .expect("the copy became executable")
        .unwrap();
    let report = String::from_utf8_lossy(&output.stdout);

    assert!(
        !report.contains("helper: not found"),
        "a helper on PATH is one a run would use, so `doctor` must see it: {report}"
    );
    assert!(
        report.contains(&installed.display().to_string()),
        "and must name the one it found: {report}"
    );
}

fn helper() -> Option<PathBuf> {
    let path = PathBuf::from(std::env::var_os("BAILEY_BPF_HELPER")?);
    path.is_file().then_some(path)
}

/// Whether the fallback observer can record on this host.
fn fallback_available() -> bool {
    bailey::backend::probe::fallback_status().is_available()
}

/// Whether a helper is discoverable with `BAILEY_BPF_HELPER` cleared and
/// `PATH` pointing at `dir`, by asking `doctor` the same question a run
/// would ask.
fn helper_discoverable_with_path(dir: &Path) -> bool {
    let output = Command::new(bailey())
        .arg("doctor")
        .env_remove("BAILEY_BPF_HELPER")
        .env("PATH", dir)
        .output()
        .unwrap();
    !String::from_utf8_lossy(&output.stdout).contains("helper: not found")
}

/// The observers this host can record with, in preference order.
///
/// Each observer skips on its own variant key: the kernel matrix asserts
/// which variants ran on each host, so an observer losing availability
/// shows up as its own skip instead of hiding behind the other one's.
fn observers() -> Vec<&'static str> {
    let mut observers = Vec::new();
    if helper().is_some() {
        observers.push("ebpf");
    } else {
        common::skip_variant("ebpf", "no audit helper configured");
    }
    if fallback_available() {
        observers.push("seccomp");
    } else {
        common::skip_variant(
            "seccomp",
            "the fallback observer is unavailable on this host",
        );
    }
    observers
}

/// Run an audit that saves a trace, and return the parsed trace.
fn trace_of(helper: Option<&Path>, dir: &Path, args: &[&str]) -> Value {
    let path = dir.join("trace.json");
    let mut full = vec!["audit", "--save-trace", path.to_str().unwrap()];
    full.extend_from_slice(args);
    let output = audit_in(helper, Some(dir), &full);
    assert!(
        path.exists(),
        "audit did not produce a trace: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap()
}

/// Run an audit that saves a trace, and return the process output and the
/// parsed trace together, for the scenarios that assert on both.
fn audit_and_trace(
    helper: Option<&Path>,
    dir: &Path,
    args: &[&str],
) -> (std::process::Output, Value) {
    let path = dir.join("trace.json");
    let mut full = vec!["audit", "--save-trace", path.to_str().unwrap()];
    full.extend_from_slice(args);
    let output = audit_in(helper, Some(dir), &full);
    let trace: Value =
        serde_json::from_str(&fs::read_to_string(&path).unwrap()).expect("the audit wrote a trace");
    (output, trace)
}

fn audit(helper: Option<&Path>, args: &[&str]) -> std::process::Output {
    audit_in(helper, None, args)
}

/// Run an audit rooted at `dir`, so config discovery cannot pick up a
/// `bailey.toml` belonging to whatever directory the suite runs from.
fn audit_in(helper: Option<&Path>, dir: Option<&Path>, args: &[&str]) -> std::process::Output {
    let mut command = Command::new(bailey());
    command.args(args);
    if let Some(dir) = dir {
        command.current_dir(dir);
    }
    if let Some(helper) = helper {
        command.env("BAILEY_BPF_HELPER", helper);
    }
    command.output().unwrap()
}

fn paths_in(trace: &Value) -> Vec<String> {
    trace["events"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|event| event["resource"]["path"].as_str().map(str::to_owned))
        .collect()
}

/// Python 3, when the host has one; several scenarios need it.
fn python3() -> Option<&'static str> {
    Path::new("/usr/bin/python3")
        .exists()
        .then_some("/usr/bin/python3")
}

/// The path-swap racer: two threads flip a shared `openat` buffer between a
/// granted file and an ungranted one while opening it, over and over.
fn python_race(granted: &Path, secret: &Path) -> String {
    format!(
        r#"
import ctypes, os, sys, threading

libc = ctypes.CDLL(None, use_errno=True)
AT_FDCWD = -100
paths = ["{granted}".encode(), "{secret}".encode()]
buf = ctypes.create_string_buffer(max(len(p) for p in paths) + 1)

def opener():
    for i in range(3000):
        path = paths[i % 2]
        libc.memcpy(buf, path, len(path) + 1)
        fd = libc.openat(AT_FDCWD, buf, 0)
        if fd >= 0:
            sys.stdout.write(os.read(fd, 64).decode(errors="replace"))
            sys.stdout.flush()
            os.close(fd)

threads = [threading.Thread(target=opener) for _ in range(2)]
for thread in threads:
    thread.start()
for thread in threads:
    thread.join()
print("done")
"#,
        granted = granted.display(),
        secret = secret.display(),
    )
}

fn startup_access(observer: &str, helper: Option<&Path>) {
    let dir = tempfile::tempdir().unwrap();
    let trace = trace_of(
        helper,
        dir.path(),
        &["--observer", observer, "/bin/sh", "-c", "true"],
    );

    assert_eq!(
        trace["version"].as_u64(),
        Some(1),
        "trace must be versioned"
    );
    assert_eq!(
        trace["observer"].as_str(),
        Some(observer),
        "the trace must name the observer that recorded it"
    );

    let paths = paths_in(&trace);
    assert!(
        paths.iter().any(|path| path.contains("libc.so")),
        "the dynamic linker's library search must be recorded, so nothing the \
         target does before the recorder is watching is missed: {paths:?}"
    );
    assert!(
        paths.iter().all(|path| path.starts_with('/')),
        "recorded paths must be absolute: {paths:?}"
    );
}

#[test]
fn startup_access_is_recorded() {
    let helper = helper();
    for observer in observers() {
        startup_access(observer, helper.as_deref());
    }
}

fn confined_during_audit(observer: &str, helper: Option<&Path>) {
    let dir = tempfile::tempdir().unwrap();
    let secret = dir.path().join("secret.txt");
    fs::write(&secret, "top-secret").unwrap();

    let output = audit(
        helper,
        &[
            "audit",
            "--observer",
            observer,
            "/bin/sh",
            "-c",
            &format!("cat {}", secret.display()),
        ],
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        !stdout.contains("top-secret"),
        "an audited target must not reach an ungranted path: {stdout}"
    );
}

#[test]
fn the_target_is_confined_during_an_audit() {
    // An audit cannot isolate yet, so Landlock is what confines it.
    if bailey::backend::probe::landlock_abi().is_none() {
        for observer in observers() {
            common::skip_variant(observer, "landlock is unavailable on this host");
        }
        return;
    }
    let helper = helper();
    for observer in observers() {
        confined_during_audit(observer, helper.as_deref());
    }
}

fn refused_egress(observer: &str, helper: Option<&Path>, python: &str) {
    let output = audit(
        helper,
        &[
            "audit",
            "--observer",
            observer,
            python,
            "-c",
            "import socket\n\
             try:\n\
             \x20   socket.socket().connect(('1.1.1.1', 443))\n\
             \x20   print('connected')\n\
             except OSError:\n\
             \x20   print('refused')\n",
        ],
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("refused"),
        "the default policy denies egress, and auditing must not lift that: {stdout}"
    );
}

#[test]
fn an_ungranted_egress_attempt_is_refused_during_an_audit() {
    let Some(python) = python3() else {
        common::skip("needs python3");
        return;
    };
    let helper = helper();
    for observer in observers() {
        refused_egress(observer, helper.as_deref(), python);
    }
}

/// Audit runs in the host namespace by design, so a policy whose mode asks
/// for more than Landlock's TCP rules names the gap instead of quietly
/// skipping it. The note is the audit's own, not an observer's.
fn network_gap_named(observer: &str, helper: Option<&Path>) {
    let dir = tempfile::tempdir().unwrap();

    let private = dir.path().join("private.toml");
    fs::write(&private, "[network]\nmode = \"private\"\n").unwrap();
    let output = audit(
        helper,
        &[
            "audit",
            "--observer",
            observer,
            "-c",
            private.to_str().unwrap(),
            "/bin/sh",
            "-c",
            "true",
        ],
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("audit runs in the host namespace"),
        "a private-mode policy audited in the host namespace must say so: {stderr}"
    );
    assert!(
        stderr.contains(&private.display().to_string()),
        "the note must name where the private mode came from: {stderr}"
    );

    let brokered = dir.path().join("brokered.toml");
    fs::write(&brokered, "[network]\nbroker = \"10.0.0.1:9999\"\n").unwrap();
    let output = audit(
        helper,
        &[
            "audit",
            "--observer",
            observer,
            "-c",
            brokered.to_str().unwrap(),
            "/bin/sh",
            "-c",
            "true",
        ],
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("the broker at 10.0.0.1:9999"),
        "a brokered policy audited in the host namespace must say so: {stderr}"
    );
    assert!(
        stderr.contains(&brokered.display().to_string()),
        "the note must name where the broker came from: {stderr}"
    );
}

#[test]
fn an_audit_of_a_network_mode_it_cannot_honour_names_the_gap() {
    let helper = helper();
    for observer in observers() {
        network_gap_named(observer, helper.as_deref());
    }
}

/// `--unconfined` lifts the filter that the fallback observes through, so
/// the fallback has nothing to record with and refuses the combination.
fn unconfined_opt_in(helper: &Path) {
    let dir = tempfile::tempdir().unwrap();
    let secret = dir.path().join("secret.txt");
    fs::write(&secret, "top-secret").unwrap();

    let output = audit(
        Some(helper),
        &[
            "audit",
            "--observer",
            "ebpf",
            "--unconfined",
            "/bin/sh",
            "-c",
            &format!("cat {}", secret.display()),
        ],
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stdout.contains("top-secret"),
        "--unconfined must actually lift confinement: {stderr}"
    );
    assert!(
        stderr.contains("without confinement"),
        "running unconfined must be reported: {stderr}"
    );
}

#[test]
fn unconfined_is_an_explicit_opt_in() {
    match helper() {
        Some(helper) => unconfined_opt_in(&helper),
        None => common::skip_variant("ebpf", "no audit helper configured"),
    }
    common::skip_variant("seccomp", "--unconfined needs the eBPF observer");
}

fn child_execution_recorded(observer: &str, helper: Option<&Path>) {
    let dir = tempfile::tempdir().unwrap();
    // `exec` replaces the shell, so the executed program is the target process
    // itself rather than a short-lived child.
    let trace = trace_of(
        helper,
        dir.path(),
        &["--observer", observer, "/bin/sh", "-c", "exec /bin/true"],
    );

    let executed: Vec<_> = trace["events"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|event| event["kind"] == "execute")
        .filter_map(|event| event["resource"]["path"].as_str().map(str::to_owned))
        .collect();

    assert!(
        executed.iter().any(|path| path.contains("true")),
        "an executed program must appear as an execute event: {executed:?}"
    );
}

#[test]
fn execution_of_a_child_program_is_recorded() {
    let helper = helper();
    for observer in observers() {
        child_execution_recorded(observer, helper.as_deref());
    }
}

fn short_lived_child_recorded(observer: &str, helper: Option<&Path>) {
    let dir = tempfile::tempdir().unwrap();
    // `cat` lives a couple of milliseconds. Under process-tree scoping its
    // exec falls inside the polling window and is missed; under cgroup
    // scoping it is in scope from its first instruction. The fallback sees
    // every notified syscall directly, so it has no polling window at all.
    let trace = trace_of(
        helper,
        dir.path(),
        &[
            "--observer",
            observer,
            "/bin/sh",
            "-c",
            "cat /etc/hostname > /dev/null",
        ],
    );

    let events = trace["events"].as_array().unwrap();
    let read_hostname = events.iter().any(|event| {
        event["kind"] == "read"
            && event["resource"]["path"]
                .as_str()
                .is_some_and(|path| path.contains("hostname"))
    });
    let exec_cat = events.iter().any(|event| {
        event["kind"] == "execute"
            && event["resource"]["path"]
                .as_str()
                .is_some_and(|path| path.contains("cat"))
    });

    assert!(read_hostname, "the child's read must be recorded");
    assert!(
        exec_cat,
        "the child's exec must be recorded, which process-tree scoping misses"
    );
}

#[test]
fn a_short_lived_child_is_recorded_when_scoping_by_cgroup() {
    // Scoping by cgroup needs only a cgroup to create, not the controllers
    // that resource limits need. Without one, observation follows the
    // process tree and this case is a race rather than a guarantee.
    if bailey::backend::cgroup::usable_root(&[]).is_none() {
        common::skip_variant("ebpf", "no cgroup to scope observation to");
        common::skip_variant("seccomp", "no cgroup to scope observation to");
        return;
    }
    let helper = helper();
    for observer in observers() {
        short_lived_child_recorded(observer, helper.as_deref());
    }
}

fn peaks_recorded(observer: &str, helper: Option<&Path>) {
    let dir = tempfile::tempdir().unwrap();
    let trace = trace_of(
        helper,
        dir.path(),
        &[
            "--observer",
            observer,
            "/bin/sh",
            "-c",
            "for i in 1 2 3 4; do sleep 1 & done; wait",
        ],
    );

    let usage = &trace["usage"];
    assert!(
        usage.is_object(),
        "a measured run records its peaks: {trace}"
    );
    let tasks = usage["tasks_peak"].as_u64().expect("a tasks peak");
    assert!(
        tasks >= 4,
        "four backgrounded sleeps plus the shell must hold at least 5 tasks, got {tasks}"
    );
    let memory = usage["memory_peak_bytes"].as_u64().expect("a memory peak");
    assert!(memory > 0, "the run allocated something: {memory}");
    assert!(
        usage["unmeasured"]
            .as_array()
            .is_none_or(|reasons| reasons.is_empty()),
        "measured peaks leave nothing to explain: {usage}"
    );
}

/// Where the run's cgroup carries the measuring controllers, the trace
/// records what the run reached: a shell that backgrounds several sleeps
/// holds more tasks at once than its own process, and allocates something.
#[test]
fn peaks_are_recorded_when_the_cgroup_carries_them() {
    // `memory.peak` arrived in 5.19 and `pids.peak` in 6.1.
    if !common::kernel_at_least(6, 1) {
        common::skip_variant("ebpf", "this kernel reports no pids.peak");
        common::skip_variant("seccomp", "this kernel reports no pids.peak");
        return;
    }
    if bailey::backend::cgroup::usable_root(&["memory", "pids"]).is_none() {
        common::skip_variant("ebpf", "no cgroup carrying memory and pids to measure in");
        common::skip_variant(
            "seccomp",
            "no cgroup carrying memory and pids to measure in",
        );
        return;
    }
    let helper = helper();
    for observer in observers() {
        peaks_recorded(observer, helper.as_deref());
    }
}

fn unmeasured_peak_explained(observer: &str, helper: Option<&Path>) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("trace.json");
    let override_path = "/nonexistent";
    let mut command = Command::new(bailey());
    command
        .args([
            "audit",
            "--observer",
            observer,
            "--save-trace",
            path.to_str().unwrap(),
            "/bin/sh",
            "-c",
            "true",
        ])
        .env("BAILEY_CGROUP_ROOT", override_path);
    if let Some(helper) = helper {
        command.env("BAILEY_BPF_HELPER", helper);
    }
    let output = command.output().unwrap();
    assert!(
        path.exists(),
        "audit did not produce a trace: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let trace: Value = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();

    let usage = &trace["usage"];
    assert!(
        usage.is_object(),
        "the run explains its missing peaks: {trace}"
    );
    assert!(
        usage["memory_peak_bytes"].is_null(),
        "no cgroup, no memory peak: {usage}"
    );
    assert!(
        usage["tasks_peak"].is_null(),
        "no cgroup, no tasks peak: {usage}"
    );
    let reasons: Vec<String> = usage["unmeasured"]
        .as_array()
        .expect("unmeasured peaks are listed")
        .iter()
        .map(|reason| reason.as_str().expect("a string reason").to_owned())
        .collect();
    assert_eq!(reasons.len(), 2, "both peaks are named: {reasons:?}");
    assert!(
        reasons.iter().all(|reason| reason.contains("no cgroup")),
        "each reason names the missing cgroup: {reasons:?}"
    );
}

/// A run with no cgroup at all records both peaks as unmeasured, and each
/// reason says what was lost rather than leaving the fields absent.
#[test]
fn an_unmeasured_peak_says_why() {
    let helper = helper();
    for observer in observers() {
        unmeasured_peak_explained(observer, helper.as_deref());
    }
}

/// A fallback trace carries the run's peaks, because the fallback waits
/// through the same measured wait the eBPF path does.
#[test]
fn a_fallback_trace_carries_measured_usage() {
    if !fallback_available() {
        common::skip("the fallback observer is unavailable on this host");
        return;
    }
    if !common::kernel_at_least(6, 1) {
        common::skip("this kernel reports no pids.peak");
        return;
    }
    if bailey::backend::cgroup::usable_root(&[]).is_none() {
        common::skip("no cgroup to scope observation to");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let trace = trace_of(
        None,
        dir.path(),
        &["--observer", "seccomp", "/bin/sh", "-c", "true"],
    );

    assert_eq!(
        trace["observer"].as_str(),
        Some("seccomp"),
        "the fallback trace names its observer"
    );
    let usage = &trace["usage"];
    assert!(
        usage.is_object(),
        "a fallback run records its peaks: {trace}"
    );
    assert!(
        usage["unmeasured"]
            .as_array()
            .is_none_or(|reasons| reasons.is_empty()),
        "measured peaks leave nothing to explain: {usage}"
    );
}

/// `auto` must fall back, loudly, when no helper can be found anywhere.
#[test]
fn auto_falls_back_without_a_helper() {
    if !fallback_available() {
        common::skip("the fallback observer is unavailable on this host");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    if helper_discoverable_with_path(dir.path()) {
        common::skip("a helper is discoverable without BAILEY_BPF_HELPER");
        return;
    }

    let missing = dir.path().join("no-such-helper");
    let path = dir.path().join("trace.json");
    let output = Command::new(bailey())
        .args([
            "audit",
            "--save-trace",
            path.to_str().unwrap(),
            "/bin/sh",
            "-c",
            "true",
        ])
        .env("BAILEY_BPF_HELPER", &missing)
        .env("PATH", dir.path())
        .output()
        .unwrap();
    assert!(
        path.exists(),
        "auto must still record: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let trace: Value = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
    assert_eq!(
        trace["observer"].as_str(),
        Some("seccomp"),
        "the fallback recorded this trace"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("seccomp fallback observer"),
        "auto must say that it fell back: {stderr}"
    );
}

/// Forcing eBPF without a helper fails the audit instead of falling back.
#[test]
fn forced_ebpf_fails_without_a_helper() {
    let dir = tempfile::tempdir().unwrap();
    if helper_discoverable_with_path(dir.path()) {
        common::skip("a helper is discoverable without BAILEY_BPF_HELPER");
        return;
    }

    let missing = dir.path().join("no-such-helper");
    let path = dir.path().join("trace.json");
    let output = Command::new(bailey())
        .args([
            "audit",
            "--observer",
            "ebpf",
            "--save-trace",
            path.to_str().unwrap(),
            "/bin/sh",
            "-c",
            "true",
        ])
        .env("BAILEY_BPF_HELPER", &missing)
        .env("PATH", dir.path())
        .output()
        .unwrap();
    assert!(
        !output.status.success(),
        "a forced eBPF audit without a helper must fail"
    );
    assert!(!path.exists(), "no trace for a run that never recorded");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("bailey-bpf-helper"),
        "the failure must say what to build: {stderr}"
    );
}

/// `--unconfined` lifts the very filter the fallback observes through, so
/// the combination is refused before anything runs.
#[test]
fn unconfined_needs_the_ebpf_observer() {
    let output = Command::new(bailey())
        .args([
            "audit",
            "--observer",
            "seccomp",
            "--unconfined",
            "/bin/sh",
            "-c",
            "true",
        ])
        .output()
        .unwrap();
    assert!(
        !output.status.success(),
        "--unconfined under the fallback must be refused"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("needs the eBPF observer"),
        "the refusal must name the observer it needs: {stderr}"
    );
}

/// When the supervisor cannot read the target's memory on the first
/// notification, the run ends with an error naming the ptrace policy, and
/// the target never ran. The hardened ptrace policies that cause this need
/// a host setting to reproduce, so the test forces the failure through the
/// test-only hook instead.
#[test]
fn a_fatal_memory_read_names_the_ptrace_policy() {
    if !fallback_available() {
        common::skip("the fallback observer is unavailable on this host");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("trace.json");
    let output = Command::new(bailey())
        .args([
            "audit",
            "--observer",
            "seccomp",
            "--save-trace",
            path.to_str().unwrap(),
            "/bin/sh",
            "-c",
            "echo should-never-print",
        ])
        .env("BAILEY_TEST_FAIL_MEMORY_READ", "1")
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        !stdout.contains("should-never-print"),
        "a run whose supervisor cannot observe must not let the target run: {stdout}"
    );
    assert!(
        !output.status.success(),
        "the run must end in an error, not in silence"
    );
    assert!(
        !path.exists(),
        "no trace for a run that never recorded anything"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("ptrace_scope"),
        "the error must name the ptrace policy that caused it: {stderr}"
    );
}

/// Observation must not create authority: a target that swaps the bytes of
/// an `openat` path between a granted file and an ungranted one, racing the
/// supervisor's read, can never pull the ungranted file's contents through,
/// because confinement is decided by the kernel at open time and not by
/// what the trace saw.
#[test]
fn a_path_swapped_after_observation_is_still_confined() {
    let Some(python) = python3() else {
        common::skip("needs python3");
        return;
    };
    if !fallback_available() {
        common::skip("the fallback observer is unavailable on this host");
        return;
    }
    if bailey::backend::probe::landlock_abi().is_none() {
        common::skip("landlock is unavailable on this host");
        return;
    }

    let dir = tempfile::tempdir().unwrap();
    let granted_dir = dir.path().join("granted");
    fs::create_dir(&granted_dir).unwrap();
    let granted = granted_dir.join("granted.txt");
    fs::write(&granted, "harmless").unwrap();
    let secret = dir.path().join("secret.txt");
    fs::write(&secret, "top-secret").unwrap();

    let config = dir.path().join("audit.toml");
    fs::write(
        &config,
        format!(
            "[filesystem]\n\
             read = [\"/usr\", \"/bin\", \"/lib\", \"/lib64\", \"/etc\", \"{}\"]\n\
             execute = [\"/usr\", \"/bin\", \"/lib\", \"/lib64\"]\n",
            granted_dir.display()
        ),
    )
    .unwrap();

    let script = dir.path().join("race.py");
    fs::write(&script, python_race(&granted, &secret)).unwrap();

    let output = audit(
        None,
        &[
            "audit",
            "--observer",
            "seccomp",
            "-c",
            config.to_str().unwrap(),
            python,
            &script.display().to_string(),
        ],
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        !stdout.contains("top-secret"),
        "the ungranted file's contents must never reach stdout, whatever the \
         trace saw: {stdout}"
    );
}

/// A fallback audit inside another fallback audit is refused: the inherited
/// filter stack already carries a listener, and a stack holds exactly one.
#[test]
fn a_nested_fallback_audit_is_refused() {
    if !fallback_available() {
        common::skip("the fallback observer is unavailable on this host");
        return;
    }

    let dir = tempfile::tempdir().unwrap();
    let inner = dir.path().join("bailey-bin");
    fs::copy(bailey(), &inner).unwrap();
    let config = dir.path().join("audit.toml");
    fs::write(
        &config,
        format!(
            "[filesystem]\n\
             read = [\"/usr\", \"/bin\", \"/lib\", \"/lib64\", \"/etc\", \"{}\"]\n\
             execute = [\"/usr\", \"/bin\", \"/lib\", \"/lib64\", \"{}\"]\n",
            dir.path().display(),
            dir.path().display()
        ),
    )
    .unwrap();

    let output = audit_in(
        None,
        Some(dir.path()),
        &[
            "audit",
            "--observer",
            "seccomp",
            "-c",
            config.to_str().unwrap(),
            inner.to_str().unwrap(),
            "audit",
            "--observer",
            "seccomp",
            "/bin/true",
        ],
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("already observes this process"),
        "the inner audit must say why it cannot arm: {stderr}"
    );
    assert_eq!(
        output.status.code(),
        Some(1),
        "the outer audit reports the inner one's failure as its own exit code"
    );
}

/// A fallback audit inside a plain `bailey run` sandbox records: the run's
/// plain denylist stacks a listener on top without trouble.
#[test]
fn an_audit_inside_bailey_run_records() {
    if !fallback_available() {
        common::skip("the fallback observer is unavailable on this host");
        return;
    }

    let dir = tempfile::tempdir().unwrap();
    let inner = dir.path().join("bailey-bin");
    fs::copy(bailey(), &inner).unwrap();
    let config = dir.path().join("run.toml");
    fs::write(
        &config,
        format!(
            "[filesystem]\n\
             read = [\"/usr\", \"/bin\", \"/lib\", \"/lib64\", \"/etc\", \"/proc\", \"{}\"]\n\
             execute = [\"/usr\", \"/bin\", \"/lib\", \"/lib64\", \"{}\"]\n\
             write = [\"{}\"]\n",
            dir.path().display(),
            dir.path().display(),
            dir.path().display()
        ),
    )
    .unwrap();

    let trace = dir.path().join("inner-trace.json");
    let output = Command::new(bailey())
        .args([
            "run",
            "-c",
            config.to_str().unwrap(),
            inner.to_str().unwrap(),
            "audit",
            "--observer",
            "seccomp",
            "--save-trace",
            trace.to_str().unwrap(),
            "/bin/true",
        ])
        .output()
        .unwrap();

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "the nested audit must succeed: {stderr}"
    );
    assert!(trace.exists(), "the inner audit wrote its trace: {stderr}");
    let inner_trace: Value = serde_json::from_str(&fs::read_to_string(&trace).unwrap()).unwrap();
    assert_eq!(
        inner_trace["observer"].as_str(),
        Some("seccomp"),
        "the inner audit records with the fallback: {inner_trace}"
    );
}

/// A syscall the denylist refuses is answered by the guard with EPERM and
/// is never notified: the guard's errno outranks the listener, so it never
/// reaches the supervisor and never appears in the trace.
#[test]
fn a_denied_syscall_is_not_notified() {
    let Some(python) = python3() else {
        common::skip("needs python3");
        return;
    };
    if !fallback_available() {
        common::skip("the fallback observer is unavailable on this host");
        return;
    }

    let dir = tempfile::tempdir().unwrap();
    let opened = dir.path().join("opened.txt");
    fs::write(&opened, "plain").unwrap();
    let config = dir.path().join("audit.toml");
    fs::write(
        &config,
        format!(
            "[filesystem]\n\
             read = [\"/usr\", \"/bin\", \"/lib\", \"/lib64\", \"/etc\", \"{}\"]\n\
             execute = [\"/usr\", \"/bin\", \"/lib\", \"/lib64\"]\n",
            dir.path().display()
        ),
    )
    .unwrap();

    let script = dir.path().join("denied.py");
    fs::write(
        &script,
        format!(
            r#"
import ctypes

libc = ctypes.CDLL(None, use_errno=True)
SYS_IO_URING_SETUP = 425
if libc.syscall(SYS_IO_URING_SETUP, 4, 0) == -1:
    print("denied", ctypes.get_errno())
else:
    print("created")
print(open("{}").read(), end="")
"#,
            opened.display()
        ),
    )
    .unwrap();

    let (output, trace) = audit_and_trace(
        None,
        dir.path(),
        &[
            "--observer",
            "seccomp",
            "-c",
            config.to_str().unwrap(),
            python,
            script.to_str().unwrap(),
        ],
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("denied 1"),
        "io_uring_setup must be refused with EPERM: {stdout}"
    );
    assert!(
        stdout.contains("plain"),
        "the open after the refusal must still work: {stdout}"
    );

    let opens: Vec<&Value> = trace["events"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|event| {
            event["kind"] == "read"
                && event["resource"]["path"]
                    .as_str()
                    .is_some_and(|path| path.ends_with("opened.txt"))
        })
        .collect();
    assert_eq!(
        opens.len(),
        1,
        "the target's open of the file is notified and recorded exactly once: {opens:?}"
    );
}

/// A descendant left behind when the target exits holds the filter with no
/// supervisor behind it: its next notified syscall fails with ENOSYS, and
/// bailey does not wait for it.
#[test]
fn a_leftover_descendant_gets_enosys() {
    if !fallback_available() {
        common::skip("the fallback observer is unavailable on this host");
        return;
    }

    let mut child = Command::new(bailey())
        .args([
            "audit",
            "--observer",
            "seccomp",
            "/bin/sh",
            "-c",
            "(sleep 1; cat /etc/hostname) & exit",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        match child.try_wait().expect("bailey is a child of this test") {
            Some(status) => {
                assert!(
                    status.success(),
                    "the target exited cleanly, so the audit reports its code"
                );
                break;
            }
            None if Instant::now() >= deadline => {
                let _ = child.kill();
                panic!("bailey must end the run without waiting for the descendant");
            }
            None => std::thread::sleep(Duration::from_millis(50)),
        }
    }

    // The descendant still holds the pipes, so draining them waits out its
    // one second of sleep and its failing cat.
    let output = child.wait_with_output().unwrap();
    let hostname = fs::read_to_string("/etc/hostname").unwrap_or_default();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        !stdout.contains(hostname.trim()),
        "the descendant's cat must fail, so nothing it read reaches stdout: {stdout}"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Function not implemented"),
        "the descendant's notified syscall must fail with ENOSYS: {stderr}"
    );
}
