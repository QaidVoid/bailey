//! Integration test for the audit-trace to profile generation flow.
mod common;

use std::fs;
use std::process::Command;

fn bailey() -> &'static str {
    env!("CARGO_BIN_EXE_bailey")
}

/// Write a trace of one routine read, naming `observer` as its recorder.
fn write_trace(dir: &std::path::Path, name: &str, observer: &str) -> std::path::PathBuf {
    let trace = dir.join(name);
    let target_dir = dir.display();
    fs::write(
        &trace,
        format!(
            r#"{{"version":1,"dropped":0,"events":[
              {{"kind":"read","resource":{{"path":"{target_dir}/data.pak"}},"pid":10,"timestamp_ns":0,"resolution":"absolute"}}
            ],"observer":"{observer}"}}"#
        ),
    )
    .unwrap();
    trace
}

/// Generate a profile from `trace`, naming `target` beside it.
fn generate(dir: &std::path::Path, trace: &std::path::Path) -> std::process::Output {
    let target = dir.join("game");
    fs::write(&target, "").unwrap();
    Command::new(bailey())
        .args(["profile", "generate", "--trace"])
        .arg(trace)
        .arg("--target")
        .arg(&target)
        .output()
        .unwrap()
}

/// The privileged helper, when this host has one that can actually load its
/// programs. Without it there is no trace to generate anything from.
fn helper() -> Option<std::path::PathBuf> {
    // Whatever the probe resolved, rather than a path guessed alongside the test
    // binary: the one next to it is usually the debug build, which has no
    // capabilities and would make this fail instead of skip.
    match bailey::backend::probe::probe(true).helper {
        bailey::backend::probe::HelperStatus::Ready(path) => Some(path),
        _ => None,
    }
}

#[test]
fn generate_excludes_high_risk_by_default() {
    let dir = tempfile::tempdir().unwrap();
    let trace = dir.path().join("trace.json");

    // A routine read inside the target directory, a credential read, and an
    // outbound connection.
    let target_dir = dir.path().display();
    fs::write(
        &trace,
        format!(
            r#"{{"version":1,"dropped":0,"events":[
              {{"kind":"read","resource":{{"path":"{target_dir}/data.pak"}},"pid":10,"timestamp_ns":0,"resolution":"absolute"}},
              {{"kind":"read","resource":{{"path":"/home/user/.ssh/id_rsa"}},"pid":10,"timestamp_ns":0,"resolution":"absolute"}},
              {{"kind":"connect","resource":{{"net":{{"host":"1.2.3.4","port":443}}}},"pid":10,"timestamp_ns":0,"resolution":"not_applicable"}}
            ]}}"#
        ),
    )
    .unwrap();

    let target = dir.path().join("game");
    fs::write(&target, "").unwrap();

    let output = Command::new(bailey())
        .args(["profile", "generate", "--trace"])
        .arg(&trace)
        .arg("--target")
        .arg(&target)
        .output()
        .unwrap();

    assert!(output.status.success());
    let profile = String::from_utf8_lossy(&output.stdout);
    assert!(
        profile.contains("data.pak"),
        "routine read should be granted"
    );
    assert!(
        !profile.contains("id_rsa"),
        "credential read must be excluded"
    );
    assert!(!profile.contains("egress"), "egress must be excluded");
}

#[test]
fn generate_includes_high_risk_when_requested() {
    let dir = tempfile::tempdir().unwrap();
    let trace = dir.path().join("trace.json");
    fs::write(
        &trace,
        r#"{"version":1,"dropped":0,"events":[{"kind":"connect","resource":{"net":{"host":"1.2.3.4","port":443}},"pid":10,"timestamp_ns":0,"resolution":"not_applicable"}]}"#,
    )
    .unwrap();
    let target = dir.path().join("game");
    fs::write(&target, "").unwrap();

    let output = Command::new(bailey())
        .args(["profile", "generate", "--include-high-risk", "--trace"])
        .arg(&trace)
        .arg("--target")
        .arg(&target)
        .output()
        .unwrap();

    assert!(output.status.success());
    let profile = String::from_utf8_lossy(&output.stdout);
    assert!(
        profile.contains("egress"),
        "egress should be included when requested"
    );
    assert!(profile.contains("443"));
}

#[test]
fn a_truncated_trace_is_refused_unless_accepted() {
    let dir = tempfile::tempdir().unwrap();
    let trace = dir.path().join("trace.json");
    let target_dir = dir.path().display();
    fs::write(
        &trace,
        format!(
            r#"{{"version":1,"dropped":7,"events":[
              {{"kind":"read","resource":{{"path":"{target_dir}/data.pak"}},"pid":10,"timestamp_ns":0,"resolution":"absolute"}}
            ]}}"#
        ),
    )
    .unwrap();
    let target = dir.path().join("game");
    fs::write(&target, "").unwrap();

    let refused = Command::new(bailey())
        .args(["profile", "generate", "--trace"])
        .arg(&trace)
        .arg("--target")
        .arg(&target)
        .output()
        .unwrap();
    assert!(
        !refused.status.success(),
        "a truncated trace must be refused"
    );
    let stderr = String::from_utf8_lossy(&refused.stderr);
    assert!(
        stderr.contains("7"),
        "the loss count must be reported: {stderr}"
    );

    let accepted = Command::new(bailey())
        .args(["profile", "generate", "--accept-truncated", "--trace"])
        .arg(&trace)
        .arg("--target")
        .arg(&target)
        .output()
        .unwrap();
    assert!(accepted.status.success());
    let profile = String::from_utf8_lossy(&accepted.stdout);
    assert!(
        profile.contains("incomplete trace"),
        "the profile must record that it came from a partial trace: {profile}"
    );
}

#[test]
fn an_unknown_trace_version_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let trace = dir.path().join("trace.json");
    fs::write(&trace, r#"{"version":99,"dropped":0,"events":[]}"#).unwrap();
    let target = dir.path().join("game");
    fs::write(&target, "").unwrap();

    let output = Command::new(bailey())
        .args(["profile", "generate", "--trace"])
        .arg(&trace)
        .arg("--target")
        .arg(&target)
        .output()
        .unwrap();

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("version 99"),
        "the unsupported version must be named: {stderr}"
    );
}

/// The whole loop the README advertises: watch a program, turn what it did into
/// a policy, and run it under that policy.
///
/// Both halves of this are covered elsewhere, live recording in `audit.rs` and
/// trace-to-profile above, but nothing walked the join between them, which is
/// where the two halves disagreeing would show up.
#[test]
fn a_recorded_run_produces_a_policy_that_run_accepts() {
    let Some(helper) = helper() else {
        common::skip("no audit helper with capabilities on this host");
        return;
    };

    let dir = tempfile::tempdir().unwrap();
    // The program and its data share a directory, so reading the data is a
    // routine finding rather than a high-risk one held back for review.
    let program = dir.path().join("program");
    fs::copy("/bin/cat", &program).unwrap();
    let data = dir.path().join("data.txt");
    fs::write(&data, "recorded\n").unwrap();

    // Without a policy for it, the data is not granted and the read fails.
    let before = Command::new(bailey())
        .arg("run")
        .arg(&program)
        .arg(&data)
        .output()
        .unwrap();
    assert!(
        !String::from_utf8_lossy(&before.stdout).contains("recorded"),
        "the data is not granted yet, so this must not read it"
    );

    let trace = dir.path().join("trace.json");
    let audited = Command::new(bailey())
        .env("BAILEY_BPF_HELPER", &helper)
        .args(["audit", "--save-trace"])
        .arg(&trace)
        .arg(&program)
        .arg(&data)
        .output()
        .unwrap();
    assert!(
        audited.status.success(),
        "the audit run failed: {}",
        String::from_utf8_lossy(&audited.stderr)
    );

    let generated = Command::new(bailey())
        .args(["profile", "generate", "--trace"])
        .arg(&trace)
        .arg("--target")
        .arg(&program)
        .output()
        .unwrap();
    assert!(generated.status.success());
    let config = dir.path().join("bailey.toml");
    fs::write(&config, &generated.stdout).unwrap();
    assert!(
        String::from_utf8_lossy(&generated.stdout).contains("data.txt"),
        "the trace saw the read, so the profile must grant it: {}",
        String::from_utf8_lossy(&generated.stdout)
    );

    let after = Command::new(bailey())
        .args(["run", "-c"])
        .arg(&config)
        .arg(&program)
        .arg(&data)
        .output()
        .unwrap();
    assert!(
        String::from_utf8_lossy(&after.stdout).contains("recorded"),
        "the generated policy must be enough to run under: {} {}",
        String::from_utf8_lossy(&after.stdout),
        String::from_utf8_lossy(&after.stderr)
    );
}

/// A real trace is thousands of files. One run of a coding agent read 1,760, of
/// which 192 sat in a single directory: a grant per file is unreadable, and an
/// unreadable policy gets replaced by a far wider one.
#[test]
fn many_files_in_one_directory_become_the_directory() {
    let dir = tempfile::tempdir().unwrap();
    let trace = dir.path().join("trace.json");
    let target_dir = dir.path().display();

    let events: Vec<String> = (0..12)
        .map(|n| {
            format!(
                r#"{{"kind":"read","resource":{{"path":"/opt/app/lib/vendor/mod{n}.js"}},"pid":10,"timestamp_ns":0,"resolution":"absolute"}}"#
            )
        })
        .chain(std::iter::once(
            format!(
                r#"{{"kind":"read","resource":{{"path":"{target_dir}/alone.conf"}},"pid":10,"timestamp_ns":0,"resolution":"absolute"}}"#
            ),
        ))
        .collect();
    fs::write(
        &trace,
        format!(
            r#"{{"version":1,"dropped":0,"events":[{}]}}"#,
            events.join(",")
        ),
    )
    .unwrap();

    let target = dir.path().join("app");
    fs::write(&target, "").unwrap();

    let output = Command::new(bailey())
        .args(["profile", "generate", "--trace"])
        .arg(&trace)
        .arg("--target")
        .arg(&target)
        .arg("--include-high-risk")
        .output()
        .unwrap();
    let profile = String::from_utf8_lossy(&output.stdout);

    assert!(
        profile.contains("/opt/app/lib/vendor\""),
        "twelve files under one directory should be that directory: {profile}"
    );
    assert!(
        !profile.contains("mod0.js"),
        "and not the files themselves: {profile}"
    );
    assert!(
        profile.contains("alone.conf"),
        "a lone file stays a file: {profile}"
    );
}

/// A trace with reads of `/`, the home, and a credential, generated with
/// `--include-high-risk`: the flag can include high-risk findings, but the
/// never tier sits above it. The connect is still granted, and stderr names
/// everything that was left out.
#[test]
fn credentials_and_home_are_never_generated() {
    let dir = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();
    let trace = dir.path().join("trace.json");
    let home_dir = home.path().display();
    fs::write(
        &trace,
        format!(
            r#"{{"version":1,"dropped":0,"events":[
              {{"kind":"read","resource":{{"path":"/"}},"pid":10,"timestamp_ns":0,"resolution":"absolute"}},
              {{"kind":"read","resource":{{"path":"{home_dir}"}},"pid":10,"timestamp_ns":0,"resolution":"absolute"}},
              {{"kind":"read","resource":{{"path":"{home_dir}/.ssh/id_ed25519"}},"pid":10,"timestamp_ns":0,"resolution":"absolute"}},
              {{"kind":"connect","resource":{{"net":{{"host":"1.2.3.4","port":443}}}},"pid":10,"timestamp_ns":0,"resolution":"not_applicable"}}
            ]}}"#
        ),
    )
    .unwrap();

    let target = dir.path().join("game");
    fs::write(&target, "").unwrap();

    let output = Command::new(bailey())
        .args(["profile", "generate", "--include-high-risk", "--trace"])
        .arg(&trace)
        .arg("--target")
        .arg(&target)
        .env("HOME", home.path())
        .output()
        .unwrap();
    assert!(output.status.success());

    let profile = String::from_utf8_lossy(&output.stdout);
    assert!(
        profile.contains("443"),
        "the connect is a flag-included high-risk access and is granted: {profile}"
    );
    let granted = read_paths(&profile, "read");
    assert!(
        granted.is_empty(),
        "no read grant may survive this trace: {granted:?}"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("never generated 3 access(es)"),
        "the count is on stderr: {stderr}"
    );
    assert!(
        stderr.contains(&home_dir.to_string()),
        "the home is named: {stderr}"
    );
    assert!(
        stderr.contains("id_ed25519"),
        "the credential is named: {stderr}"
    );
}

/// A direct read of a credential directory, not a file beneath it, is also
/// never generated: `is_credential_path` matches the contents, and the
/// ancestor rule covers the directory itself.
#[test]
fn direct_directory_findings_are_never_generated() {
    let dir = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();
    let trace = dir.path().join("trace.json");
    let target_dir = dir.path().display();
    let home_dir = home.path().display();
    fs::write(
        &trace,
        format!(
            r#"{{"version":1,"dropped":0,"events":[
              {{"kind":"read","resource":{{"path":"{home_dir}/.config"}},"pid":10,"timestamp_ns":0,"resolution":"absolute"}},
              {{"kind":"read","resource":{{"path":"{home_dir}/.ssh"}},"pid":10,"timestamp_ns":0,"resolution":"absolute"}},
              {{"kind":"read","resource":{{"path":"{target_dir}/data.pak"}},"pid":10,"timestamp_ns":0,"resolution":"absolute"}}
            ]}}"#
        ),
    )
    .unwrap();

    let target = dir.path().join("game");
    fs::write(&target, "").unwrap();

    let output = Command::new(bailey())
        .args(["profile", "generate", "--include-high-risk", "--trace"])
        .arg(&trace)
        .arg("--target")
        .arg(&target)
        .env("HOME", home.path())
        .output()
        .unwrap();
    assert!(output.status.success());

    let profile = String::from_utf8_lossy(&output.stdout);
    let granted = read_paths(&profile, "read");
    assert_eq!(
        granted,
        vec![format!("{target_dir}/data.pak")],
        "only the ordinary file is granted: {profile}"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("never generated 2 access(es)"),
        "both directories are named on stderr: {stderr}"
    );
}

/// A target that lives directly in the home and reads it: without the never
/// tier this produced `read = ["<home>"]` with no flags at all, because a
/// read under the target directory is routine. The home is still the home.
#[test]
fn a_home_directory_target_does_not_grant_home() {
    let home = tempfile::tempdir().unwrap();
    let trace = home.path().join("trace.json");
    let home_dir = home.path().display();
    fs::write(
        &trace,
        format!(
            r#"{{"version":1,"dropped":0,"events":[
              {{"kind":"read","resource":{{"path":"{home_dir}"}},"pid":10,"timestamp_ns":0,"resolution":"absolute"}},
              {{"kind":"read","resource":{{"path":"{home_dir}/data.pak"}},"pid":10,"timestamp_ns":0,"resolution":"absolute"}}
            ]}}"#,
        ),
    )
    .unwrap();

    let target = home.path().join("game");
    fs::write(&target, "").unwrap();

    let output = Command::new(bailey())
        .args(["profile", "generate", "--trace"])
        .arg(&trace)
        .arg("--target")
        .arg(&target)
        .env("HOME", home.path())
        .output()
        .unwrap();
    assert!(output.status.success());

    let profile = String::from_utf8_lossy(&output.stdout);
    let granted = read_paths(&profile, "read");
    assert_eq!(
        granted,
        vec![format!("{home_dir}/data.pak")],
        "the file under the target is routine, the home itself is not: {profile}"
    );
}

/// The read paths of a generated profile, parsed from its TOML.
fn read_paths(profile: &str, key: &str) -> Vec<String> {
    let parsed: toml::Table =
        toml::from_str(profile).expect("a generated profile always parses as TOML");
    parsed
        .get("filesystem")
        .and_then(|filesystem| filesystem.get(key))
        .and_then(toml::Value::as_array)
        .map(|paths| {
            paths
                .iter()
                .map(|path| path.as_str().expect("a path string").to_owned())
                .collect()
        })
        .unwrap_or_default()
}

/// A trace with measured peaks gets a suggestion that parses and applies
/// nothing: saving the output shows no limits, and uncommenting the block is
/// what applies the suggested numbers.
#[test]
fn a_suggestion_parses_and_applies_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let trace = dir.path().join("trace.json");
    let target_dir = dir.path().display();
    let mib: u64 = 1_048_576;
    fs::write(
        &trace,
        format!(
            r#"{{"version":1,"dropped":0,"events":[
              {{"kind":"read","resource":{{"path":"{target_dir}/data.pak"}},"pid":10,"timestamp_ns":0,"resolution":"absolute"}}
            ],"usage":{{"memory_peak_bytes":{},"tasks_peak":40,"unmeasured":[]}}}}"#,
            300 * mib
        ),
    )
    .unwrap();

    let target = dir.path().join("game");
    fs::write(&target, "").unwrap();

    let output = Command::new(bailey())
        .args(["profile", "generate", "--trace"])
        .arg(&trace)
        .arg("--target")
        .arg(&target)
        .env("XDG_CONFIG_HOME", dir.path())
        .output()
        .unwrap();
    assert!(output.status.success());
    let profile = String::from_utf8_lossy(&output.stdout);
    assert!(
        profile.contains("Uncomment to apply"),
        "the suggestion labels itself: {profile}"
    );

    let saved = dir.path().join("bailey.toml");
    fs::write(&saved, profile.as_bytes()).unwrap();
    let shown = Command::new(bailey())
        .args(["show", "-c"])
        .arg(&saved)
        .arg(&target)
        .env("XDG_CONFIG_HOME", dir.path())
        .output()
        .unwrap();
    let report = String::from_utf8_lossy(&shown.stdout);
    assert!(
        report.contains("memory_bytes: None"),
        "saving the output applies no memory limit: {report}"
    );
    assert!(
        report.contains("pids_max: None"),
        "saving the output applies no process limit: {report}"
    );

    // A person who read the block uncomments it deliberately.
    let applied: String = profile
        .lines()
        .map(|line| {
            if line.starts_with("#[resources]")
                || line.starts_with("#memory")
                || line.starts_with("#pids_max")
            {
                line.strip_prefix('#').unwrap_or(line).to_owned()
            } else {
                line.to_owned()
            }
        })
        .collect::<Vec<_>>()
        .join("\n");
    let uncommented = dir.path().join("applied.toml");
    fs::write(&uncommented, applied).unwrap();
    let shown = Command::new(bailey())
        .args(["show", "-c"])
        .arg(&uncommented)
        .arg(&target)
        .env("XDG_CONFIG_HOME", dir.path())
        .output()
        .unwrap();
    let report = String::from_utf8_lossy(&shown.stdout);
    let expected = 600 * mib;
    assert!(
        report.contains(&format!("memory_bytes: Some({expected})")),
        "uncommenting applies the suggested memory: {report}"
    );
    assert!(
        report.contains("pids_max: Some(80)"),
        "uncommenting applies the suggested pids_max: {report}"
    );
}

/// A fallback trace says so in the generated profile, on stdout as a header
/// comment the profile carries with it, and on stderr as a note.
#[test]
fn a_fallback_trace_says_so_in_the_profile() {
    let dir = tempfile::tempdir().unwrap();
    let trace = write_trace(dir.path(), "trace.json", "seccomp");

    let output = generate(dir.path(), &trace);
    assert!(output.status.success());
    let profile = String::from_utf8_lossy(&output.stdout);
    assert!(
        profile.contains("# Recorded with the seccomp fallback observer"),
        "the profile header must carry the observer note: {profile}"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("seccomp fallback observer"),
        "the user must be told what the trace came from: {stderr}"
    );
}

/// The observer that recorded a trace is not what a profile grants: the
/// same events under either observer generate the same grant lines.
#[test]
fn the_same_events_generate_the_same_grants_under_either_observer() {
    let dir = tempfile::tempdir().unwrap();
    let mut grants = Vec::new();
    for (name, observer) in [
        ("trace-ebpf.json", "ebpf"),
        ("trace-seccomp.json", "seccomp"),
    ] {
        let trace = write_trace(dir.path(), name, observer);
        let output = generate(dir.path(), &trace);
        assert!(output.status.success());
        grants.push(
            String::from_utf8_lossy(&output.stdout)
                .lines()
                .filter(|line| !line.starts_with('#') && !line.is_empty())
                .collect::<Vec<_>>()
                .join("\n"),
        );
    }

    assert_eq!(
        grants[0], grants[1],
        "grants come from the events, not from the observer that recorded them"
    );
    assert!(
        grants[0].contains("data.pak"),
        "the generated grant names the read: {}",
        grants[0]
    );
}
