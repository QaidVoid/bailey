//! Integration tests for what bailey reports about a host and about a run.
mod common;

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;

fn bailey() -> &'static str {
    env!("CARGO_BIN_EXE_bailey")
}

fn run(args: &[&str]) -> std::process::Output {
    Command::new(bailey()).args(args).output().unwrap()
}

/// Run a target under enforcement with a config file, so a report can name
/// where a policy's choice came from.
fn run_with_config(
    config_body: &str,
    args: &[&str],
    envs: &[(&str, &Path)],
) -> (std::process::Output, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("bailey.toml");
    fs::write(&config, config_body).unwrap();
    let mut command = Command::new(bailey());
    command
        .current_dir(dir.path())
        .env("HOME", dir.path())
        .env("XDG_CONFIG_HOME", dir.path().join("config"))
        .env("XDG_DATA_HOME", dir.path().join("data"));
    for (key, value) in envs {
        command.env(key, value);
    }
    let output = command
        .arg("run")
        .args(args)
        .arg("-c")
        .arg(&config)
        .arg("/bin/true")
        .output()
        .unwrap();
    (output, dir)
}

#[test]
fn doctor_reports_every_mechanism_with_its_consequence() {
    let output = run(&["doctor"]);
    assert!(output.status.success());
    let report = String::from_utf8_lossy(&output.stdout);

    for mechanism in [
        "landlock",
        "user namespaces",
        "cgroup delegation",
        "kernel BTF",
        "helper",
    ] {
        assert!(
            report.contains(mechanism),
            "doctor must report {mechanism}: {report}"
        );
    }
}

#[test]
fn doctor_explains_what_a_missing_feature_costs() {
    let output = run(&["doctor"]);
    let report = String::from_utf8_lossy(&output.stdout);

    // Every "no" answer must be followed by what it means for a run, since the
    // consequence is the part a user can act on.
    for (line, next) in report.lines().zip(report.lines().skip(1)) {
        if line.trim_end().ends_with(": no") {
            assert!(
                next.starts_with("    "),
                "`{}` reports a gap without saying what it costs",
                line.trim()
            );
        }
    }
}

#[test]
fn a_run_reports_what_it_enforced() {
    let output = run(&["run", "/bin/true"]);
    assert!(output.status.success());
    let summary = String::from_utf8_lossy(&output.stderr);
    assert!(
        summary.contains("enforced:") && summary.contains("landlock"),
        "a run must say what it enforced: {summary}"
    );
}

/// A mode a config chose is reported with the file that chose it, in the
/// summary and in the JSON a caller parses.
#[test]
fn a_configured_mode_is_reported_with_its_source() {
    let (output, dir) =
        run_with_config("[network]\negress = \"allow\"\nmode = \"host\"\n", &[], &[]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let config = dir.path().join("bailey.toml");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("network mode: host") && stderr.contains(&config.display().to_string()),
        "the summary must name the host mode and the file that set it: {stderr}"
    );

    let (output, dir) = run_with_config(
        "[network]\negress = \"allow\"\nmode = \"host\"\n",
        &["--json"],
        &[],
    );
    assert!(output.status.success());
    let config = dir.path().join("bailey.toml");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("network mode: host") && stdout.contains(&config.display().to_string()),
        "the JSON must carry the mode, its reason and its source: {stdout}"
    );
}

/// Automatic mode that falls back says the private namespace was unavailable
/// and names the prerequisite it missed. Which prerequisite is missing depends
/// on the host: without user namespaces, that is named before pasta is.
#[test]
fn an_automatic_fallback_names_the_missing_prerequisite() {
    let helpers = tempfile::tempdir().unwrap();
    let (output, _) = run_with_config(
        "[network]\negress = \"allow\"\n",
        &[],
        &[("BAILEY_HELPER_DIRS", helpers.path())],
    );
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    let missing = if bailey::backend::isolation::available() {
        "pasta is not in a trusted location"
    } else {
        "unprivileged user namespaces are unavailable"
    };
    assert!(
        stderr.contains("automatic mode fell back") && stderr.contains(missing),
        "the fallback must name the private namespace and the missing helper: {stderr}"
    );
}

/// A flag overrides every config layer, and the report says the flag chose.
#[test]
fn a_flag_override_is_reported_as_the_flag() {
    let (output, _) = run_with_config("[network]\negress = \"allow\"\n", &["--no-proxy-net"], &[]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("network mode: host (flag --no-proxy-net:"),
        "the summary must name the flag that chose the host mode: {stderr}"
    );
}

/// The private-network line answers what a run allowing egress will do, and
/// it needs pasta, user namespaces and `nft` to answer "available".
#[test]
fn doctor_reports_the_private_network_available() {
    if bailey::backend::isolation::available() {
        for helper in ["pasta", "nft"] {
            if bailey::cli::resolve_helper(helper).is_err() {
                common::skip(&format!("needs trusted {helper}"));
                return;
            }
        }
    } else {
        common::skip("needs user namespaces");
        return;
    }
    let output = run(&["doctor"]);
    let report = String::from_utf8_lossy(&output.stdout);
    assert!(
        report.contains("private network: available"),
        "a host with pasta and user namespaces reports the private network: {report}"
    );
    assert!(
        report.contains("runs that allow egress use the private network namespace by default"),
        "the report must say what automatic mode will do: {report}"
    );
}

/// A host without a trusted pasta is one where automatic mode shares the
/// host's namespace and refuses policies that need the private one. A host
/// without user namespaces names that prerequisite instead of pasta.
#[test]
fn doctor_reports_missing_pasta_and_its_consequences() {
    let helpers = tempfile::tempdir().unwrap();
    let mut command = Command::new(bailey());
    command.env("BAILEY_HELPER_DIRS", helpers.path());
    let output = command.arg("doctor").output().unwrap();
    let report = String::from_utf8_lossy(&output.stdout);
    let missing = if bailey::backend::isolation::available() {
        "pasta, which is not in a trusted location"
    } else {
        "unprivileged user namespaces, which are unavailable"
    };
    assert!(
        report.contains(&format!("private network: unavailable ({missing})")),
        "an empty helper search must report pasta missing: {report}"
    );
    assert!(
        report.contains("runs that allow egress share the host's network namespace"),
        "the report must say what runs allowing egress will do: {report}"
    );
    assert!(
        report.contains(
            "policies with forwards, published ports, a broker, or private mode are refused"
        ),
        "the report must say what is refused: {report}"
    );
}

/// `nft` is the broker's own prerequisite: without it the private namespace
/// still works, but a broker cannot be confined.
#[test]
fn doctor_reports_a_missing_nft_degrades_the_broker() {
    if !bailey::backend::isolation::available() {
        common::skip("needs user namespaces");
        return;
    }
    if bailey::cli::resolve_helper("pasta").is_err() {
        common::skip("needs trusted pasta");
        return;
    }
    // A directory holding a stand-in pasta and no nft, so only the broker's
    // prerequisite is missing.
    let helpers = tempfile::tempdir().unwrap();
    let stand_in = helpers.path().join("pasta");
    fs::write(&stand_in, "#!/bin/sh\nexit 0\n").unwrap();
    fs::set_permissions(&stand_in, std::fs::Permissions::from_mode(0o755)).unwrap();
    let mut command = Command::new(bailey());
    command.env("BAILEY_HELPER_DIRS", helpers.path());
    let output = command.arg("doctor").output().unwrap();
    let report = String::from_utf8_lossy(&output.stdout);
    assert!(
        report.contains("private network: available"),
        "a host with pasta but no nft still provides the private network: {report}"
    );
    assert!(
        report.contains("a broker cannot be confined, because its lockdown rule needs nft"),
        "the report must name what nft's absence costs: {report}"
    );
}

/// A run that keeps the mount power a Landlock domain would remove applies no
/// Landlock ruleset, so the summary must not claim it did. The layer moves to
/// the skipped list with the reason, and the JSON rendering moves with it.
#[test]
fn a_run_under_self_fuse_does_not_claim_landlock() {
    if !Path::new("/usr/bin/python3").exists() {
        common::skip("/usr/bin/python3 unavailable");
        return;
    }
    // A self_fuse run needs namespace isolation and `enforce` refuses one
    // without it, so on a host that cannot isolate the run fails rather than
    // reporting. Skipping keeps the answer about this host the same as every
    // other isolation test's.
    if !bailey::backend::isolation::available() {
        common::skip("isolation unavailable on this host");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("bailey.toml");
    fs::write(
        &config,
        "self_fuse = true\n[filesystem]\nread = [\"/usr\", \"/bin\", \"/lib\"]\n",
    )
    .unwrap();

    let output = Command::new(bailey())
        .args(["run", "--isolate", "-c"])
        .arg(&config)
        .arg("/bin/true")
        .output()
        .unwrap();
    let summary = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "a self_fuse run must succeed: {summary}"
    );
    assert!(
        !summary.contains("enforced: landlock"),
        "a run that applies no ruleset must not report landlock as enforced: \
         {summary}"
    );
    assert!(
        summary.contains("not enforced, landlock:"),
        "the skipped layer must be named with its reason: {summary}"
    );

    let json = Command::new(bailey())
        .args(["run", "--isolate", "--json", "-c"])
        .arg(&config)
        .arg("/bin/true")
        .output()
        .unwrap();
    let line = String::from_utf8_lossy(&json.stdout);
    let parsed: serde_json::Value =
        serde_json::from_str(line.trim()).expect("--json must emit valid JSON");
    let applied = parsed["applied"].as_array().expect("applied is an array");
    assert!(
        !applied.iter().any(|layer| layer == "landlock"),
        "--json must move the layer out of applied too: {line}"
    );
    let skipped = parsed["skipped"].as_array().expect("skipped is an array");
    assert!(
        skipped
            .iter()
            .any(|entry| entry["layer"] == "landlock" && entry["reason"].is_string()),
        "the JSON must record the layer as skipped with a reason: {line}"
    );
}

#[test]
fn a_skipped_layer_is_named_with_its_reason() {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("bailey.toml");
    fs::write(&config, "[resources]\nmemory = \"1GiB\"\n").unwrap();

    let output = Command::new(bailey())
        .args(["run", "-c"])
        .arg(&config)
        .arg("/bin/true")
        .output()
        .unwrap();
    let summary = String::from_utf8_lossy(&output.stderr);

    // Either the limits applied, or the summary says why they did not.
    let applied = summary.contains("enforced:") && summary.contains("resource limits");
    let explained = summary.contains("not enforced, resource limits:");
    assert!(
        applied || explained,
        "a policy that sets limits must report whether they took effect: {summary}"
    );
}

#[test]
fn the_summary_can_be_suppressed_and_machine_read() {
    let quiet = run(&["run", "--quiet", "/bin/true"]);
    assert!(
        !String::from_utf8_lossy(&quiet.stderr).contains("enforced:"),
        "--quiet must suppress the summary"
    );

    let json = run(&["run", "--json", "/bin/true"]);
    let line = String::from_utf8_lossy(&json.stdout);
    let parsed: serde_json::Value =
        serde_json::from_str(line.trim()).expect("--json must emit valid JSON");
    assert!(parsed["applied"].as_array().is_some_and(|a| !a.is_empty()));
    assert_eq!(parsed["exit_code"].as_i64(), Some(0));
}

#[test]
fn every_bundled_profile_can_be_shown_and_used() {
    let listed = run(&["profile", "list"]);
    let list = String::from_utf8_lossy(&listed.stdout);

    for name in [
        "untrusted",
        "native-game",
        "desktop-app",
        "ai-agent",
        "network-client",
    ] {
        assert!(list.contains(name), "profile list must include {name}");

        let shown = run(&["profile", "show", name]);
        assert!(shown.status.success(), "profile show {name} must succeed");
        assert!(
            !shown.stdout.is_empty(),
            "profile show {name} must print the profile"
        );

        let used = run(&["run", "--profile", name, "/bin/true"]);
        assert!(
            used.status.success(),
            "a target must run under the {name} profile: {}",
            String::from_utf8_lossy(&used.stderr)
        );
    }

    let unknown = run(&["profile", "show", "does-not-exist"]);
    assert!(!unknown.status.success());
}

#[test]
fn completions_and_a_man_page_are_generated() {
    let completions = run(&["completions", "bash"]);
    assert!(completions.status.success());
    let script = String::from_utf8_lossy(&completions.stdout);
    assert!(
        script.contains("doctor") && script.contains("audit"),
        "completions must cover the current commands"
    );

    let man = run(&["man"]);
    assert!(man.status.success());
    let page = String::from_utf8_lossy(&man.stdout);
    assert!(page.contains(".TH bailey"), "man output must be a man page");
}

#[test]
fn a_removed_hook_is_explained_rather_than_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("bailey.toml");
    fs::write(&config, "[hooks]\non_violation = [\"true\"]\n").unwrap();

    let output = Command::new(bailey())
        .args(["run", "-c"])
        .arg(&config)
        .arg("/bin/true")
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "an existing config must still run, not fail to parse"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("on_violation") && stderr.contains("ignored"),
        "the removed hook must be explained: {stderr}"
    );
}

/// A run with its own config home, so user profiles land somewhere temporary.
fn with_profiles(config_home: &Path, args: &[&str]) -> std::process::Output {
    Command::new(bailey())
        .args(args)
        .env("XDG_CONFIG_HOME", config_home)
        .output()
        .unwrap()
}

fn write_profile(config_home: &Path, name: &str, body: &str) {
    let dir = config_home.join("bailey/profiles");
    fs::create_dir_all(&dir).unwrap();
    fs::write(dir.join(format!("{name}.toml")), body).unwrap();
}

#[test]
fn a_user_profile_can_be_listed_shown_and_used() {
    let dir = tempfile::tempdir().unwrap();
    write_profile(dir.path(), "mine", "[filesystem]\nread = [\"/opt/mine\"]\n");

    let listed = with_profiles(dir.path(), &["profile", "list"]);
    let list = String::from_utf8_lossy(&listed.stdout);
    assert!(list.contains("yours:") && list.contains("mine"), "{list}");

    let shown = with_profiles(dir.path(), &["profile", "show", "mine"]);
    assert!(String::from_utf8_lossy(&shown.stdout).contains("/opt/mine"));

    let used = with_profiles(dir.path(), &["show", "--profile", "mine", "/bin/true"]);
    assert!(
        String::from_utf8_lossy(&used.stdout).contains("/opt/mine"),
        "a user profile must contribute to the policy"
    );
}

#[test]
fn a_profile_claims_its_target_unless_one_is_given() {
    let dir = tempfile::tempdir().unwrap();
    write_profile(
        dir.path(),
        "claims-true",
        "applies_to = [\"true\"]\n[filesystem]\nread = [\"/opt/claimed\"]\n",
    );

    let auto = with_profiles(dir.path(), &["show", "/bin/true"]);
    assert!(
        String::from_utf8_lossy(&auto.stdout).contains("/opt/claimed"),
        "a profile that claims the target must be selected"
    );
    assert!(
        String::from_utf8_lossy(&auto.stderr).contains("claims this target"),
        "a policy selected for the user must be reported"
    );

    let explicit = with_profiles(dir.path(), &["show", "--profile", "untrusted", "/bin/true"]);
    assert!(
        !String::from_utf8_lossy(&explicit.stdout).contains("/opt/claimed"),
        "an explicit --profile must win"
    );

    let other = with_profiles(dir.path(), &["show", "/bin/sh"]);
    assert!(
        !String::from_utf8_lossy(&other.stdout).contains("/opt/claimed"),
        "a profile must not apply to a target it does not claim"
    );
}

#[test]
fn two_profiles_claiming_one_target_is_an_error() {
    let dir = tempfile::tempdir().unwrap();
    write_profile(dir.path(), "first", "applies_to = [\"true\"]\n");
    write_profile(dir.path(), "second", "applies_to = [\"true\"]\n");

    let output = with_profiles(dir.path(), &["show", "/bin/true"]);
    assert!(
        !output.status.success(),
        "ambiguous selection must not proceed"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("first") && stderr.contains("second"),
        "the error must name both profiles: {stderr}"
    );
}

#[test]
fn a_bundled_name_cannot_be_shadowed() {
    let dir = tempfile::tempdir().unwrap();
    write_profile(
        dir.path(),
        "untrusted",
        "[filesystem]\nread = [\"/opt/shadow\"]\n",
    );

    let output = with_profiles(dir.path(), &["show", "--profile", "untrusted", "/bin/true"]);
    assert!(
        !String::from_utf8_lossy(&output.stdout).contains("/opt/shadow"),
        "a bundled profile must win over a file of the same name"
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("ignored"),
        "the shadowing attempt must be reported"
    );
}

/// An isolated run builds a user namespace for itself, so the kernel limit is
/// one of the layers that refuses a nested namespace, and the summary says so.
#[test]
fn an_isolated_run_reports_the_kernel_limit_and_the_filter() {
    if !bailey::backend::isolation::available() {
        common::skip("isolation unavailable on this host");
        return;
    }
    let output = run(&["run", "--isolate", "/bin/true"]);
    assert!(output.status.success());
    let summary = String::from_utf8_lossy(&output.stderr);
    assert!(
        summary.contains("nested namespaces: refused (kernel limit, seccomp)"),
        "an isolated run must report the guard limit with the filter: {summary}"
    );
}

/// A `--no-isolate` run with allowed egress creates no user namespace, so
/// there is no limit for the kernel to hold, and the summary must say the
/// filter is the only layer rather than claiming more.
#[test]
fn a_no_isolate_run_reports_the_filter_as_the_only_layer() {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("bailey.toml");
    fs::write(
        &config,
        "[filesystem]\nread = [\"/usr\", \"/bin\", \"/lib\", \"/lib64\"]\n\
         execute = [\"/usr\", \"/bin\", \"/lib\", \"/lib64\"]\n\
         [network]\negress = \"allow\"\n",
    )
    .unwrap();
    let output = Command::new(bailey())
        .args(["run", "--no-isolate", "-c"])
        .arg(&config)
        .arg("/bin/true")
        .output()
        .unwrap();
    assert!(output.status.success());
    let summary = String::from_utf8_lossy(&output.stderr);
    assert!(
        summary.contains("nested namespaces: refused (seccomp only)"),
        "a run without a user namespace must report the filter alone: {summary}"
    );
}

/// The doctor names the same fact, with the state this host can reach.
#[test]
fn doctor_reports_what_refuses_nested_namespaces() {
    let output = run(&["doctor"]);
    let report = String::from_utf8_lossy(&output.stdout);
    if bailey::backend::isolation::available() {
        assert!(
            report.contains("nested namespaces: refused (kernel limit, seccomp)"),
            "doctor must report the guard limit with the filter: {report}"
        );
    } else {
        assert!(
            report.contains("nested namespaces: refused (seccomp only)"),
            "doctor must report the filter alone: {report}"
        );
    }
}

/// A profile needs no trust record because you wrote it. That reasoning fails
/// when someone else can write it, and a profile claims targets on its own.
#[test]
fn a_profile_others_can_write_is_refused() {
    use std::os::unix::fs::PermissionsExt;

    let config_home = tempfile::tempdir().unwrap();
    let profiles = config_home.path().join("bailey/profiles");
    std::fs::create_dir_all(&profiles).unwrap();
    let profile = profiles.join("exposed.toml");
    std::fs::write(
        &profile,
        "applies_to = [\"true\"]\n\n[filesystem]\nread = [\"/etc\"]\n",
    )
    .unwrap();
    std::fs::set_permissions(&profile, std::fs::Permissions::from_mode(0o666)).unwrap();

    let claimed = Command::new(bailey())
        .args(["show", "/bin/true"])
        .env("XDG_CONFIG_HOME", config_home.path())
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&claimed.stderr);
    let stdout = String::from_utf8_lossy(&claimed.stdout);
    assert!(
        stderr.contains("writable by any user"),
        "an exposed profile must say why it was ignored: {stderr}"
    );
    assert!(
        stdout.contains("profile base: untrusted"),
        "and must not be the base it claimed to be: {stdout}"
    );

    // Asked for by name, it fails rather than quietly leaving a weaker policy.
    let named = Command::new(bailey())
        .args(["show", "--profile", "exposed", "/bin/true"])
        .env("XDG_CONFIG_HOME", config_home.path())
        .output()
        .unwrap();
    assert!(!named.status.success());
    assert!(
        String::from_utf8_lossy(&named.stderr).contains("chmod go-w"),
        "and names the fix"
    );

    std::fs::set_permissions(&profile, std::fs::Permissions::from_mode(0o644)).unwrap();
    let fixed = Command::new(bailey())
        .args(["show", "--profile", "exposed", "/bin/true"])
        .env("XDG_CONFIG_HOME", config_home.path())
        .output()
        .unwrap();
    assert!(fixed.status.success(), "and works once it is only yours");
}

/// A skip lands in the log CI reads, under the key the expectation files
/// name.
///
/// Runs a sibling test binary that skips on a host without the audit
/// helper, and asserts the line it appends. Cargo is invoked for the child
/// so the sibling is found whatever layout the target directory uses; the
/// build lock is not held while tests execute, so the nested invocation
/// only re-checks fingerprints and runs.
#[test]
fn a_skip_is_logged_where_ci_reads_it() {
    if std::env::var_os("BAILEY_BPF_HELPER").is_some() {
        common::skip(
            "the audit helper is configured, so the sibling test would run instead of skipping",
        );
        return;
    }
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());

    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("skips.log");
    let output = Command::new(&cargo)
        .args([
            "test",
            "--offline",
            "--test",
            "audit",
            "startup_access_is_recorded",
            "--",
            "--nocapture",
        ])
        .env("BAILEY_TEST_SKIP_LOG", &log)
        .env_remove("BAILEY_BPF_HELPER")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "the sibling run itself must succeed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let line = std::fs::read_to_string(&log).unwrap();
    assert_eq!(
        line, "audit::startup_access_is_recorded\tno audit helper configured\n",
        "the skip must be logged under the crate and test the expectation files name"
    );
}
