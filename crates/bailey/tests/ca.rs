//! The interception run's trust bundle.
//!
//! An intercepted run combines the host's system bundle with the run's CA,
//! writes the result to a per-run private directory, and binds it read-only
//! over every system trust path the reconstructed root carries. These tests
//! run real `bailey run` invocations and inspect what the target sees.

mod common;

use std::process::{Command, Stdio};

fn python() -> Option<&'static str> {
    ["/usr/bin/python3", "/bin/python3"]
        .into_iter()
        .find(|path| std::path::Path::new(path).exists())
}

/// The intercept policy every test here shares: one host, tunnelled and
/// intercepted, so the broker generates its CA.
fn config(intercept: &str) -> String {
    format!(
        "[network]\nbroker = \"builtin\"\n\n[http]\nintercept = \
         [\"{intercept}\"]\n\n[[http.allow]]\nhost = \"{intercept}\"\n"
    )
}

/// Directories this run left behind: bundle directories whose name carries
/// the run's own pid.
fn directories_of(pid: u32) -> Vec<std::path::PathBuf> {
    let mine = format!(".bailey-ca.{pid}.");
    std::fs::read_dir("/tmp")
        .into_iter()
        .flatten()
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with(&mine))
        })
        .collect()
}

/// Run bailey with `config` and the python program, and answer the lines it
/// printed on stdout, with the run's pid: the bundle directory carries that
/// pid, so the gone-after-the-run check can name its own run and stay
/// indifferent to another test's run being in flight.
fn run(dir: &std::path::Path, config: &str, program: &str) -> (u32, Vec<String>, String) {
    let config_path = dir.join("bailey.toml");
    std::fs::write(&config_path, config).unwrap();
    let child = Command::new(env!("CARGO_BIN_EXE_bailey"))
        .current_dir(dir)
        .env("HOME", dir)
        .env("XDG_CONFIG_HOME", dir.join("config"))
        .env("XDG_DATA_HOME", dir.join("data"))
        .arg("run")
        .arg("-c")
        .arg(&config_path)
        .args(["python3", "-c", program])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("bailey runs");
    let pid = child.id();
    let output = child.wait_with_output().expect("bailey runs to completion");
    let stdout = String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(str::to_owned)
        .collect();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    (pid, stdout, stderr)
}

fn line<'a>(stdout: &'a [String], prefix: &str) -> &'a str {
    stdout
        .iter()
        .find(|line| line.starts_with(prefix))
        .unwrap_or_else(|| panic!("no `{prefix}` line in {stdout:?}"))
}

fn require_sandbox() -> Option<(tempfile::TempDir, &'static str)> {
    let Some(python) = python() else {
        common::skip("needs python3");
        return None;
    };
    if !bailey::backend::isolation::available() {
        common::skip("needs user namespaces");
        return None;
    }
    Some((tempfile::tempdir().unwrap(), python))
}

/// With `/etc` granted, the bundle is visible at the system path, it counts
/// the host's certificates plus the run's CA, it refuses writes, and the CA
/// variables name the covered path.
#[test]
fn the_bundle_covers_a_granted_etc() {
    let Some((dir, _python)) = require_sandbox() else {
        return;
    };
    let mut config = config("example.com");
    config.push_str("[filesystem]\nread = [\"/etc\"]\n");
    let (pid, stdout, stderr) = run(
        dir.path(),
        &config,
        r#"
import os
path = "/etc/ssl/certs/ca-certificates.crt"
data = open(path).read()
print("CERTS", data.count("BEGIN CERTIFICATE"), flush=True)
print("ENV", os.environ.get("SSL_CERT_FILE"), flush=True)
print("ENV-REQUESTS", os.environ.get("REQUESTS_CA_BUNDLE"), flush=True)
try:
    with open(path, "a") as handle:
        handle.write("x")
    print("WRITE-REACHED", flush=True)
except OSError as error:
    print("WRITE-REFUSED", error.errno, flush=True)
"#,
    );
    assert!(
        stderr.contains("egress broker (built-in)"),
        "the run is brokered: {stderr}"
    );
    assert_eq!(
        line(&stdout, "ENV"),
        "ENV /etc/ssl/certs/ca-certificates.crt"
    );
    assert_eq!(
        line(&stdout, "ENV-REQUESTS"),
        "ENV-REQUESTS /etc/ssl/certs/ca-certificates.crt"
    );
    assert!(line(&stdout, "WRITE-REFUSED").starts_with("WRITE-REFUSED"));

    // The combined bundle carries the host's own certificates plus the CA.
    let sandbox_certs: usize = line(&stdout, "CERTS")
        .split_once(' ')
        .unwrap()
        .1
        .parse()
        .unwrap();
    let host_certs = std::fs::read_to_string("/etc/ssl/certs/ca-certificates.crt")
        .map(|data| data.matches("BEGIN CERTIFICATE").count())
        .unwrap_or(0);
    assert!(
        sandbox_certs > host_certs,
        "the sandbox bundle holds more than the host's {host_certs}: {sandbox_certs}"
    );

    assert!(
        directories_of(pid).is_empty(),
        "the bundle directory is gone after the run"
    );
}

/// Without `/etc` granted, the host's own bundle is added as an implicit
/// read grant, and the bundle is still visible and still read-only.
#[test]
fn the_bundle_covers_an_ungranted_etc() {
    let Some((dir, _python)) = require_sandbox() else {
        return;
    };
    let (pid, stdout, stderr) = run(
        dir.path(),
        &config("example.com"),
        r#"
import os
path = "/etc/ssl/certs/ca-certificates.crt"
try:
    data = open(path).read()
except OSError:
    print("BUNDLE-MISSING", flush=True)
else:
    print("CERTS", data.count("BEGIN CERTIFICATE"), flush=True)
    try:
        with open(path, "a") as handle:
            handle.write("x")
        print("WRITE-REACHED", flush=True)
    except OSError as error:
        print("WRITE-REFUSED", error.errno, flush=True)
"#,
    );
    assert!(
        stderr.contains("egress broker (built-in)"),
        "the run is brokered: {stderr}"
    );
    assert!(
        !stdout.iter().any(|line| line.starts_with("BUNDLE-MISSING")),
        "the bundle is visible without /etc granted"
    );
    assert!(line(&stdout, "WRITE-REFUSED").starts_with("WRITE-REFUSED"));
    assert!(
        directories_of(pid).is_empty(),
        "the bundle directory is gone after the run"
    );
}

/// A bundle path laid out the way Arch and Fedora lay theirs out, a symlink
/// to the real file, is covered through the link: both names show the
/// combined bundle, and neither shows what the fake host bundle said.
#[test]
fn a_symlinked_bundle_path_is_covered() {
    let Some((dir, _python)) = require_sandbox() else {
        return;
    };
    // A fake /etc, granted at /etc, whose bundle path is a symlink to the
    // real file elsewhere in the tree, the shape /etc/ssl/certs has on Arch:
    // `..` climbs out of `certs`, then out of `ssl`.
    let etc = dir.path().join("etc");
    std::fs::create_dir_all(etc.join("ssl/certs")).unwrap();
    std::fs::create_dir_all(etc.join("pki/tls/certs")).unwrap();
    std::fs::write(
        etc.join("pki/tls/certs/ca-bundle.crt"),
        "FAKE HOST BUNDLE\n",
    )
    .unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink(
        "../../pki/tls/certs/ca-bundle.crt",
        etc.join("ssl/certs/ca-certificates.crt"),
    )
    .unwrap();

    let mut config = config("example.com");
    config.push_str(&format!(
        "[filesystem]\nread = [{{ path = \"{}\", at = \"/etc\" }}]\n",
        etc.display()
    ));
    let (pid, stdout, stderr) = run(
        dir.path(),
        &config,
        r#"
paths = [
    "/etc/ssl/certs/ca-certificates.crt",
    "/etc/pki/tls/certs/ca-bundle.crt",
]
for path in paths:
    data = open(path).read()
    print("AT", path, "CERTS", data.count("BEGIN CERTIFICATE"),
          "FAKE" if "FAKE HOST BUNDLE" in data else "REAL", flush=True)
"#,
    );
    assert!(
        stderr.contains("egress broker (built-in)"),
        "the run is brokered: {stderr}"
    );
    let symlinked = line(&stdout, "AT /etc/ssl/certs/ca-certificates.crt");
    let destination = line(&stdout, "AT /etc/pki/tls/certs/ca-bundle.crt");

    // Both names show the combined bundle: the host's certificates plus the
    // run's CA, and neither shows what the fake host bundle said.
    let host_certs = std::fs::read_to_string("/etc/ssl/certs/ca-certificates.crt")
        .map(|data| data.matches("BEGIN CERTIFICATE").count())
        .unwrap_or(0);
    let expected = format!("CERTS {}", host_certs + 1);
    for (name, line) in [("symlink", symlinked), ("destination", destination)] {
        assert!(
            line.contains(&expected),
            "{name} shows the host bundle plus the CA ({expected}): {line}"
        );
        assert!(
            !line.contains("FAKE"),
            "{name} still shows the fake bundle: {line}"
        );
    }
    assert!(
        directories_of(pid).is_empty(),
        "the bundle directory is gone after the run"
    );
}
