//! Integration tests for the broker's decision log as bailey opens it and
//! reports it.
//!
//! The refusals and the summary need a real run, so these drive `bailey run`
//! with a broker and a target that does nothing, and self-skip where user
//! namespaces are unavailable. The docs check reads the sample log line the
//! reference documents and parses it.

mod common;

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

fn bailey() -> &'static str {
    env!("CARGO_BIN_EXE_bailey")
}

fn netns_available() -> bool {
    bailey::backend::isolation::available()
}

/// A run of `/bin/true` with the built-in broker, and the given log path.
///
/// The target reads and executes nothing but its own binary and libraries,
/// so the filesystem grants are the usual shared-library set.
fn run_with_log(dir: &Path, log: &Path) -> std::process::Output {
    let config = dir.join("bailey.toml");
    fs::write(
        &config,
        format!(
            "[filesystem]\n\
             read = [\"/usr\", \"/bin\", \"/lib\", \"/lib64\"]\n\
             execute = [\"/usr\", \"/bin\", \"/lib\", \"/lib64\"]\n\
             \n\
             [network]\n\
             egress = \"allow\"\n\
             broker = \"builtin\"\n\
             \n\
             [http]\n\
             intercept = [\"intercepted.invalid\"]\n\
             log = \"{}\"\n",
            log.display()
        ),
    )
    .unwrap();
    Command::new(bailey())
        .current_dir(dir)
        .env("HOME", dir)
        .env("XDG_CONFIG_HOME", dir.join("config"))
        .env("XDG_DATA_HOME", dir.join("data"))
        .arg("run")
        .arg("-c")
        .arg(&config)
        .arg("/bin/true")
        .output()
        .unwrap()
}

fn stderr_of(output: &std::process::Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

/// A log path that is a symbolic link is refused before the broker starts:
/// whatever the link points at is never opened, let alone appended to.
#[test]
fn a_symlinked_log_refuses_the_run() {
    if !netns_available() {
        common::skip("needs user namespaces");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("real-log.jsonl");
    let link = dir.path().join("http-log.jsonl");
    std::os::unix::fs::symlink(&target, &link).unwrap();

    let output = run_with_log(dir.path(), &link);
    let stderr = stderr_of(&output);
    assert!(
        !output.status.success(),
        "the run must be refused: {stderr}"
    );
    assert!(
        stderr.contains("not a regular file"),
        "the refusal names the shape: {stderr}"
    );
    assert!(!target.exists(), "the link's target was never created");
}

/// A log path whose file belongs to someone else is refused, and nothing is
/// appended to it. As root the test owns a foreign file directly; otherwise
/// any root-owned regular file stands in.
#[test]
fn a_foreign_owned_log_refuses_the_run() {
    if !netns_available() {
        common::skip("needs user namespaces");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let foreign: PathBuf;
    if unsafe { libc::geteuid() } == 0 {
        foreign = dir.path().join("foreign-log.jsonl");
        fs::write(&foreign, b"").unwrap();
        let path = std::ffi::CString::new(foreign.as_os_str().as_encoded_bytes()).unwrap();
        assert_eq!(unsafe { libc::chown(path.as_ptr(), 1, 1) }, 0, "chown runs");
    } else {
        foreign = PathBuf::from("/etc/hosts");
        let meta = fs::metadata(&foreign).expect("/etc/hosts exists");
        use std::os::unix::fs::MetadataExt;
        assert_ne!(
            meta.uid(),
            unsafe { libc::geteuid() },
            "the stand-in file must belong to someone else"
        );
    }
    let before = fs::read(&foreign).unwrap_or_default();

    let output = run_with_log(dir.path(), &foreign);
    let stderr = stderr_of(&output);
    assert!(
        !output.status.success(),
        "the run must be refused: {stderr}"
    );
    assert!(
        stderr.contains("not owned by you"),
        "the refusal names the owner: {stderr}"
    );
    assert_eq!(
        fs::read(&foreign).unwrap_or_default(),
        before,
        "nothing was appended"
    );
}

/// A run with a log prints the broker's counts after everything else it
/// says, with the log path in the line, and the log itself exists.
#[test]
fn the_parent_prints_the_broker_counts_after_the_summary() {
    if !netns_available() {
        common::skip("needs user namespaces");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("http-log.jsonl");

    let output = run_with_log(dir.path(), &log);
    assert!(output.status.success(), "{}", stderr_of(&output));
    let stderr = stderr_of(&output);
    let counts_line = format!(
        "bailey: http broker: 0 allowed, 0 refused (log: {})",
        log.display()
    );
    let at = stderr
        .find(&counts_line)
        .unwrap_or_else(|| panic!("the counts line is missing: {stderr}"));
    // The counts close the run's output: everything bailey says about the
    // run itself comes first.
    let last = stderr.trim_end().lines().last().unwrap_or("");
    assert_eq!(last, counts_line, "the counts line is last: {stderr}");
    let _ = at;
    assert!(
        fs::metadata(&log).is_ok(),
        "the log file exists after the run"
    );
}

/// The sample decision-log line in the reference is JSON with the fields
/// every line carries, so what the docs show is what the broker writes.
#[test]
fn the_docs_log_sample_parses_as_json() {
    let docs = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/reference/config.md");
    let text = fs::read_to_string(&docs).expect("the reference documents the log");
    let heading = text
        .find("The decision log")
        .unwrap_or_else(|| panic!("the log section is missing from {}", docs.display()));
    let rest = &text[heading..];
    let fence = rest
        .find("```jsonl")
        .unwrap_or_else(|| panic!("the log section has a jsonl sample: {rest}"));
    let sample = &rest[fence + "```jsonl".len()..];
    let end = sample
        .find("```")
        .unwrap_or_else(|| panic!("the sample block is closed"));
    let sample = sample[..end].trim();
    assert!(!sample.is_empty(), "the sample block holds lines");
    for line in sample.lines() {
        let value: serde_json::Value = serde_json::from_str(line.trim())
            .unwrap_or_else(|error| panic!("the sample line is not json: {error}; {line:?}"));
        for field in [
            "time",
            "method",
            "host",
            "port",
            "path",
            "verdict",
            "reason",
            "rule",
            "intercepted",
        ] {
            assert!(
                value.get(field).is_some(),
                "the sample line carries {field}: {line}"
            );
        }
        assert!(
            value["verdict"] == "allowed" || value["verdict"] == "refused",
            "the verdict is one of the two: {line}"
        );
    }
}
