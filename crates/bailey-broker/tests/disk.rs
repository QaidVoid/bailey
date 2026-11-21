//! The interception CA's key is never serialised to disk.
//!
//! The broker runs with an empty `HOME` and `TMPDIR`, intercepts one host,
//! answers its ready line with the CA certificate, and the directories must
//! be exactly as empty afterwards as they were before.

use std::io::Write;
use std::process::{Command, Stdio};

use bailey::broker::{BrokerConfig, BrokerReady};
use bailey::policy::{HttpHost, HttpPolicy};

/// Count the entries of a directory, or fail the test naming it.
fn entries(path: &std::path::Path) -> usize {
    std::fs::read_dir(path)
        .unwrap_or_else(|error| panic!("{} is readable: {error}", path.display()))
        .count()
}

#[test]
fn a_run_that_intercepts_creates_no_file() {
    let root = std::env::temp_dir().join(format!("bailey-broker-disk-{}", std::process::id()));
    let home = root.join("home");
    let tmp = root.join("tmp");
    std::fs::create_dir_all(&home).expect("the home directory is made");
    std::fs::create_dir_all(&tmp).expect("the tmp directory is made");

    let config = BrokerConfig {
        version: bailey::broker::BROKER_PROTOCOL_VERSION,
        http: HttpPolicy {
            intercept: vec![HttpHost::parse("api.anthropic.com").unwrap()],
            ..HttpPolicy::default()
        },
        credentials: Vec::new(),
        log: false,
    };

    let mut child = Command::new(env!("CARGO_BIN_EXE_bailey-broker"))
        .arg(std::process::id().to_string())
        .env("HOME", &home)
        .env("TMPDIR", &tmp)
        .env_remove("BAILEY_HELPER_DIRS")
        .env("BAILEY_BROKER_SELFTEST", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("the broker starts");

    let mut stdin = child.stdin.take().expect("the broker reads its config");
    stdin
        .write_all(&config.encode().expect("the config encodes"))
        .expect("the config is written");
    drop(stdin);

    let mut stdout = child.stdout.take().expect("the broker writes its answer");
    let ready = BrokerReady::decode(&mut stdout).expect("the ready line arrives");
    let pem = ready.ca_pem.expect("an intercepted run carries its CA");
    assert!(pem.starts_with("-----BEGIN CERTIFICATE-----"));

    let status = child.wait().expect("the broker is reaped");
    assert!(status.success(), "the broker exited with {status}");

    assert_eq!(entries(&home), 0, "the home directory is untouched");
    assert_eq!(entries(&tmp), 0, "the tmp directory is untouched");
    std::fs::remove_dir_all(&root).ok();
}
