//! The broker binary speaks the wire protocol the `bailey` library defines:
//! a configuration document on stdin, one ready line on stdout.

use std::io::{Read, Write};
use std::process::{Command, Stdio};

use bailey::broker::{BROKER_PROTOCOL_VERSION, BrokerConfig, BrokerLayers, BrokerReady};

/// Spawn the broker, hand it a configuration, and read its ready line.
#[test]
fn the_broker_answers_the_config_with_a_ready_line() {
    let config = BrokerConfig {
        version: BROKER_PROTOCOL_VERSION,
        http: bailey::policy::HttpPolicy::default(),
        credentials: Vec::new(),
        log: false,
    };

    let mut child = Command::new(env!("CARGO_BIN_EXE_bailey-broker"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("the broker binary builds and spawns");
    let mut stdin = child.stdin.take().expect("stdin is piped");
    stdin
        .write_all(&config.encode().unwrap())
        .expect("the config fits a pipe");
    drop(stdin);
    let mut stdout = child.stdout.take().expect("stdout is piped");
    let ready = BrokerReady::decode(&mut stdout).expect("a ready line");
    child.wait().expect("the broker exits cleanly");

    assert_eq!(ready.version, BROKER_PROTOCOL_VERSION);
    assert_eq!(ready.ca_pem, None, "no host is intercepted yet");
    assert_eq!(
        ready.layers,
        BrokerLayers::default(),
        "the skeleton applies no confinement layer yet"
    );
}

/// A broker handed a configuration from another protocol version refuses
/// rather than guess.
#[test]
fn the_broker_refuses_a_foreign_version() {
    let config = BrokerConfig {
        version: BROKER_PROTOCOL_VERSION + 1,
        http: bailey::policy::HttpPolicy::default(),
        credentials: Vec::new(),
        log: false,
    };

    let mut child = Command::new(env!("CARGO_BIN_EXE_bailey-broker"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("the broker binary builds and spawns");
    let mut stdin = child.stdin.take().expect("stdin is piped");
    stdin
        .write_all(&config.encode().unwrap())
        .expect("the config fits a pipe");
    drop(stdin);
    let mut stdout = child.stdout.take().expect("stdout is piped");
    let mut answer = Vec::new();
    stdout
        .read_to_end(&mut answer)
        .expect("reading the broker's stdout");
    let status = child.wait().expect("the broker exits");

    assert!(
        !status.success(),
        "a foreign version must refuse: {answer:?}"
    );
    assert!(answer.is_empty(), "no ready line for a refused config");
}
