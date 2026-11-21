//! The wire protocol between bailey and the `bailey-broker` helper.
//!
//! Both sides link this module, so the parent that spawns the broker and the
//! broker that serves it cannot drift apart about what a configuration or a
//! ready line means. The parent writes one [`BrokerConfig`] as JSON to the
//! broker's stdin and closes the pipe; the broker reads it to EOF, applies
//! its confinement, and
//! answers with one [`BrokerReady`] line on stdout. Secrets travel only
//! through the stdin pipe, never in arguments or environment.

use serde::{Deserialize, Serialize};
use std::io::{Read, Write};

/// The protocol version both sides must agree on.
///
/// Bumped whenever a field changes meaning. A broker that reads a version it
/// does not know refuses, and so does a parent whose broker answers with a
/// version it does not know: an old helper beside a new bailey must fail the
/// run at startup, not serve rules it misreads.
pub const BROKER_PROTOCOL_VERSION: u32 = 1;

/// The configuration bailey writes to the broker's stdin pipe.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BrokerConfig {
    /// The protocol version, checked against [`BROKER_PROTOCOL_VERSION`]
    /// before anything else in the document is trusted.
    pub version: u32,
    /// The HTTP rules the broker enforces.
    pub http: crate::policy::HttpPolicy,
    /// Credential values, resolved by bailey from the bindings' sources
    /// before the broker is spawned. Values live here and nowhere else: not
    /// in arguments, not in the environment.
    pub credentials: Vec<BrokerCredential>,
    /// Whether a log descriptor is on descriptor 4.
    pub log: bool,
}

/// One credential value bound to a host, in the shape it is attached as.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BrokerCredential {
    /// The intercepted host it binds to.
    pub host: crate::policy::HttpHost,
    /// The request shape the value is attached as.
    pub auth: crate::policy::AuthShape,
    /// The secret value, read once by bailey from the binding's source.
    pub value: String,
}

/// The confinement layers the broker could apply, for the summary to report.
///
/// Seccomp is not optional: a broker that cannot apply its filter refuses.
/// Landlock degrades with the kernel, and the parent says so in the summary.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct BrokerLayers {
    /// bailey's seccomp denylist with the socket family filter.
    pub seccomp: bool,
    /// The broker's Landlock ruleset: file rules and scope.
    pub landlock: bool,
    /// Landlock network connect rules, where the kernel has ABI 4 or better.
    pub landlock_network: bool,
}

/// The one ready line the broker writes to stdout before accepting.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BrokerReady {
    /// The protocol version this broker speaks, checked against
    /// [`BROKER_PROTOCOL_VERSION`] by the parent.
    pub version: u32,
    /// The generated CA certificate in PEM form, when any host is
    /// intercepted. The parent writes it into the per-run bundle (decision
    /// 10); the broker keeps the private key in memory only.
    pub ca_pem: Option<String>,
    /// The confinement layers the broker applied.
    pub layers: BrokerLayers,
}

/// The error a failed exchange produces.
#[derive(Debug, thiserror::Error)]
pub enum WireError {
    /// The document on the wire names a protocol version neither side knows.
    #[error("broker protocol version {found}, expected {expected}")]
    Version {
        /// The version the document carried.
        found: u32,
        /// The version this side speaks.
        expected: u32,
    },
    /// The document could not be read or parsed.
    #[error("broker wire protocol: {0}")]
    Io(#[from] std::io::Error),
    /// The bytes were read but are not a valid document.
    #[error("broker wire protocol: {0}")]
    Json(#[from] serde_json::Error),
}

impl BrokerConfig {
    /// Encode the configuration for the broker's stdin pipe.
    pub fn encode(&self) -> Result<Vec<u8>, WireError> {
        let mut document = serde_json::to_vec(&self)?;
        document.push(b'\n');
        Ok(document)
    }

    /// Decode the configuration from the broker's stdin, to EOF.
    pub fn decode(reader: &mut impl Read) -> Result<Self, WireError> {
        let mut text = Vec::new();
        reader.read_to_end(&mut text)?;
        let config: Self = serde_json::from_slice(&text)?;
        config.check_version()?;
        Ok(config)
    }

    fn check_version(&self) -> Result<(), WireError> {
        if self.version != BROKER_PROTOCOL_VERSION {
            return Err(WireError::Version {
                found: self.version,
                expected: BROKER_PROTOCOL_VERSION,
            });
        }
        Ok(())
    }
}

impl BrokerReady {
    /// Encode the ready line for the parent.
    pub fn encode(&self) -> Result<Vec<u8>, WireError> {
        let mut line = serde_json::to_vec(&self)?;
        line.push(b'\n');
        Ok(line)
    }

    /// Decode the ready line: one line, then nothing may follow.
    pub fn decode(reader: &mut impl Read) -> Result<Self, WireError> {
        let mut text = Vec::new();
        reader.read_to_end(&mut text)?;
        let text = std::str::from_utf8(&text).map_err(|source| {
            WireError::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, source))
        })?;
        let line = text.trim_end_matches(['\r', '\n']);
        let ready: Self = serde_json::from_str(line)?;
        if ready.version != BROKER_PROTOCOL_VERSION {
            return Err(WireError::Version {
                found: ready.version,
                expected: BROKER_PROTOCOL_VERSION,
            });
        }
        Ok(ready)
    }

    /// Write the ready line, then flush, so the parent sees it before the
    /// first client connection arrives.
    pub fn write_to(&self, out: &mut impl Write) -> Result<(), WireError> {
        out.write_all(&self.encode()?)?;
        out.flush()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{AuthShape, CredentialBinding, CredentialSource, HttpHost, HttpPolicy};

    /// A config covering every field, for the round trips.
    fn sample_config() -> BrokerConfig {
        BrokerConfig {
            version: BROKER_PROTOCOL_VERSION,
            http: HttpPolicy {
                intercept: vec![HttpHost::parse("api.anthropic.com").unwrap()],
                allow: Vec::new(),
                deny: Vec::new(),
                credentials: vec![CredentialBinding {
                    host: HttpHost::parse("api.anthropic.com").unwrap(),
                    auth: AuthShape::Header("x-api-key".into()),
                    source: CredentialSource::Env("ANTHROPIC_API_KEY".into()),
                }],
                log: Some("/tmp/http-log.jsonl".into()),
                source: Some("~/.config/bailey/config.toml".into()),
            },
            credentials: vec![BrokerCredential {
                host: HttpHost::parse("api.anthropic.com").unwrap(),
                auth: AuthShape::Bearer,
                value: "sk-ant-test".into(),
            }],
            log: true,
        }
    }

    /// The parent's document and the broker's answer survive the pipe.
    #[test]
    fn wire_types_round_trip() {
        let config = sample_config();
        let encoded = config.encode().unwrap();
        let mut encoded = encoded.as_slice();
        let decoded = BrokerConfig::decode(&mut encoded).unwrap();
        assert_eq!(decoded, config);

        let ready = BrokerReady {
            version: BROKER_PROTOCOL_VERSION,
            ca_pem: Some("-----BEGIN CERTIFICATE-----".into()),
            layers: BrokerLayers {
                seccomp: true,
                landlock: true,
                landlock_network: true,
            },
        };
        let encoded = ready.encode().unwrap();
        let decoded = BrokerReady::decode(&mut encoded.as_slice()).unwrap();
        assert_eq!(decoded, ready);
    }

    /// A document from a stranger protocol version is refused before any
    /// other field is looked at.
    #[test]
    fn a_version_mismatch_is_refused() {
        let mut config = sample_config();
        config.version = BROKER_PROTOCOL_VERSION + 1;
        let encoded = config.encode().unwrap();
        match BrokerConfig::decode(&mut encoded.as_slice()) {
            Err(WireError::Version { found, expected }) => {
                assert_eq!(found, BROKER_PROTOCOL_VERSION + 1);
                assert_eq!(expected, BROKER_PROTOCOL_VERSION);
            }
            other => panic!("expected a version refusal, got {other:?}"),
        }

        let ready = BrokerReady {
            version: 99,
            ca_pem: None,
            layers: BrokerLayers::default(),
        };
        let encoded = ready.encode().unwrap();
        assert!(BrokerReady::decode(&mut encoded.as_slice()).is_err());
    }

    /// Garbage is a JSON error, not a panic, and an empty pipe is an error
    /// rather than a config with no fields.
    #[test]
    fn garbage_and_empty_are_refused() {
        let mut garbage = &b"not json"[..];
        assert!(BrokerConfig::decode(&mut garbage).is_err());

        let mut empty = &b""[..];
        assert!(BrokerConfig::decode(&mut empty).is_err());
        assert!(BrokerReady::decode(&mut empty).is_err());
    }
}
