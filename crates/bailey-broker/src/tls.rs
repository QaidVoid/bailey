//! The per-run interception CA and its leaf cache.
//!
//! The CA is ECDSA P-256, generated per run, with the key in memory only: it
//! is never serialised, never written, and dies with the broker. Its
//! nameConstraints permit exactly the intercepted names, so even a leaked
//! key cannot vouch for another host to a client that checks constraints.
//! Leaves are issued per host on first use, cached, short-lived and reissued
//! before they expire, and carry AKI and SKI, which Python 3.13 and later
//! demand under strict verification.

use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bailey::policy::HttpHost;
use rcgen::{
    BasicConstraints, CertificateParams, CidrSubnet, ExtendedKeyUsagePurpose, GeneralSubtree, IsCa,
    KeyPair, KeyUsagePurpose, NameConstraints, PKCS_ECDSA_P256_SHA256, SanType,
};
use rustls::ServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use time::OffsetDateTime;

/// How long the CA outlives its run. A leaked key matters only while it is
/// in memory; the name constraints bound what it could vouch for besides.
const CA_LIFETIME_SECS: i64 = 7 * 24 * 3600;

/// A leaf is issued for an hour and reissued when less than this remains,
/// so a long interactive run never sees a leaf expire mid-connection.
const LEAF_LIFETIME_SECS: i64 = 3600;
const REISSUE_MARGIN: Duration = Duration::from_secs(15 * 60);

/// Certificates are compared against the broker's clock with this much
/// slack, so a slightly skewed host does not reject a fresh leaf.
const BACKDATING: Duration = Duration::from_secs(5 * 60);

/// The per-run interception CA.
pub struct CertificateAuthority {
    /// The intercept list the CA is constrained to.
    intercept: Vec<HttpHost>,
    /// The issued CA, kept for signing the leaves.
    ca_cert: rcgen::Certificate,
    /// The CA's key, in memory only.
    ca_key: KeyPair,
    /// The CA's DER form, for the chains the leaves are served in.
    ca_der: CertificateDer<'static>,
    /// One server config per host, issued on first use.
    leaves: Mutex<HashMap<String, CachedLeaf>>,
}

struct CachedLeaf {
    /// The TLS server configuration serving this host, ready to use.
    server_config: Arc<ServerConfig>,
    /// Reissue when this instant has passed.
    deadline: Instant,
}

/// What CA or leaf generation can fail with.
#[derive(Debug)]
pub enum TlsError {
    /// rcgen refused a parameter or a signature.
    Rcgen(rcgen::Error),
    /// rustls refused the assembled configuration.
    Rustls(rustls::Error),
    /// A host no intercept entry covers was asked for a leaf.
    NotIntercepted(String),
}

impl fmt::Display for TlsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Rcgen(error) => write!(f, "certificate generation: {error}"),
            Self::Rustls(error) => write!(f, "TLS configuration: {error}"),
            Self::NotIntercepted(host) => {
                write!(f, "`{host}` is not in the intercept list")
            }
        }
    }
}

impl std::error::Error for TlsError {}

/// The provider every config in this process is built with.
fn ring_provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// The ALPN the broker speaks on both legs: `http/1.1` alone.
pub const ALPN_HTTP11: &[u8] = b"http/1.1";

/// The client configuration upstream connections are opened with, built
/// once from the host's own roots.
///
/// Upstream certificates are verified for the CONNECT name against these
/// roots, and the broker offers `http/1.1` as the only protocol. The broker
/// serves the whole run, so the roots are read once and shared.
pub fn upstream_config() -> Result<Arc<rustls::ClientConfig>, rustls::Error> {
    static CONFIG: std::sync::OnceLock<Result<Arc<rustls::ClientConfig>, rustls::Error>> =
        std::sync::OnceLock::new();
    CONFIG
        .get_or_init(|| {
            let mut roots = rustls::RootCertStore::empty();
            let native = rustls_native_certs::load_native_certs();
            // A layout the broker may only partly read (a hashed-certificates
            // directory it cannot list beside a bundle file it can) still
            // leaves usable roots; only a load that yielded nothing at all
            // is fatal.
            if native.certs.is_empty() && !native.errors.is_empty() {
                return Err(rustls::Error::General(format!(
                    "the host's certificates: {}",
                    native.errors[0]
                )));
            }
            for cert in native.certs {
                roots
                    .add(cert)
                    .map_err(|error| rustls::Error::General(format!("a host root: {error}")))?;
            }
            Ok(Arc::new({
                let mut config = rustls::ClientConfig::builder_with_provider(ring_provider())
                    .with_safe_default_protocol_versions()
                    .map_err(|error| rustls::Error::General(error.to_string()))?
                    .with_root_certificates(roots)
                    .with_no_client_auth();
                config.alpn_protocols = vec![ALPN_HTTP11.to_vec()];
                config
            }))
        })
        .clone()
}

impl CertificateAuthority {
    /// Generate the run's CA, constrained to exactly the intercepted names.
    ///
    /// A `*.suffix` entry contributes the constraint `suffix`, never
    /// `*.suffix`: a literal wildcard inside nameConstraints makes rustls
    /// reject every handshake, while the parent name is equivalent
    /// everywhere.
    pub fn generate(intercept: &[HttpHost]) -> Result<Self, TlsError> {
        let mut permitted = Vec::new();
        for listed in intercept {
            match listed {
                HttpHost::Any => {
                    // Resolution refuses `*`; a run that reached here with
                    // it would unconstrain the CA, so it is refused too.
                    return Err(TlsError::NotIntercepted("*".to_owned()));
                }
                HttpHost::Exact(name) => permitted.push(GeneralSubtree::DnsName(name.clone())),
                HttpHost::Wildcard(suffix) => {
                    permitted.push(GeneralSubtree::DnsName(suffix.clone()))
                }
                HttpHost::Address(ip) => permitted.push(GeneralSubtree::IpAddress(
                    CidrSubnet::from_addr_prefix(*ip, if ip.is_ipv4() { 32 } else { 128 }),
                )),
            }
        }
        if permitted.is_empty() {
            return Err(TlsError::NotIntercepted(
                "no host is intercepted".to_owned(),
            ));
        }

        let now = OffsetDateTime::now_utc();
        let mut ca_params = CertificateParams::default();
        ca_params.not_before = now - BACKDATING;
        ca_params.not_after = now + time::Duration::seconds(CA_LIFETIME_SECS);
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyCertSign,
        ];
        ca_params.name_constraints = Some(NameConstraints {
            permitted_subtrees: permitted,
            excluded_subtrees: Vec::new(),
        });
        let mut distinguished_name = rcgen::DistinguishedName::new();
        distinguished_name.push(rcgen::DnType::CommonName, "bailey egress broker CA");
        ca_params.distinguished_name = distinguished_name;

        let ca_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).map_err(TlsError::Rcgen)?;
        let ca_cert = ca_params.self_signed(&ca_key).map_err(TlsError::Rcgen)?;
        let ca_der = ca_cert.der().clone();

        Ok(Self {
            intercept: intercept.to_vec(),
            ca_cert,
            ca_key,
            ca_der,
            leaves: Mutex::new(HashMap::new()),
        })
    }

    /// The CA certificate in PEM form, for the ready line and the bundle.
    pub fn certificate_pem(&self) -> String {
        self.ca_cert.pem()
    }

    /// Whether a host is intercepted, and so may have a leaf.
    pub fn is_intercepted(&self, host: &str) -> bool {
        self.intercept
            .iter()
            .any(|listed| host_covered(host, listed))
    }

    /// The server configuration for one intercepted host: a fresh leaf on
    /// first use, a cached one inside its reissue margin.
    ///
    /// A host the intercept list does not cover is refused: no leaf is
    /// issued for a name the CA is not constrained to.
    pub fn server_config(&self, host: &str) -> Result<Arc<ServerConfig>, TlsError> {
        if !self.is_intercepted(host) {
            return Err(TlsError::NotIntercepted(host.to_owned()));
        }
        let mut leaves = self.leaves.lock().expect("the leaf lock is never poisoned");
        if let Some(cached) = leaves.get(host)
            && Instant::now() < cached.deadline
        {
            return Ok(Arc::clone(&cached.server_config));
        }
        let server_config = Arc::new(self.issue_leaf(host)?);
        // A leaf past its reissue margin is dead weight: the run names
        // hosts it never returns to, so expired entries leave with the
        // reissue instead of accumulating for the run's length.
        let now = Instant::now();
        leaves.retain(|_, leaf| now < leaf.deadline);
        leaves.insert(
            host.to_owned(),
            CachedLeaf {
                deadline: Instant::now() + Duration::from_secs(LEAF_LIFETIME_SECS as u64)
                    - REISSUE_MARGIN,
                server_config: Arc::clone(&server_config),
            },
        );
        Ok(server_config)
    }

    /// Issue one leaf for `host` and assemble its server configuration.
    fn issue_leaf(&self, host: &str) -> Result<ServerConfig, TlsError> {
        let now = OffsetDateTime::now_utc();
        let mut leaf_params = CertificateParams::default();
        leaf_params.not_before = now - BACKDATING;
        leaf_params.not_after = now + time::Duration::seconds(LEAF_LIFETIME_SECS);
        // ExplicitNoCa writes the critical basicConstraints CA:FALSE and the
        // subject key identifier; with the authority key identifier turned
        // on the leaf satisfies Python's strict verification.
        leaf_params.is_ca = IsCa::ExplicitNoCa;
        leaf_params.use_authority_key_identifier_extension = true;
        leaf_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        leaf_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        leaf_params.subject_alt_names = match host.parse::<std::net::IpAddr>() {
            Ok(ip) => vec![SanType::IpAddress(ip)],
            Err(_) => vec![SanType::DnsName(
                host.try_into()
                    .map_err(|_| TlsError::NotIntercepted(host.to_owned()))?,
            )],
        };
        let mut distinguished_name = rcgen::DistinguishedName::new();
        distinguished_name.push(rcgen::DnType::CommonName, host);
        leaf_params.distinguished_name = distinguished_name;

        let leaf_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).map_err(TlsError::Rcgen)?;
        let leaf = leaf_params
            .signed_by(&leaf_key, &self.ca_cert, &self.ca_key)
            .map_err(TlsError::Rcgen)?;

        let private_key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der()));
        ServerConfig::builder_with_provider(ring_provider())
            .with_safe_default_protocol_versions()
            .map_err(TlsError::Rustls)?
            .with_no_client_auth()
            .with_single_cert(vec![leaf.der().clone(), self.ca_der.clone()], private_key)
            .map_err(TlsError::Rustls)
            .map(|mut config| {
                // The broker offers HTTP/1.1 alone.
                config.alpn_protocols = vec![ALPN_HTTP11.to_vec()];
                config
            })
    }
}

/// Whether a host the target asked for is covered by one intercept entry.
///
/// The same matching the policy makes: an exact entry covers itself, a
/// `*.suffix` entry covers the subdomains of `suffix`, and an address entry
/// covers the literal.
fn host_covered(host: &str, listed: &HttpHost) -> bool {
    match listed {
        HttpHost::Any => true,
        HttpHost::Exact(name) => name == host,
        HttpHost::Wildcard(suffix) => {
            host != suffix.as_str()
                && host
                    .strip_suffix(suffix.as_str())
                    .is_some_and(|rest| rest.ends_with('.'))
        }
        HttpHost::Address(addr) => host
            .parse()
            .is_ok_and(|parsed: std::net::IpAddr| parsed == *addr),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An authority over a small intercept list, for the tests.
    fn authority() -> CertificateAuthority {
        CertificateAuthority::generate(&[
            HttpHost::parse("api.github.com").unwrap(),
            HttpHost::parse("*.npmjs.org").unwrap(),
            HttpHost::parse("10.0.0.7").unwrap(),
        ])
        .expect("the CA generates")
    }

    /// Leaves are issued for every name the intercept list covers, exact
    /// and wildcard and address alike, and the same config comes back
    /// cached within the reissue margin.
    #[test]
    fn leaves_are_issued_for_intercepted_hosts() {
        let authority = authority();
        for host in ["api.github.com", "registry.npmjs.org", "10.0.0.7"] {
            let first = authority.server_config(host).expect("the leaf is issued");
            let second = authority
                .server_config(host)
                .expect("the cached leaf is served");
            assert!(Arc::ptr_eq(&first, &second), "{host} is cached");
        }
    }

    /// An expired entry leaves the cache at the next reissue, and a live
    /// one beside it stays: a run that names many hosts once must not
    /// accumulate dead leaves for its whole length.
    #[test]
    fn an_expired_leaf_leaves_at_the_next_reissue() {
        let authority = authority();
        authority
            .server_config("api.github.com")
            .expect("the leaf is issued");
        authority
            .server_config("registry.npmjs.org")
            .expect("the leaf is issued");
        {
            let mut leaves = authority.leaves.lock().expect("the leaf lock");
            let stale_config = Arc::clone(&leaves["api.github.com"].server_config);
            let stale = || CachedLeaf {
                deadline: Instant::now() - Duration::from_secs(1),
                server_config: Arc::clone(&stale_config),
            };
            leaves.insert("expired.npmjs.org".to_owned(), stale());
            leaves.insert("forgotten.npmjs.org".to_owned(), stale());
            assert_eq!(leaves.len(), 4);
        }
        authority
            .server_config("expired.npmjs.org")
            .expect("the stale host is reissued");
        let leaves = authority.leaves.lock().expect("the leaf lock");
        assert_eq!(
            leaves.len(),
            3,
            "two live entries and the one reissued remain"
        );
        assert!(leaves.contains_key("api.github.com"));
        assert!(leaves.contains_key("registry.npmjs.org"));
        assert!(leaves.contains_key("expired.npmjs.org"));
        assert!(
            !leaves.contains_key("forgotten.npmjs.org"),
            "the entry nobody reissued left with the reissue"
        );
    }

    /// No leaf is issued for a host the intercept list does not cover, and
    /// the apex of a wildcard entry is not covered by it either.
    #[test]
    fn no_leaf_is_issued_for_an_unlisted_host() {
        let authority = authority();
        for host in ["evil.example", "npmjs.org", "github.com", "10.0.0.8"] {
            match authority.server_config(host) {
                Err(TlsError::NotIntercepted(refused)) => assert_eq!(refused, host),
                other => panic!("`{host}` got a leaf: {other:?}"),
            }
        }
    }

    /// A CA refuses to unconstrain itself: `*` is refused, and so is an
    /// empty intercept list, which would be a CA constrained to nothing
    /// issued for nothing.
    #[test]
    fn an_unconstrained_ca_is_refused() {
        assert!(matches!(
            CertificateAuthority::generate(&[HttpHost::Any]),
            Err(TlsError::NotIntercepted(_))
        ));
        assert!(matches!(
            CertificateAuthority::generate(&[]),
            Err(TlsError::NotIntercepted(_))
        ));
    }

    /// The intercept test agrees with the coverage the leaves use, so a
    /// host the policy lists is exactly a host the CA will serve.
    #[test]
    fn the_intercept_test_matches_the_leaf_coverage() {
        let authority = authority();
        for host in ["api.github.com", "registry.npmjs.org", "npmjs.org", "x"] {
            assert_eq!(
                authority.is_intercepted(host),
                authority.server_config(host).is_ok(),
                "{host}"
            );
        }
    }

    /// A leaf reissues when its reissue margin has passed, and the fresh
    /// config is a different object than the one it replaced.
    #[test]
    fn a_leaf_reissues_before_expiry() {
        let authority = authority();
        let first = authority
            .server_config("api.github.com")
            .expect("the leaf is issued");
        {
            let mut leaves = authority.leaves.lock().unwrap();
            let cached = leaves.get_mut("api.github.com").unwrap();
            cached.deadline = Instant::now() - Duration::from_secs(1);
        }
        let second = authority
            .server_config("api.github.com")
            .expect("the leaf is reissued");
        assert!(!Arc::ptr_eq(&first, &second), "a stale leaf is replaced");
    }

    /// The CA PEM is well-formed enough to hand to a client: it carries the
    /// PEM envelope, and the same bytes come back on every call.
    #[test]
    fn the_ca_pem_is_stable() {
        let authority = authority();
        let pem = authority.certificate_pem();
        assert!(pem.starts_with("-----BEGIN CERTIFICATE-----"));
        assert_eq!(pem, authority.certificate_pem());
    }
}
