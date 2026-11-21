//! The built-in HTTP egress broker.
//!
//! bailey spawns this binary beside the sandbox with the namespaced listener
//! on descriptor 3, the log on descriptor 4, its configuration on stdin, and
//! its own pid as the only argument. The broker confines itself, answers
//! one ready line on stdout,
//! and then serves the CONNECT ACL and HTTP rules the configuration carries.

use std::io;

fn main() -> Result<(), bailey::broker::WireError> {
    // The configuration arrives as one JSON document on stdin, to EOF.
    // Nothing else is trusted: arguments and environment carry no secrets.
    let config = bailey::broker::BrokerConfig::decode(&mut io::stdin().lock())?;

    // Confinement, CONNECT serving and credential use arrive with tasks 3.4
    // and 3.5. Until then the wire protocol is the whole program, and the
    // ready line reports honestly that no confinement layer is applied.
    let ready = bailey::broker::BrokerReady {
        version: bailey::broker::BROKER_PROTOCOL_VERSION,
        ca_pem: None,
        layers: bailey::broker::BrokerLayers::default(),
    };
    ready.write_to(&mut io::stdout().lock())?;
    let _ = config;

    Ok(())
}
