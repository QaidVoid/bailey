//! The broker's serving core: the request and response codecs, the TLS
//! setup, and the CONNECT tunnel. The binary is a thin entry point over
//! this library, and the fuzz targets exercise the codecs through it.

pub mod request;
pub mod response;
pub mod tls;
pub mod tunnel;
