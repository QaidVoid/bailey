//! Shared `no_std` types crossing the bailey eBPF/userspace boundary.
//!
//! The eBPF programs fill an [`AccessRecord`] and submit it through a ring
//! buffer; the userspace audit backend reads the raw bytes back into the same
//! layout and converts them into higher-level access events.

#![no_std]

use bytemuck::{Pod, Zeroable};

/// Filesystem read.
pub const KIND_READ: u32 = 0;
/// Filesystem write.
pub const KIND_WRITE: u32 = 1;
/// Filesystem execute.
pub const KIND_EXECUTE: u32 = 2;
/// Outbound TCP connect.
pub const KIND_CONNECT: u32 = 3;
/// TCP bind.
pub const KIND_BIND: u32 = 4;

/// Maximum path length captured per record, in bytes.
pub const PATH_LEN: usize = 256;

/// A fixed-size access record passed from an eBPF program to userspace.
///
/// The layout is `repr(C)` with no padding so it can be read back byte for byte
/// on the userspace side.
#[repr(C)]
#[derive(Clone, Copy, Pod, Zeroable)]
pub struct AccessRecord {
    /// One of the `KIND_*` constants.
    pub kind: u32,
    /// PID of the accessing process.
    pub pid: u32,
    /// IPv4 address in network byte order for net events, otherwise zero.
    pub addr: u32,
    /// TCP port for net events, otherwise zero.
    pub port: u16,
    /// Number of valid bytes in `path`.
    pub path_len: u16,
    /// Accessed path, for filesystem events. Not NUL terminated.
    pub path: [u8; PATH_LEN],
}
