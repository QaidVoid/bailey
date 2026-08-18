//! Shared `no_std` types crossing the bailey eBPF/userspace boundary.
//!
//! The eBPF programs fill an [`AccessRecord`] and submit it through a ring
//! buffer; the userspace audit backend reads the raw bytes back into the same
//! layout and converts them into higher-level access events.
//!
//! The helper and the main tool are separately built binaries, so the layout is
//! versioned: the helper announces [`PROTOCOL_VERSION`] at startup and a
//! mismatch is rejected rather than parsed as garbage.

#![no_std]

use bytemuck::{Pod, Zeroable};

/// Version of the helper protocol and record layout.
///
/// Bump this whenever [`AccessRecord`] changes shape or the handshake changes.
pub const PROTOCOL_VERSION: u8 = 1;

/// First byte the helper writes once its programs are attached, followed by
/// [`PROTOCOL_VERSION`].
pub const HELLO: u8 = 0x01;
/// Byte the helper writes once the observation scope is seeded, after which the
/// target may be released.
pub const ACK: u8 = 0x02;
/// Frame tag for an [`AccessRecord`].
pub const FRAME_RECORD: u8 = 0x10;
/// Frame tag for the closing summary, followed by a little-endian `u64` count of
/// records the kernel could not deliver.
pub const FRAME_SUMMARY: u8 = 0x11;

/// Filesystem read.
pub const KIND_READ: u32 = 0;
/// Filesystem write.
pub const KIND_WRITE: u32 = 1;
/// Filesystem execute.
pub const KIND_EXECUTE: u32 = 2;
/// Outbound connect.
pub const KIND_CONNECT: u32 = 3;
/// Socket bind.
pub const KIND_BIND: u32 = 4;

/// Address family for an event with no network address.
pub const FAMILY_NONE: u16 = 0;
/// IPv4, with the address in the first four bytes of [`AccessRecord::addr`].
pub const FAMILY_INET: u16 = 2;
/// IPv6, with the address in all sixteen bytes of [`AccessRecord::addr`].
pub const FAMILY_INET6: u16 = 10;

/// `dirfd` value meaning "relative to the process's working directory".
pub const AT_FDCWD: i32 = -100;

/// Maximum path length captured per record, in bytes.
pub const PATH_LEN: usize = 256;

/// A fixed-size access record passed from an eBPF program to userspace.
///
/// The layout is `repr(C)` with explicit padding so it can be read back byte for
/// byte on the userspace side.
#[repr(C)]
#[derive(Clone, Copy, Pod, Zeroable)]
pub struct AccessRecord {
    /// One of the `KIND_*` constants.
    pub kind: u32,
    /// PID of the accessing process.
    pub pid: u32,
    /// Monotonic timestamp of the access, in nanoseconds.
    pub timestamp_ns: u64,
    /// Network address, in network byte order. IPv4 uses the first four bytes.
    pub addr: [u8; 16],
    /// One of the `FAMILY_*` constants.
    pub family: u16,
    /// TCP or UDP port, in host byte order.
    pub port: u16,
    /// Number of valid bytes in `path`.
    pub path_len: u16,
    /// Padding, kept so the layout has no implicit holes.
    pub _padding: u16,
    /// Directory the path is relative to, or [`AT_FDCWD`]. Meaningless for an
    /// absolute path.
    pub dirfd: i32,
    /// Open flags as passed to the kernel, for deciding read against write.
    pub flags: u32,
    /// Accessed path, as the caller supplied it. Not NUL terminated.
    pub path: [u8; PATH_LEN],
}

impl AccessRecord {
    /// An empty record, for a program to fill in.
    pub const fn empty() -> Self {
        Self {
            kind: KIND_READ,
            pid: 0,
            timestamp_ns: 0,
            addr: [0; 16],
            family: FAMILY_NONE,
            port: 0,
            path_len: 0,
            _padding: 0,
            dirfd: AT_FDCWD,
            flags: 0,
            path: [0; PATH_LEN],
        }
    }
}
